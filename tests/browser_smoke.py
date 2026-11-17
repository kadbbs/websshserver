"""Real-browser SSH interoperability checks (test-only dependency: Playwright).

Build bin/sshd.test with go test -c, then: python tests/browser_smoke.py
Set CHROMIUM_PATH when using an already-installed Chromium executable.
The delivered client itself has no Python, npm, or Playwright dependency.
"""
import functools
import http.server
import json
import os
import pwd
import re
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
USERNAME = pwd.getpwuid(os.getuid()).pw_name


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_):
        pass


def submit(page, url, password):
    endpoint = urlsplit(url)
    page.locator("#host").fill(endpoint.hostname)
    page.locator("#port").fill(str(endpoint.port or (443 if endpoint.scheme == "wss" else 80)))
    page.locator("#username").fill(USERNAME)
    page.locator("#password").fill(password)
    page.locator("#connect").click()


def check_presentation(page):
    visible = page.locator("body").inner_text()
    assert not re.search(r"WebSocket|wss?://|/ssh|AES|HMAC|ECDSA|Origin|Web Crypto", visible), visible
    assert page.locator("#endpoint").count() == 0
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")


def enter(page, text):
    page.locator("#terminal-input").evaluate(
        "(el, value) => {el.value = value; el.dispatchEvent(new InputEvent('input', {bubbles: true}));}",
        text + "\r",
    )


def native_ssh_checks(work, port, password):
    if not shutil.which("ssh") or not shutil.which("ssh-keygen"):
        print("SKIP system OpenSSH checks: ssh and ssh-keygen are required")
        return
    public_key = subprocess.check_output(["ssh-keygen", "-y", "-f", str(work / "host_key")], text=True)
    known_hosts = work / "known_hosts"
    known_hosts.write_text(f"[127.0.0.1]:{port} " + public_key)
    askpass = work / "askpass.py"
    askpass.write_text("#!/usr/bin/python3\nprint(" + repr(password) + ")\n")
    askpass.chmod(0o700)
    env = {**os.environ, "SSH_ASKPASS": str(askpass), "SSH_ASKPASS_REQUIRE": "force", "DISPLAY": ":99"}
    args = ["ssh", "-F", "/dev/null", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + str(known_hosts),
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", "PubkeyAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
            "-o", "PreferredAuthentications=password", "-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=5", "-p", str(port)]
    result = subprocess.run(args + [USERNAME + "@127.0.0.1", "id -u; printf 'OPENSSH_OK\\n'; exit 7"],
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env, timeout=15)
    assert result.returncode == 7 and result.stdout == str(os.getuid()) + "\nOPENSSH_OK\n", (result.returncode, result.stdout, result.stderr)
    result = subprocess.run(args + ["-tt", USERNAME + "@127.0.0.1", "stty size"],
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env, timeout=15)
    assert result.returncode == 0 and result.stdout.strip() == "24 80", (result.returncode, result.stdout, result.stderr)
    print("PASS system OpenSSH PAM password login, actual system UID, host verification, PTY and exit status")


def tampering_checks(page, url, password, fingerprint):
    mac_state = {"armed": False, "changed": False}

    def mac_route(route):
        server = route.connect_to_server()

        def receive(data):
            if mac_state["armed"] and not mac_state["changed"] and isinstance(data, bytes) and len(data) >= 48:
                altered = bytearray(data)
                altered[-1] ^= 1
                data = bytes(altered)
                mac_state["changed"] = True
            route.send(data)

        server.on_message(receive)

    mac_url = url + "?test=mac"
    page.route_web_socket(re.compile(re.escape(mac_url) + "$"), mac_route)
    page.evaluate("""async ({url, password, fingerprint, username}) => {
      window.tamperError = null;
      window.tamperClient = new WebSSH.SSHClient({url, username, password,
        onHostKey: info => info.fingerprint === fingerprint,
        onClose: info => { window.tamperError = info.error ? info.error.message : 'closed'; }
      });
      await window.tamperClient.connect();
    }""", {"url": mac_url, "password": password, "fingerprint": fingerprint, "username": USERNAME})
    mac_state["armed"] = True
    page.evaluate("command => window.tamperClient.write(command)", "printf 'integrity check\\n'\r")
    page.wait_for_function("window.tamperError !== null")
    assert mac_state["changed"]
    assert "完整性校验失败" in page.evaluate("window.tamperError")

    signature_state = {"changed": False}

    def signature_route(route):
        server = route.connect_to_server()

        def receive(data):
            if not signature_state["changed"] and isinstance(data, bytes) and len(data) > 16 and data[5] == 31:
                # Alter the final byte of the signature, keeping SSH packet framing intact.
                altered = bytearray(data)
                packet_size = int.from_bytes(data[:4], "big") + 4
                altered[packet_size - data[4] - 1] ^= 1
                data = bytes(altered)
                signature_state["changed"] = True
            route.send(data)

        server.on_message(receive)

    signature_url = url + "?test=signature"
    page.route_web_socket(re.compile(re.escape(signature_url) + "$"), signature_route)
    error = page.evaluate("""async ({url, password, username}) => {
      window.trustCalls = 0;
      const client = new WebSSH.SSHClient({url, username, password,
        onHostKey: () => {window.trustCalls++; return true;}
      });
      try { await client.connect(); client.close(); return 'unexpected success'; }
      catch (error) { return error.message; }
    }""", {"url": signature_url, "password": password, "username": USERNAME})
    assert signature_state["changed"]
    assert "主机签名校验失败" in error, error
    assert page.evaluate("window.trustCalls") == 0
    print("PASS corrupted MAC and forged host signature are rejected")


def main():
    binary = Path(os.environ.get("SSH_SERVER_TEST_BINARY", ROOT / "bin/sshd.test"))
    if not binary.is_file():
        raise SystemExit("Build the isolated PAM test executable: make browser-test-build")
    password = secrets.token_urlsafe(24)
    handler = functools.partial(QuietHandler, directory=str(ROOT / "client"))
    static = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=static.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{static.server_port}"
    ws_port = free_port()
    tcp_port = free_port()
    ws_url = f"ws://127.0.0.1:{ws_port}/ssh"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    errors = []
    with tempfile.TemporaryDirectory(prefix="webssh-browser-") as work:
        work = Path(work)
        pamdir = work / "pam"
        pamdir.mkdir()
        check = pamdir / "check.py"
        check.write_text("import hmac, os, sys\nsys.exit(0 if os.environ.get('PAM_USER') == " + repr(USERNAME) + " and hmac.compare_digest(sys.stdin.buffer.read().rstrip(b'\\0'), " + repr(password.encode()) + ") else 1)\n")
        (pamdir / "webssh-browser-test").write_text(f"auth required pam_exec.so expose_authtok /usr/bin/python3 {check}\nauth required pam_permit.so\naccount required pam_permit.so\nsession required pam_permit.so\n")
        config = work / "config.json"
        config.write_text(json.dumps({"TCPAddr": f"127.0.0.1:{tcp_port}", "HTTPAddr": f"127.0.0.1:{ws_port}", "HostKeyFile": str(work / "host_key"), "PAMService": "webssh-browser-test", "PAMConfigDir": str(pamdir), "AllowedOrigins": [origin, "null"], "MaxConnections": 8, "RekeyBytes": 32768}))
        with (work / "server.log").open("w+") as log:
            proc = subprocess.Popen(
                [str(binary), "--test-server", str(config)],
                env=os.environ.copy(),
                stdout=log, stderr=log,
            )
            try:
                for _ in range(100):
                    try:
                        with opener.open(f"http://127.0.0.1:{ws_port}/healthz", timeout=1):
                            break
                    except OSError:
                        if proc.poll() is not None:
                            raise RuntimeError("server exited before becoming ready")
                        time.sleep(0.05)
                else:
                    raise RuntimeError("server did not become ready")
                native_ssh_checks(work, tcp_port, password)
                with sync_playwright() as playwright:
                    executable = os.environ.get("CHROMIUM_PATH")
                    if not executable:
                        cached = list((Path.home() / ".cache/ms-playwright").glob("chromium-*/chrome-linux64/chrome"))
                        executable = str(cached[-1]) if cached else None
                    browser = playwright.chromium.launch(headless=True, executable_path=executable, args=["--no-sandbox"])
                    page = browser.new_page(viewport={"width": 1440, "height": 900})
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    page.goto(origin)
                    check_presentation(page)
                    page.screenshot(path="/tmp/webssh-client-idle.png", full_page=True)
                    page.locator("#shortcuts").click()
                    assert page.locator("#shortcuts-dialog").is_visible()
                    page.locator("#close-shortcuts").click()
                    page.locator("#password").fill("visibility-check")
                    page.locator("#toggle-password").click()
                    assert page.locator("#password").get_attribute("type") == "text"
                    page.locator("#toggle-password").click()
                    assert page.locator("#password").get_attribute("type") == "password"
                    page.keyboard.press("Control+k")
                    assert page.locator("#host").evaluate("el => el === document.activeElement")
                    submit(page, ws_url, password)
                    page.locator("#host-dialog[open]").wait_for()
                    assert page.locator("#host-address").inner_text() == f"127.0.0.1:{ws_port}"
                    check_presentation(page)
                    fingerprint = page.locator("#host-fingerprint").inner_text()
                    assert fingerprint.startswith("SHA256:")
                    page.locator("#accept-host").click()
                    page.locator('#status[data-state="connected"]').wait_for(timeout=20000)
                    enter(page, "printf 'WEB%s\\n' 'SSH_OK'; printf '中文%s\\n' '通过'")
                    page.wait_for_function("document.querySelector('#screen').textContent.includes('WEBSSH_OK') && document.querySelector('#screen').textContent.includes('中文通过')")
                    assert page.locator("#password").input_value() == ""
                    assert password not in page.evaluate("JSON.stringify(localStorage)")
                    assert page.locator(".recent-item").count() == 1
                    assert page.locator("#terminal-empty").is_hidden()
                    check_presentation(page)
                    page.locator("#font-larger").click()
                    assert page.evaluate("getComputedStyle(document.documentElement).getPropertyValue('--terminal-font').trim()") == "15px"
                    page.locator("#font-smaller").click()
                    page.locator("#focus-mode").click()
                    assert page.locator(".sidebar").is_hidden()
                    page.locator("#focus-mode").click()
                    assert page.locator(".sidebar").is_visible()
                    page.screenshot(path="/tmp/webssh-client-desktop.png", full_page=True)
                    print("PASS browser ECDH/ECDSA/AES/HMAC, password auth, PTY and UTF-8")

                    page.set_viewport_size({"width": 960, "height": 700})
                    page.wait_for_timeout(200)
                    dims = page.locator("#dimensions").inner_text().split(" × ")
                    enter(page, "printf 'SIZE_'; stty size")
                    page.wait_for_function("expected => document.querySelector('#screen').textContent.includes(expected)", arg=f"SIZE_{dims[1]} {dims[0]}")
                    enter(page, "sleep 30")
                    page.wait_for_timeout(150)
                    page.locator("#terminal-input").focus()
                    page.keyboard.press("Control+c")
                    enter(page, "printf 'CTRL_%s\\n' 'OK'")
                    page.wait_for_function("document.querySelector('#screen').textContent.includes('CTRL_OK')")
                    print("PASS terminal resizing and Ctrl-C")

                    awaitable_probe = """async ({url, password, fingerprint, username}) => {
                      window.probeBytes = 0; window.probeText = ''; window.probeError = null; window.keyExchanges = 0;
                      const decoder = new TextDecoder();
                      window.probe = new WebSSH.SSHClient({url, username, password, cols: 80, rows: 24,
                        onHostKey: info => info.fingerprint === fingerprint,
                        onSecurity: () => window.keyExchanges++,
                        onData: data => { window.probeBytes += data.length; window.probeText = (window.probeText + decoder.decode(data, {stream:true})).slice(-8192); },
                        onClose: info => { window.probeError = info.error ? info.error.message : null; }
                      });
                      await window.probe.connect();
                      await window.probe.requestRekey();
                    }"""
                    page.evaluate(awaitable_probe, {"url": ws_url, "password": password, "fingerprint": fingerprint, "username": USERNAME})
                    page.wait_for_function("window.keyExchanges >= 2 && !window.probe.kexBarrier")
                    page.evaluate("command => window.probe.write(command)", "head -c 3145728 /dev/zero | tr '\\000' 'x'; printf 'FLOW_%s\\n' 'DONE'\r")
                    page.wait_for_function("window.probeBytes >= 3145728 && window.probeText.includes('FLOW_DONE')", timeout=90000)
                    assert page.evaluate("window.keyExchanges") > 2
                    assert page.evaluate("window.probeError") is None
                    page.evaluate("window.probe.close()")
                    print("PASS client/server rekey and >2 MiB SSH channel flow control")

                    page.locator("#disconnect").click()
                    page.locator('#status[data-state="offline"]').wait_for()
                    page.locator("#host").fill("other.example")
                    page.locator(".recent-item").click()
                    assert page.locator("#host").input_value() == "127.0.0.1"
                    assert page.locator("#port").input_value() == str(ws_port)
                    assert page.locator("#password").input_value() == ""
                    requests = []
                    page.on("websocket", lambda ws: requests.append(ws.url))
                    submit(page, ws_url, "incorrect-password")
                    page.wait_for_function("document.querySelector('#feedback').textContent.includes('认证失败')")
                    assert not page.locator("#host-dialog").is_visible()
                    assert requests == [ws_url], requests
                    print("PASS wrong-password rejection and remembered host identity")

                    storage_key = f"webssh.host:127.0.0.1:{ws_port}"
                    page.evaluate("key => localStorage.setItem(key, JSON.stringify('SHA256:changed-test-key'))", storage_key)
                    submit(page, ws_url, password)
                    page.locator("#host-dialog[open]").wait_for()
                    assert page.locator("#host-title").inner_text() == "服务器指纹已变化"
                    page.locator("#reject-host").click()
                    page.locator('#status[data-state="offline"]').wait_for()
                    print("PASS changed-host warning and rejection")

                    tampering_checks(page, ws_url, password, fingerprint)

                    # Retain only the server address in the UI, while choosing
                    # a TLS transport automatically even on an arbitrary port.
                    if shutil.which("openssl"):
                        tls_port = free_port()
                        tls_cert, tls_key = work / "tls.crt", work / "tls.key"
                        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                                        "-keyout", str(tls_key), "-out", str(tls_cert), "-subj", "/CN=localhost",
                                        "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"], check=True, capture_output=True)
                        tls_config = work / "tls-config.json"
                        tls_config.write_text(json.dumps({**json.loads(config.read_text()), "TCPAddr": "", "HTTPAddr": f"127.0.0.1:{tls_port}",
                                                          "TLSCertFile": str(tls_cert), "TLSKeyFile": str(tls_key)}))
                        tls_server = subprocess.Popen([str(binary), "--test-server", str(tls_config)], stdout=log, stderr=log)
                        try:
                            for _ in range(100):
                                try:
                                    with socket.create_connection(("127.0.0.1", tls_port), timeout=0.1):
                                        break
                                except OSError:
                                    time.sleep(0.05)
                            context = browser.new_context(ignore_https_errors=True)
                            tls_page = context.new_page()
                            tls_page.on("pageerror", lambda error: errors.append(str(error)))
                            tls_page.goto(origin)
                            # Pins from the former interface must remain bound
                            # to the server even when its transport changes.
                            tls_page.evaluate("key => localStorage.setItem(key, JSON.stringify('SHA256:old-host-pin'))", f"webssh.host:ws://127.0.0.1:{tls_port}/ssh")
                            attempts = []
                            tls_page.on("websocket", lambda ws: attempts.append(ws.url))
                            submit(tls_page, f"wss://127.0.0.1:{tls_port}/ssh", password)
                            tls_page.locator("#host-dialog[open]").wait_for(timeout=20000)
                            assert tls_page.locator("#host-title").inner_text() == "服务器指纹已变化"
                            check_presentation(tls_page)
                            tls_page.locator("#accept-host").click()
                            tls_page.locator('#status[data-state="connected"]').wait_for(timeout=20000)
                            assert attempts == [f"ws://127.0.0.1:{tls_port}/ssh", f"wss://127.0.0.1:{tls_port}/ssh"], attempts
                            enter(tls_page, "printf 'TLS_%s\\n' 'OK'")
                            tls_page.wait_for_function("document.querySelector('#screen').textContent.includes('TLS_OK')")
                            tls_page.locator("#disconnect").click()
                            context.close()
                            print("PASS host/port-only UI, automatic TLS connection, legacy host pin migration and no authentication retry")
                        finally:
                            tls_server.terminate()
                            tls_server.wait(timeout=8)

                    # A local file loads ordinary scripts without a module server or build tool.
                    file_page = browser.new_page(viewport={"width": 390, "height": 844})
                    file_page.on("pageerror", lambda error: errors.append(str(error)))
                    standalone = work / "ssh-client.html"
                    shutil.copyfile(ROOT / "client/ssh-client.html", standalone)
                    file_page.goto(standalone.as_uri())
                    check_presentation(file_page)
                    file_page.screenshot(path="/tmp/webssh-client-mobile-idle.png", full_page=True)
                    submit(file_page, ws_url, password)
                    file_page.locator("#host-dialog[open]").wait_for()
                    file_page.locator("#accept-host").click()
                    file_page.locator('#status[data-state="connected"]').wait_for(timeout=20000)
                    enter(file_page, "printf 'FILE_%s\\n' 'OK'")
                    file_page.wait_for_function("document.querySelector('#screen').textContent.includes('FILE_OK')")
                    assert file_page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                    check_presentation(file_page)
                    assert file_page.locator(".sidebar").is_hidden()
                    assert file_page.locator(".terminal-panel").bounding_box()["height"] > 600
                    file_page.screenshot(path="/tmp/webssh-client-mobile.png", full_page=True)
                    file_page.locator("#disconnect").click()
                    assert file_page.locator(".sidebar").is_visible()
                    print("PASS file:// standalone client and mobile layout")
                    assert not errors, errors
                    browser.close()
            except Exception:
                log.flush()
                log.seek(0)
                print(log.read())
                raise
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                static.shutdown()


if __name__ == "__main__":
    main()
