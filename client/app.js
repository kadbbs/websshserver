(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const panel = document.querySelector(".terminal-panel");
  const fields = [$("host"), $("port"), $("username"), $("password")];
  let client = null, activeAttempt = null, pendingTrust = null, hadSession = false;
  let durationTimer = null, startedAt = 0, fontSize = 14;

  function readStorage(key) { try { return JSON.parse(localStorage.getItem(key)); } catch (_) { return null; } }
  function saveStorage(key, value) { try { localStorage.setItem(key, JSON.stringify(value)); } catch (_) {} }
  function connectionRecord(value) {
    let host = String(value.host || "").trim();
    const port = String(value.port || "").trim();
    const username = String(value.username || "").trim();
    if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
    if (!host || /[\s/@?#\\]/.test(host) || host.includes("://")) throw new Error("请输入服务器 IP 或主机名");
    if (!/^\d{1,5}$/.test(port) || Number(port) < 1 || Number(port) > 65535) throw new Error("端口应为 1 到 65535 之间的整数");
    let parsed;
    try { parsed = new URL("ws://" + (host.includes(":") ? "[" + host + "]" : host) + ":" + port + "/ssh"); }
    catch (_) { throw new Error("服务器地址无效，请检查 IP 或主机名"); }
    if (!username || username.length > 128 || /[\x00\r\n]/.test(username)) throw new Error("请输入有效的系统用户名");
    return { host: parsed.hostname.replace(/^\[|\]$/g, ""), port: String(Number(port)), username };
  }
  function address(record) { return (record.host.includes(":") ? "[" + record.host + "]" : record.host) + ":" + record.port; }
  function restoreRecord(value) {
    if (!value || typeof value !== "object") return null;
    try {
      if (!value.host && value.url) {
        const url = new URL(value.url);
        if (!["ws:", "wss:"].includes(url.protocol)) return null;
        const record = connectionRecord({ host: url.hostname, port: url.port || (url.protocol === "wss:" ? 443 : 80), username: value.username });
        saveStorage("webssh.transport:" + address(record), url.protocol);
        return record;
      }
      return connectionRecord(value);
    } catch (_) { return null; }
  }
  function fillConnection(record) {
    $("host").value = record.host; $("port").value = record.port; $("username").value = record.username;
    clearPassword();
  }
  function clearPassword() {
    $("password").value = ""; $("password").type = "password";
    $("toggle-password").setAttribute("aria-label", "显示密码");
    $("toggle-password").setAttribute("aria-pressed", "false");
  }
  const previous = restoreRecord(readStorage("webssh.connection"));
  if (previous) { fillConnection(previous); saveStorage("webssh.connection", previous); }
  let recent = (Array.isArray(readStorage("webssh.recent")) ? readStorage("webssh.recent") : []).map(restoreRecord).filter(Boolean).slice(0, 3);

  function icon(name) {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.classList.add("icon"); svg.setAttribute("aria-hidden", "true");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use"); use.setAttribute("href", "#i-" + name); svg.appendChild(use);
    return svg;
  }
  function renderRecent() {
    $("recent-list").replaceChildren();
    $("recent-empty").hidden = recent.length > 0;
    $("clear-history").hidden = recent.length === 0;
    $("recent-card").dataset.empty = String(recent.length === 0);
    recent.forEach((record) => {
      const button = document.createElement("button"); button.type = "button"; button.className = "recent-item";
      button.disabled = !!activeAttempt;
      button.setAttribute("aria-label", "填入 " + record.username + "@" + address(record));
      const mark = document.createElement("span"); mark.className = "recent-server-icon"; mark.appendChild(icon("server"));
      const details = document.createElement("span"); details.className = "recent-details";
      const host = document.createElement("span"); host.className = "recent-address"; host.textContent = address(record);
      const username = document.createElement("span"); username.className = "recent-username"; username.textContent = record.username;
      details.append(host, username); button.append(mark, details, icon("arrow"));
      button.addEventListener("click", () => { fillConnection(record); $("password").focus(); feedback("已填入连接信息，请输入密码"); });
      $("recent-list").appendChild(button);
    });
  }
  function rememberConnection(record) {
    recent = [record, ...recent.filter((item) => address(item) !== address(record) || item.username !== record.username)].slice(0, 3);
    saveStorage("webssh.recent", recent); renderRecent();
  }
  function feedback(text, error) {
    $("feedback").textContent = text;
    $("feedback").classList.toggle("error", !!error);
    $("feedback-wrap").classList.toggle("error", !!error);
  }
  function setFocusMode(enabled) {
    document.body.classList.toggle("focus-mode", enabled);
    $("focus-mode").setAttribute("aria-pressed", String(enabled));
    const label = enabled ? "展开连接栏" : "收起连接栏";
    $("focus-mode").setAttribute("aria-label", label); $("focus-mode").title = label;
    requestAnimationFrame(() => terminal.fit());
  }
  function state(value) {
    panel.dataset.state = value; $("status").dataset.state = value;
    $("status-text").textContent = { offline: "待连接", connecting: "连接中", connected: "已连接" }[value];
    $("connect-label").textContent = { offline: "连接服务器", connecting: "正在连接", connected: "已连接" }[value];
    $("connect").disabled = value !== "offline";
    fields.forEach((field) => { field.disabled = value !== "offline"; });
    $("toggle-password").disabled = value !== "offline";
    $("terminal-input").disabled = value !== "connected";
    $("disconnect").hidden = value === "offline";
    $("disconnect-label").textContent = value === "connecting" ? "取消" : "断开";
    $("disconnect").title = value === "connecting" ? "取消连接" : "断开连接";
    $("footer-dot").classList.toggle("active", value === "connected");
    $("security-status").textContent = value === "connected" ? "SSH 安全会话" : value === "connecting" ? "正在连接" : hadSession ? "会话已结束" : "等待连接";
    $("terminal-empty").hidden = hadSession && value !== "connecting";
    $("empty-title").textContent = value === "connecting" ? "正在连接服务器" : "终端已就绪";
    $("empty-description").textContent = value === "connecting" ? "正在建立安全会话，请稍候。" : "填写连接信息，进入你的服务器。";
    document.body.classList.toggle("connected", value === "connected");
    document.body.classList.toggle("connecting", value === "connecting");
    document.querySelectorAll(".recent-item").forEach((button) => { button.disabled = value !== "offline"; });
    if (value === "offline") { setFocusMode(false); document.body.classList.remove("show-connection"); }
    requestAnimationFrame(() => terminal.fit());
  }
  function stopTimer() { clearInterval(durationTimer); durationTimer = null; }
  function startTimer() {
    stopTimer(); startedAt = Date.now();
    const tick = () => { const seconds = Math.floor((Date.now() - startedAt) / 1000); $("duration").textContent = [Math.floor(seconds / 3600), Math.floor(seconds / 60) % 60, seconds % 60].map((n) => String(n).padStart(2, "0")).join(":"); };
    tick(); durationTimer = setInterval(tick, 1000);
  }
  function publicError(error) {
    const text = error && error.message || "连接未完成，请重试";
    if (/WebSocket|Origin|TLS/.test(text) || error && error.code === "CONNECTION_FAILED") return "无法连接服务器，请检查地址、端口及服务器访问权限";
    if (/Web Crypto/.test(text)) return "当前页面无法建立安全连接，请通过本地文件或 HTTPS 打开";
    if (/算法|主机密钥类型/.test(text)) return "服务器不支持当前客户端的安全设置";
    return text.replace(/SSH 通道/g, "SSH 会话");
  }
  const terminal = new WebSSH.Terminal($("terminal"), $("screen"), $("terminal-input"), {
    onInput: (data) => { if (client && client.ready) client.write(data); },
    onResize: (cols, rows) => { $("dimensions").textContent = cols + " × " + rows; if (client) client.resize(cols, rows); }
  });

  async function verifyHost({ fingerprint, url }, record) {
    // A server's identity belongs to its host and port, independently of the
    // transport. Retain pins saved by the previous URL-based interface too.
    const key = "webssh.host:" + address(record);
    const oldURLs = [url, ...["ws:", "wss:"].map((protocol) => new URL(protocol + "//" + address(record) + "/ssh").href)];
    const saved = readStorage(key) || oldURLs.map((old) => readStorage("webssh.host:" + old)).find((pin) => typeof pin === "string");
    if (saved === fingerprint) { saveStorage(key, fingerprint); return true; }
    $("host-address").textContent = address(record);
    $("host-fingerprint").textContent = fingerprint;
    $("old-fingerprint").hidden = !saved;
    $("old-fingerprint").textContent = saved ? "原指纹：" + saved : "";
    $("host-title").textContent = saved ? "服务器指纹已变化" : "确认服务器身份";
    $("host-description").textContent = saved ? "这台服务器的身份与上次连接不同。请确认服务器指纹及变更原因后再继续。" : "首次连接此服务器，请将下面的指纹与服务器提供的指纹核对。";
    $("remember-host").checked = true;
    feedback("等待确认服务器身份");
    return new Promise((resolve) => {
      pendingTrust = (accepted) => {
        pendingTrust = null;
        if (accepted && $("remember-host").checked) saveStorage(key, fingerprint);
        $("host-dialog").close(); resolve(accepted);
      };
      $("host-dialog").showModal();
    });
  }
  $("accept-host").addEventListener("click", () => { if (pendingTrust) pendingTrust(true); });
  $("reject-host").addEventListener("click", () => { if (pendingTrust) pendingTrust(false); });
  $("host-dialog").addEventListener("cancel", (event) => { event.preventDefault(); if (pendingTrust) pendingTrust(false); });

  function connectionURLs(record) {
    const remembered = readStorage("webssh.transport:" + address(record));
    const preferred = remembered === "ws:" || remembered === "wss:" ? remembered : ["443", "8443"].includes(record.port) ? "wss:" : "ws:";
    const protocols = location.protocol === "https:" ? ["wss:"] : [preferred, preferred === "wss:" ? "ws:" : "wss:"];
    return protocols.map((protocol) => new URL(protocol + "//" + address(record) + "/ssh").href);
  }
  $("connect-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (activeAttempt) return;
    let record;
    try { record = connectionRecord({ host: $("host").value, port: $("port").value, username: $("username").value }); }
    catch (error) { feedback(error.message, true); return; }
    let password = $("password").value;
    if (!password) { feedback("请输入系统登录密码", true); $("password").focus(); return; }
    saveStorage("webssh.connection", record);
    const attempt = { cancelled: false, phase: "connecting" };
    activeAttempt = attempt; hadSession = false; stopTimer(); $("duration").textContent = "00:00:00";
    $("session-name").textContent = record.username + "@" + record.host;
    terminal.reset(); feedback("正在连接 " + address(record) + "…"); state("connecting");
    document.body.classList.remove("show-connection");
    const urls = connectionURLs(record);
    try {
      for (let index = 0; index < urls.length; index++) {
        if (attempt.cancelled || activeAttempt !== attempt) return;
        const current = new WebSSH.SSHClient({
          url: urls[index], username: record.username, password, cols: terminal.cols, rows: terminal.rows,
          transportTimeout: 7000,
          onHostKey: (info) => verifyHost(info, record),
          onData: (data) => terminal.write(data),
          onBanner: (text) => terminal.write(text.replace(/\n/g, "\r\n")),
          onClose: ({ error, exitStatus, signal }) => {
            if (client !== current) return;
            if (pendingTrust) pendingTrust(false);
            if (attempt.phase === "connecting") return;
            activeAttempt = null; stopTimer(); clearPassword(); state("offline");
            const text = error ? publicError(error) : signal ? "会话已结束：" + signal : exitStatus !== undefined ? "会话已结束，退出状态 " + exitStatus : "连接已断开";
            feedback(text, !!error);
          }
        });
        client = current;
        try { await current.connect(); }
        catch (error) {
          current.close();
          if (attempt.cancelled || activeAttempt !== attempt) return;
          // Only retry failed transport establishment. Never retry rejected
          // credentials, host trust, signatures or an established SSH session.
          if (error.code === "CONNECTION_FAILED" && index + 1 < urls.length) continue;
          throw error;
        }
        if (current.closed || attempt.cancelled || activeAttempt !== attempt) return;
        attempt.phase = "connected"; hadSession = true;
        saveStorage("webssh.transport:" + address(record), new URL(urls[index]).protocol);
        rememberConnection(record); clearPassword(); startTimer();
        feedback("已连接到 " + address(record)); state("connected"); terminal.focus();
        requestAnimationFrame(() => { terminal.fit(); current.resize(terminal.cols, terminal.rows); });
        return;
      }
    } catch (error) { if (!attempt.cancelled && activeAttempt === attempt) feedback(publicError(error), true); }
    finally {
      password = "";
      if (activeAttempt === attempt && attempt.phase === "connecting") { activeAttempt = null; clearPassword(); state("offline"); }
    }
  });

  $("disconnect").addEventListener("click", () => {
    if (activeAttempt && activeAttempt.phase === "connecting") {
      activeAttempt.cancelled = true; activeAttempt = null;
      if (pendingTrust) pendingTrust(false);
      if (client) client.close(); clearPassword(); state("offline"); feedback("已取消连接");
    } else if (client) client.close();
  });
  $("toggle-password").addEventListener("click", () => {
    const visible = $("password").type === "password";
    $("password").type = visible ? "text" : "password";
    $("toggle-password").setAttribute("aria-label", visible ? "隐藏密码" : "显示密码");
    $("toggle-password").setAttribute("aria-pressed", String(visible));
  });
  $("clear-history").addEventListener("click", () => { recent = []; saveStorage("webssh.recent", recent); renderRecent(); });
  $("clear").addEventListener("click", () => { terminal.clear(); if (client && client.ready) client.write("\x0c"); terminal.focus(); });
  $("copy").addEventListener("click", async () => {
    const selection = getSelection();
    if (!selection || !selection.rangeCount || !$("screen").contains(selection.getRangeAt(0).commonAncestorContainer) || !String(selection)) { feedback("请先选中要复制的终端文本"); return; }
    try { await navigator.clipboard.writeText(String(selection)); feedback("已复制所选文本"); }
    catch (_) { feedback("请使用系统复制快捷键复制所选文本"); }
  });
  $("fullscreen").addEventListener("click", async () => {
    try { if (document.fullscreenElement) await document.exitFullscreen(); else await panel.requestFullscreen(); }
    catch (_) { feedback("此浏览器暂不支持全屏模式"); }
  });
  function changeFont(delta) {
    fontSize = Math.max(12, Math.min(20, fontSize + delta));
    document.documentElement.style.setProperty("--terminal-font", fontSize + "px");
    document.documentElement.style.setProperty("--terminal-line", (fontSize + 9) + "px");
    $("font-smaller").disabled = fontSize === 12; $("font-larger").disabled = fontSize === 20;
    terminal.fit();
  }
  $("font-smaller").addEventListener("click", () => changeFont(-1));
  $("font-larger").addEventListener("click", () => changeFont(1));
  $("focus-mode").addEventListener("click", () => setFocusMode(!document.body.classList.contains("focus-mode")));
  function focusConnection() {
    setFocusMode(false); document.body.classList.add("show-connection");
    document.querySelector(".connection-card").scrollIntoView({ block: "nearest" });
    if (!$("host").disabled) { $("host").focus(); $("host").select(); }
    else $("disconnect").focus();
  }
  $("focus-connection").addEventListener("click", focusConnection);
  document.querySelector(".brand").addEventListener("click", (event) => { event.preventDefault(); focusConnection(); });
  $("shortcuts").addEventListener("click", () => $("shortcuts-dialog").showModal());
  $("close-shortcuts").addEventListener("click", () => $("shortcuts-dialog").close());
  const mac = /Mac|iPhone|iPad/.test(navigator.platform);
  $("connect-modifier").textContent = mac ? "⌘" : "Ctrl"; $("shortcut-modifier").textContent = mac ? "⌘" : "Ctrl";
  window.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k" && !document.querySelector("dialog[open]")) { event.preventDefault(); event.stopPropagation(); focusConnection(); }
    else if (event.key === "?" && !/INPUT|TEXTAREA/.test(event.target.tagName) && !event.target.isContentEditable && !document.querySelector("dialog[open]")) { event.preventDefault(); $("shortcuts-dialog").showModal(); }
  }, true);
  document.querySelectorAll("[data-key]").forEach((button) => {
    button.addEventListener("click", () => { if (client && client.ready) client.write(JSON.parse('"' + button.dataset.key + '"')); terminal.focus(); });
  });
  window.addEventListener("beforeunload", () => { stopTimer(); if (client) client.close(); });
  renderRecent(); state("offline");
})();
