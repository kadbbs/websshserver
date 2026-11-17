"""Package a native Linux build and its licenses without third-party tooling."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
GO = os.environ.get("GO", "go")


def go_output(*args):
    return subprocess.check_output([GO, *args], cwd=ROOT, text=True)


def archive_info(info):
    info.uid = info.gid = info.mtime = 0
    info.uname = info.gname = "root"
    info.mode = 0o755 if info.isdir() or info.mode & 0o111 else 0o644
    return info


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    binary = ROOT / "bin/sshserver"
    if not binary.is_file():
        raise SystemExit("Build the native server first: make release")
    environment = json.loads(go_output("env", "-json", "GOOS", "GOARCH", "GOROOT"))
    build_info = go_output("version", "-m", str(binary))
    target = {parts[1].split("=", 1)[0]: parts[1].split("=", 1)[1]
              for line in build_info.splitlines()
              if len(parts := line.split()) == 2 and parts[0] == "build" and "=" in parts[1]}
    if target.get("GOOS") != "linux" or target.get("CGO_ENABLED") != "1":
        raise SystemExit("Release requires a Linux server built with CGO/PAM")
    if any(target.get(name) != environment[name] for name in ("GOOS", "GOARCH")):
        raise SystemExit("Built server and selected Go target do not match")
    package = "websshserver_" + target["GOOS"] + "_" + target["GOARCH"]
    destination = ROOT / "dist"
    destination.mkdir(exist_ok=True)
    archive = destination / (package + ".tar.gz")

    licenses = [(Path(environment["GOROOT"]) / "LICENSE", "Go/LICENSE")]
    modules = []
    for line in build_info.splitlines():
        parts = line.split()
        if not parts or parts[0] != "dep":
            continue
        path, version = parts[1:3]
        module = json.loads(go_output("list", "-m", "-json", path))
        if module.get("Version") != version or module.get("Replace"):
            raise SystemExit("Module metadata does not match the release binary: " + path)
        directory = Path(module["Dir"])
        found = sorted(file for file in directory.iterdir()
                       if file.is_file() and file.name.upper().startswith(("LICENSE", "COPYING", "NOTICE", "PATENTS")))
        if not any(file.name.upper().startswith(("LICENSE", "COPYING")) for file in found):
            raise SystemExit("Missing third-party license: " + path)
        modules.append(path + " " + version)
        licenses.extend((file, path.replace("/", "_") + "@" + version + "/" + file.name) for file in found)
    notice = ("Third-party components retain their original licenses.\n\n" +
              "Go toolchain: " + build_info.splitlines()[0].split(": ", 1)[-1] + "\n" +
              "\n".join(modules) + "\n").encode()

    with archive.open("wb") as output, gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as tar:
            for relative in ("bin/sshserver", "client/ssh-client.html", "README.md", "LICENSE", "config/pam.d/webssh", "docs"):
                tar.add(ROOT / relative, arcname=package + "/" + relative, filter=archive_info)
            for source, relative in licenses:
                tar.add(source, arcname=package + "/THIRD_PARTY_LICENSES/" + relative, filter=archive_info)
            info = archive_info(tarfile.TarInfo(package + "/THIRD_PARTY_LICENSES/README.txt"))
            info.size = len(notice)
            tar.addfile(info, io.BytesIO(notice))
    shutil.copyfile(ROOT / "client/ssh-client.html", destination / "ssh-client.html")
    assets = sorted([*destination.glob("websshserver_*.tar.gz"), destination / "ssh-client.html"])
    checksums = "".join(sha256(path) + "  " + path.name + "\n" for path in assets)
    (destination / "SHA256SUMS.txt").write_text(checksums)
    print("Packaged " + str(archive.relative_to(ROOT)))
    print("Wrote dist/ssh-client.html and dist/SHA256SUMS.txt")


if __name__ == "__main__":
    main()
