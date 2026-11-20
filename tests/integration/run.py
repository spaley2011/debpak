#!/usr/bin/env python3
"""End-to-end check: convert real sample apps, build and install them, run them.

The unit tests stop at the manifest. This goes the rest of the way, with the
real flatpak-builder, the real base apps from Flathub and the real Electron
download, so it needs a Linux machine with flatpak, flatpak-builder and
network access. It installs into your user installation (app IDs under
org.debpak.test) and uninstalls each app again unless --keep is given.

    tests/integration/run.py                    every case the installed tools allow
    tests/integration/run.py --only wine-exe    cases whose name contains this
    tests/integration/run.py --list             show the cases and stop

Extra-data cases serve the sample files from a local web server, so Flatpak
downloads them at install time just as it would from a vendor, and
apply_extra runs debpak-unpack on them for real.

Exit status: 0 if every case that ran passed, 1 otherwise. A summary goes to
stdout and the details to WORK/results.json and one log per case.
"""
from __future__ import annotations

import argparse
import functools
import http.server
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE))
import samples  # noqa: E402

FLATHUB = "https://dl.flathub.org/repo/flathub.flatpakrepo"
ID_PREFIX = "org.debpak.test"

# (case name, sample, extra convert arguments, mode, app id suffix)
CASES = [
    ("deb", "deb", [], "bundle", "Deb"),
    ("deb-extra", "deb", [], "extra-data", "DebExtra"),
    ("run", "run", [], "bundle", "Run"),
    ("run-extra", "run", [], "extra-data", "RunExtra"),
    ("wine-exe", "exe", [], "bundle", "WineExe"),
    ("wine-zip-extra-writable", "exe-zip", ["--writable"], "extra-data", "WineZip"),
    ("wine-nsis", "exe-nsis", ["--exec", "hello.exe"], "bundle", "WineNsis"),
    ("wine-nsis-extra", "exe-nsis", ["--exec", "hello.exe"], "extra-data", "WineNsisExtra"),
    ("wine-msi", "exe-msi", [], "bundle", "WineMsi"),
    ("electron-zip", "electron-zip", [], "bundle", "ElectronZip"),
    ("electron-zip-extra", "electron-zip", [], "extra-data", "ElectronZipExtra"),
    ("electron-nsis-extra", "electron-nsis", [], "extra-data", "ElectronNsis"),
    ("electron-mac-extra", "electron-mac", [], "extra-data", "ElectronMac"),
    ("recipe-install", "exe-zip", [], "recipe", "Recipe"),
]


def sh(cmd: list[str], log, timeout: int = 3600, env: dict | None = None, check: bool = False):
    """Run a command, appending its output to the case log; return the CompletedProcess."""
    log.write(f"\n$ {' '.join(cmd)}\n")
    log.flush()
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                       env={**os.environ, **(env or {})})
    log.write(r.stdout + r.stderr + f"[exit {r.returncode}]\n")
    log.flush()
    if check and r.returncode != 0:
        raise RuntimeError(f"{cmd[0]} {cmd[1] if len(cmd) > 1 else ''} exited {r.returncode}")
    return r


def debpak(*args) -> list[str]:
    return [sys.executable, "-m", "debpak", *args]


def latest_electron() -> str:
    """Return the newest stable Electron release."""
    with urllib.request.urlopen("https://releases.electronjs.org/releases.json", timeout=60) as r:
        for rel in json.load(r):
            if "-" not in rel["version"]:
                return rel["version"]
    raise RuntimeError("no stable Electron release found")


def serve(root: Path) -> str:
    """Serve root over HTTP on 127.0.0.1 in a background thread; return its base URL."""
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(root))
    handler.log_message = lambda *a: None
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{srv.server_address[1]}"


def setup(branch: str, log) -> None:
    """Add Flathub for the user and install the runtimes the cases need."""
    sh(["flatpak", "remote-add", "--user", "--if-not-exists", "flathub", FLATHUB], log, check=True)
    sh(["flatpak", "install", "--user", "-y", "--noninteractive", "flathub",
        f"org.freedesktop.Platform//{branch}", f"org.freedesktop.Sdk//{branch}"], log, check=True)


def smoke(app_id: str, info: dict, log) -> tuple[bool, str]:
    """Run the installed app and check its marker (or exit status)."""
    cmd = ["flatpak", "run", "--user", app_id]
    if shutil.which("xvfb-run"):
        cmd = ["xvfb-run", "-a", *cmd]
    r = sh(cmd, log, timeout=300)
    out = r.stdout + r.stderr
    if "expect" in info:
        ok = info["expect"] in out
        return ok, f"output {'has' if ok else 'lacks'} {info['expect']!r}"
    ok = r.returncode == info["expect_rc"]
    return ok, f"exit status {r.returncode} (wanted {info['expect_rc']})"


def run_case(case, made: dict, work: Path, base_url: str, branch: str, keep: bool) -> dict:
    name, sample, extra, mode, suffix = case
    info = made.get(sample, {"skip": "sample not built"})
    if "skip" in info:
        return {"case": name, "status": "skip", "detail": info["skip"]}
    app_id = f"{ID_PREFIX}.{suffix}"
    out = work / "out" / name
    shutil.rmtree(out, ignore_errors=True)
    src = work / "samples" / info["file"]
    started = time.time()
    with open(work / f"{name}.log", "w") as log:
        try:
            conv = ["convert", str(src), "--app-id", app_id, "-o", str(out), "--anyway",
                    "--runtime", f"org.freedesktop.Platform//{branch}", *extra]
            if "electron" in info:
                conv += ["--electron-version", info["electron"]]
            if mode in ("extra-data", "recipe"):
                conv += ["--mode", "extra-data", "--url", f"{base_url}/{info['file']}"]
            if mode == "recipe":
                conv.append("--no-build")
            r = sh(debpak(*conv), log, env={"PYTHONPATH": str(REPO / "src")})
            if r.returncode != 0:
                return {"case": name, "status": "fail", "detail": f"convert exited {r.returncode}",
                        "seconds": round(time.time() - started)}
            if mode == "recipe":
                coll = work / "collection"
                shutil.rmtree(coll, ignore_errors=True)
                sh(debpak("recipe", "make", str(out), "--to", str(coll)), log, check=True,
                   env={"PYTHONPATH": str(REPO / "src")})
                sh(debpak("install", app_id, "--recipes", str(coll), "--yes"), log, check=True,
                   env={"PYTHONPATH": str(REPO / "src")})
            ok, detail = smoke(app_id, info, log)
            if ok and mode == "extra-data":
                # apply_extra really ran: the unpacked files are in /app/extra
                r = sh(["flatpak", "run", "--user", "--command=ls", app_id, "/app/extra"], log)
                if r.returncode != 0 or not r.stdout.split():
                    ok, detail = False, "/app/extra is empty: apply_extra didn't unpack anything"
            return {"case": name, "status": "pass" if ok else "fail", "detail": detail,
                    "seconds": round(time.time() - started)}
        except (RuntimeError, subprocess.TimeoutExpired) as e:
            return {"case": name, "status": "fail", "detail": str(e), "seconds": round(time.time() - started)}
        finally:
            if not keep:
                sh(debpak("uninstall", app_id), log, env={"PYTHONPATH": str(REPO / "src")})


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--work", default=str(Path.home() / ".cache/debpak-integration"))
    ap.add_argument("--only", action="append", default=[], help="run cases whose name contains this")
    ap.add_argument("--branch", default="25.08", help="runtime branch (default 25.08)")
    ap.add_argument("--electron-version", help="default: the newest stable release")
    ap.add_argument("--keep", action="store_true", help="leave the test apps installed")
    ap.add_argument("--list", action="store_true", help="list the cases and stop")
    args = ap.parse_args(argv)
    cases = [c for c in CASES if not args.only or any(o in c[0] for o in args.only)]
    if args.list:
        for c in cases:
            print(f"{c[0]:<26} sample {c[1]:<14} {c[3]}")
        return 0
    for tool in ("flatpak", "flatpak-builder"):
        if not shutil.which(tool):
            print(f"{tool} isn't installed", file=sys.stderr)
            return 1
    work = Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    with open(work / "setup.log", "w") as log:
        setup(args.branch, log)
    electron = args.electron_version or latest_electron()
    made = samples.build_all(work / "samples", electron)
    base_url = serve(work / "samples")
    results = []
    for case in cases:
        print(f"{case[0]:<26} ...", end=" ", flush=True)
        res = run_case(case, made, work, base_url, args.branch, args.keep)
        results.append(res)
        print(f"{res['status']:<5} {res.get('detail', '')}"
              + (f"  ({res['seconds']} s)" if "seconds" in res else ""), flush=True)
    (work / "results.json").write_text(json.dumps({"electron": electron, "branch": args.branch,
                                                    "results": results}, indent=2) + "\n")
    failed = [r["case"] for r in results if r["status"] == "fail"]
    print(f"\n{sum(r['status'] == 'pass' for r in results)} passed, {len(failed)} failed, "
          f"{sum(r['status'] == 'skip' for r in results)} skipped. Logs in {work}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
