#!/usr/bin/env python3
"""Run debpak on the apps in apps.json and write a report. Start it through run.sh, which puts it in tmux.

    tests/compat/run.sh --check                       look up every download link, nothing else
    tests/compat/run.sh --send-to USER@HOST:DIR       the full run, then copy report.txt there
    tests/compat/run.sh --only notion --redo          one app again

Each app is looked up, downloaded, converted, built and installed, started on
a virtual screen (with a screenshot), then uninstalled. Everything goes to
~/debpak-compat (DEBPAK_COMPAT_DIR): results.json, report.txt, logs/, shots/
and downloads/. Apps already in results.json are skipped on the next run, so
an interrupted run picks up where it stopped; --retry redoes the ones that
didn't pass and --redo redoes everything.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / "src"))

from debpak import net, recipes  # noqa: E402

WORK = Path(os.environ.get("DEBPAK_COMPAT_DIR", Path.home() / "debpak-compat"))
SECONDS = {"wine": 90, "electron": 60}            # time to start; everything else gets 45
PASS = {"works", "exited", "refused-expected"}
MEANING = {
    "works": "built, installed, and still running when the time was up",
    "exited": "built and installed; exited cleanly before the time was up (fine for command-line tools)",
    "refused-expected": "debpak declined it, as it should (system services)",
    "crashed": "built and installed, but exited with an error",
    "refused": "debpak declined it: see the blockers",
    "converted-unexpectedly": "debpak converted an app it should have declined",
    "build-failed": "debpak wrote a manifest but flatpak-builder failed",
    "convert-error": "debpak stopped with an error before building",
    "on-flathub": "debpak found it on Flathub (the catalog shouldn't list it)",
    "download-failed": "the file couldn't be downloaded",
    "lookup-failed": "the catalog's link or version check didn't work (a catalog problem, not debpak's)",
}


# ------------------------------------------------------------------ helpers

def log(msg: str = "") -> None:
    print(msg, flush=True)


def app_id(key: str) -> str:
    part = re.sub(r"[^A-Za-z0-9_]", "_", key)
    return "org.debpak.compat." + ("x" + part if part[0].isdigit() else part)


def debpak(*argv: str, log_to: Path, timeout: float, cwd: Path | None = None) -> int:
    """Run debpak from this checkout; append its output to log_to; return its exit status (124 on timeout)."""
    env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
    with open(log_to, "a") as f:
        f.write(f"\n$ debpak {' '.join(argv)}\n")
        f.flush()
        try:
            return subprocess.run([sys.executable, "-m", "debpak", *argv], stdout=f, stderr=subprocess.STDOUT,
                                  env=env, cwd=cwd, timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            f.write(f"\n[timed out after {timeout:.0f}s]\n")
            return 124


def tail(path: Path, n: int = 40) -> str:
    try:
        lines = path.read_text("utf-8", "replace").splitlines()
    except OSError:
        return ""
    return "\n".join(lines[-n:])


def save_json(path: Path, data) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1))
    tmp.replace(path)


# ------------------------------------------------------------------ steps

def lookup(app: dict) -> tuple[str, str]:
    """Return (download URL or snap:NAME, version)."""
    src = app["source"]
    if src["type"] == "snap":
        return f"snap:{src['name']}", "stable"
    if src["type"] == "url":
        return recipes.resolve_redirect(src["url"]), "latest"
    return recipes.find_latest(src)


def download(app: dict, url: str, dest_dir: Path, logf: Path) -> Path:
    """Download into dest_dir (kept between runs) and return the file."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    if url.startswith("snap:"):
        for old in dest_dir.glob("*.snap"):
            old.unlink()
        with open(logf, "a") as f:
            r = subprocess.run(["snap", "download", url[5:], f"--target-directory={dest_dir}"],
                               stdout=f, stderr=subprocess.STDOUT, timeout=1800)
        snaps = sorted(dest_dir.glob("*.snap"))
        if r.returncode or not snaps:
            raise RuntimeError(f"snap download {url[5:]} failed (see the log)")
        return snaps[-1]
    name = urllib.parse.unquote(Path(urllib.parse.urlparse(url).path).name) or f"{app['key']}.download"
    dest = dest_dir / name
    marker = dest_dir / ".url"
    if dest.is_file() and dest.stat().st_size and marker.is_file() and marker.read_text() == url:
        return dest
    for old in dest_dir.iterdir():
        if old.is_file():
            old.unlink()
    part = dest.with_name(dest.name + ".part")
    with net.urlopen(url, timeout=120) as r, open(part, "wb") as f:
        shutil.copyfileobj(r, f, 1 << 20)
    part.replace(dest)
    marker.write_text(url)
    return dest


def free_display() -> int:
    for n in range(90, 200):
        if not Path(f"/tmp/.X{n}-lock").exists() and not Path(f"/tmp/.X11-unix/X{n}").exists():
            return n
    raise RuntimeError("no free X display number")


def screenshot(display: int, out: Path) -> bool:
    env = {**os.environ, "DISPLAY": f":{display}"}
    if shutil.which("import"):
        cmd = ["import", "-window", "root", str(out)]
    elif shutil.which("xwd") and (shutil.which("magick") or shutil.which("convert")):
        conv = shutil.which("magick") or shutil.which("convert")
        cmd = ["sh", "-c", f"xwd -root -silent | {conv} xwd:- png:{out}"]
    else:
        return False
    try:
        return subprocess.run(cmd, env=env, capture_output=True, timeout=30).returncode == 0 and out.is_file()
    except subprocess.TimeoutExpired:
        return False


def run_app(fid: str, seconds: int, logf: Path, shot: Path) -> tuple[str, str]:
    """Start the app on its own virtual screen; return (status, note)."""
    display = free_display()
    xvfb = subprocess.Popen(["Xvfb", f":{display}", "-screen", "0", "1280x800x24", "-nolisten", "tcp"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(2)
        env = {k: v for k, v in os.environ.items() if k not in ("WAYLAND_DISPLAY",)}
        env["DISPLAY"] = f":{display}"
        with open(logf, "a") as f:
            f.write(f"\n$ flatpak run --user {fid}   (DISPLAY=:{display}, {seconds}s)\n")
            f.flush()
            proc = subprocess.Popen(["flatpak", "run", "--user", fid], stdout=f, stderr=subprocess.STDOUT,
                                    env=env, start_new_session=True)
            try:
                code = proc.wait(timeout=max(5, seconds - 5))
            except subprocess.TimeoutExpired:
                code = None
            took = screenshot(display, shot)
            if code is None:
                try:
                    code = proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    code = None
            subprocess.run(["flatpak", "kill", fid], capture_output=True)
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
        shot_note = "" if took else " (no screenshot)"
        if code is None:
            return "works", f"running after {seconds}s{shot_note}"
        if code == 0:
            return "exited", f"exited cleanly{shot_note}"
        return "crashed", f"exited with status {code}: " + (tail(logf, 1) or "no output")[:200]
    finally:
        xvfb.terminate()
        try:
            xvfb.wait(timeout=10)
        except subprocess.TimeoutExpired:
            xvfb.kill()


def classify_convert(code: int, logf: Path, expect: str) -> tuple[str, str]:
    text = logf.read_text("utf-8", "replace") if logf.is_file() else ""
    if code == 0:
        return ("converted-unexpectedly", "converted and built") if expect == "refused" else ("built", "")
    if code == 4:
        m = re.search(r"already on Flathub as (\S+?);", text)
        return "on-flathub", m.group(1) if m else ""
    if code == 2:
        blockers = re.findall(r"x \[blocker\] (.+)", text)
        note = "; ".join(dict.fromkeys(blockers))[:300] or (tail(logf, 1)[:200])
        return ("refused-expected" if expect == "refused" else "refused"), note
    if code == 124:
        return "build-failed", "timed out"
    errors = re.findall(r"^(?:Error: |debpak: error: )(.+)$", text, re.M)
    if "Building and installing" in text:
        return "build-failed", (errors[-1] if errors else f"exit {code}")[:300]
    return "convert-error", (errors[-1] if errors else tail(logf, 1) or f"exit {code}")[:300]


def cleanup(fid: str, logf: Path) -> None:
    debpak("uninstall", fid, "--delete-data", "--delete-build", log_to=logf, timeout=300)
    if subprocess.run(["flatpak", "info", "--user", fid], capture_output=True).returncode == 0:
        subprocess.run(["flatpak", "uninstall", "--user", "-y", "--delete-data", fid], capture_output=True)
    # flatpak-builder's cache holds every app it built; keep only its source downloads
    for d in ("cache", "build", "rofiles", "checksums"):
        shutil.rmtree(WORK / ".flatpak-builder" / d, ignore_errors=True)


def test_one(app: dict) -> dict:
    key, fid = app["key"], app_id(app["key"])
    logf = WORK / "logs" / f"{key}.log"
    logf.write_text(f"{app['name']} ({app['route']}): {app['why']}\n")
    res = {"key": key, "name": app["name"], "route": app["route"], "app_id": fid,
           "started": dt.datetime.now().isoformat(timespec="seconds"), "times": {}}
    t = time.time()
    try:
        url, version = lookup(app)
    except Exception as e:                                   # noqa: BLE001 - recorded, not raised
        res.update(status="lookup-failed", note=str(e)[:300])
        return res
    res.update(url=url, version=version)
    res["times"]["lookup"] = round(time.time() - t)
    t = time.time()
    try:
        f = download(app, url, WORK / "downloads" / key, logf)
    except Exception as e:                                   # noqa: BLE001
        res.update(status="download-failed", note=str(e)[:300])
        return res
    res.update(file=f.name, size=f.stat().st_size)
    res["times"]["download"] = round(time.time() - t)
    t = time.time()
    out = WORK / "out" / key
    shutil.rmtree(out, ignore_errors=True)
    code = debpak("convert", str(f), "--app-id", fid, "-o", str(out), *app.get("args", []),
                  log_to=logf, timeout=3600, cwd=WORK)
    res["times"]["convert"] = round(time.time() - t)
    status, note = classify_convert(code, logf, app.get("expect", "runs"))
    if status == "built" or status == "converted-unexpectedly":
        t = time.time()
        shot = WORK / "shots" / f"{key}.png"
        run_status, note = run_app(fid, app.get("seconds", SECONDS.get(app["route"], 45)), logf, shot)
        if status == "built":
            status = run_status
        if shot.is_file():
            res["shot"] = str(shot.relative_to(WORK))
        res["times"]["run"] = round(time.time() - t)
    res.update(status=status, note=note)
    cleanup(fid, logf)
    return res


# ------------------------------------------------------------------ report

def commit() -> str:
    r = subprocess.run(["git", "-C", str(REPO), "log", "-1", "--format=%h %s"], capture_output=True, text=True)
    return r.stdout.strip() or "?"


def render(results: dict, apps: list[dict]) -> str:
    order = [a["key"] for a in apps if a["key"] in results]
    rows = [results[k] for k in order]
    passed = [r for r in rows if r["status"] in PASS]
    lines = [f"debpak compatibility run, {dt.datetime.now():%Y-%m-%d %H:%M} on {socket.gethostname()}",
             f"debpak:  {commit()}",
             f"result:  {len(passed)} of {len(rows)} passed ({len(apps) - len(rows)} not run yet)", ""]
    by_route: dict[str, list] = {}
    for r in rows:
        by_route.setdefault(r["route"], []).append(r)
    lines.append("by route:  " + ",  ".join(f"{route} {sum(r['status'] in PASS for r in rs)}/{len(rs)}"
                                            for route, rs in by_route.items()))
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    lines.append("by status: " + ",  ".join(f"{s} {n}" for s, n in sorted(counts.items(), key=lambda x: -x[1])))
    lines += ["", f"{'':2}{'app':<28}{'route':<10}{'status':<24}{'version':<16}{'mins':>5}  note"]
    for r in rows:
        mins = sum(r.get("times", {}).values()) / 60
        mark = "ok" if r["status"] in PASS else "!!"
        lines.append(f"{mark:2}{r['name'][:27]:<28}{r['route']:<10}{r['status']:<24}"
                     f"{str(r.get('version', ''))[:15]:<16}{mins:5.1f}  {r.get('note', '')[:110]}")
    lines += ["", "statuses:"] + [f"  {s:<24}{m}" for s, m in MEANING.items() if s in counts]
    for r in rows:
        if r["status"] in PASS:
            continue
        lines += ["", f"===== {r['name']} ({r['route']}): {r['status']}",
                  f"url:  {r.get('url', '-')}", f"note: {r.get('note', '')}", ""]
        lines.append(tail(WORK / "logs" / f"{r['key']}.log", 45))
    shots = [r for r in rows if r.get("shot")]
    if shots:
        lines += ["", f"screenshots ({len(shots)}) are in {WORK / 'shots'}"]
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ main

def preflight(need_run: bool) -> list[str]:
    missing = [t for t in ("flatpak", "flatpak-builder", "Xvfb") if need_run and not shutil.which(t)]
    if need_run and not (shutil.which("import") or shutil.which("xwd")):
        log("note: no screenshot tool (sudo apt install imagemagick), so there won't be screenshots")
    return missing


def can_send(dest: str) -> bool:
    host = dest.split(":", 1)[0]
    return subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host, "true"],
                          capture_output=True).returncode == 0


def send(report: Path, dest: str) -> None:
    r = subprocess.run(["scp", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", str(report), dest],
                       capture_output=True, text=True)
    if r.returncode == 0:
        log(f"Sent {report.name} to {dest}")
    else:
        log(f"Couldn't send the report to {dest}: {r.stderr.strip()}")
        log(f"It's at {report}; copy it with:  scp {socket.gethostname()}:{report} .")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="only look up each app's download link")
    ap.add_argument("--only", action="append", default=[], metavar="KEY", help="only these apps (repeatable)")
    ap.add_argument("--redo", action="store_true", help="test apps again even if results.json has them")
    ap.add_argument("--retry", action="store_true", help="test again the apps that didn't pass")
    ap.add_argument("--send-to", metavar="USER@HOST:DIR", help="copy report.txt there with scp at the end")
    ap.add_argument("--catalog", default=str(HERE / "apps.json"))
    args = ap.parse_args(argv)

    apps = json.loads(Path(args.catalog).read_text())["apps"]
    unknown = set(args.only) - {a["key"] for a in apps}
    if unknown:
        log(f"unknown app keys: {', '.join(sorted(unknown))}")
        return 2
    todo = [a for a in apps if not args.only or a["key"] in args.only]
    for d in ("logs", "shots", "downloads", "out"):
        (WORK / d).mkdir(parents=True, exist_ok=True)

    if args.check:
        bad = 0
        for i, app in enumerate(todo, 1):
            try:
                url, version = lookup(app)
                log(f"[{i:2}/{len(todo)}] ok    {app['key']:<16} {version:<14} {url}")
            except Exception as e:                           # noqa: BLE001
                bad += 1
                log(f"[{i:2}/{len(todo)}] FAIL  {app['key']:<16} {str(e)[:150]}")
        log(f"\n{len(todo) - bad} of {len(todo)} links found")
        return 1 if bad else 0

    missing = preflight(True)
    if missing:
        log(f"missing: {', '.join(missing)}  (sudo apt install flatpak flatpak-builder xvfb)")
        return 2
    if args.send_to and not can_send(args.send_to):
        log(f"warning: can't reach {args.send_to.split(':')[0]} over SSH without a password, so the report "
            "won't be sent at the end. To fix it, run these once, then start again:\n"
            "  ssh-keygen -t ed25519            (press Enter at each question)\n"
            f"  ssh-copy-id {args.send_to.split(':')[0]}\n"
            "Starting in 20 seconds anyway; Ctrl+C to stop.")
        time.sleep(20)

    results_path = WORK / "results.json"
    results = json.loads(results_path.read_text()) if results_path.is_file() else {}
    report = WORK / "report.txt"
    started = time.time()
    done = 0
    try:
        for i, app in enumerate(todo, 1):
            prev = results.get(app["key"])
            if prev and not args.redo and not (args.retry and prev["status"] not in PASS):
                continue
            log(f"[{i:2}/{len(todo)}] {app['name']} ({app['route']}) ...")
            res = test_one(app)
            results[app["key"]] = res
            save_json(results_path, results)
            report.write_text(render(results, apps))
            done += 1
            mins = (time.time() - started) / 60
            log(f"        {res['status']}: {res.get('note', '')[:120]}   ({mins:.0f} min so far)")
    except KeyboardInterrupt:
        log("\nStopped. Finished apps are saved; run the same command to continue.")
    report.write_text(render(results, apps))
    log(f"\nTested {done} app(s) this run. Report: {report}")
    if args.send_to:
        send(report, args.send_to)
    return 0


if __name__ == "__main__":
    sys.exit(main())
