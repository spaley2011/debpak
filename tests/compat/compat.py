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
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / "src"))

from debpak import net, recipes  # noqa: E402

WORK = Path(os.environ.get("DEBPAK_COMPAT_DIR", Path.home() / "debpak-compat"))
SECONDS = {"wine": 90, "electron": 60}            # time to start; everything else gets 45
# more apps at once than the machine has cores start more slowly; main() scales the times by this
WAIT_FACTOR = 1.0
PASS = {"works", "exited", "refused-expected"}
MEANING = {
    "works": "built, installed, and showing a window with no error when the time was up",
    "error-dialog": "running, but showing an error or printing a fatal error (missing runtime, crash dialog)",
    "no-window": "running, but with no visible window when the time was up",
    "exited": "a command-line tool that ran and exited cleanly",
    "quit": "a GUI app that exited cleanly without showing a window (a failure)",
    "refused-expected": "debpak declined it, as it should, for the expected reason (a system service, driver or the like)",
    "crashed": "built and installed, but exited with an error",
    "refused": "debpak declined it: see the blockers",
    "converted-unexpectedly": "debpak converted an app it should have declined",
    "build-failed": "debpak wrote a manifest but flatpak-builder failed",
    "convert-error": "debpak stopped with an error before building",
    "on-flathub": "debpak found it on Flathub (the catalog shouldn't list it)",
    "download-failed": "the file couldn't be downloaded",
    "lookup-failed": "the catalog's link or version check didn't work (a catalog problem, not debpak's)",
    "error": "the test itself crashed (a compat.py bug, not a result)",
}


# ------------------------------------------------------------------ helpers

_print_lock = threading.Lock()


def log(msg: str = "") -> None:
    with _print_lock:
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
    path = Path(urllib.parse.urlparse(url).path)
    # SourceForge links end in /download after the file's name
    name = urllib.parse.unquote((path.parent if path.name == "download" else path).name) or f"{app['key']}.download"
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


_displays: set[int] = set()
_display_lock = threading.Lock()


def free_display() -> int:
    """Claim a display number no other worker or X server is using; release_display gives it back."""
    with _display_lock:
        for n in range(90, 200):
            if n not in _displays and not Path(f"/tmp/.X{n}-lock").exists() \
                    and not Path(f"/tmp/.X11-unix/X{n}").exists():
                _displays.add(n)
                return n
    raise RuntimeError("no free X display number")


def release_display(n: int) -> None:
    with _display_lock:
        _displays.discard(n)


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


# A process that's still running proves little: a crash dialog or a missing-runtime message keeps
# it alive too. These look at the window titles and the app's own output.
ERROR_TITLE = re.compile(r"(?i)\berror\b|program error|unhandled|exception|crash|\.net (runtime|framework|desktop)|"
                         r"install \.net|wine (mono|gecko) installer|not responding|\bmissing\b|cannot be (loaded|opened|found)|"
                         r"\bfailed\b")
FATAL_OUTPUT = re.compile(r"Unhandled exception|Unhandled page fault|TypeInitializationException|"
                          r"DllNotFoundException|Could not load file or assembly|You must install (or update )?\.NET|"
                          r"A JavaScript error occurred|core dumped|Segmentation fault|"
                          r"wine: could not load|err:mscoree:\S+ (?:Wine Mono is not installed|.*not found)")


def visible_windows(display: int) -> list[str] | None:
    """Titles of the visible windows on the display, or None if there's no tool to ask (xdotool, xwininfo)."""
    env = {**os.environ, "DISPLAY": f":{display}"}
    try:
        if shutil.which("xdotool"):
            ids = subprocess.run(["xdotool", "search", "--onlyvisible", "--name", ""], env=env,
                                 capture_output=True, text=True, timeout=15).stdout.split()
            names = [subprocess.run(["xdotool", "getwindowname", i], env=env, capture_output=True, text=True,
                                    timeout=15).stdout.strip() for i in ids[:40]]
            return [n for n in names if n]
        if shutil.which("xwininfo"):
            out = subprocess.run(["xwininfo", "-root", "-tree"], env=env, capture_output=True, text=True,
                                 timeout=15).stdout
            # top-level windows with a title and a real size (xwininfo can't tell mapped ones apart)
            return [m.group(1) for m in re.finditer(r'^\s{5}0x[0-9a-f]+ "([^"]+)": .*?\s(\d+)x(\d+)\+', out, re.M)
                    if int(m.group(2)) >= 80 and int(m.group(3)) >= 40]
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def judge(running: bool, code: int | None, titles: list[str] | None, output: str, cli: bool,
          tray: bool = False) -> tuple[str, str]:
    """Decide the run status from what was on screen and what the app printed."""
    fatal = FATAL_OUTPUT.search(output)
    bad = [t for t in titles or [] if ERROR_TITLE.search(t)]
    shown = f"windows: {'; '.join(titles)[:150]}" if titles else ""
    if bad:
        return "error-dialog", f"window says: {'; '.join(bad)[:200]}"
    if fatal:
        line = next((ln for ln in output.splitlines() if fatal.group(0) in ln), fatal.group(0))
        return ("error-dialog" if running or code == 0 else "crashed"), line.strip()[:200]
    if not running:
        if code == 0 and cli:
            return "exited", "exited cleanly"
        if code == 0:
            # a GUI app that quit without leaving a window hasn't worked, whatever its exit status
            return "quit", "exited cleanly without showing a window" + (f" ({shown})" if shown else "")
        return "crashed", f"exited with status {code}: " + (output.strip().splitlines() or ["no output"])[-1][:200]
    if titles is not None and not titles and not cli:
        if tray:
            return "works", "running in the tray (no window, as expected)"
        return "no-window", "still running, but no visible window"
    return "works", shown or "still running (no window tool to check what it shows)"


SETTLED_SECONDS = 30         # a long first start (a runtime install) ends once a window has been up this long


def wait_for_start(proc: subprocess.Popen, display: int, seconds: int) -> int | None:
    """Wait up to seconds for the app; return its exit code, or None if it's still running.

    A long wait is for a first start that installs a runtime, which can take
    up to twenty minutes; once the same windows have been showing for
    SETTLED_SECONDS, the app is up and there's no reason to wait longer.
    """
    deadline = time.time() + max(5, seconds - 5)
    if seconds <= 120:
        try:
            return proc.wait(timeout=max(5, seconds - 5))
        except subprocess.TimeoutExpired:
            return None
    shown, since = None, None
    while time.time() < deadline:
        try:
            return proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        titles = [t for t in visible_windows(display) or [] if t != "Wine"]   # "Wine": the prefix being set up
        if titles and titles == shown:
            if time.time() - since >= SETTLED_SECONDS:
                return None
        else:
            shown, since = titles, time.time()
    return None


def run_app(fid: str, seconds: int, logf: Path, shot: Path, cli: bool = False, tray: bool = False,
            winedebug: str | None = None) -> tuple[str, str]:
    """Start the app on its own virtual screen; return (status, note)."""
    display = free_display()
    xvfb = subprocess.Popen(["Xvfb", f":{display}", "-screen", "0", "1280x800x24", "-nolisten", "tcp"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wm = None
    try:
        time.sleep(2)
        # apps count on a window manager to hold windows to their size limits: without one,
        # MEGAsync's dialogs stay 1x1 (see miniwm.py)
        wm = subprocess.Popen([sys.executable, "-I", str(HERE / "miniwm.py")],
                              env={**os.environ, "DISPLAY": f":{display}"},
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        env = {k: v for k, v in os.environ.items() if k not in ("WAYLAND_DISPLAY",)}
        env["DISPLAY"] = f":{display}"
        # the app must draw on the virtual X screen. Without these, flatpak finds the desktop's
        # wayland-0 socket, so --socket=fallback-x11 grants no X11, and a Qt app started from
        # an SSH session (XDG_SESSION_TYPE=tty) looks for X11 and aborts
        env["WAYLAND_DISPLAY"] = "debpak-compat-no-wayland"
        env["XDG_SESSION_TYPE"] = "x11"
        with open(logf, "a") as f:
            f.write(f"\n$ flatpak run --user {fid}   (DISPLAY=:{display}, {seconds}s)\n")
            f.flush()
            # and inside the sandbox the made-up name mustn't send apps looking for Wayland
            # (kitty: "Wayland: Failed to connect to display", then "GLFW initialization failed")
            extra = ["--unset-env=WAYLAND_DISPLAY"] + ([f"--env=WINEDEBUG={winedebug}"] if winedebug else [])
            proc = subprocess.Popen(["flatpak", "run", "--user", *extra, fid], stdout=f, stderr=subprocess.STDOUT,
                                    env=env, start_new_session=True)
            code = wait_for_start(proc, display, seconds)
            took = screenshot(display, shot)
            titles = visible_windows(display)
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
        run_output = logf.read_text("utf-8", "replace").split(f"$ flatpak run --user {fid}", 1)[-1]
        status, note = judge(code is None, code, titles, run_output, cli, tray)
        return status, note + ("" if took else " (no screenshot)")
    finally:
        if wm:
            wm.kill()
            wm.wait()
        xvfb.terminate()
        try:
            xvfb.wait(timeout=10)
        except subprocess.TimeoutExpired:
            xvfb.kill()
        release_display(display)


# what a correct refusal is for: something a Flatpak can't do, not a gap in debpak
EXPECTED_REFUSAL = re.compile(r"system service|daemon|kernel|driver|wine-platform|needs root", re.I)


def classify_convert(code: int, logf: Path, expect: str) -> tuple[str, str]:
    text = logf.read_text("utf-8", "replace") if logf.is_file() else ""
    if code == 0:
        return ("converted-unexpectedly", "converted and built") if expect == "refused" else ("built", "")
    if code == 4:
        m = re.search(r"already on Flathub as (\S+?);", text)
        return "on-flathub", m.group(1) if m else ""
    if code == 2:
        blockers = re.findall(r"^\s+x (?:\[blocker\] )?(.+)$", text, re.M)
        note = "; ".join(dict.fromkeys(blockers))[:300] or (tail(logf, 1)[:200])
        if expect == "refused" and any(EXPECTED_REFUSAL.search(b) for b in blockers):
            return "refused-expected", note
        if expect == "refused":
            note = "refused, but not for the expected reason: " + (note or "INCOMPLETE (libraries missing)")
        return "refused", note
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


FIRST_START_INSTALL_SECONDS = 1200     # winetricks: dotnet48 alone can take ten minutes


def test_one(app: dict, winedebug: str | None = None) -> dict:
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
    # a run that was stopped can leave the app's data behind, and a Wine prefix from it
    # would skip the first-start setup this test is meant to exercise
    shutil.rmtree(Path.home() / ".var/app" / fid, ignore_errors=True)
    cwd = WORK / "work" / key          # flatpak-builder keeps its state in .flatpak-builder here
    shutil.rmtree(cwd, ignore_errors=True)
    cwd.mkdir(parents=True)
    args = [*app.get("args", [])]
    if "--anyway" not in args:          # the vendor's package is what's under test, Flathub or not
        args.append("--anyway")
    for attempt in range(3):
        mark = logf.stat().st_size
        code = debpak("convert", str(f), "--app-id", fid, "-o", str(out), *args,
                      log_to=logf, timeout=1500, cwd=cwd)
        # flatpak installs running side by side can trip over each other's temporary
        # remotes ("Remote ... not found"); that's the test's doing, so build again
        tail = logf.read_bytes()[mark:].decode("utf-8", "replace")
        if code == 0 or not re.search(r"Remote \"[^\"]+\" not found|Install failed", tail) or attempt == 2:
            break
        with open(logf, "a") as fh:
            fh.write("\n(flatpak install clashed with another test's; building again)\n")
        time.sleep(5 + 10 * attempt)
    res["times"]["convert"] = round(time.time() - t)
    status, note = classify_convert(code, logf, app.get("expect", "runs"))
    if status == "built" or status == "converted-unexpectedly":
        t = time.time()
        shot = WORK / "shots" / f"{key}.png"
        seconds = app.get("seconds", SECONDS.get(app["route"], 45))
        if "the first start installs" in logf.read_text("utf-8", "replace"):
            seconds = max(seconds, FIRST_START_INSTALL_SECONDS)
        if "seconds" not in app:        # a catalog time is already chosen with care (see wait_for_start)
            seconds = round(seconds * WAIT_FACTOR)
        run_status, note = run_app(fid, seconds, logf, shot, cli=app.get("cli", False),
                                   tray=app.get("tray", False), winedebug=winedebug)
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
        logf = WORK / "logs" / f"{r['key']}.log"
        if r["status"] == "build-failed":       # the cause is usually far above the last lines
            errs = [ln for ln in logf.read_text("utf-8", "replace").splitlines()
                    if re.search(r"\b(error|Error|ERROR|failed|invalid)\b", ln)] if logf.is_file() else []
            if errs:
                lines += ["error lines:"] + [f"  {ln[:200]}" for ln in errs[-15:]] + [""]
        lines.append(tail(logf, 45))
    shots = [r for r in rows if r.get("shot")]
    if shots:
        lines += ["", f"screenshots ({len(shots)}) are in {WORK / 'shots'}"]
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ main

def preflight(need_run: bool) -> list[str]:
    missing = [t for t in ("flatpak", "flatpak-builder", "Xvfb") if need_run and not shutil.which(t)]
    if need_run and not (shutil.which("import") or shutil.which("xwd")):
        log("note: no screenshot tool (sudo apt install imagemagick), so there won't be screenshots")
    if need_run and not (shutil.which("xdotool") or shutil.which("xwininfo")):
        log("note: no window tool (sudo apt install xdotool), so an error dialog can't be told from a working app")
    return missing


def can_send(dest: str) -> bool:
    host = dest.split(":", 1)[0]
    return subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host, "true"],
                          capture_output=True).returncode == 0


def extras_dest(dest: str, name: str) -> str:
    """Where the extras go: next to the report (HOST:dir/report.txt) or into the folder given (HOST:dir)."""
    host, _, path = dest.partition(":")
    if path.endswith(".txt"):
        folder = str(Path(path).parent)
        folder = "" if folder == "." else folder + "/"
    else:
        folder = path if not path or path.endswith("/") else path + "/"
    return f"{host}:{folder}{name}"


def send(report: Path, dest: str) -> None:
    """scp the report to dest, and the logs, screenshots and results as compat-extras.tar.gz beside it."""
    extras = WORK / "compat-extras.tar.gz"
    subprocess.run(["tar", "czf", str(extras), "-C", str(WORK), "logs", "shots", "results.json", "report.txt"],
                   capture_output=True)
    ok = True
    for src, to in ((report, dest), (extras, extras_dest(dest, extras.name))):
        if not src.is_file():
            continue
        r = subprocess.run(["scp", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", str(src), to],
                           capture_output=True, text=True)
        if r.returncode == 0:
            log(f"Sent {src.name} to {to}")
        else:
            ok = False
            log(f"Couldn't send {src.name} to {to}: {r.stderr.strip()}")
    if not ok:
        log(f"They're in {WORK}; copy them with:  scp {socket.gethostname()}:{report} .")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="only look up each app's download link")
    ap.add_argument("--only", action="append", default=[], metavar="KEY", help="only these apps (repeatable)")
    ap.add_argument("--redo", action="store_true", help="test apps again even if results.json has them")
    ap.add_argument("--retry", action="store_true", help="test again the apps that didn't pass")
    ap.add_argument("--rejudge", action="store_true",
                    help="look at finished apps' logs again with the current checks (no window titles), then stop")
    ap.add_argument("--winedebug", metavar="CHANNELS",
                    help="run Wine apps with WINEDEBUG=CHANNELS (e.g. err+all,warn+module) to see why one fails")
    ap.add_argument("--send-to", metavar="USER@HOST:PATH",
                    help="copy report.txt there with scp at the end, and the logs and screenshots next to it")
    ap.add_argument("--jobs", "-j", type=int, default=1, metavar="N",
                    help="test N apps at once, each on its own virtual screen (4 suits 16 cores and 32 GB)")
    ap.add_argument("--wait-factor", type=float, metavar="F",
                    help="give each app F times as long to start (default: jobs / cores, at least 1)")
    ap.add_argument("--catalog", default=str(HERE / "apps.json"))
    args = ap.parse_args(argv)
    global WAIT_FACTOR
    WAIT_FACTOR = args.wait_factor or max(1.0, args.jobs / (os.cpu_count() or 1))

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

    if args.rejudge:
        results_path = WORK / "results.json"
        results = json.loads(results_path.read_text()) if results_path.is_file() else {}
        changed = 0
        for key, r in results.items():
            logf = WORK / "logs" / f"{key}.log"
            if r["status"] not in ("works", "exited") or not logf.is_file():
                continue
            out = logf.read_text("utf-8", "replace").split(f"$ flatpak run --user {r['app_id']}", 1)[-1]
            app = next((a for a in apps if a["key"] == key), {})
            status, note = judge(r["status"] == "works", 0 if r["status"] == "exited" else None, None, out,
                                 app.get("cli", False), app.get("tray", False))
            if status != r["status"]:
                log(f"{key}: {r['status']} -> {status}: {note}")
                r.update(status=status, note=note)
                changed += 1
        save_json(results_path, results)
        (WORK / "report.txt").write_text(render(results, apps))
        log(f"{changed} result(s) changed")
        return 0

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
    queue = [(i, app) for i, app in enumerate(todo, 1)
             if not (results.get(app["key"]) and not args.redo
                     and not (args.retry and results[app["key"]]["status"] not in PASS))]
    lock = threading.Lock()

    def one(i: int, app: dict) -> dict:
        log(f"[{i:2}/{len(todo)}] {app['name']} ({app['route']}) ...")
        return test_one(app, args.winedebug)

    pool = ThreadPoolExecutor(max_workers=max(1, args.jobs))
    running = {}
    try:
        while queue or running:
            while queue and len(running) < max(1, args.jobs):
                i, app = queue.pop(0)
                running[pool.submit(one, i, app)] = (i, app)
            finished, _ = wait(running, return_when=FIRST_COMPLETED)
            for fut in finished:
                i, app = running.pop(fut)
                try:
                    res = fut.result()
                except Exception as e:                       # noqa: BLE001 - one app's crash isn't the run's
                    res = {"key": app["key"], "name": app["name"], "route": app["route"],
                           "app_id": app_id(app["key"]), "status": "error", "note": f"compat.py: {e}"[:300]}
                with lock:
                    results[app["key"]] = res
                    save_json(results_path, results)
                    report.write_text(render(results, apps))
                    done += 1
                mins = (time.time() - started) / 60
                log(f"[{i:2}/{len(todo)}] {app['name']}: {res['status']}: {res.get('note', '')[:110]}"
                    f"   ({mins:.0f} min so far)")
    except KeyboardInterrupt:
        log("\nStopping: no new apps start; waiting for the ones running now. Ctrl+C again to quit at once.")
        queue.clear()
        try:
            for fut in list(running):
                i, app = running.pop(fut)
                res = fut.result()
                results[app["key"]] = res
                save_json(results_path, results)
                done += 1
        except KeyboardInterrupt:
            pass
        log("Stopped. Finished apps are saved; run the same command to continue.")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    report.write_text(render(results, apps))
    log(f"\nTested {done} app(s) this run. Report: {report}")
    if args.send_to:
        send(report, args.send_to)
    return 0


if __name__ == "__main__":
    sys.exit(main())
