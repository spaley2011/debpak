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
import html
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
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / "src"))

from debpak import net, recipes, selfcheck  # noqa: E402

WORK = Path(os.environ.get("DEBPAK_COMPAT_DIR", Path.home() / "debpak-compat"))
SECONDS = {"wine": 90, "electron": 60}            # time to start; everything else gets 45
# more apps at once than the machine has cores start more slowly; main() scales the times by this
WAIT_FACTOR = 1.0
PASS = {"works", "exited", "cli", "refused-expected"}
MEANING = {
    "works": "built, installed, and showing a window with no error when the time was up",
    "error-dialog": "running, but showing an error or printing a fatal error (missing runtime, crash dialog)",
    "no-window": "running, but with no visible window when the time was up",
    "exited": "a command-line tool that ran and exited cleanly",
    "cli": "a command-line program in a sample of GUI apps: debpak's check found no graphical menu entry and its "
           "usage text, and it exited at once, as it does run with no arguments",
    "not-an-app": "a theme, base or content snap, a release of libraries or a build environment, in a sample of "
                  "GUI apps: it has no apps to convert",
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


def debpak(*argv: str, log_to: Path, timeout: float, cwd: Path | None = None, tmp: Path | None = None) -> int:
    """Run debpak from this checkout; append its output to log_to; return its exit status (124 on timeout)."""
    # unpacked packages go where the app's lane says (see Lanes): not the shared /tmp, which is often
    # a RAM disk that many conversions at once would fill
    tmp = tmp or WORK / "tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "PYTHONPATH": str(REPO / "src"), "TMPDIR": str(tmp)}
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

# Waits between tries of a lookup or download that failed for a reason that passes. Karasu's,
# leanstudio's and spark-wallet's lookups in batch 2 failed with "The read operation timed out",
# a GitHub link that answered at once when tried again; a failed lookup counts against the batch.
RETRY_WAITS = (10, 30, 90)
TRANSIENT_HTTP = {408, 425, 429, 500, 502, 503, 504}
DEAD_HTTP = {404, 410}


class DeadLink(RuntimeError):
    """The catalog's link is gone (404, or a web page with no link to the file)."""


def transient(e: BaseException | None) -> bool:
    """True if the error is one that passes (a timeout, a dropped connection, a busy server)."""
    import http.client
    import ssl
    seen = set()
    while e is not None and id(e) not in seen:
        seen.add(id(e))
        if isinstance(e, urllib.error.HTTPError):
            return e.code in TRANSIENT_HTTP
        if isinstance(e, ssl.SSLCertVerificationError):
            return False
        if isinstance(e, (TimeoutError, socket.timeout, ConnectionError, http.client.IncompleteRead,
                          http.client.RemoteDisconnected, socket.gaierror)):
            return True
        if isinstance(e, urllib.error.URLError) and isinstance(e.reason, (OSError, str)):
            if isinstance(e.reason, BaseException) and transient(e.reason):
                return True
            return "timed out" in str(e.reason)
        if re.search(r"timed out|temporarily unavailable|connection (reset|refused|aborted)", str(e), re.I):
            return True
        e = e.__cause__ or e.__context__
    return False


def retrying(what: str, fn, waits: tuple = ()):
    """Call fn, and again after each of RETRY_WAITS while it fails with an error that passes."""
    waits = waits or RETRY_WAITS
    for i in range(len(waits) + 1):
        try:
            return fn()
        except Exception as e:                               # noqa: BLE001 - re-raised unless it passes
            if i == len(waits) or not transient(e):
                raise
            log(f"  {what}: {e}; trying again in {waits[i]}s")
            time.sleep(waits[i])


def lookup(app: dict) -> tuple[str, str]:
    """Return (download URL or snap:NAME[@CHANNEL], version)."""
    src = app["source"]
    if src["type"] == "snap":
        return snap_lookup(src)
    if src["type"] == "url":
        try:
            return retrying(src["url"], lambda: recipes.resolve_redirect(src["url"])), "latest"
        except urllib.error.HTTPError as e:
            if e.code not in DEAD_HTTP:
                raise
            # CuteCut Pro's winget link, a GitHub release asset, answered 404: a newer manifest of the
            # same winget package may have a link that works
            for url, version in winget_candidates(app):
                try:
                    return retrying(url, lambda: recipes.resolve_redirect(url)), version
                except OSError:
                    continue
            raise
    return retrying(app["key"], lambda: recipes.find_latest(src))


# ------------------------------------------------------------------ snaps

SNAP_STORE = "https://api.snapcraft.io/v2/snaps/info/"
SNAP_RISKS = ("stable", "candidate", "beta", "edge")


def snap_arch() -> str:
    import platform
    m = platform.machine().lower()
    return {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64", "armv7l": "armhf",
            "i686": "i386", "i386": "i386", "ppc64le": "ppc64el", "s390x": "s390x"}.get(m, m)


def snap_store_info(name: str) -> dict:
    """The snap store's record of a snap (its channel map), as the store's API gives it."""
    req = urllib.request.Request(SNAP_STORE + urllib.parse.quote(name),
                                 headers={"Snap-Device-Series": "16"})
    with net.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def snap_channel(info: dict, arch: str) -> tuple[str, str] | None:
    """Return (channel, version) of the most stable release for arch in a snap's channel map, else None.

    The default track (latest) comes first, then the others; stable before candidate, beta and edge.
    """
    best = None
    for c in info.get("channel-map", []):
        ch = c.get("channel", {})
        if ch.get("architecture") != arch or ch.get("risk") not in SNAP_RISKS:
            continue
        rank = (ch.get("track", "latest") != "latest", SNAP_RISKS.index(ch["risk"]))
        name = ch["risk"] if ch.get("track", "latest") == "latest" else f"{ch['track']}/{ch['risk']}"
        if best is None or rank < best[0]:
            best = (rank, name, str(c.get("version", "")))
    return best and best[1:]


def snap_lookup(src: dict) -> tuple[str, str]:
    """Return ("snap:NAME" or "snap:NAME@CHANNEL", version) for a catalog's snap.

    knotter, libretextus, classroom-plus and opentubex are in the store with no stable release
    (knotter and classroom-plus only in beta, libretextus only in edge), and snap download, which
    takes the stable channel, failed with "no snap revision available as specified". The store's
    own record says which channels a snap has for this machine, and the most stable of them is
    taken; a catalog entry can name its "channel" itself. When the store can't be asked, snap
    download's own stable channel is tried, as before.
    """
    name = src["name"]
    if src.get("channel"):
        return f"snap:{name}@{src['channel']}", src["channel"]
    try:
        info = retrying(f"snap store {name}", lambda: snap_store_info(name))
    except urllib.error.HTTPError as e:
        if e.code != 404:
            return f"snap:{name}", "stable"
        try:
            why = "; ".join(x.get("message", "") for x in json.loads(e.read()).get("error-list", []))
        except (ValueError, OSError, AttributeError):
            why = ""
        raise RuntimeError(f"the snap store has no snap named {name!r}" + (f" ({why})" if why else "")) from e
    except (OSError, ValueError):
        return f"snap:{name}", "stable"
    arch = snap_arch()
    found = snap_channel(info, arch)
    if not found:
        archs = sorted({c.get("channel", {}).get("architecture", "?") for c in info.get("channel-map", [])})
        raise RuntimeError(f"the snap store has {name} with no release for {arch}"
                           + (f" (only for {', '.join(archs)})" if archs else " (no releases at all)"))
    channel, version = found
    return (f"snap:{name}" if channel == "stable" else f"snap:{name}@{channel}"), f"{channel} {version}".strip()


# what snap download says when trying again won't help
SNAP_FOR_GOOD = re.compile(r"no snap revision|not found|snap not available|unsupported architecture|"
                           r"cannot find|invalid", re.I)


def snap_download(spec: str, dest_dir: Path, logf: Path, waits: tuple = ()) -> None:
    """Run snap download for NAME or NAME@CHANNEL into dest_dir, trying again while it fails for a passing reason.

    Raises:
        RuntimeError: with snap download's own error, not just "see the log".
    """
    name, _, channel = spec.partition("@")
    cmd = ["snap", "download", name, f"--target-directory={dest_dir}"] + ([f"--channel={channel}"] if channel else [])
    waits = waits or RETRY_WAITS
    for i in range(len(waits) + 1):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            out, code = (r.stdout or "") + (r.stderr or ""), r.returncode
        except subprocess.TimeoutExpired as e:
            out, code = f"{e}\nerror: snap download timed out", 124
        with open(logf, "a") as f:
            f.write(out)
        if code == 0 and any(dest_dir.glob("*.snap")):
            return
        error = next((ln.strip() for ln in reversed(out.splitlines()) if ln.strip().startswith("error:")),
                     (out.strip().splitlines() or [f"exit status {code}"])[-1].strip())
        if i == len(waits) or SNAP_FOR_GOOD.search(error):
            raise RuntimeError(f"snap download {spec} failed: {error}"[:300])
        log(f"  snap download {spec}: {error}; trying again in {waits[i]}s")
        time.sleep(waits[i])


# ------------------------------------------------------------------ winget

WINGET_API = "https://api.github.com/repos/microsoft/winget-pkgs/contents/"
WINGET_RAW = "https://raw.githubusercontent.com/microsoft/winget-pkgs/master/"
WINGET_TYPES = {"exe", "inno", "nullsoft", "msi", "wix", "burn", "zip", "portable"}


def winget_package(app: dict) -> tuple[str, str] | None:
    """(package id, version) of a winget sample's entry, from its why ("winget sample ID VERSION"), else None."""
    m = re.match(r"winget sample (\S+) (\S+)", app.get("why", ""))
    return (m.group(1), m.group(2)) if m else None


def winget_installers(text: str) -> list[dict]:
    """The installers of a winget installer manifest, each a dict of its own keys over the manifest's.

    A small reader of the one layout winget-pkgs uses, so the suite needs no YAML library: an
    Installers list whose items' keys sit two spaces in from their dash.
    """
    top, items, indent = {}, [], None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        lead = len(line) - len(line.lstrip())
        body = line.strip()
        if indent is None:
            if lead == 0 and body.startswith("Installers:"):
                indent = -1
            elif lead == 0 and (m := re.match(r"([A-Za-z]+):\s*(.*)", body)):
                top[m.group(1)] = m.group(2).strip("'\"")
            continue
        if lead == 0 and not body.startswith("-"):
            if (m := re.match(r"([A-Za-z]+):\s*(.*)", body)):
                top[m.group(1)] = m.group(2).strip("'\"")
            indent = None
            continue
        if body.startswith("- ") and (indent == -1 or lead == indent):
            indent = lead
            items.append({})
            body = body[2:].strip()
            lead += 2
        if items and lead == indent + 2 and (m := re.match(r"([A-Za-z]+):\s*(.*)", body)):
            items[-1][m.group(1)] = m.group(2).strip("'\"")
    return [{**top, **i} for i in items if i.get("InstallerUrl")]


def winget_pick(installers: list[dict]) -> str | None:
    """The installer URL winget_sample.py would take: an x64 or neutral one, else x86."""
    ok = [i for i in installers if i.get("InstallerType", "").lower() in WINGET_TYPES or not i.get("InstallerType")]
    for archs in (("x64", "neutral"), ("x86",)):
        for i in ok:
            if i.get("Architecture") in archs:
                return i["InstallerUrl"]
    return None


def winget_candidates(app: dict):
    """Yield (URL, version) from the app's winget package's current manifests, newest first.

    CuteCut Pro's winget link (2.5.4), a GitHub release asset, answered 404, and a package whose
    vendor moves its files often has a newer manifest that links to where they went, or the same
    version's manifest fixed in place by winget's bot. The versions come from the winget-pkgs
    repository on GitHub (with $GITHUB_TOKEN when set), the installer manifests from its raw files;
    when GitHub won't list the versions, the sampled version's own manifest is still read. Versions
    older than the sampled one aren't taken, nor a link already tried. Nothing is yielded for an app
    that isn't a winget sample.
    """
    pkg = winget_package(app)
    if not pkg:
        return
    pid, have = pkg
    folder = "manifests/" + pid[0].lower() + "/" + pid.replace(".", "/")
    try:
        listing = json.loads(retrying(f"winget-pkgs {pid}", lambda: recipes.fetch(WINGET_API + folder)))
        versions = [d["name"] for d in listing if isinstance(d, dict) and d.get("type") == "dir"]
    except (OSError, ValueError, TypeError) as e:
        log(f"  {app['key']}: can't list {pid}'s winget manifests: {e}")
        versions = []
    current = sorted({v for v in versions if recipes.version_key(v) >= recipes.version_key(have)} | {have},
                     key=recipes.version_key, reverse=True)
    seen = {app.get("source", {}).get("url")}
    for v in current:
        for name in (f"{pid}.installer.yaml", f"{pid}.yaml"):
            raw = f"{WINGET_RAW}{folder}/{urllib.parse.quote(v)}/{name}"
            try:
                text = retrying(name, lambda: recipes.fetch(raw)).decode("utf-8", "replace")
            except OSError:
                continue
            url = winget_pick(winget_installers(text))
            if url and url not in seen:
                seen.add(url)
                log(f"  {app['key']}: trying winget's {pid} {v} link {url}")
                yield url, v
            break


def download(app: dict, url: str, dest_dir: Path, logf: Path) -> Path:
    """Download into dest_dir (kept between runs) and return the file."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    if url.startswith("snap:"):
        marker = dest_dir / ".url"
        kept = sorted(dest_dir.glob("*.snap"))
        if kept and marker.is_file() and marker.read_text() == url and (dest_dir / ".complete").is_file():
            return kept[-1]             # fetched before (by --download-only, or a run that was stopped)
        for old in dest_dir.glob("*.snap"):
            old.unlink()
        snap_download(url[5:], dest_dir, logf)
        snaps = sorted(dest_dir.glob("*.snap"))
        marker.write_text(url)
        (dest_dir / ".complete").write_text("")
        return snaps[-1]
    path = Path(urllib.parse.urlparse(url).path)
    # SourceForge links end in /download after the file's name
    name = urllib.parse.unquote((path.parent if path.name == "download" else path).name) or f"{app['key']}.download"
    # a signed link to a GitHub release asset ends in the asset's id; its name is in the query
    # (FAF Client's faf_windows-x64_2026_11_0.exe came out as d0e6b61a-..., with no .exe)
    query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    for k in ("response-content-disposition", "rscd"):
        if (m := re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)', " ".join(query.get(k, [])))):
            name = Path(urllib.parse.unquote(m.group(1))).name or name
            break
    dest = dest_dir / name
    marker = dest_dir / ".url"
    if not dest.exists() and marker.is_file() and marker.read_text() == url:
        # the same download, kept under the name an earlier version of this script gave it
        kept = [f for f in dest_dir.iterdir() if f.is_file() and not f.name.startswith(".") and f.suffix != ".part"]
        if len(kept) == 1:
            kept[0].rename(dest)
    if dest.is_file() and dest.stat().st_size and marker.is_file() and marker.read_text() == url \
            and not web_page_file(dest) and whole(dest, url):
        return dest
    for old in dest_dir.iterdir():
        if old.is_file():
            old.unlink()
    part = dest.with_name(dest.name + ".part")

    def fetch(link: str) -> None:
        try:
            retrying(link, lambda: net.download(link, part))
        except urllib.error.HTTPError as e:
            if e.code in DEAD_HTTP:
                raise DeadLink(f"{e} ({link})") from e
            raise
    fetch(url)
    if (real := landing_page_link(part, name, url)):
        # CPU-Z's www.cpuid.com/downloads/cpu-z/cpu-z_3.02-en.zip is a page that links to
        # download.cpuid.com/cpu-z/cpu-z_3.02-en.zip, the file itself
        fetch(real)
    if web_page_file(part):
        # BomberClone's winget link, www.bomberclone.de/stuff/bomberclone-0.11.9.exe, now redirects to
        # an article about the game on another site, with no link to the file: the catalog's link is
        # out of date, which is no conversion's failure
        part.unlink()
        raise DeadLink(f"the link leads to a web page ({url}), not the file, and the page has no link "
                       "to the file: the catalog's link is out of date")
    part.replace(dest)
    marker.write_text(url)
    return dest


def download_any(app: dict, url: str, version: str, dest_dir: Path, logf: Path) -> tuple[str, str, Path]:
    """download, and when the link is dead, the app's newer winget links in turn; return (url, version, file)."""
    try:
        return url, version, download(app, url, dest_dir, logf)
    except DeadLink as dead:
        for alt, alt_version in winget_candidates(app):
            if alt == url:
                continue
            try:
                f = download(app, alt, dest_dir, logf)
            except (DeadLink, OSError) as e:
                with open(logf, "a") as lf:
                    lf.write(f"winget's {alt_version} link didn't work either: {e}\n")
                continue
            with open(logf, "a") as lf:
                lf.write(f"the catalog's link is dead ({dead}); took winget's {alt_version} link {alt}\n")
            return alt, alt_version, f
        raise


def convert_timeout(download: Path) -> float:
    """Return how long converting and building a download may take, in seconds.

    25 minutes, and 5 more per 100 MB past the first 300 MB, times WAIT_FACTOR: the
    JetBrains IDEs, KNIME and Cardinal (1 to 3 GB) ran out of 25 minutes copying
    and committing their files with a dozen builds at once. Twice that, since
    convert checks the app it built and may build it again (see selfcheck).
    """
    size = download.stat().st_size if download.is_file() else 0
    extra = max(0, size - (300 << 20)) / (100 << 20) * 300
    return 2 * (1500 + extra) * WAIT_FACTOR


def batch_of(apps: list, spec: str) -> list:
    """Return part N of M ("N/M") of the catalog: M parts as equal as can be, each with the same mix of routes.

    A catalog grouped by route would otherwise give one part all its Windows apps and another all
    its snaps, and the parts' pass rates couldn't be compared.
    """
    m = re.fullmatch(r"(\d+)/(\d+)", spec)
    if not m or not 1 <= int(m.group(1)) <= int(m.group(2)):
        raise ValueError(f"{spec!r} isn't N/M with 1 <= N <= M")
    n, parts = int(m.group(1)), int(m.group(2))
    seen: dict[str, int] = {}
    out = []
    for i, app in enumerate(apps):
        route = app.get("route", "")
        k = seen.get(route, 0)
        seen[route] = k + 1
        # the offset by route keeps the leftovers of small routes from all landing in part 1
        if (k + sum(map(ord, route))) % parts == n - 1:
            out.append(app)
    return out


def whole(path: Path, url: str) -> bool:
    """Return False if the server gives url a size and path, a kept download, isn't that size.

    A download kept from before net.download checked sizes can be cut short
    (Snipaste's AppImage, 28 of 37 MB); one whose size can't be checked counts as whole.
    """
    try:
        with net.urlopen(urllib.request.Request(url, method="HEAD"), timeout=60) as r:
            length = r.headers.get("Content-Length") if not r.headers.get("Content-Encoding") else None
    except OSError:
        return True
    return not (length and length.isdigit()) or path.stat().st_size == int(length)


def landing_page_link(path: Path, name: str, page: str = "") -> str | None:
    """Return the full link to a file called name in path, a small web page from the URL page, else None.

    A page that sends the browser on with a meta refresh, as SourceForge's
    "your download will start shortly" page does, is followed there first; then
    a link to the file on another host than the page's own (CPU-Z's
    www.cpuid.com page links to download.cpuid.com), then any other. A link
    may carry a query (SourceForge's mirror links end in ?ts=...&use_mirror=...),
    and the page's &amp; is read as the & it stands for.
    """
    if path.stat().st_size > 1 << 20:
        return None
    text = path.read_bytes()[:1 << 20].decode("utf-8", "replace")
    if not _web_page(text):
        return None
    text = html.unescape(text)
    to_file = r"https?://[^\"'\s<>?]+/" + re.escape(name) + r"(?:\?[^\"'\s<>]*)?"
    refresh = [m.group(1) for m in re.finditer(
        r"<meta\b[^>]*http-equiv=[\"']?refresh[^>]*content=[\"']?[^\"'>]*?url=(" + to_file + ")", text, re.I)]
    # the page links to itself too: by its own URL, and with a query (CPU-Z's "switch to the
    # desktop layout" link)
    links = [u for u in re.findall(to_file + r"(?=[\"'\s<>]|$)", text) if u != page]
    host = urllib.parse.urlparse(page).netloc
    links.sort(key=lambda u: urllib.parse.urlparse(u).netloc == host)
    return next(iter(refresh + links), None)


def _web_page(text: str) -> bool:
    return bool(re.match(r"\s*(<!doctype html|<html)", text.lstrip("\ufeff"), re.I))


def web_page_file(path: Path) -> bool:
    """True if the file at path is a web page (HTML), not a download."""
    try:
        with open(path, "rb") as f:
            return _web_page(f.read(4096).decode("utf-8", "replace"))
    except OSError:
        return False


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


def dialogs_to_raise(stack: list[tuple[int, int | None, bool]]) -> list[int]:
    """Return the windows to raise, in order, so each dialog sits above the window it belongs to.

    stack is the screen's top-level windows from bottom to top, each as
    (window, the window it's transient for or None, whether it's mapped).
    Any window manager keeps a dialog above its parent, but the virtual
    screen has none, so an app that raises its main window after showing
    a dialog (Google Earth Pro does, with its start-up tips and a notice)
    hides the dialog behind it. Its OpenGL view then doesn't repaint where
    the dialog was mapped, which leaves a blank box over the globe that
    isn't the app's fault. A dialog of a dialog is handled by going round
    again, and the bound stops a loop of windows transient for each other.
    """
    order = [w for w, _, _ in stack]
    parent = {w: p for w, p, _ in stack}
    mapped = {w for w, _, shown in stack if shown}
    raised = []
    for _ in range(len(order)):
        moved = False
        for w in list(order):
            p = parent[w]
            if w in mapped and p in order and order.index(p) > order.index(w):
                order.remove(w)
                order.append(w)
                raised.append(w)
                moved = True
        if not moved:
            break
    return raised


def raise_dialogs(display: int) -> bool:
    """Do a window manager's one job the screenshot depends on (see dialogs_to_raise); True if any moved."""
    if not (shutil.which("xwininfo") and shutil.which("xprop") and shutil.which("xdotool")):
        return False
    env = {**os.environ, "DISPLAY": f":{display}"}

    def ask(*cmd: str) -> str:
        return subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=15).stdout
    try:
        # xwininfo lists the root's children from the top down
        tops = re.findall(r"^\s{5}(0x[0-9a-f]+) ", ask("xwininfo", "-root", "-children"), re.M)[::-1]
        stack = []
        for w in tops[-60:]:
            m = re.search(r"window id # (0x[0-9a-f]+)", ask("xprop", "-id", w, "WM_TRANSIENT_FOR"))
            shown = bool(m) and "IsViewable" in ask("xwininfo", "-id", w)
            stack.append((int(w, 16), int(m.group(1), 16) if m else None, shown))
        raised = dialogs_to_raise(stack)
        for w in raised:
            ask("xdotool", "windowraise", str(w))
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return False
    return bool(raised)


# A process that's still running proves little: a crash dialog or a missing-runtime message keeps
# it alive too. These look at the window titles and the app's own output.
# "Error Reporting" asks whether to send reports (TEdit's first start), and a crash only counts as a
# word of its own, not inside a program's name (NirSoft's WinCrashReport)
ERROR_TITLE = re.compile(r"(?i)\berror\b(?! report)|program error|unhandled|exception|\bcrash|\.net (runtime|framework|desktop)|"
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
            # by class too: the search by name skips a window whose WM_NAME xdotool can't decode, and
            # Ren'Py's launcher (WM_NAME of type UTF-8) was "still running, but no visible window"
            ids = list(dict.fromkeys(
                i for what in ("--name", "--classname")
                for i in subprocess.run(["xdotool", "search", "--onlyvisible", what, ""], env=env,
                                        capture_output=True, text=True, timeout=15).stdout.split()))
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


def _ancestors(pid: int) -> set[int]:
    out = set()
    while pid > 1 and pid not in out:
        out.add(pid)
        try:
            pid = int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            break
    return out


def has_tray_icon(pid: int) -> bool:
    """True if a process started by pid has an icon on the desktop's tray (a StatusNotifierItem).

    The session bus's StatusNotifierWatcher lists the items; the connection that
    registered one belongs to the Flatpak's D-Bus proxy, which flatpak run starts.
    """
    if not shutil.which("gdbus"):
        return False

    def call(*a: str) -> str:
        try:
            return subprocess.run(["gdbus", "call", "--session", *a], capture_output=True, text=True,
                                  timeout=10).stdout
        except (subprocess.TimeoutExpired, OSError):
            return ""
    items = call("--dest", "org.kde.StatusNotifierWatcher", "--object-path", "/StatusNotifierWatcher",
                 "--method", "org.freedesktop.DBus.Properties.Get", "org.kde.StatusNotifierWatcher",
                 "RegisteredStatusNotifierItems")
    for name in dict.fromkeys(re.findall(r"'([^'/]+)", items)):
        m = re.search(r"uint32 (\d+)", call("--dest", "org.freedesktop.DBus", "--object-path",
                                            "/org/freedesktop/DBus", "--method",
                                            "org.freedesktop.DBus.GetConnectionUnixProcessID", name))
        if m and pid in _ancestors(int(m.group(1))):
            return True
    return False


def docked_tray_icons(path: Path) -> list[str]:
    """The icon windows an app docked with miniwm's system tray (miniwm.py --tray), which removes the file.

    Without a StatusNotifierWatcher on the session bus (has_tray_icon), a tray icon docks with the
    screen's system tray: GtkStatusIcon does (KimaiTray, a Tauri app, picks it outside GNOME and
    KDE), and so do libayatana-appindicator's fallback and Chromium's windowed icon. Gitification
    and Whisperio, tray apps, ran without a word and were "still running, but no visible window".
    """
    try:
        icons = path.read_text().split()
        path.unlink()
    except OSError:
        return []
    return icons


# a page on this machine the app named in what it printed: 121GW Companion's window is one it serves,
# "121GW Companion: http://127.0.0.1:8221/", which it asks the desktop to open in the web browser
LOCAL_URL = re.compile(r"""https?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0):\d+[^\s"'<>()\[\]]*""")


def local_page(output: str) -> str | None:
    """Return the first local URL the app printed if it answers with a web page (HTML), else None.

    debpak's check asks the same of the app (selfcheck.SERVED); a program
    whose window is a page it serves for the web browser shows none on the
    test's screen, which has no browser.
    """
    m = LOCAL_URL.search(output)
    if not m:
        return None
    url = m.group(0).replace("//0.0.0.0:", "//127.0.0.1:")
    import ssl
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
    try:
        with opener.open(url, timeout=10) as r:
            return url if "html" in r.headers.get("Content-Type", "").lower() else None
    except (OSError, ValueError):
        return None


def judge(running: bool, code: int | None, titles: list[str] | None, output: str, cli: bool,
          tray: bool = False, command_line: bool = False, server: bool = False,
          in_terminal: bool = False, served: str | None = None) -> tuple[str, str]:
    """Decide the run status from what was on screen and what the app printed.

    command_line is debpak's own finding, in the convert log, that the app is a
    command-line program (see selfcheck.command_line): Arkloop's ark and
    appimagetool, in a sample of GUI apps, print their usage and exit with a
    status of 1 or 2 when started with no arguments, which isn't a crash.
    server is its finding that it is one that runs on with no window it could
    open (selfcheck.SERVER), as lingma-proxy, a local proxy, does.
    in_terminal is its finding that a terminal program that failed with no
    terminal ran in one (selfcheck.IN_TERMINAL): LE, an ncurses editor, ended
    at "Segmentation fault" here as in debpak's first start, which counted as
    a crash, and what it does with no terminal says nothing of how it runs.
    served is the page on this machine it serves as its window (local_page).
    """
    fatal = FATAL_OUTPUT.search(output)
    bad = [t for t in titles or [] if ERROR_TITLE.search(t)]
    shown = f"windows: {'; '.join(titles)[:150]}" if titles else ""
    if bad:
        return "error-dialog", f"window says: {'; '.join(bad)[:200]}"
    if in_terminal and not titles:
        return "cli", f"{selfcheck.COMMAND_LINE}: it runs in a terminal (debpak's check started it in one)"
    if fatal:
        line = next((ln for ln in output.splitlines() if fatal.group(0) in ln), fatal.group(0))
        return ("error-dialog" if running or code == 0 else "crashed"), line.strip()[:200]
    if not running and command_line and not titles:
        return "cli", f"{selfcheck.COMMAND_LINE}: exited with status {code} when started with no arguments"
    if running and server and titles is not None and not titles and not cli:
        # lingma-proxy, a server with no display in its sandbox, which debpak's check found running on
        return "cli", f"{selfcheck.COMMAND_LINE}: still running, with no window it could open"
    if not titles and (need := selfcheck.terminal_need(output)):
        # superfile, a text interface, said "could not open TTY" and quit, and MeshTalk drew its own in
        # the terminal it took itself to be in: no GUI app needs one
        return "cli", f"{selfcheck.COMMAND_LINE}: it needs a terminal ({need})"
    if not running:
        if code == 0 and cli:
            return "exited", "exited cleanly"
        if code == 0:
            # a GUI app that quit without leaving a window hasn't worked, whatever its exit status
            return "quit", "exited cleanly without showing a window" + (f" ({shown})" if shown else "")
        return "crashed", f"exited with status {code}: " + (output.strip().splitlines() or ["no output"])[-1][:200]
    if titles is not None and not titles and not cli:
        if served:
            return "works", f"serving its window as a web page at {served}, for the web browser"
        if tray:
            return "works", "running in the tray (no window, as expected)"
        return "no-window", "still running, but no visible window"
    return "works", shown or "still running (no window tool to check what it shows)"


# A tray-only app has nothing on screen to judge until someone opens it, so a catalog entry can say
# how: "show" is a list of steps done once the app is up, before the screenshot. "tray" clicks the
# app's icon in Wine's stand-in tray: Xvfb has no system tray, so Wine's explorer shows its icons in
# a small window of its own, the one a user without a tray would click. "key:ctrl+grave" presses
# keys with xdotool over the app's windows, since Wine only sees keys sent to a Wine window.
SHOW_SETTLE_SECONDS = 5


def wine_tray_icon(display: int) -> tuple[int, int] | None:
    """Where to click the first icon in Wine's stand-in tray window, or None if there's none."""
    env = {**os.environ, "DISPLAY": f":{display}"}
    ids = subprocess.run(["xdotool", "search", "--onlyvisible", "--class", "^explorer\\.exe$"], env=env,
                         capture_output=True, text=True, timeout=15).stdout.split()
    for wid in ids:
        out = subprocess.run(["xdotool", "getwindowgeometry", "--shell", wid], env=env, capture_output=True,
                             text=True, timeout=15).stdout
        g = dict(ln.split("=", 1) for ln in out.splitlines() if "=" in ln)
        try:
            x, y, w, h = (int(g[k]) for k in ("X", "Y", "WIDTH", "HEIGHT"))
        except (KeyError, ValueError):
            continue
        # a strip of icons, not explorer's 1x1 helper windows; the first icon fills its left end
        if 10 <= h <= 48 and w >= h:
            return x + h // 2, y + h // 2
    return None


def wine_tray_icon_safe(display: int) -> tuple[int, int] | None:
    """wine_tray_icon, or None when there's no xdotool or it fails."""
    if not shutil.which("xdotool"):
        return None
    try:
        return wine_tray_icon(display)
    except (subprocess.TimeoutExpired, OSError):
        return None


def fid_is_wine(fid: str) -> bool:
    """True if the installed app runs on the Wine base app."""
    try:
        out = subprocess.run(["flatpak", "info", "--user", "-m", fid], capture_output=True, text=True,
                             timeout=30).stdout
    except (subprocess.TimeoutExpired, OSError):
        return False
    return "org.winehq.Wine" in out


def show_window(display: int, steps: list[str]) -> str:
    """Do a tray app's show steps; return what couldn't be done ("" if all were)."""
    if not shutil.which("xdotool"):
        return "no xdotool to open the app's window with"
    env = {**os.environ, "DISPLAY": f":{display}"}
    for step in steps:
        try:
            if step == "tray":
                at = wine_tray_icon(display)
                if not at:
                    return "no tray icon to click"
                cmd = ["xdotool", "mousemove", str(at[0]), str(at[1]), "click", "1"]
            elif step.startswith("key:"):
                at = wine_tray_icon(display)
                # Xvfb has no window manager, so the keyboard goes to the window under the pointer
                cmd = ["xdotool", *(["mousemove", str(at[0]), str(at[1])] if at else []), "key", step[4:]]
            else:
                return f"unknown show step {step!r}"
            subprocess.run(cmd, env=env, capture_output=True, timeout=15)
        except (subprocess.TimeoutExpired, OSError) as e:
            return f"show step {step!r} failed: {e}"
        time.sleep(SHOW_SETTLE_SECONDS)
    return ""


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


LATE_WINDOW_SECONDS = 30     # how much longer a running app with no window gets before it's judged


def late_window(proc: subprocess.Popen, display: int, seconds: int) -> list[str] | None:
    """Look for the app's window for up to seconds more while it runs; return the titles last seen.

    PutiaCNC, an egui app that keeps its window hidden until it has drawn the
    first frame, had no window after 45 seconds in a batch run, with a dozen
    other builds and runs on the machine, though debpak's own check on the
    same machine had seen it minutes before, and it shows in a few seconds on
    an idle one. A slow start isn't a missing window.
    """
    titles = visible_windows(display)
    deadline = time.time() + seconds
    while titles == [] and proc.poll() is None and time.time() < deadline:
        time.sleep(3)
        titles = visible_windows(display)
    return titles


# The commonest desktop size. Apps size their first window from the screen: Bulk Rename Utility
# takes three quarters of its height, and on 1280x800 that left its file list 30 pixels tall.
SCREEN = "1920x1080"


def park_pointer(display: int) -> None:
    """Move the pointer to the screen's top-left corner, off where apps put their windows.

    Xvfb starts it in the middle of the screen, right over a centred window,
    so the screenshot showed whatever hovering there opens: on 1920x1080,
    Bulk Rename Utility's help tooltip for a field in the middle of its window.
    """
    if shutil.which("xdotool"):
        try:
            subprocess.run(["xdotool", "mousemove", "0", "0"], env={**os.environ, "DISPLAY": f":{display}"},
                           capture_output=True, timeout=15)
        except (subprocess.TimeoutExpired, OSError):
            pass


def run_app(fid: str, seconds: int, logf: Path, shot: Path, cli: bool = False, tray: bool = False,
            winedebug: str | None = None, show: list[str] | None = None,
            command_line: bool = False, server: bool = False, in_terminal: bool = False,
            chromium: bool = False) -> tuple[str, str]:
    """Start the app on its own virtual screen; return (status, note).

    chromium: an Electron or CEF app, whose pages are drawn in its own window,
    so a page it serves on this machine is no window (see local_page).
    """
    display = free_display()
    xvfb = subprocess.Popen(["Xvfb", f":{display}", "-screen", "0", f"{SCREEN}x24", "-nolisten", "tcp"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wm = None
    try:
        time.sleep(2)
        park_pointer(display)
        # apps count on a window manager to hold windows to their size limits: without one,
        # MEGAsync's dialogs stay 1x1 (see miniwm.py)
        # and it is the screen's system tray, which records the icons an app docks there (see
        # docked_tray_icons); not for Wine, whose own stand-in tray window is the one to click
        tray_file = None if fid_is_wine(fid) else shot.with_name(shot.stem + ".tray")
        wm = subprocess.Popen([sys.executable, "-I", str(HERE / "miniwm.py")]
                              + (["--tray", str(tray_file)] if tray_file else []),
                              env={**os.environ, "DISPLAY": f":{display}"},
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        env = {k: v for k, v in os.environ.items() if k not in ("WAYLAND_DISPLAY",)}
        env["DISPLAY"] = f":{display}"
        # the app must draw on the virtual X screen. Without these, flatpak finds the desktop's
        # wayland-0 socket, so --socket=fallback-x11 grants no X11, and a Qt app started from
        # an SSH session (XDG_SESSION_TYPE=tty) looks for X11 and aborts
        env["WAYLAND_DISPLAY"] = "debpak-compat-no-wayland"
        env["XDG_SESSION_TYPE"] = "x11"
        # a desktop session sets DESKTOP_SESSION, which Fluxy can't start without
        env.setdefault("DESKTOP_SESSION", "debpak-compat")
        with open(logf, "a") as f:
            f.write(f"\n$ flatpak run --user {fid}   (DISPLAY=:{display}, {seconds}s)\n")
            f.flush()
            # and inside the sandbox the made-up name mustn't send apps looking for Wayland
            # (kitty: "Wayland: Failed to connect to display", then "GLFW initialization failed")
            extra = ["--unset-env=WAYLAND_DISPLAY"] + ([f"--env=WINEDEBUG={winedebug}"] if winedebug else [])
            # a Windows program draws in software on the virtual screen, as in debpak's own check
            # (selfcheck.VIRTUAL_DISPLAY_WINE_ENV): Wine's EGL took the test PC's GPU, whose driver the
            # sandbox lacks, and left TouchOSC and vimacc with no OpenGL
            if fid_is_wine(fid):
                extra += [f"--env={k}={v}" for k, v in selfcheck.VIRTUAL_DISPLAY_WINE_ENV.items()]
            # no terminal, as from a menu: a login shell the app starts to read the user's environment
            # (Harnss) would otherwise wait on the test's own terminal
            proc = subprocess.Popen(["flatpak", "run", "--user", *extra, fid], stdin=subprocess.DEVNULL, stdout=f,
                                    stderr=subprocess.STDOUT, env=env, start_new_session=True)
            code = wait_for_start(proc, display, seconds)
            if code is None and raise_dialogs(display):
                time.sleep(2)                                # for the raised dialogs to draw
            missed = ""
            if show and code is None:
                missed = show_window(display, show)
                if missed:
                    f.write(f"(couldn't open the window: {missed})\n")
                    f.flush()
            titles = visible_windows(display)
            if code is None and titles == [] and not cli and not tray and not show:
                titles = late_window(proc, display, round(LATE_WINDOW_SECONDS * WAIT_FACTOR))
            took = screenshot(display, shot)
            # a tray app shows nothing but its icon, which goes to the desktop's own panel, or for a
            # Windows program to Wine's stand-in tray window, which Wine only shows once a program has put
            # an icon in it (PhraseExpress)
            docked = docked_tray_icons(tray_file) if tray_file else []
            in_tray = code is None and titles == [] and proc.poll() is None and (
                has_tray_icon(proc.pid) or bool(docked)
                or (fid_is_wine(fid) and wine_tray_icon_safe(display) is not None))
            served = None
            if code is None and titles == [] and not in_tray and proc.poll() is None and not chromium:
                f.flush()
                served = local_page(logf.read_text("utf-8", "replace").split(f"$ flatpak run --user {fid}", 1)[-1])
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
        # once the harness has opened a tray app's window, that window has to be there
        status, note = judge(code is None, code, titles, run_output, cli, (tray and not show) or in_tray,
                             command_line, server, in_terminal, served)
        if in_tray and status == "works":
            note = "running in the tray (its icon is on the desktop's panel; no window until it's opened)"
            if docked and not fid_is_wine(fid):
                note = "running in the tray (its icon docked with the screen's system tray; no window until it's opened)"
        if missed and status == "no-window":
            note += f" ({missed})"
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
EXPECTED_REFUSAL = re.compile(r"system service|daemon|kernel|driver|wine-platform|needs root|PAM", re.I)


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
        if any(b.startswith(("a library, not an app:", "a build environment, not an app:")) for b in blockers):
            # a release that holds only libraries (LongScroll-Qt's Qt widget library, iohook's Node
            # module), or a project's toolchain (Colosseum's colo-build-tools), that the sample took for
            # an app: like a theme snap, there is nothing to convert
            return "not-an-app", note
        if expect == "refused" and any(EXPECTED_REFUSAL.search(b) for b in blockers):
            return "refused-expected", note
        if expect == "refused":
            note = "refused, but not for the expected reason: " + (note or "INCOMPLETE (libraries missing)")
        return "refused", note
    if code == 124:
        return "build-failed", "timed out"
    errors = re.findall(r"^(?:Error: |debpak: error: )(.+)$", text, re.M)
    if re.search(r"snap with no apps \(a base, runtime|installs no program, only libraries", text):
        # a theme or content snap that the sample of GUI snaps took for an app (Flat Remix GTK), or a
        # Windows installer of a library that winget lists as a package (SDL3Installer.msi)
        return "not-an-app", (errors[-1] if errors else "a snap with no apps")[:300]
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


def prune(key: str, passed: bool = True) -> None:
    """Delete an app's build state, and once it has passed its download too.

    A thousand apps' downloads don't fit on most disks. A failure keeps its
    download, so a rerun after a fix needn't fetch it again, but not its build
    files (the output folder, flatpak-builder's state and debpak's temporary
    folder), which a rerun makes afresh: kept for the failures of part 4 of the
    third catalog, they filled a 469 GB disk, and the temporary folders alone,
    the unpacked packages, grew by 50 GB an hour in batch 1 of the holdout.
    """
    for d in ((WORK / "downloads" / key) if passed else None, WORK / "work" / key, WORK / "out" / key,
              WORK / "tmp" / key):
        if d is not None:
            shutil.rmtree(d, ignore_errors=True)


class Lanes:
    """Where each app is unpacked, staged and built: in RAM when it fits, on disk when it doesn't.

    Every app is written out several times on its way to being installed: debpak
    unpacks it, stages it, flatpak-builder copies it into its build folder, caches
    it and exports it. On disk, a dozen of those at once held the SSD at full use
    with a write latency of seconds (a 6 GB app alone wrote 166 MB/s for minutes),
    and the run crawled. In a RAM disk (/tmp or /dev/shm) they cost nothing; only the
    install reaches the disk. A RAM budget decides how many run at once: an app
    reserves an estimate of what it needs, from its download's size, and waits
    while the budget is spent. An app too big for the budget builds on disk, at
    most `disk_jobs` at a time.
    """
    # what an app needs in RAM, per byte of download: unpacked about three times its size,
    # then about three copies of that alive at once while it builds
    FACTOR = 9
    FLOOR = 300 << 20
    WINE_FLOOR = 1536 << 20       # an installer run under Wine fills a whole new prefix

    def __init__(self, ram: Path | None, budget: int, disk_jobs: int):
        self.ram, self.budget, self.free = ram, budget, budget
        self.disk = threading.Semaphore(max(1, disk_jobs))
        self.cond = threading.Condition()

    def need(self, download: Path, route: str = "") -> int:
        size = download.stat().st_size if download.is_file() else 0
        return max(self.WINE_FLOOR if route == "wine" else self.FLOOR, size * self.FACTOR)

    def acquire(self, key: str, download: Path, route: str = "") -> tuple[Path, int]:
        """Wait for room and return (the folder to work in, the RAM reserved, 0 on disk)."""
        need = self.need(download, route)
        if self.ram is None or need > self.budget // 2:
            self.disk.acquire()
            return WORK, 0
        with self.cond:
            while True:
                if self.free >= need:
                    self.free -= need
                    return self.ram, need
                # RAM is spent: build on disk if a disk place is free, rather than wait (most of a
                # Windows app's time goes to waiting on its installer, not to writing)
                if self.disk.acquire(blocking=False):
                    return WORK, 0
                self.cond.wait(timeout=5)

    def release(self, base: Path, reserved: int) -> None:
        if reserved:
            with self.cond:
                self.free += reserved
                self.cond.notify_all()
        else:
            self.disk.release()


LANES = Lanes(None, 0, 2)
OFFLINE = False


# RAM disks to build in, in order. /tmp comes first: flatpak-builder mounts its build folder with
# rofiles-fuse, and Ubuntu's AppArmor profile for fusermount3 allows mounts under /tmp (and $HOME,
# /mnt, /media, /run/user) but not /dev/shm ("fusermount3: mount failed: Permission denied")
RAM_DISKS = ("/tmp", "/dev/shm")


def _tmpfs_mounts() -> set[str]:
    try:
        return {f.split()[1] for f in Path("/proc/mounts").read_text().splitlines() if f.split()[2:3] == ["tmpfs"]}
    except OSError:
        return set()


def ram_dir() -> tuple[Path | None, int]:
    """Return a folder on a RAM disk to build in and how much of it to use, or (None, 0)."""
    tmpfs = _tmpfs_mounts()
    for disk in RAM_DISKS:
        if disk not in tmpfs or not os.access(disk, os.W_OK):
            continue
        _clear_stale(Path(disk))
        st = os.statvfs(disk)
        free = st.f_bavail * st.f_frsize
        if free < (4 << 30):
            continue
        d = Path(disk) / f"debpak-compat-{os.getpid()}"
        d.mkdir(exist_ok=True)
        return d, int(free * 0.75)
    return None, 0


def _clear_stale(disk: Path) -> None:
    """Delete the build folders that runs which have ended left on disk, a RAM disk.

    A run that is stopped (or loses its terminal) leaves its debpak-compat-<pid> folder behind,
    and on a RAM disk that is memory: three such folders held 10 of /tmp's 24 GB.
    """
    for d in disk.glob("debpak-compat-*"):
        pid = d.name.rpartition("-")[2]
        if not pid.isdigit() or int(pid) == os.getpid() or Path(f"/proc/{pid}").exists():
            continue
        shutil.rmtree(d, ignore_errors=True)


def fetch_only(app: dict) -> str:
    """Look up and download one app, as test_one would, and say how it went (--download-only)."""
    logf = WORK / "logs" / f"{app['key']}.download.log"
    try:
        url, version = lookup(app)
        _, _, f = download_any(app, url, version, WORK / "downloads" / app["key"], logf)
    except Exception as e:                                   # noqa: BLE001 - reported, not raised
        return f"failed: {str(e)[:120]}"
    return f"{f.stat().st_size >> 20} MB"


def test_one(app: dict, winedebug: str | None = None) -> dict:
    key, fid = app["key"], app_id(app["key"])
    logf = WORK / "logs" / f"{key}.log"
    logf.write_text(f"{app['name']} ({app['route']}): {app['why']}\n")
    res = {"key": key, "name": app["name"], "route": app["route"], "app_id": fid,
           "started": dt.datetime.now().isoformat(timespec="seconds"), "times": {}}
    t = time.time()
    # the package is the largest file: snap download leaves a .assert beside the .snap
    kept = sorted((f for f in (WORK / "downloads" / key).glob("*")
                   if f.is_file() and f.suffix not in (".part", ".partial", ".assert") and not f.name.startswith(".")),
                  key=lambda f: f.stat().st_size) if OFFLINE and (WORK / "downloads" / key).is_dir() else []
    if kept:
        # --offline: test the file downloaded before, as it is, without asking for the latest
        f = kept[-1]
        res.update(file=f.name, size=f.stat().st_size, version="(kept download)")
        if web_page_file(f):
            res.update(status="download-failed", note=f"{f.name} is a web page (HTML), not the file: the catalog's "
                                                         "link is out of date")
            return res
        base, reserved = LANES.acquire(key, f, app["route"])
        try:
            return _convert_and_run(app, res, f, base, logf, winedebug)
        finally:
            if base != WORK:
                for d in ("out", "work", "tmp"):
                    shutil.rmtree(base / d / key, ignore_errors=True)
            LANES.release(base, reserved)
    try:
        url, version = lookup(app)
    except Exception as e:                                   # noqa: BLE001 - recorded, not raised
        res.update(status="lookup-failed", note=str(e)[:300])
        return res
    res.update(url=url, version=version)
    res["times"]["lookup"] = round(time.time() - t)
    t = time.time()
    try:
        url, version, f = download_any(app, url, version, WORK / "downloads" / key, logf)
    except Exception as e:                                   # noqa: BLE001
        res.update(status="download-failed", note=str(e)[:300])
        return res
    res.update(url=url, version=version)
    res.update(file=f.name, size=f.stat().st_size)
    res["times"]["download"] = round(time.time() - t)
    base, reserved = LANES.acquire(key, f, app["route"])
    try:
        return _convert_and_run(app, res, f, base, logf, winedebug)
    finally:
        if base != WORK:
            for d in ("out", "work", "tmp"):
                shutil.rmtree(base / d / key, ignore_errors=True)
        LANES.release(base, reserved)


def _convert_and_run(app: dict, res: dict, f: Path, base: Path, logf: Path, winedebug: str | None) -> dict:
    """Convert, build, install and start one app, building under base (see Lanes)."""
    key, fid = app["key"], app_id(app["key"])
    if base != WORK:
        res["built_in"] = "ram"
    t = time.time()
    out = base / "out" / key
    shutil.rmtree(out, ignore_errors=True)
    # a run that was stopped can leave the app's data behind, and a Wine prefix from it
    # would skip the first-start setup this test is meant to exercise
    shutil.rmtree(Path.home() / ".var/app" / fid, ignore_errors=True)
    cwd = base / "work" / key          # flatpak-builder keeps its state in .flatpak-builder here
    shutil.rmtree(cwd, ignore_errors=True)
    cwd.mkdir(parents=True)
    tmp = base / "tmp" / key
    args = [*app.get("args", [])]
    if "--anyway" not in args:          # the vendor's package is what's under test, Flathub or not
        args.append("--anyway")
    for attempt in range(3):
        mark = logf.stat().st_size
        code = debpak("convert", str(f), "--app-id", fid, "-o", str(out), *args,
                      log_to=logf, timeout=convert_timeout(f), cwd=cwd, tmp=tmp)
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
        log_text = logf.read_text("utf-8", "replace")
        if "converted as its Windows build running under Wine" in log_text:
            # an Electron app the Electron route couldn't take (Descript) starts its Wine prefix first
            seconds = max(seconds, SECONDS["wine"])
        if "the first start installs" in log_text:
            seconds = max(seconds, FIRST_START_INSTALL_SECONDS)
        if "seconds" not in app:        # a catalog time is already chosen with care (see wait_for_start)
            seconds = round(seconds * WAIT_FACTOR)
        command_line = f"Check: {selfcheck.COMMAND_LINE}:" in logf.read_text("utf-8", "replace")
        server = any(f"Check: {selfcheck.COMMAND_LINE}: {why}" in logf.read_text("utf-8", "replace")
                     for why in (selfcheck.SERVER, selfcheck.TERMINAL_ONLY))
        in_terminal = f"Check: {selfcheck.COMMAND_LINE}: {selfcheck.IN_TERMINAL}" in log_text
        run_status, note = run_app(fid, seconds, logf, shot, cli=app.get("cli", False),
                                   tray=app.get("tray", False), winedebug=winedebug, show=app.get("show"),
                                   command_line=command_line, server=server, in_terminal=in_terminal,
                                   chromium=bool(re.search(r"(?m)^\s*kind:\s+(?:electron|cef)\b", log_text)))
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


def keep_awake(argv) -> None:
    """Run the rest of the suite under systemd-inhibit, so the machine doesn't go to sleep mid-run.

    Desktops count an SSH session as idle, and the test PC suspends during
    long runs. This used to happen only through run.sh; started any other way
    (compat.py in a tmux of its own) the machine slept and the run stopped.
    """
    if os.environ.get("DEBPAK_COMPAT_AWAKE"):
        return
    inhibit = shutil.which("systemd-inhibit")
    # --no-ask-password: from a terminal with no desktop session, polkit would otherwise ask for a
    # password on it and wait there (a run started in tmux stopped at "Password:")
    if inhibit and subprocess.run([inhibit, "--no-ask-password", "--what=sleep:idle", "true"], capture_output=True,
                                  stdin=subprocess.DEVNULL, timeout=30).returncode == 0:
        os.environ["DEBPAK_COMPAT_AWAKE"] = "1"
        argv = sys.argv[1:] if argv is None else list(argv)
        os.execv(inhibit, [inhibit, "--no-ask-password", "--what=sleep:idle", "--who=debpak", "--why=compatibility run",
                           sys.executable, str(Path(__file__).resolve()), *argv])
    log("WARNING: couldn't block sleep (systemd-inhibit missing or refused); if the machine suspends, "
        "the run stops; run the same command again to continue where it stopped")


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
    ap.add_argument("--prune", action="store_true",
                    help="delete each app's build state when it's done, and its download too once it passes, "
                    "to save disk space")
    ap.add_argument("--offline", action="store_true",
                    help="test each app's file already in downloads/ as it is, with no lookup or download "
                         "(for re-testing on a slow network)")
    ap.add_argument("--download-only", action="store_true",
                    help="only download the apps (kept for the run that tests them): a slow network can fill "
                         "up ahead of the builds")
    ap.add_argument("--no-ram", action="store_true",
                    help="build every app on disk, not in a RAM disk (/tmp or /dev/shm) when it fits (see Lanes)")
    ap.add_argument("--ram-gb", type=float, metavar="GB",
                    help="use at most this much of the RAM disk (default: three quarters of its free space); "
                         "several runs at once each need a share")
    ap.add_argument("--disk-jobs", type=int, default=2, metavar="N",
                    help="apps too big for RAM build on disk, at most N at a time (default 2)")
    ap.add_argument("--catalog", default=str(HERE / "apps.json"))
    ap.add_argument("--batch", metavar="N/M", help="only the Nth of M equal parts of the catalog, in its order, "
                    "so a long catalog can be run and fixed a part at a time")
    args = ap.parse_args(argv)
    global WAIT_FACTOR, LANES, OFFLINE
    OFFLINE = args.offline
    WAIT_FACTOR = args.wait_factor or max(1.0, args.jobs / (os.cpu_count() or 1))
    ram, budget = (None, 0) if args.no_ram else ram_dir()
    if ram and args.ram_gb:
        budget = min(budget, int(args.ram_gb * (1 << 30)))
    LANES = Lanes(ram, budget, args.disk_jobs)

    apps = json.loads(Path(args.catalog).read_text())["apps"]
    if args.batch:
        try:
            apps = batch_of(apps, args.batch)
        except ValueError as e:
            log(f"--batch: {e}")
            return 2
    unknown = set(args.only) - {a["key"] for a in apps}
    if unknown:
        log(f"unknown app keys: {', '.join(sorted(unknown))}")
        return 2
    todo = [a for a in apps if not args.only or a["key"] in args.only]
    if not (args.check or args.rejudge):
        keep_awake(argv)
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
    if args.download_only:
        (WORK / "logs").mkdir(parents=True, exist_ok=True)
        with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as ex:
            for n, (app, how) in enumerate(zip(todo, ex.map(fetch_only, todo)), 1):
                log(f"[{n:3}/{len(todo)}] {app['name']}: {how}")
        return 0
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
                if args.prune:
                    prune(app["key"], res.get("status") in PASS)
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
