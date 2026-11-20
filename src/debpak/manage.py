"""After conversion: is the app already on Flathub, which apps debpak installed,
and keeping them updated.

  Flathub check  `flatpak search` (Flathub's catalogue, already on the machine)
                 for the package's name and its menu name; an exact match on the
                 app's name or the last part of its ID counts. An official
                 Flatpak beats a converted one, so convert stops and says so.
  Registry       $XDG_DATA_HOME/debpak/apps.json: what each converted app came
                 from and how it was converted, so `update` can redo it.
  update         re-download the vendor URL (or ask the Snap Store, for snaps)
                 and convert again when the file changed.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path


# --------------------------------------------------------------------------- Flathub

@dataclass
class FlathubHit:
    app_id: str
    name: str


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def flathub_search(term: str) -> list[FlathubHit] | None:
    """Flathub apps matching term, from the local appstream data; None if we can't search."""
    fp = shutil.which("flatpak")
    if not fp:
        return None
    try:
        r = subprocess.run([fp, "search", "--columns=application,name,remotes", term],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    hits = []
    for line in r.stdout.splitlines():
        cols = [c.strip() for c in line.split("\t")]
        if len(cols) < 3 or cols[0] in ("Application ID", "Application"):
            continue
        app_id, name, remotes = cols[0], cols[1], cols[2]
        if "flathub" in remotes.split(","):
            hits.append(FlathubHit(app_id, name))
    return hits


def flathub_match(names: list[str]) -> FlathubHit | None:
    """The Flathub app whose name, or the last part of its ID, matches one of names exactly."""
    wanted = {_norm(n) for n in names if n and len(_norm(n)) >= 3}
    terms = []
    for n in names:
        for t in (n, n.replace("-", " ").replace("_", " ")):
            if t and t not in terms:
                terms.append(t)
    for n in terms:
        for h in flathub_search(n) or []:
            if _norm(h.name) in wanted or _norm(h.app_id.rsplit(".", 1)[-1]) in wanted:
                return h
    return None


def flathub_install_cmd(app_id: str) -> list[list[str]]:
    return [["flatpak", "remote-add", "--user", "--if-not-exists", "flathub",
             "https://dl.flathub.org/repo/flathub.flatpakrepo"],
            ["flatpak", "install", "--user", "-y", "flathub", app_id]]


# --------------------------------------------------------------------------- registry

def registry_path() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return Path(base) / "debpak" / "apps.json"


def load_registry() -> dict:
    try:
        return json.loads(registry_path().read_text())
    except (OSError, ValueError):
        return {}


def save_registry(reg: dict) -> None:
    p = registry_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(reg, indent=2, sort_keys=True) + "\n")
    tmp.replace(p)


# options of `convert` that update repeats
CONVERT_OPTIONS = ("runtime", "runtime_index", "mode", "url", "deps_dir", "mirror", "suite", "components",
                   "rpm_repo", "permissive", "exec", "force", "allow_run")


def record(app_id: str, args, pkg, out: Path, installed: bool) -> None:
    reg = load_registry()
    src = Path(args.deb)
    entry = {
        "output": str(out.resolve()),
        "source": str(src.resolve()),
        "format": getattr(pkg, "format", "deb"),
        "version": pkg.version,
        "installed": installed,
        "converted": time.strftime("%Y-%m-%d %H:%M:%S"),
        "options": {k: getattr(args, k, None) for k in CONVERT_OPTIONS if getattr(args, k, None) not in (None, False, [])},
    }
    if src.is_file():
        entry["sha256"] = _sha256(src)
    if getattr(pkg, "format", "") == "snap":
        entry["snap"] = pkg.name
        rev = snap_revision(src)
        if rev:
            entry["snap_revision"] = rev
    reg[app_id] = entry
    save_registry(reg)


def snap_revision(src: Path) -> int | None:
    """Revision of an installed snap folder (/snap/NAME/123 or .../current -> 123) or a NAME_123.snap file."""
    try:
        real = src.resolve()
    except OSError:
        real = src
    for cand in (real.name, src.name):
        m = re.search(r"(?:^|_)(\d+)(?:\.snap)?$", cand)
        if m:
            return int(m.group(1))
    return None


def options_to_argv(opts: dict) -> list[str]:
    argv = []
    for k, v in opts.items():
        flag = "--" + k.replace("_", "-")
        if isinstance(v, bool):
            if v:
                argv.append(flag)
        elif isinstance(v, list):
            for x in v:
                argv += [flag, str(x)]
        else:
            argv += [flag, str(v)]
    return argv


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- update

@dataclass
class UpdateCheck:
    app_id: str
    status: str            # "up to date", "update available", "can't check"
    detail: str
    new_file: Path | None = None


def check_update(app_id: str, entry: dict, download: bool, workdir: Path, opener=None) -> UpdateCheck:
    url = (entry.get("options") or {}).get("url")
    if entry.get("snap"):
        from .snap import store_download, store_info
        arch = os.uname().machine
        try:
            info = store_info(entry["snap"], arch, opener=opener)
        except Exception as e:      # network, store API changes
            return UpdateCheck(app_id, "can't check", f"Snap Store: {e}")
        have = entry.get("snap_revision")
        if have and info["revision"] and int(info["revision"]) <= int(have):
            return UpdateCheck(app_id, "up to date", f"{entry['snap']} revision {have}")
        detail = f"{entry['snap']} {info['version']} (revision {info['revision']}, have {have or '?'})"
        if not download:
            return UpdateCheck(app_id, "update available", detail)
        path, _ = store_download(entry["snap"], workdir, arch, opener=opener)
        return UpdateCheck(app_id, "update available", detail, path)
    if url:
        dest = workdir / (Path(urllib.request.urlparse(url).path).name or "download")
        try:
            with (opener or urllib.request.urlopen)(url, timeout=120) as r, open(dest, "wb") as f:
                shutil.copyfileobj(r, f)
        except Exception as e:
            return UpdateCheck(app_id, "can't check", f"{url}: {e}")
        if entry.get("sha256") and _sha256(dest) == entry["sha256"]:
            return UpdateCheck(app_id, "up to date", f"{url} unchanged")
        return UpdateCheck(app_id, "update available", f"{url} changed", dest)
    src = Path(entry.get("source", ""))
    if src.is_file() and entry.get("sha256") and _sha256(src) != entry["sha256"]:
        return UpdateCheck(app_id, "update available", f"{src} changed on disk", src)
    return UpdateCheck(app_id, "can't check", "no download URL recorded (convert with --url to enable updates)")


def update_workdir() -> Path:
    return Path(tempfile.mkdtemp(prefix="debpak-update-"))
