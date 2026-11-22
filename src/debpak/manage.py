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
from . import net


# --------------------------------------------------------------------------- Flathub

@dataclass
class FlathubHit:
    """An app found on Flathub: its app ID and display name."""
    app_id: str
    name: str


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def flathub_search(term: str) -> list[FlathubHit] | None:
    """Search Flathub's catalogue on this machine for term; return None if flatpak can't search."""
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
    """Return the Flathub app whose name, or the last part of its ID, exactly matches one of names."""
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


_HOMEPAGES: dict[str, str] | None = None


def flathub_homepages() -> dict[str, str]:
    """Return {app ID: homepage} from the Flathub AppStream data flatpak keeps on this machine."""
    global _HOMEPAGES
    if _HOMEPAGES is not None:
        return _HOMEPAGES
    import gzip
    import xml.etree.ElementTree as ET
    _HOMEPAGES = {}
    data = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    for base in (Path(data) / "flatpak", Path("/var/lib/flatpak")):
        for f in sorted((base / "appstream" / "flathub").glob("*/active/appstream.xml*")):
            try:
                with (gzip.open(f) if f.suffix == ".gz" else open(f, "rb")) as fh:
                    for _ev, el in ET.iterparse(fh):
                        if el.tag != "component":
                            continue
                        cid = (el.findtext("id") or "").strip().removesuffix(".desktop")
                        url = next((u.text.strip() for u in el.findall("url")
                                    if u.get("type") == "homepage" and u.text), "")
                        if cid and url:
                            _HOMEPAGES.setdefault(cid, url)
                        el.clear()
            except (OSError, ET.ParseError, EOFError):
                continue
    return _HOMEPAGES


def site(url: str) -> str:
    """Return a URL's site, the last two labels of its host (www.warp.dev is warp.dev; three for x.co.uk)."""
    host = re.sub(r"^[a-z]+://", "", url.strip().lower()).split("/")[0].split(":")[0]
    labels = [p for p in host.split(".") if p]
    n = 3 if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in ("co", "com", "org", "net", "ac") else 2
    return ".".join(labels[-n:])


def looks_reverse_dns(name: str) -> bool:
    parts = name.split(".")
    return len(parts) >= 3 and 2 <= len(parts[0]) <= 6 and parts[0].isalpha() and parts[0].islower()


def different_app(hit: FlathubHit, homepage: str = "", desktop_id: str = "") -> str:
    """Say why a same-named Flathub app is probably a different app, or return "" when nothing says so.

    The package's desktop file ID (dev.warp.Warp, against Flathub's app.drey.Warp)
    and its homepage against the Flathub app's are the evidence; without either,
    the name match stands.
    """
    if desktop_id and looks_reverse_dns(desktop_id):
        if desktop_id.lower() == hit.app_id.lower():
            return ""
        if desktop_id.lower().split(".")[:2] != hit.app_id.lower().split(".")[:2]:
            return f"the package's app ID is {desktop_id}"
    if homepage:
        theirs = flathub_homepages().get(hit.app_id)
        ours = site(homepage)
        if theirs and ours and site(theirs) != ours \
                and ".".join(reversed(ours.split("."))) not in hit.app_id.lower():
            return f"the package's homepage is {ours}, Flathub's {hit.app_id} is {site(theirs)}"
    return ""


def flathub_install_cmd(app_id: str) -> list[list[str]]:
    """Return the commands that add Flathub for the user (if missing) and install app_id from it."""
    return [["flatpak", "remote-add", "--user", "--if-not-exists", "flathub",
             "https://dl.flathub.org/repo/flathub.flatpakrepo"],
            ["flatpak", "install", "--user", "-y", "flathub", app_id]]


# --------------------------------------------------------------------------- registry

def registry_path() -> Path:
    """Return the registry file: $XDG_DATA_HOME/debpak/apps.json."""
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return Path(base) / "debpak" / "apps.json"


def load_registry() -> dict:
    """Return the registry as {app_id: entry}; empty if it's missing or unreadable."""
    try:
        return json.loads(registry_path().read_text())
    except (OSError, ValueError):
        return {}


def save_registry(reg: dict) -> None:
    """Write the registry atomically (to a temporary file, then rename)."""
    p = registry_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(reg, indent=2, sort_keys=True) + "\n")
    tmp.replace(p)


# options of `convert` that update repeats
CONVERT_OPTIONS = ("runtime", "runtime_index", "mode", "url", "deps_dir", "mirror", "suite", "components",
                   "rpm_repo", "permissive", "exec", "force", "allow_run", "native_dir", "wine_branch", "writable",
                   "no_fetch_natives", "wine_runtime")


def record(app_id: str, args, pkg, out: Path, installed: bool) -> None:
    """Add or replace an app's registry entry after a successful install.

    The entry keeps what `debpak update` needs to redo the conversion: the
    source file and its SHA-256, the output folder, the convert options in
    CONVERT_OPTIONS, and for a snap its name and revision.

    Args:
        app_id: The installed app.
        args: The parsed `convert` arguments.
        pkg: The converted package.
        out: The output folder.
        installed: Whether the build was installed.
    """
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
    """Return the revision of an installed snap folder (/snap/NAME/123, or .../current) or a NAME_123.snap file."""
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
    """Turn recorded convert options back into command-line flags: {'deps_dir': ['a']} -> ['--deps-dir', 'a']."""
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
    """The result of checking one app for a new version.

    Attributes:
        status: "up to date", "update available" or "can't check".
        detail: What was compared, for the user.
        new_file: The downloaded or changed package to convert, if there's one.
    """
    app_id: str
    status: str
    detail: str
    new_file: Path | None = None


def check_update(app_id: str, entry: dict, download: bool, workdir: Path, opener=None) -> UpdateCheck:
    """Check one registered app for a newer version.

    Apps installed from a recipe are checked against the recipe collection,
    snaps against the Snap Store by revision, apps converted with --url by
    downloading the file again and comparing SHA-256, and anything else by
    whether the original file changed on disk.

    Args:
        app_id: The app, for the result.
        entry: Its registry entry.
        download: Download the new version (False for `update --check`).
        workdir: Where downloads go.
        opener: A urlopen replacement, for tests.
    """
    url = (entry.get("options") or {}).get("url")
    if entry.get("recipe"):
        from .recipes import RecipeError, find, load_index
        try:
            hits = find(load_index(entry["recipe_source"]), entry["recipe"])
        except RecipeError as e:
            return UpdateCheck(app_id, "can't check", str(e))
        if not hits:
            return UpdateCheck(app_id, "can't check", f"{entry['recipe_source']} no longer has this recipe")
        if hits[0]["recipe_sha256"] == entry.get("recipe_sha256"):
            return UpdateCheck(app_id, "up to date", f"recipe {entry.get('version')}")
        return UpdateCheck(app_id, "update available", f"recipe {entry.get('version')} -> {hits[0]['version']}")
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
            with (opener or net.urlopen)(url, timeout=120) as r, open(dest, "wb") as f:
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
    """Create a temporary folder for update downloads."""
    return Path(tempfile.mkdtemp(prefix="debpak-update-"))
