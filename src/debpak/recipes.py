"""Recipes: conversions someone already did and checked, ready to install.

A recipe is a conversion's output minus anything that came from the vendor:
the flatpak-builder manifest, its app/ folder (launchers, desktop file,
icon, metainfo, unpack plan) and a recipe.json describing it. The manifest
has to be in extra-data mode, so Flatpak downloads the vendor's file from
the vendor when the app is installed, checked against the SHA-256 the
recipe pins. Nothing in a recipe is the vendor's to distribute.

A collection of recipes is a folder, locally or on a web server:

    index.json                     every recipe: id, name, version, summary, hash
    APP_ID/recipe.json             name, version, source download, permissions,
                                   and the SHA-256 of every other file
    APP_ID/APP_ID.json             the manifest
    APP_ID/app/...                 the manifest's dir source

`debpak recipe make OUT --to DIR` turns a conversion into a recipe and
updates DIR's index. `debpak install NAME` finds a recipe in the default
collection (recipes/ in the debpak repository, or $DEBPAK_RECIPES, or
--recipes), downloads it, checks every file's hash, shows what the app
will be allowed to do, and builds it with flatpak-builder.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import time
import urllib.parse
import urllib.request
from pathlib import Path

DEFAULT_SOURCE = "https://raw.githubusercontent.com/spaley2011/debpak/main/recipes"
SCHEMA = 1
MAX_RECIPE_BYTES = 5 * 1024 * 1024
ICON_EXTS = (".png", ".svg")
ALLOWED_SOURCES = ("dir", "extra-data", "archive", "file", "git", "patch", "shell")


class RecipeError(Exception):
    """A recipe that can't be made, found, downloaded or trusted."""


def fetch(url: str) -> bytes:
    """Download a URL (the tests replace this)."""
    with urllib.request.urlopen(url, timeout=60) as r:       # noqa: S310 - recipe sources are https or files
        return r.read()


def default_source() -> str:
    """Return where recipes come from: $DEBPAK_RECIPES, else the debpak repository's recipes/ folder."""
    return os.environ.get("DEBPAK_RECIPES") or DEFAULT_SOURCE


def _sha256(data: bytes) -> str:
    """Return the SHA-256 of data as hex."""
    return hashlib.sha256(data).hexdigest()


def _read(source: str, rel: str) -> bytes:
    """Read rel from a recipe collection that is a folder or a URL.

    Raises:
        RecipeError: The path is unsafe or the file can't be read.
    """
    if rel.startswith("/") or ".." in rel.split("/") or "\\" in rel:
        raise RecipeError(f"unsafe path in recipe: {rel!r}")
    if re.match(r"https?://", source):
        url = source.rstrip("/") + "/" + urllib.parse.quote(rel)
        try:
            return fetch(url)
        except OSError as e:
            raise RecipeError(f"can't download {url}: {e}") from e
    try:
        return (Path(source) / rel).read_bytes()
    except OSError as e:
        raise RecipeError(f"can't read {Path(source) / rel}: {e}") from e


# --------------------------------------------------------------------------- making recipes

def _manifest_path(out: Path) -> Path:
    """Return the flatpak-builder manifest in a conversion's output folder.

    Raises:
        RecipeError: There isn't one.
    """
    for p in sorted(out.glob("*.json")):
        if p.name in ("report.json", "recipe.json"):
            continue
        try:
            m = json.loads(p.read_text())
        except ValueError:
            continue
        if isinstance(m, dict) and "id" in m and "modules" in m:
            return p
    raise RecipeError(f"no flatpak-builder manifest in {out} (convert with -o {out} first)")


def _is_text(data: bytes) -> bool:
    """Return True for UTF-8 text without NUL bytes (scripts, JSON, XML, desktop files)."""
    if b"\0" in data[:8192]:
        return False
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def _check_sources(manifest: dict) -> list[str]:
    """Return problems with the manifest's sources: anything a recipe can't carry or fetch reproducibly."""
    problems = []
    mods = list(manifest.get("modules", []))
    extra = False
    while mods:
        m = mods.pop(0)
        if not isinstance(m, dict):
            problems.append("a module given as a file name; recipes need every module inline")
            continue
        mods += m.get("modules", [])
        for s in m.get("sources", []):
            t = s.get("type")
            if t not in ALLOWED_SOURCES:
                problems.append(f"module {m.get('name')}: source type {t!r} isn't allowed in recipes")
            elif t == "extra-data":
                extra = True
                if not (s.get("url") and s.get("sha256") and s.get("size")):
                    problems.append(f"module {m.get('name')}: extra-data source without url, sha256 and size")
            elif t == "dir" and s.get("path") != "app":
                problems.append(f"module {m.get('name')}: dir source {s.get('path')!r} (only app/ is copied)")
            elif t in ("archive", "file") and not (s.get("url") and s.get("sha256")):
                problems.append(f"module {m.get('name')}: {t} source must be a url with a sha256 "
                                f"(local file {s.get('path')!r})")
            elif t == "git" and not s.get("commit"):
                problems.append(f"module {m.get('name')}: git source without a pinned commit")
            elif t == "patch" and s.get("path"):
                problems.append(f"module {m.get('name')}: patch files aren't carried in recipes")
    if not extra:
        problems.append("the conversion isn't in extra-data mode, so it would carry the vendor's files: "
                        "convert again with --mode extra-data --url URL")
    return problems


def _desktop_name(app: Path, app_id: str) -> str | None:
    """Return Name= from the app's desktop file, or None."""
    d = app / "share/applications" / f"{app_id}.desktop"
    if d.is_file():
        for line in d.read_text("utf-8", "replace").splitlines():
            if line.startswith("Name="):
                return line[5:].strip()
    return None


def _metainfo_summary(app: Path, app_id: str) -> str:
    """Return the summary from the app's metainfo, or ''."""
    md = app / "share/metainfo" / f"{app_id}.metainfo.xml"
    if md.is_file():
        m = re.search(r"<summary>(.*?)</summary>", md.read_text("utf-8", "replace"), re.S)
        if m:
            from html import unescape
            return unescape(m.group(1).strip())
    return ""


def make(out: Path, dest_root: Path, allow_binaries: bool = False, note: str = "") -> Path:
    """Turn a conversion's output folder into a recipe under dest_root, and update dest_root's index.

    Args:
        out: The folder convert wrote (-o).
        dest_root: The recipe collection (a folder).
        allow_binaries: Accept binary files other than icons in app/, such as
            libraries bundled from a Linux distribution. Only for files you
            may redistribute.
        note: Free text for the recipe, such as what was tested.

    Returns:
        The recipe's folder.

    Raises:
        RecipeError: The conversion can't be shared as a recipe; the message
            lists every reason.
    """
    out, dest_root = Path(out), Path(dest_root)
    mpath = _manifest_path(out)
    manifest = json.loads(mpath.read_text())
    app_id = manifest["id"]
    problems = _check_sources(manifest)
    app = out / "app"
    files: dict[str, bytes] = {f"{app_id}.json": mpath.read_bytes()}
    total = 0
    if app.is_dir():
        for p in sorted(app.rglob("*")):
            rel = "app/" + p.relative_to(app).as_posix()
            if p.is_symlink():
                problems.append(f"{rel} is a symbolic link; recipes carry plain files only")
                continue
            if not p.is_file():
                continue
            data = p.read_bytes()
            total += len(data)
            if not (_is_text(data) or p.suffix.lower() in ICON_EXTS and "/icons/" in rel or allow_binaries):
                problems.append(f"{rel} is a binary file (pass --allow-binaries if you may redistribute it)")
            files[rel] = data
    if total > MAX_RECIPE_BYTES:
        problems.append(f"app/ holds {total // 1024} KiB; recipes are meant to be small (at most "
                        f"{MAX_RECIPE_BYTES // 1024 // 1024} MiB)")
    if problems:
        raise RecipeError("can't make a recipe from " + str(out) + ":\n  - " + "\n  - ".join(problems))

    x = manifest.get("x-debpak", {})
    extra_src = next(s for m in _all_modules(manifest) for s in m.get("sources", []) if s.get("type") == "extra-data")
    name = _desktop_name(app, app_id) or x.get("package", app_id).split()[0]
    version = x.get("package", "").split()[-1] if x.get("package") else "0"
    recipe = {
        "schema": SCHEMA,
        "id": app_id,
        "name": name,
        "version": version,
        "summary": _metainfo_summary(app, app_id),
        "format": x.get("format"),
        "route": x.get("route") or x.get("kind"),
        "source": {k: extra_src[k] for k in ("url", "sha256", "size")},
        "permissions": manifest.get("finish-args", []),
        "permission-reasons": x.get("permission-reasons", {}),
        "made-with": x.get("generator"),
        "made": time.strftime("%Y-%m-%d"),
        "note": note,
        "files": {rel: _sha256(data) for rel, data in sorted(files.items())},
    }
    dest = dest_root / app_id
    if dest.exists():
        shutil.rmtree(dest)
    for rel, data in files.items():
        p = dest / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        if rel.startswith("app/bin/"):
            p.chmod(0o755)
    (dest / "recipe.json").write_text(json.dumps(recipe, indent=2) + "\n")
    reindex(dest_root)
    return dest


