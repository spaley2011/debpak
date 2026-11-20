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


def _all_modules(manifest: dict) -> list[dict]:
    """Return every module of a manifest, nested ones included."""
    out, todo = [], list(manifest.get("modules", []))
    while todo:
        m = todo.pop(0)
        if isinstance(m, dict):
            out.append(m)
            todo += m.get("modules", [])
    return out


def reindex(root: Path) -> Path:
    """Write root/index.json from the recipe.json files under root; return its path."""
    root = Path(root)
    entries = []
    for rj in sorted(root.glob("*/recipe.json")):
        data = rj.read_bytes()
        r = json.loads(data)
        entries.append({"id": r["id"], "name": r["name"], "version": r["version"], "summary": r.get("summary", ""),
                        "route": r.get("route"), "recipe_sha256": _sha256(data)})
    path = root / "index.json"
    root.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema": SCHEMA, "recipes": entries}, indent=2) + "\n")
    return path


# --------------------------------------------------------------------------- finding and installing

def load_index(source: str) -> list[dict]:
    """Return the recipes a collection lists.

    Raises:
        RecipeError: The index can't be read or is from a newer debpak.
    """
    try:
        idx = json.loads(_read(source, "index.json"))
    except ValueError as e:
        raise RecipeError(f"{source}: index.json isn't valid JSON ({e})") from e
    if idx.get("schema", 0) > SCHEMA:
        raise RecipeError(f"{source} needs a newer debpak (recipe schema {idx['schema']})")
    return idx.get("recipes", [])


def _norm(s: str) -> str:
    """Lower-case s and drop everything but letters and digits, for name matching."""
    return re.sub(r"[^a-z0-9]", "", s.lower())


def find(index: list[dict], query: str) -> list[dict]:
    """Return recipes matching query: its app ID exactly, else its name or the last part of its ID."""
    exact = [r for r in index if r["id"] == query]
    if exact:
        return exact
    q = _norm(query)
    return [r for r in index if q and (_norm(r["name"]) == q or _norm(r["id"].rsplit(".", 1)[-1]) == q)]


def search(index: list[dict], term: str | None) -> list[dict]:
    """Return recipes whose ID, name or summary contains term (all of them without one)."""
    if not term:
        return list(index)
    t = term.lower()
    return [r for r in index if t in r["id"].lower() or t in r["name"].lower() or t in r.get("summary", "").lower()]


def download(source: str, entry: dict, dest: Path) -> dict:
    """Download one recipe into dest, checking recipe.json against the index and every file against recipe.json.

    Returns:
        The recipe.

    Raises:
        RecipeError: A hash doesn't match, a path is unsafe, or a file is missing.
    """
    app_id = entry["id"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", app_id):
        raise RecipeError(f"bad app id in index: {app_id!r}")
    raw = _read(source, f"{app_id}/recipe.json")
    if _sha256(raw) != entry.get("recipe_sha256"):
        raise RecipeError(f"{app_id}/recipe.json doesn't match the index's hash")
    recipe = json.loads(raw)
    if recipe.get("id") != app_id or recipe.get("schema", 0) > SCHEMA:
        raise RecipeError(f"{app_id}/recipe.json is for {recipe.get('id')!r} or needs a newer debpak")
    if f"{app_id}.json" not in recipe.get("files", {}):
        raise RecipeError(f"{app_id}: the recipe has no manifest")
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    for rel, digest in recipe["files"].items():
        if not (rel == f"{app_id}.json" or rel.startswith("app/")):
            raise RecipeError(f"{app_id}: unexpected file {rel!r}")
        data = _read(source, f"{app_id}/{rel}")
        if _sha256(data) != digest:
            raise RecipeError(f"{app_id}/{rel} doesn't match the recipe's hash")
        p = dest / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        if rel.startswith("app/bin/"):
            p.chmod(0o755)
    helper = dest / "app/bin/debpak-unpack"
    if helper.exists():
        # it runs at install time: use this debpak's own copy, not whatever the recipe carries
        shutil.copyfile(Path(__file__).with_name("unpack.py"), helper)
        helper.chmod(0o755)
    (dest / "recipe.json").write_bytes(raw)
    manifest = json.loads((dest / f"{app_id}.json").read_text())
    if manifest.get("id") != app_id:
        raise RecipeError(f"{app_id}: the manifest is for {manifest.get('id')!r}")
    problems = _check_sources(manifest)
    if problems:
        raise RecipeError(f"{app_id}: the manifest isn't a valid recipe:\n  - " + "\n  - ".join(problems))
    return recipe


def describe(recipe: dict) -> str:
    """Return what installing a recipe will do: the app, where its files come from, and its permissions."""
    reasons = recipe.get("permission-reasons", {})
    lines = [f"{recipe['name']} {recipe['version']}  ({recipe['id']})"]
    if recipe.get("summary"):
        lines.append(f"  {recipe['summary']}")
    src = recipe["source"]
    lines += [f"  downloads {src['url']}", f"    ({src['size'] / 1e6:.1f} MB, sha256 {src['sha256'][:16]}...)",
              "  permissions:"]
    lines += [f"    {p:<45} # {reasons[p]}" if p in reasons else f"    {p}" for p in recipe.get("permissions", [])]
    if recipe.get("note"):
        lines.append(f"  note: {recipe['note']}")
    lines.append(f"  recipe made {recipe.get('made', '?')} with {recipe.get('made-with') or 'debpak'}")
    return "\n".join(lines) + "\n"


def recipes_dir() -> Path:
    """Return where installed recipes are kept (~/.local/share/debpak/recipes)."""
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return Path(base) / "debpak" / "recipes"


def record(recipe: dict, source: str, dest: Path, recipe_sha256: str) -> None:
    """Add or replace an installed recipe's registry entry, so list, update and uninstall know it."""
    from .manage import load_registry, save_registry
    reg = load_registry()
    reg[recipe["id"]] = {
        "output": str(dest.resolve()),
        "source": recipe["source"]["url"],
        "format": "recipe",
        "version": recipe["version"],
        "installed": True,
        "converted": time.strftime("%Y-%m-%d %H:%M:%S"),
        "recipe": recipe["id"],
        "recipe_source": source,
        "recipe_sha256": recipe_sha256,
        "options": {},
    }
    save_registry(reg)
