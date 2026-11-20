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
import urllib.error
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


def make(out: Path, dest_root: Path, allow_binaries: bool = False, note: str = "", check: dict | None = None) -> Path:
    """Turn a conversion's output folder into a recipe under dest_root, and update dest_root's index.

    Args:
        out: The folder convert wrote (-o).
        dest_root: The recipe collection (a folder).
        allow_binaries: Accept binary files other than icons in app/, such as
            libraries bundled from a Linux distribution. Only for files you
            may redistribute.
        note: Free text for the recipe, such as what was tested.
        check: How to find the vendor's newest version (see find_latest).
            When None, the check of the recipe being replaced is kept.

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
    if check is not None:
        problems += [f"--check: {p}" for p in check_problems(check)]
    if problems:
        raise RecipeError("can't make a recipe from " + str(out) + ":\n  - " + "\n  - ".join(problems))
    old_recipe = dest_root / app_id / "recipe.json"
    if check is None and old_recipe.is_file():
        check = json.loads(old_recipe.read_text()).get("check")

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
        "convert": x.get("convert-options", {}),
        "files": {rel: _sha256(data) for rel, data in sorted(files.items())},
    }
    if x.get("convert-local-options"):
        recipe["convert-local-options"] = x["convert-local-options"]
    if check:
        recipe["check"] = check
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


# --------------------------------------------------------------------------- finding new versions

CHECK_TYPES = {
    "redirect": ("url", "version"),     # a "latest" link that redirects to a versioned file
    "html": ("url", "pattern"),         # a download page, searched with a regex
    "json": ("url", "url-key", "version-key"),
    "github": ("repo", "asset"),        # the newest GitHub release
}


def check_problems(check: dict) -> list[str]:
    """Return what's wrong with a recipe's check block ([] when it's usable)."""
    t = check.get("type")
    if t not in CHECK_TYPES:
        return [f"type must be one of {', '.join(CHECK_TYPES)}"]
    missing = [k for k in CHECK_TYPES[t] if not check.get(k)]
    problems = [f"{t} needs {', '.join(missing)}"] if missing else []
    for key in ("version", "pattern", "asset"):
        if check.get(key):
            try:
                re.compile(check[key])
            except re.error as e:
                problems.append(f"{key} isn't a valid regular expression ({e})")
    if t == "html" and check.get("pattern") and "?P<url>" not in check["pattern"]:
        problems.append("html pattern needs a (?P<url>...) group, and usually (?P<version>...)")
    return problems


def resolve_redirect(url: str) -> str:
    """Return where a URL ends up after redirects, without downloading the body (the tests replace this)."""
    req = urllib.request.Request(url, method="HEAD")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:      # noqa: S310
            return r.geturl()
    except urllib.error.HTTPError as e:
        if e.code not in (403, 405):
            raise
    with urllib.request.urlopen(url, timeout=60) as r:          # noqa: S310 - servers that refuse HEAD
        return r.geturl()


def version_key(v: str) -> tuple:
    """Sort key for version strings: numbers compare as numbers ('1.10' > '1.9')."""
    return tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in re.findall(r"\d+|[A-Za-z]+", v))


def _dig(data, dotted: str):
    for part in dotted.split("."):
        data = data[int(part)] if isinstance(data, list) else data[part]
    return data


def find_latest(check: dict) -> tuple[str, str]:
    """Return (download URL, version) of the vendor's newest release, as the recipe's check block says to find it.

    Raises:
        RecipeError: The check fails or finds nothing.
    """
    t = check["type"]
    try:
        if t == "redirect":
            final = resolve_redirect(check["url"])
            m = re.search(check["version"], final)
            if not m:
                raise RecipeError(f"{final} doesn't match {check['version']!r}")
            return final, m.group(1)
        if t == "html":
            page = fetch(check["url"]).decode("utf-8", "replace")
            hits = [(m.group("url"), m.groupdict().get("version") or m.group("url"))
                    for m in re.finditer(check["pattern"], page)]
            if not hits:
                raise RecipeError(f"{check['url']}: nothing matches the pattern")
            url, version = max(hits, key=lambda h: version_key(h[1]))
            return urllib.parse.urljoin(check["url"], url), version
        if t == "json":
            data = json.loads(fetch(check["url"]))
            return str(_dig(data, check["url-key"])), str(_dig(data, check["version-key"]))
        if t == "github":
            rel = json.loads(fetch(f"https://api.github.com/repos/{check['repo']}/releases/latest"))
            for a in rel.get("assets", []):
                if re.search(check["asset"], a["name"]):
                    return a["browser_download_url"], rel["tag_name"].lstrip("v")
            raise RecipeError(f"{check['repo']} {rel.get('tag_name')}: no asset matches {check['asset']!r}")
    except (OSError, ValueError, KeyError, IndexError, TypeError) as e:
        raise RecipeError(f"check failed: {e}") from e
    raise RecipeError(f"unknown check type {t!r}")


def download_file(url: str, dest: Path) -> Path:
    """Download url to dest in chunks (the tests replace this)."""
    with urllib.request.urlopen(url, timeout=120) as r, open(dest, "wb") as f:     # noqa: S310
        shutil.copyfileobj(r, f, 1 << 20)
    return dest


def check_updates(root: Path, ids: list[str] | None = None, apply: bool = False, work: Path | None = None,
                  log=print) -> list[dict]:
    """Look for new vendor releases of the recipes in root, and with apply, convert them and replace the recipes.

    Returns:
        One dict per recipe looked at: id, status (up to date, update, updated,
        no check, can't update, error), old and new version, and detail.
    """
    import tempfile
    root = Path(root)
    results = []
    for rj in sorted(root.glob("*/recipe.json")):
        r = json.loads(rj.read_text())
        if ids and r["id"] not in ids:
            continue
        res = {"id": r["id"], "old": r["version"], "new": None, "detail": ""}
        results.append(res)
        if not r.get("check"):
            res.update(status="no check", detail="the recipe has no check block")
            continue
        try:
            url, version = find_latest(r["check"])
        except RecipeError as e:
            res.update(status="error", detail=str(e))
            continue
        res["new"] = version
        if url == r["source"]["url"]:
            res.update(status="up to date")
            continue
        res.update(status="update", detail=url)
        if not apply:
            continue
        if r.get("convert-local-options"):
            res.update(status="can't update", detail="it was converted with local files ("
                       + ", ".join("--" + o.replace("_", "-") for o in r["convert-local-options"])
                       + "); convert the new version by hand")
            continue
        with tempfile.TemporaryDirectory(dir=work) as tmp:
            tmp = Path(tmp)
            name = re.sub(r"[^\w.+-]", "_", urllib.parse.unquote(url.rsplit("/", 1)[-1].split("?")[0])) or "download"
            log(f"{r['id']}: downloading {url}")
            try:
                src = download_file(url, tmp / name)
            except OSError as e:
                res.update(status="error", detail=f"download failed: {e}")
                continue
            from .cli import main as cli_main
            from .manage import options_to_argv
            argv = ["convert", str(src), "--app-id", r["id"], "-o", str(tmp / "out"), "--no-build", "--anyway",
                    *options_to_argv({**r.get("convert", {}), "mode": "extra-data", "url": url})]
            code = cli_main(argv)
            if code != 0:
                res.update(status="error", detail=f"conversion failed (exit {code}); run `debpak "
                                                  + " ".join(argv[:2]) + " ...` by hand")
                continue
            try:
                make(tmp / "out", root, note=f"Updated automatically from {r['version']}; not tested by hand yet.",
                     check=r["check"])
            except RecipeError as e:
                res.update(status="error", detail=str(e))
                continue
            res.update(status="updated")
    return results


# --------------------------------------------------------------------------- publishing a Flatpak repository

FLATHUB_REPO = "https://dl.flathub.org/repo/flathub.flatpakrepo"


def _run(cmd: list[str], log) -> None:
    import subprocess
    log("$ " + " ".join(cmd))
    r = subprocess.run(cmd)
    if r.returncode != 0:
        raise RecipeError(f"{cmd[0]} exited {r.returncode}")


def publish(root: Path, repo: Path, url: str, gpg_key: str | None = None, gpg_homedir: str | None = None,
            title: str = "debpak recipes", ids: list[str] | None = None, log=print) -> list[str]:
    """Build recipes into a Flatpak (OSTree) repository that any static web host can serve.

    Each recipe is built with flatpak-builder --repo. The repository then gets
    a summary (flatpak build-update-repo), REPO/debpak.flatpakrepo for
    `flatpak remote-add`, a .flatpakref per app under REPO/apps, and a plain
    index.html. Apps keep downloading the vendor's files themselves at
    install time, so the repository holds no vendor files.

    Args:
        root: The recipe collection.
        repo: The repository folder; created, or updated in place.
        url: Where repo will be served from (the .flatpakrepo points there).
        gpg_key: Key ID to sign with. Without one the repository is unsigned,
            and users have to add it with --no-gpg-verify.
        gpg_homedir: GnuPG home holding that key.
        ids: Only build these recipes (the summary still lists all apps in repo).

    Returns:
        The app IDs built.

    Raises:
        RecipeError: A build or signing step fails.
    """
    import base64
    import html
    import subprocess
    root, repo = Path(root), Path(repo)
    repo.mkdir(parents=True, exist_ok=True)
    sign = [f"--gpg-sign={gpg_key}"] + ([f"--gpg-homedir={gpg_homedir}"] if gpg_homedir else []) if gpg_key else []
    built = []
    entries = load_index(str(root))
    for e in entries:
        if ids and e["id"] not in ids:
            continue
        manifest = root / e["id"] / f"{e['id']}.json"
        problems = _check_sources(json.loads(manifest.read_text()))
        if problems:
            raise RecipeError(f"{e['id']}: " + "; ".join(problems))
        build_dir = repo.parent / ".debpak-build" / e["id"]
        _run(["flatpak-builder", "--user", "--force-clean", "--install-deps-from=flathub", f"--repo={repo}",
              *sign, f"--state-dir={repo.parent / '.flatpak-builder'}", str(build_dir), str(manifest)], log)
        shutil.rmtree(build_dir, ignore_errors=True)
        built.append(e["id"])
    if (repo / "config").is_file():
        _run(["flatpak", "build-update-repo", f"--title={title}", "--prune", *sign, str(repo)], log)
    else:
        log("no apps built yet, so there's no repository to update; writing the pages only")

    key_line = ""
    if gpg_key:
        cmd = ["gpg", "--export", gpg_key] + (["--homedir", gpg_homedir] if gpg_homedir else [])
        key = subprocess.run(cmd, capture_output=True).stdout
        if not key:
            raise RecipeError(f"gpg exported nothing for key {gpg_key}")
        key_line = "GPGKey=" + base64.b64encode(key).decode() + "\n"
    url = url.rstrip("/") + "/"
    (repo / "debpak.flatpakrepo").write_text(
        "[Flatpak Repo]\n"
        f"Title={title}\n"
        f"Url={url}\n"
        "Homepage=https://github.com/spaley2011/debpak\n"
        "Comment=Apps converted by debpak. Each one downloads the app from its vendor when installed.\n"
        + key_line)
    (repo / "apps").mkdir(exist_ok=True)
    rows = []
    for e in entries:
        (repo / "apps" / f"{e['id']}.flatpakref").write_text(
            "[Flatpak Ref]\n"
            f"Name={e['id']}\nBranch=master\nTitle={e['name']}\nUrl={url}\n"
            f"RuntimeRepo={FLATHUB_REPO}\nIsRuntime=false\n" + key_line)
        rows.append(f"<tr><td>{html.escape(e['name'])}</td><td>{html.escape(e['version'])}</td>"
                    f"<td>{html.escape(e.get('summary', ''))}</td>"
                    f"<td><code>flatpak install debpak {html.escape(e['id'])}</code></td></tr>")
    no_verify = "" if gpg_key else " --no-gpg-verify"
    (repo / "index.html").write_text(
        "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        f"<title>{html.escape(title)}</title></head><body>\n"
        f"<h1>{html.escape(title)}</h1>\n"
        "<p>Apps converted with <a href=\"https://github.com/spaley2011/debpak\">debpak</a>. "
        "Installing one downloads the app from its vendor; this site only has debpak's part.</p>\n"
        f"<pre>flatpak remote-add --user{no_verify} --if-not-exists debpak {html.escape(url)}debpak.flatpakrepo</pre>\n"
        "<table><tr><th>App</th><th>Version</th><th>About</th><th>Install</th></tr>\n"
        + "\n".join(rows) + "\n</table>\n</body></html>\n")
    return built
