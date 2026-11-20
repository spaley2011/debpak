"""Windows programs packaged as Flatpaks that run them under Wine.

The Flatpak is built on the org.winehq.Wine base app, which brings Wine,
wine-mono (for .NET programs) and wine-gecko. The program's files go in
/app/opt/NAME, and a launcher in /app/bin starts them:

  - The Wine prefix lives in the app's own data folder
    (~/.var/app/APP_ID/data/wine) and is created on first run.
  - Arguments that name existing files are turned into Windows paths with
    winepath, so "open with" works.
  - /app is read-only. A program that writes next to its own .exe needs
    --writable, which copies it into the prefix's C: drive on first run.
    On an update, files the user changed since the last copy are kept.

When a Wine index is cached (see `winegap index`), the program's imports are
checked against it, and a DLL or function Wine lacks entirely stops the
conversion unless --force is given.
"""
from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

from .foreign import Plan, _need_replay, copy_tree, extra_source, write_integration
from .packages import Package
from .permissions import Permission
from .runtime import parse_ref, sdk_for
from .unpack import APPLY_EXTRA, install_helper

WINE_BASE = "org.winehq.Wine"
DEFAULT_RUNTIME = "org.freedesktop.Platform//25.08"
NETWORK_DLLS = {"ws2_32.dll", "wsock32.dll", "wininet.dll", "winhttp.dll", "urlmon.dll", "iphlpapi.dll",
                "dnsapi.dll", "mswsock.dll"}
# names the launcher must not take, because the Wine base already has them in /app/bin
RESERVED = {"wine", "wine64", "wineboot", "winecfg", "wineserver", "winepath", "msiexec", "regedit", "notepad",
            "winetricks"}


def wine_branch(args) -> tuple[str, str]:
    """Return (base-version of org.winehq.Wine, runtime branch).

    --wine-branch wins and sets the runtime branch to match. Otherwise the
    runtime branch picks it: wow64-25.08 for 25.08 (a 64-bit Wine that also
    runs 32-bit programs, with no i386 runtime needed), stable-BRANCH for
    26.08 and later, where the stable build is WoW64 too.
    """
    wb = getattr(args, "wine_branch", None)
    if wb:
        return wb, wb.rsplit("-", 1)[-1]
    _rid, _arch, branch = parse_ref(getattr(args, "runtime", None) or DEFAULT_RUNTIME, "x86_64")
    return ({"24.08": "wow64-24.08", "25.08": "wow64-25.08"}.get(branch, f"stable-{branch}"), branch)


def _pe_files(root: Path, limit: int = 2000) -> list[Path]:
    """Return up to limit .exe and .dll files under root, for the import scan."""
    out = []
    for p in sorted(root.rglob("*")):
        if p.suffix.lower() in (".exe", ".dll") and p.is_file() and not p.is_symlink():
            out.append(p)
            if len(out) >= limit:
                break
    return out


def _cached_indexes() -> dict:
    """Load the newest cached Wine index for each architecture ({} when none is cached)."""
    from .wine import WineIndex, default_cache
    found: dict = {}
    d = default_cache()
    if not d.is_dir():
        return found
    for f in sorted(d.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            idx = WineIndex.load(f)
        except (OSError, ValueError, KeyError):
            continue
        found.setdefault(idx.arch, idx)
    return found


def plan(pkg: Package, args) -> Plan:
    """Work out a Wine conversion: entry point, architecture, Wine check, permissions, notes and blockers."""
    from .foreign import pick_main_exe
    from .pe import PeError, read_pe
    pl = Plan(pkg, "wine")
    prog = pkg.extra["program_dir"]
    if getattr(args, "exec", None):
        main = pick_main_exe(prog, args.exec)
        if main is None:
            pl.blockers.append(f"--exec {args.exec}: no such program in the package")
        else:
            pkg.extra["main_exe"] = main.relative_to(prog).as_posix()
            pl.notes = [n for n in pl.notes if "(guessed; override with --exec)" not in n]
    main_rel = pkg.extra["main_exe"]
    base_version, branch = wine_branch(args)
    pl.data.update(base_version=base_version, branch=branch)
    try:
        info = read_pe(prog / main_rel)
    except (PeError, OSError, ValueError) as e:
        info = None
        pl.blockers.append(f"{main_rel} can't be read as a Windows program ({e})")
    pl.details += [("from", f"Windows ({pkg.extra.get('unpacked_by')})"),
                   ("program", main_rel + (f" ({info.machine}, {info.subsystem})" if info else "")),
                   ("runs on", f"{WINE_BASE}//{base_version} (org.freedesktop.Platform//{branch})")]
    if pkg.extra.get("company"):
        pl.details.insert(1, ("publisher", pkg.extra["company"]))
    if info:
        if info.machine == "i386":
            pl.notes.append("32-bit program; Wine's WoW64 mode runs it in the 64-bit Wine")
        elif info.machine not in ("x86_64", "i386"):
            pl.blockers.append(f"{main_rel} is built for {info.machine}; the Wine base app is x86_64 only")
        if info.is_dotnet:
            pl.notes.append(".NET program: it runs on wine-mono, which the Wine base app includes. Programs "
                            "that need the real .NET runtime may not work")

    files = _pe_files(prog)
    dlls: set[str] = set()
    for f in files:
        try:
            dlls |= {i.dll.lower() for i in read_pe(f).imports}
        except (PeError, OSError, ValueError):
            continue
    perms = [Permission("--share=ipc", "X11 shared memory"),
             Permission("--socket=x11", "Wine draws windows through X11"),
             Permission("--device=dri", "OpenGL, Vulkan and Direct3D through the GPU"),
             Permission("--socket=pulseaudio", "Wine's sound output")]
    net = sorted(dlls & NETWORK_DLLS)
    if net:
        perms.append(Permission("--share=network", f"imports {net[0]}"))
    if getattr(args, "permissive", False):
        perms.append(Permission("--filesystem=home", "--permissive"))
    else:
        perms += [Permission("--filesystem=xdg-documents", "Wine's file dialogs can't use portals, so the "
                                                          "program only sees folders it's given"),
                  Permission("--filesystem=xdg-download", "same: Downloads")]
    pl.permissions = perms

    indexes = _cached_indexes()
    if indexes:
        from .wine import scan
        result = scan(prog, indexes, pkg.extra.get("display_name"))
        rep = result.report
        pl.details.append(("Wine check", f"{rep.verdict} (against {rep.provider})"))
        if rep.worst == "fatal":
            fatal = [g.key for g in rep.by_tier("fatal")][:8]
            pl.blockers.append("Wine lacks what the program needs to start: " + ", ".join(fatal)
                               + (" ..." if len(rep.by_tier("fatal")) > 8 else "")
                               + " (`winegap scan` gives the full report)")
        elif rep.worst in ("crash", "degraded"):
            pl.notes.append(f"Wine check: {rep.verdict}; `winegap scan` lists them")
    else:
        pl.notes.append("no Wine index is cached, so the program's imports weren't checked against Wine "
                        "(`winegap index` makes one)")
    if not getattr(args, "writable", False):
        pl.notes.append("the program runs from read-only /app; if it saves files next to its .exe, convert "
                        "with --writable")
    return pl


def launcher(pkg: Package, slug: str, main_rel: str, writable: bool, stamp: str) -> str:
    """Return the /app/bin launcher script."""
    name = pkg.extra.get("display_name", slug)
    sub = str(Path(main_rel).parent)
    lines = [
        "#!/bin/sh",
        f"# Generated by debpak: runs {name} under Wine.",
        'export WINEPREFIX="${WINEPREFIX:-$XDG_DATA_HOME/wine}"',
        'export WINEDEBUG="${WINEDEBUG:--all}"',
        "# don't let Wine add its own menu entries; the Flatpak has one",
        'export WINEDLLOVERRIDES="${WINEDLLOVERRIDES:-winemenubuilder.exe=d}"',
        'if [ ! -f "$WINEPREFIX/system.reg" ]; then',
        '    echo "Setting up Wine (first run only)..." >&2',
        "    wineboot --init >/dev/null 2>&1",
        "fi",
        f"PROGRAM=/app/opt/{slug}",
    ]
    if writable:
        lines += [
            "# The program writes next to its .exe, so it runs from a copy in the prefix.",
            "# Files changed since the last copy (settings, saves) are never overwritten.",
            f'DEST="$WINEPREFIX/drive_c/Program Files/{slug}"',
            f'if [ "$(cat "$DEST/.debpak-version" 2>/dev/null)" != "{stamp}" ]; then',
            f'    echo "Copying {name} into the Wine prefix..." >&2',
            '    mkdir -p "$DEST"',
            '    (cd "$PROGRAM" && find . -type f) | while IFS= read -r f; do',
            '        if [ -e "$DEST/$f" ]; then',
            '            sum=$(cd "$DEST" && md5sum "$f")',
            '            grep -qxF "$sum" "$DEST/.debpak-sums" 2>/dev/null || continue',
            "        fi",
            '        mkdir -p "$(dirname "$DEST/$f")"',
            '        cp -p "$PROGRAM/$f" "$DEST/$f"',
            "    done",
            '    (cd "$PROGRAM" && find . -type f -exec md5sum {} +) > "$DEST/.debpak-sums"',
            f'    echo "{stamp}" > "$DEST/.debpak-version"',
            "fi",
            'PROGRAM="$DEST"',
        ]
    lines += [
        "# Windows programs expect Windows paths: convert arguments that name existing files.",
        'for a; do',
        "    shift",
        '    if [ -e "$a" ]; then a=$(winepath -w "$a" 2>/dev/null || printf "%s" "$a"); fi',
        '    set -- "$@" "$a"',
        "done",
        "# many programs look for their files in the current folder",
        f'cd "$PROGRAM/{sub}" || exit 1' if sub != "." else 'cd "$PROGRAM" || exit 1',
        f'exec wine "$PROGRAM/{main_rel}" "$@"',
    ]
    return "\n".join(lines) + "\n"


def write(pl: Plan, out: Path, app_id: str, args) -> Path:
    """Write out/app (program files, launcher, desktop integration) and the manifest; return the manifest path."""
    from .winres import extract_png
    pkg = pl.pkg
    slug = pkg.name if pkg.name not in RESERVED else f"{pkg.name}-app"
    prog = pkg.extra["program_dir"]
    main_rel = pkg.extra["main_exe"]
    app = out / "app"
    if app.exists():
        shutil.rmtree(app)
    extra_data = getattr(args, "mode", "bundle") == "extra-data"
    build = ["cp -a bin share ${FLATPAK_DEST}/", f"chmod +x ${{FLATPAK_DEST}}/bin/{slug}"]
    sources: list[dict] = [{"type": "dir", "path": "app"}]
    if extra_data:
        # Flatpak downloads the original at install time; apply_extra unpacks the program
        # into /app/extra/program, and /app/opt/NAME points there.
        replay = _need_replay(pkg, args)
        extra_name, extra_src = extra_source(pkg, args.url)
        sources.append(extra_src)
        install_helper(app, {"source": extra_name, "steps": replay["steps"], "take": replay["take"],
                             "target": "program", "drop": replay["drop"]})
        (app / "bin" / "apply_extra").write_text(APPLY_EXTRA)
        (app / "bin" / "apply_extra").chmod(0o755)
        build.append(f"install -d ${{FLATPAK_DEST}}/opt && ln -s /app/extra/program ${{FLATPAK_DEST}}/opt/{slug}")
    else:
        copy_tree(prog, app / "opt" / slug)
        build[0] = "cp -a opt bin share ${FLATPAK_DEST}/"
    writable = bool(getattr(args, "writable", False))
    h = hashlib.sha256()
    with open(prog / main_rel, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    stamp = f"{pkg.version}-{h.hexdigest()[:12]}"
    (app / "bin").mkdir(parents=True, exist_ok=True)
    script = app / "bin" / slug
    script.write_text(launcher(pkg, slug, main_rel, writable, stamp))
    script.chmod(0o755)
    pl.notes += write_integration(app, app_id, pkg, slug, extract_png(prog / main_rel),
                                  wm_class=Path(main_rel).name.lower(), exec_codes="%F")

    base_version, branch = pl.data["base_version"], pl.data["branch"]
    ext = ["org.winehq.Wine.gecko", "org.winehq.Wine.mono"]
    if base_version.startswith("wow64-"):
        ext = [e + "-wow64" for e in ext]
    from . import __version__
    manifest = {
        "id": app_id,
        "runtime": "org.freedesktop.Platform",
        "runtime-version": branch,
        "sdk": sdk_for("org.freedesktop.Platform"),
        "base": WINE_BASE,
        "base-version": base_version,
        "inherit-extensions": ext,
        "command": slug,
        "separate-locales": False,
        "finish-args": [p.arg for p in pl.permissions],
        "modules": [{
            "name": slug,
            "buildsystem": "simple",
            "build-commands": build,
            "sources": sources,
        }],
        "x-debpak": {"generator": f"debpak {__version__}", "source-package": pkg.path.name, "format": pkg.format,
                     "route": "wine", "mode": "extra-data" if extra_data else "bundle",
                     "package": f"{pkg.name} {pkg.version}",
                     "unpacked-by": pkg.extra.get("unpacked_by"), "entry-point": f"/app/opt/{slug}/{main_rel}",
                     "writable": writable,
                     "permission-reasons": {p.arg: p.reason for p in pl.permissions}},
    }
    path = out / f"{app_id}.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    return path
