"""Lay out the /app tree and write the flatpak-builder manifest.

Two modes:
  bundle      the vendor's files are copied into the Flatpak. Simple, but you
              are redistributing the vendor's binaries.
  extra-data  the manifest names the vendor's file by URL and sha256, and an
              apply_extra script unpacks it on the user's machine at install
              time (how Flathub ships Chrome and Slack).
Libraries added to fill gaps always go in /app/lib/debpak.
"""
from __future__ import annotations

import hashlib
import json
import mmap
import os
import re
import shlex
import shutil
import struct
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__
from .analyze import CHROMIUM_KINDS, Analysis, _is_electron_helper, _is_script, desktop_entry_value, sandbox_filename
from . import net
from .desktop import app_display_name, install_icons, install_mime, metainfo, placeholder_icon, rewrite_desktop
from .deb import resolve_in_root
from .maintscripts import STRIP_PREFIXES, keeps_chromium_sandbox
from .permissions import Permission
from .resolve import HELPER_DIRS
from .runtime import TRIPLETS, parse_ref, sdk_for

WRAPPER = "debpak-run"
BUNDLED_LIBDIR = "lib/debpak"
ELECTRON_BASE = "org.electronjs.Electron2.BaseApp"


@dataclass
class StageResult:
    """Where stage() wrote the manifest, and notes for the report."""
    manifest_path: Path
    notes: list[str] = field(default_factory=list)


def map_bundle(rel: str) -> str:
    """Map a payload path to its place under /app in bundle mode: usr/bin/x -> bin/x, opt/V -> opt/V."""
    rel = rel.strip("/")
    if rel.startswith("usr/local/"):
        return rel[len("usr/local/"):]
    if rel.startswith("usr/"):
        return rel[len("usr/"):]
    return opt_without_spaces(rel)


def opt_without_spaces(rel: str) -> str:
    """Replace blanks in a payload path's opt/ folder: opt/Beekeeper Studio/x -> opt/Beekeeper-Studio/x.

    electron-builder installs .deb and .rpm apps in /opt/<product name>. Chromium splits
    the path of its sandbox helper (beside the program) at blanks when it starts the
    zygote, so under zypak such an app dies with "failed to execvp: /app/opt/Beekeeper".
    """
    parts = rel.strip("/").split("/")
    if len(parts) >= 2 and parts[0] == "opt" and re.search(r"\s", parts[1]):
        parts[1] = re.sub(r"\s+", "-", parts[1].strip())
    return "/".join(parts)


def install_path(rel: str, mode: str) -> str:
    """Return where a payload path ends up in the sandbox: under /app in bundle mode, /app/extra in extra-data mode."""
    return "/app/extra/" + opt_without_spaces(rel) if mode == "extra-data" else "/app/" + map_bundle(rel)


def _stripped(rel: str) -> bool:
    """Return True for payload paths in STRIP_PREFIXES (cron jobs, systemd units, ...), which aren't copied."""
    return any(rel == p or rel.startswith(p + "/") for p in STRIP_PREFIXES)


def _copy_payload(root: Path, dest: Path) -> None:
    """Copy the package's files into the /app tree, mapped with map_bundle.

    Stripped paths and the original .desktop files (stage writes its own) are
    left out. Symlinks are rewritten as relative links to the target's new place;
    a link that points outside the package is dropped.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        keep_dirs = []
        for d in dirnames:
            rel = f"{rel_dir}/{d}".lstrip("/")
            if _stripped(rel):
                continue
            if (Path(dirpath) / d).is_symlink():
                filenames.append(d)
            else:
                keep_dirs.append(d)
        dirnames[:] = keep_dirs
        for fn in filenames:
            rel = f"{rel_dir}/{fn}".lstrip("/")
            if _stripped(rel) or (rel.startswith("usr/share/applications/") and rel.endswith(".desktop")):
                continue
            src = Path(dirpath) / fn
            out = dest / map_bundle(rel)
            out.parent.mkdir(parents=True, exist_ok=True)
            if src.is_symlink():
                target = os.readlink(src)
                target_rel = (target.lstrip("/") if target.startswith("/")
                              else os.path.normpath(os.path.join(rel_dir, target)))
                if target_rel.startswith(".."):
                    continue  # escapes the payload; drop it
                if target.startswith("/") and resolve_in_root(root, target_rel) is None:
                    # an absolute link to a file the package doesn't ship names the system's own
                    # file (appimage-builder's runtime/default links to /lib64/ld-linux-x86-64.so.2),
                    # which the runtime has at the same path; pointing it into /app would leave it
                    # dangling
                    link = target
                else:
                    link = os.path.relpath(map_bundle(target_rel), os.path.dirname(map_bundle(rel)) or ".")
                if out.exists() or out.is_symlink():
                    out.unlink()
                os.symlink(link, out)
            elif src.is_file():
                shutil.copy2(src, out)


def _rewrite_prefixes(a: Analysis, mode: str) -> list[tuple[str, str]]:
    """Return (old, new) install prefixes for the hardcoded paths found, longest first so nested prefixes rewrite correctly."""
    pairs = set()
    for h in a.hardcoded:
        for prefix in [h.prefix] if h.prefix else _prefix_candidates(h.path, a.pkg.name):
            pairs.add((prefix, install_path(prefix, mode)))
    return sorted(pairs, key=lambda p: -len(p[0]))


def _prefix_candidates(path: str, pkg_name: str) -> list[str]:
    """Return the install prefix a hardcoded path sits under (/opt/<dir>, /usr/share/<pkg> or /usr/lib/<pkg>), if any."""
    parts = path.strip("/").split("/")
    if parts[0] == "opt" and len(parts) >= 2:
        return ["/" + "/".join(parts[:2])]
    if parts[:2] in (["usr", "share"], ["usr", "lib"]) and len(parts) >= 3 and parts[2] == pkg_name:
        return ["/" + "/".join(parts[:3])]
    return []


def library_path_dirs(a: Analysis, mode: str, have_bundled: bool) -> list[str]:
    """Return the folders the wrapper puts on LD_LIBRARY_PATH.

    That's the bundle's lib/debpak when libraries were added, the package's own
    library folders that hold a needed soname, any absolute RPATH folder the
    package ships, and, when the launcher script debpak skips set LD_LIBRARY_PATH,
    the folders of libraries the dynamic linker wouldn't find without it. /app/lib
    is left out, being on the default path already.
    """
    dirs: list[str] = []
    if have_bundled:
        dirs.append("/app/" + BUNDLED_LIBDIR)
    triplet = TRIPLETS.get(a.arch, f"{a.arch}-linux-gnu")
    standard = {"usr/lib", "lib", f"usr/lib/{triplet}", f"lib/{triplet}", "usr/lib64", "lib64"}
    needed_pkg_dirs = set()
    for soname, rel in a.package_sonames.items():
        d = os.path.dirname(rel)
        if d in standard and (soname in _all_needed(a)):
            needed_pkg_dirs.add(d)
    for rp in sorted(a.abs_rpath_dirs):
        rel = rp.strip("/")
        if (a.root / rel).is_dir():
            needed_pkg_dirs.add(rel)
    needed_pkg_dirs |= _unreachable_from_main(a) - standard
    if _script_sets_library_path(a):
        needed_pkg_dirs |= _unreachable_lib_dirs(a) - standard
    for d in sorted(needed_pkg_dirs):
        if _carries_toolchain(a, d):
            continue    # a module's private copy of the C++ runtime would shadow the runtime's for everything
        p = install_path(d, mode)
        if mode == "bundle" and p in ("/app/lib",):
            continue  # already on the default search path
        if p not in dirs:
            dirs.append(p)
    return dirs


def _carries_toolchain(a: Analysis, d: str) -> bool:
    """Return whether package folder d holds its own copy of the C or C++ runtime.

    Such a folder is one module's private stack, found through that module's
    own RPATH (AnythingLLM's canvas module ships libstdc++.so.6 beside its
    cairo); on LD_LIBRARY_PATH it would shadow the runtime's newer copy for
    every program, and zypak-helper then fails to load.
    """
    return any(os.path.dirname(rel) == d and so.startswith(TOOLCHAIN_LIBS)
               for so, rel in a.package_sonames.items())


def _script_sets_library_path(a: Analysis) -> bool:
    """Return True if the launcher script debpak doesn't run (see Analysis.bypassed_script) sets LD_LIBRARY_PATH."""
    if not a.bypassed_script:
        return False
    script = resolve_in_root(a.root, a.bypassed_script)
    # only a script says what it sets; a compiled launcher (sharun's AppRun) names
    # LD_LIBRARY_PATH among its strings but its bundled glibc must not go on it
    if script is None or not _is_script(script):
        return False
    try:
        return "LD_LIBRARY_PATH" in script.read_text("utf-8", "replace")
    except OSError:
        return False


# the variables Chromium's own launcher script (chrome-wrapper) exports, as Google Chrome's
# google-chrome and Slimjet's flashpeak-slimjet (renamed SLIMJET_WRAPPER) do
CHROMIUM_WRAPPER_VAR = re.compile(r"^\s*export\s+([A-Z][A-Z0-9]*_(?:WRAPPER|DESKTOP))=", re.M)


def chromium_wrapper_env(a: Analysis) -> list[str]:
    """Return launcher lines that set the variables a Chromium browser's own launcher script sets.

    A browser built from Chromium learns from them how it was started: the
    script's path (to start itself again and to register as the default
    browser) and its menu entry. Slimjet refuses to start without them ("Please
    launch slimjet via the wrapper script: flashpeak-slimjet"). debpak runs the
    browser without that script (Analysis.bypassed_script), so the launcher sets
    them: the script is debpak's launcher, and the menu entry the Flatpak's own.
    """
    if a.kind not in CHROMIUM_KINDS or not a.bypassed_script:
        return []
    script = resolve_in_root(a.root, a.bypassed_script)
    if script is None or not _is_script(script):
        return []
    try:
        names = dict.fromkeys(CHROMIUM_WRAPPER_VAR.findall(script.read_text("utf-8", "replace")))
    except OSError:
        return []
    return [f"export {n}=/app/bin/{WRAPPER}" if n.endswith("_WRAPPER") else f'export {n}="$FLATPAK_ID.desktop"'
            for n in names]


def _search_dirs(info, rel: str) -> set[str]:
    """Return the payload folders an ELF file's RPATH and RUNPATH name, $ORIGIN expanded."""
    out = set()
    for rp in info.rpath + info.runpath:
        rp = rp.replace("${ORIGIN}", "$ORIGIN")
        if rp.startswith("$ORIGIN"):
            rp = os.path.join(os.path.dirname(rel), rp[len("$ORIGIN"):].lstrip("/"))
        elif not rp.startswith("/"):
            continue
        out.add(os.path.normpath(rp.strip("/")) if rp.strip("/") else "")
    return out


def _unreachable_from_main(a: Analysis) -> set[str]:
    """Return the folders of libraries the main program loads that the dynamic linker won't find.

    A program's RUNPATH serves only its own needs, not those of the libraries
    it loads: Reqable's $ORIGIN/lib finds its libayatana-appindicator3.so.1,
    whose libdbusmenu-gtk3.so.4 beside it isn't found ("cannot open shared
    object file"). Each library's needs are looked up through its own RPATH
    and RUNPATH, and the program's RPATH (not its RUNPATH).
    """
    main = a.main_exec if a.main_exec in a.elfs else None
    if not main or getattr(a.pkg, "extra", {}).get("sharun"):
        return set()            # sharun's programs get their libraries from sharun's own loader
    info = a.elfs[main]
    main_rpath = _search_dirs(info, main) if not info.runpath else set()
    out: set[str] = set()
    found: set[str] = set()
    queue = [main]
    while queue:
        rel = queue.pop(0)
        dirs = _search_dirs(a.elfs[rel], rel) | main_rpath
        for n in a.elfs[rel].needed:
            prov = a.package_sonames.get(n)
            if n in found or not prov or prov not in a.elfs or n.startswith(TOOLCHAIN_LIBS):
                continue
            found.add(n)
            d = os.path.dirname(prov)
            if d not in dirs:
                out.add(d)
            queue.append(prov)
    return out


def _unreachable_lib_dirs(a: Analysis) -> set[str]:
    """Return the package's folders holding libraries that the dynamic linker won't find.

    A vendor's launcher script often sets LD_LIBRARY_PATH to the app's folder, which
    debpak's launcher doesn't run (Chromium apps start through zypak). Libraries the
    main program loads are found through its RPATH and are already loaded when a plugin
    needs them; but a plugin's other needs are looked up through the plugin's own RPATH
    (and the program's DT_RPATH, never its RUNPATH): ONLYOFFICE's Qt platform plugin
    needs libQt5XcbQpa.so.5 beside the program and fails to load without the script.
    """
    main = a.main_exec if a.main_exec in a.elfs else None
    loaded: set[str] = set()
    queue = [main] if main else []
    seen: set[str] = set()
    while queue:
        rel = queue.pop()
        if rel in seen:
            continue
        seen.add(rel)
        for n in a.elfs[rel].needed:
            loaded.add(n)
            prov = a.package_sonames.get(n)
            if prov in a.elfs:
                queue.append(prov)
    main_rpath = _search_dirs(a.elfs[main], main) if main and not a.elfs[main].runpath else set()
    out = set()
    for rel, info in a.elfs.items():
        is_plugin = not info.is_executable
        dirs = _search_dirs(info, rel) | (main_rpath if is_plugin and not info.runpath else set())
        for n in info.needed:
            prov = a.package_sonames.get(n)
            if not prov or (is_plugin and n in loaded) or n.startswith(TOOLCHAIN_LIBS):
                continue
            d = os.path.dirname(prov)
            if d not in dirs and (a.root / d).is_dir():
                out.add(d)
    return out


# The C and C++ runtime: the runtime always has them, newer than any copy a package
# carries, and a package folder put on LD_LIBRARY_PATH for one of them shadows the
# runtime's for every program (AnythingLLM's canvas module ships an old libstdc++.so.6,
# which zypak-helper then failed to load with)
TOOLCHAIN_LIBS = ("libstdc++.so", "libgcc_s.so", "libc.so", "libm.so", "ld-linux")


def _all_needed(a: Analysis) -> set[str]:
    """Return every DT_NEEDED soname across the package's ELF files."""
    s: set[str] = set()
    for info in a.elfs.values():
        s.update(info.needed)
    return s


# zypak works with the sandbox of Electron 5 and later; under it Electron 2 (React Proto's) segfaults at once
ZYPAK_MIN_ELECTRON = 5


def electron_major(path: Path) -> int | None:
    """Return the major version of the Electron a program is (from its Chrome/... Electron/X.Y.Z string)."""
    try:
        with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
            hit = re.search(rb"Electron/(\d+)\.\d+\.\d+", m)
            return int(hit.group(1)) if hit else None      # while the map is open
    except (OSError, ValueError):
        return None


def old_electron(a: Analysis) -> bool:
    """True for an Electron too old for zypak: it starts with --no-sandbox instead."""
    if a.no_chromium_sandbox and a.kind in CHROMIUM_KINDS:
        return True
    if a.kind != "electron" or not a.main_exec or a.main_exec not in a.elfs:
        return False
    major = electron_major(a.root / a.main_exec)
    return major is not None and major < ZYPAK_MIN_ELECTRON


def uses_zypak(a: Analysis) -> bool:
    """Return True if the launcher starts the entry point through zypak-wrapper.

    Electron and Chromium binaries need zypak: Chromium's own sandbox can't start
    inside a Flatpak. A CEF app needs it only when it keeps that sandbox, which its
    package shows by shipping chrome-sandbox or by having its scripts make it
    setuid or load an AppArmor profile for it (Webex, Zoom). Otherwise the vendor
    runs CEF with the sandbox off, and the app starts directly, as Flathub starts
    Spotify: under zypak Spotify's process dies at once ("zypak-helper: Wait found
    events, but sd-event found none"). A downloader for an Electron client
    (Analysis.downloads_client) runs under zypak too, see wrapper_script.
    """
    if a.kind not in CHROMIUM_KINDS or (a.main_exec_is_script and not a.downloads_client):
        return False
    if old_electron(a):
        return False
    if a.kind == "cef":
        return any(_is_electron_helper(Path(r).name) and "sandbox" in Path(r).name for r in a.elfs) \
            or keeps_chromium_sandbox(a.findings)
    return True


def is_chromium_browser(a: Analysis) -> bool:
    """Return True if the app is a Chromium web browser (Edge, Chrome, Brave, Vivaldi) rather than an Electron app.

    Its menu entry offers it for web links (x-scheme-handler/http or text/html), and
    no Electron app (resources/app.asar or resources/app) sits beside its program.
    """
    if a.kind != "electron" or not a.main_exec or not a.desktop_file:
        return False
    exe = resolve_in_root(a.root, a.main_exec) or a.root / a.main_exec
    if (exe.parent / "resources").is_dir():
        return False
    try:
        text = (a.root / a.desktop_file).read_text("utf-8", "replace")
    except OSError:
        return False
    mime = (desktop_entry_value(text, "MimeType") or "").split(";")
    return "x-scheme-handler/http" in mime or "text/html" in mime


# Waits, once the program has exited, while anything else runs in the sandbox. When the
# first process in a Flatpak exits, Flatpak ends the sandbox and kills what is left in it,
# but programs hand over to a process of their own and exit: Sublime Text forks into the
# background, Rocket.Chat restarts itself with --disable-gpu when the GPU is unusable.
# PID 1 is bubblewrap's init and the launcher is PID 2; started any other way (flatpak
# enter, flatpak-spawn) it isn't, and nothing ends when it exits. Zombies and a lingering
# crash reporter don't count.
WAIT_FOR_OTHERS = """status=$?
[ $$ = 2 ] || exit $status
while :; do
    busy=
    for p in /proc/[0-9]*; do
        p=${p#/proc/}
        [ "$p" = 1 ] || [ "$p" = $$ ] && continue
        name= state=
        while read -r key value _; do
            case $key in Name:) name=$value ;; State:) state=$value; break ;; esac
        done 2>/dev/null < "/proc/$p/status"
        case $state:$name in :*|Z:*|X:*|*:*crashpad*) continue ;; esac
        busy=1
        break
    done
    [ -n "$busy" ] || break
    sleep 1
done
exit $status"""



# the settings at the top of Discord's /usr/bin/discord: CHANNEL=stable, DOWNLOAD=https://updates.discord.com/, ...
DOWNLOADER_SETTING = re.compile(r"^(CHANNEL|DOWNLOAD|DIR|EXE)=([A-Za-z0-9_.:/-]+)\s*$", re.M)


def downloader_settings(a: Analysis) -> dict[str, str] | None:
    """Return the settings of the script a downloader package starts its downloader with, or None.

    Discord's script runs `updater_bootstrap ~/.config/discord stable
    https://updates.discord.com/` the first time, which prints the folder it
    put the client in, and from then on starts ~/.config/discord/Discord.
    """
    if not a.bypassed_script:
        return None
    try:
        text = (a.root / a.bypassed_script).read_text("utf-8", "replace")
    except OSError:
        return None
    found = dict(DOWNLOADER_SETTING.findall(text))
    return found if set(found) == {"CHANNEL", "DOWNLOAD", "DIR", "EXE"} else None


def bootstrap_lines(boot: dict[str, str], downloader: str, zypak: bool) -> list[str]:
    """Return launcher lines that do what the vendor's script does, with the client started under zypak.

    The downloader itself isn't Chromium, so it runs directly; zypak can't
    start the vendor's script, which isn't an ELF program.
    """
    q = shlex.quote
    folder = f'"$config_home"/{q(boot["DIR"])}'
    return [
        "# what the package's own launcher script does, with the client it downloads started under zypak",
        'config_home="${XDG_CONFIG_HOME:-$HOME/.config}"',
        f'client={folder}/{q(boot["EXE"])}',
        'if [ ! -x "$client" ]; then',
        f"    mkdir -p {folder} || exit 1",
        f'    app_dir=$({q(downloader)} {folder} {q(boot["CHANNEL"])} {q(boot["DOWNLOAD"])}) || {{',
        '        echo "Bootstrap failed or was canceled" >&2',
        "        exit 2",
        "    }",
        f'    client={folder}/"$app_dir"/{q(boot["EXE"])}',
        "fi",
        f'{"zypak-wrapper " if zypak else ""}"$client" "$@"',
    ]


def restarts_itself(a: Analysis) -> bool:
    """Return True for LibreOffice, whose soffice.bin exits with 81 to be started again (see wrapper_script)."""
    return any(r.endswith("/program/soffice.bin") for r in a.elfs)


def wrapper_script(a: Analysis, mode: str, lib_dirs: list[str], env: dict[str, str] | None = None) -> str:
    """Write the launcher script that the Flatpak's command and .desktop file run.

    It sets LD_LIBRARY_PATH and any env VAR=... from the original Exec= line,
    copies first-run files into the home folder (Analysis.home_skel), then runs
    the entry point (through zypak-wrapper for Electron and most CEF binaries, see
    uses_zypak; zypak needs ZYPAK_CEF_LIBRARY_PATH to find a CEF app's libcef.so).
    Started with no arguments, as `flatpak run` starts it, it passes the ones
    the menu entry's Exec= gives the program (Espanso's menu entry runs
    `espanso launcher`; plain `espanso` prints its help); the menu entry
    passes them itself. When the program exits, the launcher waits for any
    process it left running (WAIT_FOR_OTHERS), then exits with the program's
    status. LibreOffice is started again when it exits with 81, its request
    for a restart (restarts_itself).

    A package that is only a downloader for an Electron client (Discord's
    updater_bootstrap) runs under zypak-wrapper as well: zypak works through
    LD_PRELOAD and environment variables, which the client the downloader
    starts inherits. ZYPAK_DISABLE_SANDBOX=1 has zypak start Chromium's helper
    processes in the app's own sandbox, where they can reach the client in the
    app's data folder; a sandbox of their own only sees /app.

    A Chromium web browser (is_chromium_browser) starts with --no-first-run. Its
    first run offers to import from the other browsers on the computer and to
    become the default browser, and neither can work in the sandbox: it hides the
    other browsers' profiles, and the host's default browser can't be set from
    inside it. Microsoft Edge's welcome page goes further and stops at a blank
    dialog over the window, its script failing on the empty list of browsers to
    import from ("Cannot read properties of undefined (reading 'importerType')").
    Import from a file still works later, from the browser's settings.
    """
    target = install_path(a.main_exec, mode)
    lines = ["#!/bin/sh", f"# Generated by debpak {__version__} for {a.pkg.name} {a.pkg.version}"]
    if a.writable and (m := re.match(r"(/app/(?:extra/)?opt/[^/]+)/(.+)$", target)):
        # --writable: the program writes next to itself (a game's saves, a portable app's settings),
        # so it runs from a copy of its folder in the app's data, refreshed when the version changes
        src, rest = m.groups()
        dest = '"${XDG_DATA_HOME:-$HOME/.local/share}/debpak-writable/' + Path(src).name + '"'
        stamp = shlex.quote(f"{a.pkg.name} {a.pkg.version}")
        lines += [f"# --writable: run from a copy of {src}",
                  f"if [ \"$(cat {dest}/.debpak-version 2>/dev/null)\" != {stamp} ]; then",
                  f"    mkdir -p {dest} && cp -a {src}/. {dest}/ && echo {stamp} > {dest}/.debpak-version",
                  "fi"]
        target = dest[:-1] + "/" + rest + '"'
        quoted_target = target
    else:
        quoted_target = shlex.quote(target)
    if lib_dirs:
        lines.append(f'export LD_LIBRARY_PATH="{":".join(lib_dirs)}${{LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}}"')
    if getattr(a.pkg, "format", "") == "appimage" and (opt := getattr(a.pkg, "extra", {}).get("opt_name")):
        # the AppImage runtime sets APPDIR to the mounted image; compiled AppRuns
        # (appimage-builder's, sharun's) and many AppRun scripts look there for the app
        lines.append(f"export APPDIR={shlex.quote(install_path('opt/' + opt, mode))}")
    for k, v in sorted({**a.desktop_exec_env, **(env or {})}.items()):
        lines.append(f"export {k}={shlex.quote(v)}")
    lines += chromium_wrapper_env(a)
    zypak = uses_zypak(a)
    if zypak and a.kind == "cef" and (cef := a.package_sonames.get("libcef.so")):
        lines.append(f"export ZYPAK_CEF_LIBRARY_PATH={shlex.quote(install_path(cef, mode))}")
    if a.downloads_client:
        lines.append("export ZYPAK_DISABLE_SANDBOX=1")
    if zypak and (sandbox := sandbox_filename(a.root, a.main_exec)):
        lines.append(f"export ZYPAK_SANDBOX_FILENAME={shlex.quote(sandbox)}")
    if a.home_skel:
        skel, home_dir = a.home_skel
        src, dest = shlex.quote(install_path(skel, mode)), f'"$HOME"/{shlex.quote(home_dir)}'
        lines += [f"# the program copies these into ~/{home_dir} at first start, from /{skel}",
                  f"mkdir -p {dest}",
                  f"for f in {src}/*; do",
                  f'    [ -e {dest}/"${{f##*/}}" ] || cp -R "$f" {dest}/',
                  "done"]
    if a.desktop_exec_args:
        lines.append('[ "$#" -gt 0 ] || set -- ' + " ".join(shlex.quote(x) for x in a.desktop_exec_args))
    if a.downloads_client and (boot := downloader_settings(a)):
        lines += bootstrap_lines(boot, target, zypak)
    elif restarts_itself(a):
        # LibreOffice's soffice.bin exits with status 81 once its first start has set up the
        # user profile, asking to be started again. Its oosplash does that, but an AppImage
        # (LibreItalia's) starts soffice.bin itself, and the app then quit without a window
        lines += ["# LibreOffice asks to be started again with status 81, as its oosplash would",
                  f'while {"zypak-wrapper " if zypak else ""}{quoted_target} "$@"; status=$?; '
                  '[ "$status" = 81 ]; do :; done',
                  "(exit $status)"]
    else:
        first_run = ""
        if old_electron(a):
            lines.append("# no Chromium sandbox: " + ("--no-chromium-sandbox" if a.no_chromium_sandbox else
                         f"Electron {electron_major(a.root / a.main_exec)} is older than zypak supports"))
            first_run = "--no-sandbox "
        if is_chromium_browser(a):
            lines.append("# a browser's first-run import and default-browser steps can't reach the host")
            first_run = "--no-first-run "
        lines.append(f'{"zypak-wrapper " if zypak else ""}{quoted_target} {first_run}"$@"')
    lines.append(WAIT_FOR_OTHERS)
    return "\n".join(lines) + "\n"


def extra_filename(pkg) -> str:
    """Return the vendor file's name in /app/extra, with the extension its format needs."""
    fmt = getattr(pkg, "format", "deb")
    if fmt == "deb":
        return f"{pkg.name}.deb"
    if fmt == "rpm":
        return f"{pkg.name}.rpm"
    if fmt == "appimage":
        return f"{pkg.name}.AppImage"
    m = re.search(r"(\.pkg\.tar(?:\.\w+)?|\.tar\.\w+|\.tgz|\.txz|\.tbz2?|\.tar|\.zip)$", pkg.path.name, re.I)
    return pkg.name + (m.group(1) if m else ".archive")


def apply_extra_script(a: Analysis, filename: str) -> str:
    """Unpack the vendor's file inside /app/extra at install time, into the same layout
    debpak analyzed (usr/..., opt/NAME/...)."""
    pkg = a.pkg
    fmt = getattr(pkg, "format", "deb")
    f = shlex.quote(filename)
    lines = ["#!/bin/sh", "set -e", f"# Generated by debpak {__version__}: unpack {pkg.name} ({fmt}) at install time"]
    if fmt == "deb":
        lines.append(f"bsdtar -Oxf {f} 'data.tar*' | bsdtar -xf -")
    elif fmt == "rpm":
        lines.append(f"bsdtar -xf {f}")                      # libarchive reads RPM payloads
    elif fmt == "pacman":
        lines.append(f"bsdtar -xf {f} --exclude .PKGINFO --exclude .MTREE --exclude .BUILDINFO "
                     "--exclude .INSTALL --exclude .CHANGELOG")
    elif fmt == "run":
        if "replay" not in pkg.extra:
            raise ValueError("--mode extra-data can't unpack this .run installer at install time (its payload "
                             "is zstd-compressed); use the default bundle mode")
        lines.append("python3 /app/bin/debpak-unpack /app/share/debpak/unpack.json")
    elif fmt == "appimage":
        opt = shlex.quote(f"opt/{pkg.extra['opt_name']}")
        # uruntime ("anylinux") AppImages unpack into AppDir and leave squashfs-root as a symlink to it
        lines += [f"chmod +x {f}", f"./{filename} --appimage-extract >/dev/null",
                  f'mkdir -p opt && rm -rf {opt} && mv "$(readlink -f squashfs-root)" {opt} && rm -f squashfs-root']
        # the same real programs in place of sharun's launcher copies as at build time (see unwrap_sharun)
        for real, stubs in pkg.extra.get("sharun", []):
            src = shlex.quote(f"opt/{pkg.extra['opt_name']}/{real}")
            for s in stubs:
                lines.append("rm -f " + shlex.quote(f"opt/{pkg.extra['opt_name']}/{s}"))
            for s in stubs[:-1]:
                lines.append(f"cp -p {src} " + shlex.quote(f"opt/{pkg.extra['opt_name']}/{s}"))
            lines.append(f"mv {src} " + shlex.quote(f"opt/{pkg.extra['opt_name']}/{stubs[-1]}"))
    else:   # plain archive
        opt = shlex.quote(f"opt/{pkg.extra['opt_name']}")
        strip = int(pkg.extra.get("strip", 0))
        lines += [f"mkdir -p {opt}",
                  f"bsdtar -xf {f} -C {opt}" + (f" --strip-components {strip}" if strip else "")]
        if marker := pkg.extra.get("marker"):
            lines.append("touch " + shlex.quote(f"opt/{pkg.extra['opt_name']}/{marker}"))
    lines.append(f"rm -f {f}")
    strip = [p for p in STRIP_PREFIXES if (a.root / p).exists()]
    if strip:
        lines.append("rm -rf " + " ".join(shlex.quote(p) for p in strip))
    opt_root = a.root / "opt"
    for d in sorted(opt_root.iterdir() if opt_root.is_dir() else []):
        if d.is_dir() and (new := opt_without_spaces(f"opt/{d.name}")) != f"opt/{d.name}":
            lines.append(f"mv {shlex.quote('opt/' + d.name)} {shlex.quote(new)}")
    pairs = _rewrite_prefixes(a, "extra-data")
    text_files = sorted({opt_without_spaces(h.file) for h in a.hardcoded if h.is_text})
    if pairs and text_files:
        # a path that follows a variable or a command (${HERE}/opt/xpipe) is relative to it, not absolute
        before, after = "\\(^\\|[^A-Za-z0-9._/})-]\\)", "\\([^A-Za-z0-9._-]\\|$\\)"
        expr = " ".join("-e " + shlex.quote(f"s#{before}{old}{after}#\\1{new}\\2#g") for old, new in pairs)
        for f in text_files:
            lines.append(f"sed -i {expr} {shlex.quote(f)}")
    return "\n".join(lines) + "\n"


# libraries the runtime's own programs (bash, sh) load; the copy a package bundles is found first
# through the app's library path, by those programs too when the app runs them
SHELL_LIBRARIES = ("libreadline.so", "libhistory.so", "libtinfo.so", "libncurses.so", "libncursesw.so")


def _drop_shadowing_libraries(a: Analysis, app: Path, res) -> None:
    """Leave out a bundled readline or ncurses the runtime has under the same name.

    Vease's AppImage carries an older libreadline.so.8, and the runtime's bash, run
    by the app with the app's library path, then failed: "undefined symbol:
    rl_full_quoting_desc". The same name promises the same interface, so the
    app's own programs work with the runtime's newer copy.
    """
    if not a.runtime:
        return
    dropped = []
    for so, rel in sorted(a.package_sonames.items()):
        if so.startswith(SHELL_LIBRARIES) and a.runtime.provides(so):
            p = app / map_bundle(rel)
            if p.is_file() or p.is_symlink():
                p.unlink()
                dropped.append(so)
    if dropped:
        res.notes.append(f"left out the package's {', '.join(dropped)}: the runtime has them, and its "
                         "shell breaks on an older copy in the app's library path")


def _fix_interpreters(a: Analysis, app: Path, res) -> None:
    """Point programs whose loader is somewhere the Flatpak has none at the runtime's own.

    A classic snap's programs load through /snap/core22/current/lib64/ld-linux-x86-64.so.2
    (Alacritty's: "cannot execute: required file not found"), a Nix build's through
    /nix/store/...; a loader the package ships itself stays.
    """
    from .elf import STANDARD_INTERP, set_interpreter
    fixed = []
    for rel, info in a.elfs.items():
        interp = info.interp
        std = STANDARD_INTERP.get(info.machine)
        if not interp or not std or interp == std or not interp.startswith(("/snap/", "/nix/", "/gnu/store/")):
            continue
        if resolve_in_root(a.root, interp.lstrip("/")) is not None:
            continue
        p = app / map_bundle(rel)
        if p.is_file() and not p.is_symlink() and set_interpreter(p, std):
            fixed.append(rel)
    if fixed:
        res.notes.append(f"pointed {len(fixed)} program(s) at the runtime's loader ({fixed[0]}"
                         + (", ..." if len(fixed) > 1 else "") + "): they named a loader outside the package")


def _fix_absolute_symbols(a: Analysis, app: Path, res) -> None:
    """Give functions a library exports as absolute their section back (see elf.fix_absolute_symbols)."""
    from .elf import ET_DYN, fix_absolute_symbols
    fixed = []
    for rel, info in sorted(a.elfs.items()):
        p = app / map_bundle(rel)
        if info.elf_type != ET_DYN or not p.is_file() or p.is_symlink():
            continue
        mode = p.stat().st_mode
        try:
            p.chmod(mode | 0o200)
            n = fix_absolute_symbols(p)
        except (OSError, struct.error):
            n = 0
        finally:
            p.chmod(mode)
        if n:
            fixed.append(f"{rel} ({n})")
    if fixed:
        res.notes.append("gave exported functions marked absolute their section back, which glibc 2.28 and "
                         f"later no longer relocate: {', '.join(fixed[:4])}" + (", ..." if len(fixed) > 4 else ""))


def relocate_strings(path: Path, old: re.Pattern, new: bytes) -> int:
    """Replace a path prefix in the C strings of a binary, in place; return how many were changed.

    Each string keeps its length: the new prefix must be no longer than what it
    replaces, and the rest of the string moves up, followed by NULs.
    """
    data = bytearray(path.read_bytes())
    count = 0
    for m in reversed(list(old.finditer(data))):
        if len(new) > m.end() - m.start() or (m.start() and data[m.start() - 1] != 0):
            continue
        end = data.find(b"\0", m.end())
        if end < 0:
            continue
        rest = bytes(data[m.end():end])
        data[m.start():end] = (new + rest).ljust(end - m.start(), b"\0")
        count += 1
    if count:
        mode = path.stat().st_mode
        path.chmod(mode | 0o200)
        path.write_bytes(bytes(data))
        path.chmod(mode)
    return count


def _write_exec(path: Path, text: str) -> None:
    """Write text to path and make it executable."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755)


def stage(a: Analysis, out: Path, app_id: str, runtime_ref: str, mode: str,
          permissions: list[Permission], bundled: dict[str, str], bundled_libdir: Path | None,
          url: str | None = None) -> StageResult:
    """Write the /app tree and the flatpak-builder manifest into out.

    Args:
        a: The analysis of the package.
        out: The output folder; out/app is replaced.
        app_id: The Flatpak app ID.
        runtime_ref: The runtime to build against.
        mode: "bundle" copies the package into the Flatpak; "extra-data" has the
            user's machine download it at install time, from url.
        permissions: finish-args, from permissions.infer.
        bundled: Soname -> origin of the libraries fill_gaps added.
        bundled_libdir: Where fill_gaps put those libraries.
        url: The vendor's download URL (extra-data mode only).

    Raises:
        ValueError: extra-data mode without a url.
    """
    res = StageResult(manifest_path=out / f"{app_id}.json")
    app = out / "app"
    if app.exists():
        shutil.rmtree(app)
    app.mkdir(parents=True)
    root = a.root

    # payload
    if mode == "bundle":
        _copy_payload(root, app)
        _fix_interpreters(a, app, res)
        _fix_absolute_symbols(a, app, res)
        _drop_shadowing_libraries(a, app, res)
        text_files = sorted({h.file for h in a.hardcoded if h.is_text})
        for f in text_files:
            p = app / map_bundle(f)
            if p.is_file() and not p.is_symlink():
                data = p.read_bytes()
                for old, new in _rewrite_prefixes(a, "bundle"):
                    # a path that follows a variable or a command (${HERE}/opt/xpipe) is relative to it
                    data = re.sub(rb"(?<![A-Za-z0-9._/})-])" + re.escape(old.encode()) + rb"(?![A-Za-z0-9._-])",
                                  new.encode(), data)
                p.write_bytes(data)
        binary_hits = sorted({h.file for h in a.hardcoded if not h.is_text})
        if binary_hits:
            res.notes.append("binaries contain hardcoded install paths that cannot be rewritten: "
                             + ", ".join(binary_hits[:5]) + ("..." if len(binary_hits) > 5 else ""))
    else:
        (app / "extra").mkdir()  # placeholder so the dir exists at build time

    # gap-filling libraries
    env = dict(a.java["env"]) if a.java else {}
    if bundled and bundled_libdir:
        dest = app / BUNDLED_LIBDIR
        dest.mkdir(parents=True, exist_ok=True)
        for so in bundled:
            shutil.copy2(bundled_libdir / so, dest / so)
        # WebKitGTK's helper programs, which it would look for where its distribution put them
        for so, helpers in sorted(HELPER_DIRS.items()):
            if (bundled_libdir / helpers).is_dir():
                shutil.copytree(bundled_libdir / helpers, dest / helpers, symlinks=True, dirs_exist_ok=True)
                env["WEBKIT_EXEC_PATH"] = f"/app/{BUNDLED_LIBDIR}/{helpers}"
                env["WEBKIT_INJECTED_BUNDLE_PATH"] = f"/app/{BUNDLED_LIBDIR}/{helpers}/injected-bundle"
                # a release build of WebKitGTK ignores WEBKIT_EXEC_PATH and starts its helpers from the
                # folder compiled in (Harana: "Failed to spawn child process /usr/lib/x86_64-linux-gnu/
                # webkit2gtk-4.0/WebKitNetworkProcess"), so that path in the library points here instead
                if (dest / so).is_file():
                    n = relocate_strings(dest / so, re.compile(rb"/usr/lib/(?:[\w-]+-linux-gnu/)?" +
                                                               re.escape(helpers.encode())),
                                         f"/app/{BUNDLED_LIBDIR}/{helpers}".encode())
                    if n:
                        res.notes.append(f"pointed {so} at its helper programs in /app/{BUNDLED_LIBDIR}/{helpers}")

    # launcher
    lib_dirs = library_path_dirs(a, mode, bool(bundled))
    _write_exec(app / "bin" / WRAPPER, wrapper_script(a, mode, lib_dirs, env))
    if bundled:
        # Flatpak adds the folders /app/etc/ld.so.conf names to the app's linker cache, so the
        # libraries debpak added are found even by a program started with its own
        # LD_LIBRARY_PATH: ZoomLauncher starts zoom with LD_LIBRARY_PATH=/app/opt/zoom
        conf = app / "etc/ld.so.conf"
        conf.parent.mkdir(parents=True, exist_ok=True)
        conf.write_text(f"/app/{BUNDLED_LIBDIR}\n")

    # desktop integration
    share = app / "share"
    name = app_display_name(root, a.desktop_file, a.pkg.name)
    has_desktop = False
    if a.desktop_file:
        text = (root / a.desktop_file).read_text("utf-8", "replace")
        icon = desktop_entry_value(text, "Icon")
        dest = share / "applications" / f"{app_id}.desktop"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(rewrite_desktop(text, app_id, WRAPPER))
        has_desktop = True
        icons, warns = install_icons(root, icon, share, app_id)
        res.notes += warns
        if not icons:
            d = share / "icons/hicolor/128x128/apps"
            d.mkdir(parents=True, exist_ok=True)
            (d / f"{app_id}.png").write_bytes(placeholder_icon(app_id))
            res.notes.append("made a plain placeholder icon, since AppStream won't accept an app without one")
    else:
        res.notes.append("package ships no .desktop file; the app will only be runnable via `flatpak run`")
    install_mime(root, share, app_id)
    md = share / "metainfo" / f"{app_id}.metainfo.xml"
    md.parent.mkdir(parents=True, exist_ok=True)
    md.write_text(metainfo(a.pkg, app_id, name, has_desktop))

    # manifest
    rid, _arch, branch = parse_ref(runtime_ref, a.arch)
    sources: list[dict] = [{"type": "dir", "path": "app"}]
    build_commands = [
        "cp -a . ${FLATPAK_DEST}/",
        f"chmod +x ${{FLATPAK_DEST}}/bin/{WRAPPER}",
    ]
    if a.java:
        build_commands += a.java["commands"]
        res.notes.append(f"Java app without a Java of its own: the build adds a JDK from {a.java['extension']}")
    if mode == "extra-data":
        if not url:
            raise ValueError("extra-data mode needs --url pointing at the vendor's download")
        extra_name = extra_filename(a.pkg)
        data = a.pkg.path.read_bytes()
        sources.append({"type": "extra-data", "filename": extra_name, "url": net.quote_url(url),
                        "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
        _write_exec(app / "bin" / "apply_extra", apply_extra_script(a, extra_name))
        build_commands.append("chmod +x ${FLATPAK_DEST}/bin/apply_extra")
        if getattr(a.pkg, "format", "") == "run":
            from .unpack import install_helper
            r = a.pkg.extra["replay"]
            install_helper(app, {"source": extra_name, "steps": r["steps"], "take": r["take"],
                                 "target": f"opt/{a.pkg.extra['opt_name']}", "drop": r["drop"]})
        shutil.rmtree(app / "extra")

    manifest: dict = {
        "id": app_id,
        "runtime": rid,
        "runtime-version": branch,
        "sdk": sdk_for(rid),
        # the files are the vendor's own builds: no stripping, no debuginfo split
        "build-options": {"no-debuginfo": True},
    }
    if a.kind in CHROMIUM_KINDS:
        manifest["base"] = ELECTRON_BASE
        manifest["base-version"] = branch
        if rid != "org.freedesktop.Platform":
            res.notes.append(f"{ELECTRON_BASE} expects org.freedesktop.Platform; runtime is {rid}")
    if a.java:
        manifest["sdk-extensions"] = [a.java["extension"]]
    manifest.update({
        "command": WRAPPER,
        "separate-locales": False,
        "finish-args": [p.arg for p in permissions],
        "modules": [{
            "name": a.pkg.name,
            "buildsystem": "simple",
            "build-commands": build_commands,
            "sources": sources,
        }],
        "x-debpak": {
            "generator": f"debpak {__version__}",
            "source-deb" if getattr(a.pkg, "format", "deb") == "deb" else "source-package": a.pkg.path.name,
            "format": getattr(a.pkg, "format", "deb"),
            "package": f"{a.pkg.name} {a.pkg.version}",
            "mode": mode,
            "kind": a.kind,
            "entry-point": a.main_exec,
            "permission-reasons": {p.arg: p.reason for p in permissions},
            "bundled-libraries": bundled,
        },
    })
    res.manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    return res
