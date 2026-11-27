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

from . import __version__, compat32
from .analyze import CHROMIUM_KINDS, QT_WEBENGINE_BASE, Analysis, _is_electron_helper, _is_script, desktop_entry_value, sandbox_filename
from . import net
from .desktop import app_display_name, install_icons, install_mime, metainfo, placeholder_icon, rewrite_desktop
from .deb import resolve_in_root
from .maintscripts import STRIP_PREFIXES, keeps_chromium_sandbox
from .permissions import Permission
from .resolve import HELPER_DIRS, WEBENGINE_DIR
from .runtime import TRIPLETS, parse_ref, sdk_for

WRAPPER = "debpak-run"
BUNDLED_LIBDIR = "lib/debpak"
ELECTRON_BASE = "org.electronjs.Electron2.BaseApp"
# WebKitGTK 6.0, the GTK 4 one, always starts its web process in a sandbox of its own, which inside a
# Flatpak it asks Flatpak's portal for, with an accessibility bus name made from the app's GApplication
# ID. The portal takes only names under the Flatpak's ID, which a converted app's ID never is: YT-GO, a
# Wails 3 app, printed "Portal call failed: Invalid sandbox a11y own name:
# 'org.wails.yt-go.Sandboxed.WebProcess-...' doesn't match app id", then "Connection: failed to receive
# credentials", and stopped at a SIGTRAP. Without its own sandbox the web process starts inside the
# Flatpak's, as WebKitGTK 4.1's does unless an app asks for one
WEBKITGTK6 = "libwebkitgtk-6.0.so.4"
WEBKIT_NO_SANDBOX = {"WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS": "1"}


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
    extra = getattr(a.pkg, "extra", None) or {}
    snap_opt = f"opt/{extra['opt_name']}" if getattr(a.pkg, "format", "") == "snap" and extra.get("opt_name") else ""
    for rp in sorted(a.abs_rpath_dirs):
        rel = rp.strip("/")
        if (a.root / rel).is_dir():
            needed_pkg_dirs.add(rel)
        elif snap_opt and rel not in standard and (a.root / snap_opt / rel).is_dir():
            # a snap's program names a folder of the base snap, where the snap's own copy of it is found
            # through the library path of snapcraft's desktop-launch: Music Radar's pactl has RUNPATH
            # /usr/lib/<triplet>/pulseaudio, for the snap's libpulsecommon-16.1.so, and outside the snap
            # it couldn't start ("Cannot get the default Sink."); it's the snap's folder of that name
            needed_pkg_dirs.add(f"{snap_opt}/{rel}")
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


# where links to the package's libraries that its Python code looks up by name (see ctypes_libraries) go,
# under /app; /app/etc/ld.so.conf names the folder
CTYPES_LIBDIR = "lib/debpak-ctypes"
CTYPES_FIND = re.compile(rb"find_library\(\s*['\"]([A-Za-z0-9][\w.+-]*)['\"]\s*\)")


def ctypes_libraries(a: Analysis, limit: int = 20000) -> dict[str, str]:
    """Return {soname: its file in the package} for the package's own libraries that its Python code looks
    up with ctypes.util.find_library and the runtime hasn't.

    Wolvix Player's snap carries libmpv.so.2 in usr/lib/<triplet>, and python-mpv finds it with
    ctypes.util.find_library("mpv"), which on Linux asks the linker's cache (ldconfig -p) and
    nothing else, as there's no compiler or ld in the runtime: the snap's folders, on the library
    path, aren't in the cache, and the app stopped at "Cannot find libmpv in the usual places".
    """
    names: set[str] = set()
    seen = 0
    for d, dirs, files in os.walk(a.root):
        dirs.sort()
        for f in sorted(files):
            if not f.endswith(".py") or seen >= limit:
                continue
            seen += 1
            p = Path(d) / f
            try:
                if p.is_symlink() or p.stat().st_size > (1 << 20):
                    continue
                data = p.read_bytes()
            except OSError:
                continue
            if b"find_library" in data:
                names |= {m.decode() for m in CTYPES_FIND.findall(data)}
    out = {}
    for name in sorted(names):
        for so, rel in sorted(a.package_sonames.items()):
            if not re.fullmatch(re.escape(f"lib{name}") + r"\.so(\.\d+)*", so) or rel not in a.elfs:
                continue
            if a.runtime and a.runtime.provides(so):
                continue
            out[so] = rel
    return out


def link_ctypes_libraries(a: Analysis, app: Path) -> list[str]:
    """Link the libraries of ctypes_libraries from app/CTYPES_LIBDIR, for the linker's cache; return their sonames.

    Only links to those libraries go in the cache, not their folders, whose other libraries would
    then come before the runtime's for every program in the sandbox.
    """
    d = app / CTYPES_LIBDIR
    out = []
    for so, rel in ctypes_libraries(a).items():
        target = app / map_bundle(rel)
        if not (target.is_file() or target.is_symlink()):
            continue
        d.mkdir(parents=True, exist_ok=True)
        if not os.path.lexists(d / so):
            os.symlink(os.path.relpath(target, d), d / so)
        out.append(so)
    return out


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
    """True for an Electron too old for zypak, or with --no-chromium-sandbox: it starts with --no-sandbox instead.

    Only an Electron (or Chromium browser) program takes Chromium's --no-sandbox.
    A CEF app's program is the vendor's own: Amazon WorkSpaces quit with "Unknown
    option --no-sandbox". It keeps zypak, with its helpers unsandboxed (see wrapper_script).
    """
    if a.kind != "electron":
        return False
    if a.no_chromium_sandbox:
        return True
    if not a.main_exec or a.main_exec not in a.elfs:
        return False
    major = electron_major(a.root / a.main_exec)
    return major is not None and major < ZYPAK_MIN_ELECTRON


# the first Electron that turns its sandbox off when ELECTRON_DISABLE_SANDBOX is set, as --no-sandbox does
ELECTRON_DISABLE_SANDBOX_MIN = 5


def sandbox_off_by_env(a: Analysis) -> bool:
    """True when an Electron that runs without Chromium's sandbox is told so by ELECTRON_DISABLE_SANDBOX.

    --no-sandbox on the command line reaches the app's own scripts in process.argv, and
    an app that parses its options with commander refuses it: Fether (Electron 7) ended
    at "error: unknown option `--no-sandbox'". Electron 5 and later read the variable
    and add the switch to Chromium's command line only, which the app never sees. An
    older Electron, a program whose version can't be read, and a Chromium browser
    (which knows no such variable) still get --no-sandbox.
    """
    if a.kind != "electron" or not a.main_exec or is_chromium_browser(a):
        return False
    major = electron_major(a.root / a.main_exec)
    return major is not None and major >= ELECTRON_DISABLE_SANDBOX_MIN


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


def python_path_dirs(a: Analysis, mode: str) -> list[str]:
    """Return the package's Python module folders, for PYTHONPATH, when its entry point is a Python script.

    A distribution's Python finds a package's modules in /usr/lib/python3/dist-packages;
    in the Flatpak they are in /app/lib/python3/dist-packages, where the runtime's Python
    doesn't look, and Ulauncher stopped at "No module named 'ulauncher'".
    """
    from .pydeps import APP_SITE
    if not python_entry(a):
        return []
    dirs = [d for pat in ("usr/lib/python3*/*-packages", "usr/local/lib/python3*/*-packages",
                          "usr/lib64/python3*/*-packages")
            for d in sorted(a.root.glob(pat)) if d.is_dir() and not d.is_symlink()]
    dirs += [d for d in venv_site_dirs(a) if d not in dirs]
    return [install_path(d.relative_to(a.root).as_posix(), mode) for d in dirs] + (
        [f"/app/{APP_SITE}"] if a.python_site else [])


def venv_site_dirs(a: Analysis) -> list[Path]:
    """Return the site-packages folders of the virtualenv the Python entry point is in, or [].

    OpenNumismat's .deb is a dh-virtualenv: /opt/venvs/open-numismat holds pyvenv.cfg, its modules in
    lib/python3.10/site-packages, and bin/open-numismat, a console script whose #! line names the
    venv's python3, a link to /usr/bin/python3.10. The launcher runs the script with the Python debpak
    adds, which knows nothing of the venv, and the script stopped at "PackageNotFoundError: No package
    metadata was found for OpenNumismat". The venv's site-packages go on PYTHONPATH, which also puts
    its .egg-info and .dist-info where importlib.metadata looks.
    """
    if not a.main_exec:
        return []
    venv = (a.root / a.main_exec).parent.parent
    try:
        if venv == a.root or not (venv / "pyvenv.cfg").is_file():
            return []
    except OSError:
        return []
    return [d for pat in ("lib/python3*/site-packages", "lib64/python3*/site-packages")
            for d in sorted(venv.glob(pat)) if d.is_dir() and not d.is_symlink()]


def python_entry(a: Analysis) -> str:
    """Return "script" when the entry point is a Python script, "launcher" when it is a script that runs
    the package's Python program (a.python_app), or "".

    Dialect's snap starts with debpak's launcher for it, a shell script, which runs
    usr/bin/dialect, a Python script that begins #!/usr/bin/env python3. Its compiled
    modules are built for Python 3.10, which debpak added, and the Flatpak's launcher
    ran the shell script with that Python: "SyntaxError: invalid syntax" at its
    first line. Python goes in front of a Python script only.
    """
    from .pydeps import is_python_script
    if not a.main_exec or not a.main_exec_is_script:
        return ""
    if is_python_script(a.root / a.main_exec):
        return "script"
    return "launcher" if a.python_app or a.python_launcher else ""


def point_python_app_at(a: Analysis, app: Path, mode: str) -> str:
    """Make the package's Python program (a.python_app), which a launcher script runs, start with the Python
    debpak added for its compiled modules, when its #! line names the system's Python.

    A #!/usr/bin/env python3 line finds that Python on PATH (see wrapper_script);
    #!/usr/bin/python3 would be the runtime's, which can't load them.

    Returns:
        The program changed, as the sandbox sees it, or "".
    """
    from .pydeps import interpreter_command
    if not (a.python_version and a.python_home and a.python_app and python_entry(a) == "launcher"):
        return ""
    if mode == "extra-data":
        return ""
    p = app / map_bundle(a.python_app)
    try:
        if p.is_symlink() or not p.is_file():
            return ""
        data = p.read_bytes()
    except OSError:
        return ""
    first, nl, rest = data.partition(b"\n")
    m = re.fullmatch(rb"#!\s*/usr/bin/python3(?:\.\d+)?(\s.*)?", first.rstrip(b"\r"))
    if not m:
        return ""
    mode_bits = p.stat().st_mode
    p.chmod(mode_bits | 0o200)
    p.write_bytes(b"#!" + interpreter_command(a.python_version).encode() + (m.group(1) or b"") + nl + rest)
    p.chmod(mode_bits)
    return install_path(a.python_app, mode)


def restarts_itself(a: Analysis) -> bool:
    """Return True for LibreOffice, whose soffice.bin exits with 81 to be started again (see wrapper_script)."""
    return any(r.endswith("/program/soffice.bin") for r in a.elfs)


def appimage_identity(a: Analysis) -> list[str]:
    """Return the launcher lines that give an AppImage's AppRun script the APPIMAGE and ARGV0 the
    AppImage runtime would, when the script reads them.

    fre:ac's AppRun picks the program to run by the name it was started as:
    basename "$ARGV0" when APPIMAGE is set, else basename "$0", and runs
    $HERE/<that name> when there is one. Started as AppRun, with no APPIMAGE,
    it found AppRun itself and ran it again, for ever, and the check saw it
    running with no window. The AppImage runtime always sets both; APPIMAGE is
    the launcher here, which starts the app as the AppImage file did, and
    ARGV0 the AppImage's own file name. Only a shell script AppRun that reads
    ARGV0, which it does only to choose a program by name, gets them: one that
    reads APPIMAGE alone does things meant for the image file, as Eternal
    Lands' writes a thumbnail for it and runs xdg-icon-resource, which the
    runtime lacks, under set -e. Never a Chromium or Electron app's either,
    whose updater takes APPIMAGE for a file it can replace.
    """
    if not a.main_exec or not a.main_exec_is_script or Path(a.main_exec).name != "AppRun" \
            or a.kind in CHROMIUM_KINDS:
        return []
    try:
        text = (a.root / a.main_exec).read_text("utf-8", "replace")
    except OSError:
        return []
    if not re.search(r"\$\{?ARGV0\b", text):
        return []
    name = Path(getattr(a.pkg, "path", "") or "app.AppImage").name
    return ["# the AppImage runtime's APPIMAGE and ARGV0, which AppRun reads (see stage.appimage_identity)",
            f"export APPIMAGE=/app/bin/{WRAPPER}",
            f"export ARGV0={shlex.quote(name)}"]


# the folders a .deb or .rpm keeps its private programs in, under its own name (usr/lib/<name>)
TOOL_DIR = re.compile(r"usr/(?:lib|lib64|libexec)/[^/]+")


def named_tool_dirs(a: Analysis) -> list[str]:
    """Return the package's folders of helper programs that a binary names by their /usr path.

    RKDevelopTool-GUI's rpm keeps the rkdeveloptool it runs in /usr/lib/rkdeveloptool-gui,
    and looks for it there from Python code inside a Nuitka onefile program, where the path is
    compressed and can't be pointed at /app; it then tries PATH, and stopped at "Error:
    rkdeveloptool not found". Such a folder goes at the end of the launcher's PATH, behind the
    runtime's programs: one under usr/lib, lib64 or libexec that a binary names (the paths
    analyze.scan_hardcoded found) and that holds a program other than the app's own.
    """
    out: list[str] = []
    for h in a.hardcoded:
        rel = h.path.strip("/")
        if h.is_text or not TOOL_DIR.fullmatch(rel) or rel in out or not (a.root / rel).is_dir():
            continue
        try:
            programs = [f for f in (a.root / rel).iterdir() if f.is_file() and not f.is_symlink()
                        and os.access(f, os.X_OK) and f"{rel}/{f.name}" != a.main_exec
                        and not f.name.endswith((".so", ".node")) and ".so." not in f.name]
        except OSError:
            continue
        if programs:
            out.append(rel)
    return out


# DynamoIt's jar, which reads the AWS profiles in ~/.aws (analyze.TOOL_SETTINGS), stopped with "profile file
# cannot be null" and an error window where the user has none: the AWS SDK for Java gives no file when
# ~/.aws/credentials isn't there. An app that reads ~/.aws gets an empty profiles file of its own then, by
# the variables the SDKs read for it (AWS_CREDENTIAL_PROFILES_FILE for Java's v1, AWS_SHARED_CREDENTIALS_FILE
# for the others), and shows no profiles, as on a system where the user set none up; once ~/.aws/credentials
# or ~/.aws/config exists, the SDK finds it there as before. DynamoIt lists its profiles from the config
# file, though (the SDK's DEFAULT_CONFIG_LOCATION_PROVIDER), which gives no file either where ~/.aws/config
# isn't there, and stopped the same way with only the profiles file made: it gets an empty config file of
# its own too, by AWS_CONFIG_FILE, which every SDK reads, while ~/.aws/config isn't there
AWS_NO_PROFILES = [
    "# the AWS SDK fails without a profiles file: an empty one of the app's own until ~/.aws has one",
    'aws_dir="${XDG_CONFIG_HOME:-$HOME/.config}/aws"',
    'if [ ! -e "$HOME/.aws/credentials" ] && [ ! -e "$HOME/.aws/config" ] '
    '&& [ -z "${AWS_CREDENTIAL_PROFILES_FILE:-}${AWS_SHARED_CREDENTIALS_FILE:-}" ]; then',
    '    aws_profiles="$aws_dir/credentials"',
    '    mkdir -p "$aws_dir" && touch "$aws_profiles"',
    '    export AWS_CREDENTIAL_PROFILES_FILE="$aws_profiles" AWS_SHARED_CREDENTIALS_FILE="$aws_profiles"',
    "fi",
    'if [ ! -e "$HOME/.aws/config" ] && [ -z "${AWS_CONFIG_FILE:-}" ]; then',
    '    mkdir -p "$aws_dir" && touch "$aws_dir/config"',
    '    export AWS_CONFIG_FILE="$aws_dir/config"',
    "fi"]


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
        folder = dest[:-1] + ("/" + os.path.dirname(rest) if "/" in rest else "") + '"'
    else:
        quoted_target = shlex.quote(target)
        folder = shlex.quote(install_path(a.chdir_to, mode) if a.chdir_to else os.path.dirname(target))
    if a.python_version and a.python_home:
        # the app's compiled modules are built for this Python, not the runtime's (dupeGuru's .deb)
        from .pydeps import interpreter_command
        if python_entry(a) == "script":
            quoted_target = f"{interpreter_command(a.python_version)} {quoted_target}"
        else:
            # a snap's launcher is a shell script that runs the Python program (see python_entry): the
            # program finds this Python as python3 on PATH, or by its #! line (point_python_app_at)
            lines.append(f"# {a.python_app or a.main_exec} runs on Python {a.python_version}, which its compiled modules are "
                         "built for")
            lines.append(f'export PATH="{os.path.dirname(interpreter_command(a.python_version))}:$PATH"')
    if (py := python_path_dirs(a, mode)):
        lines.append(f'export PYTHONPATH="{":".join(py)}${{PYTHONPATH:+:$PYTHONPATH}}"')
    if a.autostart:
        # Coco AI's launch-at-login setting writes its entry into ~/.config/autostart, which every desktop
        # has, and panicked at start on the app's own config folder, which has none
        lines.append('mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/autostart" 2>/dev/null')
    if a.xlib_copies and a.kind not in CHROMIUM_KINDS:
        # one Xlib for every library: the runtime's, before the copy linked into another (analyze.xlib_copies)
        lines.append(f"# {', '.join(a.xlib_copies)[:200]} carries its own Xlib")
        lines.append('export LD_PRELOAD="libX11.so.6${LD_PRELOAD:+:$LD_PRELOAD}"')
    if a.fd_limit:
        # --fd-limit: Flatpak raises the soft limit on open files to the hard one, and a program that
        # select()s on file numbers up to it aborts past FD_SETSIZE (QDriverStation)
        lines.append(f"ulimit -Sn {int(a.fd_limit)} 2>/dev/null")
    if a.script_stubs:
        lines.append(f"# stand-ins for what {a.main_exec} runs that can't work in a Flatpak: "
                     + ", ".join(a.script_stubs))
    if a.host_commands:
        lines.append("# commands it runs on the host (--host-command): " + ", ".join(a.host_commands))
    if a.script_stubs or a.host_commands:
        lines.append(f'export PATH="/app/{STUB_DIR}:$PATH"')
    if (tool_dirs := named_tool_dirs(a)):
        lines.append("# the package's own folders of helper programs, which a binary names by their /usr path")
        lines.append(f'export PATH="$PATH:{":".join(install_path(d, mode) for d in tool_dirs)}"')
    if lib_dirs:
        lines.append(f'export LD_LIBRARY_PATH="{":".join(lib_dirs)}${{LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}}"')
    if a.signal_onstack:
        why = " ".join(a.signal_onstack.split())
        lines.append(f"# signal handlers run on Go's signal stack: {why} (see stage.ONSTACK_SHIM)")
        lines.append(f'export LD_PRELOAD="/app/{BUNDLED_LIBDIR}/{ONSTACK_SHIM}${{LD_PRELOAD:+:$LD_PRELOAD}}"')
    if a.qt_app_copy:
        lines.append(f"# {a.qt_app_copy} holds its own copy of Qt's application pointer (see stage.QT_SELF_SHIM)")
        lines.append(f'export LD_PRELOAD="/app/{BUNDLED_LIBDIR}/{QT_SELF_SHIM}${{LD_PRELOAD:+:$LD_PRELOAD}}"')
    extra = getattr(a.pkg, "extra", {}) or {}
    if (getattr(a.pkg, "format", "") == "appimage" or extra.get("appdir")) and (opt := extra.get("opt_name")):
        # the AppImage runtime sets APPDIR to the mounted image; compiled AppRuns
        # (appimage-builder's, sharun's) and many AppRun scripts look there for the app
        lines.append(f"export APPDIR={shlex.quote(install_path('opt/' + opt, mode))}")
        lines += appimage_identity(a)
    for k, v in sorted({**a.desktop_exec_env, **(env or {})}.items()):
        lines.append(f"export {k}={shlex.quote(v)}")
    lines += chromium_wrapper_env(a)
    zypak = uses_zypak(a)
    if zypak and a.kind == "cef" and (cef := a.package_sonames.get("libcef.so")):
        lines.append(f"export ZYPAK_CEF_LIBRARY_PATH={shlex.quote(install_path(cef, mode))}")
    if a.downloads_client:
        lines.append("export ZYPAK_DISABLE_SANDBOX=1")
    elif zypak and a.writable:
        # the program runs from its copy in the app's data (--writable), which a sandbox of the helper
        # processes' own can't see, as it sees only /app: MiMo Studio's zygote failed to start ("exec
        # failed ... --type=zygote: No such file or directory") and no window came. They start in the
        # app's own sandbox instead
        lines.append("# Chromium's helper processes start from the writable copy too: --writable")
        lines.append("export ZYPAK_DISABLE_SANDBOX=1")
    elif zypak and a.no_chromium_sandbox:
        # a CEF app with --no-chromium-sandbox: zypak still stands in for Chromium's sandbox, but starts
        # the helper processes without one of their own
        lines.append("# no Chromium sandbox for the helper processes: --no-chromium-sandbox")
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
    if ".aws" in a.tool_settings:
        lines += AWS_NO_PROFILES
    if a.chdir or a.writable:
        # see Analysis.chdir; a file named relative to where it was started is passed on by its full path
        lines += [f"# start in the program's folder: {a.chdir or 'it writes next to itself'}",
                  'n=$#',
                  'for arg in "$@"; do',
                  '    case $arg in /*|-*) ;; *) [ -e "$arg" ] && arg="$PWD/$arg" ;; esac',
                  '    set -- "$@" "$arg"',
                  'done',
                  'shift "$n"',
                  f"cd {folder} || exit 1"]
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
            if sandbox_off_by_env(a):
                lines.append("export ELECTRON_DISABLE_SANDBOX=1")
            else:
                first_run = "--no-sandbox "
        if is_chromium_browser(a):
            lines.append("# a browser's first-run import and default-browser steps can't reach the host")
            first_run += "--no-first-run "
        lines.append(f'{"zypak-wrapper " if zypak else ""}{quoted_target} {first_run}"$@"')
    lines.append(WAIT_FOR_OTHERS)
    return "\n".join(lines) + "\n"


def _sharun_moves(pkg) -> list[str]:
    """Return the commands that put the same real programs in place of sharun's launcher copies as at
    build time (see packages.unwrap_sharun)."""
    lines = []
    for real, stubs in pkg.extra.get("sharun", []):
        src = shlex.quote(f"opt/{pkg.extra['opt_name']}/{real}")
        for s in stubs:
            lines.append("rm -f " + shlex.quote(f"opt/{pkg.extra['opt_name']}/{s}"))
        for s in stubs[:-1]:
            lines.append(f"cp -p {src} " + shlex.quote(f"opt/{pkg.extra['opt_name']}/{s}"))
        lines.append(f"mv {src} " + shlex.quote(f"opt/{pkg.extra['opt_name']}/{stubs[-1]}"))
    return lines


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
    elif fmt == "appimage" and pkg.extra.get("archive_member"):
        raise ValueError("--mode extra-data can't unpack an AppImage that comes inside an archive at install "
                         "time; use the default bundle mode")
    elif fmt == "appimage":
        opt = shlex.quote(f"opt/{pkg.extra['opt_name']}")
        # uruntime ("anylinux") AppImages unpack into AppDir and leave squashfs-root as a symlink to it
        lines += [f"chmod +x {f}", f"./{filename} --appimage-extract >/dev/null",
                  f'mkdir -p opt && rm -rf {opt} && mv "$(readlink -f squashfs-root)" {opt} && rm -f squashfs-root']
        lines += _sharun_moves(pkg)
    else:   # plain archive
        opt = shlex.quote(f"opt/{pkg.extra['opt_name']}")
        strip = int(pkg.extra.get("strip", 0))
        if pkg.extra.get("fs_root"):
            opt = "."                      # a file system root (see packages._root_archive_package)
        lines += [f"mkdir -p {opt}",
                  f"bsdtar -xf {f} -C {opt}" + (f" --strip-components {strip}" if strip else "")]
        if marker := pkg.extra.get("marker"):
            lines.append("touch " + shlex.quote(f"opt/{pkg.extra['opt_name']}/{marker}"))
        lines += _sharun_moves(pkg)       # an AppDir in a tarball (see packages._appdir_entry)
        for m in pkg.extra.get("unmarked", []):
            # the portable-mode markers removed at build time (see packages._portable_markers)
            lines.append("rm -f " + shlex.quote(f"opt/{pkg.extra['opt_name']}/{m}"))
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


# ncurses' wide libraries, which the runtime builds on a terminfo library of their own (libtinfow), and
# its narrow ones, which use libtinfo (see wide_terminfo)
WIDE_CURSES = ("libncursesw.so.6", "libformw.so.6", "libmenuw.so.6", "libpanelw.so.6")
NARROW_CURSES = ("libncurses.so.6", "libform.so.6", "libmenu.so.6", "libpanel.so.6")
TINFO, TINFO_WIDE = "libtinfo.so.6", "libtinfow.so.6"


def wide_terminfo(a: Analysis) -> str:
    """Return the runtime's libtinfow.so.6 when a program built on one libtinfo for both ncurses needs it; or "".

    Debian, Ubuntu and Fedora build one libtinfo.so.6 that their narrow and wide
    ncurses share, and a program built there links libncursesw.so.6 and
    libtinfo.so.6 side by side. The Freedesktop runtime builds two: libncursesw
    loads libtinfow.so.6, and libtinfo.so.6 is the narrow one. LE, a text editor
    whose rpm links both, so got two terminal libraries whose screen data are laid
    out differently, and its calls such as keypad() went to the one ncursesw never
    set up: it ended at "le: Caught signal 11" in a terminal as well as without
    one. A package that needs libtinfo.so.6 and a wide ncurses library, and no
    narrow one, has its libtinfo.so.6 be the runtime's libtinfow.so.6 (a link in
    /app/lib/debpak, on the library path), which the loader then loads once for
    both.
    """
    rt = a.runtime
    if not rt or TINFO not in rt.sonames or TINFO_WIDE not in rt.sonames or TINFO in a.package_sonames:
        return ""
    needed = _all_needed(a)
    if TINFO not in needed or not needed & set(WIDE_CURSES) or needed & set(NARROW_CURSES):
        return ""
    return rt.sonames[TINFO_WIDE]


def _link_wide_terminfo(a: Analysis, app: Path, res) -> bool:
    """Make the package's libtinfo.so.6 the runtime's libtinfow.so.6 (see wide_terminfo); True if it is."""
    if not (wide := wide_terminfo(a)):
        return False
    link = app / BUNDLED_LIBDIR / TINFO
    link.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(link):
        link.unlink()
    os.symlink(wide, link)
    res.notes.append(f"{TINFO} is the runtime's {TINFO_WIDE}, which its libncursesw uses: the package was built "
                     "where both ncurses share one, and two would each keep their own terminal")
    return True


# the file whose presence beside a program turns on its portable mode, in which it keeps the user's
# data in its own folder (Prism Launcher and its forks: portable.txt)
PORTABLE_MARKERS = ("portable.txt", "portable")


# the folders a desktop's sessions are listed in, which a launcher may look in to tell whether there is a
# desktop to run on: a Flatpak's /usr is the runtime's, which has neither
SESSION_FOLDERS = (b"/usr/share/xsessions", b"/usr/share/wayland-sessions")
# where the launcher finds one session instead, in the Flatpak
SESSIONS_STANDIN = "share/debpak/xsessions"


def _sessions_for_launcher(a: Analysis, app: Path, res) -> None:
    """Point a launcher script that looks for the desktop's sessions at a folder that lists one.

    Eternal Lands' AppImage runs AppRun, which starts the game only when
    /usr/share/xsessions has something in it, and otherwise says "Need a
    graphical environment to run." and exits with 0 (for its build's tests,
    which have no desktop); in the Flatpak, where /usr is the runtime's, it
    always did. The script's own copy now names /app/share/debpak/xsessions,
    which holds one session.
    """
    if not a.main_exec or not a.main_exec_is_script:
        return
    p = app / map_bundle(a.main_exec)
    try:
        if not p.is_file() or p.is_symlink() or p.stat().st_size > (1 << 20):
            return
        data = p.read_bytes()
    except OSError:
        return
    if not any(f in data for f in SESSION_FOLDERS):
        return
    for folder in SESSION_FOLDERS:
        data = re.sub(re.escape(folder) + rb"(?![\w.-])", b"/app/" + SESSIONS_STANDIN.encode(), data)
    p.write_bytes(data)
    standin = app / SESSIONS_STANDIN
    standin.mkdir(parents=True, exist_ok=True)
    (standin / "flatpak.desktop").write_text("[Desktop Entry]\nType=XSession\nName=Flatpak\nExec=true\n")
    res.notes.append(f"{a.main_exec} starts the app only when it finds the desktop's sessions in "
                     "/usr/share/xsessions, which is the runtime's in a Flatpak: it looks in "
                     f"/app/{SESSIONS_STANDIN} instead, which lists one")


# a shell variable set to the folder of the script itself, from $0 or BASH_SOURCE (see _package_root_in_script)
_SELF_DIR = re.compile(r"(?m)^[ \t]*(?:export[ \t]+|local[ \t]+|readonly[ \t]+)?([A-Za-z_]\w*)=[^\n]*"
                       r"\bdirname\b[^\n]*(?:\$\{?0\}?|BASH_SOURCE)[^\n]*$")


def _stage_javafx(a: Analysis, app: Path, env: dict[str, str], res) -> None:
    """Put Debian's JavaFX (see javart.fetch_javafx) in /app/share/openjfx/lib, and point the app at it.

    lunaticsmtp's launcher runs java --module-path /usr/share/openjfx/lib --add-modules
    javafx.controls,javafx.fxml,javafx.web, Debian's place for it: a package's script that names
    /usr/share/openjfx names /app/share/openjfx instead. When none does, the app found JavaFX on its
    own system some other way, and Java is given the module path and JavaFX's modules through
    JDK_JAVA_OPTIONS, which every java it starts reads.
    """
    from .javart import APP_JAVAFX, DEBIAN_JAVAFX, JAVAFX_MODULES
    shutil.copytree(a.javafx_dir, app / APP_JAVAFX, symlinks=True, dirs_exist_ok=True)
    new = "/app/" + APP_JAVAFX.rsplit("/", 1)[0]
    pointed = []
    for d, _dirs, files in os.walk(app):
        for n in files:
            p = Path(d) / n
            try:
                if p.is_symlink() or not p.is_file() or p.stat().st_size > (1 << 20):
                    continue
                with open(p, "rb") as f:
                    if f.read(2) != b"#!":
                        continue
                data = p.read_bytes()
            except OSError:
                continue
            if DEBIAN_JAVAFX.encode() in data:
                p.write_bytes(re.sub(re.escape(DEBIAN_JAVAFX.encode()) + rb"(?![\w.-])", new.encode(), data))
                pointed.append(p.relative_to(app).as_posix())
    if pointed:
        res.notes.append(f"{', '.join(pointed[:3])} look{'s' if len(pointed) == 1 else ''} for JavaFX in {new}")
    else:
        env["JDK_JAVA_OPTIONS"] = f"--module-path=/app/{APP_JAVAFX} --add-modules={','.join(JAVAFX_MODULES)}"


def _package_root_in_script(a: Analysis, app: Path, res) -> None:
    """Make a launcher in usr/ that finds the package's root by climbing from its own folder climb one level less.

    iPhotron's .deb starts usr/bin/iPhotron, which sets HERE to its own folder
    and APPDIR="$(dirname "$(dirname "$HERE")")", the root its opt/iPhotron
    sits in, as an AppDir's launcher does. In the Flatpak usr/bin is /app/bin,
    one level nearer the top, so APPDIR was / and it ran "//opt/iPhotron/main.bin":
    No such file. A launcher under usr/ whose climb from its folder (nested
    dirname, or /.. repeated) reaches the package's root now climbs one level
    less, which in the Flatpak is /app, where opt/ is.
    """
    if not a.main_exec or not a.main_exec_is_script or not a.main_exec.startswith("usr/") \
            or a.main_exec.startswith("usr/local/"):
        return
    p = app / map_bundle(a.main_exec)
    try:
        if not p.is_file() or p.is_symlink() or p.stat().st_size > (1 << 20):
            return
        text = p.read_text("utf-8", "replace")
    except OSError:
        return
    levels = len(Path(a.main_exec).parent.parts)      # usr/bin: 2, as many as climb to the root
    selves = [m.group(1) for m in _SELF_DIR.finditer(text) if "dirname" in m.group(0)]
    new = text
    for v in dict.fromkeys(selves):
        ref = rf"\$(?:\{{{v}\}}|{v}\b)"
        # $(dirname "$(dirname "$HERE")") with as many dirname as levels
        nested = r'\$\(dirname\s+"?' * levels + "(" + ref + ")" + r'"?\s*\)' * levels
        new = re.sub(nested, lambda m: '$(dirname "' * (levels - 1) + m.group(1) + '")' * (levels - 1)
                     if levels > 1 else m.group(1), new)
        # "$HERE/../.." with as many /.. as levels
        new = re.sub("(" + ref + r")((?:/\.\.){" + str(levels) + r"})(?![\w.])(?!/\.\.(?![\w.]))",
                     lambda m: m.group(1) + "/.." * (levels - 1), new)
    if new == text:
        return
    p.write_text(new)
    res.notes.append(f"{a.main_exec} finds the package's root {levels} levels above its own folder, which in the "
                     f"Flatpak is /app/{Path(map_bundle(a.main_exec)).parent}: it climbs one level less, to /app")


def _drop_portable_marker(a: Analysis, app: Path, res) -> None:
    """Leave out the file that turns on an archive's portable mode.

    Fjord Launcher's portable tarball holds portable.txt ("This file enables
    the portable mode for the launcher... it will store all data here"), and in
    the Flatpak, where its folder is read-only, it opened only a window saying
    "The launcher data folder is not writable!". Without the file it keeps its
    data in the user's data folder, as the file itself says. Only a marker
    beside the main program or at the top of its folder in /app/opt counts, and
    only one that is empty or speaks of a portable mode.
    """
    if not a.main_exec or not a.main_exec.startswith("opt/"):
        return
    top = Path(*Path(a.main_exec).parts[:2])
    for folder in dict.fromkeys([Path(a.main_exec).parent, top, Path(a.main_exec).parent.parent]):
        if folder != top and top not in folder.parents:
            continue
        for name in PORTABLE_MARKERS:
            p = app / map_bundle(str(folder / name))
            if not p.is_file() or p.is_symlink() or p.stat().st_size > 4096:
                continue
            text = p.read_text("utf-8", "replace")
            if text.strip() and "portable" not in text.lower():
                continue
            p.unlink()
            res.notes.append(f"left out {folder / name}, which turns on the app's portable mode: its own folder "
                             "is read-only in a Flatpak, so it keeps its data in the user's data folder instead")
            return


# the kinds of package electron-builder names in resources/package-type, for electron-updater
UPDATER_PACKAGE_TYPES = {"deb", "rpm", "pacman", "apk"}


def _drop_updater_package_type(app: Path, res) -> None:
    """Leave out the file that tells an Electron app's updater it was installed from a .deb or an rpm.

    Grubie Launcher's .deb shows its main window only once its updater is done: it checked
    GitHub, found a newer release and downloaded the .deb, which it would then install with
    pkexec and dpkg, behind a small splash window with no title, and the check saw no window in
    its 40 seconds. electron-updater picks its deb, rpm or pacman updater by resources/package-type,
    which electron-builder writes into those packages; without it, it takes the app for an
    AppImage, and with no APPIMAGE set it doesn't look for updates at all, which the app reads
    as none. A Flatpak can't install a package, and is updated as a Flatpak instead.
    """
    for d, _dirs, files in os.walk(app):
        if "package-type" not in files or not any(n.endswith(".asar") for n in files) \
                and not os.path.isdir(os.path.join(d, "app")):
            continue
        p = Path(d) / "package-type"
        try:
            if p.is_symlink() or not p.is_file() or p.stat().st_size > 64 \
                    or p.read_text("utf-8", "replace").strip() not in UPDATER_PACKAGE_TYPES:
                continue
            p.unlink()
        except OSError:
            continue
        res.notes.append(f"left out {p.relative_to(app).as_posix()}, by which the app's updater would download "
                         "and install new packages of it, which a Flatpak can't")


# where the runtime's metadata points GI_TYPELIB_PATH, which the launcher's own setting replaces
RUNTIME_TYPELIBS = "/app/lib/girepository-1.0"


def own_typelib_dirs(a: Analysis, mode: str) -> list[str]:
    """Return the package's own folders of GObject introspection typelibs that GI wouldn't search,
    as they are in the sandbox.

    word-sys PDF Editor's tarball is an AppDir holding its own Python, GTK 4,
    libadwaita and their typelibs in usr/lib/girepository-1.0, and a launcher
    script that sets the library path but not GI_TYPELIB_PATH. On its own
    distribution those typelibs are also installed system-wide; in the Flatpak
    only the runtime's were searched, and the Freedesktop runtime has no GTK 4,
    so it stopped at "Namespace Gtk not available for version 4.0". A folder
    named girepository-1.0 that holds .typelib files now goes on GI_TYPELIB_PATH,
    ahead of the runtime's, as Flatpak puts /app/lib/girepository-1.0 ahead of
    them: the package's typelibs describe the libraries it carries. A snap's
    launcher sets GI_TYPELIB_PATH itself (see snap.py).
    """
    if getattr(a.pkg, "format", "") == "snap":
        return []
    out = []
    for top, dirs, files in os.walk(a.root):
        dirs[:] = sorted(d for d in dirs if not (Path(top) / d).is_symlink())
        here = Path(top)
        if here.name != "girepository-1.0" or not any(f.endswith(".typelib") for f in files):
            continue
        rel = here.relative_to(a.root).as_posix()
        if _stripped(rel):
            continue
        where = install_path(rel, mode)
        if where != RUNTIME_TYPELIBS:
            out.append(where)
    return out


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
    replaced, replaced32 = [], []
    for rel, names in sorted(a.runtime_replaces.items()):
        p = app / map_bundle(rel)
        for f in [p] + [p.parent / n for n in names if n != p.name]:
            if f.is_symlink() or f.is_file():
                f.unlink()
        (replaced32 if rel in a.compat32_elfs else replaced).append(Path(rel).name)
    if replaced32:
        res.notes.append(f"left out {len(replaced32)} of the package's own 32-bit libraries ("
                         f"{', '.join(replaced32[:4])}{', ...' if len(replaced32) > 4 else ''}): its glibc's, which "
                         "only that glibc's loader can use, or its GL stack, which GL32 brings to match the driver")
    if replaced:
        res.notes.append(f"left out {len(replaced)} of the package's own copies of libraries the runtime has "
                         f"({', '.join(replaced[:4])}{', ...' if len(replaced) > 4 else ''}): the runtime's "
                         "copies are newer and match its other libraries")


def _apprun_env(app: Path, res) -> None:
    """Take the GL driver settings out of an appimage-builder AppImage's AppRun.env.

    appimage-builder's compiled AppRun exports what AppRun.env beside it says.
    PonyPlayer's sets LIBGL_DRIVERS_PATH to the AppImage's own dri folder, whose
    Mesa 21 driver the Flatpak leaves out with the rest of its OpenGL stack
    (analyze.mesa_dependency_copies); a Mesa of the GL extension that still loads
    its drivers by that path would look for them there, and find none or an old
    one. The GL extension's Mesa finds its own drivers, as for a snap
    (snap.GL_DRIVER_VARIABLES).
    """
    from .snap import GL_DRIVER_VARIABLES
    keys = "|".join(re.escape(k) for k in GL_DRIVER_VARIABLES)
    dropped = []
    for env in sorted(app.glob("opt/*/AppRun.env")):
        if env.is_symlink() or not env.is_file() or not (env.parent / "AppRun").exists():
            continue
        text = env.read_text("utf-8", "replace")
        new = re.sub(rf"^(?:export\s+)?({keys})=.*\n?", "", text, flags=re.M)
        if new != text:
            env.write_text(new)
            dropped += re.findall(rf"^(?:export\s+)?({keys})=", text, re.M)
    if dropped:
        res.notes.append(f"took {', '.join(sorted(set(dropped)))} out of AppRun.env: the GL extension's Mesa "
                         "finds its own drivers")


def _unix_line_ends(app: Path, res) -> None:
    """Give a jpackage app's launcher settings Unix line ends.

    YPtun's .deb was built on Windows: its lib/app/YPtun.cfg ends each line with
    CR LF, and the launcher passed the CR on to Java, which stopped at
    "Invalid maximum heap size: -Xmx512m".
    """
    fixed = []
    for cfg in app.glob("**/lib/app/*.cfg"):
        if cfg.is_symlink() or not cfg.is_file():
            continue
        data = cfg.read_bytes()
        if b"\r\n" in data and b"[Application]" in data:
            cfg.write_bytes(data.replace(b"\r\n", b"\n"))
            fixed.append(cfg.name)
    if fixed:
        res.notes.append(f"gave {', '.join(fixed)} Unix line ends: Java's launcher reads a Windows one into its options")


def _fix_interpreters(a: Analysis, app: Path, res) -> None:
    """Point programs whose loader is somewhere the Flatpak has none at the runtime's own.

    A classic snap's programs load through /snap/core22/current/lib64/ld-linux-x86-64.so.2
    (Alacritty's: "cannot execute: required file not found"), a Nix build's through
    /nix/store/...; a loader the package ships itself stays, unless it is left out with the
    rest of the package's glibc (runtime_replaces): Tux Math's snap (core18) carries
    Ubuntu 18.04's glibc and its programs name /snap/tux-math/current/lib/x86_64-linux-gnu/ld-2.27.so,
    which became /app/opt/tux-math//////lib/...; the runtime's glibc took that glibc's place,
    and tuxmath stopped at "cannot execute: required file not found".
    """
    from .elf import STANDARD_INTERP, set_interpreter
    left_out = set()
    for r, names in a.runtime_replaces.items():
        left_out.add("/app/" + map_bundle(r))
        left_out.update("/app/" + map_bundle(str(Path(r).parent / n)) for n in names)
    fixed = []
    for rel, info in a.elfs.items():
        interp = info.interp
        std = STANDARD_INTERP.get(info.machine)
        if not interp or not std or interp == std:
            continue
        if not interp.startswith(("/snap/", "/nix/", "/gnu/store/")) \
                and os.path.normpath(interp) not in left_out:
            continue
        if os.path.normpath(interp) not in left_out and resolve_in_root(a.root, interp.lstrip("/")) is not None:
            continue
        p = app / map_bundle(rel)
        if p.is_file() and not p.is_symlink() and set_interpreter(p, std):
            fixed.append(rel)
    if fixed:
        res.notes.append(f"pointed {len(fixed)} program(s) at the runtime's loader ({fixed[0]}"
                         + (", ..." if len(fixed) > 1 else "") + "): they named a loader outside the package")


def _fix_nodeflib(a: Analysis, app: Path, res) -> None:
    """Let programs and libraries linked not to search the default folders search them again.

    In a Flatpak the default folders are the runtime's, where glibc and every
    library the package doesn't carry are: a classic snap's MiniZinc IDE,
    linked with -z nodefaultlib to load only from /snap/core24, couldn't find
    the runtime's libpthread.so.0 (see elf.clear_nodeflib).
    """
    from .elf import clear_nodeflib
    fixed = []
    for rel, info in sorted(a.elfs.items()):
        p = app / map_bundle(rel)
        if info.nodeflib and p.is_file() and not p.is_symlink() and clear_nodeflib(p):
            fixed.append(rel)
    if fixed:
        res.notes.append(f"let {len(fixed)} program(s) and libraries find the runtime's libraries ({fixed[0]}"
                         + (", ..." if len(fixed) > 1 else "") + "): they were linked to search only their own paths")


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


def _stub_go_functions(a: Analysis, app: Path, res) -> None:
    """Make the Go functions --go-stub names return at once, in each program that has them (see
    elf.stub_go_functions)."""
    from .elf import stub_go_functions
    if not a.go_stubs:
        return
    done: dict[str, list[str]] = {}
    for rel, info in sorted(a.elfs.items()):
        p = app / map_bundle(rel)
        if not info.is_executable or not p.is_file() or p.is_symlink():
            continue
        mode = p.stat().st_mode
        try:
            p.chmod(mode | 0o200)
            for name in stub_go_functions(p, set(a.go_stubs)):
                done.setdefault(name, []).append(rel)
        except (OSError, struct.error):
            pass
        finally:
            p.chmod(mode)
    for name in a.go_stubs:
        if name in done:
            res.notes.append(f"made {name.rsplit('/', 1)[-1]} return as soon as it's called, in "
                             f"{', '.join(done[name][:3])}" + (", ..." if len(done[name]) > 3 else ""))
        else:
            res.notes.append(f"found no Go program with the function {name} to change")


def _hide_harfbuzz(a: Analysis, app: Path, res) -> None:
    """Keep the HarfBuzz a program or library has linked in to itself (see elf.hide_harfbuzz)."""
    from .elf import hide_harfbuzz
    done = []
    for rel in a.harfbuzz_copies:
        p = app / map_bundle(rel)
        if not p.is_file() or p.is_symlink():
            continue
        mode = p.stat().st_mode
        try:
            p.chmod(mode | 0o200)
            if hide_harfbuzz(p):
                done.append(rel)
        except (OSError, struct.error):
            pass
        finally:
            p.chmod(mode)
    if done:
        res.notes.append(f"{', '.join(done[:3])}" + (", ..." if len(done) > 3 else "") + " carr"
                         + ("ies" if len(done) == 1 else "y") + " its own HarfBuzz, now kept to itself: the "
                         "runtime's, which Pango loads, would have bound its calls to that copy")


def _lower_libm_versions(a: Analysis, app: Path, res) -> None:
    """Bind calls to libm functions at versions the runtime lacks to their older versions (see analyze.lower_libm_needs)."""
    from .elf import lower_libm_versions
    done = []
    for rel, versions in sorted(a.libm_lowered.items()):
        p = app / map_bundle(rel)
        if not p.is_file() or p.is_symlink():
            continue
        mode = p.stat().st_mode
        try:
            p.chmod(mode | 0o200)
            if lower_libm_versions(p, versions):
                done.append(rel)
        except OSError:
            pass
        finally:
            p.chmod(mode)
    if done:
        versions = sorted(set().union(*(a.libm_lowered[r] for r in done)))
        res.notes.append(f"{len(done)} file(s) ({done[0]}" + (", ..." if len(done) > 1 else "") + ") needed libm at "
                         f"{', '.join(versions)} only for functions that version made faster, not different; "
                         "they use the runtime's older versions of them")


def _relocate_usr_paths(a: Analysis, app: Path) -> dict[str, bool]:
    """Point a binary's paths to the package's own folders in /usr at /app.

    Ned's .deb puts its program in /usr/lib/Ned and its settings and icons in
    /usr/share/Ned, a path compiled into the program, and in the Flatpak, where
    /usr is the runtime's, it aborted at start on a settings file it couldn't
    find. A binary's strings can't grow, but /usr/share/<name> and
    /usr/lib/<name> are /app/share/<name> and /app/lib/<name> in the Flatpak,
    the same length, so such a path is rewritten where it begins a C string
    (relocate_strings). A path under /opt would get longer, and stays.

    Returns:
        {binary changed: whether all the paths found in it were}.
    """
    by_file: dict[str, set[str]] = {}
    for h in a.hardcoded:
        if not h.is_text:
            by_file.setdefault(h.file, set()).update(_prefix_candidates(h.path, a.pkg.name) or [h.path])
    out = {}
    for rel, prefixes in sorted(by_file.items()):
        p = app / map_bundle(rel)
        usr = sorted(x for x in prefixes if x.startswith("/usr/") and len(install_path(x[1:], "bundle")) == len(x))
        if not usr or not p.is_file() or p.is_symlink():
            continue
        n = 0
        for prefix in usr:
            n += relocate_strings(p, re.compile(re.escape(prefix.encode()) + rb"(?=[/\0])"),
                                  install_path(prefix[1:], "bundle").encode())
        if n:
            out[rel] = len(usr) == len(prefixes)
    return out


def _link_data_beside_programs(a: Analysis, app: Path) -> list[str]:
    """Give a program kept in lib/<name> its package's share/<name> beside it too.

    Ned's .deb puts its program in /usr/lib/Ned and its settings, fonts and icons in
    /usr/share/Ned, and the program looks for its bundled settings beside itself
    (/usr/lib/Ned/resources), then in ../share/Ned from its own folder; finding
    neither, it aborted at start with an uncaught JSON error. Every entry of
    share/<name> that lib/<name> lacks is now linked into lib/<name>, for a folder
    there that holds a program (an ELF with an interpreter); nothing in the
    package is replaced.

    Returns:
        The lib/<name> folders (under /app) that got links.
    """
    dirs = set()
    for rel, info in a.elfs.items():
        parts = map_bundle(rel).split("/")
        if info.interp and len(parts) == 3 and parts[0] == "lib":
            dirs.add(parts[1])
    done = []
    for name in sorted(dirs):
        lib, share = app / "lib" / name, app / "share" / name
        if not lib.is_dir() or lib.is_symlink() or not share.is_dir():
            continue
        linked = 0
        for entry in sorted(share.iterdir()):
            target = lib / entry.name
            if not target.exists() and not target.is_symlink():
                target.symlink_to(f"../../share/{name}/{entry.name}")
                linked += 1
        if linked:
            done.append(f"lib/{name}")
    return done


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


# A library the launcher preloads into a Go program with a WebKitGTK window (analyze.go_webkit), and
# what the build compiles it from. Go runs every signal handler on a signal stack of its own, set up
# with sigaltstack for each of its threads, and when its handler finds itself on any other stack it
# ends the program: "signal 11 received but handler not on signal stack ... fatal error: non-Go code
# set up signal handler without SA_ONSTACK flag". WebKitGTK's JavaScriptCore installs handlers for
# SIGSEGV (for its JIT and WebAssembly code) and SIGUSR1 (JSC_SIGNAL_FOR_GC, its thread
# suspension) without SA_ONSTACK, and hands a fault that isn't its own to the handler it replaced,
# Go's, on the stack it was running on. A nil pointer that Go would turn into a panic (fmt and
# encoding/json recover from such panics all the time) then kills the program: ProKZee, a Wails
# app, as it opened its window. Wails 2.9 adds SA_ONSTACK to the handlers once, just after it makes
# the web view, and ProKZee died all the same, so JavaScriptCore installs its handler later than
# that. This library wraps sigaction() and adds SA_ONSTACK to every handler installed, whenever
# that is: on a thread that has a signal stack (Go's) the handler runs there, and Go's handler,
# called from it, finds itself where it expects; on any other thread the flag changes nothing.
# JSC_SIGNAL_FOR_GC, which WebKit's warning about signal 10 suggests, only moves the suspension
# signal and leaves the SIGSEGV handler as it was.
ONSTACK_SHIM = "libdebpak-onstack.so"
ONSTACK_SOURCE = r"""#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>

typedef int (*sigaction_fn)(int, const struct sigaction *, struct sigaction *);

int sigaction(int sig, const struct sigaction *act, struct sigaction *old)
{
    static sigaction_fn real;
    if (!real)
        real = (sigaction_fn)dlsym(RTLD_NEXT, "sigaction");
    if (act && !(act->sa_flags & SA_ONSTACK) &&
        ((act->sa_flags & SA_SIGINFO) || (act->sa_handler != SIG_DFL && act->sa_handler != SIG_IGN))) {
        struct sigaction copy = *act;
        copy.sa_flags |= SA_ONSTACK;
        return real(sig, &copy, old);
    }
    return real(sig, act, old);
}
"""


# A library the launcher preloads into a Qt program that holds its own copy of QCoreApplication::self
# (analyze.qt_app_copy), and what the build compiles it from. A program built without -fPIC against
# a Qt whose headers read that pointer inline (qApp) gets a copy of it in its own data, which the
# loader points every other library's reads at. The runtime's libQt6Core writes the application
# object to its own variable and not through that copy, so the copy stays empty: QPrompt's deb, built
# against Debian's Qt 6.8, crashed in the KDE runtime's QApplication constructor, as libQt6Gui read
# the empty copy to announce the first screen (a null sender in QGuiApplication::screenAdded). This
# library wraps the constructors of QCoreApplication, QGuiApplication and QApplication and fills the
# copy with the object being made, before Qt's own code runs (Qt itself does the same, early in
# them), and empties it again in their destructors. Where there is no copy the pointer it finds is
# Qt's own, and writing what Qt writes there changes nothing.
QT_SELF_SHIM = "libdebpak-qtself.so"
QT_SELF_SOURCE = r"""#define _GNU_SOURCE
#include <dlfcn.h>

static void set_self(void *app)
{
    void **self = (void **)dlsym(RTLD_DEFAULT, "_ZN16QCoreApplication4selfE");
    if (self)
        *self = app;
}

#define CTOR(sym) \
void sym(void *obj, int *argc, char **argv, int flags) \
{ \
    static void (*real)(void *, int *, char **, int); \
    if (!real) \
        real = (void (*)(void *, int *, char **, int))dlsym(RTLD_NEXT, #sym); \
    set_self(obj); \
    real(obj, argc, argv, flags); \
}

#define DTOR(sym) \
void sym(void *obj) \
{ \
    static void (*real)(void *); \
    if (!real) \
        real = (void (*)(void *))dlsym(RTLD_NEXT, #sym); \
    real(obj); \
    set_self(0); \
}

CTOR(_ZN16QCoreApplicationC1ERiPPci)
CTOR(_ZN16QCoreApplicationC2ERiPPci)
CTOR(_ZN15QGuiApplicationC1ERiPPci)
CTOR(_ZN15QGuiApplicationC2ERiPPci)
CTOR(_ZN12QApplicationC1ERiPPci)
CTOR(_ZN12QApplicationC2ERiPPci)
DTOR(_ZN16QCoreApplicationD1Ev)
DTOR(_ZN15QGuiApplicationD1Ev)
DTOR(_ZN12QApplicationD1Ev)
"""


def shim_sources(a: Analysis) -> dict[str, str]:
    """Return the libraries the launcher preloads (ONSTACK_SHIM, QT_SELF_SHIM), with their source."""
    out = {}
    if a.signal_onstack:
        out[ONSTACK_SHIM] = ONSTACK_SOURCE
    if a.qt_app_copy:
        out[QT_SELF_SHIM] = QT_SELF_SOURCE
    return out


def _shim_source_name(shim: str) -> str:
    return "debpak-src/" + shim.removeprefix("lib").removesuffix(".so") + ".c"


def onstack_commands(shims=(ONSTACK_SHIM,)) -> list[str]:
    """Return the build steps that compile the shims (ONSTACK_SHIM and the like) into /app/lib/debpak,
    from the sources stage wrote."""
    return [f"mkdir -p ${{FLATPAK_DEST}}/{BUNDLED_LIBDIR}"] + \
        [f"cc -shared -fPIC -O2 -o ${{FLATPAK_DEST}}/{BUNDLED_LIBDIR}/{shim} {_shim_source_name(shim)} -ldl"
         for shim in shims] + ["rm -rf ${FLATPAK_DEST}/debpak-src"]


SCHEMA_DIR = "share/glib-2.0/schemas"


# where a distribution package installs its schemas; under /usr these land in /app/share
STANDARD_SCHEMA_DIRS = ("usr/share/glib-2.0/schemas", "usr/local/share/glib-2.0/schemas")
# a snap or AppImage also carries the schemas of the libraries it bundles (GTK's, the GNOME
# desktop's); copied into /app/share they would hide the runtime's newer ones, so only the app's own
# schemas are taken from such a folder
PLATFORM_SCHEMAS = ("org.gnome.desktop.", "org.gtk.", "org.gnome.system.", "org.freedesktop.", "ca.desrt.",
                    "org.gnome.settings-daemon.", "org.gnome.mutter", "org.gnome.Vino", "org.gnome.evolution-data")


def gsettings_schemas(root: Path) -> list[Path]:
    """Return the GSettings schema files (and vendor overrides) a package ships.

    A distribution compiles them into gschemas.compiled when the package is
    installed (the postinst trigger that runs glib-compile-schemas), and GLib only
    reads the compiled file. GameHub, a Vala app, opens its settings with
    g_settings_new() at start; without the compiled schemas GLib stops it with
    "Settings schema 'com.github.tkashkin.gamehub....' is not installed", a
    g_error and so a SIGTRAP ("Trace/breakpoint trap (core dumped)"). The message
    itself never showed: GameHub's log handler prints to stdout, which is
    buffered when it isn't a terminal and lost when the process dies.

    A snap or AppImage keeps its schemas in its own folder (GNOME Sudoku's snap in
    share/glib-2.0/schemas), which ends up under /app/opt where GLib doesn't look:
    it stopped with "Settings schema 'org.gnome.Sudoku' is not installed". Those
    folders are searched too, for the app's own schemas.
    """
    def wanted(p: Path) -> bool:
        return p.is_file() and p.name.endswith((".gschema.xml", ".gschema.override", ".enums.xml"))

    out: list[Path] = []
    for d in STANDARD_SCHEMA_DIRS:
        if (root / d).is_dir():
            out += sorted(p for p in (root / d).iterdir() if wanted(p))
    seen = {p.name for p in out}
    for d in sorted(root.glob("**/share/glib-2.0/schemas")):
        rel = d.relative_to(root).as_posix()
        if rel in STANDARD_SCHEMA_DIRS or len(d.relative_to(root).parts) > 8 or not d.is_dir() or d.is_symlink():
            continue
        for p in sorted(d.iterdir()):
            if wanted(p) and p.name not in seen and not p.name.startswith(PLATFORM_SCHEMAS):
                out.append(p)
                seen.add(p.name)
    return out


def schema_commands(a: Analysis, app: Path, mode: str) -> list[str]:
    """Return the build step that compiles the package's GSettings schemas into /app/share/glib-2.0/schemas.

    In bundle mode a distribution package's schemas are already there with the
    rest of the package; the schemas of a snap or an AppImage, and in extra-data
    mode every package's (the package itself is unpacked later, under /app/extra,
    where GLib doesn't look), are copied in: they are small files. GLib in a
    Flatpak reads gschemas.compiled from every share folder of XDG_DATA_DIRS,
    /app/share first. glib-compile-schemas leaves out a faulty schema file and
    goes on (it is only strict with --strict); should it fail outright, the
    build goes on without, as it did before.
    """
    files = gsettings_schemas(a.root)
    if not files:
        return []
    dest = app / SCHEMA_DIR
    dest.mkdir(parents=True, exist_ok=True)
    for f in files:
        standard = f.parent.relative_to(a.root).as_posix() in STANDARD_SCHEMA_DIRS
        if (mode != "bundle" or not standard) and not (dest / f.name).exists():
            shutil.copy2(f, dest / f.name)
    return [f"glib-compile-schemas ${{FLATPAK_DEST}}/{SCHEMA_DIR} || "
            "echo 'debpak: the GSettings schemas did not compile' >&2"]


# where the launcher keeps its stand-ins for commands the launcher script runs that can't do their
# job in a Flatpak (analyze.SCRIPT_STUBS); it puts the folder first on PATH
STUB_DIR = "libexec/debpak/bin"
ROOT_STUB = """#!/bin/sh
# Written by debpak: nothing in a Flatpak can become root, so this stands in for {name}. A program of
# the app's own runs as the user; anything else (setting up the host: a udev rule, a group, a service)
# is skipped with status 0, so a script run under set -e goes on (Plover's AppRun runs pkexec to
# install a udev rule at every start)
name=${{0##*/}}
while [ $# -gt 0 ]; do
    case $1 in
        --) shift; break ;;
        -u|-g|-p|-C|-D|-r|-t|-T|-U|-m|--user|--group|--prompt|--message|--description) shift 2 ;;
        -*) shift ;;
        [A-Za-z_]*=*) export "$1"; shift ;;
        *) break ;;
    esac
done
[ $# -gt 0 ] || exit 0
case $(command -v "$1") in
    /app/*) exec "$@" ;;
esac
echo "debpak: skipped $name $1: nothing in a Flatpak can run as root" >&2
exit 0
"""
NOTIFY_STUB = """#!/bin/sh
# Written by debpak: a notification is shown when it can be and never stops the script that asked for
# it (Plover's AppRun runs notify-send under set -e, and exited where no notification service answered)
[ -x /usr/bin/notify-send ] && /usr/bin/notify-send "$@"
exit 0
"""


DESKTOP_DB_STUB = """#!/bin/sh
# Written by debpak: the app registers itself as the handler of its links with this program, which
# the runtime lacks and which has nothing to do in a Flatpak, whose menu entry says what the app
# opens. It succeeds without doing anything (KimaiTray's deep-link plugin ended the app at start
# when it was missing), or runs the runtime's own, should it have one
for d in /usr/bin /bin; do
    [ -x "$d/${0##*/}" ] && exec "$d/${0##*/}" "$@"
done
exit 0
"""


# A command the app runs on the host (--host-command): PrazyCron, a front end to cron, runs crontab -l
# and systemctl, which a Flatpak hasn't got and which would only reach the sandbox's own if it had; its
# start showed "[Errno 2] No such file or directory: 'crontab'". What it edits is the host's crontab
HOST_STUB = """#!/bin/sh
# Written by debpak: {name} runs on the host (--host-command)
exec flatpak-spawn --host {name} "$@"
"""


def stub_files(a: Analysis) -> dict[str, str]:
    """Return the stand-ins for the commands the app runs that can't work in a Flatpak (Analysis.script_stubs),
    and the commands it runs on the host (Analysis.host_commands), by name."""
    from .analyze import DESKTOP_DB_TOOLS, ROOT_HELPERS
    stubs = {n: ROOT_STUB.format(name=n) if n in ROOT_HELPERS else DESKTOP_DB_STUB if n in DESKTOP_DB_TOOLS
             else NOTIFY_STUB for n in a.script_stubs}
    return {**stubs, **{n: HOST_STUB.format(name=n) for n in a.host_commands}}


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
        _unix_line_ends(app, res)
        main = app / map_bundle(a.main_exec or ".")
        if a.main_exec and main.is_file() and not main.is_symlink() and not os.access(main, os.X_OK):
            # a launcher script the package left without its x bit (TrueConf's), run by the wrapper
            main.chmod(main.stat().st_mode | 0o755)
        _fix_interpreters(a, app, res)
        _fix_nodeflib(a, app, res)
        _fix_absolute_symbols(a, app, res)
        _lower_libm_versions(a, app, res)
        _hide_harfbuzz(a, app, res)
        _stub_go_functions(a, app, res)
        _drop_shadowing_libraries(a, app, res)
        _drop_portable_marker(a, app, res)
        _drop_updater_package_type(app, res)
        _sessions_for_launcher(a, app, res)
        _package_root_in_script(a, app, res)
        _apprun_env(app, res)
        text_files = sorted({h.file for h in a.hardcoded if h.is_text})
        for f in text_files:
            p = app / map_bundle(f)
            if p.is_file() and not p.is_symlink():
                data = p.read_bytes()
                for old, new in _rewrite_prefixes(a, "bundle"):
                    # a path that follows a variable or a command (${HERE}/opt/xpipe) is relative to it,
                    # also when the variable is quoted: Banshee's snap launcher lists "$SNAP"/usr/lib/cli/*
                    data = re.sub(rb"(?<![A-Za-z0-9._/})-])(?<![\w})][\"'])" + re.escape(old.encode())
                                  + rb"(?![A-Za-z0-9._-])", new.encode(), data)
                p.write_bytes(data)
        relocated = _relocate_usr_paths(a, app)
        if relocated:
            res.notes.append(f"pointed the /usr paths of the package's own files in {len(relocated)} binar"
                             f"{'y' if len(relocated) == 1 else 'ies'} ({', '.join(list(relocated)[:3])}"
                             f"{', ...' if len(relocated) > 3 else ''}) at /app, where they are in the Flatpak")
        beside = _link_data_beside_programs(a, app)
        if beside:
            res.notes.append(f"linked the package's share/<name> data into {', '.join(beside[:3])}, beside the "
                             "program, where it may look for it")
        binary_hits = sorted({h.file for h in a.hardcoded if not h.is_text and not relocated.get(h.file)})
        if binary_hits:
            res.notes.append("binaries contain hardcoded install paths that cannot be rewritten: "
                             + ", ".join(binary_hits[:5]) + ("..." if len(binary_hits) > 5 else ""))
    else:
        (app / "extra").mkdir()  # placeholder so the dir exists at build time
        if a.libm_lowered:
            res.notes.append("WARNING: " + ", ".join(sorted(a.libm_lowered)[:3]) + " need libm versions the runtime "
                             "lacks, which debpak lowers only in the files it bundles (not with --mode extra-data)")

    # gap-filling libraries
    env = {**(a.java["env"] if a.java else {}), **(a.mono["env"] if a.mono else {}),
           **((getattr(a.pkg, "extra", None) or {}).get("env") or {})}
    if any(Path(rel).name == "QtWebEngineProcess" for rel in a.elfs):
        # the package's own Qt WebEngine (Dream-VoiceTraining's, beside its Python and Qt 6): Chromium's
        # sandbox can't start inside Flatpak's, as with the one debpak bundles below
        env["QTWEBENGINE_DISABLE_SANDBOX"] = "1"
    if any(WEBKITGTK6 in i.needed for i in a.elfs.values()):
        env.update(WEBKIT_NO_SANDBOX)
    if a.webengine_base:
        # Qt WebEngine from the base app (analyze.webengine_from_base), whose helper program isn't where
        # the runtime's Qt would look for it; the base app's own README sets these
        env.update({"QTWEBENGINEPROCESS_PATH": "/app/bin/QtWebEngineProcess",
                    "QTWEBENGINE_DICTIONARIES_PATH": "/app/qtwebengine_dictionaries"})
    if bundled and bundled_libdir:
        dest = app / BUNDLED_LIBDIR
        dest.mkdir(parents=True, exist_ok=True)
        for so in bundled:
            shutil.copy2(bundled_libdir / so, dest / so)
        if (bundled_libdir / WEBENGINE_DIR).is_dir():
            # Qt WebEngine's helper program and data, which it would look for in its Qt's folders (see
            # resolve.QT_WEBENGINE); Chromium's own sandbox can't start inside Flatpak's
            shutil.copytree(bundled_libdir / WEBENGINE_DIR, dest / WEBENGINE_DIR, symlinks=True, dirs_exist_ok=True)
            base = f"/app/{BUNDLED_LIBDIR}/{WEBENGINE_DIR}"
            env.update({"QTWEBENGINEPROCESS_PATH": f"{base}/libexec/QtWebEngineProcess",
                        "QTWEBENGINE_RESOURCES_PATH": f"{base}/resources",
                        "QTWEBENGINE_LOCALES_PATH": f"{base}/locales",
                        "QTWEBENGINE_DISABLE_SANDBOX": "1"})
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

    # a package's own WebKitGTK with its helper programs beside it, as a distribution lays them out:
    # JRosaryBibleApp's snap carries Ubuntu's libwebkit2gtk-4.1 and webkit2gtk-4.1/WebKitNetworkProcess
    # in its usr/lib/<triplet>, and the library started its helper from /usr/lib/<triplet>/webkit2gtk-4.1,
    # which isn't there ("Unable to spawn a new child process", a GLib trap). The library is pointed at
    # a link in /app/lib/debpak, a path short enough to take the compiled-in one's place
    for so, helpers in sorted(HELPER_DIRS.items()):
        rel = a.package_sonames.get(so)
        if not rel or rel not in a.elfs:
            continue
        lib = app / map_bundle(rel)
        own = lib.parent / helpers
        link = app / BUNDLED_LIBDIR / helpers
        if not lib.is_file() or lib.is_symlink() or not own.is_dir() or os.path.lexists(link):
            continue
        link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(os.path.relpath(own, link.parent), link)
        if relocate_strings(lib, re.compile(rb"/usr/lib/(?:[\w-]+-linux-gnu/)?" + re.escape(helpers.encode())),
                            f"/app/{BUNDLED_LIBDIR}/{helpers}".encode()):
            res.notes.append(f"pointed the package's {so} at its helper programs beside it, through "
                             f"/app/{BUNDLED_LIBDIR}/{helpers}")

    tcltk_lib = []
    if a.python_site and a.python_site.is_dir():
        from .pydeps import APP_SITE, TCLTK
        shutil.copytree(a.python_site, app / APP_SITE, symlinks=True, dirs_exist_ok=True)
        # Tkinter's Tcl and Tk (see pydeps.add_tkinter): their libraries, and the scripts they read
        tcltk = app / APP_SITE / TCLTK
        if (tcltk / "lib").is_dir():
            tcltk_lib.append(f"/app/{APP_SITE}/{TCLTK}/lib")
        for var, pat in (("TCL_LIBRARY", "tcl8*"), ("TK_LIBRARY", "tk8*")):
            if (found := sorted(d for d in tcltk.glob(pat) if (d / ("init.tcl" if var == "TCL_LIBRARY"
                                                                     else "tk.tcl")).is_file())):
                env[var] = f"/app/{APP_SITE}/{TCLTK}/{found[-1].name}"
    if a.python_version and a.python_home and a.python_home.is_dir():
        from .pydeps import APP_PYTHON
        shutil.copytree(a.python_home, app / APP_PYTHON.format(v=a.python_version), symlinks=True,
                        dirs_exist_ok=True)
        if (changed := point_python_app_at(a, app, mode)):
            res.notes.append(f"{changed} starts with Python {a.python_version}, which its compiled modules are "
                             "built for")
    typelibs = []
    if a.typelib_dir and a.typelib_dir.is_dir():
        from .pydeps import APP_TYPELIBS
        shutil.copytree(a.typelib_dir, app / APP_TYPELIBS, symlinks=True, dirs_exist_ok=True)
        typelibs.append(f"/app/{APP_TYPELIBS}")
    if (own := own_typelib_dirs(a, mode)):
        typelibs += own
        res.notes.append(f"GObject introspection looks for the package's own typelibs in {', '.join(own[:3])}")
    if typelibs:
        env["GI_TYPELIB_PATH"] = ":".join(dict.fromkeys(typelibs + [RUNTIME_TYPELIBS]))

    if a.javafx_dir and a.javafx_dir.is_dir():
        _stage_javafx(a, app, env, res)

    for shim, source in shim_sources(a).items():
        src_file = app / _shim_source_name(shim)
        src_file.parent.mkdir(parents=True, exist_ok=True)
        src_file.write_text(source)

    # launcher
    for n, text in stub_files(a).items():
        _write_exec(app / STUB_DIR / n, text)
    if a.script_stubs:
        res.notes.append(f"{a.main_exec} runs {', '.join(a.script_stubs)}, which can't do that in a Flatpak: "
                         "its launcher stands in for them")
    wide_tinfo = _link_wide_terminfo(a, app, res)
    lib_dirs = library_path_dirs(a, mode, bool(bundled) or wide_tinfo) + tcltk_lib
    _write_exec(app / "bin" / WRAPPER, wrapper_script(a, mode, lib_dirs, env))
    cache_dirs = []
    if bundled:
        # Flatpak adds the folders /app/etc/ld.so.conf names to the app's linker cache, so the
        # libraries debpak added are found even by a program started with its own
        # LD_LIBRARY_PATH: ZoomLauncher starts zoom with LD_LIBRARY_PATH=/app/opt/zoom
        cache_dirs.append(f"/app/{BUNDLED_LIBDIR}")
    if mode == "bundle" and (linked := link_ctypes_libraries(a, app)):
        cache_dirs.append(f"/app/{CTYPES_LIBDIR}")
        res.notes.append(f"the linker's cache lists {', '.join(linked)}, which the app's Python code looks up "
                         "by name (ctypes.util.find_library)")
    if a.compat32:
        # 32-bit programs (see compat32): the libraries debpak fetched for them, and the folders the
        # linker's cache lists for them
        if a.compat32_bundled and a.compat32_bundled_dir:
            dest = app / compat32.BUNDLED_LIBDIR
            dest.mkdir(parents=True, exist_ok=True)
            for so in a.compat32_bundled:
                shutil.copy2(a.compat32_bundled_dir / so, dest / so)
        lib_dirs32 = [install_path(d, mode) for d in a.compat32_lib_dirs]
        if mode == "bundle" and (app / compat32.COMPAT_DIR).is_dir():
            # the package's own usr/lib/i386-linux-gnu, where the extension is mounted, would be hidden
            (app / compat32.COMPAT_DIR).rename(app / compat32.OWN_DIR)
            lib_dirs32 = [f"/app/{compat32.OWN_DIR}" if d == f"/app/{compat32.COMPAT_DIR}" else d for d in lib_dirs32]
        cache_dirs = compat32.ld_conf_lines(a.compat32_gl, lib_dirs32, bool(a.compat32_bundled)) + cache_dirs
        res.notes.append(f"{', '.join(Path(p).name for p in a.compat32[:3])}{', ...' if len(a.compat32) > 3 else ''} "
                         f"{'is a 32-bit x86 program' if len(a.compat32) == 1 else 'are 32-bit x86 programs'}: the "
                         f"Flatpak adds Flathub's {compat32.COMPAT_EXTENSION}"
                         f"{' and ' + compat32.GL32_EXTENSION if a.compat32_gl else ''}, the 32-bit libraries the "
                         "loader and they need")
    if cache_dirs:
        conf = app / "etc/ld.so.conf"
        conf.parent.mkdir(parents=True, exist_ok=True)
        conf.write_text("".join(f"{c}\n" for c in cache_dirs))

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
    if a.script_stubs or a.host_commands:
        build_commands.append(f"chmod +x ${{FLATPAK_DEST}}/{STUB_DIR}/*")
    build_commands += schema_commands(a, app, mode)
    if (shims := shim_sources(a)):
        build_commands += onstack_commands(list(shims))
    if a.qt_app_copy:
        res.notes.append(f"{a.qt_app_copy} holds its own copy of Qt's application pointer, which the runtime's "
                         f"Qt doesn't fill: its launcher preloads {QT_SELF_SHIM}, which does")
    if a.signal_onstack:
        res.notes.append(f"{a.signal_onstack}: its launcher preloads {ONSTACK_SHIM}, which has signal handlers "
                         "run on Go's signal stack (SA_ONSTACK)")
    if a.java:
        build_commands += a.java["commands"]
        res.notes.append(f"Java app without a Java of its own: the build adds a JDK from {a.java['extension']}")
    if a.mono:
        build_commands += a.mono["commands"]
        if "libgdiplus.so.0" in bundled:
            # Mono's config maps gdiplus to a bare libgdiplus.so, which only LD_LIBRARY_PATH would find,
            # and BizHawk's start script sets its own; the copy debpak added is named by its full path
            build_commands.append(f"sed -i 's|target=\"[^\"]*libgdiplus[^\"]*\"|target=\"/app/{BUNDLED_LIBDIR}/"
                                  "libgdiplus.so.0\"|' /app/etc/mono/config")
        res.notes.append(f".NET app run with mono, which the package lacks: the build adds Mono from "
                         f"{a.mono['extension']}")
    if a.compat32:
        # the folders the extensions are mounted on (as Steam's manifest makes them)
        build_commands.append(f"mkdir -p ${{FLATPAK_DEST}}/{compat32.COMPAT_DIR}"
                              + (f" ${{FLATPAK_DEST}}/{compat32.COMPAT_DIR}/GL" if a.compat32_gl else ""))
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
    elif a.webengine_base:
        manifest["base"] = QT_WEBENGINE_BASE
        manifest["base-version"] = a.webengine_base
        # the base app's headers and build files, which it leaves for the app to remove
        manifest["cleanup-commands"] = ["/app/cleanup-BaseApp.sh"]
    if a.compat32:
        manifest["add-extensions"] = compat32.add_extensions(compat32.freedesktop_branch(runtime_ref), a.compat32_gl)
    extensions = [x["extension"] for x in (a.java, a.mono) if x]
    if extensions:
        manifest["sdk-extensions"] = extensions
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
