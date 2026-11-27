"""Snap input: a .snap file (a squashfs image) or an installed snap's folder
(/snap/NAME/current), turned into an ordinary app under /opt/NAME.

Snap's permission declarations (plugs, slots, interfaces) are ignored: the
Flatpak's permissions come from what the binaries use, as for every
other format. The one exception is an mpris slot, whose bus name the app
gets to own (see mpris_names). What a snap does need to run outside snapd is recreated:

- one launcher script per app in meta/snap.yaml (opt/NAME/.debpak-snap/APP)
  that sets $SNAP and the other SNAP_* variables, the snap's `environment:`,
  and library and program paths inside the snap, then runs the app's
  `command` (snapcraft's extension launchers in `command-chain` are skipped:
  they exist to find GNOME/KDE content snaps, which the Flatpak runtime
  replaces, see snapcontent; debpak's own desktop-launch keeps what of them
  is about the snap's own folders);
- the snap's menu entries (meta/gui/*.desktop) pointed at those launchers;
- the libraries the snap expected from its base snap are missing from the
  package, so `convert` fills them from the matching Ubuntu release
  (core22 -> jammy, ...), unless you name other library sources.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

from .packages import Package, PackageError, _desktop_value, _place_icon, _set_desktop_exec
from . import net
from .runtime import EXTENSION_PROVIDED_PREFIXES
from .snapcontent import content_environment, content_plugs, describe as describe_content, extension_desktop_launch

BASE_TO_UBUNTU = {"core": "xenial", "core18": "bionic", "core20": "focal", "core22": "jammy",
                  "core24": "noble", "core26": "resolute"}
SNAP_ARCH = {"amd64": "x86_64", "arm64": "aarch64", "armhf": "arm", "i386": "i386"}
LAUNCH_DIR = ".debpak-snap"


# --------------------------------------------------------------------------- the YAML snap.yaml uses

def _scalar(v: str):
    """Decode a YAML scalar or flow collection: quoted strings (with escapes), [a, b], {k: v}, else the plain text."""
    v = v.strip()
    if not v:
        return ""
    if v[0] in "'\"" and v[-1:] == v[0] and len(v) >= 2:
        inner = v[1:-1]
        if v[0] == "'":
            return inner.replace("''", "'")
        return re.sub(r'\\(u[0-9a-fA-F]{4}|["\\/nt])',
                      lambda m: chr(int(m.group(1)[1:], 16)) if m.group(1)[0] == "u"
                      else {"n": "\n", "t": "\t"}.get(m.group(1), m.group(1)), inner)
    if v.startswith("[") and v.endswith("]"):
        return [_scalar(x) for x in _split_flow(v[1:-1])]
    if v.startswith("{") and v.endswith("}"):
        out = {}
        for item in _split_flow(v[1:-1]):
            k, _, val = item.partition(":")
            out[_scalar(k)] = _scalar(val)
        return out
    return v


def _split_flow(s: str) -> list[str]:
    """Split the inside of a flow collection at top-level commas, respecting quotes and nesting."""
    parts, depth, cur, quote = [], 0, "", None
    for ch in s:
        if quote:
            cur += ch
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(cur.strip())
            cur = ""
            continue
        cur += ch
    if cur.strip():
        parts.append(cur.strip())
    return parts


def _strip_comment(line: str) -> str:
    """Remove a trailing # comment from a YAML line, unless the # is inside quotes."""
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip()
    return line.rstrip()


def _closed_quote(val: str) -> bool:
    """Return whether a quoted YAML scalar ends where val does."""
    if val.startswith("'"):
        return bool(re.fullmatch(r"'(?:[^']|'')*'", val))
    return bool(re.fullmatch(r'"(?:[^"\\]|\\.)*"', val))


def parse_yaml(text: str):
    """Parse the subset of YAML that snap.yaml uses.

    Handles block mappings and sequences, flow [..] and {..}, quoted strings and
    | / > block scalars. Anchors, tags and multi-document files aren't supported.
    Plain scalars stay strings: snap.yaml has no values that need typing.
    A snap.yaml written as JSON, which is YAML too, is read as JSON: Classroom+'s whole snap.yaml
    is one JSON object spread over many lines, which the block parser can't follow.
    """
    if text.lstrip().startswith("{"):
        try:
            return json.loads(text)
        except ValueError:
            pass
    raw = text.splitlines()
    lines: list[tuple[int, str, int]] = []      # (indent, content, raw index)
    for i, l in enumerate(raw):
        c = _strip_comment(l)
        if c.strip() and not c.strip().startswith("---"):
            lines.append((len(c) - len(c.lstrip(" ")), c.strip(), i))
    pos = 0

    def block_scalar(start_raw: int, parent_indent: int, style: str) -> str:
        """Read a | or > block scalar that starts after line start_raw; return its text."""
        nonlocal pos
        body = []
        j = start_raw + 1
        ind = None
        while j < len(raw):
            line = raw[j]
            if line.strip():
                cur = len(line) - len(line.lstrip(" "))
                if cur <= parent_indent:
                    break
                ind = cur if ind is None else ind
                body.append(line[ind:])
            else:
                body.append("")
            j += 1
        while pos < len(lines) and lines[pos][2] < j:
            pos += 1
        while body and not body[-1]:
            body.pop()
        if style.startswith(">"):
            paras, cur_p = [], []
            for b in body:
                if b:
                    cur_p.append(b.strip())
                else:
                    paras.append(" ".join(cur_p))
                    cur_p = []
            paras.append(" ".join(cur_p))
            return "\n".join(paras) + "\n"
        return "\n".join(body) + "\n"

    def parse(indent: int):
        """Parse the mapping or sequence at indent and return it."""
        nonlocal pos
        if pos >= len(lines):
            return None
        if lines[pos][1].startswith("- ") or lines[pos][1] == "-":
            seq = []
            while pos < len(lines) and lines[pos][0] == indent and (lines[pos][1].startswith("- ")
                                                                    or lines[pos][1] == "-"):
                ind, content, ri = lines[pos]
                item = content[1:].strip()
                if not item:
                    pos += 1
                    seq.append(parse(lines[pos][0]) if pos < len(lines) and lines[pos][0] > indent else None)
                elif re.match(r"^[^'\"\[{][^:]*:(\s|$)", item):
                    # "- key: value" starts a mapping at the item's indentation
                    sub_indent = ind + 2
                    lines[pos] = (sub_indent, item, ri)
                    seq.append(parse(sub_indent))
                else:
                    pos += 1
                    seq.append(_scalar(item))
            return seq
        mapping: dict = {}
        while pos < len(lines) and lines[pos][0] == indent:
            ind, content, ri = lines[pos]
            m = re.match(r"^(?P<k>'[^']*'|\"[^\"]*\"|[^:]+?)\s*:(?:\s+(?P<v>.*))?$", content)
            if not m:
                pos += 1
                continue
            key = _scalar(m.group("k"))
            val = (m.group("v") or "").strip()
            pos += 1
            # a quoted or plain scalar can go on over more indented lines (cool-retro-term's
            # description); read to its end, or the rest of the mapping is lost
            quoted = val[:1] in ("'", '"') and not _closed_quote(val)
            while val and pos < len(lines) and (quoted or (lines[pos][0] > ind and val[0] not in "|>[{")):
                val += " " + lines[pos][1]
                pos += 1
                quoted = quoted and not _closed_quote(val)
            if val and val[0] in "|>":
                mapping[key] = block_scalar(ri, ind, val)
            elif val:
                mapping[key] = _scalar(val)
            elif pos < len(lines) and lines[pos][0] > ind:
                mapping[key] = parse(lines[pos][0])
            elif pos < len(lines) and lines[pos][0] == ind and lines[pos][1].startswith("-"):
                mapping[key] = parse(ind)          # sequence at the key's own indentation
            else:
                mapping[key] = None
        return mapping

    result = parse(lines[0][0]) if lines else {}
    return result if result is not None else {}


# --------------------------------------------------------------------------- extraction

def is_snap_dir(p: Path) -> bool:
    """Return True for an installed snap's folder (it has meta/snap.yaml)."""
    return p.is_dir() and (p / "meta/snap.yaml").is_file()


def _unsquash(path: Path, out: Path) -> None:
    """Unpack a .snap file with unsquashfs.

    Raises:
        PackageError: unsquashfs is missing or failed.
    """
    us = shutil.which("unsquashfs")
    if not us:
        raise PackageError("unpacking a .snap needs `unsquashfs` (package squashfs-tools); for an installed "
                           "snap, give its folder instead: /snap/NAME/current")
    r = subprocess.run([us, "-no-xattrs", "-d", str(out), str(path)], capture_output=True, text=True)
    if r.returncode != 0:
        raise PackageError(f"unsquashfs failed: {r.stderr.strip()[-400:]}")


# snaps whose files another snap runs on, with nothing in Flatpak to stand in for them
# (GNOME, KDE and theme content snaps are covered by the Flatpak runtime instead)
PLATFORM_SNAPS = ("wine-platform",)


def platform_snaps(meta: dict) -> dict[str, str]:
    """Return {plug: provider snap} for the content plugs that pull in a platform snap like wine-platform."""
    plugs = meta.get("plugs") if isinstance(meta.get("plugs"), dict) else {}
    out = {}
    for plug, spec in plugs.items():
        if not isinstance(spec, dict) or spec.get("interface") != "content":
            continue
        provider = str(spec.get("default-provider") or "").split(":")[0]
        if provider.startswith(PLATFORM_SNAPS):
            out[str(plug)] = provider
    return out


# interfaces only a privileged system service plugs: VMs, containers, firewall and
# network setup, kernel modules (the *-support ones belong to Docker, LXD, Multipass ...)
SYSTEM_PLUGS = ("kvm", "firewall-control", "network-control", "network-setup-control", "kernel-module-control",
                "kernel-module-load", "mount-control", "block-devices", "snapd-control")


def _plug_names(spec: dict) -> list[str]:
    plugs = spec.get("plugs") or []
    return [str(p) for p in (plugs if isinstance(plugs, list) else plugs.keys() if isinstance(plugs, dict) else [])]


# system services a snap may carry its own copy of that a Flatpak reaches on the host instead, with the
# finish-arg that lets it in: Cryptnox's snap runs its own pcscd for its card tools
HOST_SERVICES = {"pcscd": "--socket=pcsc"}


def host_services(apps: dict) -> dict[str, str]:
    """Return {daemon app: finish-arg} for the snap's daemons that the host's own service replaces."""
    out = {}
    for a, s in apps.items():
        if isinstance(s, dict) and s.get("daemon"):
            prog = os.path.basename((str(s.get("command") or "").split() or [""])[0])
            if prog in HOST_SERVICES:
                out[str(a)] = HOST_SERVICES[prog]
    return out


def system_services(apps: dict, has_gui: bool, web_ui: bool = False, slots: dict | None = None,
                    classic: bool = False) -> list[str]:
    """Return the system services in snap.yaml that the snap can't do without.

    A system service is a daemon whose daemon-scope isn't user. A snap
    without a menu entry is a service with command-line clients (LXD, Docker),
    so any of them counts; next to a graphical app, one counts when it plugs an
    interface only a privileged service uses (SYSTEM_PLUGS or *-support):
    Multipass's multipassd plugs kvm and multipass-support, and its CLI and GUI
    only drive it. When the graphical app only opens the service's web page
    (web_ui: Plex Media Server's pms-web runs xdg-open http://localhost:32400),
    a daemon that serves on the network (network-bind) counts too. So does one
    that the system bus starts for a name of the snap's own (activates-on a
    dbus slot on the system bus): Factory Reset Tools' window asks its
    dbus-daemon, running as root, to write the reset media. A daemon the
    host has its own of (HOST_SERVICES) doesn't count: Cryptnox's card tools
    talk to the host's pcscd as well as to the snap's. In a classic snap
    (classic), which plugs nothing, any system service counts: it runs as root
    with the whole system open to it, as Ubuntu Desktop Bootstrap's
    subiquity-server does for the installer window that drives it.
    """
    out = []
    on_host = host_services(apps)
    for a, s in apps.items():
        if not isinstance(s, dict) or not s.get("daemon") or str(s.get("daemon-scope") or "system") == "user" \
                or str(a) in on_host:
            continue
        privileged = [p for p in _plug_names(s) if p in SYSTEM_PLUGS or p.endswith("-support")]
        on_system_bus = any(isinstance(sp := (slots or {}).get(slot), dict) and sp.get("interface") == "dbus"
                            and sp.get("bus") == "system" for slot in s.get("activates-on") or [])
        if privileged or on_system_bus or classic or not has_gui or (web_ui and "network-bind" in _plug_names(s)):
            out.append(str(a))
    return out


# interfaces through which an app installs or removes the system's software: App Center plugs
# snapd-control and packagekit-control
SOFTWARE_PLUGS = ("snapd-control", "packagekit-control")
# Python modules of the system's package manager: Ubuntu Budgie Welcome imports apt to install programs
PACKAGE_MANAGER_IMPORT = re.compile(rb"(?m)^\s*(?:import|from)\s+(apt|apt_pkg|aptdaemon)\b")


def manages_software(opt: Path, apps: dict) -> str:
    """Return why the snap's apps install the system's software, or "".

    An app that plugs SOFTWARE_PLUGS, or whose command is a Python program that
    imports apt, is a front end to the system's package manager (snapd, apt,
    PackageKit), which a Flatpak can't reach.
    """
    for a, s in apps.items():
        if not isinstance(s, dict) or s.get("daemon"):
            continue
        if (plug := next((p for p in _plug_names(s) if p in SOFTWARE_PLUGS), None)):
            return f"app {a} plugs {plug}"
        cmd = opt / str(s.get("command") or "").split(" ", 1)[0]
        try:
            head = cmd.read_bytes()[:1 << 20] if cmd.is_file() and cmd.stat().st_size < (1 << 20) else b""
        except OSError:
            continue
        if head.startswith(b"#!") and b"python" in head.split(b"\n", 1)[0] and \
                (m := PACKAGE_MANAGER_IMPORT.search(head)):
            return f"{cmd.relative_to(opt)} imports {m.group(1).decode()}"
    return ""


# toolkit bindings a snap's Python app imports and may leave to a content snap, and the
# distribution package each is (which picks the runtime, see pydeps.TOOLKIT_RUNTIME)
PYTHON_BINDINGS = {"gi": "python3-gi", "PyQt5": "python3-pyqt5", "PyQt6": "python3-pyqt6",
                   "PySide2": "python3-pyside2", "PySide6": "python3-pyside6"}
_BINDING_IMPORT = re.compile(rb"(?m)^\s*(?:import|from)\s+(" + b"|".join(k.encode() for k in PYTHON_BINDINGS)
                             + rb")\b")


def _python_sites(opt: Path) -> list[Path]:
    """Return the snap's site-packages and dist-packages folders."""
    out = []
    for d, dirs, _files in os.walk(opt):
        if os.path.basename(d) in ("site-packages", "dist-packages"):
            out.append(Path(d))
            dirs.clear()
    return out


def python_bindings(opt: Path, apps: dict) -> tuple[str, list[str]]:
    """Return (an app's Python program, relative to opt, the binding packages it needs), or ("", []).

    Mousam's snap is a Python script (usr/bin/mousam) that imports gi, which
    snapcraft's gnome extension brings from the gnome-core26 content snap; the
    snap has only the app's pure-Python modules, and on the Freedesktop
    runtime's Python it stopped at "No module named 'gi'". A binding the snap
    doesn't carry itself is a dependency, as a .deb's Depends would name it,
    and picks the runtime that has it (PyGObject: GNOME).
    """
    for s in apps.values():
        if not isinstance(s, dict) or s.get("daemon"):
            continue
        rel = re.sub(r"^\$\{?SNAP\}?/", "", (str(s.get("command") or "").split() or [""])[0])
        p = opt / rel
        try:
            if not rel or not p.is_file() or p.stat().st_size > (1 << 20):
                continue
            head = p.read_bytes()
        except OSError:
            continue
        if not (head.startswith(b"#!") and b"python" in head.split(b"\n", 1)[0]):
            continue
        wanted = []
        sites = None
        for m in _BINDING_IMPORT.finditer(head):
            mod = m.group(1).decode()
            if PYTHON_BINDINGS[mod] in wanted:
                continue
            if sites is None:
                sites = _python_sites(opt)
            if any((d / mod).is_dir() for d in sites):
                continue
            wanted.append(PYTHON_BINDINGS[mod])
        if wanted:
            return rel, wanted
    return "", []


def gi_packages(opt: Path, meta: dict) -> list[str]:
    """Return the gir1.2-* packages of the typelibs the snap's Python code asks for, when it plugs a GNOME
    content snap and doesn't carry them itself.

    Rundfunk's snap, a tray app in Python, asks for AyatanaAppIndicator3 0.1, whose typelib and library
    its gnome-46-2404 content snap carried; the GNOME runtime that stands in for it has neither, and the
    app stopped at "Namespace AyatanaAppIndicator3 not available". Each namespace becomes the package
    Debian names for it (pydeps.gir_package), and is fetched as a .deb's gir1.2-* dependency is: only
    when the runtime lacks the library the typelib describes, with that library from the snap's base.
    """
    if not any(p["kind"] == "gnome" for p in content_plugs(meta)):
        return []
    from .pydeps import gi_requirements, gir_package
    return [gir_package(ns, version) for ns, version in gi_requirements(opt)]


def opens_local_web_page(opt: Path, apps: dict) -> bool:
    """Return True if an app that isn't a daemon is a small script that opens a page on this computer."""
    for s in apps.values():
        if not isinstance(s, dict) or s.get("daemon"):
            continue
        cmd = opt / str(s.get("command") or "").split(" ", 1)[0]
        try:
            if cmd.is_file() and cmd.stat().st_size < 4096 and \
                    re.search(rb"https?://(localhost|127\.0\.0\.1)\b", cmd.read_bytes()):
                return True
        except OSError:
            continue
    return False


def _expanding(arg: str) -> str:
    """Quote arg for sh so that its $VARIABLES expand and nothing else does."""
    if "$" not in arg:
        return shlex.quote(arg)
    return '"' + re.sub(r'(["\\`])', r"\\\1", arg) + '"'


# what marks snapcraft-desktop-helpers' desktop-launch (the desktop-gtk3, desktop-qt5 ... parts that
# snaps from before snapcraft's extensions copy into bin/): it records the revision it last set up
DESKTOP_HELPER_MARK = b"SNAP_DESKTOP_LAST_REVISION"

# debpak's desktop-launch, in place of the snap's: what of the original's settings still means
# something in a Flatpak, and only for the folders the snap has
DESKTOP_LAUNCH = """#!/bin/sh
# debpak put this in place of the snap's desktop-launch (snapcraft-desktop-helpers, or the one of
# snapcraft's gnome and kde-neon extensions). Outside snapd the original linked GSettings schemas
# and copied mime data under $SNAP_USER_DATA, and pointed fonts, GTK, GDK pixbuf loaders, GL drivers
# and EGL vendors at copies the snap was expected to have from its base or a content snap; the
# Flatpak runtime has its own of all those. What stays is where the snap keeps its own data,
# typelibs, Qt and GStreamer plugins. The snap's data folders come after the runtime's, so the
# runtime's GSettings schemas and themes win over older copies in the snap.
A="$(uname -m)-linux-gnu"
XDG_DATA_DIRS="${XDG_DATA_DIRS:-/app/share:/usr/share}"
for d in "$SNAP/usr/share" "$SNAP/share" "$SNAP/data-dir"; do
  [ -d "$d" ] && XDG_DATA_DIRS="$XDG_DATA_DIRS:$d"
done
export XDG_DATA_DIRS
[ -d "$SNAP/etc/xdg" ] && export XDG_CONFIG_DIRS="${XDG_CONFIG_DIRS:-/etc/xdg}:$SNAP/etc/xdg"
# the runtime's typelibs before the snap's, as the runtime's libraries replace the snap's copies of them
t="${GI_TYPELIB_PATH:+$GI_TYPELIB_PATH:}/usr/lib/$A/girepository-1.0"
for d in "$SNAP/usr/lib/girepository-1.0" "$SNAP/usr/lib/$A/girepository-1.0"; do
  [ -d "$d" ] && t="$t:$d" && export GI_TYPELIB_PATH="$t"
done
d="$SNAP/usr/lib/$A/gstreamer-1.0"
[ -d "$d" ] && export GST_PLUGIN_PATH="$d${GST_PLUGIN_PATH:+:$GST_PLUGIN_PATH}"
for q in qt4 qt5 qt6; do
  d="$SNAP/usr/lib/$A/$q/plugins"
  [ -d "$d" ] && export QT_PLUGIN_PATH="$d${QT_PLUGIN_PATH:+:$QT_PLUGIN_PATH}"
done
d="$SNAP/usr/lib/$A/qt5/qml"
[ -d "$d" ] && export QML2_IMPORT_PATH="$d${QML2_IMPORT_PATH:+:$QML2_IMPORT_PATH}"
d="$SNAP/usr/lib/$A/qt6/qml"
[ -d "$d" ] && export QML_IMPORT_PATH="$d${QML_IMPORT_PATH:+:$QML_IMPORT_PATH}"
d="$SNAP/usr/lib/$A/qt4"
[ -d "$d" ] && export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}$d"
exec "$@"
"""
# where the launchers find DESKTOP_LAUNCH for the apps that ran through an extension's desktop-launch
DESKTOP_ENV = ".desktop-launch"


def replace_desktop_helpers(opt: Path) -> list[str]:
    """Put debpak's DESKTOP_LAUNCH in place of each snapcraft-desktop-helpers launcher in the snap.

    Snaps built before snapcraft's extensions run their app through
    bin/desktop-launch (Atomify's wrapper: desktop-launch custom-qt-helper
    atomify; MiniZinc's command: bin/desktop-launch $SNAP/MiniZincIDE.sh).
    Outside snapd it filled the log with "ln: failed to create symbolic link
    ... File exists" for GSettings schemas, compiled the runtime's schemas with
    the snap's older ones (GLib then ignored whole schema files), failed at
    update-mime-database, and pointed LIBGL_DRIVERS_PATH and
    __EGL_VENDOR_LIBRARY_DIRS at the snap's own Mesa. The stand-in keeps the
    name, so every way the snap calls it (its command, a wrapper, a
    command-chain) reaches it.

    Returns:
        The replaced files, relative to opt.
    """
    out = []
    for p in sorted(opt.rglob("desktop-launch")):
        try:
            if p.is_symlink() or not p.is_file() or p.stat().st_size > (1 << 20) \
                    or DESKTOP_HELPER_MARK not in p.read_bytes():
                continue
        except OSError:
            continue
        p.write_text(DESKTOP_LAUNCH)
        p.chmod(0o755)
        out.append(str(p.relative_to(opt)))
    return out


# --------------------------------------------------------------------------- paths snapd gives the snap

# what the path rewrite reads: bigger files, and media and archives, hold no paths worth changing
# (Facturel Soft's libwebkit2gtk-4.1.so.0, which names its helpers' folder, is 100 MB)
PATH_SCAN_LIMIT = 256 << 20
PATH_SCAN_SKIP = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".svgz", ".ico", ".ogg", ".oga", ".mp3", ".wav",
                  ".flac", ".opus", ".mp4", ".webm", ".zip", ".gz", ".xz", ".bz2", ".zst", ".ttf", ".otf",
                  ".woff", ".woff2", ".pak", ".dat", ".h", ".hpp")
# the characters a path is made of, so that a path is only matched whole: /usr/lib/cli is not
# /usr/lib/cli-common, and /snap/core24/current/usr/lib/... is not /usr/lib/...
_PATH_CHARS = rb"A-Za-z0-9._~+@-"
# a shell expansion that a path follows, making it a path somewhere else: "$SNAP"/usr/lib/cli
_AFTER_EXPANSION = re.compile(rb"(?:\$\w+|\$\{[^}\s]*\}|\$\([^)]*\))[\"']?$")


def layout_paths(meta: dict, opt: Path) -> dict[str, str]:
    """Return {path in /usr: the snap's folder or file that snap.yaml's layout puts there, relative to opt}.

    A snap reaches files its libraries look for at their build-time paths
    through a layout: GIMP's binds /usr/lib/<triplet>/babl-0.1 and gegl-0.4 to
    its own copies (babl looks for its extensions there), Banshee's binds
    /usr/lib/cli, where its Mono assemblies' .dll.config files point, and
    ChartGeany's /usr/share/qt5. Only paths under /usr are taken, since in the
    Flatpak each has a place in /app of the same length (/usr/X is /app/X), and
    only sources the snap has: one in a content snap's folder (Facturel Soft's
    webkit2gtk-4.1 from $SNAP/gnome-platform) counts when the snap carries its
    own copy at the layout's path.
    """
    layout = meta.get("layout")
    out: dict[str, str] = {}
    if not isinstance(layout, dict):
        return out
    for path, spec in layout.items():
        path = str(path).rstrip("/")
        if not isinstance(spec, dict) or not path.startswith("/usr/") or path.startswith("/usr/local/"):
            continue
        src = next((str(spec[k]) for k in ("bind", "symlink", "bind-file") if spec.get(k)), "")
        m = re.fullmatch(r"\$(?:SNAP|\{SNAP\})/(.+?)/?", src)
        if not m or ".." in m.group(1).split("/"):
            continue
        for rel in (m.group(1), path[1:]):
            # a content snap's folder is there, empty, as the place snapd mounts it
            if (opt / rel).is_file() or (opt / rel).is_dir() and any((opt / rel).iterdir()):
                out[path] = rel
                break
    return out


# the module folders a library also finds through a variable, for a layout path where the
# library builds the folder's path itself, so that no string in it can be pointed at /app: GIMP's
# libbabl did, and stopped at babl_format("CIE Lab float"): not found
LAYOUT_VARIABLES = {"babl-0.1": "BABL_PATH", "gegl-0.4": "GEGL_PATH", "libheif/plugins": "LIBHEIF_PLUGIN_PATH",
                    "frei0r-1": "FREI0R_PATH", "ladspa": "LADSPA_PATH", "lv2": "LV2_PATH", "dssi": "DSSI_PATH"}


def layout_variables(layouts: dict[str, str]) -> dict[str, str]:
    """Return {variable: the snap's folder, relative to opt} for the layout paths in LAYOUT_VARIABLES."""
    out = {}
    for path, rel in sorted(layouts.items()):
        m = re.fullmatch(r"/usr/lib(?:/[^/]+-linux-gnu[^/]*)?/(.+)", path)
        if m and m.group(1) in LAYOUT_VARIABLES:
            out.setdefault(LAYOUT_VARIABLES[m.group(1)], rel)
    return out


def link_layouts(root: Path, opt: Path, layouts: dict[str, str]) -> list[str]:
    """Put a link at each layout path (under root, so /usr/X lands at /app/X) to the snap's folder.

    Returns:
        The layout paths linked.
    """
    out = []
    for path, rel in sorted(layouts.items()):
        link = root / path.lstrip("/")
        if os.path.lexists(link):
            continue
        link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(os.path.relpath(opt / rel, link.parent), link)
        out.append(path)
    return out


def snap_path_rewrites(name: str, layouts) -> list[tuple[bytes, bytes, bytes]]:
    """Return (path, its place in the Flatpak in a binary, in a text file) for rewrite_paths.

    Snaps built with their install prefix at their mount point keep
    /snap/NAME/current in their files: Mousam's launcher, a Python script,
    loads its resources from pkgdatadir = '/snap/mousam/current/usr/share/mousam'.
    That is /app/opt/NAME in the Flatpak, five characters shorter; in a binary,
    whose strings can't move, the difference is made up with slashes
    (/app/opt/NAME//////usr/share/...), which name the same folder. A layout's
    path /usr/X becomes /app/X, which link_layouts points at the snap's own folder.
    """
    snap = f"/snap/{name}/current".encode()
    here = f"/app/opt/{name}".encode()
    out = [(snap, here + b"/" * (len(snap) - len(here)), here)]
    for path in layouts:
        new = ("/app/" + path[len("/usr/"):]).encode()
        out.append((path.encode(), new, new))
    return out


_PATH_CHAR = re.compile(rb"[" + _PATH_CHARS + rb"]")


def _packed_mount_point(data: bytes, start: int) -> bool:
    """Return whether the snap's mount point at start in a binary, right after a letter or digit, starts a
    string of its own.

    A Rust program keeps its strings end to end, with nothing between them: Mousai's has "Unable to
    start GStreamer/snap/mousai/current/usr/share/mousai/resources.gresource", and the path, after the
    "r" of the string before it, wasn't pointed at /app; it stopped at "Could not load gresource file:
    ... /snap/mousai/current/usr/share/mousai/resources.gresource". The letters before the path are
    another string's end unless they are a folder of a longer path (/var/snap/NAME/current, which is
    $SNAP_DATA, or /home/USER/snap/NAME/current) or a variable ($HOME/snap/NAME/current).
    """
    i = start
    while i > 0 and start - i < 64 and _PATH_CHAR.match(data, i - 1):
        i -= 1
    return i == 0 or data[i - 1:i] not in (b"/", b"$", b"\\")


def rewrite_paths(opt: Path, rewrites: list[tuple[bytes, bytes, bytes]],
                  skip_dirs: tuple[str, ...] = ("meta", "snap", LAUNCH_DIR)) -> list[str]:
    """Replace whole paths in the snap's files, in place: binaries keep their length, text needn't.

    A file with a NUL byte in it (an ELF file, compiled Python) is a binary.
    A path counts where it isn't part of a longer one: not after a path
    character or a slash (unless that's the end of "://"), and not before a
    path character.

    Returns:
        The files changed, relative to opt.
    """
    if not rewrites:
        return []
    olds = sorted({r[0] for r in rewrites}, key=len, reverse=True)
    pattern = re.compile(rb"(?:(?<=://)|(?<![/" + _PATH_CHARS + rb"]))(" + b"|".join(map(re.escape, olds))
                         + rb")(?![" + _PATH_CHARS + rb"])")
    # in a binary, the snap's mount point may also follow the last letters of another string (see
    # _packed_mount_point)
    mounts = [o for o in olds if o.startswith(b"/snap/")]
    packed = re.compile(rb"(?<=[A-Za-z0-9])(" + b"|".join(map(re.escape, mounts)) + rb")(?![" + _PATH_CHARS
                        + rb"])") if mounts else None
    binary = {r[0]: r[1] for r in rewrites}
    text = {r[0]: r[2] for r in rewrites}
    first = re.compile(b"|".join(map(re.escape, olds)))
    changed = []
    for dirpath, dirnames, filenames in os.walk(opt):
        if Path(dirpath) == opt:
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fn in filenames:
            p = Path(dirpath) / fn
            if fn.lower().endswith(PATH_SCAN_SKIP) or p.is_symlink():
                continue
            try:
                if not p.is_file() or p.stat().st_size > PATH_SCAN_LIMIT:
                    continue
                data = p.read_bytes()
            except OSError:
                continue
            if not first.search(data):
                continue
            table = binary if b"\0" in data else text

            def sub(m, table=table, data=data):
                # "$SNAP"/usr/lib/cli in a script is already the snap's folder (Banshee's launcher)
                if _AFTER_EXPANSION.search(data, max(0, m.start() - 64), m.start()):
                    return m.group(0)
                return table[m.group(1)]
            new = pattern.sub(sub, data)
            if packed is not None and table is binary:
                new = packed.sub(lambda m, new=new: table[m.group(1)] if _packed_mount_point(new, m.start())
                                 else m.group(0), new)
            if new == data:
                continue
            mode = p.stat().st_mode
            p.chmod(mode | 0o200)
            p.write_bytes(new)
            p.chmod(mode)
            changed.append(str(p.relative_to(opt)))
    return changed


def relocate_package_dirs(opt: Path, layouts) -> list[str]:
    """Point a program at /app/share or /app/lib where it joins /usr/share or /usr/lib to its own name.

    Liferea's snap binds /usr/share/liferea to its own folder with a layout, and
    the program, built with autotools' prefix at /usr, makes the path at run time
    from "/usr/share" and its package name, "liferea", so no whole path in it
    could be pointed at /app; it stopped at "failed to add UI: Failed to open
    file /usr/share/liferea/mainwindow.ui". In a program named NAME whose snap
    lays out /usr/share/NAME or /usr/lib/NAME, and which has NAME as a string of
    its own, the string "/usr/share" (or "/usr/lib") on its own becomes
    "/app/share" (or "/app/lib"), the same length, where link_layouts put NAME.

    Returns:
        The programs changed, relative to opt.
    """
    wanted: dict[str, set[str]] = {}
    for path in layouts:
        if m := re.fullmatch(r"/usr/(share|lib)/([^/]+)", path):
            wanted.setdefault(m.group(2), set()).add(m.group(1))
    out = []
    for name, bases in sorted(wanted.items()):
        for p in sorted(opt.glob(f"**/bin/{name}")) + sorted(opt.glob(f"**/sbin/{name}")):
            try:
                if p.is_symlink() or not p.is_file() or p.stat().st_size > PATH_SCAN_LIMIT:
                    continue
                data = p.read_bytes()
            except OSError:
                continue
            if not data.startswith(b"\x7fELF") or b"\0" + name.encode() + b"\0" not in data:
                continue
            new = data
            for base in sorted(bases):
                new = new.replace(f"\0/usr/{base}\0".encode(), f"\0/app/{base}\0".encode())
            if new != data:
                mode = p.stat().st_mode
                p.chmod(mode | 0o200)
                p.write_bytes(new)
                p.chmod(mode)
                out.append(str(p.relative_to(opt)))
    return out


# Qt 5 keeps its install prefix in a string with room to change it ("qt_prfxpath=/usr" and NULs),
# from which it finds its plugins, its QtWebEngineProcess and its data
QT5_PREFIX = b"qt_prfxpath=/usr\0"


def relocate_qt5(opt: Path, app_opt: str) -> list[str]:
    """Point the prefix of the snap's own Qt 5 (libQt5Core) at its place in the Flatpak, app_opt/usr.

    ChartGeany's snap carries Qt 5 and Qt WebEngine from Ubuntu, whose Qt looks
    for QtWebEngineProcess in /usr/lib/<triplet>/qt5/libexec and for its
    resources in /usr/share/qt5; snapcraft's desktop-launch set
    QTWEBENGINEPROCESS_PATH and its layout bound /usr/share/qt5, and without
    them it stopped at "Could not find QtWebEngineProcess". With the prefix at
    the snap's usr, Qt finds all of its folders (plugins, libexec, data,
    translations) in the snap. Only a Qt whose folders are in the snap moves.

    Returns:
        The libraries changed, relative to opt.
    """
    out = []
    new = b"qt_prfxpath=" + f"{app_opt}/usr".encode()
    for p in sorted(opt.glob("usr/lib/*/libQt5Core.so.5*")) + sorted(opt.glob("lib/*/libQt5Core.so.5*")):
        if p.is_symlink() or not p.is_file() or not (p.parent / "qt5").is_dir():
            continue
        data = bytearray(p.read_bytes())
        i = data.find(QT5_PREFIX)
        if i < 0 or data[i + len(QT5_PREFIX) - 1:i + len(new) + 1].strip(b"\0"):
            continue
        data[i:i + len(new)] = new
        mode = p.stat().st_mode
        p.chmod(mode | 0o200)
        p.write_bytes(bytes(data))
        p.chmod(mode)
        out.append(str(p.relative_to(opt)))
    return out


# what a snap sets to find its own GL and video drivers: the GL extension's Mesa reads its drivers,
# EGL vendors and Vulkan ICDs from the extension, and a path into the snap would point it elsewhere
GL_DRIVER_VARIABLES = ("LIBGL_DRIVERS_PATH", "LIBGL_DRIVERS_DIR", "__EGL_VENDOR_LIBRARY_DIRS",
                       "__EGL_VENDOR_LIBRARY_FILENAMES", "LIBVA_DRIVERS_PATH", "VK_ICD_FILENAMES",
                       "VK_DRIVER_FILES", "GBM_BACKENDS_PATH", "DRIRC_CONFIGDIR", "VDPAU_DRIVER_PATH")


def _kept_environment(env: dict, opt: Path | None) -> dict:
    """Return the snap.yaml environment the launcher sets, without what would mislead the runtime.

    Left out are the GL driver variables (GL_DRIVER_VARIABLES), and any
    variable whose value is one path into the snap that the snap doesn't
    have: it named a file from the snap's base or a content snap (a
    FONTCONFIG_FILE=$SNAP/etc/fonts/fonts.conf the snap never staged would
    leave fontconfig without any configuration).
    """
    out = {}
    for k, v in env.items():
        v = str(v)
        if str(k) in GL_DRIVER_VARIABLES:
            continue
        m = re.fullmatch(r"\$(?:SNAP|\{SNAP\})/([^:$]+?)/?", v)
        if opt is not None and m and not os.path.lexists(opt / m.group(1)):
            continue
        out[k] = v
    return out


def content_targets(meta: dict) -> list[str]:
    """Return the folders in the snap (relative to $SNAP) that its content plugs mount other snaps at."""
    plugs = meta.get("plugs") if isinstance(meta.get("plugs"), dict) else {}
    out = []
    for spec in plugs.values():
        if isinstance(spec, dict) and spec.get("interface") == "content":
            m = re.fullmatch(r"\$(?:SNAP|\{SNAP\})/(.+?)/?", str(spec.get("target") or ""))
            if m:
                out.append(m.group(1))
    return out


def content_wrapper(opt: Path, chain: str, meta: dict) -> bool:
    """Return True if a command-chain script only hands over to a content snap the snap doesn't carry.

    0 A.D.'s snap runs its game through bin/gpu-2404-wrapper (its own copy of
    the GPU extension's wrapper, so not under snap/command-chain/), which asks
    snapctl whether the gpu-2404 plug is connected and then runs
    $SNAP/gpu-2404/bin/gpu-2404-provider-wrapper. Outside snapd it ended with
    "the gpu-2404 interface isn't connected" and status 1. A small script whose
    exec goes into a content plug's folder that is empty or missing in the
    snap is skipped, as snapcraft's own extension launchers are; the GL
    extension and the runtime stand in for the content snap.
    """
    p = opt / chain
    try:
        if not p.is_file() or p.stat().st_size > (64 << 10):
            return False
        text = p.read_text("utf-8", "replace")
    except OSError:
        return False
    for target in content_targets(meta):
        d = opt / target
        if d.is_dir() and any(d.iterdir()):
            continue
        if re.search(r"(?m)^\s*exec\s+[\"']?\$\{?SNAP\}?/" + re.escape(target) + r"/", text):
            return True
    return False


def _launcher(snap_name: str, app: str, spec: dict, meta: dict, services: dict[str, str] | None = None,
              opt: Path | None = None) -> str:
    """Write the shell launcher for one app in snap.yaml.

    The launcher recreates what snapd would set up: $SNAP and the other SNAP_*
    variables (user data under $XDG_DATA_HOME/snap), library and program paths
    inside the snap, and the snap's environment. Then it runs the app's command
    through its command-chain, minus snapcraft's desktop-extension launchers.

    services ({bus name: app}) are the snap's user services that D-Bus starts
    when something asks for their name (see session_services); the launcher
    starts each one whose name has no owner yet, and waits for it to appear.
    """
    env = dict(meta.get("environment") or {})
    env.update(spec.get("environment") or {})
    env = _kept_environment(env, opt)
    env, _ = content_environment(env, meta, opt)
    command = str(spec.get("command") or app)
    try:
        argv = shlex.split(command)
    except ValueError:
        argv = command.split()
    prog = argv[0] if argv else app
    if not prog.startswith(("$SNAP", "${SNAP}", "/")):
        prog = "$SNAP/" + prog
    chain = [c for c in (spec.get("command-chain") or []) if not str(c).startswith("snap/command-chain/")
             and not (opt is not None and content_wrapper(opt, str(c), meta))]
    lines = [
        "#!/bin/sh",
        f"# Generated by debpak from {snap_name}'s snap.yaml (app {app!r}); runs it without snapd.",
        'SNAP="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"',
        f"export SNAP SNAP_NAME={shlex.quote(snap_name)} SNAP_INSTANCE_NAME={shlex.quote(snap_name)}",
        f"export SNAP_VERSION={shlex.quote(str(meta.get('version', '')))} SNAP_REVISION=debpak",
        'export SNAP_ARCH="$(uname -m | sed -e s/x86_64/amd64/ -e s/aarch64/arm64/)"',
        ': "${XDG_DATA_HOME:=$HOME/.local/share}"',
        'export SNAP_USER_DATA="$XDG_DATA_HOME/snap/current" SNAP_USER_COMMON="$XDG_DATA_HOME/snap/common"',
        'export SNAP_DATA="$SNAP_USER_DATA" SNAP_COMMON="$SNAP_USER_COMMON" SNAP_REAL_HOME="$HOME"',
        'mkdir -p "$SNAP_USER_DATA" "$SNAP_USER_COMMON"',
        'DEBPAK_LIBRARY_PATH="$LD_LIBRARY_PATH"',
        'for d in "$SNAP/usr/lib/$(uname -m)-linux-gnu" "$SNAP/lib/$(uname -m)-linux-gnu" "$SNAP/usr/lib" '
        '"$SNAP/lib"; do',
        '  [ -d "$d" ] && LD_LIBRARY_PATH="$d${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" && '
        'DEBPAK_SNAP_LIBRARY_PATH="$d${DEBPAK_SNAP_LIBRARY_PATH:+:$DEBPAK_SNAP_LIBRARY_PATH}"',
        "done",
        'export LD_LIBRARY_PATH PATH="$SNAP/usr/bin:$SNAP/bin:$PATH"',
    ]
    for k, v in env.items():
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(k)):
            lines.append(f'export {k}="{str(v)}"')
    for var, rel in (layout_variables(layout_paths(meta, opt)) if opt is not None else {}).items():
        if var not in env:
            lines.append(f'export {var}="${{{var}:-$SNAP/{rel}}}"')
    if "LD_LIBRARY_PATH" in env:
        # The snap sets its own library path (Multipass: $SNAP/lib:$SNAP/usr/lib/...),
        # which would drop the folders the Flatpak's launcher put there; the libraries
        # debpak added in place of the base snap's are found after the snap's own. The
        # snap's library folders follow it too, as snapcraft-runner (a command-chain
        # debpak skips) adds them: TiMidity++'s snap sets only .../pulseaudio, and its
        # zenity then couldn't find the snap's own libwebkit2gtk-4.0.so.37
        lines.append('export LD_LIBRARY_PATH="$LD_LIBRARY_PATH${DEBPAK_SNAP_LIBRARY_PATH:+:$DEBPAK_SNAP_LIBRARY_PATH}'
                     '${DEBPAK_LIBRARY_PATH:+:$DEBPAK_LIBRARY_PATH}"')
    for bus_name, service in sorted((services or {}).items()):
        # Firmware Updater's app only runs `gapplication launch com.canonical.firmware_updater`:
        # snapd's session bus would start the snap's firmware-updater-app for that name
        lines += [
            f"# D-Bus would start the snap's {service} for {bus_name}; nothing does in a Flatpak",
            "if ! gdbus call --session --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus "
            f"--method org.freedesktop.DBus.NameHasOwner {bus_name} 2>/dev/null | grep -q true; then",
            f'  "$SNAP/{LAUNCH_DIR}/{service}" &',
            f"  gdbus wait --session --timeout 20 {bus_name} 2>/dev/null",
            "fi",
        ]
    if extension_desktop_launch(spec):
        # the extension's desktop-launch is skipped, but what of it is about the snap's own folders
        # isn't: KGoldrunner's levels are in $SNAP/usr/share/kgoldrunner, found through XDG_DATA_DIRS
        chain.insert(0, f"{LAUNCH_DIR}/{DESKTOP_ENV}")
    chain_cmds = " ".join(f'"$SNAP/{c}"' for c in chain)
    # snapd expands $SNAP and the like in a command's arguments (Pick's command is
    # "bin/desktop-launch $SNAP/bin/pick-colour-picker"), so they go in double quotes
    args = " ".join(_expanding(a) for a in argv[1:])
    lines.append(f'exec {chain_cmds + " " if chain_cmds else ""}"{prog}"{" " + args if args else ""} "$@"')
    return "\n".join(lines) + "\n"


def extract_snap(path: Path, dest: Path) -> Package:
    """Unpack a snap into opt/<name>, with one launcher per app.

    Daemons get no launcher, and the report says so; a system service the
    snap can't do without (see system_services) is a blocker. The snap's
    meta/gui entries are installed pointing at the launchers, with the snap's
    icon.

    Args:
        path: A .snap file, or an installed snap's folder (/snap/NAME/current).
        dest: An empty working folder.

    Raises:
        PackageError: Not a snap, a base or content snap with no apps, or every
            app is a daemon.
    """
    dest.mkdir(parents=True, exist_ok=True)
    tree = dest / "snap"
    if path.is_dir():
        shutil.copytree(path, tree, symlinks=True)
    else:
        _unsquash(path, tree)
    yml = tree / "meta/snap.yaml"
    if not yml.is_file():
        raise PackageError(f"{path}: no meta/snap.yaml (not a snap?)")
    meta = parse_yaml(yml.read_text("utf-8", "replace"))
    if not isinstance(meta, dict) or not meta.get("name"):
        raise PackageError(f"{path}: couldn't read meta/snap.yaml")
    name = str(meta["name"])
    kind = str(meta.get("type") or "app")
    apps = meta.get("apps") or {}
    if kind != "app" or not apps:
        what = f"an {kind}" if kind[:1] in "aeiou" else f"a {kind}"
        raise PackageError(f"{name} is {what} snap with no apps (a base, runtime, theme or content snap), "
                           "nothing to convert")

    root = dest / "root"
    opt = root / "opt" / name
    opt.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(tree), str(opt))

    launch = opt / LAUNCH_DIR
    launch.mkdir()
    helpers = replace_desktop_helpers(opt)
    if any(isinstance(sp, dict) and extension_desktop_launch(sp) for sp in apps.values()):
        (launch / DESKTOP_ENV).write_text(DESKTOP_LAUNCH)
        (launch / DESKTOP_ENV).chmod(0o755)
    session = session_services(meta)
    for app, spec in apps.items():
        spec = spec if isinstance(spec, dict) else {}
        if spec.get("daemon") and str(app) not in session.values():
            continue                         # services aren't apps; reported below
        p = launch / str(app)
        p.write_text(_launcher(name, str(app), spec, meta, None if spec.get("daemon") else session, opt))
        p.chmod(0o755)
    main_app = name if (launch / name).exists() else next(
        (a for a, sp in apps.items() if (launch / str(a)).exists() and not (isinstance(sp, dict) and sp.get("daemon"))),
        None)
    if main_app is None:
        # authd-google's one app is a D-Bus daemon of the system bus (an authentication broker), which
        # snapd runs as root: a snap of system services alone, which a Flatpak can't be
        if all(str(sp.get("daemon-scope") or "system") != "user" for sp in apps.values() if isinstance(sp, dict)):
            raise PackageError(f"{name}: every app in snap.yaml is a system service (a daemon snapd runs as root); "
                               "nothing to launch")
        raise PackageError(f"{name}: every app in snap.yaml is a daemon; nothing to launch")

    # menu entries: meta/gui (and snap/gui for older snaps), pointed at the launchers
    icon_name = name
    desktops = sorted((opt / "meta/gui").glob("*.desktop")) + sorted((opt / "snap/gui").glob("*.desktop"))
    apps_dir = root / "usr/share/applications"
    menu_apps = []
    for d in desktops:
        text = d.read_text("utf-8", "replace")
        exec_line = _desktop_value(text, "Exec") or ""
        tok = (exec_line.split() or [""])[0].removeprefix("/snap/bin/").removeprefix("env BAMF_DESKTOP_FILE_HINT")
        app = tok.split(".", 1)[1] if tok.startswith(name + ".") else (name if tok == name else
                                                                       d.stem.split("_")[-1])
        target = launch / app if (launch / app).exists() else launch / main_app
        menu_apps.append(target.name)
        text = _set_desktop_exec(text, f"/opt/{name}/{LAUNCH_DIR}/{target.name}")
        icon = _desktop_value(text, "Icon") or ""
        icon_file = None
        if icon.startswith(("${SNAP}", "$SNAP", "/snap/")):
            rel = re.sub(r"^(\$\{SNAP\}|\$SNAP|/snap/[^/]+/(current|\d+))/?", "", icon)
            icon_file = opt / rel
        elif icon and not icon.startswith("/"):
            for cand in (opt / "meta/gui" / f"{icon}.png", opt / "meta/gui" / f"{icon}.svg",
                         opt / "meta/gui/icon.png", opt / "meta/gui/icon.svg"):
                if cand.is_file():
                    icon_file = cand
                    break
        if icon_file and icon_file.is_file():
            _place_icon(icon_file, root, icon_name)
            text = re.sub(r"(?m)^Icon=.*$", f"Icon={icon_name}", text)
        apps_dir.mkdir(parents=True, exist_ok=True)
        (apps_dir / f"{name}_{app}.desktop").write_text(text)
    if not desktops:
        for cand in (opt / "meta/gui/icon.png", opt / "meta/gui/icon.svg"):
            if cand.is_file():
                _place_icon(cand, root, icon_name)
                break
    if menu_apps and main_app not in menu_apps:
        # the Flatpak's command and its menu entry run the same program: the graphical
        # app (Multipass's gui), not a command-line app that happens to share the snap's name
        main_app = menu_apps[0]

    # the paths snapd gave the snap's files: its mount point, and its layout's paths in /usr
    layouts = layout_paths(meta, opt)
    linked = link_layouts(root, opt, layouts)
    rewritten = rewrite_paths(opt, snap_path_rewrites(name, {p: layouts[p] for p in linked}))
    rewritten += [f for f in relocate_package_dirs(opt, linked) if f not in rewritten]
    qt5 = relocate_qt5(opt, f"/app/opt/{name}")

    base = str(meta.get("base") or "core")
    arch_list = meta.get("architectures") or []
    arch = next((SNAP_ARCH[a] for a in arch_list if isinstance(a, str) and a in SNAP_ARCH), "")
    if not arch:
        arch = _guess_arch(opt) or ""
    pkg = Package("snap", path, root, name, str(meta.get("version", "0")), arch,
                  str(meta.get("summary") or meta.get("title") or ""), str(meta.get("description") or ""),
                  str(meta.get("website") or ""), str(meta.get("license") or ""),
                  default_exec=f"/opt/{name}/{LAUNCH_DIR}/{main_app}",
                  extra={"opt_name": name, "base": base, "ubuntu_suite": BASE_TO_UBUNTU.get(base),
                         "confinement": meta.get("confinement", "strict"), "apps": sorted(map(str, apps))})
    if (python_app := python_bindings(opt, apps))[0]:
        pkg.extra["python_app"] = f"opt/{name}/{python_app[0]}"
        pkg.extra["requires"] = python_app[1]
    if (gir := gi_packages(opt, meta)):
        pkg.extra["gir"] = gir
    if names := {**mpris_names(meta), **own_bus_names(meta)}:
        pkg.extra["bus_names"] = names
    access = bus_access(meta)
    for daemon, arg in host_services(apps).items():
        access.setdefault(arg, f"the snap runs its own {daemon}; the host's stands in for it")
    if access:
        pkg.extra["bus_access"] = access
    for plug, target in platform_snaps(meta).items():
        pkg.extra.setdefault("findings", []).append((
            "blocker", "snap.yaml",
            f"runs on the {target} snap (content plug {plug}), which a Flatpak can't reach"
            + ("; convert the Windows program itself instead, which runs on the Wine base app"
               if target.startswith("wine-platform") else "")))
    services = system_services(apps, bool(desktops) or any(isinstance(s, dict) and s.get("desktop")
                                                              for s in apps.values()),
                               web_ui=opens_local_web_page(opt, apps), slots=_slots(meta),
                               classic=meta.get("confinement") == "classic")
    if services:
        # Multipass's CLI and GUI only drive multipassd, which runs the VMs as root:
        # its menu entry would open a client with nothing to connect to
        pkg.extra.setdefault("findings", []).append((
            "blocker", "snap.yaml",
            f"runs a system service ({', '.join(services)}) that the snap's apps rely on; "
            "Flatpaks cannot run system services"))
    if (why := manages_software(opt, apps)):
        pkg.extra.setdefault("findings", []).append((
            "blocker", "snap.yaml",
            f"installs and removes the system's software ({why}); the package manager it drives "
            "(snapd, apt, PackageKit) can't be reached from a Flatpak"))
    daemons = [str(a) for a, s in apps.items() if isinstance(s, dict) and s.get("daemon") and str(a) not in services
               and str(a) not in session.values()]
    if (on_host := host_services(apps)):
        pkg.notes.append(f"the snap's {', '.join(on_host)} isn't converted: the app uses the host's "
                         "(install it there if the app can't find it)")
        daemons = [d for d in daemons if d not in on_host]
    if daemons:
        pkg.notes.append(f"background services in the snap aren't converted: {', '.join(daemons)}")
    if any(str(c).startswith("snap/command-chain/") for s in apps.values() if isinstance(s, dict)
           for c in (s.get("command-chain") or [])):
        pkg.notes.append("snapcraft desktop-extension launchers skipped; the Flatpak runtime provides GTK/Qt"
                         + (", and debpak's desktop-launch points the app at the snap's own data and plugins"
                            if (launch / DESKTOP_ENV).exists() else ""))
    if (content := describe_content(meta)):
        pkg.notes.append(content)
    if helpers:
        pkg.notes.append(f"put debpak's own desktop-launch in place of the snap's ({', '.join(helpers)}): the "
                         "original sets up GSettings, mime, fonts and GL from the snap's base, which the runtime replaces")
    if linked:
        pkg.notes.append(f"the snap's layout puts its own files at {', '.join(linked)}: they are at the same "
                         "paths under /app, and the snap's files name them there")
    if rewritten:
        pkg.notes.append(f"pointed the paths snapd gives the snap (/snap/{name}/current"
                         f"{' and its layout' if linked else ''}) at /app in {len(rewritten)} file(s) "
                         f"({', '.join(rewritten[:3])}{', ...' if len(rewritten) > 3 else ''})")
    if qt5:
        pkg.notes.append(f"the snap's Qt 5 ({', '.join(qt5)}) looks for its plugins and data in the snap")
    pkg.notes.append(f"snap contents are under /app/opt/{name}; launchers in /app/opt/{name}/{LAUNCH_DIR}")
    return pkg


# bases built on an Ubuntu release older than any runtime debpak builds on (Freedesktop 25.08 and later)
OLDER_THAN_RUNTIMES = ("core", "core18", "core20", "core22", "core24")
# Qt's platform and style plugins use its private API, which changes with every minor version: a
# snap's own Qt stays, with the plugins it was built with (see analyze.kde_runtime_for_qt for the rest)
KEEP_OWN = re.compile(r"^lib(Qt\d|KF\d)")


# a library named for its project's release (libtool's -release: libpulsecommon-16.1.so), which only
# that release's other libraries link
RELEASE_LIBRARY = re.compile(r"^lib[\w+]+(?:-[A-Za-z]\w*)*-\d+(?:\.\d+)+\.so$")


def runtime_copies(opt: str, base: str, elfs: dict, package_sonames: dict[str, str], runtime,
                   triplet: str) -> dict[str, list[str]]:
    """Return the snap's copies of Ubuntu libraries that the runtime's own copies replace.

    A snap carries the Ubuntu packages it was built with (its stage-packages) in
    usr/lib/<triplet> and lib/<triplet>, and its launcher puts those folders first
    on the library path, so they were loaded in place of the runtime's. Tusk's
    snap, built on Ubuntu 16.04, brings its own GLib, GTK, fontconfig and GnuTLS:
    they couldn't load the runtime's GIO modules or read its font settings, and
    the window stayed blank; Vectr's brings its own librt.so.1, which wanted a
    private part of a glibc that isn't there. The runtime's library is used
    instead when it defines every symbol version the snap's copy defines and the
    snap's programs ask for. A library without symbol versions is replaced only
    when the snap's base is older than the runtime, so the runtime's copy is the
    newer one. glibc's own libraries are always the runtime's, and so is the
    graphics stack the GL extension brings (runtime.EXTENSION_PROVIDED_PREFIXES),
    also from the mesa and mesa-egl folders older snaps keep it in: it has to
    match the extension's Mesa and the host's driver (PWGen-Rust's libdrm_amdgpu
    broke the extension's libGLX_mesa; Atomify carried Ubuntu 16.04's own libGL).
    Qt and KDE Frameworks stay (KEEP_OWN), and so does a library that links
    a private library of its release which the snap's programs link too:
    Music Radar's libpulse.so.0 and pactl both link libpulsecommon-16.1.so,
    and the runtime's libpulse.so.0 would have loaded its own
    libpulsecommon-17.0.so into pactl beside it.

    Returns:
        {path of the snap's library: the names it goes by in the package}.
    """
    from .analyze import is_never_bundle
    dirs = {f"{opt}/{d}" for d in ("lib", "usr/lib", f"lib/{triplet}", f"usr/lib/{triplet}")}
    gl_dirs = dirs | {f"{opt}/{d}/{m}" for d in ("lib", "usr/lib", f"lib/{triplet}", f"usr/lib/{triplet}")
                      for m in ("mesa", "mesa-egl")}
    asked: dict[str, set[str]] = {}
    for info in elfs.values():
        for lib, vs in info.verneed.items():
            asked.setdefault(lib, set()).update(vs)
    names: dict[str, list[str]] = {}
    for so, rel in package_sonames.items():
        names.setdefault(rel, []).append(so)
    # the snap's private libraries of one release (see RELEASE_LIBRARY) that the runtime hasn't, and that a
    # program of the snap, or a library the runtime has no copy of, links: a library linking one stays
    # with it, as the runtime's copy would load the runtime's release of it beside the snap's
    kept_needs = {n for r, i in elfs.items()
                  if not i.is_shared_library or not runtime.provides(i.soname or Path(r).name) for n in i.needed}
    private = {so for so in package_sonames
               if RELEASE_LIBRARY.match(so) and not runtime.provides(so) and so in kept_needs}
    out = {}
    for rel, sonames in names.items():
        info = elfs.get(rel)
        if info is None:
            continue
        so = info.soname or Path(rel).name
        graphics = so.startswith(EXTENSION_PROVIDED_PREFIXES) and runtime.provides(so)
        if os.path.dirname(rel) not in (gl_dirs if graphics else dirs):
            continue
        if not graphics and private.intersection(info.needed):
            continue
        # glibc's libc.so.6 is a program too (it has a loader), so only that test isn't enough
        # (a loader stays: a program may name the snap's own as its interpreter)
        if not (info.is_shared_library or is_never_bundle(so)) or so.startswith(("ld-linux", "ld64.so")) \
                or KEEP_OWN.match(so) or not runtime.provides(so):
            continue
        if not (is_never_bundle(so) or graphics):
            have = runtime.versions_of(so) or set()
            defined = set(info.verdef) - {so}
            if not defined and base not in OLDER_THAN_RUNTIMES:
                continue
            if not (defined | asked.get(so, set())) <= have:
                continue
        out[rel] = sorted(sonames)
    return out


def _slots(meta: dict) -> dict:
    slots = meta.get("slots")
    return slots if isinstance(slots, dict) else {}


def _interface(meta: dict, plug: str) -> tuple[str, dict]:
    """Return a plug's interface and its attributes; a plug named after its interface needs no entry."""
    plugs = meta.get("plugs") if isinstance(meta.get("plugs"), dict) else {}
    spec = plugs.get(plug) if isinstance(plugs.get(plug), dict) else {}
    return str(spec.get("interface") or plug), spec


def session_services(meta: dict) -> dict[str, str]:
    """Return {bus name: app} for the snap's user services that the session bus starts on demand.

    Such an app is a daemon with daemon-scope user, daemon: dbus and
    activates-on a dbus slot on the session bus: Firmware Updater's
    firmware-updater-app is its window, and the app in its menu only asks
    D-Bus for com.canonical.firmware_updater. A Flatpak can't export a
    D-Bus service under another name than its own, so the launchers start it.
    """
    out = {}
    apps = meta.get("apps") if isinstance(meta.get("apps"), dict) else {}
    for app, spec in apps.items():
        if not isinstance(spec, dict) or spec.get("daemon") != "dbus" or spec.get("daemon-scope") != "user":
            continue
        for slot in spec.get("activates-on") or []:
            sspec = _slots(meta).get(slot)
            if isinstance(sspec, dict) and sspec.get("interface") == "dbus" and \
                    str(sspec.get("bus") or "session") == "session" and sspec.get("name"):
                out[str(sspec["name"])] = str(app)
    return out


def own_bus_names(meta: dict) -> dict[str, str]:
    """Return the session-bus names the snap's dbus slots let it own, with where each was found."""
    out = {}
    for slot, spec in _slots(meta).items():
        if isinstance(spec, dict) and spec.get("interface") == "dbus" and \
                str(spec.get("bus") or "session") == "session" and re.fullmatch(r"[\w.-]+", str(spec.get("name") or "")):
            out[str(spec["name"])] = f"dbus slot {slot} in snap.yaml"
    return out


# snapd interfaces that let an app talk to a service of the host on the system bus, and the
# service's bus name: what the app says there can't be read from its programs (Firmware Updater,
# a Flutter app, asks fwupd over D-Bus for the firmware it can update)
SYSTEM_BUS_PLUGS = {
    "fwupd": "org.freedesktop.fwupd", "udisks2": "org.freedesktop.UDisks2", "upower-observe": "org.freedesktop.UPower",
    "network-manager": "org.freedesktop.NetworkManager", "network-manager-observe": "org.freedesktop.NetworkManager",
    "bluez": "org.bluez", "modem-manager": "org.freedesktop.ModemManager1", "shutdown": "org.freedesktop.login1",
    "login-session-observe": "org.freedesktop.login1", "hostname-control": "org.freedesktop.hostname1",
    "timedate-control": "org.freedesktop.timedate1", "avahi-observe": "org.freedesktop.Avahi",
    "avahi-control": "org.freedesktop.Avahi",
}


# plugs for what a Flatpak reaches through a socket of the host's, with the finish-arg that lets it in
SOCKET_PLUGS = {"audio-playback": "--socket=pulseaudio", "audio-record": "--socket=pulseaudio",
                "pulseaudio": "--socket=pulseaudio", "alsa": "--socket=pulseaudio"}


def bus_access(meta: dict) -> dict[str, str]:
    """Return {finish-arg: why} for the D-Bus services and sound the snap's apps plug.

    Those are the host services in SYSTEM_BUS_PLUGS, the names of dbus plugs,
    and the sound server for SOCKET_PLUGS. Only the apps that run in the
    Flatpak count: the snap's system services don't. Singularety's snap, a
    Flutter app, plugs audio-playback and audio-record and links nothing of
    sound: WebRTC's audio module loads libpulse.so.0 itself, and without the
    sound server it aborted at start with "Failed to initialize the ADM".
    """
    out = {}
    apps = meta.get("apps") if isinstance(meta.get("apps"), dict) else {}
    for app, spec in apps.items():
        if not isinstance(spec, dict) or (spec.get("daemon") and spec.get("daemon-scope") != "user"):
            continue
        for plug in _plug_names(spec):
            iface, attrs = _interface(meta, plug)
            if iface in SYSTEM_BUS_PLUGS:
                out.setdefault(f"--system-talk-name={SYSTEM_BUS_PLUGS[iface]}", f"{plug} plug in snap.yaml")
            elif iface in SOCKET_PLUGS:
                out.setdefault(SOCKET_PLUGS[iface], f"{plug} plug in snap.yaml")
            elif iface == "dbus" and re.fullmatch(r"[\w.-]+", str(attrs.get("name") or "")):
                bus = "system-talk-name" if attrs.get("bus") == "system" else "talk-name"
                out.setdefault(f"--{bus}={attrs['name']}", f"dbus plug {plug} in snap.yaml")
    return out


def mpris_names(meta: dict) -> dict[str, str]:
    """Return the MPRIS bus names the snap's mpris slots declare, with where each was found.

    snapd lets the app own org.mpris.MediaPlayer2.NAME and the names under it
    (NAME is the slot's name attribute, else the snap's name). Spotify takes it at
    start and quits quietly when it can't, as if another Spotify were running.
    A slot may also be named only in an app's slots, with no entry of its own
    at the top: snapd then makes it a slot of the interface it is named after.
    Rundfunk's app lists "mpris" that way, and with no name to own its pydbus
    code stopped at RequestName with ServiceUnknown.
    """
    out = {}
    slots = dict(_slots(meta))
    apps = meta.get("apps") if isinstance(meta.get("apps"), dict) else {}
    for spec in apps.values():
        listed = spec.get("slots") if isinstance(spec, dict) else None
        for slot in (listed if isinstance(listed, list) else []):
            slots.setdefault(str(slot), None)
    for slot, spec in slots.items():
        spec = spec if isinstance(spec, dict) else {}
        if str(spec.get("interface") or slot) == "mpris":
            name = str(spec.get("name") or meta.get("name") or "")
            if re.fullmatch(r"[A-Za-z0-9_-]+", name):
                out.setdefault(f"org.mpris.MediaPlayer2.{name}", f"mpris slot {slot} in snap.yaml")
                out.setdefault(f"org.mpris.MediaPlayer2.{name}.*", f"mpris slot {slot} in snap.yaml")
    return out


def _guess_arch(opt: Path) -> str | None:
    """Return the architecture of the first ELF file in the snap, for snaps whose snap.yaml doesn't say."""
    from .packages import _elf_machine
    for p in opt.rglob("*"):
        if p.is_file() and not p.is_symlink() and (m := _elf_machine(p)):
            return m
    return None


def python_without_stdlib(opt: Path) -> list[str]:
    """Return the Python versions (3.10) whose libpython the snap carries without its standard library.

    MySQL Workbench's snap carries libpython3.10 for the Python it embeds; the
    standard library and the python3 it finds on PATH come from its base snap
    (core22's /usr/lib/python3.10), and outside snapd the embedded Python
    stopped: "Could not find platform independent libraries".
    """
    out = []
    for lib in sorted(opt.glob("usr/lib/*/libpython3.*.so.1*")) + sorted(opt.glob("usr/lib/libpython3.*.so.1*")):
        m = re.match(r"libpython(3\.\d+)", lib.name)
        if m and m.group(1) not in out and not (opt / f"usr/lib/python{m.group(1)}/os.py").is_file():
            out.append(m.group(1))
    for _cfg, v in base_venvs(opt):
        if v not in out and not (opt / f"usr/lib/python{v}/os.py").is_file():
            out.append(v)
    return out


def base_venvs(opt: Path) -> list[tuple[Path, str]]:
    """Return the Python virtual environments in the snap made from the base snap's Python, with its version.

    snapcraft's python plugin makes the snap a venv (pyvenv.cfg at its root,
    lib/python3.12/site-packages) whose bin/python3 is a link to the base's
    /usr/bin/python3.12. File Vault's launcher runs python3 $SNAP/usr/bin/main.py:
    without the base, python3 was the runtime's 3.13, which knows nothing of the
    venv, and stopped at "No module named 'PyQt6'" (its sip module is built for 3.12).
    A venv made where the snap was built, and only then moved into the snap, keeps
    that place as its home: Wolvix Player's says home = /root/stage/bin, and its
    bin/python3 is a link to /usr/bin/python3.10, the base's. It runs on the
    base's Python all the same, and its launcher stopped at "bin/python3: No such
    file or directory"; a venv whose python3 links to /usr/bin/python3.X is one too.
    """
    out = []
    for cfg in sorted(opt.glob("pyvenv.cfg")) + sorted(opt.glob("*/pyvenv.cfg")):
        try:
            text = cfg.read_text("utf-8", "replace")
        except OSError:
            continue
        home = re.search(r"(?m)^\s*home\s*=\s*(\S+)", text)
        ver = re.search(r"(?m)^\s*version(?:_info)?\s*=\s*(3\.\d+)", text)
        if not (home and ver and (cfg.parent / f"lib/python{ver.group(1)}/site-packages").is_dir()):
            continue
        if home.group(1).startswith("/usr/") or _links_to_base_python(cfg.parent / "bin", ver.group(1)):
            out.append((cfg, ver.group(1)))
    return out


def _links_to_base_python(bindir: Path, version: str) -> bool:
    """Return True if a venv's bin/python3 (or bin/python3.X) links, through its own links, to /usr/bin/python3.X."""
    for name in ("python3", f"python{version}", "python"):
        p, seen = bindir / name, 0
        while p.is_symlink() and seen < 8:
            target = os.readlink(p)
            if re.fullmatch(r"/usr/bin/python3(?:\.\d+)?", target):
                return target in ("/usr/bin/python3", f"/usr/bin/python{version}")
            if target.startswith("/"):
                break
            p, seen = p.parent / target, seen + 1
    return False


def point_venvs_at(opt: Path, app_opt: str) -> list[str]:
    """Make the snap's venvs (see base_venvs) use the base's Python copied into the snap's usr.

    pyvenv.cfg's home becomes app_opt/usr/bin (where the snap is in the
    sandbox), and the venv's links to /usr/bin/python3.X point at that copy.

    Returns:
        The venvs changed, relative to opt.
    """
    out = []
    for cfg, v in base_venvs(opt):
        if not (opt / f"usr/bin/python{v}").is_file():
            continue
        text = cfg.read_text("utf-8", "replace")
        cfg.write_text(re.sub(r"(?m)^(\s*home\s*=\s*)\S+", lambda m: m.group(1) + f"{app_opt}/usr/bin", text))
        bindir = cfg.parent / "bin"
        for link in sorted(bindir.glob("python*")) if bindir.is_dir() else []:
            if link.is_symlink() and os.readlink(link).startswith("/usr/bin/python"):
                link.unlink()
                link.symlink_to(os.path.relpath(opt / f"usr/bin/python{v}", bindir))
        out.append(str(cfg.parent.relative_to(opt)) if cfg.parent != opt else ".")
    return out


def add_base_python(opt: Path, versions: list[str], fetch, link_python3: bool = True) -> list[str]:
    """Copy each Python's standard library and interpreter from the base's Ubuntu packages into the snap.

    fetch(package name) returns the unpacked Ubuntu package (a DebPackage) or
    None. What the base snap had at /usr/lib/python3.X and /usr/bin/python3.X
    goes under the snap's usr, and usr/bin/python3 points at it when the snap
    has none: that is the python3 the snap's programs found on PATH, unless
    link_python3 is False (a venv's bin/python3 is that python3; see
    point_venvs_at).

    Returns:
        The packages copied in.
    """
    used = []
    for v in versions:
        for name in (f"libpython{v}-minimal", f"libpython{v}-stdlib", f"python{v}-minimal"):
            deb = fetch(name)
            if deb is None:
                continue
            used.append(f"{deb.name} ({deb.version})")
            for sub in (f"usr/lib/python{v}", f"usr/bin/python{v}"):
                src = deb.root / sub
                if src.is_dir():
                    shutil.copytree(src, opt / sub, symlinks=True, dirs_exist_ok=True)
                elif src.is_file():
                    (opt / sub).parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, opt / sub)
        if link_python3 and (opt / f"usr/bin/python{v}").exists() and not os.path.lexists(opt / "usr/bin/python3"):
            (opt / "usr/bin/python3").symlink_to(f"python{v}")
    return used


def embedded_pythons(opt: Path, versions: list[str]) -> list[str]:
    """Return the versions among versions whose libpython a program or library of the snap links.

    Such a program runs Python inside itself, and finds the standard library
    by where it is started from or, failing that, at the /usr/lib/python3.X
    it was built for. iRASPA's snap (core20) links libpython3.8 and names
    itself "iRASPA", which isn't on PATH: outside snapd its Python looked in
    the runtime's /usr/lib/python3.8 and stopped at "No module named
    'encodings'", though the base's standard library had been added to the
    snap's usr (see add_base_python).
    """
    from .elf import ElfError, is_elf, read_elf
    names = {f"libpython{v}.so.1.0": v for v in versions} | {f"libpython{v}.so.1": v for v in versions}
    found: list[str] = []
    for dirpath, _dirs, files in os.walk(opt):
        for fn in files:
            p = Path(dirpath) / fn
            if fn.startswith(("libpython", "python3")) or p.is_symlink() or not is_elf(p):
                continue
            try:
                needed = read_elf(p, want_symbols=False).needed
            except (ElfError, OSError):
                continue
            for n in needed:
                if n in names and names[n] not in found:
                    found.append(names[n])
    return sorted(found)


def point_scripts_at_python(opt: Path, app_opt: str) -> list[str]:
    """Point the snap's scripts that run /usr/bin/python3 at the snap's own Python, when its modules need it.

    PixelCraft Image Studio's snap (core22) starts with a shell script that runs
    exec /usr/bin/python3 "$SNAP/main.py", which under snapd is the base's
    Python 3.10, and its Pillow in usr/lib/python3/dist-packages is built for
    3.10 (_imaging.cpython-310-x86_64-linux-gnu.so); on the runtime's Python it
    stopped at "cannot import name '_imaging' from 'PIL'". When the snap has
    usr/bin/python3.X (its own, or the base's that add_base_python copied in)
    and compiled modules for 3.X and for no other Python, /usr/bin/python3 and
    /usr/bin/python3.X in its scripts (text files that start with #!) become
    that Python's path in the sandbox.

    Returns:
        The scripts changed, relative to opt.
    """
    tags = set()
    for d in ("usr/lib/python3", "usr/lib/python3.*", "lib/python3*", "usr/local/lib/python3*"):
        for folder in opt.glob(d):
            for so in folder.rglob("*.cpython-3*.so"):
                if m := re.search(r"\.cpython-3(\d+)", so.name):
                    tags.add(m.group(1))
    if len(tags) != 1:
        return []
    v = f"3.{tags.pop()}"
    if not (opt / f"usr/bin/python{v}").is_file():
        return []
    pattern = re.compile(rb"(?<![\w./-])/usr/bin/python(?:3|" + re.escape(v.encode()) + rb")(?![\w.-])")
    new = f"{app_opt}/usr/bin/python{v}".encode()
    changed = []
    for dirpath, dirnames, filenames in os.walk(opt):
        if Path(dirpath) == opt:
            dirnames[:] = [d for d in dirnames if d not in ("meta", "snap", LAUNCH_DIR)]
        elif Path(dirpath) == opt / "usr/lib":
            dirnames[:] = [d for d in dirnames if not d.startswith("python")]     # the standard library's own
        for fn in filenames:
            p = Path(dirpath) / fn
            try:
                if p.is_symlink() or not p.is_file() or p.stat().st_size > 1 << 20:
                    continue
                data = p.read_bytes()
            except OSError:
                continue
            if not data.startswith(b"#!") or b"\0" in data or not pattern.search(data):
                continue
            mode = p.stat().st_mode
            p.chmod(mode | 0o200)
            p.write_bytes(pattern.sub(new, data))
            p.chmod(mode)
            changed.append(str(p.relative_to(opt)))
    return changed


def ubuntu_mirror(arch: str) -> str:
    """Return the Ubuntu archive for arch: archive.ubuntu.com for x86, ports.ubuntu.com for the rest."""
    return ("http://archive.ubuntu.com/ubuntu" if arch in ("x86_64", "i386")
            else "http://ports.ubuntu.com/ubuntu-ports")


# --------------------------------------------------------------------------- the Snap Store, without snapd

def store_info(name: str, arch: str = "x86_64", channel: str = "stable", opener=None) -> dict:
    """Ask the Snap Store API (no snapd needed) about a snap's current release.

    Returns:
        {"version", "revision", "url", "sha3_384", "size"} for the given
        architecture and channel.

    Raises:
        PackageError: The channel has no release for that architecture.
    """
    import json
    import urllib.request
    snap_arch = {v: k for k, v in SNAP_ARCH.items()}.get(arch, "amd64")
    req = urllib.request.Request(f"https://api.snapcraft.io/v2/snaps/info/{name}"
                                 "?fields=download,version,revision",
                                 headers={"Snap-Device-Series": "16"})
    with (opener or net.urlopen)(req, timeout=30) as r:
        data = json.load(r)
    track, _, risk = channel.rpartition("/")
    track = track or "latest"
    for e in data.get("channel-map", []):
        ch = e.get("channel", {})
        if ch.get("architecture") == snap_arch and ch.get("risk") == risk and ch.get("track") == track:
            d = e.get("download", {})
            return {"version": e.get("version"), "revision": e.get("revision"), "url": d.get("url"),
                    "sha3_384": d.get("sha3-384"), "size": d.get("size")}
    raise PackageError(f"{name}: no {track}/{risk} release for {snap_arch} in the Snap Store")


def store_download(name: str, dest_dir: Path, arch: str = "x86_64", channel: str = "stable",
                   opener=None) -> tuple[Path, dict]:
    """Download a snap's current release from the Snap Store and check its SHA3-384.

    Returns:
        (path of the downloaded .snap, the release info from store_info).

    Raises:
        PackageError: The store has no such release, or the checksum doesn't match.
    """
    import hashlib
    import urllib.request
    info = store_info(name, arch, channel, opener)
    dest_dir.mkdir(parents=True, exist_ok=True)
    out = dest_dir / f"{name}_{info['revision']}.snap"
    h = hashlib.sha3_384()
    with (opener or net.urlopen)(info["url"], timeout=120) as r, open(out, "wb") as f:
        while chunk := r.read(1 << 20):
            h.update(chunk)
            f.write(chunk)
    if info.get("sha3_384") and h.hexdigest() != info["sha3_384"]:
        out.unlink()
        raise PackageError(f"{name}: download checksum mismatch")
    return out, info


def snap_root() -> Path:
    """Return where installed snaps are mounted: $DEBPAK_SNAP_ROOT, /snap, or /var/lib/snapd/snap (Fedora, Arch)."""
    if os.environ.get("DEBPAK_SNAP_ROOT"):
        return Path(os.environ["DEBPAK_SNAP_ROOT"])
    for p in ("/snap", "/var/lib/snapd/snap"):
        if Path(p).is_dir():
            return Path(p)
    return Path("/snap")
