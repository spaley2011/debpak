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
  replaces);
- the snap's menu entries (meta/gui/*.desktop) pointed at those launchers;
- the libraries the snap expected from its base snap are missing from the
  package, so `convert` fills them from the matching Ubuntu release
  (core22 -> jammy, ...), unless you name other library sources.
"""
from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

from .packages import Package, PackageError, _desktop_value, _place_icon, _set_desktop_exec
from . import net
from .runtime import EXTENSION_PROVIDED_PREFIXES

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
    """
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


def system_services(apps: dict, has_gui: bool, web_ui: bool = False, slots: dict | None = None) -> list[str]:
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
    dbus-daemon, running as root, to write the reset media.
    """
    out = []
    for a, s in apps.items():
        if not isinstance(s, dict) or not s.get("daemon") or str(s.get("daemon-scope") or "system") == "user":
            continue
        privileged = [p for p in _plug_names(s) if p in SYSTEM_PLUGS or p.endswith("-support")]
        on_system_bus = any(isinstance(sp := (slots or {}).get(slot), dict) and sp.get("interface") == "dbus"
                            and sp.get("bus") == "system" for slot in s.get("activates-on") or [])
        if privileged or on_system_bus or not has_gui or (web_ui and "network-bind" in _plug_names(s)):
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
# debpak put this in place of the snap's desktop-launch (snapcraft-desktop-helpers). Outside
# snapd the original linked GSettings schemas and copied mime data under $SNAP_USER_DATA, and
# pointed fonts, GTK, GDK pixbuf loaders, GL drivers and EGL vendors at copies the snap was
# expected to have from its base or a content snap; the Flatpak runtime has its own of all
# those. What stays is where the snap keeps its own data, typelibs, Qt and GStreamer plugins.
A="$(uname -m)-linux-gnu"
for d in "$SNAP/usr/share" "$SNAP/share" "$SNAP/data-dir"; do
  [ -d "$d" ] && XDG_DATA_DIRS="$d:${XDG_DATA_DIRS:-/app/share:/usr/share}"
done
export XDG_DATA_DIRS
[ -d "$SNAP/etc/xdg" ] && export XDG_CONFIG_DIRS="$SNAP/etc/xdg:${XDG_CONFIG_DIRS:-/etc/xdg}"
for d in "$SNAP/usr/lib/girepository-1.0" "$SNAP/usr/lib/$A/girepository-1.0"; do
  [ -d "$d" ] && export GI_TYPELIB_PATH="$d${GI_TYPELIB_PATH:+:$GI_TYPELIB_PATH}"
done
d="$SNAP/usr/lib/$A/gstreamer-1.0"
[ -d "$d" ] && export GST_PLUGIN_PATH="$d${GST_PLUGIN_PATH:+:$GST_PLUGIN_PATH}"
for q in qt4 qt5; do
  d="$SNAP/usr/lib/$A/$q/plugins"
  [ -d "$d" ] && export QT_PLUGIN_PATH="$d${QT_PLUGIN_PATH:+:$QT_PLUGIN_PATH}"
done
d="$SNAP/usr/lib/$A/qt5/qml"
[ -d "$d" ] && export QML2_IMPORT_PATH="$d${QML2_IMPORT_PATH:+:$QML2_IMPORT_PATH}"
d="$SNAP/usr/lib/$A/qt4"
[ -d "$d" ] && export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}$d"
exec "$@"
"""


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
    command = str(spec.get("command") or app)
    try:
        argv = shlex.split(command)
    except ValueError:
        argv = command.split()
    prog = argv[0] if argv else app
    if not prog.startswith(("$SNAP", "${SNAP}", "/")):
        prog = "$SNAP/" + prog
    chain = [c for c in (spec.get("command-chain") or []) if not str(c).startswith("snap/command-chain/")]
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
        '  [ -d "$d" ] && LD_LIBRARY_PATH="$d${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"',
        "done",
        'export LD_LIBRARY_PATH PATH="$SNAP/usr/bin:$SNAP/bin:$PATH"',
    ]
    for k, v in env.items():
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(k)):
            lines.append(f'export {k}="{str(v)}"')
    if "LD_LIBRARY_PATH" in env:
        # The snap sets its own library path (Multipass: $SNAP/lib:$SNAP/usr/lib/...),
        # which would drop the folders the Flatpak's launcher put there; the libraries
        # debpak added in place of the base snap's are found after the snap's own
        lines.append('export LD_LIBRARY_PATH="$LD_LIBRARY_PATH${DEBPAK_LIBRARY_PATH:+:$DEBPAK_LIBRARY_PATH}"')
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
    if names := {**mpris_names(meta), **own_bus_names(meta)}:
        pkg.extra["bus_names"] = names
    if access := bus_access(meta):
        pkg.extra["bus_access"] = access
    for plug, target in platform_snaps(meta).items():
        pkg.extra.setdefault("findings", []).append((
            "blocker", "snap.yaml",
            f"runs on the {target} snap (content plug {plug}), which a Flatpak can't reach"
            + ("; convert the Windows program itself instead, which runs on the Wine base app"
               if target.startswith("wine-platform") else "")))
    services = system_services(apps, bool(desktops) or any(isinstance(s, dict) and s.get("desktop")
                                                              for s in apps.values()),
                               web_ui=opens_local_web_page(opt, apps), slots=_slots(meta))
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
    if daemons:
        pkg.notes.append(f"background services in the snap aren't converted: {', '.join(daemons)}")
    if any(str(c).startswith("snap/command-chain/") for s in apps.values() if isinstance(s, dict)
           for c in (s.get("command-chain") or [])):
        pkg.notes.append("snapcraft desktop-extension launchers skipped; the Flatpak runtime provides GTK/Qt")
    if helpers:
        pkg.notes.append(f"put debpak's own desktop-launch in place of the snap's ({', '.join(helpers)}): the "
                         "original sets up GSettings, mime, fonts and GL from the snap's base, which the runtime replaces")
    pkg.notes.append(f"snap contents are under /app/opt/{name}; launchers in /app/opt/{name}/{LAUNCH_DIR}")
    return pkg


# bases built on an Ubuntu release older than any runtime debpak builds on (Freedesktop 25.08 and later)
OLDER_THAN_RUNTIMES = ("core", "core18", "core20", "core22", "core24")
# Qt's platform and style plugins use its private API, which changes with every minor version: a
# snap's own Qt stays, with the plugins it was built with (see analyze.kde_runtime_for_qt for the rest)
KEEP_OWN = re.compile(r"^lib(Qt\d|KF\d)")


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
    Qt and KDE Frameworks stay (KEEP_OWN).

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
    out = {}
    for rel, sonames in names.items():
        info = elfs.get(rel)
        if info is None:
            continue
        so = info.soname or Path(rel).name
        graphics = so.startswith(EXTENSION_PROVIDED_PREFIXES) and runtime.provides(so)
        if os.path.dirname(rel) not in (gl_dirs if graphics else dirs):
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


def bus_access(meta: dict) -> dict[str, str]:
    """Return {finish-arg: why} for the D-Bus services the snap's apps plug, on the system or session bus.

    Those are the host services in SYSTEM_BUS_PLUGS and the names of dbus
    plugs. Only the apps that run in the Flatpak count: the snap's system
    services don't.
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
            elif iface == "dbus" and re.fullmatch(r"[\w.-]+", str(attrs.get("name") or "")):
                bus = "system-talk-name" if attrs.get("bus") == "system" else "talk-name"
                out.setdefault(f"--{bus}={attrs['name']}", f"dbus plug {plug} in snap.yaml")
    return out


def mpris_names(meta: dict) -> dict[str, str]:
    """Return the MPRIS bus names the snap's mpris slots declare, with where each was found.

    snapd lets the app own org.mpris.MediaPlayer2.NAME (NAME is the slot's name
    attribute, else the snap's name). Spotify takes it at start and quits
    quietly when it can't, as if another Spotify were running.
    """
    out = {}
    slots = meta.get("slots") or {}
    for slot, spec in (slots.items() if isinstance(slots, dict) else []):
        spec = spec if isinstance(spec, dict) else {}
        if str(spec.get("interface") or slot) == "mpris":
            name = str(spec.get("name") or meta.get("name") or "")
            if re.fullmatch(r"[A-Za-z0-9_-]+", name):
                out.setdefault(f"org.mpris.MediaPlayer2.{name}", f"mpris slot {slot} in snap.yaml")
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
    return out


def add_base_python(opt: Path, versions: list[str], fetch) -> list[str]:
    """Copy each Python's standard library and interpreter from the base's Ubuntu packages into the snap.

    fetch(package name) returns the unpacked Ubuntu package (a DebPackage) or
    None. What the base snap had at /usr/lib/python3.X and /usr/bin/python3.X
    goes under the snap's usr, and usr/bin/python3 points at it when the snap
    has none: that is the python3 the snap's programs found on PATH.

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
        if (opt / f"usr/bin/python{v}").exists() and not os.path.lexists(opt / "usr/bin/python3"):
            (opt / "usr/bin/python3").symlink_to(f"python{v}")
    return used


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
