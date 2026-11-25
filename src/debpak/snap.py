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
        return _unquote(v)
    if v.startswith("[") and v.endswith("]"):
        return [_scalar(x) for x in _split_flow(v[1:-1])]
    if v.startswith("{") and v.endswith("}"):
        return _flow_mapping(v[1:-1])
    return v


def _unquote(v: str) -> str:
    """Decode a quoted YAML scalar: '' in single quotes, backslash escapes in double quotes."""
    inner = v[1:-1]
    if v[0] == "'":
        return inner.replace("''", "'")
    return re.sub(r'\\(u[0-9a-fA-F]{4}|["\\/nt])', _unescape, inner)


def _unescape(m: re.Match) -> str:
    """Return the character a double-quoted string's backslash escape stands for."""
    esc = m.group(1)
    if esc[0] == "u":
        return chr(int(esc[1:], 16))
    return {"n": "\n", "t": "\t"}.get(esc, esc)


def _flow_mapping(inside: str) -> dict:
    """Decode the inside of a flow mapping {k: v, ...}."""
    out = {}
    for item in _split_flow(inside):
        k, _, val = item.partition(":")
        out[_scalar(k)] = _scalar(val)
    return out


_FLOW_DEPTH = {"[": 1, "{": 1, "]": -1, "}": -1}


def _quote_after(ch: str, quote: str | None) -> str | None:
    """Return the open quote character after ch, given the one open before it (or None)."""
    if quote:
        return None if ch == quote else quote
    return ch if ch in "'\"" else None


def _flow_char(ch: str, quote: str | None, depth: int) -> tuple[str | None, int]:
    """Return the open quote and the nesting depth after ch in a flow collection."""
    if quote or ch in "'\"":
        return _quote_after(ch, quote), depth
    return None, depth + _FLOW_DEPTH.get(ch, 0)


def _split_flow(s: str) -> list[str]:
    """Split the inside of a flow collection at top-level commas, respecting quotes and nesting."""
    parts: list[str] = []
    depth, cur, quote = 0, "", None
    for ch in s:
        if not quote and ch == "," and depth == 0:
            parts.append(cur.strip())
            cur = ""
            continue
        cur += ch
        quote, depth = _flow_char(ch, quote, depth)
    if cur.strip():
        parts.append(cur.strip())
    return parts


def _strip_comment(line: str) -> str:
    """Remove a trailing # comment from a YAML line, unless the # is inside quotes."""
    quote = None
    for i, ch in enumerate(line):
        if not quote and ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip()
        quote = _quote_after(ch, quote)
    return line.rstrip()


def _closed_quote(val: str) -> bool:
    """Return whether a quoted YAML scalar ends where val does."""
    if val.startswith("'"):
        return bool(re.fullmatch(r"'(?:[^']|'')*'", val))
    return bool(re.fullmatch(r'"(?:[^"\\]|\\.)*"', val))


def _fold(body: list[str]) -> str:
    """Join a > block scalar's lines: lines within a paragraph with spaces, paragraphs with newlines."""
    paras, cur_p = [], []
    for b in body:
        if b:
            cur_p.append(b.strip())
        else:
            paras.append(" ".join(cur_p))
            cur_p = []
    paras.append(" ".join(cur_p))
    return "\n".join(paras) + "\n"


_KEY = re.compile(r"^(?P<k>'[^']*'|\"[^\"]*\"|[^:]+?)\s*:(?:\s+(?P<v>.*))?$")
_ITEM_MAPPING = re.compile(r"^[^'\"\[{][^:]*:(\s|$)")


class _YamlParser:
    """A cursor over snap.yaml's lines that reads its mappings, sequences and block scalars."""

    def __init__(self, text: str):
        self.raw = text.splitlines()
        self.lines: list[tuple[int, str, int]] = []      # (indent, content, raw index)
        for i, rl in enumerate(self.raw):
            c = _strip_comment(rl)
            if c.strip() and not c.strip().startswith("---"):
                self.lines.append((len(c) - len(c.lstrip(" ")), c.strip(), i))
        self.pos = 0

    def _more(self) -> bool:
        """Return whether lines are left."""
        return self.pos < len(self.lines)

    def _at_item(self, indent: int) -> bool:
        """Return whether the current line is a sequence item ("- ...") at indent."""
        ind, content, _ = self.lines[self.pos]
        return ind == indent and (content.startswith("- ") or content == "-")

    def parse(self, indent: int):
        """Parse the mapping or sequence at indent and return it."""
        if not self._more():
            return None
        content = self.lines[self.pos][1]
        if content.startswith("- ") or content == "-":
            return self._sequence(indent)
        return self._mapping(indent)

    def _sequence(self, indent: int) -> list:
        """Parse the block sequence at indent."""
        seq = []
        while self._more() and self._at_item(indent):
            seq.append(self._item(indent))
        return seq

    def _item(self, indent: int):
        """Parse one "- ..." item of the sequence at indent."""
        ind, content, ri = self.lines[self.pos]
        item = content[1:].strip()
        if not item:
            self.pos += 1
            return self.parse(self.lines[self.pos][0]) if self._more() and self.lines[self.pos][0] > indent else None
        if _ITEM_MAPPING.match(item):
            # "- key: value" starts a mapping at the item's indentation
            sub_indent = ind + 2
            self.lines[self.pos] = (sub_indent, item, ri)
            return self.parse(sub_indent)
        self.pos += 1
        return _scalar(item)

    def _mapping(self, indent: int) -> dict:
        """Parse the block mapping at indent."""
        mapping: dict = {}
        while self._more() and self.lines[self.pos][0] == indent:
            ind, content, ri = self.lines[self.pos]
            m = _KEY.match(content)
            self.pos += 1
            if not m:
                continue
            key = _scalar(m.group("k"))
            val = self._continued((m.group("v") or "").strip(), ind)
            mapping[key] = self._value(val, ind, ri)
        return mapping

    def _continued(self, val: str, ind: int) -> str:
        """Return val with the lines it goes on over appended, reading past them."""
        # a quoted or plain scalar can go on over more indented lines (cool-retro-term's
        # description); read to its end, or the rest of the mapping is lost
        quoted = val[:1] in ("'", '"') and not _closed_quote(val)
        while val and self._more() and (quoted or (self.lines[self.pos][0] > ind and val[0] not in "|>[{")):
            val += " " + self.lines[self.pos][1]
            self.pos += 1
            quoted = quoted and not _closed_quote(val)
        return val

    def _value(self, val: str, ind: int, ri: int):
        """Return the value of the key at indent ind on raw line ri, whose text after the colon is val."""
        if val and val[0] in "|>":
            return self._block_scalar(ri, ind, val)
        if val:
            return _scalar(val)
        if self._more() and self.lines[self.pos][0] > ind:
            return self.parse(self.lines[self.pos][0])
        if self._more() and self.lines[self.pos][0] == ind and self.lines[self.pos][1].startswith("-"):
            return self.parse(ind)          # sequence at the key's own indentation
        return None

    def _block_lines(self, start_raw: int, parent_indent: int) -> tuple[list[str], int]:
        """Return a block scalar's lines after raw line start_raw, and the raw index where it ends."""
        body = []
        j = start_raw + 1
        ind = None
        while j < len(self.raw):
            line = self.raw[j]
            j += 1
            if not line.strip():
                body.append("")
                continue
            cur = len(line) - len(line.lstrip(" "))
            if cur <= parent_indent:
                return body, j - 1
            if ind is None:
                ind = cur
            body.append(line[ind:])
        return body, j

    def _block_scalar(self, start_raw: int, parent_indent: int, style: str) -> str:
        """Read a | or > block scalar that starts after line start_raw; return its text."""
        body, end = self._block_lines(start_raw, parent_indent)
        while self._more() and self.lines[self.pos][2] < end:
            self.pos += 1
        while body and not body[-1]:
            body.pop()
        if style.startswith(">"):
            return _fold(body)
        return "\n".join(body) + "\n"


def parse_yaml(text: str):
    """Parse the subset of YAML that snap.yaml uses.

    Handles block mappings and sequences, flow [..] and {..}, quoted strings and
    | / > block scalars. Anchors, tags and multi-document files aren't supported.
    Plain scalars stay strings: snap.yaml has no values that need typing.
    """
    parser = _YamlParser(text)
    result = parser.parse(parser.lines[0][0]) if parser.lines else {}
    return result if result is not None else {}


# --------------------------------------------------------------------------- extraction

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
    plugs = meta["plugs"] if isinstance(meta.get("plugs"), dict) else {}
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
        if _needed_service(s, has_gui, web_ui, slots or {}):
            out.append(str(a))
    return out


def _needed_service(s: dict, has_gui: bool, web_ui: bool, slots: dict) -> bool:
    """Return whether the system service s is one the snap can't do without (see system_services)."""
    privileged = [p for p in _plug_names(s) if p in SYSTEM_PLUGS or p.endswith("-support")]
    on_system_bus = any(_system_bus_slot(slots.get(slot)) for slot in s.get("activates-on") or [])
    return bool(privileged or on_system_bus or not has_gui or (web_ui and "network-bind" in _plug_names(s)))


def _system_bus_slot(sp) -> bool:
    """Return whether a slot's spec is a dbus slot on the system bus."""
    return isinstance(sp, dict) and sp.get("interface") == "dbus" and sp.get("bus") == "system"


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
        cmd = _command_file(opt, s)
        if (module := _package_manager_import(cmd)):
            return f"{cmd.relative_to(opt)} imports {module}"
    return ""


def _command_file(opt: Path, spec: dict) -> Path:
    """Return the file an app's command runs (its first word, inside the snap)."""
    return opt / str(spec.get("command") or "").split(" ", 1)[0]


def _package_manager_import(cmd: Path) -> str:
    """Return the package manager's module that cmd, a Python program under 1 MiB, imports, or ""."""
    try:
        head = cmd.read_bytes()[:1 << 20] if cmd.is_file() and cmd.stat().st_size < (1 << 20) else b""
    except OSError:
        return ""
    if head.startswith(b"#!") and b"python" in head.split(b"\n", 1)[0] and \
            (m := PACKAGE_MANAGER_IMPORT.search(head)):
        return m.group(1).decode()
    return ""


def opens_local_web_page(opt: Path, apps: dict) -> bool:
    """Return True if an app that isn't a daemon is a small script that opens a page on this computer."""
    for s in apps.values():
        if not isinstance(s, dict) or s.get("daemon"):
            continue
        if _opens_localhost(_command_file(opt, s)):
            return True
    return False


def _opens_localhost(cmd: Path) -> bool:
    """Return whether cmd is a script under 4 KiB that names a page on this computer."""
    try:
        return bool(cmd.is_file() and cmd.stat().st_size < 4096 and
                    re.search(rb"https?://(localhost|127\.0\.0\.1)\b", cmd.read_bytes()))
    except OSError:
        return False


def _expanding(arg: str) -> str:
    """Quote arg for sh so that its $VARIABLES expand and nothing else does."""
    if "$" not in arg:
        return shlex.quote(arg)
    return '"' + re.sub(r'(["\\`])', r"\\\1", arg) + '"'


def _launcher(snap_name: str, app: str, spec: dict, meta: dict, services: dict[str, str] | None = None) -> str:
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
    argv, prog = _command_argv(spec, app)
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
    lines += _env_exports(env)
    lines += _service_starts(services or {})
    lines.append(_exec_line(chain, prog, argv[1:]))
    return "\n".join(lines) + "\n"


def _command_argv(spec: dict, app: str) -> tuple[list[str], str]:
    """Return an app's command split into words, and the program it runs (under $SNAP unless absolute)."""
    command = str(spec.get("command") or app)
    try:
        argv = shlex.split(command)
    except ValueError:
        argv = command.split()
    prog = argv[0] if argv else app
    if not prog.startswith(("$SNAP", "${SNAP}", "/")):
        prog = "$SNAP/" + prog
    return argv, prog


def _env_exports(env: dict) -> list[str]:
    """Return the launcher lines that export the snap's environment."""
    lines = [f'export {k}="{v!s}"' for k, v in env.items() if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(k))]
    if "LD_LIBRARY_PATH" in env:
        # The snap sets its own library path (Multipass: $SNAP/lib:$SNAP/usr/lib/...),
        # which would drop the folders the Flatpak's launcher put there; the libraries
        # debpak added in place of the base snap's are found after the snap's own
        lines.append('export LD_LIBRARY_PATH="$LD_LIBRARY_PATH${DEBPAK_LIBRARY_PATH:+:$DEBPAK_LIBRARY_PATH}"')
    return lines


def _service_starts(services: dict[str, str]) -> list[str]:
    """Return the launcher lines that start each user service ({bus name: app}) whose name has no owner yet."""
    lines: list[str] = []
    for bus_name, service in sorted(services.items()):
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
    return lines


def _exec_line(chain: list, prog: str, argv: list[str]) -> str:
    """Return the launcher's last line: exec the command-chain, then the program with its arguments."""
    chain_cmds = " ".join(f'"$SNAP/{c}"' for c in chain)
    # snapd expands $SNAP and the like in a command's arguments (Pick's command is
    # "bin/desktop-launch $SNAP/bin/pick-colour-picker"), so they go in double quotes
    args = " ".join(_expanding(a) for a in argv)
    return f'exec {chain_cmds + " " if chain_cmds else ""}"{prog}"{" " + args if args else ""} "$@"'


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
    meta, tree = _read_snap(path, dest)
    name = str(meta["name"])
    apps = meta["apps"]
    root = dest / "root"
    opt = root / "opt" / name
    opt.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(tree), str(opt))

    session = session_services(meta)
    main_app = _write_launchers(opt, name, apps, meta, session)
    menu_apps, has_desktops = _install_menu_entries(opt, root, name, main_app)
    if menu_apps and main_app not in menu_apps:
        # the Flatpak's command and its menu entry run the same program: the graphical
        # app (Multipass's gui), not a command-line app that happens to share the snap's name
        main_app = menu_apps[0]

    base = str(meta.get("base") or "core")
    pkg = Package("snap", path, root, name, str(meta.get("version", "0")), _snap_arch(meta, opt),
                  str(meta.get("summary") or meta.get("title") or ""), str(meta.get("description") or ""),
                  str(meta.get("website") or ""), str(meta.get("license") or ""),
                  default_exec=f"/opt/{name}/{LAUNCH_DIR}/{main_app}",
                  extra={"opt_name": name, "base": base, "ubuntu_suite": BASE_TO_UBUNTU.get(base),
                         "confinement": meta.get("confinement", "strict"), "apps": sorted(map(str, apps))})
    if names := {**mpris_names(meta), **own_bus_names(meta)}:
        pkg.extra["bus_names"] = names
    if access := bus_access(meta):
        pkg.extra["bus_access"] = access
    services = _snap_blockers(pkg, meta, opt, has_desktops)
    _snap_notes(pkg, apps, set(services) | set(session.values()))
    return pkg


def _snap_notes(pkg: Package, apps: dict, kept: set[str]) -> None:
    """Note the daemons left out and the desktop-extension launchers skipped. kept: services that aren't left out."""
    daemons = [str(a) for a, s in apps.items() if isinstance(s, dict) and s.get("daemon") and str(a) not in kept]
    if daemons:
        pkg.notes.append(f"background services in the snap aren't converted: {', '.join(daemons)}")
    if any(str(c).startswith("snap/command-chain/") for s in apps.values() if isinstance(s, dict)
           for c in (s.get("command-chain") or [])):
        pkg.notes.append("snapcraft desktop-extension launchers skipped; the Flatpak runtime provides GTK/Qt")
    name = pkg.extra["opt_name"]
    pkg.notes.append(f"snap contents are under /app/opt/{name}; launchers in /app/opt/{name}/{LAUNCH_DIR}")


def _read_snap(path: Path, dest: Path) -> tuple[dict, Path]:
    """Unpack the snap into dest/snap and return its snap.yaml and that folder.

    Raises:
        PackageError: Not a snap, or a base, runtime or content snap with no apps.
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
    kind = str(meta.get("type") or "app")
    if kind != "app" or not meta.get("apps"):
        raise PackageError(f"{meta['name']} is a {kind} snap with no apps (a base, runtime or content snap), "
                           "nothing to convert")
    return meta, tree


def _write_launchers(opt: Path, name: str, apps: dict, meta: dict, session: dict) -> str:
    """Write a launcher for each app that isn't a system daemon; return the main app.

    Raises:
        PackageError: Every app is a daemon.
    """
    launch = opt / LAUNCH_DIR
    launch.mkdir()
    for app, spec in apps.items():
        spec = spec if isinstance(spec, dict) else {}
        if spec.get("daemon") and str(app) not in session.values():
            continue                         # services aren't apps; reported below
        p = launch / str(app)
        p.write_text(_launcher(name, str(app), spec, meta, None if spec.get("daemon") else session))
        p.chmod(0o755)
    return _main_app(launch, name, apps)


def _main_app(launch: Path, name: str, apps: dict) -> str:
    """Return the app the Flatpak runs: the one named after the snap, else the first launcher that isn't a daemon.

    Raises:
        PackageError: Every app is a daemon.
    """
    if (launch / name).exists():
        return name
    main_app = next((a for a, sp in apps.items()
                     if (launch / str(a)).exists() and not (isinstance(sp, dict) and sp.get("daemon"))), None)
    if main_app is None:
        raise PackageError(f"{name}: every app in snap.yaml is a daemon; nothing to launch")
    return main_app


def _install_menu_entries(opt: Path, root: Path, name: str, main_app: str) -> tuple[list[str], bool]:
    """Install meta/gui's (and older snaps' snap/gui's) menu entries, pointed at the launchers, with their icons.

    Returns the launchers the entries run, and whether there were any entries.
    """
    desktops = sorted((opt / "meta/gui").glob("*.desktop")) + sorted((opt / "snap/gui").glob("*.desktop"))
    menu_apps = []
    for d in desktops:
        menu_apps.append(_install_menu_entry(d, opt, root, name, main_app))
    if not desktops:
        _place_gui_icon(opt, root, name)
    return menu_apps, bool(desktops)


def _install_menu_entry(d: Path, opt: Path, root: Path, name: str, main_app: str) -> str:
    """Install one menu entry, pointed at its app's launcher (else main_app's), with its icon; return the launcher."""
    launch = opt / LAUNCH_DIR
    text = d.read_text("utf-8", "replace")
    app = _menu_entry_app(text, name, d)
    target = launch / app if (launch / app).exists() else launch / main_app
    text = _set_desktop_exec(text, f"/opt/{name}/{LAUNCH_DIR}/{target.name}")
    icon_file = _snap_icon_file(opt, _desktop_value(text, "Icon") or "")
    if icon_file and icon_file.is_file():
        _place_icon(icon_file, root, name)
        text = re.sub(r"(?m)^Icon=.*$", f"Icon={name}", text)
    apps_dir = root / "usr/share/applications"
    apps_dir.mkdir(parents=True, exist_ok=True)
    (apps_dir / f"{name}_{app}.desktop").write_text(text)
    return target.name


def _menu_entry_app(text: str, name: str, d: Path) -> str:
    """Return the app a menu entry runs: from its Exec (NAME.APP or NAME), else from its file name."""
    exec_line = _desktop_value(text, "Exec") or ""
    tok = (exec_line.split() or [""])[0].removeprefix("/snap/bin/").removeprefix("env BAMF_DESKTOP_FILE_HINT")
    if tok.startswith(name + "."):
        return tok.split(".", 1)[1]
    if tok == name:
        return name
    return d.stem.split("_")[-1]


def _place_gui_icon(opt: Path, root: Path, name: str) -> None:
    """Install the snap's meta/gui icon, for a snap without menu entries."""
    for cand in (opt / "meta/gui/icon.png", opt / "meta/gui/icon.svg"):
        if cand.is_file():
            _place_icon(cand, root, name)
            return


def _snap_icon_file(opt: Path, icon: str) -> Path | None:
    """Return the file a snap menu entry's Icon= names, or None."""
    if icon.startswith(("${SNAP}", "$SNAP", "/snap/")):
        return opt / re.sub(r"^(\$\{SNAP\}|\$SNAP|/snap/[^/]+/(current|\d+))/?", "", icon)
    if icon and not icon.startswith("/"):
        for cand in (opt / "meta/gui" / f"{icon}.png", opt / "meta/gui" / f"{icon}.svg",
                     opt / "meta/gui/icon.png", opt / "meta/gui/icon.svg"):
            if cand.is_file():
                return cand
    return None


def _snap_arch(meta: dict, opt: Path) -> str:
    arch_list = meta.get("architectures") or []
    arch = next((SNAP_ARCH[a] for a in arch_list if isinstance(a, str) and a in SNAP_ARCH), "")
    return arch or _guess_arch(opt) or ""


def _snap_blockers(pkg: Package, meta: dict, opt: Path, has_desktops: bool) -> list[str]:
    """Add findings for what a Flatpak can't do: platform snaps, system services, managing software.

    Returns the system services the snap's apps rely on.
    """
    apps = meta["apps"]
    findings = pkg.extra.setdefault("findings", [])
    for plug, provider in platform_snaps(meta).items():
        findings.append((
            "blocker", "snap.yaml",
            f"runs on the {provider} snap (content plug {plug}), which a Flatpak can't reach"
            + ("; convert the Windows program itself instead, which runs on the Wine base app"
               if provider.startswith("wine-platform") else "")))
    services = system_services(apps, has_desktops or any(isinstance(s, dict) and s.get("desktop")
                                                         for s in apps.values()),
                               web_ui=opens_local_web_page(opt, apps), slots=_slots(meta))
    if services:
        # Multipass's CLI and GUI only drive multipassd, which runs the VMs as root:
        # its menu entry would open a client with nothing to connect to
        findings.append((
            "blocker", "snap.yaml",
            f"runs a system service ({', '.join(services)}) that the snap's apps rely on; "
            "Flatpaks cannot run system services"))
    if (why := manages_software(opt, apps)):
        findings.append((
            "blocker", "snap.yaml",
            f"installs and removes the system's software ({why}); the package manager it drives "
            "(snapd, apt, PackageKit) can't be reached from a Flatpak"))
    if not findings:
        del pkg.extra["findings"]
    return services


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
    newer one. glibc's own libraries are always the runtime's. Qt and KDE
    Frameworks stay (KEEP_OWN).

    Returns:
        {path of the snap's library: the names it goes by in the package}.
    """
    from .analyze import is_never_bundle
    dirs = {f"{opt}/{d}" for d in ("lib", "usr/lib", f"lib/{triplet}", f"usr/lib/{triplet}")}
    asked = _asked_versions(elfs)
    names: dict[str, list[str]] = {}
    for so, rel in package_sonames.items():
        names.setdefault(rel, []).append(so)
    out = {}
    for rel, sonames in names.items():
        info = elfs.get(rel)
        if os.path.dirname(rel) not in dirs or info is None:
            continue
        if _runtime_replaces(rel, info, base, asked, runtime, is_never_bundle):
            out[rel] = sorted(sonames)
    return out


def _asked_versions(elfs: dict) -> dict[str, set[str]]:
    """Return {library: the symbol versions the snap's programs ask it for}."""
    asked: dict[str, set[str]] = {}
    for info in elfs.values():
        for lib, vs in info.verneed.items():
            asked.setdefault(lib, set()).update(vs)
    return asked


def _runtime_replaces(rel: str, info, base: str, asked: dict[str, set[str]], runtime, is_never_bundle) -> bool:
    """Return whether the runtime's copy of the snap's library rel replaces it (see runtime_copies)."""
    so = info.soname or Path(rel).name
    # glibc's libc.so.6 is a program too (it has a loader), so only that test isn't enough
    # (a loader stays: a program may name the snap's own as its interpreter)
    if not (info.is_shared_library or is_never_bundle(so)) or so.startswith(("ld-linux", "ld64.so")) \
            or KEEP_OWN.match(so) or not runtime.provides(so):
        return False
    if is_never_bundle(so):
        return True
    have = runtime.versions_of(so) or set()
    defined = set(info.verdef) - {so}
    if not defined and base not in OLDER_THAN_RUNTIMES:
        return False
    return (defined | asked.get(so, set())) <= have


def _slots(meta: dict) -> dict:
    slots = meta.get("slots")
    return slots if isinstance(slots, dict) else {}


def _interface(meta: dict, plug: str) -> tuple[str, dict]:
    """Return a plug's interface and its attributes; a plug named after its interface needs no entry."""
    plugs = meta["plugs"] if isinstance(meta.get("plugs"), dict) else {}
    spec = plugs[plug] if isinstance(plugs.get(plug), dict) else {}
    return str(spec.get("interface") or plug), spec


def session_services(meta: dict) -> dict[str, str]:
    """Return {bus name: app} for the snap's user services that the session bus starts on demand.

    Such an app is a daemon with daemon-scope user, daemon: dbus and
    activates-on a dbus slot on the session bus: Firmware Updater's
    firmware-updater-app is its window, and the app in its menu only asks
    D-Bus for com.canonical.firmware_updater. A Flatpak can't export a
    D-Bus service under another name than its own, so the launchers start it.
    """
    out: dict[str, str] = {}
    apps = meta["apps"] if isinstance(meta.get("apps"), dict) else {}
    for app, spec in apps.items():
        if not isinstance(spec, dict) or spec.get("daemon") != "dbus" or spec.get("daemon-scope") != "user":
            continue
        for name in _activating_names(meta, spec):
            out[name] = str(app)
    return out


def _activating_names(meta: dict, spec: dict) -> list[str]:
    """Return the session-bus names of the dbus slots an app is activated on."""
    names = []
    for slot in spec.get("activates-on") or []:
        sspec = _slots(meta).get(slot)
        if isinstance(sspec, dict) and sspec.get("interface") == "dbus" and \
                str(sspec.get("bus") or "session") == "session" and sspec.get("name"):
            names.append(str(sspec["name"]))
    return names


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
    out: dict[str, str] = {}
    apps = meta["apps"] if isinstance(meta.get("apps"), dict) else {}
    for spec in apps.values():
        for plug in _flatpak_app_plugs(spec):
            if (arg := _bus_access_arg(meta, plug)):
                out.setdefault(*arg)
    return out


def _flatpak_app_plugs(spec) -> list[str]:
    """Return an app's plugs if it runs in the Flatpak (it isn't a system service), else none."""
    if not isinstance(spec, dict) or (spec.get("daemon") and spec.get("daemon-scope") != "user"):
        return []
    return _plug_names(spec)


def _bus_access_arg(meta: dict, plug: str) -> tuple[str, str] | None:
    """Return (finish-arg, why) for a plug that talks to a D-Bus service, or None."""
    iface, attrs = _interface(meta, plug)
    if iface in SYSTEM_BUS_PLUGS:
        return f"--system-talk-name={SYSTEM_BUS_PLUGS[iface]}", f"{plug} plug in snap.yaml"
    if iface == "dbus" and re.fullmatch(r"[\w.-]+", str(attrs.get("name") or "")):
        bus = "system-talk-name" if attrs.get("bus") == "system" else "talk-name"
        return f"--{bus}={attrs['name']}", f"dbus plug {plug} in snap.yaml"
    return None


def mpris_names(meta: dict) -> dict[str, str]:
    """Return the MPRIS bus names the snap's mpris slots declare, with where each was found.

    snapd lets the app own org.mpris.MediaPlayer2.NAME (NAME is the slot's name
    attribute, else the snap's name). Spotify takes it at start and quits
    quietly when it can't, as if another Spotify were running.
    """
    out: dict[str, str] = {}
    slots = meta.get("slots") or {}
    for slot, spec in (slots.items() if isinstance(slots, dict) else []):
        if (name := _mpris_name(meta, slot, spec)):
            out.setdefault(f"org.mpris.MediaPlayer2.{name}", f"mpris slot {slot} in snap.yaml")
    return out


def _mpris_name(meta: dict, slot, spec) -> str:
    """Return the NAME in org.mpris.MediaPlayer2.NAME for an mpris slot, or "" for any other slot."""
    spec = spec if isinstance(spec, dict) else {}
    if str(spec.get("interface") or slot) != "mpris":
        return ""
    name = str(spec.get("name") or meta.get("name") or "")
    return name if re.fullmatch(r"[A-Za-z0-9_-]+", name) else ""


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
    used: list[str] = []
    for v in versions:
        used += _add_python(opt, v, fetch)
    return used


def _add_python(opt: Path, v: str, fetch) -> list[str]:
    """Copy Python v's standard library and interpreter into the snap; return the packages copied in."""
    used = []
    for name in (f"libpython{v}-minimal", f"libpython{v}-stdlib", f"python{v}-minimal"):
        deb = fetch(name)
        if deb is None:
            continue
        used.append(f"{deb.name} ({deb.version})")
        for sub in (f"usr/lib/python{v}", f"usr/bin/python{v}"):
            _copy_from_deb(deb.root / sub, opt / sub)
    if (opt / f"usr/bin/python{v}").exists() and not os.path.lexists(opt / "usr/bin/python3"):
        (opt / "usr/bin/python3").symlink_to(f"python{v}")
    return used


def _copy_from_deb(src: Path, dst: Path) -> None:
    """Copy a folder or file from an unpacked package into the snap, if the package has it."""
    if src.is_dir():
        shutil.copytree(src, dst, symlinks=True, dirs_exist_ok=True)
    elif src.is_file():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


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
