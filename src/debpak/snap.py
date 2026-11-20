"""Snap input: a .snap file (a squashfs image) or an installed snap's folder
(/snap/NAME/current), turned into an ordinary app under /opt/NAME.

Snap's permission declarations (plugs, slots, interfaces) are ignored: the
Flatpak's permissions come from what the binaries use, as for every
other format. What a snap does need to run outside snapd is recreated:

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


def _launcher(snap_name: str, app: str, spec: dict, meta: dict) -> str:
    """Write the shell launcher for one app in snap.yaml.

    The launcher recreates what snapd would set up: $SNAP and the other SNAP_*
    variables (user data under $XDG_DATA_HOME/snap), library and program paths
    inside the snap, and the snap's environment. Then it runs the app's command
    through its command-chain, minus snapcraft's desktop-extension launchers.
    """
    env = dict(meta.get("environment") or {})
    env.update(spec.get("environment") or {})
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
        'for d in "$SNAP/usr/lib/$(uname -m)-linux-gnu" "$SNAP/lib/$(uname -m)-linux-gnu" "$SNAP/usr/lib" '
        '"$SNAP/lib"; do',
        '  [ -d "$d" ] && LD_LIBRARY_PATH="$d${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"',
        "done",
        'export LD_LIBRARY_PATH PATH="$SNAP/usr/bin:$SNAP/bin:$PATH"',
    ]
    for k, v in env.items():
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(k)):
            lines.append(f'export {k}="{str(v)}"')
    chain_cmds = " ".join(f'"$SNAP/{c}"' for c in chain)
    args = " ".join(shlex.quote(a) for a in argv[1:])
    lines.append(f'exec {chain_cmds + " " if chain_cmds else ""}"{prog}"{" " + args if args else ""} "$@"')
    return "\n".join(lines) + "\n"


def extract_snap(path: Path, dest: Path) -> Package:
    """Unpack a snap into opt/<name>, with one launcher per app.

    Daemons get no launcher, and the report says so. The snap's meta/gui
    entries are installed pointing at the launchers, with the snap's icon.

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
        raise PackageError(f"{name} is a {kind} snap with no apps (a base, runtime or content snap), "
                           "nothing to convert")

    root = dest / "root"
    opt = root / "opt" / name
    opt.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(tree), str(opt))

    launch = opt / LAUNCH_DIR
    launch.mkdir()
    for app, spec in apps.items():
        spec = spec if isinstance(spec, dict) else {}
        if spec.get("daemon"):
            continue                         # services aren't apps; reported below
        p = launch / str(app)
        p.write_text(_launcher(name, str(app), spec, meta))
        p.chmod(0o755)
    main_app = name if (launch / name).exists() else next((a for a in apps if (launch / str(a)).exists()), None)
    if main_app is None:
        raise PackageError(f"{name}: every app in snap.yaml is a daemon; nothing to launch")

    # menu entries: meta/gui (and snap/gui for older snaps), pointed at the launchers
    icon_name = name
    desktops = sorted((opt / "meta/gui").glob("*.desktop")) + sorted((opt / "snap/gui").glob("*.desktop"))
    apps_dir = root / "usr/share/applications"
    for d in desktops:
        text = d.read_text("utf-8", "replace")
        exec_line = _desktop_value(text, "Exec") or ""
        tok = (exec_line.split() or [""])[0].removeprefix("/snap/bin/").removeprefix("env BAMF_DESKTOP_FILE_HINT")
        app = tok.split(".", 1)[1] if tok.startswith(name + ".") else (name if tok == name else
                                                                       d.stem.split("_")[-1])
        target = launch / app if (launch / app).exists() else launch / main_app
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
    daemons = [str(a) for a, s in apps.items() if isinstance(s, dict) and s.get("daemon")]
    if daemons:
        pkg.notes.append(f"background services in the snap aren't converted: {', '.join(daemons)}")
    if any(str(c).startswith("snap/command-chain/") for s in apps.values() if isinstance(s, dict)
           for c in (s.get("command-chain") or [])):
        pkg.notes.append("snapcraft desktop-extension launchers skipped; the Flatpak runtime provides GTK/Qt")
    pkg.notes.append(f"snap contents are under /app/opt/{name}; launchers in /app/opt/{name}/{LAUNCH_DIR}")
    return pkg


def _guess_arch(opt: Path) -> str | None:
    """Return the architecture of the first ELF file in the snap, for snaps whose snap.yaml doesn't say."""
    from .packages import _elf_machine
    for p in opt.rglob("*"):
        if p.is_file() and not p.is_symlink() and (m := _elf_machine(p)):
            return m
    return None


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
                                 headers={"Snap-Device-Series": "16", "User-Agent": "debpak"})
    with (opener or urllib.request.urlopen)(req, timeout=30) as r:
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
    with (opener or urllib.request.urlopen)(info["url"], timeout=120) as r, open(out, "wb") as f:
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
