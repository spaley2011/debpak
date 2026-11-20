"""Snap input: a .snap file (a squashfs image) or an installed snap's folder
(/snap/NAME/current), turned into an ordinary app under /opt/NAME.

Snap's permission declarations (plugs, slots, interfaces) are ignored: the
Flatpak's permissions come from what the binaries actually use, as for every
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
    """Block mappings and sequences, flow [..]/{..}, quoted strings and |/> block
    scalars: enough for snap.yaml. Anchors, tags and multi-document files aren't."""
    raw = text.splitlines()
    lines: list[tuple[int, str, int]] = []      # (indent, content, raw index)
    for i, l in enumerate(raw):
        c = _strip_comment(l)
        if c.strip() and not c.strip().startswith("---"):
            lines.append((len(c) - len(c.lstrip(" ")), c.strip(), i))
    pos = 0

    def block_scalar(start_raw: int, parent_indent: int, style: str) -> str:
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

