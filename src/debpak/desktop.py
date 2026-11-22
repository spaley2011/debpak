"""Desktop integration: .desktop rewrite, icon export, MIME, AppStream."""
from __future__ import annotations

import datetime
import re
import shutil
import struct
from pathlib import Path
from xml.sax.saxutils import escape

from .analyze import desktop_entry_value, parse_exec
from .deb import DebPackage, resolve_in_root

_NEEDS_QUOTE = re.compile(r'[\s"\'\\><~|&;$*?#()`]')


def _quote_arg(arg: str) -> str:
    """Quote one Exec= argument per the Desktop Entry spec; field codes like %U stay bare."""
    if arg.startswith("%") and len(arg) == 2:
        return arg  # field code
    if not _NEEDS_QUOTE.search(arg):
        return arg
    return '"' + re.sub(r'(["`$\\])', r"\\\1", arg) + '"'


def rewrite_desktop(text: str, app_id: str, command: str) -> str:
    """Point a .desktop file at the Flatpak.

    Every Exec= line (the main entry and each [Desktop Action]) runs command with
    the original arguments, minus any program and env prefix. TryExec= is dropped,
    because the program it names doesn't exist outside the sandbox, and the main
    Icon= becomes the app ID, which is the name the icons are exported under.
    """
    out = []
    group = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            group = s
            out.append(line)
            continue
        key = s.split("=", 1)[0].strip() if "=" in s else None
        if key == "Exec":
            _env, _prog, args = parse_exec(s.split("=", 1)[1])
            out.append("Exec=" + " ".join([command] + [_quote_arg(a) for a in args]))
        elif key == "TryExec":
            continue
        elif key == "Icon" and group == "[Desktop Entry]":
            out.append(f"Icon={app_id}")
        else:
            out.append(line)
    return "\n".join(out) + "\n"


def png_size(path: Path) -> tuple[int, int] | None:
    """Return a PNG's (width, height) from its header, or None if it isn't a PNG."""
    with open(path, "rb") as f:
        head = f.read(24)
    if head[:8] != b"\x89PNG\r\n\x1a\n" or head[12:16] != b"IHDR":
        return None
    return struct.unpack(">II", head[16:24])


def _icon_candidates(root: Path, icon: str) -> list[tuple[Path, str]]:
    """Find icon files for Icon= in the package as (file, size folder) pairs; the size folder is '256x256', 'scalable' or '' when unknown."""
    found: list[tuple[Path, str]] = []
    if "/" in icon:
        p = resolve_in_root(root, icon)
        if p and p.is_file():
            found.append((p, ""))
        return found
    hicolor = root / "usr/share/icons/hicolor"
    if hicolor.is_dir():
        for size_dir in sorted(hicolor.iterdir()):
            for ext in ("png", "svg", "svgz"):
                p = resolve_in_root(root, f"usr/share/icons/hicolor/{size_dir.name}/apps/{icon}.{ext}")
                if p and p.is_file():
                    found.append((p, size_dir.name))
    if not found:
        for ext in ("png", "svg", "xpm"):
            p = resolve_in_root(root, f"usr/share/pixmaps/{icon}.{ext}")
            if p and p.is_file():
                found.append((p, ""))
    return found


def install_icons(root: Path, icon: str | None, share: Path, app_id: str) -> tuple[list[str], list[str]]:
    """Export the app's icons under its app ID, as Flatpak requires.

    Each icon goes to share/icons/hicolor/<size>/apps/<app_id>.<ext>. A PNG
    outside a size folder is sized from its header, and skipped if it isn't
    square or is larger than 512px. XPM icons are skipped. Each skip adds a
    warning.

    Returns:
        (installed paths relative to share's parent, warnings).
    """
    installed, warnings = [], []
    if not icon:
        return installed, ["desktop file has no Icon= entry"]
    for src, size_dir in _icon_candidates(root, icon):
        ext = src.suffix.lstrip(".").lower()
        if ext == "xpm":
            warnings.append(f"skipped XPM icon {src.name} (convert it to PNG)")
            continue
        if ext in ("svg", "svgz"):
            size_dir = "scalable"
        elif not size_dir:
            dims = png_size(src)
            if not dims:
                warnings.append(f"skipped unreadable icon {src.name}")
                continue
            w, h = dims
            if w != h or w > 512:
                warnings.append(f"skipped {src.name}: {w}x{h} (Flatpak needs square icons up to 512px)")
                continue
            size_dir = f"{w}x{h}"
        dest = share / "icons/hicolor" / size_dir / "apps" / f"{app_id}.{ext}"
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
        installed.append(dest.relative_to(share.parent).as_posix())
    if not installed:
        warnings.append(f"no usable icon found for Icon={icon}")
    return installed, warnings


def placeholder_icon(app_id: str, size: int = 128) -> bytes:
    """Return a plain PNG icon for an app that ships none.

    AppStream's compose step, which flatpak-builder runs, refuses a desktop
    application without an icon, and a menu entry without one looks broken.
    This draws a rounded square in a colour taken from the app ID, so two
    apps don't look the same, with a white window outline on it.
    """
    from .winres import _png
    import hashlib
    h = int(hashlib.sha256(app_id.encode()).hexdigest()[:6], 16)
    base = ((h >> 16) & 0x7F) + 40, ((h >> 8) & 0x7F) + 40, (h & 0x7F) + 40
    px = bytearray(size * size * 4)
    r = size // 6                                   # corner radius
    m = size // 4                                   # window margin
    t = max(2, size // 32)                          # line thickness

    def inside_rounded(x, y):
        cx = min(max(x, r), size - 1 - r)
        cy = min(max(y, r), size - 1 - r)
        return (x - cx) ** 2 + (y - cy) ** 2 <= r * r

    for y in range(size):
        for x in range(size):
            i = (y * size + x) * 4
            if not inside_rounded(x, y):
                continue
            in_win = m <= x < size - m and m <= y < size - m
            edge = in_win and (x < m + t or x >= size - m - t or y < m + t or y >= size - m - t
                               or m + size // 8 <= y < m + size // 8 + t)
            bar = in_win and y < m + size // 8
            px[i:i + 4] = bytes((255, 255, 255, 255)) if edge or bar else bytes((*base, 255))
    return _png(size, size, bytes(px))


def install_mime(root: Path, share: Path, app_id: str) -> list[str]:
    """Copy the package's MIME type definitions, renamed after the app ID; return the new paths."""
    src_dir = root / "usr/share/mime/packages"
    out = []
    if not src_dir.is_dir():
        return out
    for i, src in enumerate(sorted(src_dir.glob("*.xml"))):
        name = f"{app_id}.xml" if i == 0 else f"{app_id}.{src.stem}.xml"
        dest = share / "mime/packages" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
        out.append(dest.relative_to(share.parent).as_posix())
    return out


def upstream_version(deb_version: str) -> str:
    """Strip the epoch and Debian revision from a version: '1:2.3-4' -> '2.3'."""
    v = deb_version.split(":", 1)[-1]
    return v.rsplit("-", 1)[0] if "-" in v else v


# Common SPDX identifiers (Flathub requires SPDX in project_license). Legacy RPM names like
# "GPLv2+" aren't SPDX, so they fall back to LicenseRef-proprietary with a comment.
SPDX_IDS = {
    "MIT", "ISC", "Zlib", "0BSD", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "MPL-2.0", "Unlicense",
    "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later", "LGPL-2.1-only",
    "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "EPL-2.0", "CC0-1.0", "CC-BY-4.0", "CC-BY-SA-4.0", "Artistic-2.0", "BSL-1.0", "OFL-1.1", "PSF-2.0",
    "Python-2.0", "OpenSSL", "Vim", "WTFPL", "MIT-0", "BlueOak-1.0.0", "EUPL-1.2", "GPL-2.0-with-classpath-exception",
}


def spdx_license(text: str) -> str | None:
    """Return the package's license if it's an SPDX expression of identifiers in SPDX_IDS, else None."""
    import re as _re
    t = (text or "").strip()
    if not t:
        return None
    tokens = [x for x in _re.split(r"\s+(?:AND|OR|WITH)\s+|[()]", t) if x.strip()]
    if tokens and all(x.strip() in SPDX_IDS or x.strip().startswith("LicenseRef-") for x in tokens):
        return t
    return None


def metainfo(pkg: DebPackage, app_id: str, name: str, has_desktop: bool) -> str:
    """Write AppStream metainfo XML for the app.

    The license is the package's own when it's valid SPDX, else
    LicenseRef-proprietary with a comment quoting what the package says. The
    release date is today, since packages rarely record one.
    """
    summary = pkg.summary or name
    paras = [p.strip() for p in pkg.long_description.split("\n\n") if p.strip()] or [summary]
    desc = "\n".join(f"    <p>{escape(' '.join(p.split()))}</p>" for p in paras)
    homepage = getattr(pkg, "homepage", "") or pkg.control.get("Homepage")
    license_id = spdx_license(getattr(pkg, "license", ""))
    stated = escape(getattr(pkg, "license", "")).replace("--", "- -")    # "--" can't appear in a comment
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        "<!-- Generated by debpak. Review project_license before publishing. -->"
        + (f"\n<!-- The package states its license as: {stated} -->"
           if stated and not license_id else ""),
        f'<component type="{"desktop-application" if has_desktop else "console-application"}">',
        f"  <id>{escape(app_id)}</id>",
        "  <metadata_license>CC0-1.0</metadata_license>",
        f"  <project_license>{escape(license_id or 'LicenseRef-proprietary')}</project_license>",
        f"  <name>{escape(name)}</name>",
        f"  <summary>{escape(summary)}</summary>",
        "  <description>",
        desc,
        "  </description>",
    ]
    if has_desktop:
        lines.append(f'  <launchable type="desktop-id">{escape(app_id)}.desktop</launchable>')
    if homepage:
        lines.append(f'  <url type="homepage">{escape(homepage)}</url>')
    lines += [
        "  <content_rating type=\"oars-1.1\"/>",
        "  <releases>",
        f'    <release version="{escape(upstream_version(pkg.version))}" date="{datetime.date.today().isoformat()}"/>',
        "  </releases>",
        "</component>",
    ]
    return "\n".join(lines) + "\n"


def app_display_name(root: Path, desktop_rel: str | None, fallback: str) -> str:
    """Return the Name= of the app's .desktop file, or fallback."""
    if desktop_rel:
        v = desktop_entry_value((root / desktop_rel).read_text("utf-8", "replace"), "Name")
        if v:
            return v
    return fallback
