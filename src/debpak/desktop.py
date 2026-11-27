"""Desktop integration: .desktop rewrite, icon export, MIME, AppStream."""
from __future__ import annotations

import datetime
import re
import shutil
import struct
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING
from xml.sax.saxutils import escape

from .analyze import desktop_entry_value, parse_exec
from .deb import DebPackage, resolve_in_root

if TYPE_CHECKING:
    from .packages import Package

_NEEDS_QUOTE = re.compile(r'[\s"\'\\><~|&;$*?#()`]')


def _quote_arg(arg: str) -> str:
    """Quote one Exec= argument per the Desktop Entry spec; field codes like %U stay bare."""
    if arg.startswith("%") and len(arg) == 2:
        return arg  # field code
    if not _NEEDS_QUOTE.search(arg):
        return arg
    return '"' + re.sub(r'(["`$\\])', r"\\\1", arg) + '"'


# Additional categories and the main categories the desktop menu spec says go with them;
# desktop-file-validate rejects one without any of its main categories, and flatpak's export then fails
NEEDS_MAIN = {
    "TerminalEmulator": "System", "Shell": "System", "FileManager": "System", "Filesystem": "System",
    "Monitor": "System", "Emulator": "System", "PackageManager": "System", "Security": "System",
    "Building": "Development", "Debugger": "Development", "IDE": "Development", "GUIDesigner": "Development",
    "Profiling": "Development", "RevisionControl": "Development", "Translation": "Development",
    "WebDevelopment": "Development",
    "Calendar": "Office", "ContactManagement": "Office", "Dictionary": "Office", "Chart": "Office",
    "Email": "Office", "Finance": "Office", "FlowChart": "Office", "PDA": "Office",
    "ProjectManagement": "Office", "Presentation": "Office", "Spreadsheet": "Office", "WordProcessor": "Office",
    "2DGraphics": "Graphics", "3DGraphics": "Graphics", "RasterGraphics": "Graphics",
    "VectorGraphics": "Graphics", "Scanning": "Graphics", "OCR": "Graphics", "Photography": "Graphics",
    "Publishing": "Graphics", "Viewer": "Graphics",
    "Dialup": "Network", "InstantMessaging": "Network", "Chat": "Network", "IRCClient": "Network",
    "Feed": "Network", "FileTransfer": "Network", "News": "Network", "P2P": "Network",
    "RemoteAccess": "Network", "Telephony": "Network", "VideoConference": "Network", "WebBrowser": "Network",
    "Midi": "AudioVideo", "Mixer": "AudioVideo", "Sequencer": "AudioVideo", "Tuner": "AudioVideo",
    "TV": "AudioVideo", "AudioVideoEditing": "AudioVideo", "Player": "AudioVideo",
    "Recorder": "AudioVideo", "DiscBurning": "AudioVideo",
    "ActionGame": "Game", "AdventureGame": "Game", "ArcadeGame": "Game", "BoardGame": "Game",
    "BlocksGame": "Game", "CardGame": "Game", "KidsGame": "Game", "LogicGame": "Game",
    "RolePlaying": "Game", "Shooter": "Game", "Simulation": "Game", "SportsGame": "Game",
    "StrategyGame": "Game",
    "TextEditor": "Utility", "TextTools": "Utility", "Archiving": "Utility", "Compression": "Utility",
    "Calculator": "Utility", "Clock": "Utility", "Accessibility": "Utility",
}
# the main categories each one also accepts (a TerminalEmulator under Utility is fine too, say)
ALSO_OK = {
    "TerminalEmulator": {"Utility"}, "Shell": set(), "Emulator": {"Game"}, "Security": {"Settings"},
    "WebDevelopment": {"Network"}, "Dictionary": {"TextTools"}, "Email": {"Network"},
    "Photography": {"Office"}, "Viewer": {"Office"}, "Publishing": {"Office"},
    "Accessibility": {"Settings"}, "Archiving": {"System"}, "Compression": {"System"},
    "Midi": {"Audio"}, "Mixer": {"Audio"}, "Sequencer": {"Audio"}, "Tuner": {"Audio"}, "TV": {"Video"},
    "Recorder": {"Audio", "Video"}, "Player": {"Audio", "Video"},
}


# the menu spec's main categories; appstreamcli compose (which flatpak-builder runs) drops an
# app without one with no-valid-category, and the build fails
MAIN_CATEGORIES = ("AudioVideo", "Audio", "Video", "Development", "Education", "Game", "Graphics",
                   "Network", "Office", "Science", "Settings", "System", "Utility")


def fix_categories(value: str) -> str:
    """Add the main category an additional category needs (TerminalEmulator; becomes TerminalEmulator;System;).

    A list with no main category at all gets Utility: Tauri writes an empty
    Categories= when the app sets none (Jan).
    """
    cats = [c.strip() for c in value.split(";") if c.strip()]
    for c in list(cats):
        main = NEEDS_MAIN.get(c)
        if main and not ({main} | ALSO_OK.get(c, set())) & set(cats):
            cats.append(main)
    if not set(cats) & set(MAIN_CATEGORIES):
        cats.append("Utility")
    return ";".join(cats) + ";"


def _rewrite_line(line: str, main_group: bool, app_id: str, command: str) -> str | None:
    """Return a .desktop line as rewrite_desktop changes it, or None to drop it."""
    key, sep, value = line.strip().partition("=")
    if not sep:
        return line
    key = key.strip()
    if key == "Exec":
        _env, _prog, args = parse_exec(value)
        # an AppImage's way to start Chromium without its setuid helper; zypak does that here
        return "Exec=" + " ".join([command] + [_quote_arg(a) for a in args if a != "--no-sandbox"])
    if key in ("TryExec", "DBusActivatable"):
        # DBusActivatable: the desktop would start the app through a D-Bus service named after the app ID,
        # which the Flatpak hasn't got; flatpak-builder refuses to export such an entry (Ghostty's)
        return None
    if key == "Icon" and main_group:
        return f"Icon={app_id}"
    if key == "Categories" and main_group:
        return "Categories=" + fix_categories(value.strip())
    if key == "MimeType":
        return _mime_line(value)
    return line


def _mime_line(value: str) -> str | None:
    """Return a MimeType= line with only the values that are content types, or None if none are."""
    # only type/subtype values: Quickgui's and Harmony Music's MimeType=null made flatpak
    # refuse to start them ("not allowed by the policy set by your administrator")
    types = [t.strip() for t in value.split(";") if re.fullmatch(r"[\w.+-]+/[\w.+*-]+", t.strip())]
    return "MimeType=" + ";".join(types) + ";" if types else None


def rewrite_desktop(text: str, app_id: str, command: str) -> str:
    """Point a .desktop file at the Flatpak.

    Every Exec= line (the main entry and each [Desktop Action]) runs command with
    the original arguments, minus any program and env prefix and --no-sandbox.
    MimeType= keeps only values that are content types. TryExec= is dropped,
    because the program it names doesn't exist outside the sandbox, and so is
    DBusActivatable=, since no D-Bus service starts the app; the main
    Icon= becomes the app ID, which is the name the icons are exported under.
    Categories= gains any main category the menu spec requires, and an entry
    without Categories= gets one (see fix_categories).
    """
    out: list[str] = []
    group = None
    has_categories = "Categories" in _entry_keys(text)
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            has_categories = _end_group(out, group, has_categories)
            group = s
            out.append(line)
            continue
        new = _rewrite_line(line, group == "[Desktop Entry]", app_id, command)
        if new is not None:
            out.append(new)
    _end_group(out, group, has_categories)
    return "\n".join(out) + "\n"


def _end_group(out: list[str], group: str | None, has_categories: bool) -> bool:
    """Finish the group being written: [Desktop Entry] gets Categories= if it has none; return whether it has them."""
    if group == "[Desktop Entry]" and not has_categories:
        _add_categories(out)
        return True
    return has_categories


def _entry_keys(text: str) -> set[str]:
    """Return the keys of the [Desktop Entry] group of a .desktop file."""
    keys, group = set(), None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            group = s
        elif group == "[Desktop Entry]" and "=" in s:
            keys.add(s.split("=", 1)[0].strip())
    return keys


def _add_categories(out: list[str]) -> None:
    """Add Categories= to the end of the group being written, before its trailing blank lines."""
    i = len(out)
    while i and not out[i - 1].strip():
        i -= 1
    out.insert(i, "Categories=" + fix_categories(""))


def png_size(path: Path) -> tuple[int, int] | None:
    """Return a PNG's (width, height) from its header, or None if it isn't a PNG."""
    with open(path, "rb") as f:
        head = f.read(24)
    if head[:8] != b"\x89PNG\r\n\x1a\n" or head[12:16] != b"IHDR":
        return None
    return struct.unpack(">II", head[16:24])


def looks_like_image(path: Path, ext: str) -> bool:
    """Whether an icon file holds what its extension says: a PNG's signature, an SVG's <svg element.

    Other extensions (XPM) are taken at their word if the file isn't empty.
    """
    import gzip
    try:
        with open(path, "rb") as f:
            head = f.read(65536)
        if ext in ("svg", "svgz") and head[:2] == b"\x1f\x8b":
            with gzip.open(path, "rb") as g:
                head = g.read(65536)
    except (OSError, EOFError):
        return False
    if ext == "png":
        return head[:8] == b"\x89PNG\r\n\x1a\n"
    if ext in ("svg", "svgz"):
        return b"<svg" in head
    return bool(head)


def _svg_length(value: str | None) -> float | None:
    """Return an SVG width or height in pixels (a plain number or px), or None for other units."""
    m = re.fullmatch(r"\s*([0-9]*\.?[0-9]+(?:[eE][-+]?[0-9]+)?)\s*(px)?\s*", value or "")
    return float(m.group(1)) if m else None


def _svg_number(v: float) -> str:
    return f"{v:.4f}".rstrip("0").rstrip(".")


def _set_attr(mt: re.Match[str], value: str) -> str:
    """Return the attribute matched by mt with its value replaced."""
    return f'{mt.group(1)}"{value}"'


# flatpak-validate-icon refuses an SVG whose width or height is over this ("Image too large
# (5832x5832). Max. size 4096x4096"), WhatsUp's snap's icon
MAX_SVG = 4096
# and what such an icon is drawn at instead: its viewBox keeps the drawing as it was
SVG_SIZE = 512


def _svg_attr(tag: str, name: str) -> str | None:
    a = re.search(rf"\s{name}\s*=\s*([\"'])(.*?)\1", tag, re.S)
    return a.group(2) if a else None


def _parse_box(vb: str | None) -> list[float] | None:
    """Return a viewBox's four numbers, or None without one.

    Raises:
        ValueError: It isn't four numbers, or its width or height isn't positive.
    """
    if not vb:
        return None
    box = [float(x) for x in re.split(r"[\s,]+", vb.strip())]
    if len(box) != 4 or box[2] <= 0 or box[3] <= 0:
        raise ValueError(f"unusable viewBox {vb!r}")
    return box


def _sized_box(w: str | None, h: str | None, box: list[float] | None) -> tuple[float, list[float]] | None:
    """Return the larger of an <svg> tag's width and height and its box, or None if it's square (and no larger
    than MAX_SVG) or not in pixels."""
    wl, hl = _svg_length(w), _svg_length(h)
    if wl is None or hl is None or wl <= 0 or hl <= 0 or (wl == hl and wl <= MAX_SVG):
        return None            # square already, or in units the box can't be matched to
    return max(wl, hl), box or [0.0, 0.0, wl, hl]


def _squared(box: list[float], size: float | None) -> dict[str, str]:
    """Return the viewBox centring box on a square canvas, and width and height when size is given."""
    x, y, bw, bh = box
    side = max(bw, bh)
    new = {"viewBox": " ".join(_svg_number(v) for v in (x - (side - bw) / 2, y - (side - bh) / 2, side, side))}
    if size is not None:
        new["width"] = new["height"] = _svg_number(size if size <= MAX_SVG else SVG_SIZE)
    return new


def _square_attrs(tag: str) -> dict[str, str] | None:
    """Return the attributes that make an <svg> tag square, or None if it's square or can't be read."""
    w, h, vb = _svg_attr(tag, "width"), _svg_attr(tag, "height"), _svg_attr(tag, "viewBox")
    try:
        box = _parse_box(vb)
    except ValueError:
        return None
    size = None
    if w is not None or h is not None:
        sized = _sized_box(w, h, box)
        if sized is None:
            return None
        size, box = sized
    elif box is None or box[2] == box[3]:
        return None
    return _squared(box, size)


def _with_attrs(tag: str, new: dict[str, str]) -> str:
    """Return a tag with the attributes in new set: the ones it has replaced, the others added at its end."""
    for name, value in new.items():
        if _svg_attr(tag, name) is not None:
            # a function, not a template, so nothing in value is read as a group reference
            tag = re.sub(rf"(\s{name}\s*=\s*)([\"']).*?\2", partial(_set_attr, value=value), tag, count=1,
                         flags=re.S)
        else:
            end = len(tag) - (2 if tag.endswith("/>") else 1)
            tag = f'{tag[:end]} {name}="{value}"{tag[end:]}'
    return tag


def square_svg(path: Path) -> bytes | None:
    """Return an SVG icon centred on a square canvas, or None if it is square already or can't be read.

    flatpak's export refuses an icon that isn't square ("Expected a square icon
    but got: 41x40", AppFlowy). The root element's viewBox is widened to a
    square around the drawing, and width and height become the larger of the two.
    It refuses one over MAX_SVG pixels too: WhatsUp's snap's icon.svg is 5832x5832,
    and the build failed at the export. Such an icon gets a width and height of
    SVG_SIZE, and a viewBox of its old size if it had none, so it draws the same.
    An .svgz stays compressed.
    """
    import gzip
    data = path.read_bytes()
    packed = data[:2] == b"\x1f\x8b"
    try:
        text = (gzip.decompress(data) if packed else data).decode("utf-8", "surrogateescape")
    except (OSError, EOFError):
        return None
    m = re.search(r"<svg\b[^>]*>", text)
    if not m:
        return None
    tag = m.group(0)
    new = _square_attrs(tag)
    if new is None:
        return None
    tag = _with_attrs(tag, new)
    out = (text[:m.start()] + tag + text[m.end():]).encode("utf-8", "surrogateescape")
    return gzip.compress(out) if packed else out


def _icon_candidates(root: Path, icon: str) -> list[tuple[Path, str]]:
    """Find icon files for Icon= in the package as (file, size folder) pairs; the size folder is '256x256', 'scalable' or '' when unknown."""
    if "/" in icon:
        p = _existing(root, icon)
        return [(p, "")] if p else []
    # Icon= names a theme icon without its extension, but some vendors write the
    # file name (Icon=bcompare.png)
    icon = re.sub(r"\.(png|svgz?|xpm)$", "", icon, flags=re.I)
    found = _hicolor_icons(root, icon)
    if found:
        return found
    for ext in ("png", "svg", "xpm"):
        p = _existing(root, f"usr/share/pixmaps/{icon}.{ext}")
        if p:
            found.append((p, ""))
    return found


def _existing(root: Path, rel: str) -> Path | None:
    """Return the file rel names inside an extracted package root, or None if there's no such file."""
    p = resolve_in_root(root, rel)
    return p if p and p.is_file() else None


def _hicolor_icons(root: Path, icon: str) -> list[tuple[Path, str]]:
    """Find the theme icon named icon in the package's hicolor size folders, as (file, size folder) pairs."""
    hicolor = root / "usr/share/icons/hicolor"
    if not hicolor.is_dir():
        return []
    found = []
    for size_dir in sorted(hicolor.iterdir()):
        for ext in ("png", "svg", "svgz"):
            p = _existing(root, f"usr/share/icons/hicolor/{size_dir.name}/apps/{icon}.{ext}")
            if p:
                found.append((p, size_dir.name))
    return found


# the size folders appstreamcli compose (which flatpak-builder runs) takes an app's icon
# from; with none of them it fails with icon-not-found
APPSTREAM_ICON_DIRS = ("64x64", "128x128", "256x256", "512x512", "64x64@2", "128x128@2", "scalable")


def _shrunk_icon(src: Path, size_dir: str, share: Path, app_id: str, installed: list, warnings: list) -> None:
    """Install a PNG icon too large for Flatpak as the 512x512 one, if there's none yet."""
    from .winres import MAX_ICON, shrink_png
    dest = share / "icons/hicolor" / f"{MAX_ICON}x{MAX_ICON}" / "apps" / f"{app_id}.png"
    if dest.exists():
        warnings.append(f"skipped the {size_dir} icon (Flatpak takes icons up to {MAX_ICON}px)")
        return
    try:
        data = shrink_png(src.read_bytes(), MAX_ICON)
    except ValueError:
        warnings.append(f"skipped the {size_dir} icon: too large for Flatpak and unreadable")
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    installed.append(dest.relative_to(share.parent).as_posix())
    warnings.append(f"the {size_dir} icon is larger than Flatpak takes; scaled it down to {MAX_ICON}x{MAX_ICON}")


def install_icons(root: Path, icon: str | None, share: Path, app_id: str) -> tuple[list[str], list[str]]:
    """Export the app's icons under its app ID, as Flatpak requires.

    Each icon goes to share/icons/hicolor/<size>/apps/<app_id>.<ext>. A PNG
    outside a size folder is sized from its header, and skipped if it isn't
    square or is larger than 512px. XPM icons are skipped. Each skip adds a
    warning. When none of the icons is in a folder AppStream reads
    (APPSTREAM_ICON_DIRS), a 128 or 256px copy of the largest PNG is added:
    Beyond Compare has only a 32x32 icon and MongoDB Compass a 276x276 one.

    Returns:
        (installed paths relative to share's parent, warnings).
    """
    if not icon:
        return [], ["desktop file has no Icon= entry"]
    sink = _IconSink(share, app_id)
    pngs: list[tuple[int, Path]] = []       # square PNGs, for a copy AppStream can use
    for src, size_dir in _icon_candidates(root, icon):
        ext = src.suffix.lstrip(".").lower()
        dims = png_size(src) if ext == "png" else None
        if not _is_image(sink, src, ext):
            continue
        if 0 <= (side := _square_side(dims)) <= 1024:
            pngs.append((side, src))
        _install_icon(sink, src, _size_folder(size_dir), ext, dims)
    installed, warnings = sink.installed, sink.warnings
    _appstream_fallbacks(sink, pngs, share, app_id)
    if not installed:
        warnings.append(f"no usable icon found for Icon={icon}")
    return installed, warnings


def _square_side(dims: tuple[int, int] | None) -> int:
    """Return the side of a square image of dims, -1 if it isn't square or its size is unknown."""
    return dims[0] if dims and dims[0] == dims[1] else -1


def _size_folder(size_dir: str) -> str:
    """Return the size folder an icon was found in, or "" when the folder gives no size."""
    if re.fullmatch(r"0+x0+(?:@\d+x?)?", size_dir):
        # electron-builder names the folder of an icon it couldn't size 0x0 (Slipstream GUI's
        # 1024x1024 icon), which is no size at all: the image's own size decides
        return ""
    return size_dir


def _is_image(sink: _IconSink, src: Path, ext: str) -> bool:
    """Whether an icon file is the image its extension says; a warning says why one is skipped."""
    if looks_like_image(src, ext):
        return True
    # flatpak's export refuses what isn't an image ("is not a valid icon: Format not
    # recognized"): zsync2's AppImage ships an empty zsync2.svg
    sink.warnings.append(f"skipped {src.name}: it isn't a {ext.upper()} image" if src.stat().st_size
                         else f"skipped {src.name}: the file is empty")
    return False


def _install_icon(sink: _IconSink, src: Path, size_dir: str, ext: str, dims: tuple[int, int] | None) -> None:
    """Install one icon file install_icons found, the way its kind and folder call for."""
    if ext == "xpm":
        sink.warnings.append(f"skipped XPM icon {src.name} (convert it to PNG)")
    elif ext in ("svg", "svgz"):
        _svg_icon(sink, src, ext)
    elif size_dir and (m := re.fullmatch(r"(\d+)x(\d+)(?:@(\d+)x?)?", size_dir)):
        _sized_icon(sink, src, ext, size_dir, m, dims)
    elif not size_dir:
        _loose_icon(sink, src, ext)
    else:
        sink.copy(src, size_dir, ext)


def _appstream_fallbacks(sink: _IconSink, pngs: list[tuple[int, Path]], share: Path, app_id: str) -> None:
    """Scale down an icon over 512px, and add a copy of the largest square PNG when AppStream would find no icon."""
    if sink.too_big:
        _shrunk_icon(*sink.too_big[0], share, app_id, sink.installed, sink.warnings)
    if pngs and not any(Path(i).parts[3] in APPSTREAM_ICON_DIRS for i in sink.installed):
        made = _appstream_icon_copy(max(pngs), share, app_id, sink.warnings)
        if made:
            sink.installed.append(made)


class _IconSink:
    """Where install_icons puts icons, and what it says about them."""

    def __init__(self, share: Path, app_id: str):
        self.share, self.app_id = share, app_id
        self.installed: list[str] = []
        self.warnings: list[str] = []
        self.too_big: list[tuple[Path, str]] = []   # square PNGs over 512px, scaled down if there's no 512px one

    def write(self, size_dir: str, ext: str, data: bytes) -> None:
        dest = self.share / "icons/hicolor" / size_dir / "apps" / f"{self.app_id}.{ext}"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        self.installed.append(dest.relative_to(self.share.parent).as_posix())

    def copy(self, src: Path, size_dir: str, ext: str) -> None:
        dest = self.share / "icons/hicolor" / size_dir / "apps" / f"{self.app_id}.{ext}"
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
        self.installed.append(dest.relative_to(self.share.parent).as_posix())


def _svg_icon(sink: _IconSink, src: Path, ext: str) -> None:
    squared = square_svg(src)
    if squared is None:
        sink.copy(src, "scalable", ext)
        return
    sink.write("scalable", ext, squared)
    sink.warnings.append(f"{src.name} isn't square, or is larger than {MAX_SVG}px, which Flatpak refuses; "
                         "centred it on a square canvas of a size Flatpak takes")


def _sized_icon(sink: _IconSink, src: Path, ext: str, size_dir: str, m: re.Match[str],
                dims: tuple[int, int] | None) -> None:
    """Install an icon from a WxH (or WxH@scale) folder, scaling, padding or skipping what Flatpak refuses."""
    width, height, scale = int(m.group(1)), int(m.group(2)), int(m.group(3) or 1)
    # a HiDPI folder holds the icon at scale times its size: 512x512@2x is 1024 pixels, more
    # than Flatpak takes (Uncode), and the 512x512 folder has the same icon
    if m.group(3) and width * scale > 512:
        sink.warnings.append(f"skipped the {size_dir} icon (Flatpak takes icons up to 512px)")
        return
    # flatpak's export rejects icons over 512px (Hyper ships a 1024x1024 one): a square PNG
    # becomes the 512x512 icon, unless the package has its own
    if width > 512 or height > 512:
        _too_big_icon(sink, src, size_dir, dims)
        return
    if dims and _misfit_icon(sink, src, size_dir, width, height, scale, dims):
        return
    sink.copy(src, size_dir, ext)


def _misfit_icon(sink: _IconSink, src: Path, size_dir: str, width: int, height: int, scale: int,
                 dims: tuple[int, int]) -> bool:
    """Deal with an image that doesn't fit its WxH folder; return False if it fits and can be copied as it is."""
    # flatpak's export also rejects an image bigger than its folder says
    # (1Password's 256x256 icon is 257x258)
    if dims[0] > width * scale or dims[1] > height * scale:
        _oversized_icon(sink, src, size_dir, width * scale, width == height, dims)
        return True
    # and one that isn't square (Satisfactory Mod Manager's 64x64 icon is 64x61)
    if dims[0] != dims[1]:
        _padded_icon(sink, src, size_dir, width, height, dims)
        return True
    return False


def _too_big_icon(sink: _IconSink, src: Path, size_dir: str, dims: tuple[int, int] | None) -> None:
    """Keep a square PNG from a folder over 512px to scale down later; skip anything else."""
    if dims and dims[0] == dims[1]:
        sink.too_big.append((src, size_dir))
    else:
        sink.warnings.append(f"skipped the {size_dir} icon (Flatpak takes icons up to 512px)")


def _padded_icon(sink: _IconSink, src: Path, size_dir: str, width: int, height: int, dims: tuple[int, int]) -> None:
    """Install a PNG that isn't square centred on a canvas of its folder's size, or skip it if it can't be read."""
    from .winres import pad_png
    try:
        data = pad_png(src.read_bytes(), width, height)
    except ValueError:
        sink.warnings.append(f"skipped the {size_dir} icon: the image is {dims[0]}x{dims[1]}")
        return
    sink.write(size_dir, "png", data)
    sink.warnings.append(f"the {size_dir} icon is {dims[0]}x{dims[1]}, which Flatpak refuses; centred it "
                         "on a square canvas")


def _oversized_icon(sink: _IconSink, src: Path, size_dir: str, want: int, square_dir: bool,
                    dims: tuple[int, int]) -> None:
    """Install an image bigger than its folder says, shrunk when it's that icon at twice the size or more."""
    if dims[0] == dims[1] and square_dir and dims[0] >= 2 * want:
        # a 1024x1024 image in the 512x512 folder (PlayMe) is that icon at twice the size
        from .winres import shrink_png
        try:
            sink.write(size_dir, "png", shrink_png(src.read_bytes(), want))
            sink.warnings.append(f"the {size_dir} icon is {dims[0]}x{dims[1]}; scaled it to fit its folder")
            return
        except ValueError:
            pass
    sink.warnings.append(f"skipped the {size_dir} icon: the image is {dims[0]}x{dims[1]}")


def _loose_icon(sink: _IconSink, src: Path, ext: str) -> None:
    """Install an icon that isn't in a size folder, sized from its PNG header."""
    dims = png_size(src)
    if not dims:
        sink.warnings.append(f"skipped unreadable icon {src.name}")
        return
    w, h = dims
    if w == h and w > 512:
        sink.too_big.append((src, f"{w}x{h}"))
    elif w != h or w > 512:
        sink.warnings.append(f"skipped {src.name}: {w}x{h} (Flatpak needs square icons up to 512px)")
    else:
        sink.copy(src, f"{w}x{h}", ext)


def _appstream_icon_copy(png: tuple[int, Path], share: Path, app_id: str, warnings: list[str]) -> str | None:
    """Add a 128 or 256px copy of a (size, PNG file) icon that AppStream can use; return its path.

    The copy is scaled to the nearest pixel (winres.scale_png), which keeps a
    small icon's hard edges. A PNG that can't be decoded (16-bit, interlaced)
    gets a placeholder icon instead, so the build still passes AppStream.
    """
    from .winres import scale_png
    size, src = png
    target = 256 if size >= 256 else 128
    try:
        data = scale_png(src.read_bytes(), target)
        warnings.append(f"the app's icon is {size}x{size}, a size AppStream doesn't read; added a "
                        f"{target}x{target} copy of it")
    except ValueError as e:
        data = placeholder_icon(app_id, target)
        warnings.append(f"the app's icon is {size}x{size}, a size AppStream doesn't read, and couldn't be "
                        f"scaled ({e}); added a plain {target}x{target} placeholder icon")
    dest = share / "icons/hicolor" / f"{target}x{target}" / "apps" / f"{app_id}.png"
    if dest.exists():
        return None
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    return dest.relative_to(share.parent).as_posix()


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
            px[i:i + 4] = bytes((255, 255, 255, 255)) if _on_window(x, y, size, m, t) else bytes((*base, 255))
    return _png(size, size, bytes(px))


def _on_window(x: int, y: int, size: int, m: int, t: int) -> bool:
    """Return True where placeholder_icon draws its window: the outline and the title bar."""
    in_win = m <= x < size - m and m <= y < size - m
    edge = in_win and (x < m + t or x >= size - m - t or y < m + t or y >= size - m - t
                       or m + size // 8 <= y < m + size // 8 + t)
    bar = in_win and y < m + size // 8
    return edge or bar


def install_mime(root: Path, share: Path, app_id: str) -> list[str]:
    """Copy the package's MIME type definitions, renamed after the app ID; return the new paths."""
    src_dir = root / "usr/share/mime/packages"
    out: list[str] = []
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


def metainfo(pkg: DebPackage | Package, app_id: str, name: str, has_desktop: bool) -> str:
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
