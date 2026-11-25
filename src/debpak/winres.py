"""Read a Windows program's resources: its icon and its version strings.

The converters use these to name a converted app and give it a menu icon.
The icon code started in appbridge's icons.py; the version reader follows
the VS_VERSIONINFO layout in Microsoft's documentation.
"""
from __future__ import annotations

import struct
import zlib
from pathlib import Path

from .pe import PeError, _Image

DIR_RESOURCE = 2
RT_ICON, RT_GROUP_ICON, RT_VERSION = 3, 14, 16


def _walk(img: _Image, m, base: int, rva: int, depth: int, path: tuple, out: list) -> None:
    """Collect ((type, name, lang), data_rva, size) for every leaf of the resource tree."""
    off = img.off(rva)
    _ch, _ts, _maj, _min, n_named, n_id = struct.unpack_from("<IIHHHH", m, off)
    for i in range(n_named + n_id):
        name, target = struct.unpack_from("<II", m, off + 16 + 8 * i)
        key = name if not name & 0x80000000 else f"#{name & 0x7FFFFFFF:x}"
        if target & 0x80000000:
            if depth < 2:
                _walk(img, m, base, base + (target & 0x7FFFFFFF), depth + 1, path + (key,), out)
        else:
            data_rva, size = struct.unpack_from("<II", m, img.off(base + target))
            out.append((path + (key,), data_rva, size))


def _resources(data: bytes) -> tuple[_Image, list]:
    """Return the parsed image and its resource leaves (empty when there's no .rsrc)."""
    if data[:2] != b"MZ":
        raise PeError("not a PE file")
    img = _Image(data)
    rsrc = img.dirs[DIR_RESOURCE][0]
    leaves: list = []
    if rsrc:
        _walk(img, data, rsrc, rsrc, 0, (), leaves)
    return img, leaves


def icon_images(exe: str | Path) -> list[tuple[int, int, bytes]]:
    """Return (width, bit count, raw RT_ICON bytes) for each image in the file's first icon group.

    Raises:
        PeError: The file isn't a PE image or its resources are damaged.
    """
    data = Path(exe).read_bytes()
    try:
        img, leaves = _resources(data)
        icons = {path[1]: (rva, size) for path, rva, size in leaves if path[0] == RT_ICON}
        groups = [(rva, size) for path, rva, size in leaves if path[0] == RT_GROUP_ICON]
        if not groups:
            return []
        g = img.off(groups[0][0])
        _res, _typ, count = struct.unpack_from("<HHH", data, g)
        out = []
        for i in range(count):
            w, _h, _colors, _r, _planes, bits, _size, icon_id = struct.unpack_from("<BBBBHHIH", data, g + 6 + 14 * i)
            if icon_id in icons:
                rva, size = icons[icon_id]
                o = img.off(rva)
                out.append((w or 256, bits, bytes(data[o:o + size])))
        return out
    except (struct.error, IndexError) as e:
        raise PeError(f"{exe}: malformed resources ({e})") from e


def _png(width: int, height: int, rgba: bytes) -> bytes:
    def chunk(tag: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + tag + body + struct.pack(">I", zlib.crc32(tag + body) & 0xFFFFFFFF)
    rows = b"".join(b"\0" + rgba[y * width * 4:(y + 1) * width * 4] for y in range(height))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b""))


def png_pixels(png: bytes) -> tuple[int, int, bytes]:
    """Decode a PNG to (width, height, RGBA bytes).

    Reads the kinds icons come in: 8 bits per channel (grey, RGB, palette, grey
    with alpha, RGBA), not interlaced.

    Raises:
        ValueError: It isn't a PNG, or it's 16-bit, under 8-bit, interlaced or damaged.
    """
    if png[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    off, idat, plte, trns, head = 8, bytearray(), b"", b"", None
    try:
        while off + 8 <= len(png):
            n, tag = struct.unpack_from(">I4s", png, off)
            body = png[off + 8:off + 8 + n]
            off += 12 + n
            if tag == b"IHDR":
                head = struct.unpack(">IIBBBBB", body[:13])
            elif tag == b"PLTE":
                plte = body
            elif tag == b"tRNS":
                trns = body
            elif tag == b"IDAT":
                idat += body
            elif tag == b"IEND":
                break
        if not head:
            raise ValueError("PNG has no header")
        width, height, depth, ctype, _comp, _filt, interlace = head
        channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(ctype)
        if depth != 8 or not channels or interlace or not (0 < width <= 1024 and 0 < height <= 1024):
            raise ValueError(f"unsupported PNG ({width}x{height}, {depth}-bit, type {ctype}, interlace {interlace})")
        raw = zlib.decompress(bytes(idat))
    except (struct.error, zlib.error) as e:
        raise ValueError(f"damaged PNG: {e}") from e
    stride = width * channels
    if len(raw) < (stride + 1) * height:
        raise ValueError("PNG data is shorter than its size")
    rows, prev = [], bytearray(stride)
    for y in range(height):
        kind, line = raw[y * (stride + 1)], bytearray(raw[y * (stride + 1) + 1:(y + 1) * (stride + 1)])
        for i in range(stride):
            a = line[i - channels] if i >= channels else 0
            b, c = prev[i], prev[i - channels] if i >= channels else 0
            if kind == 1:
                line[i] = (line[i] + a) & 0xFF
            elif kind == 2:
                line[i] = (line[i] + b) & 0xFF
            elif kind == 3:
                line[i] = (line[i] + (a + b) // 2) & 0xFF
            elif kind == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                line[i] = (line[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 0xFF
            elif kind:
                raise ValueError(f"damaged PNG: filter {kind}")
        rows.append(line)
        prev = line
    px = bytearray()
    for line in rows:
        for x in range(width):
            s = line[x * channels:(x + 1) * channels]
            if ctype == 6:
                px += s
            elif ctype == 2:
                px += s + (b"\0" if trns[:6] == bytes((0, s[0], 0, s[1], 0, s[2])) else b"\xff")
            elif ctype == 4:
                px += bytes((s[0], s[0], s[0], s[1]))
            elif ctype == 0:
                px += bytes((s[0],) * 3) + (b"\0" if trns[:2] == bytes((0, s[0])) else b"\xff")
            else:
                i = s[0]
                px += (plte[3 * i:3 * i + 3] or b"\0\0\0") + bytes((trns[i] if i < len(trns) else 255,))
    return width, height, bytes(px)


def scale_png(png: bytes, size: int) -> bytes:
    """Return the PNG redrawn at size x size, each pixel taken from the nearest one in the original.

    Nearest-pixel keeps a small icon's hard edges: 16 and 32 pixel icons grow
    by a whole factor and look the same, only bigger.

    Raises:
        ValueError: png_pixels can't read it.
    """
    width, height, rgba = png_pixels(png)
    out = bytearray(size * size * 4)
    for y in range(size):
        sy = y * height // size
        for x in range(size):
            s = (sy * width + x * width // size) * 4
            out[(y * size + x) * 4:(y * size + x) * 4 + 4] = rgba[s:s + 4]
    return _png(size, size, bytes(out))


# the largest icon flatpak build-export accepts ("Image too large (1024x1024). Max. size 512x512")
MAX_ICON = 512


def shrink_png(png: bytes, size: int = MAX_ICON) -> bytes:
    """Return a square PNG scaled down to size x size, each pixel the average of the ones it covers.

    Raises:
        ValueError: png_pixels can't read it.
    """
    width, height, rgba = png_pixels(png)
    out = bytearray(size * size * 4)
    for y in range(size):
        y0, y1 = y * height // size, max(y * height // size + 1, (y + 1) * height // size)
        for x in range(size):
            x0, x1 = x * width // size, max(x * width // size + 1, (x + 1) * width // size)
            acc = [0, 0, 0, 0]
            n = 0
            for sy in range(y0, y1):
                row = sy * width * 4
                for sx in range(x0, x1):
                    i = row + sx * 4
                    a = rgba[i + 3]
                    # weigh colour by opacity, so transparent pixels don't darken the edges
                    acc[0] += rgba[i] * a
                    acc[1] += rgba[i + 1] * a
                    acc[2] += rgba[i + 2] * a
                    acc[3] += a
                    n += 1
            o = (y * size + x) * 4
            if acc[3]:
                out[o:o + 3] = bytes(min(255, c // acc[3]) for c in acc[:3])
            out[o + 3] = acc[3] // n
    return _png(size, size, bytes(out))


def pad_png(png: bytes, width: int, height: int) -> bytes:
    """Return the PNG centred on a transparent width x height canvas (at least its own size).

    Raises:
        ValueError: png_pixels can't read it.
    """
    w, h, rgba = png_pixels(png)
    width, height = max(width, w), max(height, h)
    out = bytearray(width * height * 4)
    left, top = (width - w) // 2, (height - h) // 2
    for y in range(h):
        start = ((top + y) * width + left) * 4
        out[start:start + w * 4] = rgba[y * w * 4:(y + 1) * w * 4]
    return _png(width, height, bytes(out))


def dib_to_png(dib: bytes) -> bytes:
    """Convert an icon's DIB (BITMAPINFOHEADER, XOR bitmap, AND mask) to a PNG.

    Raises:
        ValueError: The bit depth isn't 1, 4, 8, 24 or 32, the size is implausible
            (over 1024 pixels), or the bitmap is shorter than its header says.
    """
    hsize, width, h2, _planes, bpp = struct.unpack_from("<IiiHH", dib, 0)
    height = abs(h2) // 2
    if not (0 < width <= 1024 and 0 < height <= 1024) or hsize < 12 or hsize > len(dib):
        raise ValueError(f"implausible icon size {width}x{height}")
    ncolors = struct.unpack_from("<I", dib, 32)[0] if hsize >= 36 else 0
    if bpp <= 8:
        ncolors = ncolors or (1 << bpp)
    palette = [dib[hsize + 4 * i:hsize + 4 * i + 4] for i in range(ncolors if bpp <= 8 else 0)]
    xor_off = hsize + 4 * len(palette)
    stride = ((width * bpp + 31) // 32) * 4
    and_off = xor_off + stride * height
    and_stride = ((width + 31) // 32) * 4
    has_mask = len(dib) >= and_off + and_stride * height
    alpha_seen = False
    px = bytearray(width * height * 4)
    for y in range(height):
        src = xor_off + (height - 1 - y) * stride          # DIB rows are stored bottom-up
        for x in range(width):
            if bpp == 32:
                b, g, r, a = dib[src + 4 * x:src + 4 * x + 4]
                alpha_seen |= a != 0
            elif bpp == 24:
                b, g, r = dib[src + 3 * x:src + 3 * x + 3]
                a = 255
            elif bpp in (1, 4, 8):
                bit = x * bpp
                idx = (dib[src + bit // 8] >> (8 - bpp - bit % 8)) & ((1 << bpp) - 1)
                b, g, r, _ = palette[idx] if idx < len(palette) else (0, 0, 0, 0)
                a = 255
            else:
                raise ValueError(f"unsupported icon bit depth {bpp}")
            o = (y * width + x) * 4
            px[o:o + 4] = bytes((r, g, b, a))
    if has_mask and not alpha_seen:   # older icons take transparency from the AND mask
        for y in range(height):
            src = and_off + (height - 1 - y) * and_stride
            for x in range(width):
                if dib[src + x // 8] >> (7 - x % 8) & 1:
                    px[(y * width + x) * 4 + 3] = 0
    return _png(width, height, bytes(px))


def extract_png(exe: str | Path) -> bytes | None:
    """Return the largest icon in a .exe as PNG bytes, or None if it has none or it can't be read."""
    try:
        imgs = icon_images(exe)
        if not imgs:
            return None
        _w, _bits, raw = max(imgs, key=lambda t: (t[0], t[1]))
        return raw if raw.startswith(b"\x89PNG") else dib_to_png(raw)
    except (PeError, ValueError, struct.error, OSError):
        return None


def _parse_block(data: bytes, off: int, end: int, out: dict[str, str], depth: int = 0) -> None:
    """Walk a VS_VERSIONINFO block and its children, collecting String key/value pairs."""
    while off + 6 <= end:
        length, value_len, is_text = struct.unpack_from("<HHH", data, off)
        if length < 6:
            return
        block_end = min(off + length, end)
        k = off + 6
        key_end = k
        while key_end + 1 < block_end and data[key_end:key_end + 2] != b"\0\0":
            key_end += 2
        key = data[k:key_end].decode("utf-16-le", "replace")
        v = (key_end + 2 + 3) & ~3
        # VS_VERSIONINFO > StringFileInfo > table > String. Some compilers write
        # wType=0 on these, but a String's value is always text.
        if depth == 3 and value_len:
            raw = data[v:min(v + 2 * value_len, block_end)]
            out.setdefault(key, raw.decode("utf-16-le", "replace").split("\0")[0].strip())
        else:
            child = v + (value_len if depth == 0 else 2 * value_len if is_text else value_len)
            child = (child + 3) & ~3
            if depth < 3 and key != "VarFileInfo":
                _parse_block(data, child, block_end, out, depth + 1)
        off = (off + length + 3) & ~3


def version_strings(exe: str | Path) -> dict[str, str]:
    """Return a .exe's version strings (ProductName, ProductVersion, CompanyName, FileDescription ...).

    The first string table wins when there are several languages. A file
    without a version resource, or one that can't be read, gives {}.
    """
    try:
        data = Path(exe).read_bytes()
        img, leaves = _resources(data)
        ver = next(((rva, size) for path, rva, size in leaves if path[0] == RT_VERSION), None)
        if not ver:
            return {}
        o = img.off(ver[0])
        out: dict[str, str] = {}
        _parse_block(data, o, o + ver[1], out)
        return {k: v for k, v in out.items() if v}
    except (PeError, struct.error, IndexError, OSError):
        return {}
