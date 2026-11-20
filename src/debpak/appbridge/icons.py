"""Extract an app's own icon from its Windows .exe (RT_GROUP_ICON / RT_ICON
resources) and save the largest image as a PNG. Pure Python, like the rest of
debpak; used so menu entries show the real Word or Photoshop icon from the
copy you installed."""
from __future__ import annotations

import struct
import zlib
from pathlib import Path

from ..pe import PeError, _Image

DIR_RESOURCE = 2
RT_ICON, RT_GROUP_ICON = 3, 14


def _walk(img: _Image, m, base: int, rva: int, depth: int, path: tuple, out: list) -> None:
    """Collect (type, name, lang) -> (data_rva, size) leaves of the resource tree."""
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


def icon_images(exe: str | Path) -> list[tuple[int, int, bytes]]:
    """(width, bit_count, raw RT_ICON bytes) for the first icon group in the file."""
    data = Path(exe).read_bytes()
    if data[:2] != b"MZ":
        raise PeError(f"{exe}: not a PE file")
    try:
        img = _Image(data)
        rsrc = img.dirs[DIR_RESOURCE][0]
        if not rsrc:
            return []
        leaves: list = []
        _walk(img, data, rsrc, rsrc, 0, (), leaves)
        icons = {path[1]: (rva, size) for path, rva, size in leaves if path[0] == RT_ICON}
        groups = [(rva, size) for path, rva, size in leaves if path[0] == RT_GROUP_ICON]
        if not groups:
            return []
        g = img.off(groups[0][0])
        _res, typ, count = struct.unpack_from("<HHH", data, g)
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


def dib_to_png(dib: bytes) -> bytes:
    """Convert an icon's DIB (BITMAPINFOHEADER + XOR bitmap + AND mask) to PNG."""
    hsize, width, h2, _planes, bpp = struct.unpack_from("<IiiHH", dib, 0)
    height = abs(h2) // 2
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
        src = xor_off + (height - 1 - y) * stride          # DIB rows are bottom-up
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
    if has_mask and not alpha_seen:   # older icons: transparency comes from the AND mask
        for y in range(height):
            src = and_off + (height - 1 - y) * and_stride
            for x in range(width):
                if dib[src + x // 8] >> (7 - x % 8) & 1:
                    px[(y * width + x) * 4 + 3] = 0
    return _png(width, height, bytes(px))


def extract_png(exe: str | Path) -> bytes | None:
    """The best icon in the .exe as PNG bytes, or None if it has none."""
    imgs = icon_images(exe)
    if not imgs:
        return None
    w, bits, raw = max(imgs, key=lambda t: (t[0], t[1]))
    if raw.startswith(b"\x89PNG"):
        return raw
    return dib_to_png(raw)


def png_size(png: bytes) -> tuple[int, int]:
    return struct.unpack_from(">II", png, 16)
