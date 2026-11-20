"""A fake Linux desktop for appbridge tests: a home directory, a PATH of stub
tools, and helpers that 'install' Office, Adobe and VM apps the way their
projects lay them out on disk."""
from __future__ import annotations

import struct
from pathlib import Path

from debpak.appbridge.host import Host


class FakeDesktop:
    def __init__(self, root: Path, desktop: str = "KDE"):
        self.root = root
        self.home = root / "home"
        self.bin = root / "bin"
        self.home.mkdir()
        self.bin.mkdir()
        self.calls = root / "calls.log"
        self.env = {"HOME": str(self.home), "PATH": str(self.bin), "XDG_CURRENT_DESKTOP": desktop,
                    "XDG_SESSION_TYPE": "wayland", "APPBRIDGE_FLATPAK_SYSTEM_DIR": str(root / "sysflatpak")}

    def host(self) -> Host:
        return Host(env=dict(self.env), checkout=None)

    def tool(self, name: str, body: str = "") -> Path:
        """A stub program that logs its arguments."""
        p = self.bin / name
        p.write_text(f'#!/bin/sh\necho "{name} $*" >> "{self.calls}"\n{body}\n')
        p.chmod(0o755)
        return p

    def put(self, rel: str, data: bytes = b"") -> Path:
        p = self.home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    # ---------------------------------------------------------------- installs
    def office(self, exe: str = "WINWORD.EXE", pfx: bool = False, data: bytes = b"MZ") -> Path:
        root = ".local/share/ms365/prefix" + ("/pfx" if pfx else "")
        return self.put(f"{root}/drive_c/Program Files/Microsoft Office/root/Office16/{exe}", data)

    def adobe(self, folder: str, exe: str, base: str = ".local/share/adobewine", data: bytes = b"MZ") -> Path:
        return self.put(f"{base}/prefix/drive_c/Program Files/Adobe/{folder}/{exe}", data)

    def winapps(self, *names: str) -> None:
        self.tool("winapps")
        self.put(".config/winapps/winapps.conf", b'RDP_USER="me"\n')
        for n in names:
            self.put(f".local/share/winapps/apps/{n}/info", b"NAME=x\n")
            self.put(f".local/share/winapps/apps/{n}/icon.svg", b"<svg/>")

    def flatpak_app(self, app_id: str, system: bool = False) -> None:
        base = (self.root / "sysflatpak") if system else (self.home / ".local/share/flatpak/app")
        (base / app_id / "current").mkdir(parents=True)


# ---------------------------------------------------------------- a PE with an icon

def _dib32(w: int, h: int, top_left: tuple, rest: tuple) -> bytes:
    """32-bit BGRA icon DIB, stored bottom-up, with an AND mask."""
    hdr = struct.pack("<IiiHHIIiiII", 40, w, h * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    rows = []
    for y in range(h - 1, -1, -1):              # bottom-up
        row = b""
        for x in range(w):
            r, g, b, a = top_left if (x, y) == (0, 0) else rest
            row += bytes((b, g, r, a))
        rows.append(row)
    mask = b"\0" * (((w + 31) // 32) * 4 * h)
    return hdr + b"".join(rows) + mask


def _dib8_masked(w: int, h: int) -> bytes:
    """8-bit paletted icon whose transparency comes only from the AND mask."""
    hdr = struct.pack("<IiiHHIIiiII", 40, w, h * 2, 1, 8, 0, 0, 0, 0, 2, 0)
    palette = bytes((0, 0, 255, 0)) + bytes((255, 0, 0, 0))     # index 0 red, 1 blue (BGRx)
    stride = ((w * 8 + 31) // 32) * 4
    xor = b"".join((bytes([1] * w) + b"\0" * (stride - w)) for _ in range(h))
    and_stride = ((w + 31) // 32) * 4
    # DIB rows are bottom-up: the first stored mask row is the image's bottom row; make it transparent
    mask_rows = [b"\xff" * and_stride] + [b"\0" * and_stride] * (h - 1)
    return hdr + palette + xor + b"".join(mask_rows)


def build_pe_with_icons(images: list[bytes]) -> bytes:
    """x86_64 PE whose .rsrc holds RT_ICON entries 1..n and one RT_GROUP_ICON."""
    sect_rva, sect_raw = 0x1000, 0x200
    # group directory
    grp = struct.pack("<HHH", 0, 1, len(images))
    for i, img in enumerate(images, 1):
        if img.startswith(b"\x89PNG"):
            w = struct.unpack_from(">I", img, 16)[0]
            bits = 32
        else:
            w, bits = struct.unpack_from("<i", img, 4)[0], struct.unpack_from("<H", img, 14)[0]
        grp += struct.pack("<BBBBHHIH", w % 256, w % 256, 0, 0, 1, bits, len(img), i)

    def directory(entries):          # entries: [(id, offset, is_dir)]
        out = struct.pack("<IIHHHH", 0, 0, 0, 0, 0, len(entries))
        for ident, off, is_dir in entries:
            out += struct.pack("<II", ident, off | (0x80000000 if is_dir else 0))
        return out

    # layout: root, type dirs, name dirs, lang dirs, data entries, then data
    leaves = [(3, i, img) for i, img in enumerate(images, 1)] + [(14, 1, grp)]
    root_size = 16 + 8 * 2
    type_dirs_off = root_size
    n_icons = len(images)
    type3_size = 16 + 8 * n_icons
    type14_size = 16 + 8
    name_off = type_dirs_off + type3_size + type14_size
    lang_dir_size = 16 + 8
    data_entry_off = name_off + lang_dir_size * len(leaves)
    data_off = data_entry_off + 16 * len(leaves)

    blob_parts, data_entries, cur = [], [], data_off
    for _t, _i, payload in leaves:
        cur = (cur + 7) & ~7
        data_entries.append((cur, len(payload)))
        blob_parts.append((cur, payload))
        cur += len(payload)
    total = cur

    rsrc = bytearray(total)
    rsrc[0:root_size] = directory([(3, type_dirs_off, True), (14, type_dirs_off + type3_size, True)])
    rsrc[type_dirs_off:type_dirs_off + type3_size] = directory(
        [(i, name_off + lang_dir_size * (i - 1), True) for i in range(1, n_icons + 1)])
    rsrc[type_dirs_off + type3_size:name_off] = directory([(1, name_off + lang_dir_size * n_icons, True)])
    for k in range(len(leaves)):
        o = name_off + lang_dir_size * k
        rsrc[o:o + lang_dir_size] = directory([(1033, data_entry_off + 16 * k, False)])
        off, size = data_entries[k]
        rsrc[data_entry_off + 16 * k:data_entry_off + 16 * k + 16] = struct.pack("<IIII", sect_rva + off, size, 0, 0)
    for off, payload in blob_parts:
        rsrc[off:off + len(payload)] = payload
    raw_size = (len(rsrc) + 0x1FF) & ~0x1FF
    rsrc += b"\0" * (raw_size - len(rsrc))

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x22)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<Q", opt, 24, 0x140000000)
    struct.pack_into("<II", opt, 32, 0x1000, 0x200)
    struct.pack_into("<I", opt, 56, sect_rva + ((raw_size + 0xFFF) & ~0xFFF))
    struct.pack_into("<I", opt, 60, sect_raw)
    struct.pack_into("<H", opt, 68, 2)
    struct.pack_into("<I", opt, 108, 16)
    struct.pack_into("<II", opt, 112 + 8 * 2, sect_rva, total)
    sec = struct.pack("<8sIIIIIIHHI", b".rsrc", total, sect_rva, raw_size, sect_raw, 0, 0, 0, 0, 0x40000040)
    head = bytes(dos) + b"PE\0\0" + coff + bytes(opt) + sec
    head += b"\0" * (sect_raw - len(head))
    return head + bytes(rsrc)
