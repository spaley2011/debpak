"""Pin down behaviour of winres, unpack and foreign that the other tests reach only in part.

These were written when those modules' larger functions were split into
helpers: PNG row filters and colour types, DIB bit depths, version-resource
walking, the laziness of unpack's resource reader, and unpack's step errors.
"""
from __future__ import annotations

import inspect
import io
import json
import shutil
import struct
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

from debpak import foreign, unpack, winres
from debpak.pe_write import PeSpec, build_pe, version_info

CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}


def chunk(tag: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + tag + body + struct.pack(">I", zlib.crc32(tag + body) & 0xFFFFFFFF)


def predictor(kind: int, a: int, b: int, c: int) -> int:
    """PNG's prediction for filter kind from the left (a), above (b) and above-left (c) bytes."""
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    paeth = a if pa <= pb and pa <= pc else b if pb <= pc else c
    return [0, a, b, (a + b) // 2, paeth][kind]


def encode(width: int, height: int, ctype: int, pixels: bytes, filters: list[int], extra: bytes = b"") -> bytes:
    """Return an 8-bit PNG of colour type ctype whose rows use the given filters in turn."""
    ch = CHANNELS[ctype]
    stride, raw, prev = width * ch, bytearray(), bytes(width * ch)
    for y in range(height):
        line, kind = pixels[y * stride:(y + 1) * stride], filters[y % len(filters)]
        raw.append(kind)
        for i, v in enumerate(line):
            a = line[i - ch] if i >= ch else 0
            c = prev[i - ch] if i >= ch else 0
            raw.append((v - predictor(kind, a, prev[i], c)) & 0xFF)
        prev = line
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, ctype, 0, 0, 0)) + extra
            + chunk(b"IDAT", zlib.compress(bytes(raw))) + chunk(b"IEND", b""))


def rgba_of(ctype: int, s: bytes) -> bytes:
    """Return one pixel as RGBA, for an image with no tRNS whose palette entry i is bytes 3i, 3i+1, 3i+2."""
    if ctype == 6:
        return s
    if ctype == 2:
        return s + b"\xff"
    if ctype == 4:
        return bytes((s[0],) * 3 + (s[1],))
    if ctype == 0:
        return bytes((s[0],) * 3) + b"\xff"
    return bytes(range(3 * s[0], 3 * s[0] + 3)) + b"\xff"


class PngTests(unittest.TestCase):
    def test_every_filter_and_colour_type(self):
        w, h = 5, 6
        for ctype, ch in CHANNELS.items():
            px = bytes((x * 53 + y * 31 + k * 97) % 256 for y in range(h) for x in range(w) for k in range(ch))
            if ctype == 3:
                px = bytes(v % 4 for v in px)
            plte = chunk(b"PLTE", bytes(range(12))) if ctype == 3 else b""
            for filters in ([0], [1], [2], [3], [4], [4, 3, 2, 1, 0]):
                with self.subTest(ctype=ctype, filters=filters):
                    _w, _h, rgba = winres.png_pixels(encode(w, h, ctype, px, filters, plte))
                    want = b"".join(rgba_of(ctype, px[i * ch:(i + 1) * ch]) for i in range(w * h))
                    self.assertEqual(rgba, want)

    def test_transparency_chunks(self):
        rgb = encode(2, 1, 2, b"\x01\x02\x03\x04\x05\x06", [1], chunk(b"tRNS", b"\x00\x04\x00\x05\x00\x06"))
        self.assertEqual(winres.png_pixels(rgb)[2], b"\x01\x02\x03\xff\x04\x05\x06\x00")
        grey = encode(2, 1, 0, b"\x07\x08", [4], chunk(b"tRNS", b"\x00\x08"))
        self.assertEqual(winres.png_pixels(grey)[2], b"\x07\x07\x07\xff\x08\x08\x08\x00")
        # past the end of tRNS a palette entry is opaque, and past the end of PLTE it's black
        pal = encode(3, 1, 3, b"\x00\x01\x05", [2], chunk(b"PLTE", b"\x0a\x0b\x0c\x0d\x0e\x0f") + chunk(b"tRNS", b"\x80"))
        self.assertEqual(winres.png_pixels(pal)[2], b"\x0a\x0b\x0c\x80\x0d\x0e\x0f\xff\x00\x00\x00\xff")

    def test_bad_filter(self):
        png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))
               + chunk(b"IDAT", zlib.compress(b"\x05\x00")) + chunk(b"IEND", b""))
        with self.assertRaisesRegex(ValueError, r"^damaged PNG: filter 5$"):
            winres.png_pixels(png)

    def test_shrink_weighs_by_opacity(self):
        # a 2x2 of one opaque red pixel and three transparent white ones averages to red, a quarter opaque
        png = winres._png(2, 2, b"\xff\x00\x00\xff" + b"\xff\xff\xff\x00" * 3)
        self.assertEqual(winres.png_pixels(winres.shrink_png(png, 1))[2], b"\xff\x00\x00\x3f")


def dib(bpp: int, width: int, height: int, palette: bytes, xor: bytes, mask: bytes) -> bytes:
    """Return an icon DIB: header (its colour count from the palette's length), palette, XOR bitmap, AND mask."""
    head = struct.pack("<IiiHHIIiiII", 40, width, height * 2, 1, bpp, 0, 0, 0, 0, len(palette) // 4, 0)
    return head + palette + xor + mask


class DibTests(unittest.TestCase):
    def test_bit_depths_and_mask(self):
        # 2x2, rows stored bottom-up, each padded to 4 bytes; the AND mask clears the top-left pixel
        mask = b"\x00\x00\x00\x00" + b"\x80\x00\x00\x00"
        pal = b"\x00\x00\xff\x00" + b"\x00\xff\x00\x00"           # BGRx: red, green
        cases = {
            1: (pal, b"\x40\x00\x00\x00" + b"\x80\x00\x00\x00"),
            4: (pal, b"\x01\x00\x00\x00" + b"\x10\x00\x00\x00"),
            8: (pal, b"\x00\x01\x00\x00" + b"\x01\x00\x00\x00"),
            24: (b"", b"\x00\x00\xff\x00\xff\x00\x00\x00" + b"\x00\xff\x00\x00\x00\xff\x00\x00"),
        }
        want = b"\x00\xff\x00\x00" + b"\xff\x00\x00\xff" + b"\xff\x00\x00\xff" + b"\x00\xff\x00\xff"
        for bpp, (palette, xor) in cases.items():
            with self.subTest(bpp=bpp):
                self.assertEqual(winres.png_pixels(winres.dib_to_png(dib(bpp, 2, 2, palette, xor, mask)))[2], want)

    def test_alpha_wins_over_mask(self):
        xor = b"\x01\x02\x03\x80" * 4
        out = winres.png_pixels(winres.dib_to_png(dib(32, 2, 2, b"", xor, b"\xff" * 8)))[2]
        self.assertEqual(out, b"\x03\x02\x01\x80" * 4)

    def test_errors(self):
        with self.assertRaisesRegex(ValueError, "unsupported icon bit depth 16"):
            winres.dib_to_png(dib(16, 2, 2, b"", bytes(16), b""))
        with self.assertRaisesRegex(ValueError, "implausible icon size 0x2"):
            winres.dib_to_png(dib(32, 0, 2, b"", b"", b""))


class VersionTests(unittest.TestCase):
    def test_first_value_wins_and_var_file_info_is_skipped(self):
        _typ, _id, data = version_info({"ProductName": "Acme", "CompanyName": "", "Comments": "a\0b"})
        out: dict[str, str] = {}
        winres._parse_block(data, 0, len(data), out)
        self.assertEqual(out, {"ProductName": "Acme", "CompanyName": "", "Comments": "a"})
        # a String written with wType=0 is still read as text
        patched = bytearray(data)
        at = patched.find("ProductName".encode("utf-16-le")) - 6
        patched[at + 4:at + 6] = b"\0\0"
        out = {}
        winres._parse_block(bytes(patched), 0, len(patched), out)
        self.assertEqual(out["ProductName"], "Acme")


class UnpackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="debpak-refactor-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def zip(self, entries: dict[str, bytes]) -> Path:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for n, d in entries.items():
                z.writestr(n, d)
        path = self.tmp / "a.zip"
        path.write_bytes(buf.getvalue())
        return path

    def test_resource_blobs_is_lazy(self):
        # a damaged file fails only once read, inside squirrel_nupkg's handler
        gen = unpack._resource_blobs(b"MZ")
        self.assertTrue(inspect.isgenerator(gen))
        with self.assertRaises(struct.error):
            next(gen)
        self.assertIsNone(unpack.squirrel_nupkg(b"MZ"))
        nupkg = io.BytesIO()
        with zipfile.ZipFile(nupkg, "w") as z:
            z.writestr("acme.nuspec", "<package/>")
        data = build_pe(PeSpec(is_dll=False, imports={"kernel32.dll": ["ExitProcess"]},
                               resources=[(10, 131, nupkg.getvalue()), (10, 132, b"second")]))
        gen = unpack._resource_blobs(data)
        self.assertEqual(next(gen), nupkg.getvalue())
        self.assertEqual(list(gen), [b"second"])
        self.assertEqual(unpack.squirrel_nupkg(data), nupkg.getvalue())

    def test_step_errors(self):
        src = self.zip({"in/inner.zip": b"x", "in/a.txt": b"a"})
        cases = [
            ([{"kind": "nope"}], "unknown step 'nope'"),
            ([{}], "unknown step None"),
            ([{"kind": "zip"}, {"kind": "zip"}], "only the last step may leave a folder"),
            ([{"kind": "zip", "inner": "../a.zip"}], "../a.zip isn't in the unpacked files"),
            ([{"kind": "zip", "inner": "in"}], "in isn't in the unpacked files"),
            ([{"kind": "squirrel"}], "no .nupkg in this Setup.exe"),
            ([{"kind": "7z", "offset": 2}], "no 7z archive at offset 2"),
        ]
        for n, (steps, msg) in enumerate(cases):
            with self.subTest(steps=steps):
                with self.assertRaises(unpack.UnpackError) as cm:
                    unpack.unpack(src, steps, self.tmp / f"w{n}")
                self.assertEqual(str(cm.exception), msg)
        out = unpack.unpack(src, [{"kind": "zip", "inner": "in/a.txt"}, {"kind": "copy", "name": "c"}], self.tmp / "ok")
        self.assertEqual(out, self.tmp / "ok/step1")
        self.assertEqual((out / "c").read_bytes(), b"a")

    def test_unzip_entries(self):
        src = self.zip({"dir\\b.txt": b"b", "/": b"", "ok.txt": b"o"})
        unpack.unzip(src, self.tmp / "u")
        self.assertEqual(sorted(p.relative_to(self.tmp / "u").as_posix() for p in (self.tmp / "u").rglob("*")),
                         ["dir", "dir/b.txt", "ok.txt"])
        with self.assertRaisesRegex(unpack.UnpackError, "unsafe path '../evil'"):
            unpack.unzip(self.zip({"../evil": b"x"}), self.tmp / "v")

    def test_asar_entries(self):
        header = {"files": {"lib": {"files": {"a.node": {"size": 1, "offset": "0", "integrity": {}}}},
                            "f": {"size": 1, "offset": "1"}}}
        self.assertIs(unpack._asar_entry(header, "lib/a.node", False, "app.asar"), header["files"]["lib"]["files"]["a.node"])
        for p, create, msg in [("lib/b.node", False, "lib/b.node isn't in app.asar"),
                               ("x/y", False, "x/y isn't in app.asar"),
                               ("f/y", True, "f/y: f is a file in app.asar"),
                               ("lib", True, "lib is a folder in app.asar"),
                               ("a/../b", True, "bad asar path 'a/../b'")]:
            with self.subTest(p=p), self.assertRaises(unpack.UnpackError) as cm:
                unpack._asar_entry(json.loads(json.dumps(header)), p, create, "app.asar")
            self.assertEqual(str(cm.exception), msg)
        made = json.loads(json.dumps(header))
        self.assertEqual(unpack._asar_entry(made, "new/dir/n.node", True, "app.asar"), {})
        self.assertEqual(made["files"]["new"], {"files": {"dir": {"files": {"n.node": {}}}}})


class ForeignTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="debpak-refactor-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_msix_info_first_of_each_wins(self):
        (self.tmp / "AppxManifest.xml").write_text(
            '<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">'
            '<Identity Name="Acme.Notes" Version="1.2.0.0" ProcessorArchitecture="x64"/><Identity Name="Other"/>'
            '<Properties><DisplayName>ms-resource:Name</DisplayName><Description/></Properties>'
            '<DisplayName>Later</DisplayName><Description>Notes</Description>'
            '<Applications><Application Executable="App\\Acme.exe"/><Application Executable="b.exe"/></Applications>'
            '</Package>')
        self.assertEqual(foreign._msix_info(self.tmp), {"version": "1.2.0.0", "arch": "x64", "id": "Acme.Notes",
                                                        "name": "Acme.Notes", "description": "Notes",
                                                        "exe": "App/Acme.exe"})

    def test_detect_zip_kinds(self):
        def z(name: str, entries: dict[str, bytes]) -> Path:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                for n, d in entries.items():
                    zf.writestr(n, d)
            (self.tmp / name).write_bytes(buf.getvalue())
            return self.tmp / name
        self.assertEqual(foreign.detect(z("a.zip", {"top/app.exe": b"MZ"})), "windows")
        self.assertIsNone(foreign.detect(z("b.zip", {"top/app.exe": b"MZ", "top/prog": b"\x7fELF"})))
        self.assertIsNone(foreign.detect(z("c.zip", {"x/a/b/c.exe": b"MZ", "run.sh": b"#!"})))
        self.assertEqual(foreign.detect(z("d.zip", {"x/a/b/c.exe": b"MZ", "x/a/b/c/run.sh": b"#!"})), "windows")
        self.assertEqual(foreign.detect(z("e.zip", {"A.app/Contents/Info.plist": b""})), "macapp")
        (self.tmp / "bad.zip").write_bytes(b"PK\3\4junk")
        self.assertIsNone(foreign.detect(self.tmp / "bad.zip"))
        self.assertIsNone(foreign.detect(self.tmp / "missing"))
        self.assertEqual(foreign.detect(self.tmp / "e.zip"), "macapp")

    def test_icns_entries(self):
        def png(w: int) -> bytes:
            return b"\x89PNG\r\n\x1a\n" + struct.pack(">I4sII", 13, b"IHDR", w, w)
        body = b"".join(b"ic08" + struct.pack(">I", len(p) + 8) + p for p in (png(1024), png(256), b"jp2", png(32)))
        (self.tmp / "a.icns").write_bytes(b"icns" + struct.pack(">I", 0) + body + b"ic09\0\0\0\0" + png(64))
        self.assertEqual(foreign.icns_png(self.tmp / "a.icns"), png(256))
        self.assertEqual(foreign.icns_png(self.tmp / "a.icns", limit=16), png(32))


if __name__ == "__main__":
    unittest.main()
