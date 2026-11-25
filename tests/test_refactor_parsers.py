"""Round-trip checks for the Mach-O reader and the PE writer's import and export tables.

These pin down what the parsers return for each load command and table kind, so
restructuring them can't quietly change a result.
"""
from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from compat_fixtures import build_macho, fat

from debpak.macho import MachOError, read_macho
from debpak.pe import read_pe
from debpak.pe_write import PeSpec, build_pe

LC_DYLD_EXPORTS_TRIE = 0x80000033


def _without_trie(data: bytes) -> bytes:
    """Turn a 64-bit little-endian Mach-O's LC_DYLD_EXPORTS_TRIE into a command the reader ignores."""
    out = bytearray(data)
    ncmds = struct.unpack_from("<I", out, 16)[0]
    off = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", out, off)
        if cmd == LC_DYLD_EXPORTS_TRIE:
            struct.pack_into("<I", out, off, 0x7F)
        off += size
    return bytes(out)


class MachOTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _read(self, data: bytes):
        p = self.tmp / "bin"
        p.write_bytes(data)
        return read_macho(p)

    def test_fat_executable(self) -> None:
        dylibs = [("/usr/lib/libSystem.B.dylib", "load"), ("/opt/Weak.dylib", "weak"),
                  ("/opt/Re.dylib", "reexport")]
        undefined = [("_printf", 1, False), ("_maybe", 2, True)]
        slices = {a: build_macho(a, "execute", dylibs=dylibs, undefined=undefined, rpaths=["@executable_path/../lib"],
                                 platform=1, minos=(11, 3)) for a in ("x86_64", "arm64")}
        m = self._read(fat(slices))
        self.assertEqual(m.archs, ["x86_64", "arm64"])
        s = m.slice("arm64")
        assert s is not None
        self.assertEqual(s.filetype, "execute")
        self.assertTrue(s.twolevel)
        self.assertTrue(s.has_main)
        self.assertEqual((s.platform, s.min_os), ("macos", "11.3"))
        self.assertEqual([(d.name, d.kind, d.weak) for d in s.dylibs],
                         [("/usr/lib/libSystem.B.dylib", "load", False), ("/opt/Weak.dylib", "weak", True),
                          ("/opt/Re.dylib", "reexport", False)])
        self.assertEqual(s.rpaths, ["@executable_path/../lib"])
        self.assertEqual([(u.name, u.ordinal, u.weak) for u in s.undefined],
                         [("_printf", 1, False), ("_maybe", 2, True)])
        lib = s.library_for(s.undefined[1])
        self.assertEqual(lib.name if lib else None, "/opt/Weak.dylib")
        self.assertEqual(s.exports, set())

    def test_dylib_exports_from_trie_and_from_symbol_table(self) -> None:
        data = build_macho("x86_64", "dylib", install_name="/usr/lib/libx.dylib",
                           exports=["_a", "_ab", "_abc", "_b"], undefined=[("_u", 1, False)], platform=2, minos=(14, 0))
        s = self._read(data).slices[0]
        self.assertEqual(s.install_name, "/usr/lib/libx.dylib")
        self.assertFalse(s.has_main)
        self.assertEqual((s.platform, s.min_os), ("ios", "14.0"))
        self.assertEqual(s.exports, {"_a", "_ab", "_abc", "_b"})
        self.assertEqual(s.reexported_names, set())
        # without the trie, the symbol table's defined symbols are the exports
        s2 = self._read(_without_trie(data)).slices[0]
        self.assertEqual(s2.exports, {"_a", "_ab", "_abc", "_b"})
        self.assertEqual([u.name for u in s2.undefined], ["_u"])

    def test_damaged_files(self) -> None:
        data = build_macho("x86_64", "dylib", install_name="/x", exports=["_a"])
        for cut in (0, 4, 20, 40, len(data) // 2):
            with self.subTest(cut=cut), self.assertRaises(MachOError):
                self._read(data[:cut])
        bad = bytearray(data)
        struct.pack_into("<I", bad, 32 + 4, 4)          # first load command claims 4 bytes
        with self.assertRaisesRegex(MachOError, "bad load command size"):
            self._read(bytes(bad))
        with self.assertRaisesRegex(MachOError, "bad Mach-O magic"):
            self._read(b"\x01\x02\x03\x04" + bytes(60))


class PeWriterTest(unittest.TestCase):
    def _read(self, spec: PeSpec):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.dll"
            p.write_bytes(build_pe(spec))
            return read_pe(p)

    def test_imports_and_delay_imports(self) -> None:
        for arch in ("x86_64", "i386", "arm64"):
            with self.subTest(arch=arch):
                info = self._read(PeSpec(arch=arch, is_dll=False,
                                         imports={"kernel32.dll": ["ExitProcess", 17], "user32.dll": ["MessageBoxW"]},
                                         delay_imports={"ws2_32.dll": ["socket", 23]}))
                self.assertFalse(info.problems)
                self.assertEqual(sorted((i.dll, i.label, i.delay) for i in info.imports),
                                 [("kernel32.dll", "#17", False), ("kernel32.dll", "ExitProcess", False),
                                  ("user32.dll", "MessageBoxW", False), ("ws2_32.dll", "#23", True),
                                  ("ws2_32.dll", "socket", True)])

    def test_named_and_ordinal_exports(self) -> None:
        info = self._read(PeSpec(dll_name="mix.dll", exports=["b", "a", "a"], export_ordinals=[1, 5]))
        self.assertEqual(info.dll_name, "mix.dll")
        self.assertEqual(info.exports, {"a": 2, "b": 3})   # named exports skip the ordinal-only 1
        self.assertEqual(info.ordinals, {1, 2, 3, 5})

    def test_dotnet(self) -> None:
        info = self._read(PeSpec(is_dll=False, dotnet=True, clr_flags=0, type_refs=[("System", "Form")]))
        self.assertTrue(info.is_dotnet)
        self.assertEqual(info.clr_flags, 0)
        self.assertEqual([(i.dll, i.name) for i in info.imports], [("mscoree.dll", "_CorExeMain")])


if __name__ == "__main__":
    unittest.main()
