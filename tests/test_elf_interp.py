"""Pointing a program at the runtime's loader."""
import struct
import tempfile
import unittest
from pathlib import Path

from debpak.elf import read_elf, set_interpreter


def program(interp: str, filesz: int | None = None, pad: int = 0) -> bytes:
    """A minimal 64-bit ELF executable header with one PT_INTERP segment.

    filesz overrides the segment's size field (a damaged header); pad adds NULs after the path, inside it.
    """
    data = interp.encode() + b"\0" + bytes(pad)
    ehdr = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    ehdr += struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    size = len(data) if filesz is None else filesz
    phdr = struct.pack("<IIQQQQQQ", 3, 4, 120, 0, 0, size, size, 1)
    return ehdr + phdr + data


class TestInterp(unittest.TestCase):
    def test_snap_loader_becomes_the_runtimes(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "alacritty"
            p.write_bytes(program("/snap/core22/current/lib64/ld-linux-x86-64.so.2"))
            self.assertTrue(set_interpreter(p, "/lib64/ld-linux-x86-64.so.2"))
            self.assertEqual(read_elf(p, want_symbols=False).interp, "/lib64/ld-linux-x86-64.so.2")

    def test_longer_loader_doesnt_fit(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "x"
            p.write_bytes(program("/lib/ld.so"))
            self.assertFalse(set_interpreter(p, "/lib64/ld-linux-x86-64.so.2"))

    def test_longer_loader_fits_in_the_segments_padding(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "x"
            p.write_bytes(program("/lib/ld.so", pad=40))
            self.assertTrue(set_interpreter(p, "/lib64/ld-linux-x86-64.so.2"))
            self.assertEqual(read_elf(p, want_symbols=False).interp, "/lib64/ld-linux-x86-64.so.2")

    def test_damaged_size_only_replaces_the_path(self):
        # a p_filesz far past the path used to have the padding zero what followed it
        # (the program's version tables: "unsupported version 0 of Verneed record") or,
        # past the end of the file, grow it by as much
        snap = "/snap/core22/current/lib64/ld-linux-x86-64.so.2"
        for filesz in (len(snap) + 1 + 64, 64 << 20, 1 << 62):
            with self.subTest(filesz=filesz), tempfile.TemporaryDirectory() as t:
                p = Path(t) / "x"
                before = program(snap, filesz=filesz) + b"VERSION-TABLES" * 8
                p.write_bytes(before)
                self.assertTrue(set_interpreter(p, "/lib64/ld-linux-x86-64.so.2"))
                after = p.read_bytes()
                self.assertEqual(len(after), len(before))
                self.assertEqual(after[120 + len(snap) + 1:], before[120 + len(snap) + 1:])
                self.assertEqual(read_elf(p, want_symbols=False).interp, "/lib64/ld-linux-x86-64.so.2")

    def test_unterminated_path_is_left_alone(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "x"
            before = program("/snap/core22/current/lib64/ld-linux-x86-64.so.2")[:-1]
            p.write_bytes(before)
            self.assertFalse(set_interpreter(p, "/lib64/ld-linux-x86-64.so.2"))
            self.assertEqual(p.read_bytes(), before)



class TestRelocate(unittest.TestCase):
    def test_webkit_helper_path(self):
        import re
        from debpak.stage import relocate_strings
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "libwebkit2gtk-4.0.so.37"
            old = b"\0/usr/lib/x86_64-linux-gnu/webkit2gtk-4.0\0x\0/usr/lib/x86_64-linux-gnu/webkit2gtk-4.0/injected-bundle/\0"
            p.write_bytes(b"head" + old + b"tail")
            n = relocate_strings(p, re.compile(rb"/usr/lib/(?:[\w-]+-linux-gnu/)?webkit2gtk-4\.0"),
                                 b"/app/lib/debpak/webkit2gtk-4.0")
            data = p.read_bytes()
            self.assertEqual(n, 2)
            self.assertEqual(len(data), len(old) + 8)
            self.assertIn(b"\0/app/lib/debpak/webkit2gtk-4.0\0", data)
            self.assertIn(b"\0/app/lib/debpak/webkit2gtk-4.0/injected-bundle/\0", data)


class TestElectronVersion(unittest.TestCase):
    def test_major_from_the_binary(self):
        from debpak.stage import electron_major
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "playme"
            p.write_bytes(b"\0" * 5000 + b"Chrome/61.0.3163.100 Electron/2.0.7\0" + b"\0" * 100)
            self.assertEqual(electron_major(p), 2)


if __name__ == "__main__":
    unittest.main()


def library_with_symbols(syms) -> bytes:
    """A 64-bit ET_DYN with .text at 0x1000, .data at 0x2000 and a .dynsym of (type, shndx, value)."""
    table = bytes(24) + b"".join(struct.pack("<IBBHQQ", 1, 0x10 | t, 0, ndx, v, 4) for t, ndx, v in syms)
    sym_off = 64
    sh_off = sym_off + len(table)
    ehdr = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    ehdr += struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0, 0, sh_off, 0, 64, 56, 0, 64, 4, 0)
    shdrs = bytes(64)
    shdrs += struct.pack("<IIQQQQIIQQ", 0, 1, 0x6, 0x1000, 0, 0x100, 0, 0, 16, 0)     # .text: ALLOC|EXECINSTR
    shdrs += struct.pack("<IIQQQQIIQQ", 0, 1, 0x3, 0x2000, 0, 0x100, 0, 0, 8, 0)      # .data: ALLOC|WRITE
    shdrs += struct.pack("<IIQQQQIIQQ", 0, 11, 0x2, 0, sym_off, len(table), 0, 1, 8, 24)
    return ehdr + table + shdrs


class TestAbsoluteSymbols(unittest.TestCase):
    def test_lld5_absolute_functions_get_their_section(self):
        # Electron 2's libnode.so (LLD 5): 1361 functions marked SHN_ABS, which glibc 2.28 and later
        # don't relocate, so PlayMe jumped to the raw address 0xe6e0c0 and crashed at start
        from debpak.elf import SHN_ABS, fix_absolute_symbols
        syms = [(2, SHN_ABS, 0x1010),       # a function in .text: fixed
                (1, SHN_ABS, 0x2010),       # an object in .data: fixed
                (2, SHN_ABS, 0x2020),       # a "function" in data: left alone
                (1, SHN_ABS, 0),            # a version symbol: really absolute
                (2, SHN_ABS, 0x9000),       # outside every section
                (2, 1, 0x1020)]             # already right
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "libnode.so"
            p.write_bytes(library_with_symbols(syms))
            self.assertEqual(fix_absolute_symbols(p), 2)
            data = p.read_bytes()
            ndx = [struct.unpack_from("<H", data, 64 + 24 * i + 6)[0] for i in range(1, len(syms) + 1)]
            self.assertEqual(ndx, [1, 2, SHN_ABS, SHN_ABS, SHN_ABS, 1])
            self.assertEqual(fix_absolute_symbols(p), 0)
            exe = Path(t) / "playme"
            exe.write_bytes(program("/lib64/ld-linux-x86-64.so.2"))      # ET_EXEC: its addresses are absolute
            self.assertEqual(fix_absolute_symbols(exe), 0)
