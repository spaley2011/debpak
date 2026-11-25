"""Pointing a program at the runtime's loader."""
import struct
import tempfile
import unittest
from pathlib import Path

from debpak.elf import read_elf, set_interpreter


def program(interp: str) -> bytes:
    """A minimal 64-bit ELF executable header with one PT_INTERP segment."""
    data = interp.encode() + b"\0"
    ehdr = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    ehdr += struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 3, 4, 120, 0, 0, len(data), len(data), 1)
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


if __name__ == "__main__":
    unittest.main()
