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



def program_with_flags_1(flags: int) -> bytes:
    """A minimal 64-bit ELF with a PT_DYNAMIC segment holding DT_FLAGS_1 and DT_NULL."""
    dyn = struct.pack("<qQ", 0x6FFFFFFB, flags) + struct.pack("<qQ", 0, 0)
    ehdr = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    ehdr += struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 2, 6, 120, 0, 0, len(dyn), len(dyn), 8)
    return ehdr + phdr + dyn


class TestNodeflib(unittest.TestCase):
    def test_classic_snap_program_finds_the_runtimes_libraries(self):
        # MiniZinc's IDE (a classic snap) is linked with -z nodefaultlib, so the loader passed
        # over the runtime's /usr/lib: "libpthread.so.0: cannot open shared object file"
        from debpak.elf import clear_nodeflib
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "MiniZincIDE"
            p.write_bytes(program_with_flags_1(0x800 | 0x1))       # NODEFLIB | NOW
            self.assertTrue(read_elf(p, want_symbols=False).nodeflib)
            self.assertTrue(clear_nodeflib(p))
            self.assertFalse(read_elf(p, want_symbols=False).nodeflib)
            self.assertEqual(struct.unpack_from("<qQ", p.read_bytes(), 120), (0x6FFFFFFB, 0x1))
            self.assertFalse(clear_nodeflib(p))
            q = Path(t) / "plain"
            q.write_bytes(program("/lib64/ld-linux-x86-64.so.2"))
            self.assertFalse(clear_nodeflib(q))


class TestStaticPie(unittest.TestCase):
    def test_a_static_pie_program_is_a_program(self):
        # soar's tarball holds one static-pie Rust program: ET_DYN with no interpreter, like a
        # library, and convert found no program to start; DF_1_PIE says what it is
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "soar"
            p.write_bytes(program_with_flags_1(0x08000000 | 0x1))      # PIE | NOW
            info = read_elf(p, want_symbols=False)
            self.assertTrue(info.is_executable)
            self.assertFalse(info.is_shared_library)
            p.write_bytes(program_with_flags_1(0x1))
            info = read_elf(p, want_symbols=False)
            self.assertFalse(info.is_executable)
            self.assertTrue(info.is_shared_library)


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

    def test_sandbox_off_by_environment(self):
        # Fether's Electron 7 refused --no-sandbox in its own options ("error: unknown option
        # `--no-sandbox'"); from Electron 5 on ELECTRON_DISABLE_SANDBOX says it where the app can't see
        from types import SimpleNamespace
        from debpak.stage import sandbox_off_by_env
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            for name, version, want in (("fether", b"7.1.14", True), ("playme", b"2.0.7", False),
                                        ("unknown", None, False)):
                tail = b"Chrome/78.0.3904.130 Electron/" + version if version else b"no version here"
                (root / name).write_bytes(b"\0" * 5000 + tail + b"\0" * 100)
                a = SimpleNamespace(kind="electron", main_exec=name, root=root, desktop_file=None)
                self.assertEqual(sandbox_off_by_env(a), want, name)
            # a CEF app's program is the vendor's own and gets neither
            cef = SimpleNamespace(kind="cef", main_exec="fether", root=root, desktop_file=None)
            self.assertFalse(sandbox_off_by_env(cef))


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


STUB_LIBM = r"""
float sqrtf_old(float x) { return x * 0.5f; }
float sqrtf_new(float x) { return x * 0.25f; }
double fromfp_old(double x, int r, unsigned w) { return x; }
double fromfp_new(double x, int r, unsigned w) { return x; }
__asm__(".symver sqrtf_old,sqrtf@GLIBC_2.2.5");
__asm__(".symver sqrtf_new,sqrtf@@GLIBC_2.43");
__asm__(".symver fromfp_old,fromfp@GLIBC_2.25");
__asm__(".symver fromfp_new,fromfp@@GLIBC_2.43");
"""
OLD_LIBM = "float sqrtf(float x) { return x * 0.5f; }\n"


def _have_gcc() -> bool:
    import os
    import shutil
    return bool(shutil.which("gcc")) and os.uname().machine == "x86_64"


@unittest.skipUnless(_have_gcc(), "needs gcc on x86_64")
class TestLibmVersions(unittest.TestCase):
    """A program built on glibc 2.43 (ModelViewer-Qt) needs libm at GLIBC_2.43 for sqrtf alone."""

    def build(self, t: Path, call: str) -> Path:
        import subprocess
        (t / "new").mkdir(exist_ok=True)
        (t / "old").mkdir(exist_ok=True)
        (t / "stub.c").write_text(STUB_LIBM)
        (t / "stub.map").write_text("GLIBC_2.2.5 { local: *; };\nGLIBC_2.25 { } GLIBC_2.2.5;\n"
                                    "GLIBC_2.43 { } GLIBC_2.25;\n")
        (t / "old.c").write_text(OLD_LIBM)
        (t / "old.map").write_text("GLIBC_2.2.5 { };\n")
        (t / "prog.c").write_text("#include <stdio.h>\nfloat sqrtf(float);\ndouble fromfp(double, int, unsigned);\n"
                                  f"int main(void) {{ printf(\"%g\\n\", (double)({call})); return 0; }}\n")
        run = lambda *a: subprocess.run(["gcc", *a], check=True, capture_output=True, cwd=t)
        run("-shared", "-fPIC", "-o", "new/libm.so.6", "-Wl,-soname,libm.so.6", "-Wl,--version-script=stub.map",
            "stub.c")
        run("-shared", "-fPIC", "-o", "old/libm.so.6", "-Wl,-soname,libm.so.6", "-Wl,--version-script=old.map",
            "old.c")
        run("-fno-builtin", "-O0", "-o", "prog", "prog.c", "-Lnew", "-l:libm.so.6")
        return t / "prog"

    def test_sqrtf_bound_to_its_old_version(self):
        import os
        import subprocess
        from debpak.elf import libm_versions_lowerable, lower_libm_versions
        with tempfile.TemporaryDirectory() as d:
            t = Path(d)
            prog = self.build(t, "sqrtf(8.0f)")
            self.assertEqual(read_elf(prog).verneed["libm.so.6"], {"GLIBC_2.43"})
            env = {**os.environ, "LD_LIBRARY_PATH": str(t / "old")}
            r = subprocess.run([str(prog)], env=env, capture_output=True, text=True)
            self.assertIn("GLIBC_2.43", r.stderr)
            self.assertTrue(libm_versions_lowerable(prog, {"GLIBC_2.43"}))
            self.assertTrue(lower_libm_versions(prog, {"GLIBC_2.43"}))
            self.assertEqual(read_elf(prog).verneed["libm.so.6"], {"GLIBC_2.2.5"})
            r = subprocess.run([str(prog)], env=env, capture_output=True, text=True)
            self.assertEqual((r.returncode, r.stdout.strip()), (0, "4"))

    def test_fromfp_changed_and_stays(self):
        from debpak.elf import libm_versions_lowerable, lower_libm_versions
        with tempfile.TemporaryDirectory() as d:
            prog = self.build(Path(d), "sqrtf(8.0f) + fromfp(2.0, 0, 8)")
            before = prog.read_bytes()
            self.assertFalse(libm_versions_lowerable(prog, {"GLIBC_2.43"}))
            self.assertFalse(lower_libm_versions(prog, {"GLIBC_2.43"}))
            self.assertEqual(prog.read_bytes(), before)

    def test_analysis_takes_the_need_off(self):
        from debpak.analyze import check_versions, lower_libm_needs
        with tempfile.TemporaryDirectory() as d:
            t = Path(d)
            self.build(t, "sqrtf(8.0f)")
            elfs = {"prog": read_elf(t / "prog")}
            provided = {"GLIBC_2.2.5", "GLIBC_2.29", "GLIBC_2.42"}
            self.assertEqual(lower_libm_needs(t, elfs, provided), {"prog": {"GLIBC_2.43"}})
            self.assertEqual(check_versions(elfs, {"libm.so.6": provided}), [])
            # a runtime that has 2.43 leaves the file as it is
            elfs = {"prog": read_elf(t / "prog")}
            self.assertEqual(lower_libm_needs(t, elfs, provided | {"GLIBC_2.43"}), {})
