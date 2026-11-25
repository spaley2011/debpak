"""winegap index/scan, machgap and the Wine-installer helpers: paths the other tests don't reach,
pinned when cli_compat, winetrace and wineinstall were split into smaller functions."""
import contextlib
import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from debpak import wineinstall
from debpak.cli_compat import machgap_main, winegap_main
from debpak.darling import index_darling_root
from debpak.pe_write import PeSpec, build_pe
from debpak.winetrace import parse_log

from compat_fixtures import make_wine_source


def run(fn, *argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = fn([str(a) for a in argv])
    return code, out.getvalue(), err.getvalue()


class WinegapTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.t = Path(self._t.name)
        self.wine = make_wine_source(self.t / "wine")
        self.app = self.t / "app"
        self.app.mkdir()
        (self.app / "app.exe").write_bytes(build_pe(PeSpec(arch="x86_64", is_dll=False, imports={
            "KERNEL32.dll": ["ExitProcess", "SetCurrentConsoleFontEx"], "MSVCP140.dll": ["x"]})))

    def tearDown(self):
        self._t.cleanup()

    def test_index_then_scan_with_stubs(self):
        idx = self.t / "i.json"
        code, out, _ = run(winegap_main, "index", "--wine-source", self.wine, "-o", idx)
        self.assertEqual(code, 0)
        self.assertRegex(out, r"^wine 11\.8 \(x86_64\): \d+ DLLs, \d+ stubbed exports -> ")
        self.assertTrue(idx.is_file())
        code, out, _ = run(winegap_main, "scan", self.app, "--index", idx, "--stubs", self.t / "stubs")
        self.assertEqual(code, 2)            # MSVCP140.dll is missing: fatal
        self.assertTrue((self.t / "stubs" / "MSVCP140.dll").is_file())
        self.assertIn("wrote 1 stub DLL(s)", out)

    def test_index_goes_to_the_cache_without_output(self):
        with mock.patch.dict(os.environ, {"XDG_CACHE_HOME": str(self.t / "cache")}):
            code, _out, _ = run(winegap_main, "index", "--wine-source", self.wine, "--arch", "i386")
        self.assertEqual(code, 0)
        self.assertTrue(list((self.t / "cache/debpak/wine").glob("*_i386.json")))

    def test_scan_errors(self):
        self.assertEqual(run(winegap_main, "scan", self.app)[:2], (1, ""))
        (self.t / "bad.json").write_text("{")
        code, _, err = run(winegap_main, "scan", self.app, "--index", self.t / "bad.json")
        self.assertEqual(code, 1)
        self.assertTrue(err.startswith("error: "))

    def test_scan_indexes_source_on_the_fly(self):
        code, out, _ = run(winegap_main, "scan", self.app / "app.exe", "--wine-source", self.wine, "--json")
        self.assertEqual(code, 2)
        self.assertIn('"backend": "pe-wine"', out)


class MachgapTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.t = Path(self._t.name)
        (self.t / "empty").mkdir()
        index_darling_root(self.t / "empty").save(self.t / "d.json")

    def tearDown(self):
        self._t.cleanup()

    def test_index_without_dylibs(self):
        code, _, err = run(machgap_main, "index", "--darling-root", self.t, "--arch", "arm64")
        self.assertEqual(code, 1)
        self.assertIn("no arm64 Mach-O dylibs found", err)

    def test_dmg_and_zip_without_app(self):
        dmg = self.t / "A.dmg"
        dmg.write_bytes(b"x")
        code, _, err = run(machgap_main, "scan", dmg, "--index", self.t / "d.json")
        self.assertEqual((code, err.startswith("error: extract the .dmg first")), (1, True))
        with zipfile.ZipFile(self.t / "a.zip", "w") as z:
            z.writestr("readme.txt", "x")
        code, _, err = run(machgap_main, "scan", self.t / "a.zip", "--index", self.t / "d.json")
        self.assertEqual((code, err), (1, "error: no .app bundle inside the zip\n"))


class TraceParseTests(unittest.TestCase):
    def test_backtrace_after_other_lines_and_loader_messages_only_on_module(self):
        t = parse_log([
            "wine: Unhandled page fault on read access to 0 at address 1 (thread 0024)",
            "Backtrace:",
            "0024:fixme:dwmapi:DwmFlush () stub",
            "=>0 0x00000001400010a0 in App (+0x10a0)",
            r'0024:err:ole:x Failed to load module L"oleish.dll"; status=c0000135',
            r'0024:warn:module:load_dll Failed to load module L"C:\\x\\NV.dll"; status=c0000135',
        ])
        self.assertEqual(t.crashes, [("Unhandled page fault on read access to 0 at address 1 (thread 0024)", "app")])
        self.assertEqual(dict(t.stubs), {("dwmapi", "DwmFlush"): 1})
        self.assertEqual(dict(t.failed_loads), {"nv.dll": 1})
        self.assertEqual(dict(t.errors), {("ole", "x"): 1})


class ProgramRootTests(unittest.TestCase):
    def test_program_folders(self):
        cases = {
            ("Program Files", "Acme", "a.exe"): ("Program Files", "Acme"),
            ("Program Files", "Common Files", "a.exe"): None,
            ("laragon", "bin", "a.exe"): ("laragon",),
            ("laragon",): None,
            ("users", "me", "AppData", "Local", "Programs", "Tool", "a.exe"):
                ("users", "me", "AppData", "Local", "Programs", "Tool"),
            ("users", "me", "AppData", "Roaming", "Tool", "a.exe"): ("users", "me", "AppData", "Roaming", "Tool"),
            ("users", "me", "AppData", "LocalLow", "Tool", "a.exe"): None,
            ("users", "me", "FastCopy", "a.exe"): ("users", "me", "FastCopy"),
            ("users", "me", "Desktop", "a.exe"): None,
            ("windows", "system32", "a.dll"): None,
        }
        for parts, root in cases.items():
            with self.subTest(parts=parts):
                self.assertEqual(wineinstall._program_root(parts), root)


if __name__ == "__main__":
    unittest.main()
