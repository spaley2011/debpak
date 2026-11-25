"""Pin the behaviour of darling.scan, old-style delay imports in pe.py and GapReport.render.

These have no other tests; they were added when those functions were split into
smaller helpers, so the split can be checked against what the code did before.
"""
from __future__ import annotations

import plistlib
import struct
import tempfile
import unittest
from pathlib import Path

from compat_fixtures import APPKIT, FOUNDATION, LIBSYSTEM, METAL, _put, build_macho, fat

from debpak import darling, pe
from debpak.gap import Gap, GapReport
from debpak.pe_write import PeSpec, build_pe


def _darling_root(root: Path) -> Path:
    """A Darling prefix: libSystem re-exports libsystem_c, and AppKit stubs NSBeep."""
    _put(root, "/usr/lib/system/libsystem_c.dylib",
         build_macho(filetype="dylib", install_name="/usr/lib/system/libsystem_c.dylib",
                     exports=["_printf", "_malloc"]))
    _put(root, LIBSYSTEM, build_macho(filetype="dylib", install_name=LIBSYSTEM,
                                      dylibs=[("/usr/lib/system/libsystem_c.dylib", "reexport")]))
    _put(root, FOUNDATION, build_macho(filetype="dylib", install_name=FOUNDATION,
                                       exports=["_OBJC_CLASS_$_NSString", "_NSLog"]))
    _put(root, APPKIT, build_macho(filetype="dylib", install_name=APPKIT,
                                   exports=["_OBJC_CLASS_$_NSWindow", "_NSApplicationMain", "_NSBeep"],
                                   strings=[b"STUB: NSBeep called"]))
    return root


def _mac_app(root: Path, archs: tuple[str, ...]) -> Path:
    """An .app with a main program, a framework found through @rpath, and a plugin."""
    app = root / "Zap.app"
    (app / "Contents/MacOS").mkdir(parents=True)
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps({
        "CFBundleExecutable": "Zap", "CFBundleName": "Zap", "LSMinimumSystemVersion": "11.0"}))
    helper_id = "@rpath/Helper.framework/Versions/A/Helper"
    deps = [(LIBSYSTEM, "load"), (APPKIT, "load"), (FOUNDATION, "load"), (helper_id, "load"), (METAL, "weak")]
    undefined = [("_printf", 1, False), ("_NSApplicationMain", 2, False), ("_NSBeep", 2, False),
                 ("_OBJC_CLASS_$_NSToolbarItemGroup", 2, False), ("_OBJC_CLASS_$_NSString", 3, False),
                 ("_NSLog", 3, False), ("_helper_fn", 4, False), ("_MTLCreateSystemDefaultDevice", 5, True)]
    main = {a: build_macho(a, "execute", dylibs=deps, undefined=undefined,
                           rpaths=["@executable_path/../Frameworks"]) for a in archs}
    (app / "Contents/MacOS/Zap").write_bytes(fat(main) if len(main) > 1 else next(iter(main.values())))
    _put(app, "Contents/Frameworks/Helper.framework/Versions/A/Helper",
         fat({a: build_macho(a, "dylib", install_name=helper_id, dylibs=[(LIBSYSTEM, "load")],
                             undefined=[("_malloc", 1, False)], exports=["_helper_fn"]) for a in archs}))
    _put(app, "Contents/PlugIns/Fx.bundle/Contents/MacOS/Fx",
         fat({a: build_macho(a, "bundle", dylibs=[(METAL, "load")],
                             undefined=[("_MTLCreateSystemDefaultDevice", 1, False)]) for a in archs}))
    return app


class DarlingScanTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.index = darling.index_darling_root(_darling_root(self.tmp / "root"))

    def tearDown(self):
        self._tmp.cleanup()

    def test_index_follows_reexports_and_finds_stubs(self):
        self.assertEqual(self.index.status(LIBSYSTEM, "_malloc"), "i")
        self.assertEqual(self.index.status(LIBSYSTEM, "_nothing"), "m")
        self.assertEqual(self.index.status(APPKIT, "_NSBeep"), "s")
        self.assertEqual(self.index.status("/usr/lib/libNope.dylib", "_x"), "M")

    def test_universal_app(self):
        r = darling.scan(_mac_app(self.tmp / "u", ("x86_64", "arm64")), self.index)
        self.assertEqual([(g.tier, g.module, g.symbol, g.scope, g.importers) for g in r.gaps], [
            ("optional", "Metal", None, "app", ["Contents/MacOS/Zap", "Contents/PlugIns/Fx.bundle/Contents/MacOS/Fx"]),
            ("degraded", "AppKit", "NSBeep", "app", ["Contents/MacOS/Zap"]),
            ("fatal", "AppKit", "NSToolbarItemGroup (ObjC class)", "app", ["Contents/MacOS/Zap"])])
        self.assertEqual(r.stats, {"binaries": 3, "arch": "x86_64", "undefined_symbols": 10, "min_macos": "11.0",
                                   "objc_classes_referenced": 2})
        self.assertEqual(r.blockers, [])
        self.assertEqual(len(r.notes), 1)
        self.assertIn("Objective-C", r.notes[0])

    def test_app_without_the_index_arch(self):
        r = darling.scan(_mac_app(self.tmp / "a", ("arm64",)), self.index)
        self.assertEqual(r.blockers, ["Contents/MacOS/Zap has no x86_64 code (only arm64)"])
        self.assertEqual(r.notes, ["Contents/Frameworks/Helper.framework/Versions/A/Helper: no x86_64 slice (arm64); skipped",
                                   "Contents/PlugIns/Fx.bundle/Contents/MacOS/Fx: no x86_64 slice (arm64); skipped"])
        self.assertEqual(r.gaps, [])

    def test_folder_without_macho(self):
        (self.tmp / "e").mkdir()
        r = darling.scan(self.tmp / "e", self.index)
        self.assertEqual(len(r.blockers), 1)
        self.assertIn("no Mach-O binaries found", r.blockers[0])


def _va_style(data: bytes) -> bytes:
    """Rewrite a 32-bit PE's delay-load descriptors the old VC6 way: virtual addresses instead of RVAs."""
    b = bytearray(data)
    img = pe._Image(bytes(b))
    off = img.off(img.dirs[pe.DIR_DELAY_IMPORT][0])
    while True:
        _attrs, name, hmod, iat, int_rva, *rest = struct.unpack_from("<IIIIIIII", b, off)
        if not (name or int_rva):
            return bytes(b)
        t = img.off(int_rva)
        while (v := struct.unpack_from("<I", b, t)[0]):
            if not v & (1 << 31):
                struct.pack_into("<I", b, t, v + img.image_base)
            t += 4
        struct.pack_into("<IIIIIIII", b, off, 0, name + img.image_base, hmod, iat, int_rva + img.image_base, *rest)
        off += 32


class DelayImportTest(unittest.TestCase):
    def test_rva_and_va_descriptors_read_the_same(self):
        data = build_pe(PeSpec(arch="i386", is_dll=False, imports={"user32.dll": ["MessageBoxW"]},
                               delay_imports={"x.dll": [3, "Y"], "z.dll": ["Q"]}))
        with tempfile.TemporaryDirectory() as d:
            rva, va = Path(d) / "rva.exe", Path(d) / "va.exe"
            rva.write_bytes(data)
            va.write_bytes(_va_style(data))
            want = [("x.dll", None, 3), ("x.dll", "Y", None), ("z.dll", "Q", None)]
            for p in (rva, va):
                info = pe.read_pe(p)
                self.assertEqual([(i.dll, i.name, i.ordinal) for i in info.imports if i.delay], want)
                self.assertEqual(info.problems, [])


class RenderTest(unittest.TestCase):
    def test_render(self):
        r = GapReport("pe-wine", "App", "wine 11", stats={"modules": 2}, notes=["a note"])
        r.add(Gap("crash", "k.dll", "F", "stub", ["a.exe", "b.exe", "c.exe", "d.exe"], "plugin", "runtime", 2))
        r.add(Gap("crash", "k.dll", "G", "stub", [], "app", "guess"))
        r.add(Gap("crash", "k.dll", "F", "stub", ["a.exe", "e.exe"], "app", "static", 1))
        r.add(Gap("crash", "k.dll", "H", "stub", ["a.exe"]))
        self.assertEqual(r.render(2), (
            "App  [pe-wine -> wine 11]\n  modules: 2\n"
            "\n== CRASH (3): starts, but aborts if this function is reached\n"
            "  k.dll!F [seen running x3]\n      stub; used by a.exe, b.exe, c.exe ...\n"
            "  k.dll!G [guess]\n      stub; no importer recorded\n"
            "  ... 1 more (see --json)\n"
            "\n== NOTES\n  - a note\n"
            "\n== VERDICT\n  STARTS; may abort if it reaches any of 3 unimplemented function(s)\n"))


if __name__ == "__main__":
    unittest.main()
