import contextlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from debpak.cli_compat import gaprank_main, machgap_main, winegap_main
from debpak.darling import DarlingIndex, index_darling_root, normalize_install_name, pretty_symbol
from debpak.darling import scan as darling_scan
from debpak.gap import Gap, GapReport, load_reports, rank
from debpak.macho import is_macho, read_macho
from debpak.pe import read_pe
from debpak.pe_write import PeSpec, build_pe, stub_dll
from debpak.wine import WineIndex, index_wine_source, parse_spec
from debpak.wine import scan as wine_scan

from compat_fixtures import (APPKIT, LIBSYSTEM, build_macho, fat, make_darling_root, make_mac_app,
                             make_wine_source, make_windows_app)


def run(fn, *argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = fn(list(argv))
    return code, out.getvalue()


class PeTests(unittest.TestCase):
    def test_roundtrip_imports_exports(self):
        with tempfile.TemporaryDirectory() as t:
            exe = Path(t) / "a.exe"
            exe.write_bytes(build_pe(PeSpec(arch="x86_64", is_dll=False,
                                            imports={"KERNEL32.dll": ["ExitProcess", 17]},
                                            delay_imports={"dwmapi.dll": ["DwmFlush"]})))
            info = read_pe(exe)
            self.assertEqual(info.machine, "x86_64")
            self.assertFalse(info.is_dll)
            got = {(i.dll, i.label, i.delay) for i in info.imports}
            self.assertEqual(got, {("KERNEL32.dll", "ExitProcess", False), ("KERNEL32.dll", "#17", False),
                                   ("dwmapi.dll", "DwmFlush", True)})

    def test_i386_and_dotnet(self):
        with tempfile.TemporaryDirectory() as t:
            exe = Path(t) / "a.exe"
            exe.write_bytes(build_pe(PeSpec(arch="i386", is_dll=False, dotnet=True)))
            info = read_pe(exe)
            self.assertEqual(info.machine, "i386")
            self.assertTrue(info.is_dotnet)
            self.assertIn("mscoree.dll", info.imported_dlls)

    def test_stub_dll_exports(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "NDFAPI.DLL"
            p.write_bytes(stub_dll("NDFAPI.DLL", "x86_64", ["b", "a"], [9]))
            info = read_pe(p)
            self.assertTrue(info.is_dll)
            self.assertEqual(info.dll_name, "NDFAPI.DLL")
            self.assertEqual(set(info.exports), {"a", "b"})
            self.assertIn(9, info.ordinals)

    @unittest.skipUnless(shutil.which("objdump"), "objdump not installed")
    def test_objdump_agrees(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "x.dll"
            p.write_bytes(stub_dll("x.dll", "x86_64", ["Alpha", "Beta"]))
            out = subprocess.run(["objdump", "-p", str(p)], capture_output=True, text=True).stdout
            if "pei-x86-64" not in out:
                self.skipTest("objdump lacks PE support")
            self.assertIn("Alpha", out)
            self.assertIn("Beta", out)


class WineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.base = Path(cls._tmp.name)
        cls.src = make_wine_source(cls.base / "wine")
        cls.app = make_windows_app(cls.base / "app")
        cls.idx = {a: index_wine_source(cls.src, a) for a in ("x86_64", "i386")}

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_spec_arch_filters(self):
        spec = "@ stdcall -arch=win32 A()\n@ stdcall -arch=!i386 B()\n@ stub C\n"
        self.assertEqual(parse_spec(spec, "i386")["e"], {"A": "i", "C": "s"})
        self.assertEqual(parse_spec(spec, "x86_64")["e"], {"B": "i", "C": "s"})

    def test_forwarders_and_ordinals(self):
        i = self.idx["x86_64"]
        self.assertEqual(i.status("KERNEL32.DLL", "CreateFileW", None), "i")      # forward -> implemented
        self.assertEqual(i.status("kernel32.dll", "GetConsoleFontEx", None), "s")  # forward -> stub
        self.assertEqual(i.status("kernel32.dll", None, 17), "i")
        self.assertEqual(i.status("kernel32.dll", "Nope", None), "m")
        self.assertEqual(i.status("ndfapi.dll", "X", None), "M")
        self.assertEqual(i.version, "11.8")

    def test_scan_tiers(self):
        r = wine_scan(self.app, self.idx).report
        fatal = {g.key for g in r.by_tier("fatal")}
        crash = {g.key for g in r.by_tier("crash")}
        optional = {g.key: g.scope for g in r.by_tier("optional")}
        # missing DLLs: one imported by the exe, one by a statically linked app DLL
        self.assertEqual(fatal, {"ndfapi.dll", "ext-ms-win-uiacore-l1-1-2.dll"})
        self.assertEqual(crash, {"kernel32.dll!SetCurrentConsoleFontEx", "kernel32.dll!GetConsoleFontEx",
                                 "kernel32.dll!NotInWineAtAll"})
        self.assertEqual(optional, {"wkscli.dll": "app", "d3dcompiler_99.dll": "plugin"})
        # app-local mfplat.dll overrides the builtin, which lacks MFCreateSampleCopierMFT
        self.assertFalse([g for g in r.gaps if g.module == "mfplat.dll"])
        # the 32-bit updater is checked against the i386 index (Only32 exists there)
        self.assertFalse([g for g in r.gaps if "Only32" in g.key])
        self.assertTrue(r.verdict.startswith("WILL NOT START"))

    def test_stub_dlls_unblock_startup(self):
        with tempfile.TemporaryDirectory() as t:
            app = Path(t) / "app"
            shutil.copytree(self.app, app)
            code, out = run(winegap_main, "scan", str(app), "--wine-source", str(self.src),
                            "--stubs", str(Path(t) / "stubs"))
            self.assertEqual(code, 2, out)
            stubs = sorted(p.name for p in (Path(t) / "stubs").iterdir())
            self.assertIn("NDFAPI.DLL", stubs)
            self.assertIn("ext-ms-win-uiacore-l1-1-2.dll", stubs)
            self.assertNotIn("wkscli.dll", stubs)   # delay-loaded: not needed to start
            nd = read_pe(Path(t) / "stubs" / "NDFAPI.DLL")
            self.assertEqual(set(nd.exports), {"NdfCreateWebIncident", "NdfCloseIncident"})
            for p in (Path(t) / "stubs").iterdir():
                shutil.copy(p, app / p.name)
            code, out = run(winegap_main, "scan", str(app), "--wine-source", str(self.src))
            self.assertEqual(code, 0, out)
            self.assertIn("STARTS; may abort", out)

    def test_index_cli_roundtrip(self):
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "idx.json"
            code, out = run(winegap_main, "index", "--wine-source", str(self.src), "-o", str(f))
            self.assertEqual(code, 0, out)
            self.assertIn("4 DLLs", out)
            self.assertEqual(WineIndex.load(f).dlls, self.idx["x86_64"].dlls)

    def test_libdir_index(self):
        from debpak.wine import index_wine_libdir
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / "ndfapi.dll").write_bytes(stub_dll("ndfapi.dll", "x86_64", ["NdfCreateWebIncident"]))
            i = index_wine_libdir(t, "x86_64")
            self.assertEqual(i.status("NDFAPI.DLL", "NdfCreateWebIncident", None), "i")


class MachOTests(unittest.TestCase):
    def test_thin_and_fat(self):
        with tempfile.TemporaryDirectory() as t:
            thin = Path(t) / "thin"
            thin.write_bytes(build_macho("arm64", "dylib", install_name="/usr/lib/libx.dylib",
                                         dylibs=[(LIBSYSTEM, "load"), ("/usr/lib/liby.dylib", "weak")],
                                         undefined=[("_malloc", 1, False), ("_y", 2, True)],
                                         exports=["_a", "_b", "_c"]))
            m = read_macho(thin)
            s = m.slices[0]
            self.assertEqual((s.arch, s.filetype, s.install_name), ("arm64", "dylib", "/usr/lib/libx.dylib"))
            self.assertEqual([d.kind for d in s.dylibs], ["load", "weak"])
            self.assertEqual(s.exports, {"_a", "_b", "_c"})
            self.assertEqual([(u.name, u.ordinal, u.weak) for u in s.undefined],
                             [("_malloc", 1, False), ("_y", 2, True)])
            self.assertEqual((s.platform, s.min_os), ("macos", "11.0"))
            f = Path(t) / "fat"
            f.write_bytes(fat({"x86_64": build_macho("x86_64"), "arm64": build_macho("arm64")}))
            self.assertTrue(is_macho(f))
            self.assertEqual(read_macho(f).archs, ["x86_64", "arm64"])
            self.assertTrue(read_macho(f).slice("x86_64").has_main)

    def test_many_exports_trie(self):
        with tempfile.TemporaryDirectory() as t:
            names = [f"_sym{i:04d}" for i in range(300)]
            p = Path(t) / "lib"
            p.write_bytes(build_macho(filetype="dylib", install_name="/x", exports=names))
            self.assertEqual(read_macho(p).slices[0].exports, set(names))

    def test_java_class_is_not_macho(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "A.class"
            p.write_bytes(b"\xca\xfe\xba\xbe\x00\x00\x00\x3d" + bytes(32))
            self.assertFalse(is_macho(p))

    def test_helpers(self):
        self.assertEqual(normalize_install_name(APPKIT), "/System/Library/Frameworks/AppKit.framework/AppKit")
        self.assertEqual(pretty_symbol("_OBJC_CLASS_$_NSWindow"), "NSWindow (ObjC class)")
        self.assertEqual(pretty_symbol("_printf"), "printf")


class DarlingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.base = Path(cls._tmp.name)
        cls.root = make_darling_root(cls.base / "darling")
        cls.idx = index_darling_root(cls.root)
        cls.app = make_mac_app(cls.base / "apps")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_index(self):
        self.assertEqual(self.idx.status(LIBSYSTEM, "_printf"), "i")          # via re-export
        self.assertEqual(self.idx.status(APPKIT, "_NSBeep"), "s")             # STUB string detected
        self.assertEqual(self.idx.status(APPKIT, "_OBJC_CLASS_$_NSWindow"), "i")
        self.assertEqual(self.idx.status(APPKIT, "_Missing"), "m")
        self.assertEqual(self.idx.status("/System/Library/Frameworks/Metal.framework/Metal", "_x"), "M")

    def test_scan(self):
        r = darling_scan(self.app, self.idx)
        self.assertEqual(r.target, "Zap")
        self.assertEqual({g.key for g in r.by_tier("fatal")}, {"AppKit!NSToolbarItemGroup (ObjC class)"})
        self.assertEqual({g.key for g in r.by_tier("degraded")}, {"AppKit!NSBeep"})
        self.assertEqual({g.key for g in r.by_tier("optional")}, {"Metal"})
        # @rpath framework resolved inside the bundle -> its symbol isn't a gap
        self.assertFalse([g for g in r.gaps if "helper_fn" in g.key])
        self.assertEqual(r.stats["min_macos"], "11.0")

    def test_arm64_only_app_is_blocked(self):
        with tempfile.TemporaryDirectory() as t:
            app = make_mac_app(Path(t), archs=("arm64",))
            r = darling_scan(app, self.idx)
            self.assertTrue(r.blockers)
            self.assertIn("no x86_64 code", r.blockers[0])

    def test_ios_binary_is_blocked(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "tool"
            p.write_bytes(build_macho("x86_64", "execute", platform=2))
            self.assertIn("built for ios", darling_scan(p, self.idx).blockers[0])

    def test_cli_and_zip(self):
        with tempfile.TemporaryDirectory() as t:
            idxf = Path(t) / "d.json"
            code, out = run(machgap_main, "index", "--darling-root", str(self.root), "-o", str(idxf))
            self.assertEqual(code, 0, out)
            self.assertIn("1 detected stubs", out)
            self.assertEqual(DarlingIndex.load(idxf).status(APPKIT, "_NSBeep"), "s")
            z = shutil.make_archive(str(Path(t) / "Zap"), "zip", self.app.parent, "Zap.app")
            code, out = run(machgap_main, "scan", z, "--index", str(idxf), "--json")
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(out)["worst"], "fatal")


class RankTests(unittest.TestCase):
    def test_rank_and_sole_blockers(self):
        def rep(name, *gaps):
            r = GapReport("pe-wine", name, "wine")
            for tier, mod, sym in gaps:
                r.add(Gap(tier, mod, sym, "x", [name]))
            return r
        reports = [
            rep("A", ("fatal", "ndfapi.dll", None)),
            rep("B", ("fatal", "ndfapi.dll", None), ("fatal", "x.dll", None)),
            rep("C", ("fatal", "x.dll", None), ("crash", "kernel32.dll", "Foo")),
            rep("D", ("crash", "kernel32.dll", "Foo")),
        ]
        rows = {(r.key, r.tier): r for r in rank(reports)}
        self.assertEqual(rows[("ndfapi.dll", "fatal")].apps, 2)
        self.assertEqual(rows[("ndfapi.dll", "fatal")].sole_blocker, 1)
        self.assertEqual(rows[("x.dll", "fatal")].sole_blocker, 1)
        self.assertEqual(rows[("kernel32.dll!Foo", "crash")].apps, 2)

    def test_gaprank_across_backends(self):
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            src = make_wine_source(t / "wine")
            app = make_windows_app(t / "app")
            root = make_darling_root(t / "darling")
            mac = make_mac_app(t / "mac")
            didx = t / "d.json"
            run(machgap_main, "index", "--darling-root", str(root), "-o", str(didx))
            (t / "reports").mkdir()
            run(winegap_main, "scan", str(app), "--wine-source", str(src), "-o", str(t / "reports/win.json"))
            run(machgap_main, "scan", str(mac), "--index", str(didx), "-o", str(t / "reports/mac.json"))
            self.assertEqual(len(load_reports([t / "reports"])), 2)
            code, out = run(gaprank_main, str(t / "reports"))
            self.assertEqual(code, 0, out)
            self.assertIn("2 apps analysed; 0 would start", out)
            self.assertIn("[pe-wine] ndfapi.dll", out)
            self.assertIn("[macho-darling] AppKit!NSToolbarItemGroup (ObjC class)", out)


if __name__ == "__main__":
    unittest.main()
