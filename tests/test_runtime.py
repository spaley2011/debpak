"""Runtime evidence: Wine log tracing (winegap trace), runtime-lookup guesses in
winegap scan, and the dynamic-loader smoke test (debpak smoke)."""
import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from debpak.cli import main as debpak_main
from debpak.cli_compat import gaprank_main, winegap_main
from debpak.gap import Gap, GapReport, load_reports, rank
from debpak.pe_write import PeSpec, build_pe
from debpak.smoke import parse_ld_debug
from debpak.smoke import to_report as smoke_report
from debpak.wine import index_wine_source, scan, text_lookups
from debpak.winetrace import parse_log, to_report

from compat_fixtures import make_wine_source

WINE_LOG = r"""
0024:fixme:dwmapi:DwmSetWindowAttribute (00010066, 20, 000000000021F7DC, 4) stub
0024:fixme:dwmapi:DwmSetWindowAttribute (00010066, 20, 000000000021F7DC, 4) stub
0024:fixme:kernelbase:GetConsoleFontEx (0000000000000050, 0, 000000000021F7DC): stub
0024:fixme:ntdll:NtQuerySystemInformation info_class SYSTEM_PERFORMANCE_INFORMATION
1234.567:0024:fixme:combase:CoCreateInstanceEx no instance created for interface {00000000-0000-0000-C000-000000000046} of class {F3A1E4C2-1C5F-4D2B-9F0E-0123456789AB}, hr 0x80040154.
0024:err:ole:com_get_class_object class {11111111-2222-3333-4444-555555555555} not registered
0024:err:module:import_dll Library MSVCP140_ATOMIC_WAIT.dll (which is needed by L"C:\\Program Files\\App\\render.dll") not found
0024:err:module:import_dll Loading library d3dx9_43.dll (which is needed by L"C:\\Program Files\\App\\fx.dll") failed (error c000007b).
0024:warn:module:load_dll Failed to load module L"nvcuda.dll"; status=c0000135
0024:warn:module:load_dll Failed to load module L"nvcuda.dll"; status=c0000135
0024:trace:loaddll:build_module Loaded L"C:\\windows\\system32\\kernelbase.dll" at 00006FFFFFAA0000: builtin
0024:trace:loaddll:build_module Loaded L"C:\\Program Files\\App\\mfplat.dll" at 0000000180000000: native
wine: Call from 00006FFFFFB3C8F4 to unimplemented function KERNEL32.dll.SetCurrentConsoleFontEx, aborting
wine: Unhandled page fault on read access to 0000000000000000 at address 00000001400010A0 (thread 0024), starting debugger...
Backtrace:
=>0 0x00000001400010a0 in app (+0x10a0) (0x000000000021fe40)
  1 0x00006ffffff4a2c1 in kernel32 (+0x1a2c1) (0x0000000000000000)
"""

STARTUP_FAIL = r"""
0024:err:module:import_dll Library VCRUNTIME140_1.dll (which is needed by L"C:\\Program Files\\App\\app.exe") not found
0024:err:module:loader_init Importing dlls for L"C:\\Program Files\\App\\app.exe" failed, status c0000135
"""


def run(fn, *argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = fn(list(argv))
    return code, out.getvalue()


def tool(d: Path, name: str, body: str) -> Path:
    p = d / name
    p.write_text("#!/bin/sh\n" + body + "\n")
    p.chmod(0o755)
    return p


class WineLogTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.t = Path(self._t.name)
        self.idx = index_wine_source(make_wine_source(self.t / "wine"), "x86_64")

    def tearDown(self):
        self._t.cleanup()

    def test_parse(self):
        t = parse_log(WINE_LOG.splitlines())
        self.assertEqual(t.unimplemented[("kernel32.dll", "SetCurrentConsoleFontEx")], 1)
        self.assertEqual(t.stubs[("dwmapi", "DwmSetWindowAttribute")], 2)
        self.assertEqual(t.partial[("ntdll", "NtQuerySystemInformation")], 1)
        self.assertEqual(t.com[("{F3A1E4C2-1C5F-4D2B-9F0E-0123456789AB}", "0x80040154")], 1)
        self.assertEqual(t.com[("{11111111-2222-3333-4444-555555555555}", "0x80040154")], 1)
        self.assertEqual(t.missing_imports["msvcp140_atomic_wait.dll"], {"render.dll"})
        self.assertEqual(t.failed_loads["nvcuda.dll"], 2)
        self.assertEqual(t.failed_loads["d3dx9_43.dll"], 1)
        self.assertEqual(t.loaded, {"kernelbase.dll": "builtin", "mfplat.dll": "native"})
        self.assertEqual(len(t.crashes), 1)
        self.assertEqual(t.crashes[0][1], "app")
        self.assertIn("Unhandled page fault", t.crashes[0][0])

    def test_report(self):
        r = to_report(parse_log(WINE_LOG.splitlines()), "App", [self.idx])
        gaps = {g.key: g for g in r.gaps}
        self.assertEqual(gaps["kernel32.dll!SetCurrentConsoleFontEx"].tier, "crash")
        self.assertEqual(gaps["[dwmapi]!DwmSetWindowAttribute"].count, 2)    # not in the fixture index
        self.assertEqual(gaps["kernelbase.dll!GetConsoleFontEx"].tier, "degraded")  # the index names the DLL
        self.assertEqual(gaps["msvcp140_atomic_wait.dll"].tier, "degraded")  # needed by a DLL, not the .exe
        self.assertEqual(gaps["nvcuda.dll"].count, 2)
        self.assertEqual(gaps["app"].tier, "crash")
        self.assertIn("com!{F3A1E4C2-1C5F-4D2B-9F0E-0123456789AB}", gaps)
        self.assertTrue(all(g.evidence == "runtime" for g in r.gaps))
        self.assertTrue(any("NtQuerySystemInformation" in n for n in r.notes))
        self.assertEqual(r.stats["native_dlls"], 1)
        self.assertIn("[seen running x2]", r.render())

    def test_missing_dll_of_main_exe_is_fatal(self):
        r = to_report(parse_log(STARTUP_FAIL.splitlines()), "App")
        self.assertEqual(r.worst, "fatal")
        self.assertEqual(r.gaps[0].importers, ["app.exe"])

    def test_empty_log_explains_itself(self):
        r = to_report(parse_log(["hello from the app"]), "App")
        self.assertEqual(r.gaps, [])
        self.assertTrue(any("WINEDEBUG" in n for n in r.notes))

    def test_merge_with_static_scan(self):
        app = self.t / "app"
        app.mkdir()
        (app / "app.exe").write_bytes(build_pe(PeSpec(arch="x86_64", is_dll=False, imports={
            "KERNEL32.dll": ["ExitProcess", "SetCurrentConsoleFontEx"]})))
        static = scan(app, {"x86_64": self.idx}, "App").report
        self.assertEqual(static.gaps[0].evidence, "static")
        r = to_report(parse_log(WINE_LOG.splitlines()), "App", [self.idx], static)
        g = next(g for g in r.gaps if g.key == "kernel32.dll!SetCurrentConsoleFontEx")
        self.assertEqual(g.evidence, "both")
        self.assertIn("confirmed while running", g.reason)
        self.assertIn("traced run", r.provider)

    def test_old_reports_without_evidence_still_load(self):
        d = GapReport("pe-wine", "Old", "wine 9", [Gap("crash", "x.dll", "F", "stub")]).to_json()
        for g in d["gaps"]:
            g.pop("evidence")
            g.pop("count")
        self.assertEqual(GapReport.from_json(d).gaps[0].evidence, "static")

    def test_gaprank_prefers_seen(self):
        a = GapReport("pe-wine", "A", "w", [Gap("crash", "x.dll", "Predicted", "stub"),
                                            Gap("crash", "x.dll", "Seen", "stub", evidence="runtime")])
        b = GapReport("pe-wine", "B", "w", [Gap("crash", "x.dll", "Predicted", "stub"),
                                            Gap("crash", "x.dll", "Seen", "stub", evidence="both")])
        rows = rank([a, b])
        self.assertEqual([(r.key, r.seen) for r in rows], [("x.dll!Seen", 2), ("x.dll!Predicted", 0)])
        reports = self.t / "reports"
        reports.mkdir()
        (reports / "a.json").write_text(json.dumps(a.to_json()))
        code, out = run(gaprank_main, str(reports))
        self.assertIn("seen", out)
        self.assertEqual(len(load_reports([reports])), 1)


class TraceCommandTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.t = Path(self._t.name)
        self.bin = self.t / "bin"
        self.bin.mkdir()
        self.calls = self.t / "calls"
        self._path = os.environ["PATH"]
        os.environ["PATH"] = f"{self.bin}:{self._path}"

    def tearDown(self):
        os.environ["PATH"] = self._path
        self._t.cleanup()

    def test_read_existing_log(self):
        log = self.t / "steam-12345.log"
        log.write_text(WINE_LOG)
        out = self.t / "r.json"
        code, text = run(winegap_main, "trace", "--log", str(log), "--name", "Word", "-o", str(out))
        self.assertEqual(code, 0, text)
        d = json.loads(out.read_text())
        self.assertEqual(d["target"], "Word")
        self.assertTrue(any(g["evidence"] == "runtime" for g in d["gaps"]))

    def test_runs_app_with_winedebug(self):
        wine = tool(self.bin, "wine", f'echo "WINEDEBUG=$WINEDEBUG $*" >> {self.calls}\n'
                                      'echo "0024:fixme:dwmapi:DwmFlush () stub" >&2')
        exe = self.t / "App.exe"
        exe.write_bytes(b"MZ")
        code, text = run(winegap_main, "trace", "--wine", str(wine), "--timeout", "20", "--json", str(exe),
                         "--", "/S", "doc.txt")
        self.assertEqual(code, 0, text)
        self.assertIn("WINEDEBUG=err+all,fixme+all,warn+module,+loaddll", self.calls.read_text())
        self.assertIn(f"{exe} /S doc.txt", self.calls.read_text())
        gap = json.loads(text[text.index("{"):])["gaps"][0]
        self.assertEqual((gap["module"], gap["symbol"], gap["evidence"]), ("[dwmapi]", "DwmFlush", "runtime"))

    def test_timeout_stops_app_and_its_prefix(self):
        wine = tool(self.bin, "wine", "echo started; sleep 60")
        tool(self.bin, "wineserver", f'echo "wineserver $* $WINEPREFIX" >> {self.calls}')
        exe = self.t / "App.exe"
        exe.write_bytes(b"MZ")
        t0 = time.monotonic()
        code, text = run(winegap_main, "trace", "--wine", str(wine), "--timeout", "1",
                         "--prefix", str(self.t / "pfx"), str(exe))
        self.assertLess(time.monotonic() - t0, 20)
        self.assertIn(f"wineserver -k {self.t / 'pfx'}", self.calls.read_text())

    def test_no_wineserver_kill_without_prefix(self):
        wine = tool(self.bin, "wine", "true")
        tool(self.bin, "wineserver", f'echo "wineserver $*" >> {self.calls}')
        exe = self.t / "App.exe"
        exe.write_bytes(b"MZ")
        env = os.environ.pop("WINEPREFIX", None)
        try:
            run(winegap_main, "trace", "--wine", str(wine), str(exe))
        finally:
            if env is not None:
                os.environ["WINEPREFIX"] = env
        self.assertFalse(self.calls.exists())

    def test_needs_exe_or_log(self):
        self.assertEqual(run(winegap_main, "trace")[0], 1)


class GuessTests(unittest.TestCase):
    def test_text_lookups_find_stubbed_functions(self):
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            idx = index_wine_source(make_wine_source(t / "wine"), "x86_64")
            app = t / "app"
            app.mkdir()
            pe = build_pe(PeSpec(arch="x86_64", is_dll=False, imports={"KERNEL32.dll": ["ExitProcess"]}))
            # LoadLibraryA("kernel32.dll") + GetProcAddress(..., "SetCurrentConsoleFontEx") etc.
            # as a compiler lays them out: the wide string 2-byte aligned after the narrow ones
            strings = (b"kernel32.dll\0SetCurrentConsoleFontEx\0GetConsoleFontEx\0MessageBoxW\0user32.dll\0\0"
                       + "kernelbase.dll".encode("utf-16-le") + b"\0\0")
            (app / "app.exe").write_bytes(pe + strings)
            dlls, names = text_lookups(app / "app.exe")
            self.assertTrue({"kernel32.dll", "user32.dll", "kernelbase.dll"} <= dlls)
            r = scan(app, {"x86_64": idx}, "App").report
            guesses = {g.key for g in r.gaps if g.evidence == "guess"}
            self.assertEqual(guesses, {"kernel32.dll!SetCurrentConsoleFontEx", "kernel32.dll!GetConsoleFontEx",
                                       "kernelbase.dll!GetConsoleFontEx"})
            self.assertTrue(all(g.tier == "optional" for g in r.gaps if g.evidence == "guess"))
            self.assertIn("[guess]", r.render())
            r = scan(app, {"x86_64": idx}, "App", guess=False).report
            self.assertFalse(any(g.evidence == "guess" for g in r.gaps))

    def test_statically_imported_stub_is_not_also_a_guess(self):
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            idx = index_wine_source(make_wine_source(t / "wine"), "x86_64")
            app = t / "app"
            app.mkdir()
            pe = build_pe(PeSpec(arch="x86_64", is_dll=False,
                                 imports={"KERNEL32.dll": ["SetCurrentConsoleFontEx"]}))
            (app / "app.exe").write_bytes(pe + b"kernel32.dll\0SetCurrentConsoleFontEx\0")
            r = scan(app, {"x86_64": idx}, "App").report
            self.assertEqual([(g.key, g.evidence) for g in r.gaps],
                             [("kernel32.dll!SetCurrentConsoleFontEx", "static")])


@unittest.skipUnless(shutil.which("gcc"), "needs gcc")
class SmokeTests(unittest.TestCase):
    """Real programs, real glibc loader output."""

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.t = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()

    def cc(self, name: str, src: str, *flags: str) -> Path:
        c = self.t / f"{name}.c"
        c.write_text(src)
        out = self.t / name
        subprocess.run(["gcc", "-o", str(out), str(c), *flags], check=True, capture_output=True)
        return out

    def test_dlopen_failures(self):
        prog = self.cc("app", '#include <dlfcn.h>\nint main(void){dlopen("libm.so.6",RTLD_NOW);'
                              'dlopen("libdoesnotexist.so.3",RTLD_NOW);dlopen("libnvidia-debpak-probe.so.1",RTLD_NOW);'
                              'dlopen("/opt/nowhere/libplugin.so",RTLD_NOW);return 0;}', "-ldl")
        out = self.t / "r.json"
        code, text = run(debpak_main, "smoke", "--exec", str(prog), "-o", str(out))
        self.assertEqual(code, 0, text)
        gaps = {g["module"]: g for g in json.loads(out.read_text())["gaps"]}
        # a GPU-vendor name that no driver ships (libcuda.so.1 itself loads on NVIDIA machines)
        self.assertEqual(set(gaps), {"libdoesnotexist.so.3", "libnvidia-debpak-probe.so.1", "libplugin.so"})
        self.assertEqual(gaps["libdoesnotexist.so.3"]["tier"], "degraded")
        self.assertEqual(gaps["libnvidia-debpak-probe.so.1"]["tier"], "optional")      # a GPU probe
        self.assertEqual(gaps["libdoesnotexist.so.3"]["importers"], ["app"])
        self.assertTrue(all(g["evidence"] == "runtime" for g in gaps.values()))

    def test_missing_needed_library_is_fatal(self):
        lib = self.t / "libfoo.so"
        (self.t / "foo.c").write_text("int foo(void){return 1;}")
        subprocess.run(["gcc", "-shared", "-fPIC", "-o", str(lib), str(self.t / "foo.c")], check=True)
        prog = self.cc("app", "int foo(void);int main(void){return foo()-1;}", f"-L{self.t}", "-lfoo")
        lib.unlink()
        code, text = run(debpak_main, "smoke", "--exec", str(prog), "--json")
        self.assertEqual(code, 2, text)
        d = json.loads(text[text.index("{"):])
        self.assertEqual(d["worst"], "fatal")
        self.assertIn("libfoo.so", {g["module"] for g in d["gaps"]})

    def test_parser_on_saved_log(self):
        log = ("  101:\tfile=libgood.so.1 [0];  dynamically loaded by /app/bin/x [0]\n"
               "  101:\tfind library=libgood.so.1 [0]; searching\n"
               "  101:\tfile=libgood.so.1 [0];  generating link map\n"
               "  101:\tfile=libbad.so.2 [0];  dynamically loaded by /app/lib/plugin.so [0]\n"
               "  102:\tfile=libbad.so.2 [0];  dynamically loaded by /app/bin/x [0]\n"
               "  102:\tfile=libbad.so.2 [0];  generating link map\n"
               "/app/bin/x: symbol lookup error: /app/lib/libz.so.1: undefined symbol: inflateGetDictionary\n")
        ll = parse_ld_debug(log.splitlines())
        self.assertEqual(dict(ll.failed), {})          # pid 102 loaded it, so 101's request isn't a gap
        self.assertEqual(dict(ll.undefined), {"inflateGetDictionary": 1})
        r = smoke_report(ll, "x")
        self.assertEqual(r.gaps[0].tier, "crash")

    def test_reads_log_file(self):
        log = self.t / "ld.log"
        log.write_text("  7:\tfile=libgone.so [0];  dynamically loaded by ./x [0]\n")
        code, text = run(debpak_main, "smoke", "--log", str(log))
        self.assertIn("libgone.so", text)


if __name__ == "__main__":
    unittest.main()
