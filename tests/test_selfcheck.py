"""The check after a build: what an app's failure points to, and converting again with it."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from debpak import cli, selfcheck
from debpak.selfcheck import Observation, diagnose


def crashed(output: str, code: int = 1) -> Observation:
    return Observation(False, code, None, output)


class TestDiagnose(unittest.TestCase):
    def keys(self, obs, kind="elf", wine=False, tried=()):
        return [r.key for r in diagnose(obs, kind, wine, set(tried)).remedies]

    def test_missing_library(self):
        obs = crashed("/app/opt/x/TrueConf: error while loading shared libraries: libopenvino.so: cannot open "
                      "shared object file: No such file or directory", 127)
        self.assertEqual(self.keys(obs), ["lib:libopenvino.so"])
        self.assertEqual(self.keys(obs, tried={"lib:libopenvino.so"}), [])

    def test_file_looked_for_in_the_home_folder(self):
        # RockBot opens fonts/ relative to where it was started, the home folder
        obs = crashed("ERROR::initGraphics - could not open '/home/sophiap/fonts/pressstart2p.ttf' font", 255)
        self.assertEqual(self.keys(obs), ["chdir"])
        self.assertEqual(self.keys(crashed("could not open /home/sophiap/.config/x.ini")), [])

    def test_qt_and_glibc(self):
        self.assertEqual(self.keys(crashed("libQt6Core.so.6: version `Qt_6.10' not found (required by x)")),
                         ["runtime:kde6.10"])
        self.assertEqual(self.keys(crashed("libc.so.6: version `GLIBC_2.43' not found")), ["runtime:fd26.08"])

    def test_java_display_and_bus_name(self):
        self.assertEqual(self.keys(crashed("Error: cannot find java VM.")), ["java"])
        self.assertEqual(self.keys(crashed("SDL Error: No available video device")), ["perm:x11", "perm:ipc"])
        self.assertEqual(self.keys(crashed("Failed to register: GDBus.Error: name com.example.Tool is taken")),
                         ["own:com.example.Tool"])

    def test_documents_folder(self):
        obs = crashed("AQBot process panicked at crates/core/src/storage_paths.rs:46:10: Could not determine "
                      "Documents directory", 101)
        self.assertEqual(self.keys(obs), ["perm:xdg-documents"])
        r = diagnose(obs, "gtk3", False, set()).remedies[0]
        self.assertEqual((r.option, r.value), ("add_permission", "--filesystem=xdg-documents"))

    def test_relative_path_not_found_starts_in_own_folder(self):
        self.assertEqual(self.keys(crashed("./start.sh: 3: ./mercury/mercury: not found", 127)), ["chdir"])
        self.assertEqual(self.keys(crashed("FATAL: Could not open data/fonts/main.ttf")), ["chdir"])
        self.assertEqual(self.keys(crashed("Error : Could not load module lime@lime_application_create__prime",
                                           255)), ["chdir"])
        # the shell naming its own script, an absolute path, a library: none of them
        self.assertEqual(self.keys(crashed("./run.sh: 3: zenity: not found\n"
                                           "MESA-LOADER: failed to open swrast: /usr/lib/dri/swrast_dri.so: "
                                           "cannot open shared object file: No such file or directory")), [])

    def test_chromium_sandbox_only_for_chromium(self):
        obs = crashed("", 133)
        self.assertEqual(self.keys(obs, kind="electron"), ["no-chromium-sandbox"])
        self.assertEqual(self.keys(obs, kind="qt6"), [])
        # zypak's own failure, when the app then exits
        msg = "[2 zypak-helper] Wait found events, but sd-event found none\n"
        self.assertEqual(self.keys(crashed(msg, 1), kind="cef"), ["no-chromium-sandbox"])
        # while the app runs, only a FATAL line says the sandbox failed (Gitify, a tray app, has no window)
        self.assertEqual(self.keys(Observation(True, None, [], msg), kind="electron"), [])
        fatal = "[3:1125/060925.7:FATAL:content/browser/zygote_host/zygote_host_impl_linux.cc:128] No usable sandbox!"
        self.assertEqual(self.keys(Observation(True, None, [], fatal), kind="electron"), ["no-chromium-sandbox"])

    def test_wine(self):
        obs = crashed("err:module:import_dll Library MFC42.DLL (which is needed by L\"C:\\\\x.exe\") not found")
        self.assertEqual(self.keys(obs, wine=True), ["wine:mfc42"])
        self.assertEqual(self.keys(crashed("", 5), wine=True), ["writable"])

    def test_wine_program_writing_beside_itself(self):
        # UVR is a frozen Python program that keeps data.pkl in the folder it starts in, its own
        uvr = crashed('  File "UVR.py", line 169, in save_data\nPermissionError: [Errno 13] Permission denied: '
                      "'data.pkl'\n")
        self.assertEqual(self.keys(uvr, wine=True), ["writable"])
        dotnet = crashed("System.UnauthorizedAccessException: Access to the path 'Z:\\app\\opt\\tool\\settings.xml' "
                         "is denied.")
        self.assertEqual(self.keys(dotnet, wine=True), ["writable"])
        # a file elsewhere it can't write is another matter
        other = crashed("PermissionError: [Errno 13] Permission denied: 'C:\\Windows\\x.log'")
        self.assertEqual(self.keys(other, wine=True), [])

    def test_wine_mono(self):
        # AdiIRC trips over wine-mono's own assertions and shows its crash dialog
        obs = Observation(True, None, ["AdiIRC", "Sorry AdiIRC crashed"],
                          "/builds/mono/wine-mono/wine-mono-10.4.1/mono/mono/eglib/gpath.c:115: assertion "
                          "'filename != NULL' failed\n")
        self.assertEqual(self.keys(obs, wine=True), ["wine:dotnet48"])
        self.assertEqual(self.keys(obs, wine=True, tried={"wine:dotnet48"}), [])
        # an exception nothing caught, with Mono's stack frames
        trace = ("Unhandled Exception:\nSystem.Reflection.TargetInvocationException: Exception has been thrown\n"
                 "  at System.Runtime.InteropServices.Marshal.ThrowExceptionForHR (System.Int32 errorCode) "
                 "[0x0000a] in <60bb7eaf44204dc583390995e42e38f8>:0 \n")
        self.assertEqual(self.keys(crashed(trace), wine=True), ["wine:dotnet48"])
        snagit = Observation(True, None, [], "field __ImageBase in <Module> should have RVA data, but hasn't\n")
        self.assertEqual(self.keys(snagit, wine=True), ["wine:dotnet48"])
        # the real .NET's traces have no Mono frames, and other programs' output isn't Mono's
        self.assertEqual(self.keys(crashed("Unhandled Exception:\nSystem.IO.IOException: x\n   at A.B()\n"),
                                   wine=True), [])
        self.assertEqual(self.keys(crashed(trace), wine=False), [])

    def test_webkitgtk_app_with_no_window_draws_in_software(self):
        # gg and Agentero, Tauri apps, ran on the test PC and never showed their window
        log = ("     12: file=libwebkit2gtk-4.1.so.0 [0];  needed by /app/bin/gg [0]\n"
               "MESA-EGL: warning: DRI3 error: Could not get DRI3 device\n")
        keys = ["env:WEBKIT_DISABLE_DMABUF_RENDERER", "env:WEBKIT_DISABLE_COMPOSITING_MODE"]
        d = diagnose(Observation(True, None, [], log), "gtk3", False, set())
        self.assertEqual([r.key for r in d.remedies], keys)
        self.assertEqual([r.value for r in d.remedies],
                         ["--env=WEBKIT_DISABLE_DMABUF_RENDERER=1", "--env=WEBKIT_DISABLE_COMPOSITING_MODE=1"])
        self.assertTrue(all(r.option == "add_permission" for r in d.remedies))
        self.assertEqual(self.keys(Observation(True, None, [], log), tried=keys), [])
        # only for a WebKitGTK app, only when it ran, and only when it showed nothing
        self.assertEqual(self.keys(Observation(True, None, [], "file=libgtk-3.so.0 [0]")), [])
        self.assertEqual(self.keys(Observation(True, None, ["gg"], log)), [])
        self.assertEqual(self.keys(Observation(True, None, None, log)), [])
        self.assertEqual(self.keys(crashed(log)), [])

    def test_window_judgement(self):
        self.assertTrue(Observation(True, None, ["Editor"], "").ok)
        self.assertTrue(Observation(True, None, None, "").ok)          # no xdotool: running is all we know
        self.assertFalse(Observation(True, None, [], "").ok)
        self.assertFalse(Observation(True, None, ["Fatal Error"], "").ok)
        self.assertTrue(Observation(True, None, ["TEdit Error Reporting"], "").ok)

    def test_failed_loads(self):
        log = ("  12: file=libfoo.so.2 [0];  dynamically loaded by /app/bin/x [0]\n"
               "  12: file=libGL.so.1 [0];  dynamically loaded by /app/bin/x [0]\n"
               "  12: file=libGL.so.1 [0];  generating link map\n"
               "  12: file=libva.so.2 [0];  dynamically loaded by /app/bin/x [0]\n")
        self.assertEqual(selfcheck.failed_loads(log), ["libfoo.so.2"])        # libva is a GPU probe
        # glibc's own libraries are never bundled, and asking for one made IGdm's conversion refuse
        nss = "  12: file=libnss_myhostname.so.2 [0];  dynamically loaded by /app/bin/x [0]\n"
        self.assertEqual(selfcheck.failed_loads(nss), [])
        # a Qt plugin's processor-specific copy (Snipaste) isn't a library to add
        avx = "  12: file=/usr/lib/plugins/platforms/libqxcb.so.avx2 [0];  dynamically loaded by /app/bin/x [0]\n"
        self.assertEqual(selfcheck.failed_loads(avx), [])
        # Chromium tries many libraries with dlopen() and goes on without them; only start-up needs count
        self.assertEqual(selfcheck.failed_loads(log, "electron"), [])
        needed = "  12: file=libbar.so.1 [0];  needed by /app/bin/x [0]\n"
        self.assertEqual(selfcheck.failed_loads(log + needed, "electron"), ["libbar.so.1"])


class TestConvertAgain(unittest.TestCase):
    def test_converts_again_with_what_the_failure_points_to(self):
        with tempfile.TemporaryDirectory() as t:
            out = Path(t)
            (out / "com.example.App.json").write_text(json.dumps(
                {"id": "com.example.App", "modules": [], "x-debpak": {"kind": "elf"}}))
            args = SimpleNamespace(verify=True, no_build=False, output=str(out), add_library=None)
            seen = []
            runs = iter([crashed("x: error while loading shared libraries: libfoo.so.1: cannot open shared"),
                         Observation(True, None, ["App"], "")])
            with mock.patch.object(cli, "_convert_once", side_effect=lambda a: seen.append(a.add_library) or 0), \
                    mock.patch.object(selfcheck, "available", return_value=True), \
                    mock.patch.object(selfcheck, "observe", side_effect=lambda *a, **k: next(runs)):
                self.assertEqual(cli.cmd_convert(args), 0)
            self.assertEqual(seen, [None, ["libfoo.so.1"]])

    def test_nothing_to_go_on_prints_the_end_of_the_output(self):
        # VSeeFace exited with status 1 under Wine, and all convert said was that nothing pointed anywhere
        with tempfile.TemporaryDirectory() as t:
            out = Path(t)
            (out / "com.example.App.json").write_text(json.dumps(
                {"id": "com.example.App", "modules": [], "finish-args": ["--socket=x11"],
                 "x-debpak": {"kind": "elf"}}))
            args = SimpleNamespace(verify=True, no_build=False, output=str(out), add_library=None)
            said = ("0024:fixme:ntdll:NtQuerySystemInformation info_class SYSTEM_PERFORMANCE_INFORMATION\n"
                    "MESA-EGL: warning: DRI3 error: Could not get DRI3 device\n"
                    "Failed to initialize graphics device\n" * 3)
            runs = iter([crashed("", 1), crashed(said, 1)])
            text = io.StringIO()
            with mock.patch.object(cli, "_convert_once", return_value=0), \
                    mock.patch.object(selfcheck, "available", return_value=True), \
                    mock.patch.object(selfcheck, "observe", side_effect=lambda *a, **k: next(runs)), \
                    contextlib.redirect_stdout(text):
                self.assertEqual(cli.cmd_convert(args), 0)
            self.assertIn("The end of what it printed:\n  | Failed to initialize graphics device\n", text.getvalue())
            self.assertNotIn("fixme", text.getvalue())
            self.assertNotIn("MESA", text.getvalue())
        self.assertEqual(selfcheck.output_tail("a\n\nb\nb\nc\n", lines=2), ["b", "c"])

    def test_a_wine_prefix_the_check_cut_short_is_removed(self):
        # DYMO ID: the checks stopped its first start while it installed dotnet48, and the prefix they
        # left made the next start fail ("could not load kernel32.dll, status c0000135")
        with tempfile.TemporaryDirectory() as t:
            out = Path(t)
            (out / "com.example.App.json").write_text(json.dumps(
                {"id": "com.example.App", "modules": [], "base": "org.winehq.Wine", "x-debpak": {"kind": "wine"}}))
            args = SimpleNamespace(verify=True, no_build=False, output=str(out), add_library=None)
            for existed in (False, True):
                scripts = []
                with mock.patch.object(cli, "_convert_once", return_value=0), \
                        mock.patch.object(selfcheck, "available", return_value=True), \
                        mock.patch.object(selfcheck, "_in_app", side_effect=lambda app, sc: scripts.append(sc) or
                                          (0 if existed or sc != selfcheck.PREFIX_EXISTS else 1)), \
                        mock.patch.object(selfcheck, "observe", return_value=Observation(True, None, [], "")), \
                        contextlib.redirect_stdout(io.StringIO()) as text:
                    cli.cmd_convert(args)
                if existed:          # the user's own prefix, from before, is never touched
                    self.assertEqual(scripts, [selfcheck.PREFIX_EXISTS])
                else:
                    self.assertEqual(scripts, [selfcheck.PREFIX_EXISTS, selfcheck.UNFINISHED_PREFIX])
                    self.assertIn("removed the Wine prefix", text.getvalue())

    def test_which_prefixes_are_unfinished(self):
        import shutil
        import subprocess
        if not shutil.which("sh"):
            self.skipTest("no sh")
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            (t / "bin").mkdir()
            script = selfcheck.UNFINISHED_PREFIX.replace("/app/bin", str(t / "bin"))

            def run(launcher: str, files: list[str]) -> bool:
                p = t / "data/wine"
                shutil.rmtree(t / "data", ignore_errors=True)
                p.mkdir(parents=True)
                for f in files:
                    (p / f).write_text("x")
                (t / "bin/app").write_text(launcher)
                r = subprocess.run(["sh", "-c", script], env={"XDG_DATA_HOME": str(t / "data"), "PATH": "/usr/bin:/bin"})
                self.assertEqual(r.returncode == 0, not p.exists())
                return not p.exists()

            runtimes = '#!/bin/sh\nRUNTIMES="dotnet48"\n'
            self.assertTrue(run(runtimes, ["system.reg"]))
            self.assertFalse(run(runtimes, ["system.reg", ".debpak-runtimes"]))
            self.assertTrue(run("#!/bin/sh\n", []))
            self.assertFalse(run("#!/bin/sh\n", ["system.reg"]))

    def test_a_refused_round_keeps_the_build_before(self):
        # IGdm: a library its check asked for made the conversion refuse; the app built before stays
        with tempfile.TemporaryDirectory() as t:
            out = Path(t)
            (out / "com.example.App.json").write_text(json.dumps(
                {"id": "com.example.App", "modules": [], "x-debpak": {"kind": "elf"}}))
            args = SimpleNamespace(verify=True, no_build=False, output=str(out), add_library=None)
            rcs = iter([0, 2])
            with mock.patch.object(cli, "_convert_once", side_effect=lambda a: next(rcs)), \
                    mock.patch.object(selfcheck, "available", return_value=True), \
                    mock.patch.object(selfcheck, "observe", return_value=crashed(
                        "x: error while loading shared libraries: libfoo.so.1: cannot open shared")):
                self.assertEqual(cli.cmd_convert(args), 0)


    def test_a_round_that_fails_keeps_the_earlier_build(self):
        # Tusk: the loader's log named a library debpak won't bundle, and the second conversion
        # stopped before writing anything, though the first build was installed and running
        with tempfile.TemporaryDirectory() as t:
            out = Path(t)
            (out / "com.example.App.json").write_text(json.dumps(
                {"id": "com.example.App", "modules": [], "x-debpak": {"kind": "elf"}}))
            args = SimpleNamespace(verify=True, no_build=False, output=str(out), add_library=None)
            seen = []
            runs = iter([crashed("x: error while loading shared libraries: libfoo.so.1: cannot open shared")])
            with mock.patch.object(cli, "_convert_once", side_effect=lambda a: seen.append(a.add_library) or
                                   (2 if a.add_library else 0)), \
                    mock.patch.object(selfcheck, "available", return_value=True), \
                    mock.patch.object(selfcheck, "observe", side_effect=lambda *a, **k: next(runs)):
                self.assertEqual(cli.cmd_convert(args), 0)
            self.assertEqual(seen, [None, ["libfoo.so.1"]])          # not built a third time
            self.assertIsNone(args.add_library)

            # when the failed round did write a new manifest, the earlier options are built again
            seen.clear()
            runs = iter([crashed("x: error while loading shared libraries: libfoo.so.1: cannot open shared")])

            def convert(a):
                seen.append(a.add_library)
                if a.add_library:
                    (out / "com.example.App.json").write_text(json.dumps(
                        {"id": "com.example.App", "modules": [1], "x-debpak": {"kind": "elf"}}))
                    return 1
                return 0
            with mock.patch.object(cli, "_convert_once", side_effect=convert), \
                    mock.patch.object(selfcheck, "available", return_value=True), \
                    mock.patch.object(selfcheck, "observe", side_effect=lambda *a, **k: next(runs)):
                self.assertEqual(cli.cmd_convert(args), 0)
            self.assertEqual(seen, [None, ["libfoo.so.1"], None])

    def test_graphical_app_that_quits_silently_runs_from_a_copy(self):
        # OpenTaiko prints its arguments and quits with status 0 when it can't use the files beside it
        for entry, fmt, want in (("Terminal=false\n", "tarball", [None, True]), ("Terminal=true\n", "tarball", [None]),
                                 (None, "tarball", [None]), ("Terminal=false\n", "snap", [None]),
                                 ("x11", "tarball", [None, True])):
            with tempfile.TemporaryDirectory() as t:
                out = Path(t)
                (out / "com.example.App.json").write_text(json.dumps(
                    {"id": "com.example.App", "modules": [], "x-debpak": {"kind": "elf", "format": fmt},
                     "finish-args": ["--socket=x11"] if entry == "x11" else []}))
                if entry not in (None, "x11"):
                    (out / "app/share/applications").mkdir(parents=True)
                    (out / "app/share/applications/com.example.App.desktop").write_text(
                        "[Desktop Entry]\nType=Application\nExec=debpak-run\n" + entry)
                args = SimpleNamespace(verify=True, no_build=False, output=str(out), writable=None)
                seen = []
                runs = iter([crashed("Args: (None)", 0), crashed("Args: (None)", 0),
                             Observation(True, None, ["OpenTaiko"], "")])
                with mock.patch.object(cli, "_convert_once", side_effect=lambda a: seen.append(a.writable) or 0), \
                        mock.patch.object(selfcheck, "available", return_value=True), \
                        mock.patch.object(selfcheck, "observe", side_effect=lambda *a, **k: next(runs)):
                    self.assertEqual(cli.cmd_convert(args), 0)
                self.assertEqual(seen, want)

class TestCommandLine(unittest.TestCase):
    ARK = "usage: ark <command> [flags]\n\ncommands:\n  version                        print CLI version\n"
    TOOL = "appimagetool, continuous build\n\nERROR: SOURCE is missing\n"
    TOOL_HELP = "Usage:\n  appimagetool [OPTION...] SOURCE [DESTINATION] - Generate AppImages from existing AppDirs\n"

    def test_evidence(self):
        bare = Observation(False, 2, None, self.ARK, 0)
        self.assertTrue(selfcheck.command_line(bare, None))
        tool = Observation(False, 1, None, self.TOOL, 0)
        self.assertFalse(selfcheck.command_line(tool, None))
        self.assertTrue(selfcheck.command_line(tool, Observation(False, 0, None, self.TOOL_HELP, 0)))
        # --help has to work: exit 0 and print a usage line
        self.assertFalse(selfcheck.command_line(tool, Observation(False, 1, None, self.TOOL_HELP, 0)))
        self.assertFalse(selfcheck.command_line(tool, Observation(False, 0, None, "unknown option --help", 0)))
        # it has to exit, and at once
        self.assertFalse(selfcheck.command_line(Observation(True, None, [], self.ARK), None))
        self.assertFalse(selfcheck.command_line(Observation(False, 2, None, self.ARK, 30), None))
        # a word "usage" inside a line isn't a usage line
        self.assertFalse(selfcheck.command_line(Observation(False, 1, None, "memory usage: 30%", 0), None))

    def test_observe_reads_how_long_it_ran(self):
        def run(cmd, **kw):
            return SimpleNamespace(stdout="DEBPAK-EXIT 2 AFTER 1\n", returncode=0)
        with mock.patch.object(selfcheck.subprocess, "run", side_effect=run):
            obs = selfcheck.observe("com.example.App", 5, args=["--help"])
        self.assertEqual((obs.running, obs.code, obs.seconds), (False, 2, 1))

    def convert(self, entry, runs):
        with tempfile.TemporaryDirectory() as t:
            out = Path(t)
            (out / "com.example.App.json").write_text(json.dumps(
                {"id": "com.example.App", "modules": [], "x-debpak": {"kind": "elf", "format": "tarball"},
                 "finish-args": ["--socket=x11"] if entry == "x11" else []}))
            if entry not in (None, "x11"):
                (out / "app/share/applications").mkdir(parents=True)
                (out / "app/share/applications/com.example.App.desktop").write_text(
                    "[Desktop Entry]\nType=Application\nExec=debpak-run\n" + entry)
            args = SimpleNamespace(verify=True, no_build=False, output=str(out), writable=None, add_library=None)
            asked, runs = [], iter(runs)

            def observe(app_id, seconds, env=None, args=None):
                asked.append(args)
                return next(runs)
            printed = []
            with mock.patch.object(cli, "_convert_once", return_value=0), \
                    mock.patch.object(cli, "_app_id_of", return_value="com.example.App"), \
                    mock.patch.object(selfcheck, "available", return_value=True), \
                    mock.patch.object(selfcheck, "observe", side_effect=observe), \
                    mock.patch("builtins.print", side_effect=lambda *a, **k: printed.append(" ".join(map(str, a)))):
                self.assertEqual(cli.cmd_convert(args), 0)
            return asked, any(f"Check: {selfcheck.COMMAND_LINE}:" in p for p in printed)

    def test_convert_says_so_and_stops(self):
        # Arkloop: no desktop file, and its usage on stderr
        self.assertEqual(self.convert(None, [Observation(False, 2, None, self.ARK, 0)]), ([None], True))
        # appimagetool: a Terminal=true menu entry, and its usage only with --help
        self.assertEqual(self.convert("Terminal=true\n", [Observation(False, 1, None, self.TOOL, 0),
                                                            Observation(False, 0, None, self.TOOL_HELP, 0)]),
                         ([None, ["--help"]], True))
        # a graphical app that prints its usage and quits is not one: it goes on to the loader's log
        asked, said = self.convert("x11", [Observation(False, 2, None, self.ARK, 0),
                                           Observation(False, 2, None, self.ARK, 0)])
        self.assertFalse(said)
        self.assertNotIn(["--help"], asked)
        asked, said = self.convert("Terminal=false\n", [Observation(False, 2, None, self.ARK, 0),
                                                         Observation(False, 2, None, self.ARK, 0)])
        self.assertFalse(said)


FAKE_XDOTOOL = """#!/bin/sh
# Ren'Py's launcher: a search by name misses it (its WM_NAME has the type UTF-8), one by class finds it
case "$1 $3" in
    "search --name") echo 1 ;;
    "search --classname") printf '1\\n2\\n' ;;
    "getwindowname ") [ "$2" = 2 ] && echo "Ren'Py Launcher" ;;
esac
"""


class TestObserver(unittest.TestCase):
    def test_window_found_by_class(self):
        import os
        import subprocess
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            (t / "xdotool").write_text(FAKE_XDOTOOL)
            (t / "xdotool").chmod(0o755)
            (t / "observe.sh").write_text(selfcheck.OBSERVER)
            env = {**os.environ, "PATH": f"{t}:{os.environ['PATH']}"}
            marks = subprocess.run(["sh", str(t / "observe.sh"), "1", str(t / "out"), "sleep", "5"], env=env,
                                   capture_output=True, text=True, timeout=30).stdout
        self.assertIn("DEBPAK-RUNNING", marks)
        self.assertEqual(marks.count("DEBPAK-WINDOW"), 2)
        self.assertIn("DEBPAK-WINDOW Ren'Py Launcher", marks)


if __name__ == "__main__":
    unittest.main()
