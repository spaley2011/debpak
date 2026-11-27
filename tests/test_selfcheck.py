"""The check after a build: what an app's failure points to, and converting again with it."""
import contextlib
import io
import json
import os
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

    def test_file_the_user_would_copy_into_a_dot_folder(self):
        # clrsync's GUI wants ~/.config/clrsync/config.toml, which its package ships in /usr/share/clrsync
        obs = crashed("Fatal error: File does not exist [/home/sophiap/.config/clrsync/config.toml]\n"
                      "Hint: Set CLRSYNC_CONFIG_PATH environment variable or ensure config exists at: "
                      "/home/sophiap/.config/clrsync/config.toml", 1)
        d = diagnose(obs, "elf", False, set())
        self.assertEqual([(r.key, r.option, r.value) for r in d.remedies],
                         [("seed:.config/clrsync/config.toml", "seed_home", ".config/clrsync/config.toml")])
        self.assertEqual(self.keys(obs, tried={"seed:.config/clrsync/config.toml"}), [])
        # the app's own folder, a file named in passing, and a path with no folder of its own aren't
        self.assertEqual(self.keys(crashed("cannot open /home/u/.var/app/x/config/a/b.toml")), [])
        self.assertEqual(self.keys(crashed("loaded /home/u/.config/a/b.toml")), [])
        self.assertEqual(self.keys(crashed("could not open /home/u/.config/b.toml")), [])
        # and it's dropped when the conversion has no copy to give it
        with tempfile.TemporaryDirectory() as t:
            app = Path(t) / "app/share/clrsync"
            app.mkdir(parents=True)
            d = diagnose(obs, "elf", False, set())
            cli._drop_unseedable(SimpleNamespace(output=t), d)
            self.assertEqual(d.remedies, [])
            (app / "config.toml").write_text("")
            d = diagnose(obs, "elf", False, set())
            cli._drop_unseedable(SimpleNamespace(output=t), d)
            self.assertEqual([r.key for r in d.remedies], ["seed:.config/clrsync/config.toml"])

    def test_a_question_about_crash_reports_is_no_error(self):
        # Kimitzu Client's "Crash Reporting" window asks whether to send crash reports, beside its own window
        self.assertTrue(Observation(True, None, ["Crash Reporting", "Kimitzu Client"], "").ok)
        self.assertFalse(Observation(True, None, ["Mozilla Crash Reporter"], "").ok)
        self.assertEqual(Observation(True, None, ["Mozilla Crash Reporter"], "").describe(),
                         "showing an error (Mozilla Crash Reporter)")

    def test_program_looked_for_on_path(self):
        # rkdeveloptool-gui's dialog: "Error: rkdeveloptool not found"; and what shells say
        obs = Observation(True, None, ["Error: rkdeveloptool not found"], "")
        d = diagnose(obs, "elf", False, set())
        self.assertIn(("program:rkdeveloptool", "add_program", "rkdeveloptool"),
                      [(r.key, r.option, r.value) for r in d.remedies])
        self.assertEqual(selfcheck.missing_programs(crashed("sh: 1: rsync: not found\n/bin/sh: zenity: command not "
                                                            "found\nThe program depends on 'adb', but", 1)),
                         ["rsync", "adb"])
        # a kind of thing, a file, a library or a Python module is no program
        for said in ("Error: file not found", "'config.toml' not found", "ERROR: module not found",
                     "Fatal error: File does not exist", "'libfoo' not found", "theme 'Adwaita' not found"):
            self.assertEqual(selfcheck.missing_programs(crashed(said, 1)), [], said)
        self.assertNotIn("program:rkdeveloptool", self.keys(obs, tried={"program:rkdeveloptool"}))

    def test_qt_and_glibc(self):
        self.assertEqual(self.keys(crashed("libQt6Core.so.6: version `Qt_6.10' not found (required by x)")),
                         ["runtime:kde6.10"])
        self.assertEqual(self.keys(crashed("libc.so.6: version `GLIBC_2.43' not found")), ["runtime:fd26.08"])

    def test_java_display_and_bus_name(self):
        self.assertEqual(self.keys(crashed("Error: cannot find java VM.")), ["java"])
        self.assertEqual(self.keys(crashed("SDL Error: No available video device")), ["perm:x11", "perm:ipc"])
        self.assertEqual(self.keys(crashed("Failed to register: GDBus.Error: name com.example.Tool is taken")),
                         ["own:com.example.Tool"])
        # PyGlossary's GApplication didn't name the ID (apps.pyglossary) the bus proxy refused
        unnamed = crashed("Failed to register: GDBus.Error:org.freedesktop.DBus.Error.ServiceUnknown: "
                          "org.freedesktop.DBus.Error.ServiceUnknown")
        self.assertEqual(self.keys(unnamed), ["perm:session-bus"])
        self.assertEqual(diagnose(unnamed, "elf", False, set()).remedies[0].value, "--socket=session-bus")
        self.assertEqual(self.keys(unnamed, tried={"perm:session-bus"}), [])

    def test_a_window_saying_its_folder_is_not_writable(self):
        obs = Observation(True, None, ["The launcher data folder is not writable! — Fjord Launcher 11.1.1.0"], "")
        self.assertFalse(obs.ok)
        self.assertEqual(self.keys(obs), ["writable"])

    def test_a_program_refusing_its_hard_linked_files_runs_from_a_copy(self):
        # every file in a Flatpak's /app is a hard link into its OSTree repository, and Open CoDesign reads
        # its templates only from files with one link
        obs = Observation(True, None, ["Open CoDesign failed to start"],
                          "[error]  (method-skill-upgrades) skills.upgrade.failed {\n  error: 'Expected an "
                          "unlinked regular file: /app/opt/Open-CoDesign/resources/templates/skills/a.md'\n}")
        self.assertEqual(self.keys(obs), ["writable"])
        self.assertEqual(self.keys(obs, tried={"writable"}), [])
        # a file outside the app isn't its own
        self.assertEqual(self.keys(crashed("Expected an unlinked regular file: /home/u/notes.md")), [])

    def test_webkit_sandbox_refused_by_the_portal(self):
        obs = crashed("Portal call failed: Invalid sandbox a11y own name: 'org.wails.yt-go.Sandboxed.WebProcess-e45' "
                      "doesn't match app id\n** (YT-GO:4): ERROR **: Connection: failed to receive credentials", 2)
        self.assertEqual(self.keys(obs), ["env:WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS"])

    def test_bad_system_call_gets_multiarch(self):
        # Subway Surfers' Wine ran a 32-bit game, and Flatpak's seccomp filter killed it
        obs = crashed('/app/opt/subway-surfers/AppRun: line 15:     7 Bad system call            (core dumped) '
                      'wine "$HERE/usr/share/subwaysurfers/Subway Surfers.exe" "$@"', 159)
        self.assertEqual(self.keys(obs), ["perm:multiarch"])
        self.assertEqual(self.keys(crashed("", 159)), ["perm:multiarch"])
        self.assertEqual(self.keys(obs, tried={"perm:multiarch"}), [])

        # KDBusService in a Flatpak: the connection's unique name follows the app's, different every start
        obs = crashed("Failed to register name 'org.kde.kgoldrunner.kdbus-_1_7' with DBUS - does this process "
                      "have permission to do so?")
        self.assertEqual(self.keys(obs), ["own:org.kde.kgoldrunner.*"])
        self.assertEqual(selfcheck.diagnose(obs, "qt6", False, set()).remedies[0].value, "--own-name=org.kde.kgoldrunner.*")

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
        # Fether's Electron 7, whose GPU process kept crashing, while its Parity node ran on
        gpu = ("[3:1126/191937.948764:FATAL:gpu_data_manager_impl_private.cc(962)] The display compositor is "
               "frequently crashing. Goodbye.\n")
        self.assertEqual(self.keys(Observation(True, None, [], gpu), kind="electron"), ["no-chromium-sandbox"])
        self.assertEqual(self.keys(crashed(gpu, 133), kind="electron"), ["no-chromium-sandbox"])

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
        # vimacc's Admin Center keeps its logs beside itself and said only this before it quit
        vimacc = crashed("[32:36:1126/165532.440:ERROR:network_change_notifier_win.cc(142)] WSALookupServiceBegin "
                         "failed with: 8\nError opening logfile:  3\n", 1)
        self.assertEqual(self.keys(vimacc, wine=True), ["writable"])
        self.assertEqual(self.keys(crashed("Failed to create log file C:\\x\\a.log\n"), wine=True), ["writable"])
        self.assertEqual(self.keys(crashed("Logfile opened: a.log\nerror loading module\n"), wine=True), [])
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
        # an exception about one of wine-mono's own files: Creallo Atlas's pywebview, through pythonnet
        atlas = Observation(True, None, ["Unhandled exception in script"],
                            "System.BadImageFormatException: Invalid Image: Z:\\app\\share\\wine\\mono\\"
                            "wine-mono-10.4.1\\lib\\mono\\4.5\\System.Windows.Forms.dll\n")
        self.assertEqual(self.keys(atlas, wine=True), ["wine:dotnet48"])
        self.assertEqual(self.keys(snagit, wine=True), ["wine:dotnet48"])
        # the real .NET's traces have no Mono frames, and other programs' output isn't Mono's
        self.assertEqual(self.keys(crashed("Unhandled Exception:\nSystem.IO.IOException: x\n   at A.B()\n"),
                                   wine=True), [])
        self.assertEqual(self.keys(crashed(trace), wine=False), [])

    def test_wine_runtimes_the_plan_missed(self):
        # a function Wine's own runtime DLL lacks: the real runtime has it
        obs = crashed("wine: Call from 00006FFFFFF9DDAA to unimplemented function msvcp140.dll."
                      "?_Xbad_function_call@std@@YAXXZ, aborting\n", 1)
        self.assertEqual(self.keys(obs, wine=True), ["wine:vcrun2022"])
        self.assertEqual(self.keys(obs, wine=True, tried={"wine:vcrun2022"}), [])
        # Wine itself lacking one (PlayStation Accessories) has no runtime to install
        self.assertEqual(self.keys(crashed("wine: Call from 00006FFFFFF9DDAA to unimplemented function "
                                           "ntdll.dll.NtCreateWaitCompletionPacket, aborting"), wine=True), [])
        # .NET's apphost names the framework it was built for, in the event log Wine prints
        apphost = ("0120:err:eventlog:ReportEventW L\"Description: A .NET application failed.\\nApplication: "
                   "x.exe\\nMessage: You must install or update .NET to run this application.\\n\\nApp: x.exe"
                   "\\nArchitecture: x64\\nFramework: 'Microsoft.WindowsDesktop.App', version '8.0.0' (x64)\"\n")
        self.assertEqual(self.keys(crashed(apphost), wine=True), ["wine:dotnetdesktop8"])
        old = "The framework 'Microsoft.NETCore.App', version '6.0.0' (x64) was not found.\n"
        self.assertEqual(self.keys(crashed(old), wine=True), ["wine:dotnet6"])
        self.assertEqual(self.keys(crashed(old.replace("6.0.0", "3.1.0")), wine=True), [])
        # with no .NET at all it names only its own version: OpenDirectoryDownloader 5.1, on .NET 11
        none = "".join(f'00e0:err:eventlog:ReportEventW L"{ln}\\n"\n' for ln in (
            "Path: Z:\\app\\opt\\odd\\OpenDirectoryDownloader.exe",
            "Message: You must install .NET to run this application.", "",
            "App: Z:\\app\\opt\\odd\\OpenDirectoryDownloader.exe", "Architecture: x64",
            "App host version: 11.0.0", ".NET location: Not found"))
        self.assertEqual(self.keys(crashed(none, 131), wine=True), ["wine:dotnet11"])
        # a Wails app without WebView2 (Swiss Knife Graph, QShell): said, with nothing to install
        wails = Observation(True, None, ["Missing Requirements"], "")
        self.assertFalse(wails.ok)
        d = diagnose(wails, "wine", True, set())
        self.assertEqual(d.remedies, [])
        self.assertIn("it needs Microsoft's WebView2 runtime, which its first start downloads into the Wine prefix",
                      d.evidence)

    def test_runtimes_the_plan_installs_are_no_remedy(self):
        # converting again with --wine-runtime vcrun2022 for a program whose launcher already installs it
        # builds the same app again
        with tempfile.TemporaryDirectory() as t:
            out = Path(t)
            (out / "com.example.App.json").write_text(json.dumps(
                {"id": "com.example.App", "modules": [], "base": "org.winehq.Wine",
                 "x-debpak": {"kind": "wine", "runtimes": ["vcrun2022"]}}))
            args = SimpleNamespace(verify=True, no_build=False, output=str(out), add_library=None, wine_runtime=None)
            said = crashed("wine: Call from 0000 to unimplemented function msvcp140.dll.x, aborting\n")
            with mock.patch.object(cli, "_convert_once", return_value=0) as conv, \
                    mock.patch.object(selfcheck, "available", return_value=True), \
                    mock.patch.object(selfcheck, "_in_app", return_value=1), \
                    mock.patch.object(selfcheck, "observe", return_value=said), \
                    contextlib.redirect_stdout(io.StringIO()):
                cli.cmd_convert(args)
            self.assertEqual(conv.call_count, 1)
            self.assertIsNone(args.wine_runtime)

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
                    (p / f).parent.mkdir(parents=True, exist_ok=True)
                    (p / f).write_text("x")
                (t / "bin/app").write_text(launcher)
                r = subprocess.run(["sh", "-c", script], env={"XDG_DATA_HOME": str(t / "data"), "PATH": "/usr/bin:/bin"})
                self.assertEqual(r.returncode == 0, not p.exists())
                return not p.exists()

            k32 = "drive_c/windows/system32/kernel32.dll"
            runtimes = '#!/bin/sh\nRUNTIMES="dotnet48"\n'
            whole = ["system.reg", k32, ".debpak-prefix"]
            self.assertTrue(run(runtimes, whole))
            self.assertFalse(run(runtimes, [*whole, ".debpak-runtimes"]))
            # the launcher was installing when the check stopped it, whatever else is there
            self.assertTrue(run(runtimes, [*whole, ".debpak-runtimes", ".debpak-installing"]))
            self.assertTrue(run("#!/bin/sh\n", []))
            self.assertFalse(run("#!/bin/sh\n", ["system.reg", k32, ".debpak-prefix"]))
            # Racemo: kernel32.dll and the registry, but wine.inf never applied, and wineboot won't apply it
            self.assertTrue(run("#!/bin/sh\n", ["system.reg", k32, ".update-timestamp"]))
            # a prefix set up whole before the launcher marked it so has wine.inf's services
            p = t / "data/wine"
            self.assertTrue(run("#!/bin/sh\n", ["system.reg", k32]))
            p.mkdir(parents=True)
            (p / k32).parent.mkdir(parents=True)
            (p / k32).write_text("x")
            (p / "system.reg").write_text("[System\\\\ControlSet001\\\\Services\\\\RpcSs] 1795754926\n")
            r = subprocess.run(["sh", "-c", script], env={"XDG_DATA_HOME": str(t / "data"), "PATH": "/usr/bin:/bin"})
            self.assertEqual(r.returncode, 1)
            self.assertTrue(p.exists())
            # Intel's BCT: the check stopped wineboot after the registry, before kernel32.dll
            self.assertTrue(run("#!/bin/sh\n", ["system.reg", ".update-timestamp", "drive_c/windows/system32/ntdll.dll"]))

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
    MOLVA = ("System-wide voice input\n\nUsage: molva <COMMAND>\n\nCommands:\n  daemon      Run the daemon\n"
             "  transcribe  Transcribe a file\n\nOptions:\n  -h, --help     Print help\n"
             "  -V, --version  Print version\n")
    ZSYNC2 = ("zsync2 version 2.0.0-alpha-1 (commit fc62ae7)\n  /app/opt/zsync2/usr/bin/zsync2 {OPTIONS} [path or URL]\n\n"
              "    zsync2 -- the probably easiest efficient way to update files\n\n  OPTIONS:\n\n"
              "      -h, --help                        Display this help menu.\n")

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

    def test_check_runs_the_app_as_in_a_desktop_session(self):
        # Fluxy reads DESKTOP_SESSION and stopped at "Error: EnvVar(NotPresent)" in a check from SSH
        self.assertEqual(selfcheck.session_env({}), {"DESKTOP_SESSION": "debpak-check"})
        self.assertEqual(selfcheck.session_env({"DESKTOP_SESSION": "plasma"}), {})
        seen = []

        def run(cmd, **kw):
            seen.append(cmd)
            return SimpleNamespace(stdout="DEBPAK-EXIT 0 AFTER 1\n", returncode=0)
        with mock.patch.object(selfcheck.subprocess, "run", side_effect=run), \
                mock.patch.dict(os.environ, {"DESKTOP_SESSION": ""}):
            selfcheck.observe("com.example.App", 5)
        self.assertIn("--env=DESKTOP_SESSION=debpak-check", seen[0])
        self.assertNotIn("--env=LIBGL_ALWAYS_SOFTWARE=1", seen[0])

    def test_a_windows_program_draws_in_software_on_the_virtual_display(self):
        # TouchOSC and vimacc: Wine's EGL took the test PC's NVIDIA card, whose driver the sandbox
        # lacks ("egl: failed to create dri2 screen"), and they were left with no OpenGL and no window
        seen = []

        def run(cmd, **kw):
            seen.append(cmd)
            return SimpleNamespace(stdout="DEBPAK-EXIT 0 AFTER 1\n", returncode=0)
        with mock.patch.object(selfcheck.subprocess, "run", side_effect=run):
            selfcheck.observe("com.example.App", 5, wine=True)
            selfcheck.observe("com.example.App", 5, {"LIBGL_ALWAYS_SOFTWARE": "0"}, wine=True)
        self.assertIn("--env=LIBGL_ALWAYS_SOFTWARE=1", seen[0])
        self.assertIn("--env=LIBGL_ALWAYS_SOFTWARE=0", seen[2])

    def test_the_check_stops_waiting_once_a_window_has_stayed_up(self):
        # the check waited its full 40 s for every app, even one whose window was up in 3: the
        # conversions of batch 2 took a median 266 s against 44 s before the check
        import subprocess
        import time
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            script = t / "observe.sh"
            script.write_text(selfcheck.OBSERVER)
            bin_ = t / "bin"
            bin_.mkdir()
            (bin_ / "xdotool").write_text('#!/bin/sh\n[ "$1" = search ] && echo 42\n[ "$1" = getwindowname ] && echo Main\n'
                                          'exit 0\n')
            (bin_ / "xdotool").chmod(0o755)
            env = {"PATH": f"{bin_}:/usr/bin:/bin", "DEBPAK_CHECK_SETTLE": "4"}
            began = time.monotonic()
            r = subprocess.run(["sh", str(script), "30", str(t / "out"), "", "sleep", "60"], env=env,
                               capture_output=True, text=True, timeout=90)
            self.assertLess(time.monotonic() - began, 20)
            self.assertIn("DEBPAK-RUNNING", r.stdout)
            self.assertIn("DEBPAK-WINDOW Main", r.stdout)

    def test_the_app_inside_is_asked_to_end_before_its_sandbox_is_stopped(self):
        # ending flatpak run (bwrap) kills the sandbox outright, and Mira's lock file stayed behind,
        # so its next start quit: the processes below the one the check started get TERM first
        import subprocess
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            script = t / "observe.sh"
            script.write_text(selfcheck.OBSERVER)
            inner = f'trap "echo cleaned >> {t}/log; exit 0" TERM; while :; do sleep 0.2; done'
            # "; true" keeps the outer shell from exec'ing the inner one, as bwrap stays above the app
            r = subprocess.run(["sh", str(script), "1", str(t / "out"), "", "sh", "-c", f"sh -c '{inner}'; true"],
                               capture_output=True, text=True, timeout=60)
            self.assertIn("DEBPAK-RUNNING", r.stdout)
            self.assertEqual((t / "log").read_text(), "cleaned\n")

    def test_a_windows_program_is_ended_cleanly(self):
        # VidCutter's sandbox was killed, wineserver and all, once the check had seen its window, and
        # the next start showed none: a Windows program is asked to end, and Wine waited for, first
        import subprocess
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            script = t / "observe.sh"
            script.write_text(selfcheck.OBSERVER)
            app = f'while [ ! -e {t}/stop ]; do sleep 0.2; done; echo ended >> {t}/log'
            r = subprocess.run(["sh", str(script), "1", str(t / "out"), f"touch {t}/stop", "sh", "-c", app],
                               capture_output=True, text=True, timeout=60)
            self.assertIn("DEBPAK-RUNNING", r.stdout)
            self.assertEqual((t / "log").read_text(), "ended\n")
            # in the sandbox: the session is ended, and Wine waited for; it's only stopped if it stays
            bin_ = t / "bin"
            bin_.mkdir()
            for name, body in (("wineboot", 'echo "wineboot $*" >> "$LOG"'),
                               ("wineserver", 'echo "wineserver $* $WINEPREFIX" >> "$LOG"; '
                                              '[ "$1" != -w ] || [ ! -e "$STAYS" ]')):
                (bin_ / name).write_text(f"#!/bin/sh\n{body}\n")
                (bin_ / name).chmod(0o755)
            env = {"PATH": f"{bin_}:/usr/bin:/bin", "LOG": str(t / "wlog"), "XDG_DATA_HOME": str(t / "data"),
                   "STAYS": str(t / "stays")}
            subprocess.run(["sh", "-c", selfcheck.WINE_STOP], env=env, check=True, timeout=60)
            self.assertEqual((t / "wlog").read_text().splitlines(),
                             ["wineboot --end-session --force --shutdown", f"wineserver -w {t}/data/wine"])
            (t / "wlog").unlink()
            (t / "stays").touch()
            subprocess.run(["sh", "-c", selfcheck.WINE_STOP], env=env, timeout=60)
            self.assertEqual([ln.split()[1] for ln in (t / "wlog").read_text().splitlines()[1:]],
                             ["-w", "-k15", "-w", "-k"])
            self.assertIn("flatpak enter com.example.App sh -c", selfcheck.stop_command("com.example.App"))

    def convert(self, entry, runs, fmt="tarball", x11=False):
        with tempfile.TemporaryDirectory() as t:
            out = Path(t)
            (out / "com.example.App.json").write_text(json.dumps(
                {"id": "com.example.App", "modules": [], "x-debpak": {"kind": "elf", "format": fmt},
                 "finish-args": ["--socket=x11"] if entry == "x11" or x11 else []}))
            if entry not in (None, "x11"):
                (out / "app/share/applications").mkdir(parents=True)
                (out / "app/share/applications/com.example.App.desktop").write_text(
                    "[Desktop Entry]\nType=Application\nExec=debpak-run\n" + entry)
            args = SimpleNamespace(verify=True, no_build=False, output=str(out), writable=None, add_library=None)
            asked, runs = [], iter(runs)

            def observe(app_id, seconds, env=None, args=None, wine=False, terminal=False):
                asked.append(["(terminal)"] if terminal else args)
                return next(runs)
            printed = []
            with mock.patch.object(cli, "_convert_once", return_value=0), \
                    mock.patch.object(cli, "_app_id_of", return_value="com.example.App"), \
                    mock.patch.object(selfcheck, "available", return_value=True), \
                    mock.patch.object(selfcheck, "observe", side_effect=observe), \
                    mock.patch("builtins.print", side_effect=lambda *a, **k: printed.append(" ".join(map(str, a)))):
                self.assertEqual(cli.cmd_convert(args), 0)
            return asked, any(f"Check: {selfcheck.COMMAND_LINE}:" in p for p in printed)

    def test_an_appimages_menu_entry_is_no_sign_of_a_window(self):
        # bisonc++'s AppImage, a parser generator whose libraries link X11, has the menu entry every
        # AppImage must (Terminal=false), and printed its usage and options and ended with status 1
        bison = Observation(False, 1, None, "Usage: bisonc++ [OPTIONS] file\nWhere:\n"
                            "   --analyze-only (-A):\n           only analyze the grammar\n"
                            "   --class-name=<name>:\n           the name of the generated C++ class.\n"
                            "   --version (-v):\n           display bisonc++'s version and terminate.\n", 0)
        self.assertEqual(self.convert("Terminal=false\n", [bison], fmt="appimage", x11=True), ([None], True))
        # the same menu entry in a .deb is one the packager chose to write
        self.assertFalse(self.convert("Terminal=false\n", [bison] * 4, fmt="deb", x11=True)[1])
        # and an AppImage's graphical app that only wants a file to open isn't one
        viewer = Observation(False, 2, None, "usage: viewer [options] FILE\n", 0)
        self.assertFalse(self.convert("Terminal=false\n", [viewer] * 4, fmt="appimage", x11=True)[1])

    def test_what_the_check_left_in_the_apps_folder_goes(self):
        # Clipboard's rpm (Tauri) left its lock naming PID 4 when the check ended it; the next start, PID 4
        # again, found itself there ("another instance is already running") and aborted
        import subprocess
        with tempfile.TemporaryDirectory() as t:
            d = Path(t) / ".var/app/com.example.App"
            env = {"HOME": t, "FLATPAK_ID": "com.example.App", "PATH": "/usr/bin:/bin"}

            def sh(script):
                return subprocess.run(["sh", "-c", script], env=env).returncode
            self.assertEqual(sh(selfcheck.APP_DATA_EMPTY), 0)           # never started
            for sub in ("cache", "config", "data"):
                (d / sub).mkdir(parents=True)
            self.assertEqual(sh(selfcheck.APP_DATA_EMPTY), 0)           # started, nothing kept
            (d / "data/com.clipboard.desktop").mkdir()
            (d / "data/com.clipboard.desktop/instance.lock").write_text("4")
            self.assertNotEqual(sh(selfcheck.APP_DATA_EMPTY), 0)
            self.assertEqual(sh(selfcheck.CLEAR_APP_DATA), 0)
            self.assertEqual(sorted(p.name for p in d.iterdir()), ["cache", "config", "data"])
            self.assertEqual(list((d / "data").iterdir()), [])
        # convert clears it after the check only when the app had kept nothing before
        for before, cleared in ((0, True), (1, False)):
            scripts = []

            def in_app(app_id, script, before=before):
                scripts.append(script)
                return before if script == selfcheck.APP_DATA_EMPTY else 0
            with mock.patch.object(selfcheck, "_in_app", side_effect=in_app):
                self.convert(None, [Observation(True, None, ["Clipboard"], "")])
            self.assertEqual(selfcheck.CLEAR_APP_DATA in scripts, cleared)

    def test_convert_says_so_and_stops(self):
        # Arkloop: no desktop file, and its usage on stderr
        self.assertEqual(self.convert(None, [Observation(False, 2, None, self.ARK, 0)]), ([None], True))
        # appimagetool: a Terminal=true menu entry, and its usage only with --help
        self.assertEqual(self.convert("Terminal=true\n", [Observation(False, 1, None, self.TOOL, 0),
                                                            Observation(False, 0, None, self.TOOL_HELP, 0)]),
                         ([None, ["--help"]], True))
        # a graphical app that prints its usage and quits is not one: it goes on to the loader's log
        viewer = Observation(False, 2, None, "usage: viewer [options] FILE\n", 0)
        asked, said = self.convert("x11", [viewer, viewer])
        self.assertFalse(said)
        self.assertNotIn(["--help"], asked)
        asked, said = self.convert("Terminal=false\n", [Observation(False, 2, None, self.ARK, 0),
                                                         Observation(False, 2, None, self.ARK, 0)])
        self.assertFalse(said)
        # unless no menu entry starts it and it names commands of its own: MolvAI's molva links X11 to
        # type into other windows
        molva = Observation(False, 2, None, self.MOLVA, 0)
        self.assertEqual(self.convert("x11", [molva]), ([None], True))
        self.assertFalse(self.convert("Terminal=false\n", [molva, molva])[1])
        self.assertFalse(selfcheck.command_line(Observation(False, 2, None, self.TOOL_HELP, 0), None, graphical=True))
        self.assertTrue(selfcheck.command_line(molva, None, graphical=True))
        self.assertFalse(selfcheck.command_line(Observation(False, 139, None, self.MOLVA, 0), None, graphical=True))

    CAIRE = ("Content aware image resize library.\n    Version: \n\n  -angle float\n    \tFace rotation angle\n"
             "  -blur int\n    \tBlur radius (default 4)\n  -width int\n    \tDesired image width\n\n"
             "Please provide a width, height or percentage for image rescaling!\n")

    def test_graphical_program_with_no_menu_entry_that_lists_its_options(self):
        # caire's snap, an image resizer that can show its work in a window: no menu entry, a display in
        # its sandbox, and it printed its options (Go's flag format, no usage line) and ended with 1
        caire = Observation(False, 1, None, self.CAIRE, 0)
        self.assertTrue(selfcheck.command_line(caire, None, graphical=True))
        self.assertEqual(self.convert("x11", [caire]), ([None], True))
        self.assertFalse(self.convert("Terminal=false\n", [caire, caire, caire])[1])    # a menu entry: an app
        self.assertFalse(selfcheck.command_line(Observation(False, 139, None, self.CAIRE, 0), None, graphical=True))
        self.assertFalse(selfcheck.command_line(Observation(False, 1, None, "  -v\n  -h\n", 0), None, graphical=True))

    def test_options_without_a_usage_line(self):
        # zsync2 prints its command line and a heading of options over them, no "usage:", and exits
        # with status 2; its menu entry says Terminal=true
        zsync2 = Observation(False, 2, None, self.ZSYNC2, 0)
        self.assertTrue(selfcheck.command_line(zsync2, None))
        self.assertEqual(self.convert("Terminal=true\n", [zsync2]), ([None], True))
        self.assertFalse(selfcheck.command_line(Observation(False, 1, None, "Saving options:\nnone\n", 0), None))

    def test_programs_that_cant_open_a_window(self):
        # faynoSync, a server from a tarball: no menu entry, nothing graphical linked, and it stopped at
        # once at its settings; weiback-rs's db-upgrade-tool ended with status 0 without a word
        server = Observation(False, 1, None, 'level=fatal msg="JWT_SECRET is empty or shorter than 32 bytes"\n', 0)
        quiet = Observation(False, 0, None, "", 1)
        for obs in (server, quiet):
            self.assertTrue(selfcheck.command_line(obs, None, windowless=True))
            self.assertFalse(selfcheck.command_line(obs, None))
        # however long it took: Recoll's recollindex stopped at once at its configuration, but the sandbox
        # took its time to start on a busy PC
        recoll = Observation(False, 1, None, "Configuration problem: Configuration could not be built:\n", 12)
        self.assertTrue(selfcheck.command_line(recoll, None, windowless=True))
        self.assertFalse(selfcheck.command_line(recoll, None))
        # not when it crashed or asked for a display it wasn't given
        self.assertFalse(selfcheck.command_line(Observation(False, 139, None, "", 0), None, windowless=True))
        self.assertFalse(selfcheck.command_line(
            Observation(False, 1, None, "X11: The DISPLAY environment variable is missing\n", 0), None, windowless=True))
        self.assertFalse(selfcheck.command_line(
            Observation(False, 1, None, "Gtk-WARNING **: cannot open\n", 0), None, windowless=True))
        self.assertEqual(self.convert(None, [server, Observation(False, 1, None, "", 0)]), ([None, ["--help"]], True))
        # a menu entry for a graphical app, or a display in its sandbox, and it isn't one
        self.assertFalse(self.convert("Terminal=false\n", [server, server])[1])
        self.assertFalse(self.convert("x11", [server, server])[1])
        # lingma-proxy, a local proxy, ran on, serving, with no window it could open
        proxy = Observation(True, None, [], "lingma-proxy listening on http://127.0.0.1:8095\nmode: agent\n")
        self.assertEqual(selfcheck.command_line(proxy, None, windowless=True), selfcheck.SERVER)
        self.assertFalse(selfcheck.command_line(proxy, None))
        self.assertFalse(selfcheck.command_line(Observation(True, None, [], "Failed to open display\n"), None,
                                                windowless=True))
        self.assertEqual(self.convert(None, [proxy]), ([None], True))
        self.assertFalse(self.convert("x11", [proxy, proxy, proxy])[1])

    def test_programs_whose_menu_entries_run_them_in_a_terminal(self):
        # Amfora's snap, a Gemini browser drawn in the terminal: its only menu entry says Terminal=true and
        # nothing in it opens a window. It ran on waiting for a terminal in the cloud, and on the test PC
        # stopped at its text interface's start with Go's "fatal error" and status 2
        waiting = Observation(True, None, [], "")
        panic = Observation(False, 2, None, "fatal error: sync: Unlock of unlocked RWMutex\n\ngoroutine 1 [running]:\n", 0)
        for obs in (waiting, panic):
            self.assertEqual(selfcheck.command_line(obs, None, terminal_entry=True, windowless=True),
                             selfcheck.TERMINAL_ONLY)
            self.assertEqual(self.convert("Terminal=true\n", [obs, obs])[1], True)
            # a menu entry for a graphical app, or a display in its sandbox, and it isn't one
            self.assertFalse(self.convert("Terminal=false\n", [obs, obs, obs])[1])
            self.assertFalse(selfcheck.command_line(obs, None, terminal_entry=True))
        self.assertFalse(selfcheck.command_line(Observation(False, 139, None, "", 0), None,
                                                terminal_entry=True, windowless=True))
        self.assertFalse(selfcheck.command_line(Observation(True, None, [], "cannot open display :99\n"), None,
                                                terminal_entry=True, windowless=True))

    def test_terminal_program_that_crashes_without_a_terminal_runs_in_one(self):
        # LE, an ncurses editor whose only menu entry says Terminal=true, ended at "le: Caught signal 11"
        # with no terminal; in one it draws its screen and waits for keys
        crashed = Observation(False, 139, None, "\x1b[?1l\x1b>le: Caught signal 11\n", 0)
        drawn = Observation(True, None, [], "\x1b[?1049h\x1b[1;24r\x1b[HLoading history...")
        self.assertFalse(selfcheck.command_line(crashed, None, terminal_entry=True, windowless=True))
        self.assertEqual(selfcheck.in_terminal(drawn), selfcheck.IN_TERMINAL)
        self.assertEqual(selfcheck.in_terminal(Observation(False, 0, None, "", 0)), selfcheck.IN_TERMINAL)
        # a crash in the terminal too, or a program that wants a display, isn't one that works
        self.assertFalse(selfcheck.in_terminal(crashed))
        self.assertFalse(selfcheck.in_terminal(Observation(False, 1, None, "Error opening terminal\n", 0)))
        self.assertFalse(selfcheck.in_terminal(Observation(True, None, [], "cannot open display :99\n")))
        with mock.patch.object(selfcheck, "can_give_terminal", return_value=True):
            # (asked with --help first, it crashed the same way)
            asked, found = self.convert("Terminal=true\n", [crashed, crashed, drawn])
            self.assertTrue(found)
            self.assertEqual(asked, [None, ["--help"], ["(terminal)"]])
            # a crash in the terminal as well goes on to the loader's logging
            asked, found = self.convert("Terminal=true\n", [crashed, crashed, crashed, crashed])
            self.assertFalse(found)
            self.assertEqual(asked, [None, ["--help"], ["(terminal)"], None])
            # a menu entry for a graphical app isn't started in a terminal
            asked, found = self.convert("Terminal=false\n", [crashed, crashed, crashed])
            self.assertFalse(found)
            # musikcube's snap carries libraries that link libX11, so it may open a display: a
            # terminal program that crashed is started in a terminal all the same
            asked, found = self.convert("Terminal=true\n", [crashed, crashed, drawn], x11=True)
            self.assertTrue(found)
            self.assertEqual(asked, [None, ["--help"], ["(terminal)"]])
        with mock.patch.object(selfcheck, "can_give_terminal", return_value=False):
            self.assertFalse(self.convert("Terminal=true\n", [crashed, crashed, drawn])[1])

    def test_observe_in_a_terminal(self):
        # the app starts under script, in a pseudo-terminal of a size and kind it knows
        ran = []

        def run(cmd, **k):
            ran.append(cmd)
            return SimpleNamespace(stdout="DEBPAK-RUNNING\n", returncode=0)
        with mock.patch.object(selfcheck.subprocess, "run", side_effect=run):
            selfcheck.observe("com.example.App", 5, terminal=True)
        cmd = ran[0]
        i = cmd.index("script")
        self.assertEqual(cmd[i:i + 4], ["script", "-q", "-e", "-c"])
        self.assertTrue(cmd[i + 4].startswith("stty rows 24 cols 80"))
        self.assertIn("--env=TERM=xterm-256color", cmd[i + 4])
        self.assertIn("com.example.App", cmd[i + 4])
        self.assertEqual(cmd[-1], "/dev/null")
        ran.clear()
        with mock.patch.object(selfcheck.subprocess, "run", side_effect=run):
            selfcheck.observe("com.example.App", 5)
        self.assertNotIn("script", ran[0])
        self.assertEqual(ran[0][-1], "com.example.App")

    def test_terminal_program_that_prints_its_help(self):
        # Tizonia's snap: its menu entry says Terminal=true; it printed its help topics with status 1,
        # and with --help the same with status 0, but no "usage:" line
        topics = 'tizonia 0.22.0\n\n Help topics:\n\n  global        Global options.\n\nUse "tizonia --help topic".\n'
        bare, helped = Observation(False, 1, None, topics, 0), Observation(False, 0, None, topics, 0)
        self.assertTrue(selfcheck.command_line(bare, helped, terminal_entry=True))
        self.assertFalse(selfcheck.command_line(bare, helped))
        self.assertFalse(selfcheck.command_line(bare, Observation(False, 1, None, topics, 0), terminal_entry=True))
        self.assertFalse(selfcheck.command_line(Observation(False, 139, None, "", 0), helped, terminal_entry=True))
        self.assertEqual(self.convert("Terminal=true\n", [bare, helped]), ([None, ["--help"]], True))

    def test_interactive_prompt_with_a_graphical_menu_entry(self):
        # Cryptnox's snap: an interactive prompt read its first command with input() and stopped at
        # "EOFError: EOF when reading a line"; its menu entry says Terminal=false
        out = ("Type help for list of commands.\n\ncryptnox > Traceback (most recent call last):\n"
               '  File "main.py", line 104, in main\n    input("Press enter to exit application")\n'
               "EOFError: EOF when reading a line\n")
        cryptnox = Observation(False, 1, None, out, 1)
        self.assertEqual(selfcheck.terminal_need(out), "EOFError: EOF when reading a line")
        self.assertEqual(self.convert("Terminal=false\n", [cryptnox]), ([None], True))
        # with a window up it's an app
        self.assertFalse(selfcheck.command_line(Observation(True, None, ["Cryptnox"], out), None))

    def test_windows_console_programs(self):
        # fio printed its options and exited with 1, TrId2Console said what it missed and exited with 0,
        # Instigator printed clap's "Usage:" and exited with 2; none in a window the check could read
        fio = "fio-3.43\nZ:\\app\\opt\\fio\\fio.exe [options] [job options] <job file(s)>\n  --debug=options\n"
        trid = "file is required\nRun with --help for more information.\n"
        for obs in (Observation(False, 1, None, fio, 1), Observation(False, 0, None, trid, 1),
                    Observation(False, 2, None, "Usage: instigator.exe <COMMAND>\n", 2)):
            self.assertTrue(selfcheck.command_line(obs, None, console=True))
        # quiet, but it says how to use it with --help
        self.assertTrue(selfcheck.command_line(Observation(False, 1, None, "", 1), Observation(False, 0, None, fio, 1),
                                               console=True))
        # not one that broke: GAM's frozen Python, a DLL Wine lacks, a crash, Wine's lines alone, or a slow end
        gam = ('Traceback (most recent call last):\n  File "calendar.py", line 110, in __getitem__\n'
               "ValueError: Invalid format string\n[PYI-132:ERROR] Failed to execute script '__main__'\n")
        dll = "0024:err:module:import_dll Library icu.dll (which is needed by L\"Z:\\app\\x.exe\") not found\n"
        for obs in (Observation(False, 1, None, gam, 1), Observation(False, 53, None, "", 1),
                    Observation(False, 1, None, dll, 1), Observation(False, 9, None,
                    "0024:err:seh:NtRaiseException Unhandled exception code c0000409\n", 1),
                    Observation(False, 1, None, "Setting up Wine (first run only)...\n", 1),
                    Observation(False, 1, None, trid, 40), Observation(True, None, [], trid)):
            helped = None if "Setting up Wine" in obs.output else Observation(False, 0, None, fio, 1)
            self.assertFalse(selfcheck.command_line(obs, helped, console=True), obs)
        # the Linux rules don't count a console program's bare words
        self.assertFalse(selfcheck.command_line(Observation(False, 0, None, trid, 1), None))

    def test_convert_reads_a_windows_console_program_outside_its_console_window(self):
        with tempfile.TemporaryDirectory() as t:
            out = Path(t)
            (out / "com.example.App.json").write_text(json.dumps(
                {"id": "com.example.App", "modules": [], "base": "org.winehq.Wine",
                 "x-debpak": {"kind": "wine", "console": True}}))
            args = SimpleNamespace(verify=True, no_build=False, output=str(out), add_library=None)
            seen, runs = [], iter([Observation(False, 1, None, "", 9), Observation(False, 0, None, "file is required\n", 1)])

            def observe(app_id, seconds, env=None, args=None, wine=False):
                seen.append((env, args))
                return next(runs)
            with mock.patch.object(cli, "_convert_once", return_value=0), \
                    mock.patch.object(selfcheck, "available", return_value=True), \
                    mock.patch.object(selfcheck, "_in_app", return_value=0), \
                    mock.patch.object(selfcheck, "observe", side_effect=observe), \
                    contextlib.redirect_stdout(io.StringIO()) as text:
                self.assertEqual(cli.cmd_convert(args), 0)
            self.assertIn(f"Check: {selfcheck.COMMAND_LINE}: Windows marks it as a console program", text.getvalue())
            self.assertEqual(seen, [(None, None), (selfcheck.CONSOLE_ENV, None)])

    def test_terminal_programs(self):
        # superfile, a text interface with no menu entry, couldn't open the terminal it draws in
        tty = "Alas, there's been an error: bubbletea: error opening TTY: bubbletea: could not open TTY: open " \
              "/dev/tty: no such device or address\n"
        self.assertTrue(selfcheck.command_line(Observation(False, 1, None, tty, 12), None))
        self.assertTrue(selfcheck.command_line(Observation(True, None, [], tty), None))
        self.assertFalse(selfcheck.command_line(Observation(True, None, ["superfile"], tty), None))
        self.assertEqual(self.convert(None, [Observation(False, 1, None, tty, 0)]), ([None], True))
        # MeshTalk, an OpenTUI interface from a tarball, asked a terminal it didn't have about itself and
        # switched it to the alternate screen, and waited; Bun's runtime can open windows (x11)
        tui = Observation(True, None, [], "\x1b[?2031h\x1b]10;?\x07\x1b[6n\x1b[s\x1b[?1049h\x1b[?1000h")
        self.assertIn("full-screen text interface", selfcheck.command_line(tui, None))
        self.assertEqual(self.convert("x11", [tui]), ([None], True))
        self.assertFalse(selfcheck.command_line(Observation(True, None, [], "\x1b[31mred\x1b[0m"), None))
        # Curv: its only menu entry says Terminal=true, and its prompt ended at once at the end of its
        # input; that it can open a window of its own (--socket=x11) doesn't make it a graphical app
        curv = Observation(False, 0, None, "", 1)
        self.assertTrue(selfcheck.command_line(curv, None, terminal_entry=True))
        self.assertFalse(selfcheck.command_line(curv, None))
        self.assertFalse(selfcheck.command_line(Observation(False, 139, None, "", 1), None, terminal_entry=True))
        self.assertEqual(self.convert("Terminal=true\n", [curv, Observation(False, 0, None, "", 1)]),
                         ([None, ["--help"]], True))
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent / "compat"))
        import compat
        self.assertEqual(compat.judge(False, 1, [], tty, cli=False)[0], "cli")
        self.assertEqual(compat.judge(False, 1, ["superfile"], tty, cli=False)[0], "crashed")


FAKE_XDOTOOL = """#!/bin/sh
# Ren'Py's launcher: a search by name misses it (its WM_NAME has the type UTF-8), one by class finds it
case "$1 $3" in
    "search --name") echo 1 ;;
    "search --classname") printf '1\\n2\\n' ;;
    "getwindowname ") [ "$2" = 2 ] && echo "Ren'Py Launcher" ;;
esac
"""


class TestObserver(unittest.TestCase):
    def test_waits_while_the_launcher_installs_runtimes(self):
        # DYMO ID's first start installs dotnet48, and the check's minute and a half cut it short: while
        # the launcher's marker is there the app gets its time again from when it goes, and the
        # installer's own windows don't end the wait
        import subprocess
        import time
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            (t / "xdotool").write_text('#!/bin/sh\n[ "$1" = search ] && echo 42\n'
                                       '[ "$1" = getwindowname ] && echo Setup\nexit 0\n')
            (t / "xdotool").chmod(0o755)
            (t / "observe.sh").write_text(selfcheck.OBSERVER)
            busy = t / ".debpak-installing"
            app = f"touch {busy}; sleep 6; rm {busy}; exit 3"
            env = {"PATH": f"{t}:/usr/bin:/bin", "DEBPAK_CHECK_SETTLE": "2", "DEBPAK_CHECK_BUSY": str(busy)}
            began = time.monotonic()
            marks = subprocess.run(["sh", str(t / "observe.sh"), "3", str(t / "out"), "", "sh", "-c", app],
                                   env=env, capture_output=True, text=True, timeout=60).stdout
            self.assertGreaterEqual(time.monotonic() - began, 6)
            self.assertIn("DEBPAK-EXIT 3", marks)
            # with no marker the same app is judged at the end of its seconds, its window up
            env.pop("DEBPAK_CHECK_BUSY")
            marks = subprocess.run(["sh", str(t / "observe.sh"), "3", str(t / "out"), "", "sh", "-c",
                                    "sleep 6; exit 3"], env=env, capture_output=True, text=True, timeout=60).stdout
            self.assertIn("DEBPAK-RUNNING", marks)
            # and a marker left behind doesn't keep it waiting past the cap
            busy.touch()
            env.update(DEBPAK_CHECK_BUSY=str(busy), DEBPAK_CHECK_INSTALL="2")
            began = time.monotonic()
            marks = subprocess.run(["sh", str(t / "observe.sh"), "2", str(t / "out"), "", "sleep", "30"],
                                   env=env, capture_output=True, text=True, timeout=60).stdout
            self.assertLess(time.monotonic() - began, 15)
            self.assertIn("DEBPAK-RUNNING", marks)

    def test_window_found_by_class(self):
        import os
        import subprocess
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            (t / "xdotool").write_text(FAKE_XDOTOOL)
            (t / "xdotool").chmod(0o755)
            (t / "observe.sh").write_text(selfcheck.OBSERVER)
            env = {**os.environ, "PATH": f"{t}:{os.environ['PATH']}"}
            marks = subprocess.run(["sh", str(t / "observe.sh"), "1", str(t / "out"), "", "sleep", "5"],
                                   env=env,
                                   capture_output=True, text=True, timeout=30).stdout
        self.assertIn("DEBPAK-RUNNING", marks)
        self.assertEqual(marks.count("DEBPAK-WINDOW"), 2)
        self.assertIn("DEBPAK-WINDOW Ren'Py Launcher", marks)

    def test_page_served_as_the_window(self):
        # 121GW Companion's window is a page it serves, "121GW Companion: http://127.0.0.1:8221/", which it
        # asks the desktop to open in the web browser; the check asks for that page itself
        import os
        import shutil
        import subprocess
        import sys
        if not shutil.which("curl"):
            self.skipTest("no curl")
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            (t / "web").mkdir()
            (t / "web/index.html").write_text("<html><body>121GW</body></html>")
            (t / "observe.sh").write_text(selfcheck.OBSERVER)
            env = {k: v for k, v in os.environ.items() if k != "DISPLAY"}
            env["PATH"] = f"{t}:/usr/bin:/bin"          # no xdotool
            import socket
            with socket.socket() as so:
                so.bind(("127.0.0.1", 0))
                port = so.getsockname()[1]
            app = (f"echo 'Companion: http://127.0.0.1:{port}/'; "
                   f"exec {sys.executable} -I -m http.server {port} --bind 127.0.0.1 -d {t / 'web'}")
            marks = subprocess.run(["sh", str(t / "observe.sh"), "4", str(t / "out"), "", "sh", "-c", app],
                                   env=env, capture_output=True, text=True, timeout=60).stdout
            self.assertEqual(selfcheck.served_page(marks), f"http://127.0.0.1:{port}/")
            # a URL nothing answers at isn't a window
            marks = subprocess.run(["sh", str(t / "observe.sh"), "2", str(t / "out"), "", "sh", "-c",
                                    f"echo 'http://localhost:{port}/'; sleep 6"],
                                   env=env, capture_output=True, text=True, timeout=60).stdout
            self.assertIsNone(selfcheck.served_page(marks))

    def test_served_page_counts_as_a_window(self):
        self.assertIsNone(selfcheck.served_page("DEBPAK-SERVED http://127.0.0.1:8221/ 404 text/html\n"))
        self.assertIsNone(selfcheck.served_page("DEBPAK-SERVED http://127.0.0.1:8221/ 200 application/json\n"))
        self.assertIsNone(selfcheck.served_page("DEBPAK-SERVED http://127.0.0.1:8221/ 000 \n"))
        page = selfcheck.served_page("DEBPAK-SERVED http://127.0.0.1:8221/ 200 text/html; charset=utf-8\n")
        self.assertEqual(page, "http://127.0.0.1:8221/")
        obs = Observation(True, None, [], "121GW Companion: http://127.0.0.1:8221/\n", None, page)
        self.assertTrue(obs.ok)
        self.assertIn("web page at http://127.0.0.1:8221/", obs.describe())
        self.assertFalse(Observation(True, None, [], "", None, None).ok)
        self.assertFalse(Observation(True, None, ["Error"], "", None, page).ok)
        self.assertFalse(Observation(False, 0, [], "", 1, page).ok)


if __name__ == "__main__":
    unittest.main()
