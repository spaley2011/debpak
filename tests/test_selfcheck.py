"""The check after a build: what an app's failure points to, and converting again with it."""
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

    def test_qt_and_glibc(self):
        self.assertEqual(self.keys(crashed("libQt6Core.so.6: version `Qt_6.10' not found (required by x)")),
                         ["runtime:kde6.10"])
        self.assertEqual(self.keys(crashed("libc.so.6: version `GLIBC_2.43' not found")), ["runtime:fd26.08"])

    def test_java_display_and_bus_name(self):
        self.assertEqual(self.keys(crashed("Error: cannot find java VM.")), ["java"])
        self.assertEqual(self.keys(crashed("SDL Error: No available video device")), ["perm:x11", "perm:ipc"])
        self.assertEqual(self.keys(crashed("Failed to register: GDBus.Error: name com.example.Tool is taken")),
                         ["own:com.example.Tool"])

    def test_relative_path_not_found_starts_in_own_folder(self):
        self.assertEqual(self.keys(crashed("./start.sh: 3: ./mercury/mercury: not found", 127)), ["chdir"])
        self.assertEqual(self.keys(crashed("FATAL: Could not open data/fonts/main.ttf")), ["chdir"])
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

    def test_window_judgement(self):
        self.assertTrue(Observation(True, None, ["Editor"], "").ok)
        self.assertTrue(Observation(True, None, None, "").ok)          # no xdotool: running is all we know
        self.assertFalse(Observation(True, None, [], "").ok)
        self.assertFalse(Observation(True, None, ["Fatal Error"], "").ok)

    def test_failed_loads(self):
        log = ("  12: file=libfoo.so.2 [0];  dynamically loaded by /app/bin/x [0]\n"
               "  12: file=libGL.so.1 [0];  dynamically loaded by /app/bin/x [0]\n"
               "  12: file=libGL.so.1 [0];  generating link map\n"
               "  12: file=libva.so.2 [0];  dynamically loaded by /app/bin/x [0]\n")
        self.assertEqual(selfcheck.failed_loads(log), ["libfoo.so.2"])        # libva is a GPU probe
        # glibc's own libraries are never bundled, and asking for one made IGdm's conversion refuse
        nss = "  12: file=libnss_myhostname.so.2 [0];  dynamically loaded by /app/bin/x [0]\n"
        self.assertEqual(selfcheck.failed_loads(nss), [])
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


if __name__ == "__main__":
    unittest.main()
