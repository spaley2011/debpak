"""The compatibility suite's catalog and runner (tests/compat), without the network or Flatpak."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent / "compat"))

import compat  # noqa: E402
from debpak.cli import APP_ID_RE  # noqa: E402
from debpak.recipes import check_problems  # noqa: E402

CATALOG = json.loads((Path(__file__).resolve().parent / "compat" / "apps.json").read_text())["apps"]


class CatalogTests(unittest.TestCase):
    def test_entries_are_complete(self):
        self.assertEqual(len(CATALOG), 200)
        keys = [a["key"] for a in CATALOG]
        self.assertEqual(len(keys), len(set(keys)))
        for a in CATALOG:
            with self.subTest(a["key"]):
                self.assertTrue({"key", "name", "route", "why", "source"} <= set(a))
                self.assertIn(a["route"], {"wine", "electron", "deb", "rpm", "appimage", "tarball", "snap"})
                self.assertIn(a.get("expect", "runs"), {"runs", "refused"})
                self.assertRegex(compat.app_id(a["key"]), APP_ID_RE)
                src = a["source"]
                if src["type"] == "url":
                    self.assertTrue(src["url"].startswith("https://"))
                elif src["type"] == "snap":
                    self.assertTrue(src["name"])
                else:
                    self.assertEqual(check_problems(src), [])

    def test_app_ids(self):
        self.assertEqual(compat.app_id("1password-deb"), "org.debpak.compat.x1password_deb")
        self.assertEqual(compat.app_id("notion"), "org.debpak.compat.notion")


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.work = Path(self._t.name)
        for d in ("logs", "shots", "downloads", "out"):
            (self.work / d).mkdir()
        p = mock.patch.object(compat, "WORK", self.work)
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(self._t.cleanup)

    def log(self, text: str) -> Path:
        f = self.work / "logs" / "x.log"
        f.write_text(text)
        return f

    def test_classify_convert(self):
        c = compat.classify_convert
        self.assertEqual(c(0, self.log(""), "runs"), ("built", ""))
        self.assertEqual(c(0, self.log(""), "refused")[0], "converted-unexpectedly")
        self.assertEqual(c(4, self.log("ZAP is already on Flathub as org.zaproxy.ZAP; the official"), "runs"),
                         ("on-flathub", "org.zaproxy.ZAP"))
        refused = self.log("== Verdict ==\n  NOT CONVERTIBLE as-is:\n"
                           "    x [blocker] postinst: installs/starts a system service\n")
        self.assertEqual(c(2, refused, "refused"), ("refused-expected", "postinst: installs/starts a system service"))
        self.assertEqual(c(2, refused, "runs")[0], "refused")
        windows = self.log("== Verdict ==\n  NOT CONVERTIBLE as-is:\n    x Tool.exe can't be read as a Windows program\n"
                           "\nNot writing a manifest. Fix the issues above\n")
        self.assertEqual(c(2, windows, "runs"), ("refused", "Tool.exe can't be read as a Windows program"))
        built = self.log("Building and installing (--no-build ...)\nError: ERROR: appstreamcli compose failed\n")
        self.assertEqual(c(1, built, "runs"), ("build-failed", "ERROR: appstreamcli compose failed"))
        self.assertEqual(c(1, self.log("debpak: error: a.exe: 7z failed"), "runs"),
                         ("convert-error", "a.exe: 7z failed"))

    def test_one_app_start_to_finish(self):
        app = {"key": "acme", "name": "Acme", "route": "wine", "why": "Windows only",
               "source": {"type": "url", "url": "https://acme.example/latest"}, "args": ["--writable"]}
        f = self.work / "downloads" / "acme" / "Acme.zip"
        calls = []

        def fake_debpak(*argv, log_to, timeout, cwd=None):
            calls.append(argv)
            return 0

        with mock.patch.object(compat, "lookup", return_value=("https://acme.example/Acme.zip", "latest")), \
                mock.patch.object(compat, "download", side_effect=lambda *a: (f.parent.mkdir(parents=True),
                                                                              f.write_bytes(b"z"), f)[2]), \
                mock.patch.object(compat, "debpak", side_effect=fake_debpak), \
                mock.patch.object(compat, "run_app", return_value=("works", "windows: Acme")) as run, \
                mock.patch("subprocess.run", return_value=mock.Mock(returncode=1)):
            res = compat.test_one(app)
        self.assertEqual((res["status"], res["file"], res["version"]), ("works", "Acme.zip", "latest"))
        self.assertEqual(calls[0][:4], ("convert", str(f), "--app-id", "org.debpak.compat.acme"))
        self.assertIn("--writable", calls[0])
        self.assertEqual(run.call_args.args[1], 90)                 # Wine apps get 90s to start
        self.assertFalse(run.call_args.kwargs["tray"])
        self.assertIsNone(run.call_args.kwargs["show"])
        self.assertEqual(calls[-1][:2], ("uninstall", "org.debpak.compat.acme"))

    def test_judging_what_the_app_showed(self):
        j = compat.judge
        self.assertEqual(j(True, None, ["Notepad++ - new 1"], "", False), ("works", "windows: Notepad++ - new 1"))
        self.assertEqual(j(True, None, ["Program Error"], "", False)[0], "error-dialog")
        self.assertEqual(j(True, None, ["ShareX"], "err:ole:x\nUnhandled exception: page fault on read access\n",
                           False), ("error-dialog", "Unhandled exception: page fault on read access"))
        self.assertEqual(j(True, None, [".NET Desktop Runtime"], "", False)[0], "error-dialog")
        self.assertEqual(j(True, None, [], "", False), ("no-window", "still running, but no visible window"))
        self.assertEqual(j(True, None, [], "", True)[0], "works")                 # command-line tools
        self.assertEqual(j(True, None, None, "", False)[0], "works")              # no tool to look with
        self.assertEqual(j(False, 0, None, "Usage: kubectl\n", True), ("exited", "exited cleanly"))
        self.assertEqual(j(False, 139, None, "Segmentation fault (core dumped)\n", False)[0], "crashed")
        self.assertEqual(j(True, None, [], "", False, tray=True)[0], "works")     # Ditto: a tray icon only
        # Wine's everyday noise isn't fatal
        self.assertEqual(j(True, None, ["WinMerge"], "fixme:ole:x\nerr:winediag:y\n", False)[0], "works")

    def test_opening_a_tray_apps_window(self):
        # Wine's stand-in tray (160x20) and explorer's 1x1 helper window
        geometry = {"7": "WINDOW=7\nX=3\nY=22\nWIDTH=160\nHEIGHT=20\n", "8": "WINDOW=8\nX=0\nY=0\nWIDTH=1\nHEIGHT=1\n"}
        sent = []

        def fake_run(cmd, **kw):
            if cmd[1] == "search":
                return mock.Mock(stdout="8\n7\n")
            if cmd[1] == "getwindowgeometry":
                return mock.Mock(stdout=geometry[cmd[-1]])
            sent.append(cmd[1:])
            return mock.Mock(stdout="")

        with mock.patch("subprocess.run", side_effect=fake_run), mock.patch("shutil.which", return_value="/x"), \
                mock.patch.object(compat, "SHOW_SETTLE_SECONDS", 0):
            self.assertEqual(compat.wine_tray_icon(5), (13, 32))
            self.assertEqual(compat.show_window(5, ["tray", "key:ctrl+grave"]), "")
            self.assertEqual(sent, [["mousemove", "13", "32", "click", "1"], ["mousemove", "13", "32", "key", "ctrl+grave"]])
            self.assertEqual(compat.show_window(5, ["wave"]), "unknown show step 'wave'")
            geometry["7"] = "WINDOW=7\nX=0\nY=0\nWIDTH=1\nHEIGHT=1\n"
            self.assertEqual(compat.show_window(5, ["tray"]), "no tray icon to click")
        with mock.patch("shutil.which", return_value=None):
            self.assertEqual(compat.show_window(5, ["tray"]), "no xdotool to open the app's window with")
        # Ditto opens its clip window from the tray; once it's asked to, the window must show up
        ditto = next(a for a in CATALOG if a["key"] == "ditto")
        self.assertEqual(ditto["show"], ["tray"])
        for a in CATALOG:
            for step in a.get("show", []):
                self.assertTrue(step == "tray" or step.startswith("key:"), a["key"])

    def test_lookup_failure_is_the_catalogs(self):
        app = {"key": "gone", "name": "Gone", "route": "deb", "why": "x",
               "source": {"type": "url", "url": "https://gone.example/"}}
        with mock.patch.object(compat, "lookup", side_effect=OSError("HTTP Error 404")):
            res = compat.test_one(app)
        self.assertEqual((res["status"], res["note"]), ("lookup-failed", "HTTP Error 404"))

    def test_where_the_extras_go(self):
        x = compat.extras_dest
        self.assertEqual(x("me@mac:Downloads/compat-report.txt", "e.tgz"), "me@mac:Downloads/e.tgz")
        self.assertEqual(x("me@mac:Downloads/", "e.tgz"), "me@mac:Downloads/e.tgz")
        self.assertEqual(x("me@mac:Downloads", "e.tgz"), "me@mac:Downloads/e.tgz")
        self.assertEqual(x("me@mac:report.txt", "e.tgz"), "me@mac:e.tgz")
        self.assertEqual(x("me@mac:", "e.tgz"), "me@mac:e.tgz")

    def test_report(self):
        apps = [{"key": k, "name": n, "route": r} for k, n, r in
                (("a", "Alpha", "wine"), ("b", "Beta", "deb"), ("c", "Gamma", "deb"))]
        (self.work / "logs" / "b.log").write_text("line one\nError: it broke\n")
        results = {"a": {"key": "a", "name": "Alpha", "route": "wine", "status": "works", "version": "1.0",
                         "times": {"convert": 60, "run": 90}, "note": "running after 90s"},
                   "b": {"key": "b", "name": "Beta", "route": "deb", "status": "build-failed", "version": "2",
                         "times": {"convert": 30}, "note": "it broke", "url": "https://b.example/b.deb"}}
        text = compat.render(results, apps)
        self.assertIn("result:  1 of 2 passed (1 not run yet)", text)
        self.assertIn("by route:  wine 1/1,  deb 0/1", text)
        self.assertIn("===== Beta (deb): build-failed", text)
        self.assertIn("Error: it broke", text)
        self.assertNotIn("===== Alpha", text)

    def test_resume_skips_finished_apps(self):
        (self.work / "results.json").write_text(json.dumps(
            {"notepadpp": {"key": "notepadpp", "name": "Notepad++", "route": "wine", "status": "works"}}))
        seen = []
        with mock.patch.object(compat, "test_one", side_effect=lambda a, *_: seen.append(a["key"]) or
                               {"key": a["key"], "name": a["name"], "route": a["route"], "status": "works"}), \
                mock.patch.object(compat, "preflight", return_value=[]):
            compat.main(["--only", "notepadpp", "--only", "winmerge"])
        self.assertEqual(seen, ["winmerge"])
        self.assertTrue((self.work / "report.txt").is_file())


    def test_parallel_jobs(self):
        # four at once, each on its own display; one app's crash doesn't stop the others
        keys = ["notepadpp", "winmerge", "sharex", "heidisql", "mpchc", "sumatrapdf"]
        displays, lock = [], __import__("threading").Lock()

        def fake(app, *_):
            n = compat.free_display()
            with lock:
                displays.append(n)
            __import__("time").sleep(0.05)
            compat.release_display(n)
            if app["key"] == "sharex":
                raise RuntimeError("boom")
            return {"key": app["key"], "name": app["name"], "route": app["route"], "status": "works"}
        with mock.patch.object(compat, "test_one", side_effect=fake), \
                mock.patch.object(compat, "preflight", return_value=[]):
            compat.main(["-j", "4", *[a for k in keys for a in ("--only", k)]])
        results = json.loads((self.work / "results.json").read_text())
        self.assertEqual(set(results), set(keys))
        self.assertEqual(results["sharex"]["status"], "error")
        self.assertGreater(len(set(displays)), 1)              # really ran side by side

    def test_long_start_ends_once_the_window_settles(self):
        class Proc:
            def wait(self, timeout=None):
                raise compat.subprocess.TimeoutExpired("app", timeout)
        clock = [0.0]
        shown = iter([[], ["Wine"], ["ScreenToGif - StartUp"]] + [["ScreenToGif - StartUp"]] * 10)

        def wait(self, timeout=None):
            clock[0] += timeout
            raise compat.subprocess.TimeoutExpired("app", timeout)
        with mock.patch.object(Proc, "wait", wait), \
                mock.patch.object(compat.time, "time", lambda: clock[0]), \
                mock.patch.object(compat, "visible_windows", lambda d: next(shown)):
            self.assertIsNone(compat.wait_for_start(Proc(), 90, 1200))
        self.assertLess(clock[0], 100)                         # not the full twenty minutes

    def test_strict_passes(self):
        # a GUI app that quits without a window isn't a pass; only a command-line tool's clean exit is
        self.assertEqual(compat.judge(False, 0, [], "", cli=False)[0], "quit")
        # Mullvad Browser's "Profile Missing" dialog is an error, not a window that works
        self.assertEqual(compat.judge(True, None, ["Profile Missing"], "", cli=False)[0], "error-dialog")
        self.assertEqual(compat.judge(True, None, ["Mullvad Browser"], "", cli=False)[0], "works")
        self.assertEqual(compat.judge(False, 0, None, "", cli=True)[0], "exited")
        self.assertNotIn("quit", compat.PASS)
        # a refusal counts only for the reason it was expected
        log = self.work / "r.log"
        log.write_text("== Verdict ==\n  NOT CONVERTIBLE as-is:\n    x needs core system libraries the runtime "
                       "lacks: libnsl.so.1\n")
        self.assertEqual(compat.classify_convert(2, log, "refused")[0], "refused")
        log.write_text("== Verdict ==\n  NOT CONVERTIBLE as-is:\n    x [blocker] postinst: installs/starts a "
                       "system service; Flatpaks cannot run system services\n")
        self.assertEqual(compat.classify_convert(2, log, "refused")[0], "refused-expected")

if __name__ == "__main__":
    unittest.main()


class MiniWmTests(unittest.TestCase):
    def test_size_limits(self):
        # MEGAsync resizes its fixed-size dialogs to 1x1 and counts on the window manager to refuse
        import miniwm
        self.assertEqual(miniwm.clamp(1, 800, 800), 800)
        self.assertEqual(miniwm.clamp(1000, 200, 900), 900)
        self.assertEqual(miniwm.clamp(300, None, None), 300)
        self.assertEqual(miniwm.clamp(0, 0, 0), 1)
