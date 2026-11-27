"""The compatibility suite's catalog and runner (tests/compat), without the network or Flatpak."""
import json
import re
import shutil
import sys
import tempfile
import threading
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
                if "seconds" in a:
                    self.assertIsInstance(a["seconds"], int)
                    self.assertGreater(a["seconds"], 0)
                src = a["source"]
                if src["type"] == "url":
                    self.assertTrue(src["url"].startswith("https://"))
                elif src["type"] == "snap":
                    self.assertTrue(src["name"])
                else:
                    self.assertEqual(check_problems(src), [])

    def test_first_start_downloads_get_a_fixed_wait(self):
        # Discord's package is only updater_bootstrap, and the Minecraft .deb only fetches its
        # launcher: the first start downloads hundreds of MB before the real window shows, more
        # than the default 45 s on slow Wi-Fi. Their wait stays at 120 s or less, a fixed wait:
        # a longer one ends once the same windows have been up for SETTLED_SECONDS, and a
        # download's progress window ("Discord Setup") can stay up that long by itself.
        by_key = {a["key"]: a for a in CATALOG}
        for key in ("discord-deb", "discord-tar", "minecraft-deb"):
            with self.subTest(key):
                self.assertIn("seconds", by_key[key])
                self.assertGreater(by_key[key]["seconds"], 45)
                self.assertLessEqual(by_key[key]["seconds"], 120)

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
        theme = self.log("debpak: error: flat-remix-gtk is an app snap with no apps (a base, runtime, theme or "
                         "content snap), nothing to convert")
        self.assertEqual(c(1, theme, "runs")[0], "not-an-app")

    def test_one_app_start_to_finish(self):
        app = {"key": "acme", "name": "Acme", "route": "wine", "why": "Windows only",
               "source": {"type": "url", "url": "https://acme.example/latest"}, "args": ["--writable"]}
        f = self.work / "downloads" / "acme" / "Acme.zip"
        calls = []

        def fake_debpak(*argv, log_to, timeout, cwd=None, tmp=None):
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

    def test_lanes_put_what_fits_in_ram(self):
        ram = self.work / "shm"
        lanes = compat.Lanes(ram, 100 << 20, 1)
        small, big = self.work / "small.deb", self.work / "big.AppImage"
        small.write_bytes(b"x" * (4 << 20))          # needs 36 MB
        big.write_bytes(b"x" * (10 << 20))           # needs 90 MB: more than half the budget
        with mock.patch.object(compat.Lanes, "FLOOR", 1):
            base, held = lanes.acquire("a", small)
            self.assertEqual((base, held), (ram, 36 << 20))
            self.assertEqual(lanes.acquire("b", big), (compat.WORK, 0))
            got = []
            waiter = threading.Thread(target=lambda: got.append(lanes.acquire("c", small)))
            base2, held2 = lanes.acquire("d", small)        # 72 of 100 MB now taken: c waits
            waiter.start()
            waiter.join(0.2)
            self.assertEqual(got, [])
            lanes.release(base, held)
            waiter.join(2)
            self.assertEqual(got, [(ram, 36 << 20)])

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
            # a program with an icon there (PhraseExpress) is running in the tray, not windowless
            self.assertEqual(compat.wine_tray_icon_safe(5), (13, 32))
            self.assertEqual(compat.show_window(5, ["tray", "key:ctrl+grave"]), "")
            self.assertEqual(sent, [["mousemove", "13", "32", "click", "1"], ["mousemove", "13", "32", "key", "ctrl+grave"]])
            self.assertEqual(compat.show_window(5, ["wave"]), "unknown show step 'wave'")
            geometry["7"] = "WINDOW=7\nX=0\nY=0\nWIDTH=1\nHEIGHT=1\n"
            self.assertEqual(compat.show_window(5, ["tray"]), "no tray icon to click")
        with mock.patch("shutil.which", return_value=None):
            self.assertEqual(compat.show_window(5, ["tray"]), "no xdotool to open the app's window with")
            self.assertIsNone(compat.wine_tray_icon_safe(5))
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

    def test_convert_timeout_grows_with_the_download(self):
        with tempfile.TemporaryDirectory() as t, mock.patch.object(compat, "WAIT_FACTOR", 1.0):
            small, big = Path(t) / "small.deb", Path(t) / "clion.tar.gz"
            small.write_bytes(b"x")
            with open(big, "wb") as f:
                f.truncate(1300 << 20)
            self.assertEqual(compat.convert_timeout(small), 3000)
            self.assertEqual(compat.convert_timeout(big), 2 * (1500 + 3000))

    def test_batches(self):
        apps = [{"key": str(i), "route": "wine"} for i in range(400)] + \
               [{"key": f"a{i}", "route": "appimage"} for i in range(393)]
        parts = [compat.batch_of(apps, f"{n}/4") for n in range(1, 5)]
        self.assertTrue(all(197 <= len(p) <= 200 for p in parts))
        self.assertEqual(sorted(a["key"] for p in parts for a in p), sorted(a["key"] for a in apps))
        for p in parts:          # every part gets its share of each route
            self.assertEqual(sum(a["route"] == "wine" for a in p), 100)
        for bad in ("0/4", "5/4", "x"):
            with self.assertRaises(ValueError):
                compat.batch_of(apps, bad)

    def test_landing_page_leads_to_the_file(self):
        # CPU-Z's link is a page that links to the file of the same name on download.cpuid.com
        with tempfile.TemporaryDirectory() as t:
            page = Path(t) / "cpu-z_3.02-en.zip.part"
            page.write_text('<!DOCTYPE html><html><link rel="canonical" href="https://www.cpuid.com/downloads/cpu-z/'
                            'cpu-z_3.02-en.zip"><a href="https://www.cpuid.com/?force_layout=desktop&u=/downloads/'
                            'cpu-z/cpu-z_3.02-en.zip">desktop</a>'
                            '<a href="https://download.cpuid.com/cpu-z/cpu-z_3.02-en.zip">'
                            'download</a> <a href="https://x.example/cpu-z_3.02-en.zip.sig">sig</a></html>')
            self.assertEqual(compat.landing_page_link(page, "cpu-z_3.02-en.zip",
                                                      "https://www.cpuid.com/downloads/cpu-z/cpu-z_3.02-en.zip"),
                             "https://download.cpuid.com/cpu-z/cpu-z_3.02-en.zip")
            self.assertIsNone(compat.landing_page_link(page, "other.zip"))
            page.write_bytes(b"PK\3\4 https://download.cpuid.com/cpu-z/cpu-z_3.02-en.zip")
            self.assertIsNone(compat.landing_page_link(page, "cpu-z_3.02-en.zip"))

    def test_a_late_window_still_counts(self):
        # PutiaCNC's window came after the 45 seconds in a busy batch run
        running = mock.Mock(**{"poll.return_value": None})
        seen = iter([[], [], ["Untitled - PutiaCNC"]])
        with mock.patch.object(compat, "visible_windows", side_effect=lambda d: next(seen)), \
                mock.patch.object(compat.time, "sleep"):
            self.assertEqual(compat.late_window(running, 90, 30), ["Untitled - PutiaCNC"])
        # it stops when the app has exited, and when the time is up
        gone = mock.Mock(**{"poll.return_value": 1})
        with mock.patch.object(compat, "visible_windows", return_value=[]) as look, \
                mock.patch.object(compat.time, "sleep"):
            self.assertEqual(compat.late_window(gone, 90, 30), [])
            self.assertEqual(look.call_count, 1)
            self.assertEqual(compat.late_window(running, 90, 0), [])
        # no window tool: nothing to wait for
        with mock.patch.object(compat, "visible_windows", return_value=None) as look:
            self.assertIsNone(compat.late_window(running, 90, 30))
            self.assertEqual(look.call_count, 1)

    PAGES = Path(__file__).resolve().parent / "compat" / "pages"

    def test_sourceforge_download_page_leads_to_the_file(self):
        # SourceForge's /download page sends the browser on with a meta refresh, and has a "direct
        # link", both to a mirror URL with a query, and links back to the file's own page on sourceforge.net
        with tempfile.TemporaryDirectory() as t:
            page = Path(t) / "bomberclone-0.11.9.exe.part"
            shutil.copy(self.PAGES / "sourceforge-download.html", page)
            url = "https://sourceforge.net/projects/bomberclone/files/bomberclone/bomberclone-0.11.9.exe/download"
            self.assertEqual(compat.landing_page_link(page, "bomberclone-0.11.9.exe", url),
                             "https://downloads.sourceforge.net/project/bomberclone/bomberclone/"
                             "bomberclone-0.11.9.exe?ts=gAAAAABrCHx5&use_mirror=netix&r=")
            # without the meta refresh the direct link is taken, not the page on the page's own host
            page.write_text(re.sub(r"<meta http-equiv=\"refresh\"[^>]*>", "", page.read_text()))
            self.assertTrue(compat.landing_page_link(page, "bomberclone-0.11.9.exe", url).startswith(
                "https://downloads.sourceforge.net/project/bomberclone/bomberclone/bomberclone-0.11.9.exe?ts="))

    def test_a_page_with_no_link_to_the_file_is_a_failed_download(self):
        # BomberClone's winget link now redirects to an article about the game on another site
        article = (self.PAGES / "linux-abos-bomberclone.html").read_bytes()
        sf = (self.PAGES / "sourceforge-download.html").read_bytes()
        served = {"https://www.linux-abos.com/spiele/bomberclone/": article,
                  "https://sourceforge.net/projects/bomberclone/files/bomberclone/bomberclone-0.11.9.exe/download": sf,
                  "https://downloads.sourceforge.net/project/bomberclone/bomberclone/bomberclone-0.11.9.exe"
                  "?ts=gAAAAABrCHx5&use_mirror=netix&r=": b"MZ\x90\x00 an installer"}
        fetched = []

        def download(url, dest, **kw):
            fetched.append(url)
            dest.write_bytes(served[url])
            return dest
        with tempfile.TemporaryDirectory() as t, mock.patch.object(compat.net, "download", side_effect=download), \
                mock.patch.object(compat, "whole", return_value=True):
            d, logf = Path(t) / "dl", Path(t) / "x.log"
            with self.assertRaisesRegex(RuntimeError, "catalog's link is out of date"):
                compat.download({"key": "bc"}, "https://www.linux-abos.com/spiele/bomberclone/", d, logf)
            self.assertEqual([f.name for f in d.iterdir()], [])          # no page is kept as the download
            url = "https://sourceforge.net/projects/bomberclone/files/bomberclone/bomberclone-0.11.9.exe/download"
            f = compat.download({"key": "bc"}, url, d, logf)
            self.assertEqual((f.name, f.read_bytes()[:2]), ("bomberclone-0.11.9.exe", b"MZ"))
            self.assertEqual(len(fetched), 3)
            # a page kept from an earlier run isn't taken for the download
            f.write_bytes(article)
            self.assertEqual(compat.download({"key": "bc"}, url, d, logf).read_bytes()[:2], b"MZ")

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

    def test_window_found_by_class(self):
        # Ren'Py's launcher: xdotool's search by name misses it, its WM_NAME having the type UTF-8
        import os
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            (t / "xdotool").write_text("#!/bin/sh\n"
                                       'case "$1 $3" in\n'
                                       '    "search --name") echo 1 ;;\n'
                                       '    "search --classname") printf "1\\n2\\n" ;;\n'
                                       '    "getwindowname ") [ "$2" = 2 ] && echo "Ren\'Py Launcher" ;;\n'
                                       "esac\n")
            (t / "xdotool").chmod(0o755)
            with mock.patch.dict(os.environ, {"PATH": f"{t}:{os.environ['PATH']}"}):
                self.assertEqual(compat.visible_windows(99), ["Ren'Py Launcher"])

    def test_dialogs_raised_above_their_window(self):
        # Google Earth Pro on a screen with no window manager: its main window (1) sits above
        # its start-up tips (2) and a notice (3), both transient for it
        self.assertEqual(compat.dialogs_to_raise([(3, 1, True), (2, 1, True), (1, None, True)]), [3, 2])
        # already above it, or not mapped, or with no parent on screen: left alone
        self.assertEqual(compat.dialogs_to_raise([(1, None, True), (2, 1, True)]), [])
        self.assertEqual(compat.dialogs_to_raise([(2, 1, False), (1, None, True)]), [])
        self.assertEqual(compat.dialogs_to_raise([(2, 9, True), (1, None, True)]), [])
        # a dialog of a dialog ends above both
        self.assertEqual(compat.dialogs_to_raise([(3, 2, True), (2, 1, True), (1, None, True)]), [3, 2, 3])
        # windows transient for each other don't loop forever
        self.assertLessEqual(len(compat.dialogs_to_raise([(1, 2, True), (2, 1, True)])), 4)

    def test_screen_and_pointer(self):
        # Bulk Rename Utility's first window is three quarters of the screen's height: on 1280x800
        # its file list was 30 pixels tall
        w, h = (int(n) for n in compat.SCREEN.split("x"))
        self.assertGreaterEqual((w, h), (1920, 1080))
        # the pointer leaves the middle of the screen, where it opened tooltips over centred windows
        with mock.patch.object(compat.shutil, "which", return_value="/usr/bin/xdotool"), \
                mock.patch.object(compat.subprocess, "run") as run:
            compat.park_pointer(42)
        self.assertEqual(run.call_args.args[0], ["xdotool", "mousemove", "0", "0"])
        self.assertEqual(run.call_args.kwargs["env"]["DISPLAY"], ":42")
        # no xdotool: nothing to do, and no error
        with mock.patch.object(compat.shutil, "which", return_value=None), \
                mock.patch.object(compat.subprocess, "run") as run:
            compat.park_pointer(42)
        run.assert_not_called()

    def test_strict_passes(self):
        # a GUI app that quits without a window isn't a pass; only a command-line tool's clean exit is
        self.assertEqual(compat.judge(False, 0, [], "", cli=False)[0], "quit")
        # Mullvad Browser's "Profile Missing" dialog is an error, not a window that works
        self.assertEqual(compat.judge(True, None, ["Profile Missing"], "", cli=False)[0], "error-dialog")
        self.assertEqual(compat.judge(True, None, ["Mullvad Browser"], "", cli=False)[0], "works")
        # a consent question about error reports, and a program named for crash reports, aren't errors
        self.assertEqual(compat.judge(True, None, ["TEdit Error Reporting"], "", cli=False)[0], "works")
        self.assertEqual(compat.judge(True, None, ["WinCrashReport"], "", cli=False)[0], "works")
        self.assertEqual(compat.judge(True, None, ["Sorry AdiIRC crashed"], "", cli=False)[0], "error-dialog")
        self.assertEqual(compat.judge(False, 0, None, "", cli=True)[0], "exited")
        self.assertNotIn("quit", compat.PASS)
        # Arkloop's ark printed its usage and exited with 2: once debpak's check found it a command-line
        # program, that's what the run says, not a crash; a crash's own words still count
        ark = "usage: ark <command> [flags]\n"
        self.assertEqual(compat.judge(False, 2, None, ark, cli=False)[0], "crashed")
        self.assertEqual(compat.judge(False, 2, None, ark, cli=False, command_line=True)[0], "cli")
        self.assertEqual(compat.judge(False, 139, None, "Segmentation fault (core dumped)", cli=False,
                                      command_line=True)[0], "crashed")
        self.assertEqual(compat.judge(True, None, [], "", cli=False, command_line=True)[0], "no-window")
        # lingma-proxy, a server with no display in its sandbox, ran on in debpak's check, which said so
        self.assertEqual(compat.judge(True, None, [], "listening on http://127.0.0.1:8095\n", cli=False,
                                      command_line=True, server=True)[0], "cli")
        self.assertEqual(compat.judge(True, None, ["Proxy"], "", cli=False, command_line=True, server=True)[0],
                         "works")
        # MeshTalk drew its text interface for a terminal it didn't have
        tui = "\x1b[?2031h\x1b]10;?\x07\x1b[6n\x1b[s\x1b[?1049h\x1b[?1000h"
        self.assertEqual(compat.judge(True, None, [], tui, cli=False), ("cli", f"{compat.selfcheck.COMMAND_LINE}: "
                         "it needs a terminal (it switched a terminal to a full-screen text interface)"))
        self.assertIn("cli", compat.PASS)
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

    def test_wm_state(self):
        # Wine 10 and later wait for WM_STATE to change before a managed window's next map or
        # unmap, so without it Flow Launcher's hidden search bar stays on screen
        import miniwm
        known = {}
        self.assertEqual(miniwm.wm_state(known, miniwm.MAP_REQUEST, 5), miniwm.NORMAL)
        self.assertEqual(miniwm.wm_state(known, miniwm.UNMAP_NOTIFY, 5), miniwm.WITHDRAWN)
        # XWithdrawWindow's synthetic UnmapNotify follows the real one
        self.assertIsNone(miniwm.wm_state(known, miniwm.UNMAP_NOTIFY, 5, synthetic=True))
        # a window this window manager never mapped (override-redirect) is left alone
        self.assertIsNone(miniwm.wm_state(known, miniwm.UNMAP_NOTIFY, 6))

    def test_wm_state_iconic(self):
        import miniwm
        known = {}
        miniwm.wm_state(known, miniwm.MAP_REQUEST, 5)
        self.assertEqual(miniwm.wm_state(known, miniwm.CLIENT_MESSAGE, 5, wanted=miniwm.ICONIC), miniwm.ICONIC)
        # the window manager's own unmap keeps it iconic
        self.assertIsNone(miniwm.wm_state(known, miniwm.UNMAP_NOTIFY, 5))
        # Wine withdraws an iconic window before mapping it again
        self.assertEqual(miniwm.wm_state(known, miniwm.UNMAP_NOTIFY, 5, synthetic=True), miniwm.WITHDRAWN)
        self.assertEqual(miniwm.wm_state(known, miniwm.MAP_REQUEST, 5), miniwm.NORMAL)
        miniwm.wm_state(known, miniwm.DESTROY_NOTIFY, 5)
        self.assertEqual(known, {})


class PruneTests(unittest.TestCase):
    def test_prune_removes_download_and_build_state(self):
        with tempfile.TemporaryDirectory() as t:
            work = Path(t)
            for d in ("downloads/app/x.deb", "work/app/.flatpak-builder/f", "downloads/other/y.deb"):
                (work / d).parent.mkdir(parents=True, exist_ok=True)
                (work / d).write_text("x")
            with mock.patch.object(compat, "WORK", work):
                compat.prune("app")
            self.assertFalse((work / "downloads/app").exists())
            self.assertFalse((work / "work/app").exists())
            self.assertTrue((work / "downloads/other/y.deb").exists())
            # a failure keeps its download for the rerun, but not its build files
            for d in ("work/other/.flatpak-builder/f", "out/other/build-dir/f", "tmp/other/debpak-x/src/f"):
                (work / d).parent.mkdir(parents=True, exist_ok=True)
                (work / d).write_text("x")
            with mock.patch.object(compat, "WORK", work):
                compat.prune("other", passed=False)
            self.assertTrue((work / "downloads/other/y.deb").exists())
            self.assertFalse((work / "work/other").exists())
            self.assertFalse((work / "out/other").exists())
            self.assertFalse((work / "tmp/other").exists())

