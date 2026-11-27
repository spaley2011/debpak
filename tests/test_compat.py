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
        libs = self.log("== Verdict ==\n  NOT CONVERTIBLE as-is:\n    x a library, not an app: the package holds no "
                        "program, only libraries (iohook.node)\n")
        self.assertEqual(c(2, libs, "runs")[0], "not-an-app")
        tools = self.log("== Verdict ==\n  NOT CONVERTIBLE as-is:\n    x a build environment, not an app: opt/colo/bin "
                         "holds a compiler, a shell and the basic commands (cc, as, bash, cp, make)\n")
        self.assertEqual(c(2, tools, "runs")[0], "not-an-app")
        theme = self.log("debpak: error: flat-remix-gtk is an app snap with no apps (a base, runtime, theme or "
                         "content snap), nothing to convert")
        self.assertEqual(c(1, theme, "runs")[0], "not-an-app")
        sdl = self.log("debpak: error: SDL3Installer.msi installs no program, only libraries (SDL3.dll): it's a "
                       "library or runtime for other programs, with no app to convert")
        self.assertEqual(c(1, sdl, "runs")[0], "not-an-app")

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

    def test_the_sample_takes_the_app_not_its_build_tools(self):
        # Colosseum Launcher's release: the tarball drawn was colo-build-tools-linux-x64-....tar.gz, a
        # Python and compilers; its Linux app is the AppImage. Of two tarballs, the one with the name wins
        import subprocess
        script = Path(__file__).resolve().parent / "compat" / "sampling" / "classify.py"
        rel = {"chasem-dev/colosseum-launcher": {"assets": [
                   "https://x/colo-build-tools-linux-x64-2026-11-05.1.tar.gz", "https://x/Colosseum-Launcher.AppImage"]},
               "a/foo": {"assets": ["https://x/helper-linux-x86_64.tar.gz", "https://x/Foo-1.0-linux-x86_64.tar.gz"]},
               # HexoEditor's 32-bit build was drawn; iohook's release is a Node module, no app at all
               "zhuzhuyule/hexoeditor": {"assets": ["https://x/HexoEditor_1.5.30_linux_x32.tar.gz",
                                                    "https://x/HexoEditor_1.5.30_linux_x64.tar.gz"]},
               "wilix-team/iohook": {"assets": ["https://x/iohook-v0.9.3-electron-v69-linux-x64.tar.gz"]}}
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / "rel.json").write_text(json.dumps(rel))
            (Path(t) / "used.json").write_text(json.dumps({"repos": [], "names": []}))
            subprocess.run([sys.executable, "-I", str(script), "rel.json", "used.json"], cwd=t, check=True,
                           capture_output=True)
            got = json.loads((Path(t) / "linux-assets.json").read_text())
        self.assertEqual(got, {"chasem-dev/colosseum-launcher": {"appimage": "https://x/Colosseum-Launcher.AppImage"},
                               "a/foo": {"tarball": "https://x/Foo-1.0-linux-x86_64.tar.gz"},
                               "zhuzhuyule/hexoeditor": {"tarball": "https://x/HexoEditor_1.5.30_linux_x64.tar.gz"}})

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

    def test_local_page(self):
        import http.server
        import socketserver

        class Page(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                kind = "text/html" if self.path == "/" else "application/json"
                self.send_response(200)
                self.send_header("Content-Type", kind)
                self.end_headers()
                self.wfile.write(b"<html></html>" if kind == "text/html" else b"{}")

            def log_message(self, *a):
                pass
        with socketserver.TCPServer(("127.0.0.1", 0), Page) as httpd:
            port = httpd.server_address[1]
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            try:
                self.assertEqual(compat.local_page(f"121GW Companion: http://127.0.0.1:{port}/\nFailed to call portal"),
                                 f"http://127.0.0.1:{port}/")
                self.assertEqual(compat.local_page(f"on http://0.0.0.0:{port}/ now"), f"http://127.0.0.1:{port}/")
                self.assertIsNone(compat.local_page(f"api at http://localhost:{port}/api"))
            finally:
                httpd.shutdown()
        self.assertIsNone(compat.local_page("see https://example.com/"))
        self.assertIsNone(compat.local_page(f"http://127.0.0.1:{port}/"))       # nothing there now

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
        # LE, an ncurses editor, crashed with no terminal, and debpak's check found it working in one
        self.assertEqual(compat.judge(False, 139, None, "Segmentation fault (core dumped)", cli=False,
                                      command_line=True, in_terminal=True)[0], "cli")
        self.assertEqual(compat.judge(True, None, ["Error"], "", cli=False, command_line=True,
                                      in_terminal=True)[0], "error-dialog")
        # 121GW Companion serves its window as a web page for the browser
        self.assertEqual(compat.judge(True, None, [], "", cli=False, served="http://127.0.0.1:8221/")[0], "works")
        self.assertEqual(compat.judge(True, None, ["Error"], "", cli=False, served="http://127.0.0.1:8221/")[0],
                         "error-dialog")
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


class FetchTests(unittest.TestCase):
    """Lookups and downloads that try again, snaps with no stable release, dead winget links."""

    def setUp(self):
        p = mock.patch.object(compat.time, "sleep")
        self.sleep = p.start()
        self.addCleanup(p.stop)

    def test_what_passes(self):
        import urllib.error
        from debpak.recipes import RecipeError
        for e in (TimeoutError("The read operation timed out"),
                  urllib.error.URLError(TimeoutError("timed out")),
                  urllib.error.URLError(ConnectionResetError(104, "Connection reset by peer")),
                  urllib.error.HTTPError("https://x.example/", 503, "Service Unavailable", {}, None)):
            self.assertTrue(compat.transient(e), e)
        try:
            try:
                raise TimeoutError("The read operation timed out")
            except TimeoutError as e:
                raise RecipeError(f"check failed: {e}") from e
        except RecipeError as wrapped:
            self.assertTrue(compat.transient(wrapped))
        for e in (urllib.error.HTTPError("https://x.example/", 404, "Not Found", {}, None),
                  ValueError("no JSON"), RuntimeError("no asset matches")):
            self.assertFalse(compat.transient(e), e)

    def test_a_lookup_that_timed_out_is_tried_again(self):
        # karasu's, leanstudio's and spark-wallet's lookups in batch 2 failed with "The read operation
        # timed out", links that answered when tried again
        calls = []

        def resolve(url):
            calls.append(url)
            if len(calls) < 3:
                raise TimeoutError("The read operation timed out")
            return url
        app = {"key": "k", "source": {"type": "url", "url": "https://github.com/k/k/releases/download/v1/k.rpm"}}
        with mock.patch.object(compat.recipes, "resolve_redirect", side_effect=resolve):
            self.assertEqual(compat.lookup(app), (app["source"]["url"], "latest"))
        self.assertEqual(len(calls), 3)
        self.assertEqual([c.args[0] for c in self.sleep.call_args_list], list(compat.RETRY_WAITS[:2]))
        # a link that's gone isn't tried again
        import urllib.error
        gone = urllib.error.HTTPError(app["source"]["url"], 404, "Not Found", {}, None)
        with mock.patch.object(compat.recipes, "resolve_redirect", side_effect=gone) as r, \
                self.assertRaises(urllib.error.HTTPError):
            compat.lookup(app)
        self.assertEqual(r.call_count, 1)
        # and one that keeps timing out fails in the end, with its own error
        with mock.patch.object(compat.recipes, "resolve_redirect", side_effect=TimeoutError("timed out")) as r, \
                self.assertRaisesRegex(TimeoutError, "timed out"):
            compat.lookup(app)
        self.assertEqual(r.call_count, len(compat.RETRY_WAITS) + 1)

    STORE = {  # the store's channel maps, as api.snapcraft.io gave them for knotter and libretextus
        "knotter": {"channel-map": [{"channel": {"architecture": "amd64", "track": "latest", "risk": "beta"},
                                     "version": "0.9.7+snap-9debc474"}]},
        "libretextus": {"channel-map": [
            {"channel": {"architecture": a, "track": "latest", "risk": "edge"}, "version": "0.2"}
            for a in ("amd64", "arm64", "armhf", "i386", "ppc64el", "s390x")]},
        "both": {"channel-map": [
            {"channel": {"architecture": "amd64", "track": "2", "risk": "stable"}, "version": "2.0"},
            {"channel": {"architecture": "amd64", "track": "latest", "risk": "edge"}, "version": "1.9-1"},
            {"channel": {"architecture": "amd64", "track": "latest", "risk": "candidate"}, "version": "1.9"},
            {"channel": {"architecture": "amd64", "track": "latest", "risk": "stable"}, "version": "1.8"}]},
        "armonly": {"channel-map": [{"channel": {"architecture": "arm64", "track": "latest", "risk": "stable"},
                                     "version": "1"}]},
    }

    def test_a_snap_with_no_stable_release_comes_from_its_most_stable_channel(self):
        # knotter, classroom-plus and opentubex are only in beta, libretextus only in edge: snap
        # download, which takes stable, said "no snap revision available as specified"
        import io
        import urllib.error

        def info(name):
            if name not in self.STORE:
                raise urllib.error.HTTPError("https://api.snapcraft.io/", 404, "Not Found", {},
                                             io.BytesIO(b'{"error-list": [{"code": "resource-not-found", '
                                                        b'"message": "No snap named \'gone\' found in series \'16\'."}]}'))
            return self.STORE[name]
        with mock.patch.object(compat, "snap_store_info", side_effect=info), \
                mock.patch.object(compat, "snap_arch", return_value="amd64"):
            self.assertEqual(compat.lookup({"source": {"type": "snap", "name": "knotter"}}),
                             ("snap:knotter@beta", "beta 0.9.7+snap-9debc474"))
            self.assertEqual(compat.lookup({"source": {"type": "snap", "name": "libretextus"}})[0],
                             "snap:libretextus@edge")
            # stable wins, and the default track before the others
            self.assertEqual(compat.lookup({"source": {"type": "snap", "name": "both"}}),
                             ("snap:both", "stable 1.8"))
            # a catalog entry can name the channel itself
            self.assertEqual(compat.lookup({"source": {"type": "snap", "name": "both", "channel": "2/stable"}})[0],
                             "snap:both@2/stable")
            with self.assertRaisesRegex(RuntimeError, "no release for amd64 .only for arm64"):
                compat.lookup({"source": {"type": "snap", "name": "armonly"}})
            with self.assertRaisesRegex(RuntimeError, "has no snap named 'gone' .No snap named"):
                compat.lookup({"source": {"type": "snap", "name": "gone"}})
        # when the store can't be asked, snap download's own stable channel is tried
        with mock.patch.object(compat, "snap_store_info", side_effect=OSError("no network")):
            self.assertEqual(compat.lookup({"source": {"type": "snap", "name": "knotter"}}), ("snap:knotter", "stable"))

    def test_snap_download_says_what_went_wrong_and_tries_again_when_it_passes(self):
        runs = []

        def run(cmd, **kw):
            runs.append(cmd)
            dest = Path(next(c for c in cmd if c.startswith("--target-directory=")).split("=", 1)[1])
            if cmd[2] == "knotter" and "--channel=beta" not in cmd:
                return mock.Mock(returncode=1, stdout='Fetching snap "knotter"\n', stderr=(
                    'error: cannot download snap "knotter": no snap revision available as specified\n'))
            if len(runs) == 1:
                return mock.Mock(returncode=1, stdout="", stderr="error: unable to contact snap store\n")
            (dest / "opentubex_271.snap").write_bytes(b"hsqs")
            return mock.Mock(returncode=0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as t, mock.patch.object(compat.subprocess, "run", side_effect=run):
            d, logf = Path(t) / "dl", Path(t) / "x.log"
            f = compat.download({"key": "o"}, "snap:opentubex@beta", d, logf)
            self.assertEqual(f.name, "opentubex_271.snap")
            self.assertEqual(len(runs), 2)                       # the store didn't answer the first time
            self.assertIn("--channel=beta", runs[-1])
            self.assertIn("unable to contact snap store", logf.read_text())
            self.assertEqual(compat.download({"key": "o"}, "snap:opentubex@beta", d, logf), f)   # kept
            self.assertEqual(len(runs), 2)
            runs.clear()
            with self.assertRaisesRegex(RuntimeError, 'snap download knotter failed: error: cannot download '
                                                      'snap "knotter": no snap revision available'):
                compat.download({"key": "k"}, "snap:knotter", Path(t) / "k", logf)
            self.assertEqual(len(runs), 1)                       # trying again wouldn't help

    MANIFEST_NESTED = """# yaml-language-server: $schema=https://aka.ms/winget-manifest.installer.1.6.0.schema.json

PackageIdentifier: CuteCutPro.CuteCutPro
PackageVersion: 2.5.4
Installers:
  - Architecture: x64
    InstallerType: nullsoft
    InstallerUrl: https://github.com/MDIsmatullah/CuteCut-Pro/releases/download/v2.5.4/CuteCut.Pro.Setup.2.5.4.exe
    AppsAndFeaturesEntries:
      - DisplayName: CuteCut Pro
        InstallerUrl: https://not.this.example/
ManifestType: installer
"""
    MANIFEST_FLAT = """PackageIdentifier: SteffenPohle.BomberClone
PackageVersion: 0.11.9
InstallerType: nullsoft
Installers:
- Architecture: x86
  InstallerUrl: https://www.bomberclone.de/stuff/bomberclone-0.11.9.exe
- Architecture: arm64
  InstallerUrl: https://www.bomberclone.de/stuff/bomberclone-arm.exe
ManifestType: installer
"""

    def test_reading_winget_manifests(self):
        nested = compat.winget_installers(self.MANIFEST_NESTED)
        self.assertEqual([(i["Architecture"], i["InstallerType"]) for i in nested], [("x64", "nullsoft")])
        self.assertTrue(compat.winget_pick(nested).endswith("/v2.5.4/CuteCut.Pro.Setup.2.5.4.exe"))
        flat = compat.winget_installers(self.MANIFEST_FLAT)
        self.assertEqual([i["InstallerType"] for i in flat], ["nullsoft", "nullsoft"])     # the manifest's own
        self.assertEqual(compat.winget_pick(flat), "https://www.bomberclone.de/stuff/bomberclone-0.11.9.exe")
        self.assertIsNone(compat.winget_pick([{"Architecture": "x64", "InstallerType": "msstore",
                                               "InstallerUrl": "https://x.example/"}]))

    def winget_fetch(self, served):
        def fetch(url):
            if url not in served:
                import urllib.error
                raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
            body = served[url]
            if isinstance(body, Exception):
                raise body
            return body if isinstance(body, bytes) else body.encode()
        return fetch

    CUTECUT = {"key": "w-cutecutpro-cutecutpro", "why": "winget sample CuteCutPro.CuteCutPro 2.5.4",
               "source": {"type": "url", "url": "https://github.com/MDIsmatullah/CuteCut-Pro/releases/download/"
                                               "v2.5.4/CuteCut.Pro.Setup.2.5.4.exe"}}
    FOLDER = "manifests/c/CuteCutPro/CuteCutPro"

    def test_a_dead_winget_link_is_looked_up_in_the_packages_newer_manifests(self):
        # CuteCut Pro's winget link answered 404: the package's newer manifests (and its own, fixed
        # in place) are read for a link that works; older ones aren't
        raw = compat.WINGET_RAW + self.FOLDER
        new = self.MANIFEST_NESTED.replace("2.5.4", "2.6.0")
        served = {compat.WINGET_API + self.FOLDER: json.dumps(
                      [{"name": v, "type": "dir"} for v in ("2.5.3", "2.5.4", "2.6.0")] + [{"name": "x", "type": "file"}]),
                  f"{raw}/2.6.0/CuteCutPro.CuteCutPro.installer.yaml": new,
                  f"{raw}/2.5.4/CuteCutPro.CuteCutPro.installer.yaml": self.MANIFEST_NESTED.replace(
                      "github.com/MDIsmatullah/CuteCut-Pro/releases/download/v2.5.4", "cutecutpro.example/dl"),
                  f"{raw}/2.5.3/CuteCutPro.CuteCutPro.installer.yaml": self.MANIFEST_NESTED.replace("2.5.4", "2.5.3")}
        with mock.patch.object(compat.recipes, "fetch", side_effect=self.winget_fetch(served)):
            got = list(compat.winget_candidates(self.CUTECUT))
        self.assertEqual(got, [("https://github.com/MDIsmatullah/CuteCut-Pro/releases/download/v2.6.0/"
                                "CuteCut.Pro.Setup.2.6.0.exe", "2.6.0"),
                               ("https://cutecutpro.example/dl/CuteCut.Pro.Setup.2.5.4.exe", "2.5.4")])
        # GitHub won't list the versions: the sampled version's own manifest is still read
        del served[compat.WINGET_API + self.FOLDER]
        with mock.patch.object(compat.recipes, "fetch", side_effect=self.winget_fetch(served)):
            self.assertEqual([v for _, v in compat.winget_candidates(self.CUTECUT)], ["2.5.4"])
        # an app that isn't a winget sample has none
        self.assertEqual(list(compat.winget_candidates({"key": "x", "why": "holdout sample: snap store"})), [])

    def test_the_lookup_and_the_download_take_a_working_winget_link(self):
        import urllib.error
        dead = self.CUTECUT["source"]["url"]
        alt = "https://github.com/MDIsmatullah/CuteCut-Pro/releases/download/v2.6.0/CuteCut.Pro.Setup.2.6.0.exe"

        def resolve(url):
            if url == dead:
                raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
            return url
        with mock.patch.object(compat.recipes, "resolve_redirect", side_effect=resolve), \
                mock.patch.object(compat, "winget_candidates", return_value=iter([(alt, "2.6.0")])):
            self.assertEqual(compat.lookup(self.CUTECUT), (alt, "2.6.0"))
        with mock.patch.object(compat.recipes, "resolve_redirect", side_effect=resolve), \
                mock.patch.object(compat, "winget_candidates", return_value=iter([])), \
                self.assertRaisesRegex(urllib.error.HTTPError, "404"):
            compat.lookup(self.CUTECUT)

        # the lookup's link worked, the download's didn't
        def download(url, dest, **kw):
            if url == dead:
                raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
            dest.write_bytes(b"MZ\x90\x00 an installer")
            return dest
        with tempfile.TemporaryDirectory() as t, mock.patch.object(compat.net, "download", side_effect=download), \
                mock.patch.object(compat, "whole", return_value=True), \
                mock.patch.object(compat, "winget_candidates", return_value=iter([(dead, "2.5.4"), (alt, "2.6.0")])):
            d, logf = Path(t) / "dl", Path(t) / "x.log"
            url, version, f = compat.download_any(self.CUTECUT, dead, "latest", d, logf)
            self.assertEqual((url, version, f.name), (alt, "2.6.0", "CuteCut.Pro.Setup.2.6.0.exe"))
            self.assertIn("took winget's 2.6.0 link", logf.read_text())
        with tempfile.TemporaryDirectory() as t, mock.patch.object(compat.net, "download", side_effect=download), \
                mock.patch.object(compat, "winget_candidates", return_value=iter([])), \
                self.assertRaises(compat.DeadLink):
            compat.download_any(self.CUTECUT, dead, "latest", Path(t) / "dl", Path(t) / "x.log")


class SamplingTests(unittest.TestCase):
    """The draw leaves out what can't be fetched (tests/compat/sampling)."""
    PAGES = Path(__file__).resolve().parent / "compat" / "pages"

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(Path(__file__).resolve().parent / "compat" / "sampling"))
        import snap_gui
        import winget_sample
        cls.snap_gui, cls.winget_sample = snap_gui, winget_sample

    def test_a_snap_is_kept_with_a_release_for_amd64_in_any_channel(self):
        shot = {"media": [{"type": "icon"}, {"type": "screenshot"}]}
        beta = {"snap": shot, "channel-map": [{"channel": {"architecture": "amd64", "risk": "beta"}}]}
        self.assertTrue(self.snap_gui.keep(beta))                 # knotter: only in beta
        self.assertFalse(self.snap_gui.keep({"snap": shot, "channel-map": [
            {"channel": {"architecture": "arm64", "risk": "stable"}}]}))
        self.assertFalse(self.snap_gui.keep({"snap": {"media": []}, "channel-map": beta["channel-map"]}))
        self.assertFalse(self.snap_gui.keep(None))

    def test_a_winget_link_dead_when_drawn_is_passed_over(self):
        import urllib.error
        w = self.winget_sample
        article = (self.PAGES / "linux-abos-bomberclone.html").read_bytes()
        sf = (self.PAGES / "sourceforge-download.html").read_bytes()

        def opener(body, ctype, final="https://x.example/"):
            return lambda u, **kw: (final, {"Content-Type": ctype}, body)
        # BomberClone's link now leads to an article about the game with no link to the file
        self.assertRegex(w.link_dead("https://www.bomberclone.de/stuff/bomberclone-0.11.9.exe",
                                     opener(article, "text/html; charset=UTF-8")), "web page with no link")
        # SourceForge's /download page links to the file, which the compat run follows
        self.assertIsNone(w.link_dead("https://sourceforge.net/projects/bomberclone/files/bomberclone/"
                                      "bomberclone-0.11.9.exe/download", opener(sf, "text/html")))
        self.assertIsNone(w.link_dead("https://x.example/setup.exe", opener(b"MZ\x90\x00", "application/octet-stream")))

        def gone(code):
            def f(u, **kw):
                raise urllib.error.HTTPError(u, code, "x", {}, None)
            return f
        # CuteCut Pro's link answered 404
        self.assertEqual(w.link_dead("https://github.com/a/b/releases/download/v1/b.exe", gone(404)), "HTTP 404")
        # a link that can't be checked is left to the compat run
        self.assertIsNone(w.link_dead("https://x.example/setup.exe", gone(403)))
        self.assertIsNone(w.link_dead("https://x.example/setup.exe",
                                      lambda u, **kw: (_ for _ in ()).throw(TimeoutError("timed out"))))

    def test_a_manifest_read_that_times_out_is_tried_again(self):
        w = self.winget_sample
        tries = []

        class Answer:
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def geturl(self):
                return "https://cdn.example/m.yaml"

            def read(self, n=None):
                return b"PackageName: X"

        def urlopen(req, timeout):
            tries.append(req.full_url)
            if len(tries) < 3:
                raise TimeoutError("The read operation timed out")
            return Answer()
        with mock.patch.object(w.urllib.request, "urlopen", side_effect=urlopen), mock.patch.object(w.time, "sleep"):
            self.assertEqual(w.get("https://cdn.example/m.yaml")[2], b"PackageName: X")
        self.assertEqual(len(tries), 3)


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

    def test_tray_dock_request(self):
        import miniwm
        self.assertEqual(miniwm.docked_icon(miniwm.SYSTEM_TRAY_REQUEST_DOCK, [0, 0, 0x1400003, 0, 0]), 0x1400003)
        # a balloon message (opcode 1) or cancel (2) docks nothing
        self.assertIsNone(miniwm.docked_icon(1, [0, 1, 0x1400003, 0, 0]))
        self.assertIsNone(miniwm.docked_icon(0, [0, 0, 0, 0, 0]))

    def test_docked_icons_are_read_once(self):
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "app.tray"
            self.assertEqual(compat.docked_tray_icons(f), [])        # miniwm couldn't be the tray
            f.write_text("0x1400003\n0x1800003\n")
            self.assertEqual(compat.docked_tray_icons(f), ["0x1400003", "0x1800003"])
            self.assertFalse(f.exists())

    @unittest.skipUnless(shutil.which("Xvfb"), "needs Xvfb")
    def test_gtk_status_icon_docks_with_the_tray(self):
        # KimaiTray, a Tauri app, uses GtkStatusIcon outside GNOME and KDE, and appindicator's fallback
        # and Chromium's windowed icon dock the same way: on a bare Xvfb they found no tray at all
        import ctypes.util
        import os
        import subprocess
        import time
        if not ctypes.util.find_library("gtk-3"):
            self.skipTest("needs GTK 3")
        client = (
            "import ctypes, time\n"
            "g = ctypes.CDLL('libgtk-3.so.0')\n"
            "g.gtk_init_check.argtypes = [ctypes.c_void_p, ctypes.c_void_p]\n"
            "g.gtk_status_icon_new_from_icon_name.restype = ctypes.c_void_p\n"
            "g.gtk_status_icon_new_from_icon_name.argtypes = [ctypes.c_char_p]\n"
            "assert g.gtk_init_check(None, None)\n"
            "icon = g.gtk_status_icon_new_from_icon_name(b'dialog-information')\n"
            "end = time.time() + 3\n"
            "while time.time() < end:\n"
            "    g.gtk_main_iteration_do(0)\n"
            "    time.sleep(0.05)\n")
        display = compat.free_display()
        procs = []
        try:
            with tempfile.TemporaryDirectory() as t:
                tray = Path(t) / "app.tray"
                procs.append(subprocess.Popen(["Xvfb", f":{display}", "-screen", "0", "640x480x24", "-nolisten",
                                               "tcp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
                time.sleep(1.5)
                env = {**os.environ, "DISPLAY": f":{display}"}
                env.pop("WAYLAND_DISPLAY", None)
                procs.append(subprocess.Popen([sys.executable, "-I", str(compat.HERE / "miniwm.py"), "--tray",
                                               str(tray)], env=env))
                time.sleep(1)
                subprocess.run([sys.executable, "-I", "-c", client], env=env, timeout=60, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                icons = compat.docked_tray_icons(tray)
            self.assertEqual(len(icons), 1, icons)
        finally:
            for proc in reversed(procs):
                proc.terminate()
                proc.wait(timeout=10)
            compat.release_display(display)


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

