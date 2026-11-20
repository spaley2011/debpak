import configparser
import contextlib
import io
import json
import shutil
import struct
import subprocess
import tempfile
import unittest
import zlib
from pathlib import Path

from debpak.appbridge import cli
from debpak.appbridge.backends import BACKENDS, to_windows_path
from debpak.appbridge.catalog import BUILTIN, SUITES
from debpak.appbridge.core import NO_BACKEND, NOT_INSTALLED, READY, Bridge
from debpak.appbridge.host import Host
from debpak.appbridge.icons import dib_to_png, extract_png, png_size
from debpak.pe import PeError
from debpak.appbridge.integrate import Integrator, _exec, _exec_quote

from appbridge_fixtures import FakeDesktop, _dib8_masked, _dib32, build_pe_with_icons


def run_cli(desk, *argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = cli.main(list(argv), host=desk.host())
    return code, out.getvalue()


def read_desktop(p: Path) -> configparser.ConfigParser:
    cp = configparser.ConfigParser(interpolation=None, strict=False)
    cp.optionxform = str
    cp.read_string(p.read_text())
    return cp


def png_pixels(png: bytes):
    """Decode an 8-bit RGBA, filter-0 PNG as written by icons._png."""
    w, h = png_size(png)
    pos, idat = 8, b""
    while pos < len(png):
        n = struct.unpack_from(">I", png, pos)[0]
        tag = png[pos + 4:pos + 8]
        if tag == b"IDAT":
            idat += png[pos + 8:pos + 8 + n]
        pos += 12 + n
    raw = zlib.decompress(idat)
    rows = [raw[y * (w * 4 + 1) + 1:(y + 1) * (w * 4 + 1)] for y in range(h)]
    return w, h, [[tuple(r[4 * x:4 * x + 4]) for x in range(w)] for r in rows]


class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.d = FakeDesktop(Path(self._t.name))

    def tearDown(self):
        self._t.cleanup()

    def bridge(self):
        return Bridge(self.d.host())


class CatalogTests(unittest.TestCase):
    def test_catalog_is_consistent(self):
        ids = [a.id for a in BUILTIN]
        self.assertEqual(len(ids), len(set(ids)))
        for a in BUILTIN:
            self.assertIn(a.suite, SUITES)
            self.assertTrue(a.routes, a.id)
            for r in a.routes:
                self.assertIn(r.backend, BACKENDS, a.id)

    def test_wm_class_is_wines_window_class(self):
        word = next(a for a in BUILTIN if a.id == "word")
        ill = next(a for a in BUILTIN if a.id == "illustrator")
        self.assertEqual(word.wm_class, "winword.exe")
        self.assertEqual(ill.wm_class, "illustrator.exe")


class Ms365Tests(Base):
    def test_not_set_up_without_ms365_or_nix(self):
        res = self.bridge().resolve(self.bridge().app("word"))
        self.assertEqual(res.status, NO_BACKEND)
        self.assertIn("nix", res.summary.lower())

    def test_set_up_then_installed(self):
        self.d.tool("ms365")
        b = self.bridge()
        res = b.resolve(b.app("word"))
        self.assertEqual((res.status, res.backend.name), (NOT_INSTALLED, "ms365"))
        self.assertEqual([c.argv[1:] for c in b.install_commands(res)], [["install"]])
        self.d.office("WINWORD.EXE")
        res = b.resolve(b.app("word"))
        self.assertEqual(res.status, READY)
        doc = self.d.put("Documents/report.docx")
        cmds = b.launch_commands(res, [str(doc)])
        self.assertEqual(cmds[0].argv[1:], ["run", "word", str(doc)])

    def test_proton_pfx_layout_counts_as_installed(self):
        self.d.tool("ms365")
        self.d.office("EXCEL.EXE", pfx=True)
        b = self.bridge()
        self.assertEqual(b.resolve(b.app("excel")).status, READY)
        self.assertEqual(b.resolve(b.app("word")).status, NOT_INSTALLED)

    def test_nix_fallback_uses_flake(self):
        self.d.tool("nix")
        b = self.bridge()
        res = b.resolve(b.app("powerpoint"))
        argv = b.install_commands(res)[0].argv
        self.assertIn("github:Tombert/office365_flake#ms365", argv)
        self.assertEqual(argv[-2:], ["--", "install"])

    def test_nix_fallback_prefers_checked_out_fork(self):
        self.d.tool("nix")
        co = self.d.root / "checkout"
        (co / "third_party/office365_flake").mkdir(parents=True)
        (co / "third_party/office365_flake/flake.nix").write_text("{}")
        (co / ".gitmodules").write_text('[submodule "third_party/office365_flake"]\n'
                                        '\tpath = third_party/office365_flake\n'
                                        '\turl = https://github.com/spaley2011/office365_flake.git\n')
        h = Host(env=dict(self.d.env), checkout=co)
        argv = BACKENDS["ms365"].tool(h)
        self.assertIn(f"{co}/third_party/office365_flake#ms365", argv)
        self.assertEqual(h.submodule_repo("office365_flake"), "spaley2011/office365_flake")
        self.assertEqual(h.submodule_repo("winapps"), "winapps-org/winapps")


class AdobeTests(Base):
    def test_newest_year_folder_wins(self):
        self.d.tool("adobewine")
        self.d.adobe("Adobe Photoshop 2025", "Photoshop.exe")
        newest = self.d.adobe("Adobe Photoshop 2026", "Photoshop.exe")
        b = self.bridge()
        res = b.resolve(b.app("photoshop"))
        self.assertEqual(res.status, READY)
        self.assertEqual(res.backend.exe_path(res.app, res.state.route, b.host), newest)
        self.assertEqual(b.launch_commands(res, [])[0].argv[1:], ["photoshop"])

    def test_install_runs_setup_then_creative_cloud(self):
        self.d.tool("adobewine")
        b = self.bridge()
        res = b.resolve(b.app("illustrator"))
        self.assertEqual(res.status, NOT_INSTALLED)
        self.assertEqual([c.argv[1:] for c in b.install_commands(res)], [["setup"], ["cc"]])

    def test_flatpak_lindobe_uses_its_data_dir(self):
        self.d.tool("flatpak")
        self.d.flatpak_app("io.github.le_birnes.AdobeWine")
        self.d.adobe("Acrobat DC", "Acrobat/Acrobat.exe",
                     base=".var/app/io.github.le_birnes.AdobeWine/data/adobewine")
        b = self.bridge()
        res = b.resolve(b.app("acrobat"))
        self.assertEqual(res.status, READY)
        self.assertEqual(b.launch_commands(res, [])[0].argv[1:],
                         ["run", "--command=adobewine", "io.github.le_birnes.AdobeWine", "acrobat"])


class VmTests(Base):
    def test_winapps_needs_config(self):
        self.d.tool("winapps")
        b = self.bridge()
        res = b.resolve(b.app("visio"))
        self.assertEqual(res.status, NO_BACKEND)
        self.assertIn("winapps.conf", res.summary)

    def test_winapps_picks_the_installed_variant_and_opens_files_one_by_one(self):
        self.d.winapps("word-o365-x86", "visio")
        b = self.bridge()
        res = b.resolve(b.app("word"))
        self.assertEqual((res.status, res.backend.name), (READY, "winapps"))
        a, c = self.d.put("a.docx"), self.d.put("b.docx")
        cmds = b.launch_commands(res, [str(a), str(c)])
        self.assertEqual([x.argv[1:] for x in cmds], [["word-o365-x86", str(a)], ["word-o365-x86", str(c)]])
        self.assertEqual(b.resolve(b.app("project")).status, NOT_INSTALLED)

    def test_unknown_when_winapps_never_scanned(self):
        self.d.tool("winapps")
        self.d.put(".config/winapps/winapps.conf", b"")
        b = self.bridge()
        self.assertEqual(b.resolve(b.app("powerbi")).status, READY)   # can't tell; let it try

    def test_ms365_wins_over_vm_until_you_prefer_the_vm(self):
        self.d.tool("ms365")
        self.d.office("WINWORD.EXE")
        self.d.winapps("word-o365")
        b = self.bridge()
        self.assertEqual(b.resolve(b.app("word")).backend.name, "ms365")
        code, out = run_cli(self.d, "prefer", "word", "winapps")
        self.assertEqual(code, 0, out)
        b = self.bridge()
        self.assertEqual(b.resolve(b.app("word")).backend.name, "winapps")
        run_cli(self.d, "prefer", "word", "auto")
        self.assertEqual(self.bridge().resolve(self.bridge().app("word")).backend.name, "ms365")

    def test_unusable_preference_falls_back(self):
        self.d.tool("ms365")
        self.d.office("WINWORD.EXE")
        code, _ = run_cli(self.d, "prefer", "word", "linoffice")
        self.assertEqual(code, 0)
        self.assertEqual(self.bridge().resolve(self.bridge().app("word")).backend.name, "ms365")

    def test_preference_for_missing_app_does_not_break_launch(self):
        self.d.tool("ms365")
        self.d.office("WINWORD.EXE")
        self.d.winapps("visio")            # the VM has Visio but not Word
        run_cli(self.d, "prefer", "word", "winapps")
        res = self.bridge().resolve(self.bridge().app("word"))
        self.assertEqual((res.status, res.backend.name), (READY, "ms365"))
        res = self.bridge().resolve(self.bridge().app("word"), backend="winapps")
        self.assertEqual(res.status, NOT_INSTALLED)

    def test_linoffice_flatpak(self):
        self.d.tool("flatpak")
        self.d.flatpak_app("io.github.eylenburg.LinOffice", system=True)
        b = self.bridge()
        res = b.resolve(b.app("excel"))
        self.assertEqual(res.backend.name, "linoffice")
        self.assertEqual(b.launch_commands(res, [])[0].argv[1:],
                         ["run", "--command=/app/linoffice.sh", "io.github.eylenburg.LinOffice", "excel"])


class WrapperTests(Base):
    def test_teams_flatpak_installable(self):
        self.d.tool("flatpak")
        b = self.bridge()
        res = b.resolve(b.app("teams"))
        self.assertEqual(res.status, NOT_INSTALLED)
        self.assertEqual(b.install_commands(res)[0].argv[1:],
                         ["install", "--user", "-y", "flathub", "com.github.IsmaelMartinez.teams_for_linux"])

    def test_outlook_falls_back_to_prospect_mail(self):
        self.d.tool("prospect-mail")
        b = self.bridge()
        res = b.resolve(b.app("outlook"))
        self.assertEqual((res.status, res.backend.name), (READY, "native"))

    def test_native_not_installed_is_not_set_up(self):
        b = self.bridge()
        res = b.resolve(b.app("teams"))
        self.assertEqual(res.status, NO_BACKEND)
        self.assertIn("teams-for-linux", b.install_hint(res))

    def test_onedrive_service(self):
        self.d.tool("onedrive")
        self.d.tool("systemctl")
        self.d.tool("xdg-open")
        b = self.bridge()
        res = b.resolve(b.app("onedrive"))
        self.assertEqual(res.status, NOT_INSTALLED)
        inst = b.install_commands(res)
        self.assertTrue(inst[0].interactive)
        self.assertEqual(inst[1].argv[1:], ["--user", "enable", "--now", "onedrive.service"])
        self.d.put(".config/onedrive/refresh_token", b"x")
        self.d.put(".config/onedrive/config", b'sync_dir = "~/Work/OneDrive"\n')
        res = b.resolve(b.app("onedrive"))
        self.assertEqual(res.status, READY)
        cmds = b.launch_commands(res, [])
        self.assertEqual(cmds[0].argv[1:], ["--user", "start", "onedrive.service"])
        self.assertEqual(cmds[1].argv[1:], [str(self.d.home / "Work/OneDrive")])
        self.assertEqual(b.stop_command(res).argv[1:], ["--user", "stop", "onedrive.service"])


class CustomAppTests(Base):
    def test_add_wine_app_and_launch(self):
        self.d.tool("wine")
        code, out = run_cli(self.d, "add", "expenses", "--name", "Expense Tool",
                            "--exe", "C:\\Program Files\\Acme\\Expense.exe", "--mime", "application/x-acme")
        self.assertEqual(code, 0, out)
        self.assertIn("not installed", out)
        b = self.bridge()
        prefix = self.d.home / ".local/share/appbridge/prefixes/expenses"
        (prefix / "drive_c/Program Files/Acme").mkdir(parents=True)
        (prefix / "drive_c/Program Files/Acme/Expense.exe").write_bytes(b"MZ")
        res = b.resolve(b.app("expenses"))
        self.assertEqual(res.status, READY)
        f = self.d.put("q3 report.acme")
        c = b.launch_commands(res, [str(f)])[0]
        self.assertEqual(c.env["WINEPREFIX"], str(prefix))
        self.assertEqual(c.argv[2], f"Z:{str(f).replace('/', chr(92))}")
        self.assertEqual(b.app("expenses").wm_class, "expense.exe")
        code, out = run_cli(self.d, "launch", "--dry-run", "expenses")
        self.assertIn("WINEPREFIX=", out)

    def test_umu_runner(self):
        self.d.tool("umu-run")
        exe = self.d.put("apps/tool.exe", b"MZ")
        run_cli(self.d, "add", "tool", "--exe", str(exe), "--runner", "umu")
        b = self.bridge()
        res = b.resolve(b.app("tool"))
        c = b.launch_commands(res, [])[0]
        self.assertEqual((c.env["GAMEID"], c.env["PROTONPATH"]), ("umu-default", "GE-Proton"))
        self.assertTrue(c.argv[0].endswith("umu-run"))

    def test_umu_app_not_ready_with_only_wine(self):
        self.d.tool("wine")
        exe = self.d.put("apps/tool.exe", b"MZ")
        run_cli(self.d, "add", "tool", "--exe", str(exe), "--runner", "umu")
        res = self.bridge().resolve(self.bridge().app("tool"))
        self.assertEqual(res.status, NO_BACKEND)

    def test_reject_builtin_id_and_bad_id(self):
        self.assertEqual(run_cli(self.d, "add", "word", "--exe", "x.exe")[0], 1)
        self.assertEqual(run_cli(self.d, "add", "Bad Id", "--exe", "x.exe")[0], 1)

    def test_remove(self):
        run_cli(self.d, "add", "tool", "--exe", "x.exe")
        self.assertEqual(run_cli(self.d, "remove", "tool")[0], 0)
        with self.assertRaises(KeyError):
            self.bridge().app("tool")

    def test_windows_path(self):
        self.assertEqual(to_windows_path("/home/a/b c.docx"), "Z:\\home\\a\\b c.docx")
        self.assertEqual(to_windows_path("rel.txt"), "rel.txt")


class IntegrationTests(Base):
    def ready_word(self):
        self.d.tool("ms365")
        return self.d.office("WINWORD.EXE")

    def test_writes_desktop_entry(self):
        self.ready_word()
        self.d.winapps("word-o365")
        b = self.bridge()
        r = Integrator(b).add(["word"])
        p = self.d.home / ".local/share/applications/appbridge-word.desktop"
        self.assertIn(p, r.written)
        e = read_desktop(p)["Desktop Entry"]
        self.assertEqual(e["Name"], "Microsoft Word")
        self.assertTrue(e["Exec"].endswith(" launch word %F"))
        self.assertIn("application/vnd.openxmlformats-officedocument.wordprocessingml.document;", e["MimeType"])
        self.assertEqual(e["StartupWMClass"], "winword.exe")
        self.assertEqual(e["Icon"], "x-office-document")   # the fake .exe has no icon resources
        self.assertEqual(e["Actions"], "via-winapps;stop;")
        act = read_desktop(p)["Desktop Action via-winapps"]
        self.assertTrue(act["Exec"].endswith("launch --backend winapps word"))
        self.assertTrue(p.stat().st_mode & 0o100)
        self.assertTrue((self.d.home / ".local/share/applications/io.github.debpak.AppBridge.desktop").exists())

    def test_all_only_adds_ready_apps(self):
        self.ready_word()
        r = Integrator(self.bridge()).add(include_self=False)
        self.assertEqual([p.name for p in r.written], ["appbridge-word.desktop"])

    def test_named_app_not_ready_is_reported(self):
        r = Integrator(self.bridge()).add(["excel"], include_self=False)
        self.assertEqual(r.written, [])
        self.assertEqual(r.skipped[0][0], "excel")

    def test_skips_apps_that_ship_their_own_entry(self):
        self.d.tool("teams-for-linux")
        r = Integrator(self.bridge()).add(["teams"], include_self=False)
        self.assertEqual(r.skipped, [("teams", "it installs its own menu entry")])

    def test_does_not_duplicate_upstream_shortcut(self):
        self.ready_word()
        self.d.put(".local/share/applications/ms365-word.desktop",
                   b"[Desktop Entry]\nType=Application\nName=Microsoft Word\nExec=ms365 run word\n")
        r = Integrator(self.bridge()).add(["word"], include_self=False)
        self.assertEqual(r.written, [])
        self.assertIn("ms365-word.desktop", r.skipped[0][1])
        r = Integrator(self.bridge()).add(["word"], include_self=False, force=True)
        self.assertEqual(len(r.written), 1)

    def test_real_icon_from_exe(self):
        self.d.tool("ms365")
        self.d.office("WINWORD.EXE", data=build_pe_with_icons([_dib32(16, 16, (1, 2, 3, 255), (9, 9, 9, 128))]))
        Integrator(self.bridge()).add(["word"], include_self=False)
        e = read_desktop(self.d.home / ".local/share/applications/appbridge-word.desktop")["Desktop Entry"]
        icon = Path(e["Icon"])
        self.assertEqual(icon, self.d.home / ".local/share/appbridge/icons/word.png")
        self.assertEqual(png_size(icon.read_bytes()), (16, 16))

    def test_winapps_icon_svg(self):
        self.d.winapps("visio")
        Integrator(self.bridge()).add(["visio"], include_self=False)
        e = read_desktop(self.d.home / ".local/share/applications/appbridge-visio.desktop")["Desktop Entry"]
        self.assertTrue(e["Icon"].endswith("winapps/apps/visio/icon.svg"))

    def test_remove_only_ours(self):
        self.ready_word()
        other = self.d.put(".local/share/applications/other.desktop", b"[Desktop Entry]\nName=Other\n")
        Integrator(self.bridge()).add()
        r = Integrator(self.bridge()).remove(include_self=True)
        self.assertEqual(sorted(p.name for p in r.removed),
                         ["appbridge-word.desktop", "io.github.debpak.AppBridge.desktop"])
        self.assertTrue(other.exists())

    def test_refresh_runs_kde_and_mime_tools_and_defaults(self):
        self.ready_word()
        for t in ("kbuildsycoca6", "update-desktop-database", "xdg-mime"):
            self.d.tool(t)
        r = Integrator(self.bridge()).add(["word"], include_self=False, set_default=True)
        self.assertEqual(r.refreshed, ["update-desktop-database", "kbuildsycoca6"])
        log = self.d.calls.read_text()
        self.assertIn("xdg-mime default appbridge-word.desktop application/msword", log)
        self.assertIn("kbuildsycoca6", log)

    def test_dry_run_writes_nothing(self):
        self.ready_word()
        code, out = run_cli(self.d, "integrate", "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("would write", out)
        self.assertFalse((self.d.home / ".local/share/applications").exists())

    def test_exec_quoting(self):
        self.assertEqual(_exec_quote("plain"), "plain")
        self.assertEqual(_exec_quote("/opt/my apps/appbridge"), '"/opt/my apps/appbridge"')
        self.assertEqual(_exec_quote('a"b$c'), '"a\\"b\\$c"')
        # value-level escaping doubles the backslashes added by Exec quoting
        self.assertEqual(_exec(['a"b']), '"a\\\\"b"')

    @unittest.skipUnless(shutil.which("desktop-file-validate"), "desktop-file-validate not installed")
    def test_validates(self):
        self.ready_word()
        self.d.winapps("word-o365")
        Integrator(self.bridge()).add(["word"])
        for p in (self.d.home / ".local/share/applications").glob("*.desktop"):
            r = subprocess.run(["desktop-file-validate", str(p)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


