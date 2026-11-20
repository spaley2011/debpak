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


