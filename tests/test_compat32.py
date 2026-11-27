"""32-bit x86 programs in a 64-bit Flatpak, with Flathub's Compat.i386 (see debpak.compat32)."""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from debpak import compat32
from debpak.analyze import Analysis, _compat32, analyze
from debpak.elf import ElfInfo
from debpak.packages import Package
from debpak.runtime import RuntimeIndex
from debpak.stage import stage

from elfgen import elf

LOADER32 = "/lib/ld-linux.so.2"
LOADER64 = "/lib64/ld-linux-x86-64.so.2"


def runtime(*sonames: str) -> RuntimeIndex:
    names = ("libc.so.6", "libm.so.6", "libdl.so.2", "librt.so.1", "libutil.so.1", "libnsl.so.1", "libX11.so.6",
             "libglib-2.0.so.0", "libnotify.so.4") + sonames
    return RuntimeIndex("org.freedesktop.Platform/x86_64/25.08", "x86_64", {n: f"/usr/lib/x86_64-linux-gnu/{n}"
                                                                            for n in names}, {}, "GLIBC_2.42")


def put(root: Path, rel: str, data: bytes, mode: int = 0o755) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    p.chmod(mode)


def snap_like(t: Path, gl: bool = False) -> Package:
    """BlackBox's snap, cut down: an amd64 core18 snap whose program is i386, with Ubuntu's i386 GTK 2."""
    root = t / "root"
    opt = "opt/bbcb"
    put(root, f"{opt}/.debpak-snap/bbcb", b"#!/bin/sh\nexec \"$SNAP/usr/lib/blackbox/run-BlackBox\" \"$@\"\n")
    put(root, f"{opt}/usr/lib/blackbox/run-BlackBox", b"#!/bin/sh\nexec \"$(dirname \"$0\")/blackbox\" \"$@\"\n")
    put(root, f"{opt}/usr/lib/blackbox/blackbox", elf("i386", LOADER32, ["librt.so.1", "libdl.so.2", "libc.so.6"]
                                                       + (["libGL.so.1"] if gl else [])))
    put(root, f"{opt}/usr/lib/i386-linux-gnu/libgtk-x11-2.0.so.0", elf(
        "i386", "", ["libgdk-x11-2.0.so.0", "libX11.so.6", "libc.so.6"], "libgtk-x11-2.0.so.0"))
    put(root, f"{opt}/usr/lib/i386-linux-gnu/libgdk-x11-2.0.so.0", elf(
        "i386", "", ["libXinerama.so.1", "libc.so.6"], "libgdk-x11-2.0.so.0"))
    put(root, f"{opt}/usr/lib/i386-linux-gnu/glib-2.0/gio-querymodules", elf("i386", LOADER32, ["libc.so.6"]))
    put(root, f"{opt}/usr/lib/i386-linux-gnu/libGL.so.1", elf("i386", "", ["libGLX.so.0"], "libGL.so.1"))
    put(root, f"{opt}/usr/bin/notify-send", elf("x86_64", LOADER64, ["libnotify.so.4", "libc.so.6"]))
    put(root, "usr/share/applications/bbcb_bbcb.desktop",
        b"[Desktop Entry]\nName=BlackBox\nExec=/opt/bbcb/.debpak-snap/bbcb\nType=Application\n", 0o644)
    pkg = Package("snap", t / "bbcb_50.snap", root, "bbcb", "1.8-b1", "x86_64")
    pkg.extra.update({"opt_name": "bbcb", "base": "core18"})
    return pkg


class ProgramsTests(unittest.TestCase):
    def test_which_32_bit_programs_are_the_apps(self):
        i386 = {
            "opt/bbcb/usr/lib/blackbox/blackbox": ElfInfo("b", "i386", 2, 32, interp=LOADER32),
            "opt/bbcb/usr/lib/i386-linux-gnu/glib-2.0/gio-querymodules": ElfInfo("g", "i386", 3, 32, interp=LOADER32),
            "opt/bbcb/usr/lib/i386-linux-gnu/libgtk-x11-2.0.so.0": ElfInfo("l", "i386", 3, 32),
            "opt/x/node_modules/foo/prebuilds/linux-ia32/helper": ElfInfo("n", "i386", 2, 32, interp=LOADER32),
            "opt/x/bin/tool32": ElfInfo("t", "i386", 2, 32, interp=LOADER32),
            "opt/x/Dev/exeFreeBSD.img": ElfInfo("f", "i386", 2, 32, interp="/libexec/ld-elf.so.1"),
        }
        i386["opt/x/resources/7zip/linux/ia32/7za"] = ElfInfo("z", "i386", 2, 32, interp=LOADER32)
        own = {"opt/x/bin/tool64": ElfInfo("t64", "x86_64", 2, 64, interp=LOADER64),
               "opt/x/resources/7zip/linux/x64/7za": ElfInfo("z64", "x86_64", 2, 64, interp=LOADER64)}
        self.assertEqual(compat32.programs(i386, own), ["opt/bbcb/usr/lib/blackbox/blackbox"])
        self.assertEqual(compat32.programs(i386, {}), ["opt/bbcb/usr/lib/blackbox/blackbox", "opt/x/bin/tool32",
                                                       "opt/x/resources/7zip/linux/ia32/7za"])

    def test_freedesktop_branch_of_the_runtime(self):
        self.assertEqual(compat32.freedesktop_branch("org.freedesktop.Platform/x86_64/25.08"), "25.08")
        self.assertEqual(compat32.freedesktop_branch("org.gnome.Platform/x86_64/49"), "25.08")
        self.assertEqual(compat32.freedesktop_branch("org.gnome.Platform//51"), "26.08")
        self.assertEqual(compat32.freedesktop_branch("org.kde.Platform/x86_64/5.15-25.08"), "25.08")
        self.assertEqual(compat32.freedesktop_branch("org.kde.Platform/x86_64/6.10"), "25.08")


class AnalysisTests(unittest.TestCase):
    def test_own_32_bit_glibc_is_left_out_and_gaps_listed(self):
        # BlackBox's snap carries Ubuntu 18.04's i386 glibc, which its launcher puts first on the library path;
        # the extension's loader works only with its own
        root = Path("/nonexistent")
        i386 = {
            "opt/b/usr/lib/blackbox/blackbox": ElfInfo("b", "i386", 2, 32, interp=LOADER32,
                                                       needed=["libgtk-x11-2.0.so.0", "libc.so.6"]),
            "opt/b/lib/i386-linux-gnu/libc-2.27.so": ElfInfo("c", "i386", 3, 32, needed=["ld-linux.so.2"],
                                                             soname="libc.so.6", verdef={"GLIBC_2.0", "GLIBC_2.1"}),
            "opt/b/lib/i386-linux-gnu/libcrypt-2.27.so": ElfInfo("cr", "i386", 3, 32, soname="libcrypt.so.1",
                                                                 verneed={"libc.so.6": {"GLIBC_PRIVATE"}}),
            "opt/b/usr/lib/i386-linux-gnu/libgtk-x11-2.0.so.0": ElfInfo("g", "i386", 3, 32, soname="libgtk-x11-2.0.so.0",
                                                                        needed=["libXinerama.so.1", "libc.so.6"]),
            "opt/b/usr/lib/i386-linux-gnu/gtk-2.0/engines/libpixmap.so": ElfInfo("e", "i386", 3, 32,
                                                                                 needed=["libfoo.so.1"]),
        }
        a = Analysis(pkg=SimpleNamespace(root=root), arch="x86_64")
        links = [("libc.so.6", "opt/b/lib/i386-linux-gnu/libc-2.27.so")]
        with mock.patch("debpak.analyze.starts_own_loader", return_value=False):
            _compat32(a, ["opt/b/usr/lib/blackbox/blackbox"], i386, links, runtime())
        self.assertEqual(a.runtime_replaces["opt/b/lib/i386-linux-gnu/libc-2.27.so"], ["libc.so.6"])
        self.assertIn("opt/b/lib/i386-linux-gnu/libcrypt-2.27.so", a.runtime_replaces)
        self.assertEqual(a.compat32_missing, {"libXinerama.so.1"})
        self.assertEqual(a.compat32_missing_soft, {"libfoo.so.1"})
        self.assertFalse(a.compat32_gl)
        self.assertEqual(a.compat32_lib_dirs, ["opt/b/usr/lib/i386-linux-gnu"])
        # a package that starts its own loader keeps its glibc
        a = Analysis(pkg=SimpleNamespace(root=root), arch="x86_64")
        with mock.patch("debpak.analyze.starts_own_loader", return_value=True):
            _compat32(a, ["opt/b/usr/lib/blackbox/blackbox"], i386, links, runtime())
        self.assertEqual(a.runtime_replaces, {})

    def test_gl_only_for_a_program_that_draws(self):
        # S4A's snap carries Ubuntu's i386 Mesa and GLU beside a Squeak VM that draws with plain X11
        i386 = {"p/vm": ElfInfo("v", "i386", 2, 32, interp=LOADER32, needed=["libX11.so.6"]),
                "p/lib/libGL.so.1": ElfInfo("g", "i386", 3, 32, soname="libGL.so.1", needed=["libGLX.so.0"]),
                "p/lib/libGLU.so.1": ElfInfo("u", "i386", 3, 32, soname="libGLU.so.1", needed=["libGL.so.1"]),
                "p/lib/dri/i965_dri.so": ElfInfo("d", "i386", 3, 32, needed=["libglapi.so.0"])}
        a = Analysis(pkg=SimpleNamespace(root=Path("/nonexistent")), arch="x86_64")
        with mock.patch("debpak.analyze.starts_own_loader", return_value=False):
            _compat32(a, ["p/vm"], i386, [], runtime())
        self.assertFalse(a.compat32_gl)
        self.assertNotIn("p/lib/libGL.so.1", a.runtime_replaces)
        i386["p/game"] = ElfInfo("x", "i386", 2, 32, interp=LOADER32, needed=["libGL.so.1"])
        a = Analysis(pkg=SimpleNamespace(root=Path("/nonexistent")), arch="x86_64")
        with mock.patch("debpak.analyze.starts_own_loader", return_value=False):
            _compat32(a, ["p/game"], i386, [], runtime())
        self.assertTrue(a.compat32_gl)
        self.assertIn("p/lib/libGL.so.1", a.runtime_replaces)       # GL32's must match the host's driver
        self.assertNotIn("libglapi.so.0", a.compat32_missing | a.compat32_missing_soft)


class ManifestTests(unittest.TestCase):
    def test_snap_with_a_32_bit_program(self):
        # bbcb: "env: '/app/opt/bbcb/usr/lib/blackbox/blackbox': No such file or directory" (no /lib/ld-linux.so.2)
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            pkg = snap_like(t)
            a = analyze(pkg, runtime())
            self.assertEqual(a.compat32, ["opt/bbcb/usr/lib/blackbox/blackbox"])
            self.assertTrue(a.multiarch)
            self.assertEqual(a.compat32_missing, set())
            self.assertEqual(a.compat32_missing_soft, {"libXinerama.so.1"})
            self.assertEqual(a.blockers, [])
            out = t / "out"
            res = stage(a, out, "com.example.Bbcb", "org.freedesktop.Platform/x86_64/25.08", "bundle", [], {}, None)
            m = json.loads(res.manifest_path.read_text())
            self.assertEqual(m["add-extensions"], {compat32.COMPAT_EXTENSION: {
                "directory": "lib/i386-linux-gnu", "version": "25.08"}})
            self.assertIn("mkdir -p ${FLATPAK_DEST}/lib/i386-linux-gnu", m["modules"][0]["build-commands"])
            self.assertEqual((out / "app/etc/ld.so.conf").read_text().splitlines(),
                             ["/app/lib/i386-linux-gnu", "/app/opt/bbcb/usr/lib/i386-linux-gnu"])
            self.assertEqual(compat32.install_refs(m), ["org.freedesktop.Platform.Compat.i386/x86_64/25.08"])
            self.assertTrue(any("32-bit x86 program" in n for n in res.notes))

    def test_gl32_and_the_libraries_fetched(self):
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            pkg = snap_like(t, gl=True)
            a = analyze(pkg, runtime())
            self.assertTrue(a.compat32_gl)
            fetched = t / "fetched"
            fetched.mkdir()
            (fetched / "libXinerama.so.1").write_bytes(elf("i386", "", ["libc.so.6"], "libXinerama.so.1"))
            a.compat32_bundled, a.compat32_bundled_dir = {"libXinerama.so.1": "libxinerama1:i386"}, fetched
            out = t / "out"
            res = stage(a, out, "com.example.Bbcb", "org.gnome.Platform/x86_64/49", "bundle", [], {}, None)
            m = json.loads(res.manifest_path.read_text())
            gl = m["add-extensions"][compat32.GL32_EXTENSION]
            self.assertEqual((gl["directory"], gl["versions"], gl["add-ld-path"]),
                             ("lib/i386-linux-gnu/GL", "25.08;25.08-extra;1.4", "lib"))
            self.assertEqual(m["add-extensions"][compat32.COMPAT_EXTENSION]["version"], "25.08")
            conf = (out / "app/etc/ld.so.conf").read_text().splitlines()
            self.assertEqual(conf[:3], ["include /run/flatpak/ld.so.conf.d/app-*-org.freedesktop.Platform.GL32.*.conf",
                                        "/app/lib/i386-linux-gnu", "/app/lib/debpak-i386"])
            self.assertTrue((out / "app/lib/debpak-i386/libXinerama.so.1").is_file())
            self.assertFalse((out / "app/opt/bbcb/usr/lib/i386-linux-gnu/libGL.so.1").exists())
            self.assertEqual(compat32.install_refs(m), ["org.freedesktop.Platform.Compat.i386/x86_64/25.08",
                                                        "org.freedesktop.Platform.GL32.default/x86_64/25.08"])

    def test_package_with_no_32_bit_program_is_unchanged(self):
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            pkg = snap_like(t)
            (pkg.root / "opt/bbcb/usr/lib/blackbox/blackbox").unlink()
            a = analyze(pkg, runtime())
            self.assertEqual(a.compat32, [])
            res = stage(a, t / "out", "com.example.Bbcb", "org.freedesktop.Platform/x86_64/25.08", "bundle", [], {},
                        None)
            self.assertNotIn("add-extensions", json.loads(res.manifest_path.read_text()))

    def test_extensions_installed_after_the_app(self):
        from debpak import cli
        with tempfile.TemporaryDirectory() as t:
            manifest = Path(t) / "m.json"
            manifest.write_text(json.dumps({"add-extensions": compat32.add_extensions("25.08", False)}))
            calls = []
            with mock.patch("debpak.cli.subprocess.run"), \
                    mock.patch("debpak.cli.subprocess.call", side_effect=lambda c: calls.append(c) or 0), \
                    mock.patch("debpak.host.command", side_effect=lambda c: c):
                cli._install_extensions(manifest)
            self.assertEqual(calls, [["flatpak", "install", "--user", "-y", "--noninteractive", "--or-update",
                                      "flathub", "org.freedesktop.Platform.Compat.i386/x86_64/25.08"]])


if __name__ == "__main__":
    unittest.main()
