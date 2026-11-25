"""Conversion from .rpm, Arch packages, vendor tarballs and AppImages, using the
same compiled app and libraries as the .deb tests."""
import contextlib
import gzip
import io
import json
import lzma
import os
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock
from pathlib import Path

from debpak.cli import main
from debpak.desktop import spdx_license
from debpak.packages import PackageError, appimage_image, appimage_offset, detect_format, open_package
from debpak.rpm import extract_rpm
from debpak.runtime import index_root

from fixtures import Fixtures, have_toolchain, tiny_png
from format_fixtures import build_appimage, build_pacman, build_rpm, build_tarball, rpm_repo
from isolate import offline


def run_cli(*argv):
    out = io.StringIO()
    with offline(), contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = main(list(argv))
    return code, out.getvalue()


POSTINST = "ldconfig\nupdate-desktop-database -q || true\n"


@unittest.skipUnless(have_toolchain(), "needs gcc and dpkg-deb on x86_64")
class FormatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="debpak-formats-")
        cls.base = Path(cls._tmp.name)
        cls.fx = Fixtures(cls.base / "fx")
        cls.index_path = cls.base / "runtime.json"
        index_root(cls.fx.runtime_root, "org.test.Platform/x86_64/1", "x86_64").save(cls.index_path)
        b = cls.fx.base
        cls.app_tree, cls.lib1_tree, cls.lib2_tree = b / "pkg-fakeapp", b / "pkg-libfake1", b / "pkg-libfakedep2"
        cls.rpms = cls.base / "rpms"
        cls.rpms.mkdir()
        cls.app_rpm = build_rpm(cls.app_tree, cls.base / "fakeapp-1.2.3-1.x86_64.rpm", "fakeapp",
                                scripts={"post": POSTINST}, license="MIT")
        cls.lib1_rpm = build_rpm(cls.lib1_tree, cls.rpms / "libfake1-1.2.3-1.x86_64.rpm", "libfake1",
                                 compression="xz")
        cls.lib2_rpm = build_rpm(cls.lib2_tree, cls.rpms / "libfakedep2-1.2.3-1.x86_64.rpm", "libfakedep2")
        cls._env = dict(os.environ)
        os.environ["XDG_CACHE_HOME"] = str(cls.base / "cache")

    @classmethod
    def tearDownClass(cls):
        os.environ.clear()
        os.environ.update(cls._env)
        cls._tmp.cleanup()

    def out_dir(self, name):
        d = self.base / "out" / name
        shutil.rmtree(d, ignore_errors=True)
        return d

    def assert_runs(self, app: Path, exe: str):
        run = subprocess.run([str(app / exe)], capture_output=True, text=True,
                             env={**os.environ, "LD_LIBRARY_PATH": str(app / "lib/debpak")})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), "fakeapp says 42 4")

    # ------------------------------------------------------------------ detection
    def test_detect(self):
        self.assertEqual(detect_format(self.app_rpm), "rpm")
        self.assertEqual(detect_format(self.fx.app_deb), "deb")
        p = build_pacman(self.app_tree, self.base / "x-1-1-x86_64.pkg.tar.xz", "x")
        self.assertEqual(detect_format(p), "pacman")
        with self.assertRaises(PackageError):
            detect_format(self.fx.src / "fakeapp")        # a bare ELF program

    # ------------------------------------------------------------------ RPM
    def test_rpm_extract_matches_tree(self):
        with tempfile.TemporaryDirectory() as t:
            pkg = extract_rpm(self.app_rpm, t)
            self.assertEqual((pkg.format, pkg.name, pkg.version, pkg.pkg_arch, pkg.license),
                             ("rpm", "fakeapp", "1.2.3-1", "x86_64", "MIT"))
            self.assertEqual(pkg.flatpak_arch, "x86_64")
            self.assertIn("ldconfig", pkg.scripts["postinst"])
            self.assertTrue(pkg.scripts["postinst"].startswith("#!/bin/sh"))
            r = pkg.root
            self.assertEqual((r / "opt/Fake/fakeapp").read_bytes(), (self.app_tree / "opt/Fake/fakeapp").read_bytes())
            self.assertTrue(os.access(r / "opt/Fake/launch.sh", os.X_OK))
            self.assertEqual(os.readlink(r / "usr/bin/fakeapp"), "/opt/Fake/launch.sh")
            self.assertFalse((r / "DEBIAN").exists())

    def test_rpm_stripped_cpio_payload(self):
        # Chrome's RPM: entries are "07070X" + an index into the header's file list
        # (rpm does this when the package records 64-bit file sizes, as RPM v6 packages do)
        links = [("./opt/Fake/a", stat.S_IFREG | 0o755, b"", 77, 3), ("./opt/Fake/b", stat.S_IFREG | 0o755, b"", 77, 3),
                 ("./opt/Fake/c", stat.S_IFREG | 0o755, b"shared", 77, 3)]
        rpm = build_rpm(self.app_tree, self.base / "stripped.rpm", "fakeapp", extra_entries=links,
                        stripped=True, compression="xz")
        self.assertIn(b"07070X", lzma.decompress(rpm.read_bytes()[rpm.read_bytes().index(b"\xfd7zXZ"):]))
        with tempfile.TemporaryDirectory() as t:
            r = extract_rpm(rpm, t).root
            self.assertEqual((r / "opt/Fake/fakeapp").read_bytes(), (self.app_tree / "opt/Fake/fakeapp").read_bytes())
            self.assertTrue(os.access(r / "opt/Fake/launch.sh", os.X_OK))
            self.assertEqual(os.readlink(r / "usr/bin/fakeapp"), "/opt/Fake/launch.sh")
            self.assertEqual(len({(r / "opt/Fake" / n).stat().st_ino for n in "abc"}), 1)
            self.assertEqual((r / "opt/Fake/a").read_bytes(), b"shared")
        out = self.out_dir("rpm-stripped")
        code, log = run_cli("convert", str(rpm), "--app-id", "org.example.Stripped",
                            "--runtime-index", str(self.index_path), "--deps-dir", str(self.rpms), "-o", str(out))
        self.assertEqual(code, 0, log)
        self.assert_runs(out / "app", "opt/Fake/fakeapp")

    def test_rpm_stripped_cpio_index_outside_the_file_list(self):
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            (t / "tree").mkdir()
            (t / "tree/f").write_bytes(b"x")
            rpm = build_rpm(t / "tree", t / "s.rpm", "s", stripped=True)
            data = bytearray(rpm.read_bytes())
            raw = gzip.decompress(data[data.index(b"\x1f\x8b"):]).replace(b"07070X00000000", b"07070X00000009")
            data[data.index(b"\x1f\x8b"):] = gzip.compress(raw)
            rpm.write_bytes(bytes(data))
            with mock.patch("debpak.rpm.PAYLOADDIGEST", -1), self.assertRaises(PackageError) as cm:
                extract_rpm(rpm, t / "x")
            self.assertIn("isn't in the RPM header's file list", str(cm.exception))

    def test_rpm_convert_with_local_rpms(self):
        out = self.out_dir("rpm")
        code, log = run_cli("convert", str(self.app_rpm), "--app-id", "org.example.FakeRpm",
                            "--runtime-index", str(self.index_path), "--deps-dir", str(self.rpms), "-o", str(out))
        self.assertEqual(code, 0, log)
        self.assertIn("(x86_64, .rpm)", log)
        m = json.loads((out / "org.example.FakeRpm.json").read_text())
        self.assertEqual(set(m["x-debpak"]["bundled-libraries"]), {"libfake.so.1", "libfakedep.so.2"})
        self.assertEqual((m["x-debpak"]["format"], m["x-debpak"]["source-package"]),
                         ("rpm", self.app_rpm.name))
        app = out / "app"
        self.assertIn("\n/app/opt/Fake/launch.sh", (app / "bin/debpak-run").read_text())
        self.assert_runs(app, "opt/Fake/fakeapp")
        meta = (app / "share/metainfo/org.example.FakeRpm.metainfo.xml").read_text()
        self.assertIn("<project_license>MIT</project_license>", meta)
        self.assertIn('<url type="homepage">https://example.com</url>', meta)
        report = json.loads((out / "report.json").read_text())
        self.assertEqual(report["package"]["format"], "rpm")

    def test_rpm_repo_source(self):
        repo = rpm_repo(self.base / "repo", [
            (self.lib1_rpm, "libfake1", ["libfake.so.1()(64bit)", "libfake1"]),
            (self.lib2_rpm, "libfakedep2", ["libfakedep.so.2()(64bit)", "libfakedep.so.2"]),   # 32-bit-style ignored
        ])
        out = self.out_dir("rpm-repo")
        code, log = run_cli("convert", str(self.app_rpm), "--app-id", "org.example.FakeRepo",
                            "--runtime-index", str(self.index_path), "--rpm-repo", repo.as_uri(), "-o", str(out))
        self.assertEqual(code, 0, log)
        bundled = json.loads((out / "org.example.FakeRepo.json").read_text())["x-debpak"]["bundled-libraries"]
        self.assertIn("libfake1", bundled["libfake.so.1"])
        self.assertIn("libfakedep2", bundled["libfakedep.so.2"])
        self.assert_runs(out / "app", "opt/Fake/fakeapp")

    def test_rpm_payload_corruption_is_caught(self):
        bad = build_rpm(self.lib2_tree, self.base / "bad.rpm", "bad", corrupt_payload=True)
        with tempfile.TemporaryDirectory() as t, self.assertRaises(PackageError) as cm:
            extract_rpm(bad, t)
        self.assertRegex(str(cm.exception), "damaged|checksum mismatch")

    def test_rpm_header_corruption_is_caught(self):
        data = bytearray(self.lib2_rpm.read_bytes())
        i = data.index(b"libfakedep2", 200)          # the NAME string inside the main header
        data[i] = ord("X")
        bad = self.base / "badhdr.rpm"
        bad.write_bytes(bytes(data))
        with tempfile.TemporaryDirectory() as t, self.assertRaises(PackageError) as cm:
            extract_rpm(bad, t)
        self.assertIn("header checksum", str(cm.exception))

    def test_rpm_hostile_paths_stay_inside(self):
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            tree = t / "tree"
            (tree / "usr/bin").mkdir(parents=True)
            (tree / "usr/bin/ok").write_text("ok")
            outside = t / "outside"
            outside.mkdir()
            evil = [("./../evil", stat.S_IFREG | 0o644, b"x", 900, 1),
                    ("./esc", stat.S_IFLNK | 0o777, str(outside).encode(), 901, 1),
                    ("./esc/pwned", stat.S_IFREG | 0o644, b"x", 902, 1),
                    ("./usr/bin/suid", stat.S_IFREG | 0o4755, b"#!/bin/sh\n", 903, 1)]
            rpm = build_rpm(tree, t / "evil.rpm", "evil", extra_entries=evil)
            pkg = extract_rpm(rpm, t / "x")
            self.assertFalse((t / "x/evil").exists() or (t / "evil").exists())
            self.assertEqual(list(outside.iterdir()), [])
            self.assertTrue((pkg.root / "usr/bin/ok").is_file())
            self.assertEqual((pkg.root / "usr/bin/suid").stat().st_mode & 0o7777, 0o755)
            self.assertTrue(any("setuid" in n for n in pkg.notes))
            self.assertTrue(any("skipped 2" in n for n in pkg.notes))

    def test_rpm_hardlinks(self):
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            (t / "tree").mkdir()
            links = [("./a", stat.S_IFREG | 0o755, b"", 77, 3), ("./b", stat.S_IFREG | 0o755, b"", 77, 3),
                     ("./c", stat.S_IFREG | 0o755, b"shared", 77, 3)]
            pkg = extract_rpm(build_rpm(t / "tree", t / "h.rpm", "h", extra_entries=links), t / "x")
            inodes = {(pkg.root / n).stat().st_ino for n in "abc"}
            self.assertEqual(len(inodes), 1)
            self.assertEqual((pkg.root / "a").read_bytes(), b"shared")

    def test_rpm_zstd_through_the_zstd_command(self):
        rpm = build_rpm(self.lib2_tree, self.base / "z.rpm", "z", compression="fake-zstd")
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            bindir = t / "bin"
            bindir.mkdir()
            (bindir / "zstd").write_text("#!/bin/sh\ntail -c +5\n")     # strips the 4-byte magic
            (bindir / "zstd").chmod(0o755)
            old = os.environ["PATH"]
            os.environ["PATH"] = f"{bindir}:{old}"
            try:
                # as if no Python zstd module were installed (Python 3.14 has one built in)
                with mock.patch("debpak.deb._zstd_stream", return_value=None):
                    pkg = extract_rpm(rpm, t / "x")
            finally:
                os.environ["PATH"] = old
            self.assertTrue((pkg.root / "usr/lib/x86_64-linux-gnu/libfakedep.so.2.0.0").is_file())

    def test_rpm_zstd_tool_that_rereads_its_input(self):
        # uutils' tail (Ubuntu 25.10+) rewinds a file on stdin to the start instead of reading from
        # where it was handed over, so debpak pipes the payload instead of passing the file
        rpm = build_rpm(self.lib2_tree, self.base / "zr.rpm", "zr", compression="fake-zstd")
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            bindir = t / "bin"
            bindir.mkdir()
            (bindir / "zstd").write_text(f"#!{sys.executable}\n"
                                         "import os, sys\n"
                                         "try:\n    os.lseek(0, 0, os.SEEK_SET)\n"
                                         "except OSError:\n    pass\n"
                                         "sys.stdout.buffer.write(sys.stdin.buffer.read()[4:])\n")
            (bindir / "zstd").chmod(0o755)
            old = os.environ["PATH"]
            os.environ["PATH"] = f"{bindir}:{old}"
            try:
                with mock.patch("debpak.deb._zstd_stream", return_value=None):
                    pkg = extract_rpm(rpm, t / "x")
            finally:
                os.environ["PATH"] = old
            self.assertTrue((pkg.root / "usr/lib/x86_64-linux-gnu/libfakedep.so.2.0.0").is_file())

    def test_rpm_zstd_through_a_python_module(self):
        try:
            build_rpm(self.lib2_tree, self.base / "zp.rpm", "zp", compression="zstd")
        except ImportError:
            self.skipTest("no Python zstd module (zstandard, or Python 3.14+)")
        with tempfile.TemporaryDirectory() as t:
            pkg = extract_rpm(self.base / "zp.rpm", t)
            self.assertTrue((pkg.root / "usr/lib/x86_64-linux-gnu/libfakedep.so.2.0.0").is_file())

    def test_rpm_zstd_without_any_decoder_says_what_to_install(self):
        rpm = build_rpm(self.lib2_tree, self.base / "z2.rpm", "z2", compression="fake-zstd")
        old = os.environ["PATH"]
        os.environ["PATH"] = "/nonexistent"
        try:
            from debpak import deb
            if deb._zstd_stream(io.BytesIO(b"")) is not None:
                self.skipTest("a Python zstd module is installed")
            with tempfile.TemporaryDirectory() as t, self.assertRaises(PackageError) as cm:
                extract_rpm(rpm, t)
        finally:
            os.environ["PATH"] = old
        self.assertIn("zstd", str(cm.exception))

    def test_real_rpms_if_available(self):
        """Point DEBPAK_RPM_SAMPLES at a folder of real RPMs (e.g. rpm's tests/data/RPMS)."""
        d = os.environ.get("DEBPAK_RPM_SAMPLES")
        if not d:
            self.skipTest("DEBPAK_RPM_SAMPLES not set")
        for rpm in sorted(Path(d).glob("*.rpm")):
            with tempfile.TemporaryDirectory() as t:
                try:
                    pkg = extract_rpm(rpm, t)
                except PackageError as e:
                    self.assertRegex(str(e), "corrupt|damaged|zstd|checksum", rpm.name)
                    continue
                self.assertTrue(pkg.name)

    # ------------------------------------------------------------------ Arch
    def test_pacman_convert(self):
        pkg = build_pacman(self.app_tree, self.base / "fakeapp-1.2.3-1-x86_64.pkg.tar.xz", "fakeapp",
                           install="post_install() {\n  ldconfig\n}\n", license="MIT")
        out = self.out_dir("pacman")
        code, log = run_cli("convert", str(pkg), "--app-id", "org.example.FakeArch",
                            "--runtime-index", str(self.index_path), "--deps-dir", str(self.rpms), "-o", str(out))
        self.assertEqual(code, 0, log)
        self.assertIn(".pacman", log)
        app = out / "app"
        self.assertFalse((app / "PKGINFO").exists() or (app / ".PKGINFO").exists())
        self.assert_runs(app, "opt/Fake/fakeapp")
        self.assertIn("<project_license>MIT</project_license>",
                      (app / "share/metainfo/org.example.FakeArch.metainfo.xml").read_text())
        with tempfile.TemporaryDirectory() as t:
            p = open_package(pkg, t)
            self.assertEqual((p.name, p.version, p.homepage), ("fakeapp", "1.2.3-1", "https://example.com/fakeapp"))
            self.assertIn("ldconfig", p.scripts["postinst"])

    # ------------------------------------------------------------------ vendor tarballs
    def tarball(self, name="Foo-2.4.1-linux-x86_64.tar.gz", top="Foo-2.4.1"):
        s = self.fx.src
        desktop = b"[Desktop Entry]\nType=Application\nName=Foo\nComment=Does foo\nExec=./foo %F\nIcon=foo\n"
        return build_tarball({"foo": s / "fakeapp", "libfake.so.1": s / "libfake.so.1.0.0",
                              "libfakedep.so.2": s / "libfakedep.so.2.0.0", "foo.desktop": desktop,
                              "foo.png": tiny_png(128), "README": b"hi"},
                             self.base / name, top, modes={"foo": 0o755})

    def test_tarball_without_an_icon_gets_a_placeholder(self):
        s = self.fx.src
        desktop = b"[Desktop Entry]\nType=Application\nName=Bar\nExec=./bar\nIcon=bar\n"
        tb = build_tarball({"bar": s / "fakeapp", "libfake.so.1": s / "libfake.so.1.0.0",
                            "libfakedep.so.2": s / "libfakedep.so.2.0.0", "bar.desktop": desktop},
                           self.base / "Bar-1.0-linux-x86_64.tar.gz", "Bar-1.0", modes={"bar": 0o755})
        out = self.out_dir("bar")
        code, log = run_cli("convert", str(tb), "--app-id", "org.example.Bar",
                            "--runtime-index", str(self.index_path), "-o", str(out))
        self.assertEqual(code, 0, log)
        self.assertIn("made a plain placeholder icon", log)
        self.assertTrue((out / "app/share/icons/hicolor/128x128/apps/org.example.Bar.png").is_file())

    def test_tarball_run_with_mono_gets_mono(self):
        # BizHawk ships EmuHawk.exe with EmuHawkMono.sh, which runs `mono EmuHawk.exe`; the runtime has no mono
        from debpak.pe_write import PeSpec, build_pe
        exe = build_pe(PeSpec(arch="i386", is_dll=False, dotnet=True, type_refs=[("System.IO", "File")],
                              imports={"mscoree.dll": ["_CorExeMain"]}))
        script = b'#!/bin/sh\ncd "$(dirname "$0")"\nexec mono EmuHawk.exe "$@"\n'
        tb = build_tarball({"EmuHawk.exe": exe, "EmuHawkMono.sh": script},
                           self.base / "BizHawk-2.10-linux-x64.tar.gz", None, modes={"EmuHawkMono.sh": 0o755})
        out = self.out_dir("mono")
        code, log = run_cli("convert", str(tb), "--app-id", "org.example.Hawk", "--no-build",
                            "--runtime-index", str(self.index_path), "-o", str(out))
        self.assertEqual(code, 0, log)
        m = json.loads((out / "org.example.Hawk.json").read_text())
        self.assertEqual(m["sdk-extensions"], ["org.freedesktop.Sdk.Extension.mono6"])
        self.assertIn("/usr/lib/sdk/mono6/install.sh $(ls /usr/lib/sdk/mono6/lib/mono/gac)",
                      m["modules"][0]["build-commands"])
        self.assertIn("/app/opt/bizhawk/EmuHawkMono.sh", (out / "app/bin/debpak-run").read_text())

    def test_tarball_inspect_and_convert(self):
        tb = self.tarball()
        with tempfile.TemporaryDirectory() as t:
            p = open_package(tb, t)
            self.assertEqual((p.format, p.name, p.version, p.default_exec), ("tarball", "foo", "2.4.1", "/opt/foo/foo"))
            desktop = (p.root / "usr/share/applications/foo.desktop").read_text()
            self.assertIn("Exec=/opt/foo/foo %F", desktop)
            self.assertTrue((p.root / "usr/share/icons/hicolor/128x128/apps/foo.png").is_file())
        out = self.out_dir("tarball")
        code, log = run_cli("convert", str(tb), "--app-id", "org.example.Foo",
                            "--runtime-index", str(self.index_path), "-o", str(out))
        self.assertEqual(code, 0, log)
        app = out / "app"
        self.assertIn("\n/app/opt/foo/foo", (app / "bin/debpak-run").read_text())
        self.assertIn("Exec=debpak-run %F", (app / "share/applications/org.example.Foo.desktop").read_text())
        run = subprocess.run([str(app / "opt/foo/foo")], capture_output=True, text=True,
                             env={**os.environ, "LD_LIBRARY_PATH": str(app / "opt/foo")})
        self.assertEqual(run.stdout.strip(), "fakeapp says 42 4")

    def test_tarball_entry_is_a_program_not_a_library(self):
        # Zen's tarball: libxul.so is executable and the largest file, and was taken for the
        # entry point (segfault); the name had no version, so it kept "linux-x86_64"
        s = self.fx.src
        big = (s / "libfake.so.1.0.0").read_bytes() + bytes(1 << 16)
        tb = build_tarball({"zen": s / "fakeapp", "zen-bin": s / "fakeapp", "libxul.so": big,
                            "libfake.so.1": s / "libfake.so.1.0.0", "glxtest": s / "fakeapp"},
                           self.base / "zen.linux-x86_64.tar.gz", "zen",
                           modes={"zen": 0o755, "zen-bin": 0o755, "libxul.so": 0o755, "glxtest": 0o755})
        with tempfile.TemporaryDirectory() as t:
            p = open_package(tb, t)
            self.assertEqual((p.name, p.version, p.default_exec), ("zen", "0", "/opt/zen/zen"))
        # with no program named like the app, the largest program, never a library
        tb = build_tarball({"run-me": s / "fakeapp", "libxul.so": big}, self.base / "Thing-2.0.tar.gz", "thing",
                           modes={"run-me": 0o755, "libxul.so": 0o755})
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(open_package(tb, t).default_exec, "/opt/thing/run-me")

    def test_tor_browser_style_tarball(self):
        # Mullvad Browser: the top level holds only start-mullvad-browser.desktop, a .desktop file that
        # is also a script ("#!/usr/bin/env ./Browser/execdesktop"); run as the entry point it failed:
        # "env: './Browser/execdesktop': No such file or directory"
        s = self.fx.src
        desktop = (b"#!/usr/bin/env ./Browser/execdesktop\n[Desktop Entry]\nType=Application\nName=Mullvad Browser\n"
                   b"Comment=Privacy browser\n"
                   b"Exec=sh -c '\"$(dirname \"$*\")\"/Browser/start-mullvad-browser' dummy %k\n"
                   b"X-MullvadBrowser-ExecShell=./Browser/start-mullvad-browser\nIcon=web-browser\n")
        start = (b'#!/usr/bin/env bash\ncd "$(dirname "$0")"\nHOME="${PWD}"\n./abicheck || exit 1\n'
                 b'exec ./mullvadbrowser "$@"\n')
        files = {"start-mullvad-browser.desktop": desktop, "Browser/start-mullvad-browser": start,
                 "Browser/execdesktop": b"#!/bin/sh\n",
                 "Browser/mullvadbrowser": (s / "fakeapp").read_bytes() + bytes(4096),
                 "Browser/abicheck": s / "fakeapp", "Browser/libxul.so": s / "libfake.so.1.0.0",
                 "Browser/libfakedep.so.2": s / "libfakedep.so.2.0.0"}
        modes = {n: 0o755 for n in files}
        tb = build_tarball(files, self.base / "mullvad-browser-linux-x86_64-16.0.2.tar.gz", "mullvad-browser",
                           modes=modes)
        with tempfile.TemporaryDirectory() as t:
            p = open_package(tb, t)
            self.assertEqual((p.name, p.version), ("mullvad-browser", "16.0.2"))
            # the browser itself: the script sets HOME to its own folder, read-only in a Flatpak
            self.assertEqual(p.default_exec, "/opt/mullvad-browser/Browser/mullvadbrowser")
            # and out of portable mode, so the profile isn't kept in the read-only bundle
            self.assertTrue((p.root / "opt/mullvad-browser/Browser/is-packaged-app").is_file())
            self.assertEqual(p.extra["marker"], "Browser/is-packaged-app")
            desktop_out = (p.root / "usr/share/applications/mullvad-browser.desktop").read_text()
            self.assertTrue(desktop_out.startswith("[Desktop Entry]"))
            self.assertIn("Exec=/opt/mullvad-browser/Browser/mullvadbrowser %k", desktop_out)
        # Mullvad Browser 16: mullvadbrowser is a wrapper script and mullvadbrowser.real the browser
        files16 = {**files, "Browser/mullvadbrowser": b'#!/bin/sh\nexec "$(dirname "$0")/mullvadbrowser.real" "$@"\n',
                   "Browser/mullvadbrowser.real": (s / "fakeapp").read_bytes() + bytes(4096)}
        (self.base / "mb16").mkdir()
        tb16 = build_tarball(files16, self.base / "mb16" / "mullvad-browser-linux-x86_64-16.0.2.tar.gz",
                             "mullvad-browser", modes={n: 0o755 for n in files16})
        with tempfile.TemporaryDirectory() as t:
            p = open_package(tb16, t)
            self.assertEqual(p.default_exec, "/opt/mullvad-browser/Browser/mullvadbrowser.real")
            self.assertEqual(p.extra["marker"], "Browser/is-packaged-app")
        out = self.out_dir("mullvad-extra")
        code, log = run_cli("convert", str(tb), "--app-id", "org.example.Mullvad", "--mode", "extra-data",
                            "--url", "https://example.com/mb.tar.gz", "--runtime-index", str(self.index_path),
                            "-o", str(out))
        self.assertEqual(code, 0, log)
        self.assertIn("touch opt/mullvad-browser/Browser/is-packaged-app\n", (out / "app/bin/apply_extra").read_text())

    def test_tarball_entry_point_from_its_desktop_file(self):
        # kitty's .txz has bin/kitty, a larger bin/kitten (its command-line twin) and
        # share/applications/kitty.desktop; the guess took kitten, which printed its usage
        s = self.fx.src
        big = (s / "fakeapp").read_bytes() + b"\0" * 65536
        desktop = b"[Desktop Entry]\nType=Application\nName=kitty\nTryExec=kitty\nExec=kitty\nIcon=kitty\n"
        opener = b"[Desktop Entry]\nType=Application\nName=kitty URL Launcher\nExec=kitten +open %U\n"
        tb = build_tarball({"bin/kitten": big, "bin/kitty": s / "fakeapp", "lib/kitty/README": b"x",
                            "share/applications/kitty-open.desktop": opener,
                            "share/applications/kitty.desktop": desktop,
                            "share/icons/hicolor/256x256/apps/kitty.png": tiny_png(256)},
                           self.base / "kitty-0.51.1-x86_64.txz", None,
                           modes={"bin/kitty": 0o755, "bin/kitten": 0o755})
        with tempfile.TemporaryDirectory() as t:
            p = open_package(tb, t)
            self.assertEqual((p.name, p.version, p.default_exec), ("kitty", "0.51.1", "/opt/kitty/bin/kitty"))
            self.assertIn("Exec=/opt/kitty/bin/kitty\n", (p.root / "usr/share/applications/kitty.desktop").read_text())
        code, log = run_cli("inspect", str(tb), "--runtime-index", str(self.index_path))
        self.assertIn("entry point:  opt/kitty/bin/kitty  [--exec]", log)

    def test_tarball_entry_point_without_a_desktop_file(self):
        s = self.fx.src
        big = (s / "fakeapp").read_bytes() + b"\0" * 65536
        # a program named like the archive beats a larger command-line twin
        tb = build_tarball({"bin/foo-cli": big, "bin/foo": s / "fakeapp"}, self.base / "Foo-3.0-linux.tar.gz",
                           "Foo-3.0", modes={"bin/foo": 0o755, "bin/foo-cli": 0o755})
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(open_package(tb, t).default_exec, "/opt/foo/bin/foo")
        # with no name to go by, helpers come after the app however large they are
        tb = build_tarball({"zed": s / "fakeapp", "zed_helper": big},
                           self.base / "Thing-1.1.tar.gz", "Thing-1.1", modes={"zed": 0o755, "zed_helper": 0o755})
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(open_package(tb, t).default_exec, "/opt/thing/zed")
        # Ventoy ships its program for four processors; the largest, for MIPS, can't run here
        prog = (s / "fakeapp").read_bytes()
        mips = prog[:18] + struct.pack("<H", 8) + prog[20:] + b"\0" * 65536
        tb = build_tarball({"VentoyGUI.x86_64": s / "fakeapp", "VentoyGUI.mips64el": mips},
                           self.base / "ventoy-1.1.10-linux.tar.gz", "ventoy-1.1.10",
                           modes={"VentoyGUI.x86_64": 0o755, "VentoyGUI.mips64el": 0o755})
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(open_package(tb, t).default_exec, "/opt/ventoy/VentoyGUI.x86_64")
        # REAPER's install script sits beside the folder holding the app, and waits for a key
        tb = build_tarball({"install-reaper.sh": b"#!/bin/sh\nread x\n", "REAPER/reaper": s / "fakeapp"},
                           self.base / "reaper786_linux_x86_64.tar.xz", "reaper_linux_x86_64",
                           modes={"install-reaper.sh": 0o755, "REAPER/reaper": 0o755})
        with tempfile.TemporaryDirectory() as t:
            self.assertTrue(open_package(tb, t).default_exec.endswith("/REAPER/reaper"))
        # WindTerm's archive carries no Unix modes: its program came out unexecutable
        z = self.base / "WindTerm_2.7.0_Linux_Portable_x86_64.zip"
        with zipfile.ZipFile(z, "w") as zf:
            info = zipfile.ZipInfo("WindTerm_2.7.0/WindTerm")
            info.create_system = 0
            zf.writestr(info, (s / "fakeapp").read_bytes())
            zf.writestr("WindTerm_2.7.0/readme.txt", "x")
        with tempfile.TemporaryDirectory() as t:
            p = open_package(z, t)
            self.assertTrue(os.access(p.root / "opt/windterm/WindTerm", os.X_OK))
            self.assertFalse(os.access(p.root / "opt/windterm/readme.txt", os.X_OK))
            self.assertEqual(p.default_exec, "/opt/windterm/WindTerm")
        # a bundled Java runtime has a folder named legal/java.desktop (PyCharm, Sparrow)
        tb = build_tarball({"bin/foo": s / "fakeapp", "jbr/legal/java.desktop/LICENSE": b"x"},
                           self.base / "Foo-3.1-linux.tar.gz", "Foo-3.1", modes={"bin/foo": 0o755})
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(open_package(tb, t).default_exec, "/opt/foo/bin/foo")

    def test_tarball_extra_data(self):
        tb = self.tarball("Bar-1.0.tar.gz", "Bar-1.0")
        out = self.out_dir("tarball-extra")
        code, log = run_cli("convert", str(tb), "--app-id", "org.example.Bar", "--mode", "extra-data",
                            "--url", "https://example.com/Bar-1.0.tar.gz",
                            "--runtime-index", str(self.index_path), "-o", str(out))
        self.assertEqual(code, 0, log)
        m = json.loads((out / "org.example.Bar.json").read_text())
        extra = next(s for s in m["modules"][0]["sources"] if s["type"] == "extra-data")
        self.assertEqual(extra["filename"], "bar.tar.gz")
        script = (out / "app/bin/apply_extra").read_text()
        self.assertIn("bsdtar -xf bar.tar.gz -C opt/bar --strip-components 1", script)
        self.assertIn("\n/app/extra/opt/bar/foo", (out / "app/bin/debpak-run").read_text())

    def test_rpm_extra_data(self):
        out = self.out_dir("rpm-extra")
        code, log = run_cli("convert", str(self.app_rpm), "--app-id", "org.example.FakeRpmX", "--mode", "extra-data",
                            "--url", "https://example.com/fakeapp.rpm", "--deps-dir", str(self.rpms),
                            "--runtime-index", str(self.index_path), "-o", str(out))
        self.assertEqual(code, 0, log)
        self.assertIn("bsdtar -xf fakeapp.rpm", (out / "app/bin/apply_extra").read_text())

    def test_haxe_game_starts_in_its_folder(self):
        # Psych Engine loads lime.ndll from the folder it's started in
        s = self.fx.src
        tb = build_tarball({"PsychEngine": s / "fakeapp", "lime.ndll": s / "libfake.so.1.0.0",
                            "libfake.so.1": s / "libfake.so.1.0.0", "libfakedep.so.2": s / "libfakedep.so.2.0.0"},
                           self.base / "PsychEngine-linux.zip.tar.gz", None, modes={"PsychEngine": 0o755})
        out = self.out_dir("haxe")
        code, log = run_cli("convert", str(tb), "--app-id", "org.example.Psych", "--no-build",
                            "--runtime-index", str(self.index_path), "-o", str(out))
        self.assertEqual(code, 0, log)
        self.assertIn("lime.ndll from the folder it's started in\n", (out / "app/bin/debpak-run").read_text())
        self.assertIn("\ncd /app/opt/", (out / "app/bin/debpak-run").read_text())

    def test_program_behind_a_start_script_gets_the_display(self):
        # Ren'Py's renpy.sh runs lib/py3-linux-x86_64/renpy, whose bundled SDL opens X11 itself
        s = self.fx.src
        prog = (s / "fakeapp").read_bytes() + b"\0libX11.so.6\0libwayland-client.so.0\0"
        script = b'#!/bin/sh\nBASE=renpy\nexec "$(dirname "$0")/lib/py3-linux-x86_64/$BASE" "$@"\n'
        tb = build_tarball({"renpy.sh": script, "lib/py3-linux-x86_64/renpy": prog,
                            "lib/py3-linux-x86_64/libfake.so.1": s / "libfake.so.1.0.0",
                            "lib/py3-linux-x86_64/libfakedep.so.2": s / "libfakedep.so.2.0.0"},
                           self.base / "renpy-8.6.1-sdk.tar.gz", "renpy-8.6.1-sdk",
                           modes={"renpy.sh": 0o755, "lib/py3-linux-x86_64/renpy": 0o755})
        out = self.out_dir("renpy")
        code, log = run_cli("convert", str(tb), "--app-id", "org.example.Renpy", "--no-build", "--exec",
                            "/opt/renpy/renpy.sh", "--runtime-index", str(self.index_path), "-o", str(out))
        self.assertEqual(code, 0, log)
        args = json.loads((out / "org.example.Renpy.json").read_text())["finish-args"]
        self.assertIn("--socket=x11", args)

    def test_zip_with_a_build_for_each_system_takes_the_linux_one(self):
        # SunVox's zip: sunvox/sunvox/{linux_x86_64,linux_arm64,macos/SunVox.app,windows}/...
        s = self.fx.src
        arm = bytearray((s / "fakeapp").read_bytes())
        arm[18:20] = (0xB7).to_bytes(2, "little")
        z = self.base / "sunvox-2.1.4d.zip"
        with zipfile.ZipFile(z, "w") as zf:
            for rel, data in {"sunvox/sunvox/linux_x86_64/sunvox": (s / "fakeapp").read_bytes(),
                              "sunvox/sunvox/linux_arm64/sunvox": bytes(arm),
                              "sunvox/sunvox/macos/SunVox.app/Contents/Info.plist": b"<plist/>",
                              "sunvox/sunvox/macos/SunVox.app/Contents/MacOS/SunVox": b"\xcf\xfa\xed\xfe",
                              "sunvox/sunvox/windows_x86_64/sunvox.exe": b"MZ",
                              "sunvox/examples/song.sunvox": b"x"}.items():
                info = zipfile.ZipInfo(rel)
                info.external_attr = 0o100755 << 16
                zf.writestr(info, data)
        self.assertEqual(detect_format(z), "tarball")
        with tempfile.TemporaryDirectory() as t:
            p = open_package(z, t)
            self.assertEqual(p.default_exec, "/opt/sunvox/sunvox/linux_x86_64/sunvox")

    def test_tarball_holding_only_an_appimage_converts_the_appimage(self):
        # Specter's tarball is Specter-2.3.0.AppImage and a folder of udev rules
        from debpak import packages
        img, _ = build_appimage(self.fx.src / "fakeapp", self.base / "inner.AppImage")
        tb = build_tarball({"Specter-2.3.0.AppImage": img, "udev/51-trezor.rules": b"SUBSYSTEM==usb\n",
                            "README.md": b"hi"}, self.base / "specter-v2.3.0-x86_64-linux-gnu.tar.gz", None,
                           modes={"Specter-2.3.0.AppImage": 0o755})
        seen = []

        def fake(path, dest, allow_run=False):
            seen.append(path.name)
            return packages.Package("appimage", path, dest, "specter", "2.3.0", "x86_64", "", default_exec="x")
        with tempfile.TemporaryDirectory() as t, mock.patch.object(packages, "extract_appimage", fake):
            p = open_package(tb, t)
        self.assertEqual(seen, ["Specter-2.3.0.AppImage"])
        self.assertEqual(p.extra["archive_member"], "Specter-2.3.0.AppImage")
        # beside a program of its own, the AppImage is just one of the files
        tb2 = build_tarball({"app.AppImage": img, "app": self.fx.src / "fakeapp"}, self.base / "app-1.0.tar.gz",
                            "app-1.0", modes={"app.AppImage": 0o755, "app": 0o755})
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(open_package(tb2, t).format, "tarball")

    # ------------------------------------------------------------------ AppImage
    def test_appimage(self):
        img, offset = build_appimage(self.fx.src / "fakeapp", self.base / "My_App-3.1-x86_64.AppImage")
        self.assertEqual(appimage_offset(img), offset)
        appdir = self.base / "appdir-src"
        (appdir / "usr/bin").mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.fx.src / "fakeapp", appdir / "usr/bin/myapp")
        (appdir / "AppRun").write_text('#!/bin/sh\nHERE="$(dirname "$(readlink -f "$0")")"\nexec "$HERE/usr/bin/myapp" "$@"\n')
        (appdir / "AppRun").chmod(0o755)
        # named after the app's ID, which it registers on D-Bus (Xournal++, Nextcloud), and with an
        # argument the program needs (Espanso's menu entry runs `espanso launcher`)
        (appdir / "io.example.MyApp.desktop").write_text(
            "[Desktop Entry]\nType=Application\nName=My App\nExec=myapp --no-sandbox launcher %U\n"
            "Icon=myapp\nComment=A test app\nX-AppImage-Version=3.1.0\n")
        (appdir / "myapp.png").write_bytes(tiny_png(64))
        (appdir / ".DirIcon").symlink_to("myapp.png")
        # appimage-builder's AppRun runs programs through the system's loader by this link
        (appdir / "runtime/default/lib64").mkdir(parents=True)
        (appdir / "runtime/default/lib64/ld-linux-x86-64.so.2").symlink_to("/lib64/ld-linux-x86-64.so.2")
        (appdir / "runtime/default/usr").symlink_to("../../usr")
        # Xournal++ bundles uim's GTK input module, which quits the app without /usr/share/uim
        (appdir / "usr/lib/gtk-3.0/3.0.0/immodules").mkdir(parents=True)
        (appdir / "usr/lib/gtk-3.0/3.0.0/immodules/im-uim.so").write_bytes(b"\x7fELF")
        (appdir / "usr/lib/gtk-3.0/3.0.0/immodules/im-ibus.so").write_bytes(b"\x7fELF")
        bindir = self.base / "fakebin"
        bindir.mkdir(exist_ok=True)
        log = self.base / "unsquashfs.args"
        # stand-in unsquashfs: records its arguments and "unpacks" the prepared AppDir to -d DEST
        (bindir / "unsquashfs").write_text(
            f'#!/bin/sh\necho "$@" > {log}\nwhile [ "$1" != "-d" ]; do shift; done\ncp -a {appdir} "$2"\n')
        (bindir / "unsquashfs").chmod(0o755)
        old = os.environ["PATH"]
        os.environ["PATH"] = f"{bindir}:{old}"
        try:
            with tempfile.TemporaryDirectory() as t:
                p = open_package(img, t)
                self.assertIn(f"-o {offset} ", log.read_text())
                self.assertEqual((p.format, p.name, p.version, p.pkg_arch), ("appimage", "my-app", "3.1.0", "x86_64"))
                self.assertIn("Exec=/opt/my-app/AppRun --no-sandbox launcher %U",
                              (p.root / "usr/share/applications/my-app.desktop").read_text())
                self.assertTrue((p.root / "usr/share/icons/hicolor/64x64/apps/myapp.png").is_file())
            out = self.out_dir("appimage")
            code, text = run_cli("convert", str(img), "--app-id", "org.example.MyApp",
                                 "--runtime-index", str(self.index_path), "--deps-dir", str(self.rpms), "-o", str(out))
            self.assertEqual(code, 0, text)
            wrapper = (out / "app/bin/debpak-run").read_text()
            self.assertIn('[ "$#" -gt 0 ] || set -- launcher\n/app/opt/my-app/AppRun "$@"', wrapper)
            self.assertIn("Exec=debpak-run launcher %U",
                          (out / "app/share/applications/org.example.MyApp.desktop").read_text())
            m = json.loads((out / "org.example.MyApp.json").read_text())
            self.assertIn("--own-name=io.example.MyApp", m["finish-args"])
            self.assertIn("export APPDIR=/app/opt/my-app\n", wrapper)
            # a link to a system file stays absolute; pointed into /app it led nowhere, and the
            # AppRun of LocalSend's and RustDesk's AppImages failed: "APPRUN_ERROR: No such file or directory"
            runtime = out / "app/opt/my-app/runtime/default"
            self.assertEqual(os.readlink(runtime / "lib64/ld-linux-x86-64.so.2"), "/lib64/ld-linux-x86-64.so.2")
            self.assertEqual(os.readlink(runtime / "usr"), "../../usr")
            mods = out / "app/opt/my-app/usr/lib/gtk-3.0/3.0.0/immodules"
            self.assertEqual(sorted(p.name for p in mods.iterdir()), ["im-ibus.so"])
            out2 = self.out_dir("appimage-extra")
            code, text = run_cli("convert", str(img), "--app-id", "org.example.MyApp2", "--mode", "extra-data",
                                 "--url", "https://example.com/My_App.AppImage", "--deps-dir", str(self.rpms),
                                 "--runtime-index", str(self.index_path), "-o", str(out2))
            self.assertEqual(code, 0, text)
            self.assertIn("export APPDIR=/app/extra/opt/my-app\n", (out2 / "app/bin/debpak-run").read_text())
            script = (out2 / "app/bin/apply_extra").read_text()
            self.assertIn("./my-app.AppImage --appimage-extract", script)
            self.assertIn('mv "$(readlink -f squashfs-root)" opt/my-app && rm -f squashfs-root', script)
        finally:
            os.environ["PATH"] = old

    def test_appimage_without_the_marker(self):
        # Beeper 4.3's AppImage: a runtime without the "AI\x02" marker was taken for a plain program
        img, offset = build_appimage(self.fx.src / "fakeapp", self.base / "Beeper-4.3.340-x86_64.AppImage")
        data = bytearray(img.read_bytes())
        data[8:11] = b"\0\0\0"
        img.write_bytes(bytes(data))
        self.assertEqual(detect_format(img), "appimage")
        self.assertEqual(appimage_image(img), (offset, "squashfs"))
        # without the name, the image after the ELF's end tells
        bare = self.base / "beeper-download"
        bare.write_bytes(bytes(data))
        self.assertEqual(detect_format(bare), "appimage")
        # an image placed a little after the ELF's end (aligned) is found by its superblock
        superblock = b"hsqs" + bytes(8) + struct.pack("<I", 131072) + bytes(6) + struct.pack("<H", 17) + \
            bytes(4) + struct.pack("<HH", 4, 0) + bytes(64)
        padded = self.base / "padded"
        padded.write_bytes(bytes(data[:offset]) + bytes(4096 - 7) + b"hsqs" + bytes(3) + superblock)
        self.assertEqual(detect_format(padded), "appimage")
        self.assertEqual(appimage_image(padded), (offset + 4096, "squashfs"))
        with self.assertRaises(PackageError):
            detect_format(self.fx.src / "fakeapp")        # a bare ELF program still isn't one

    def test_appimage_without_unsquashfs(self):
        img, _ = build_appimage(self.fx.src / "fakeapp", self.base / "NoTool.AppImage")
        old = os.environ["PATH"]
        os.environ["PATH"] = "/nonexistent"
        try:
            with tempfile.TemporaryDirectory() as t, self.assertRaises(PackageError) as cm:
                open_package(img, t)
        finally:
            os.environ["PATH"] = old
        self.assertIn("unsquashfs", str(cm.exception))
        self.assertIn("--allow-run", str(cm.exception))

    def _appdir(self) -> Path:
        appdir = self.base / "appdir-dwarfs"
        if not appdir.exists():
            (appdir / "usr/bin").mkdir(parents=True)
            shutil.copy2(self.fx.src / "fakeapp", appdir / "usr/bin/myapp")
            (appdir / "AppRun").write_text('#!/bin/sh\nexec "$(dirname "$0")/usr/bin/myapp" "$@"\n')
            (appdir / "AppRun").chmod(0o755)
            (appdir / "myapp.desktop").write_text("[Desktop Entry]\nType=Application\nName=My App\nExec=myapp\n"
                                                  "Icon=myapp\nX-AppImage-Version=3.1.0\n")
        return appdir

    def test_appimage_dwarfs(self):
        # VSCodium's "anylinux" AppImage: uruntime followed by a DwarFS image, not squashfs
        img, offset = build_appimage(self.fx.src / "fakeapp", self.base / "VSCodium-1.0-anylinux-x86_64.AppImage",
                                     image="dwarfs")
        self.assertEqual(appimage_image(img), (offset, "dwarfs"))
        slot, slot_offset = build_appimage(self.fx.src / "fakeapp", self.base / "Slot.AppImage", image="dwarfs-slot")
        self.assertEqual(appimage_image(slot), (slot_offset, "dwarfs"))      # not the metadata squashfs before it
        bindir = self.base / "fakebin-dwarfs"
        bindir.mkdir(exist_ok=True)
        log = self.base / "dwarfsextract.args"
        # stand-in dwarfsextract: records its arguments and "unpacks" the prepared AppDir into -o DIR
        (bindir / "dwarfsextract").write_text(
            f'#!/bin/sh\necho "$@" > {log}\nwhile [ "$1" != "-o" ]; do shift; done\n'
            f'[ -d "$2" ] || exit 1\ncp -a {self._appdir()}/. "$2"\n')
        (bindir / "dwarfsextract").chmod(0o755)
        old = os.environ["PATH"]
        os.environ["PATH"] = f"{bindir}:{old}"
        try:
            with tempfile.TemporaryDirectory() as t:
                p = open_package(img, t)
                self.assertIn(f"--image-offset={offset}", log.read_text())
                self.assertEqual((p.format, p.name, p.version), ("appimage", "my-app", "3.1.0"))
                self.assertTrue((p.root / "opt/my-app/usr/bin/myapp").is_file())
        finally:
            os.environ["PATH"] = old

    def _sharun_appdir(self) -> Path:
        """A small VSCodium-like sharun AppDir: AppRun, sharun and every program in bin are
        copies of the launcher, the real programs are in shared/bin."""
        appdir = self.base / "appdir-sharun"
        if appdir.exists():
            return appdir
        fakeapp = (self.fx.src / "fakeapp").read_bytes()
        static = self.base / "static-rg"
        (self.base / "rg.c").write_text("void _start(void) { __asm__(\"mov $60, %eax; xor %edi, %edi; syscall\"); }\n")
        subprocess.run(["gcc", "-static", "-nostdlib", "-o", str(static), str(self.base / "rg.c")], check=True)
        launcher = fakeapp + b"\0SHARUN_EXTRA_LIBRARY_PATH\0SHARUN_LDNAME\0LD_LIBRARY_PATH\0"
        (appdir / "bin/resources/app/node_modules/rg").mkdir(parents=True)
        (appdir / "shared/bin").mkdir(parents=True)
        (appdir / "lib").mkdir()
        (appdir / "usr/bin").mkdir(parents=True)
        (appdir / "shared/lib").symlink_to("../lib")
        (appdir / "sharun").write_bytes(launcher)
        (appdir / "sharun").chmod(0o755)
        os.link(appdir / "sharun", appdir / "AppRun")            # hard links, as lib4bin makes them
        os.link(appdir / "sharun", appdir / "bin/codium")
        os.link(appdir / "sharun", appdir / "bin/gio-launch-desktop")   # no real program for it
        os.link(appdir / "sharun", appdir / "usr/bin/tool")             # dynamic, outside Chromium's folder
        shutil.copy2(appdir / "sharun", appdir / "bin/chrome-sandbox")
        (appdir / "bin/rg").symlink_to("../sharun")
        shutil.copy2(appdir / "sharun", appdir / "bin/resources/app/node_modules/rg/rg")
        for name, data in (("codium", fakeapp + b"codium"), ("chrome-sandbox", fakeapp + b"sandbox"),
                           ("tool", fakeapp + b"tool"), ("rg", static.read_bytes())):
            (appdir / "shared/bin" / name).write_bytes(data)
            (appdir / "shared/bin" / name).chmod(0o755)
        for name in ("resources.pak", "v8_context_snapshot.bin", "icudtl.dat"):
            (appdir / "bin" / name).write_bytes(b"\0" * 16)
        shutil.copy2(self.fx.src / "libfake.so.1.0.0", appdir / "bin/libfake.so.1")
        # the bundled glibc, which must never go on LD_LIBRARY_PATH
        shutil.copy2(self.fx.src / "libfake.so.1.0.0", appdir / "lib/libfake.so.1")
        (appdir / "AppRun.sh").write_text("#!/bin/sh\nMAIN_BIN=codium\nexport LD_LIBRARY_PATH=$APPDIR/lib\n")
        (appdir / "codium.desktop").write_text("[Desktop Entry]\nType=Application\nName=VSCodium\n"
                                               "Exec=codium %F\nIcon=vscodium\nX-AppImage-Version=1.0\n")
        return appdir

    def test_sharun_appimage(self):
        # VSCodium's anylinux AppImage: AppRun is sharun's launcher, which runs hooks that
        # call `unshare -Urm` and fail in Flatpak; the Electron binary has to run under zypak
        img, _ = build_appimage(self.fx.src / "fakeapp", self.base / "VSCodium-1.0-anylinux-x86_64.AppImage")
        appdir = self._sharun_appdir()
        launcher = (appdir / "sharun").read_bytes()
        bindir = self.base / "fakebin-sharun"
        bindir.mkdir(exist_ok=True)
        (bindir / "unsquashfs").write_text(
            f'#!/bin/sh\nwhile [ "$1" != "-d" ]; do shift; done\ncp -a {appdir} "$2"\n')
        (bindir / "unsquashfs").chmod(0o755)
        old = os.environ["PATH"]
        os.environ["PATH"] = f"{bindir}:{old}"
        try:
            with tempfile.TemporaryDirectory() as t:
                p = open_package(img, t)
                opt = p.root / "opt/vscodium"
                self.assertTrue((opt / "bin/codium").read_bytes().endswith(b"codium"))
                self.assertTrue((opt / "bin/chrome-sandbox").read_bytes().endswith(b"sandbox"))
                self.assertFalse((opt / "bin/rg").is_symlink())
                for rg in ("bin/rg", "bin/resources/app/node_modules/rg/rg"):     # static: runs anywhere
                    self.assertEqual((opt / rg).read_bytes(), (self.base / "static-rg").read_bytes())
                # the launcher itself is untouched, though bin/codium was a hard link to it
                self.assertEqual((opt / "AppRun").read_bytes(), launcher)
                self.assertEqual((opt / "bin/gio-launch-desktop").read_bytes(), launcher)
                self.assertEqual((opt / "usr/bin/tool").read_bytes(), launcher)   # may need the bundled glibc
                self.assertTrue((opt / "shared/bin/tool").is_file())
                self.assertFalse((opt / "shared/bin/codium").exists())
                self.assertEqual(p.extra["sharun"], [
                    ("shared/bin/chrome-sandbox", ["bin/chrome-sandbox"]), ("shared/bin/codium", ["bin/codium"]),
                    ("shared/bin/rg", ["bin/resources/app/node_modules/rg/rg", "bin/rg"])])
            out = self.out_dir("sharun")
            code, text = run_cli("convert", str(img), "--app-id", "org.example.Codium", "--deps-dir", str(self.rpms),
                                 "--runtime-index", str(self.index_path), "-o", str(out))
            self.assertEqual(code, 0, text)
            wrapper = (out / "app/bin/debpak-run").read_text()
            self.assertIn("\nzypak-wrapper /app/opt/vscodium/bin/codium ", wrapper)
            self.assertNotIn("/app/opt/vscodium/lib", wrapper)
            out2 = self.out_dir("sharun-extra")
            code, text = run_cli("convert", str(img), "--app-id", "org.example.Codium2", "--mode", "extra-data",
                                 "--url", "https://example.com/VSCodium.AppImage", "--deps-dir", str(self.rpms),
                                 "--runtime-index", str(self.index_path), "-o", str(out2))
            self.assertEqual(code, 0, text)
            self.assertIn("\nzypak-wrapper /app/extra/opt/vscodium/bin/codium ",
                          (out2 / "app/bin/debpak-run").read_text())
            script = (out2 / "app/bin/apply_extra").read_text()
            self.assertIn("rm -f opt/vscodium/bin/codium\nmv opt/vscodium/shared/bin/codium opt/vscodium/bin/codium\n",
                          script)
            self.assertIn("rm -f opt/vscodium/bin/rg\ncp -p opt/vscodium/shared/bin/rg "
                          "opt/vscodium/bin/resources/app/node_modules/rg/rg\n"
                          "mv opt/vscodium/shared/bin/rg opt/vscodium/bin/rg\n", script)
            self.assertLess(script.index("--appimage-extract"), script.index("mv opt/vscodium/shared/bin/codium"))
        finally:
            os.environ["PATH"] = old

    def test_appimage_dwarfs_without_dwarfsextract(self):
        img, _ = build_appimage(self.fx.src / "fakeapp", self.base / "NoDwarfs.AppImage", image="dwarfs")
        old = os.environ["PATH"]
        os.environ["PATH"] = "/nonexistent"
        try:
            with tempfile.TemporaryDirectory() as t, self.assertRaises(PackageError) as cm:
                open_package(img, t)
        finally:
            os.environ["PATH"] = old
        self.assertIn("DwarFS", str(cm.exception))
        self.assertIn("dwarfsextract", str(cm.exception))
        self.assertIn("--allow-run", str(cm.exception))

    def test_appimage_dwarfs_unpacks_itself_with_allow_run(self):
        # uruntime's --appimage-extract unpacks into AppDir and leaves squashfs-root as a symlink to it
        img, _ = build_appimage(self.fx.src / "fakeapp", self.base / "SelfDwarfs.AppImage", image="dwarfs")
        appdir = self._appdir()

        def fake_run(cmd, cwd, **kw):
            shutil.copytree(appdir, Path(cwd) / "AppDir", symlinks=True)
            (Path(cwd) / "squashfs-root").symlink_to("AppDir")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        old = os.environ["PATH"]
        os.environ["PATH"] = "/nonexistent"
        try:
            with tempfile.TemporaryDirectory() as t, \
                    mock.patch("debpak.packages.subprocess.run", side_effect=fake_run):
                p = open_package(img, t, allow_run=True)
                self.assertTrue((p.root / "opt/my-app/AppRun").is_file())
                self.assertFalse((p.root / "opt/my-app").is_symlink())
                self.assertFalse((Path(t) / "squashfs-root").exists() or (Path(t) / "squashfs-root").is_symlink())
        finally:
            os.environ["PATH"] = old

    def test_appimage_without_an_image(self):
        img, offset = build_appimage(self.fx.src / "fakeapp", self.base / "Broken.AppImage")
        data = bytearray(img.read_bytes())
        data[offset:offset + 4] = b"junk"
        img.write_bytes(bytes(data))
        with self.assertRaises(PackageError) as cm:
            appimage_image(img)
        self.assertIn("no squashfs or DwarFS image", str(cm.exception))


class LicenseTests(unittest.TestCase):
    def test_spdx(self):
        self.assertEqual(spdx_license("MIT"), "MIT")
        self.assertEqual(spdx_license("GPL-2.0-or-later AND MIT"), "GPL-2.0-or-later AND MIT")
        self.assertIsNone(spdx_license("GPLv2+"))          # legacy RPM name
        self.assertIsNone(spdx_license("custom:Proprietary"))
        self.assertIsNone(spdx_license(""))


if __name__ == "__main__":
    unittest.main()
