"""Conversion from .rpm, Arch packages, vendor tarballs and AppImages, using the
same compiled app and libraries as the .deb tests."""
import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from debpak.cli import main
from debpak.desktop import spdx_license
from debpak.packages import PackageError, appimage_offset, detect_format, open_package
from debpak.rpm import extract_rpm
from debpak.runtime import index_root

from fixtures import Fixtures, have_toolchain, tiny_png
from format_fixtures import build_appimage, build_pacman, build_rpm, build_tarball, rpm_repo


def run_cli(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
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
        self.assertIn("exec /app/opt/Fake/launch.sh", (app / "bin/debpak-run").read_text())
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
