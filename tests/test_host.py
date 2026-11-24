"""debpak running as a Flatpak: flatpak and flatpak-builder go through flatpak-spawn --host."""
import contextlib
import io
import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from debpak import cli, host


@contextlib.contextmanager
def sandbox(root: Path, spawn_rc: int = 0):
    """Pretend to run in a Flatpak, with a stand-in flatpak-spawn that logs its arguments to root/spawn.log."""
    info = root / "flatpak-info"
    info.write_text("[Application]\nname=io.github.spaley2011.debpak\n")
    bindir = root / "bin"
    bindir.mkdir(exist_ok=True)
    spawn = bindir / "flatpak-spawn"
    spawn.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{root}/spawn.log"\nexit {spawn_rc}\n')
    spawn.chmod(0o755)
    env = {"PATH": f"{bindir}:{os.environ.get('PATH', '')}", "HOME": str(root), "XDG_DATA_HOME": str(root / "data")}
    with mock.patch.object(host, "FLATPAK_INFO", str(info)), mock.patch.dict(host._found, clear=True), \
            mock.patch.dict(os.environ, env):
        yield root / "spawn.log"


class HostTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_outside_a_flatpak_commands_run_as_they_are(self):
        with mock.patch.object(host, "FLATPAK_INFO", str(self.tmp / "missing")):
            self.assertFalse(host.in_flatpak())
            self.assertEqual(host.command(["flatpak-builder", "--user", "b", "m.json"]),
                             ["flatpak-builder", "--user", "b", "m.json"])

    def test_in_a_flatpak_flatpak_tools_run_on_the_host(self):
        with sandbox(self.tmp):
            self.assertTrue(host.in_flatpak())
            self.assertEqual(host.command(["flatpak-builder", "--user", "--install", "b", "m.json"]),
                             ["flatpak-spawn", "--host", "flatpak-builder", "--user", "--install", "b", "m.json"])
            # a path found in the sandbox is run by name on the host
            self.assertEqual(host.command(["/usr/bin/flatpak", "info", "x"]),
                             ["flatpak-spawn", "--host", "flatpak", "info", "x"])
            # extraction tools are bundled in the sandbox and run there
            self.assertEqual(host.command(["7z", "x", "a.exe"]), ["7z", "x", "a.exe"])

    def test_which_asks_the_host_for_host_programs(self):
        with sandbox(self.tmp) as log:
            self.assertEqual(host.which("flatpak-builder"), "flatpak-builder")
            self.assertIn("--host sh -c", log.read_text())
            self.assertIn("flatpak-builder", log.read_text())
        with sandbox(self.tmp, spawn_rc=1):
            self.assertIsNone(host.which("flatpak-builder"))

    def test_build_goes_through_flatpak_spawn(self):
        out = self.tmp / "out"
        out.mkdir()
        manifest = out / "com.example.App.json"
        manifest.write_text("{}")
        args = types.SimpleNamespace(build=False, no_build=False, deb=str(self.tmp / "app.deb"))
        pkg = types.SimpleNamespace(format="deb", version="1.0", extra={})
        with sandbox(self.tmp) as log, contextlib.redirect_stdout(io.StringIO()) as printed:
            rc = cli._build_install(args, pkg, "com.example.App", out, manifest)
        self.assertEqual(rc, 0)
        lines = log.read_text().splitlines()
        self.assertEqual(lines[-1], f"--host flatpak-builder --user --install --force-clean "
                                    f"--install-deps-from=flathub {out / 'build-dir'} {manifest}")
        self.assertIn("Installed.", printed.getvalue())

    def test_build_refuses_an_output_folder_the_host_sees_elsewhere(self):
        out = Path(tempfile.mkdtemp())   # not under the sandbox's home (self.tmp)
        manifest = out / "com.example.App.json"
        manifest.write_text("{}")
        args = types.SimpleNamespace(build=False, no_build=False, deb=str(out / "app.deb"))
        with sandbox(self.tmp) as log, contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            rc = cli._build_install(args, None, "com.example.App", out, manifest)
        self.assertNotEqual(rc, 0)
        self.assertIn("outside your home folder", err.getvalue())
        self.assertNotIn("flatpak-builder --user", log.read_text())

    def test_desnap_refuses_in_a_flatpak(self):
        with sandbox(self.tmp), contextlib.redirect_stderr(io.StringIO()) as err:
            rc = cli.main(["desnap", "--dry-run"])
        self.assertNotEqual(rc, 0)
        self.assertIn("can't run from the debpak Flatpak", err.getvalue())

    def test_data_home_is_the_hosts_in_a_flatpak(self):
        with sandbox(self.tmp), mock.patch.dict(os.environ, {"HOST_XDG_DATA_HOME": "/home/u/.local/share"}):
            self.assertEqual(host.data_home(), "/home/u/.local/share")


if __name__ == "__main__":
    unittest.main()
