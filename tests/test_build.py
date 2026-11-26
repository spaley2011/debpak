"""Building: what debpak does when flatpak-builder fails."""
import tempfile
import unittest
from pathlib import Path


class TestComposeFallback(unittest.TestCase):
    def test_build_again_without_appstream(self):
        import json
        from unittest import mock
        from types import SimpleNamespace
        from debpak import cli
        with tempfile.TemporaryDirectory() as t:
            out = Path(t)
            manifest = out / "a.b.c.json"
            manifest.write_text(json.dumps({"id": "a.b.c"}))
            runs = iter([(1, "Error: ERROR: appstreamcli compose failed: Child process exited with code 1"), (0, ""),
                         (0, "")])
            args = SimpleNamespace(build=False, no_build=False)
            with mock.patch.object(cli, "_run_teed", side_effect=lambda cmd: next(runs)), \
                    mock.patch.object(cli.host, "which", return_value="/usr/bin/flatpak-builder"), \
                    mock.patch.object(cli.host, "sees", return_value=True), \
                    mock.patch("debpak.manage.record"):
                self.assertEqual(cli._build_install(args, None, "a.b.c", out, manifest), 0)
            self.assertIs(json.loads(manifest.read_text())["appstream-compose"], False)

    def test_install_again_when_its_remote_was_lost(self):
        # Dev Janitor and PDFelement, built while other conversions installed and uninstalled:
        # 'error: Remote "h_rpm_cocojojo5213_dev_janitor-origin" not found', three times over
        import json
        from unittest import mock
        from types import SimpleNamespace
        from debpak import cli
        with tempfile.TemporaryDirectory() as t:
            out = Path(t)
            manifest = out / "a.b.c.json"
            manifest.write_text(json.dumps({"id": "a.b.c"}))
            lost = 'error: Remote "c-origin" not found\nInstall failed: Child process exited with code 1\n'
            runs = iter([(0, ""), (1, lost), (0, "")])
            cmds = []
            args = SimpleNamespace(build=False, no_build=False)
            with mock.patch.object(cli, "_run_teed", side_effect=lambda cmd: cmds.append(cmd) or next(runs)), \
                    mock.patch.object(cli.host, "which", return_value="/usr/bin/flatpak-builder"), \
                    mock.patch.object(cli.host, "sees", return_value=True), \
                    mock.patch("time.sleep"), \
                    mock.patch("debpak.manage.registry_path", return_value=out / "debpak/apps.json"), \
                    mock.patch("debpak.manage.record"):
                self.assertEqual(cli._build_install(args, None, "a.b.c", out, manifest), 0)
            self.assertEqual([c[c.index("flatpak") if "flatpak" in c else 0:][:2] for c in cmds][1:],
                             [["flatpak", "install"]] * 2)
            self.assertNotIn("--install", cmds[0])
            self.assertTrue((out / "debpak/flatpak.lock").exists())
            # any other failure is the install's own and isn't repeated
            runs = iter([(0, ""), (1, "error: No space left on device\n")])
            cmds.clear()
            with mock.patch.object(cli, "_run_teed", side_effect=lambda cmd: cmds.append(cmd) or next(runs)), \
                    mock.patch.object(cli.host, "which", return_value="/usr/bin/flatpak-builder"), \
                    mock.patch.object(cli.host, "sees", return_value=True), \
                    mock.patch("debpak.manage.registry_path", return_value=out / "debpak/apps.json"):
                self.assertEqual(cli._build_install(args, None, "a.b.c", out, manifest), 1)
            self.assertEqual(len(cmds), 2)



class TestInstallerKind(unittest.TestCase):
    def test_installbuilder(self):
        from debpak import wineinstall
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "DeepSkyStacker-installer.exe"
            f.write_bytes(b"MZ" + bytes(4000) + b"BitRock InstallBuilder" + bytes(100))
            self.assertEqual(wineinstall.kind_of(f, None), "installbuilder")
            self.assertIn("unattended", wineinstall.SILENT["installbuilder"][0])


if __name__ == "__main__":
    unittest.main()
