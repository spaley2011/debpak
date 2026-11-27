import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from debpak import cli, quirks  # noqa: E402


class QuirksTests(unittest.TestCase):
    def run_convert(self, argv):
        seen = {}

        def fake(args):
            seen["args"] = args
            return 0
        with mock.patch.object(cli, "cmd_convert", fake), \
                mock.patch.object(quirks, "QUIRKS", [(r"^OmaWrite.*\.exe$", ["--exec", "OmaWrite.exe"], "test")]):
            cli.main(argv)
        return seen["args"]

    def test_an_apps_own_settings_are_added(self):
        self.assertEqual(self.run_convert(["convert", "/x/OmaWrite-1.2.exe"]).exec, "OmaWrite.exe")

    def test_the_users_options_still_win(self):
        args = self.run_convert(["convert", "/x/OmaWrite-1.2.exe", "--exec", "Other.exe"])
        self.assertEqual(args.exec, "Other.exe")

    def test_other_packages_and_no_quirks_are_left_alone(self):
        self.assertIsNone(self.run_convert(["convert", "/x/Else.exe"]).exec)
        self.assertIsNone(self.run_convert(["convert", "/x/OmaWrite-1.2.exe", "--no-quirks"]).exec)

    def test_prazycron_runs_its_commands_on_the_host(self):
        found = quirks.for_package("/x/prazycron_2.1.0_all.deb")
        self.assertEqual(len(found), 1)
        self.assertIn("crontab", found[0][0])
        self.assertEqual(found[0][0][found[0][0].index("crontab") - 1], "--host-command")


    def test_authenticatorchooser_runs_in_the_background(self):
        self.assertEqual(quirks.for_package("/d/AuthenticatorChooser-win-x64.zip")[0][0], ["--background"])
        with mock.patch.object(cli, "cmd_convert", lambda a: setattr(self, "seen", a) or 0):
            cli.main(["convert", "/d/AuthenticatorChooser-win-x64.zip"])
        self.assertTrue(self.seen.background)
        self.assertEqual(quirks.for_package("/d/Other-win-x64.zip"), [])
        self.assertEqual(quirks.for_package("/d/ibm-aspera-connect_4.2.15.870-HEAD_win32_AMD64.msi")[0][0],
                         ["--background"])

if __name__ == "__main__":
    unittest.main()
