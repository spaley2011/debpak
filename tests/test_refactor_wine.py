"""machgap scan on bad input."""
import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from debpak.cli_compat import machgap_main
from debpak.darling import index_darling_root


def run(fn, *argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = fn([str(a) for a in argv])
    return code, out.getvalue(), err.getvalue()


class MachgapTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.t = Path(self._t.name)
        (self.t / "empty").mkdir()
        index_darling_root(self.t / "empty").save(self.t / "d.json")

    def tearDown(self):
        self._t.cleanup()

    def test_zip_that_isnt_one(self):
        (self.t / "App.zip").write_text("not a zip")
        code, _, err = run(machgap_main, "scan", self.t / "App.zip", "--index", self.t / "d.json")
        self.assertEqual(code, 1)
        self.assertIn("can't read the zip", err)


if __name__ == "__main__":
    unittest.main()
