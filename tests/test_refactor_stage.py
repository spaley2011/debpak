"""Pin down edge cases of stage.py that the conversion tests don't reach."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from debpak.stage import _copy_payload


class LocalLinkTests(unittest.TestCase):
    def test_usr_local_link_onto_usr(self):
        # usr/local/lib -> ../lib: both are /app/lib, so the link would point at itself;
        # it used to stop the conversion (IsADirectoryError or FileExistsError, by walk order)
        real_walk = os.walk
        for reverse in (False, True):
            def walk(top, reverse=reverse, **kw):
                for d, dirs, files in real_walk(top, **kw):
                    dirs.sort(reverse=reverse)
                    yield d, dirs, files
            with self.subTest(reverse=reverse), tempfile.TemporaryDirectory() as t, \
                    mock.patch("os.walk", walk):
                root, dest = Path(t) / "root", Path(t) / "app"
                (root / "usr/lib").mkdir(parents=True)
                (root / "usr/lib/libfoo.so.1").write_text("x")
                (root / "usr/local").mkdir()
                (root / "usr/local/lib").symlink_to("../lib")
                (root / "usr/local/bin").mkdir()
                (root / "usr/local/bin/tool").symlink_to("/usr/local/lib/libfoo.so.1")
                _copy_payload(root, dest)
                self.assertTrue((dest / "lib").is_dir() and not (dest / "lib").is_symlink())
                self.assertEqual((dest / "lib/libfoo.so.1").read_text(), "x")
                self.assertEqual(os.readlink(dest / "bin/tool"), "../lib/libfoo.so.1")


if __name__ == "__main__":
    unittest.main()
