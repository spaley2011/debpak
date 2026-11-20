"""A short, seeded fuzz run on every test run (tests/fuzz.py does long runs), and
regression tests for what fuzzing found."""
import json
import shutil
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

import fuzz
from debpak import asar, recipes, unpack, winres
from debpak.packages import PackageError, open_package


class FuzzRun(unittest.TestCase):
    def test_every_target(self):
        for name in fuzz.TARGETS:
            with self.subTest(target=name):
                self.assertEqual(fuzz.fuzz(name, 300, seed=1, log=lambda *a: None), [])


class Regressions(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="debpak-regress-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _asar_with_header(self, header: dict) -> Path:
        js = json.dumps(header).encode()
        padded = js + b"\0" * (-len(js) % 4)
        pickle = struct.pack("<II", 4 + len(padded), len(js)) + padded
        p = self.tmp / "app.asar"
        p.write_bytes(struct.pack("<II", 4, len(pickle)) + pickle + b"data")
        return p

    def test_asar_names_cant_climb_out(self):
        secret = self.tmp / "secret.txt"
        secret.write_text("host file")
        (self.tmp / "app.asar.unpacked").mkdir()
        p = self._asar_with_header({"files": {"..": {"files": {"secret.txt": {"size": 9, "unpacked": True}}}}})
        a = asar.Asar(p)
        with self.assertRaisesRegex(asar.AsarError, "unsafe entry"):
            list(a.walk())
        with self.assertRaises(asar.AsarError):
            a.read("../secret.txt")

    def test_asar_bad_numbers(self):
        a = asar.Asar(self._asar_with_header({"files": {"x": {"size": "10'", "offset": "0"},
                                                        "y": {"size": 1, "offset": "-5"}}}))
        for name in ("x", "y"):
            with self.assertRaises(asar.AsarError):
                a.read(name)
            self.assertEqual(a.head(name), b"")

    def test_unpack_plan_source_must_stay_in_its_folder(self):
        outside = self.tmp / "keep.zip"
        with zipfile.ZipFile(outside, "w") as z:
            z.writestr("x/a", "a")
        cwd = self.tmp / "extra"
        cwd.mkdir()
        for source in ("../keep.zip", "/etc/passwd", "", ".."):
            with self.subTest(source=source), self.assertRaises(unpack.UnpackError):
                unpack.apply({"source": source, "steps": [{"kind": "zip"}], "take": "x", "target": "t"}, cwd)
        self.assertTrue(outside.exists())          # not unpacked, and above all not deleted
        shutil.copy2(outside, cwd / "in.zip")
        with self.assertRaisesRegex(unpack.UnpackError, "working folder itself"):
            unpack.apply({"source": "in.zip", "steps": [{"kind": "zip"}], "take": "x", "target": "."}, cwd)

    def test_huge_icon_is_refused_not_allocated(self):
        dib = struct.pack("<IiiHH", 40, 0x7FFFFFFF, 0x7FFFFFFE, 1, 32) + bytes(64)
        with self.assertRaisesRegex(ValueError, "implausible icon size"):
            winres.dib_to_png(dib)

    def test_encrypted_and_damaged_archives_give_messages(self):
        z = self.tmp / "Acme-1.0.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("Acme/acme", "x")
        data = bytearray(z.read_bytes())
        data[6] |= 1                               # local header: encrypted flag
        cd = data.rfind(b"PK\x01\x02")
        data[cd + 8] |= 1                          # central directory: encrypted flag
        z.write_bytes(bytes(data))
        with self.assertRaisesRegex(PackageError, "encrypted"):
            open_package(z, self.tmp / "out")
        t = self.tmp / "Acme-1.0.tar.gz"
        t.write_bytes(b"\x1f\x8b\x08\x00" + bytes(40))
        with self.assertRaisesRegex(PackageError, "damaged"):
            open_package(t, self.tmp / "out2")

    def test_malformed_recipe(self):
        coll = self.tmp / "coll"
        (coll / "a.b.C").mkdir(parents=True)
        raw = json.dumps({"schema": 1, "id": "a.b.C", "files": "everything"}).encode()
        (coll / "a.b.C/recipe.json").write_bytes(raw)
        import hashlib
        with self.assertRaisesRegex(recipes.RecipeError, "malformed"):
            recipes.download(str(coll), {"id": "a.b.C", "recipe_sha256": hashlib.sha256(raw).hexdigest()},
                             self.tmp / "dl")


if __name__ == "__main__":
    unittest.main()
