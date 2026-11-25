"""Tests for the Java runtime debpak adds to Java apps without one."""
import tempfile
import unittest
import zipfile
from pathlib import Path

from debpak import javart


def jar(path: Path, java: int) -> None:
    head = b"\xca\xfe\xba\xbe" + b"\x00\x00" + (java + 44).to_bytes(2, "big")
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        z.writestr("META-INF/versions/25/a/B.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x45")
        z.writestr("a/B.class", head + b"\x00" * 8)


class TestJava(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.root = Path(self.t.name)
        (self.root / "lib").mkdir()
        (self.root / "bin").mkdir()

    def tearDown(self):
        self.t.cleanup()

    def test_oldest_lts_that_runs_the_newest_jar(self):
        jar(self.root / "lib/old.jar", 8)
        jar(self.root / "lib/app.jar", 17)
        self.assertEqual(javart.needed_version(self.root), 17)
        s = javart.setup(self.root)
        self.assertEqual(s["extension"], "org.freedesktop.Sdk.Extension.openjdk17")
        self.assertIn("/usr/lib/sdk/openjdk17/installjdk.sh", s["commands"])
        self.assertEqual(s["env"]["JAVA_HOME"], "/app/jdk")

    def test_between_releases_and_past_the_last(self):
        self.assertEqual(javart.extension_for(12)[0], "org.freedesktop.Sdk.Extension.openjdk17")
        self.assertEqual(javart.extension_for(27)[0], "org.freedesktop.Sdk.Extension.openjdk")
        self.assertEqual(javart.extension_for(None)[0], "org.freedesktop.Sdk.Extension.openjdk21")

    def test_script_launcher_needs_one(self):
        jar(self.root / "lib/app.jar", 11)
        (self.root / "bin/app.sh").write_text("#!/bin/sh\nexec java -jar lib/app.jar\n")
        self.assertTrue(javart.needs_runtime(self.root, "java", {}, "bin/app.sh"))

    def test_bundled_java_needs_none(self):
        jar(self.root / "lib/app.jar", 11)
        self.assertFalse(javart.needs_runtime(self.root, "java", {"jre/bin/java": None}, "bin/app.sh"))

    def test_native_program_with_a_jar_needs_none(self):
        jar(self.root / "lib/plugin.jar", 11)
        (self.root / "bin/app").write_bytes(b"\x7fELF just a program")
        self.assertFalse(javart.needs_runtime(self.root, "elf", {"bin/app": None}, "bin/app"))

    def test_install4j_stub_needs_one(self):
        jar(self.root / "lib/app.jar", 11)
        (self.root / "bin/app").write_bytes(b"\x7fELF ... INSTALL4J_JAVA_HOME ...")
        self.assertTrue(javart.needs_runtime(self.root, "elf", {"bin/app": None}, "bin/app"))


if __name__ == "__main__":
    unittest.main()
