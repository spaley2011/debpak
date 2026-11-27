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


class TestJavaFX(unittest.TestCase):
    """lunaticsmtp's .deb depends on openjfx and runs java --module-path /usr/share/openjfx/lib
    --add-modules javafx.controls,javafx.fxml,javafx.web; it stopped at "Module javafx.web not found"."""

    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.root = Path(self.t.name) / "root"
        (self.root / "usr/bin").mkdir(parents=True)
        (self.root / "usr/share/app").mkdir(parents=True)
        jar(self.root / "usr/share/app/app.jar", 17)

    def tearDown(self):
        self.t.cleanup()

    def test_what_says_an_app_uses_javafx(self):
        self.assertFalse(javart.needs_javafx(self.root, {"default-jre"}))
        self.assertTrue(javart.needs_javafx(self.root, {"default-jre", "openjfx"}))
        (self.root / "usr/bin/app").write_text("#! /usr/bin/env sh\njava --module-path /usr/share/openjfx/lib "
                                               "--add-modules javafx.controls -jar /usr/share/app/app.jar $@\n")
        self.assertTrue(javart.needs_javafx(self.root, set()))
        (self.root / "usr/bin/app").unlink()
        with zipfile.ZipFile(self.root / "usr/share/app/main.jar", "w") as z:
            z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nMain-Class: org.x.Main\n")
            z.writestr("org/x/Main.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x3d javafx/application/Application")
        self.assertTrue(javart.needs_javafx(self.root, set()))
        # an app that carries its own JavaFX needs none from Debian
        with zipfile.ZipFile(self.root / "usr/share/app/fat.jar", "w") as z:
            z.writestr("javafx/application/Application.class", b"")
        self.assertFalse(javart.needs_javafx(self.root, {"openjfx"}))

    def test_debians_javafx_in_the_sdks_layout(self):
        from types import SimpleNamespace
        deb = {}
        for name, files in (("libopenjfx-java", ["usr/share/java/javafx-web-11.jar",
                                                  "usr/share/java/javafx-base-11.jar"]),
                            ("libopenjfx-jni", ["usr/lib/x86_64-linux-gnu/jni/libjfxwebkit.so",
                                                "usr/lib/x86_64-linux-gnu/jni/libglassgtk2.so"])):
            r = Path(self.t.name) / name
            for f in files:
                (r / f).parent.mkdir(parents=True, exist_ok=True)
                (r / f).write_bytes(b"not an ELF")
            deb[name] = SimpleNamespace(root=r, version="11.0.11+1-7")
        (deb["libopenjfx-java"].root / "usr/share/java/javafx-web.jar").symlink_to("javafx-web-11.jar")

        class Source:
            suite = "trixie"

            def _package(self, name):
                return deb.get(name)
        dest = Path(self.t.name) / "javafx"
        missing, needed, version = javart.fetch_javafx(Source(), dest)
        self.assertEqual((missing, version), ([], "11.0.11+1-7 from trixie"))
        self.assertEqual(sorted(p.name for p in dest.iterdir()), ["javafx.base.jar", "javafx.web.jar",
                                                                    "libjfxwebkit.so"])

    def test_the_launcher_finds_it_in_app(self):
        import re as _re
        from types import SimpleNamespace
        from debpak.stage import _stage_javafx
        app = Path(self.t.name) / "app"
        (app / "bin").mkdir(parents=True)
        (app / "bin/lunaticsmtp").write_text("#! /usr/bin/env sh\n\njava --module-path /usr/share/openjfx/lib "
                                             "--add-modules javafx.controls,javafx.fxml,javafx.web -jar x.jar $@\n")
        fx = Path(self.t.name) / "javafx"
        fx.mkdir()
        (fx / "javafx.web.jar").write_bytes(b"")
        a = SimpleNamespace(javafx_dir=fx)
        env, res = {}, SimpleNamespace(notes=[])
        _stage_javafx(a, app, env, res)
        self.assertTrue((app / "share/openjfx/lib/javafx.web.jar").is_file())
        self.assertIn("--module-path /app/share/openjfx/lib ", (app / "bin/lunaticsmtp").read_text())
        self.assertEqual(env, {})
        # a launcher that names no JavaFX: java is given it through JDK_JAVA_OPTIONS
        (app / "bin/lunaticsmtp").write_text("#!/bin/sh\nexec java -jar x.jar\n")
        _stage_javafx(a, app, env, res)
        self.assertTrue(_re.match(r"--module-path=/app/share/openjfx/lib --add-modules=javafx\.base,",
                                  env["JDK_JAVA_OPTIONS"]))


if __name__ == "__main__":
    unittest.main()
