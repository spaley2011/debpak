import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from debpak.analyze import analyze, parse_exec
from debpak.cli import main
from debpak.deb import extract, parse_control, read_ar
from debpak.desktop import rewrite_desktop
from debpak.elf import max_version, read_elf
from debpak.permissions import infer
from debpak.runtime import RuntimeIndex, index_root

from fixtures import Fixtures, have_toolchain
from isolate import offline


def run_cli(*argv):
    out = io.StringIO()
    with offline(), contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = main(list(argv))
    return code, out.getvalue()


class UnitTests(unittest.TestCase):
    def test_parse_control_continuation(self):
        c = parse_control("Package: x\nDescription: short\n long one\n .\n two\n")
        self.assertEqual(c["Package"], "x")
        self.assertEqual(c["Description"], "short\nlong one\n\ntwo")

    def test_apparmor_profile_is_not_a_service(self):
        # Cursor 3.31's postinst: Ubuntu loads a profile so Chromium's sandbox may use user namespaces
        from debpak.maintscripts import analyze_scripts
        cursor = ("#!/bin/sh\nset -e\nif command -v apparmor_parser >/dev/null 2>&1; then\n"
                  "\tif systemctl is-active --quiet apparmor 2>/dev/null; then\n"
                  "\t\tapparmor_parser -r /etc/apparmor.d/cursor-sandbox 2>/dev/null || true\n\tfi\nfi\n")
        found = analyze_scripts({"postinst": cursor, "prerm": cursor.replace("-r ", "-R ")})
        self.assertEqual({f.category for f in found}, {"ignore"})
        for service in ("systemctl enable --now svc.service", "systemctl --no-block restart svc",
                        "systemctl daemon-reload", "deb-systemd-invoke start svc"):
            self.assertIn("blocker", {f.category for f in analyze_scripts({"postinst": service})}, service)

    def test_parse_exec_env_and_args(self):
        env, prog, args = parse_exec('env A=1 B="x y" /opt/foo/bar --x "a b" %U')
        self.assertEqual(env, {"A": "1", "B": "x y"})
        self.assertEqual(prog, "/opt/foo/bar")
        self.assertEqual(args, ["--x", "a b", "%U"])

    def test_rewrite_desktop(self):
        text = "[Desktop Entry]\nName=X\nExec=env A=1 x --y \"a b\" %U\nTryExec=x\nIcon=x\n[Desktop Action n]\nExec=x --new\n"
        out = rewrite_desktop(text, "org.example.X", "debpak-run")
        self.assertIn('Exec=debpak-run --y "a b" %U', out)
        self.assertIn("Exec=debpak-run --new", out)
        self.assertIn("Icon=org.example.X", out)
        self.assertNotIn("TryExec", out)

    def test_elf_system_binary(self):
        info = read_elf("/bin/ls")
        self.assertTrue(info.is_executable)
        self.assertIn("libc.so.6", info.needed)
        self.assertIsNotNone(max_version(info.verneed["libc.so.6"], "GLIBC"))

    def test_permissions_heuristics(self):
        perms = {p.arg for p in infer({"libX11.so.6", "libasound.so.2", "libGL.so.1"}, {"getaddrinfo"}, "elf")}
        self.assertTrue({"--socket=x11", "--socket=pulseaudio", "--device=dri", "--share=network"} <= perms)
        self.assertNotIn("--filesystem=home", perms)
        perms = {p.arg for p in infer({"libwayland-client.so.0"}, set(), "elf")}
        self.assertIn("--socket=wayland", perms)
        self.assertIn("--socket=fallback-x11", perms)


@unittest.skipUnless(have_toolchain(), "needs gcc + dpkg-deb on x86_64")
class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="debpak-test-")
        cls.base = Path(cls._tmp.name)
        cls.fx = Fixtures(cls.base / "xz", compression="xz")
        cls.fx_zst = Fixtures(cls.base / "zst", compression="zstd")
        cls.index = index_root(cls.fx.runtime_root, "org.test.Platform/x86_64/1", "x86_64")
        cls.index_path = cls.base / "runtime.json"
        cls.index.save(cls.index_path)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def out_dir(self, name):
        return self.base / "out" / name

    # --- building blocks
    def test_ar_members(self):
        names = [m.name for m in read_ar(self.fx.app_deb)]
        self.assertEqual(names[0], "debian-binary")
        self.assertTrue(any(n.startswith("data.tar") for n in names))

    def test_zstd_extraction(self):
        with tempfile.TemporaryDirectory() as t:
            pkg = extract(self.fx_zst.app_deb, t)
            self.assertEqual(pkg.name, "fakeapp")
            self.assertTrue((pkg.root / "opt/Fake/fakeapp").is_file())

    def test_runtime_index(self):
        self.assertIn("libc.so.6", self.index.sonames)
        self.assertTrue(self.index.glibc.startswith("GLIBC_2."))
        self.assertTrue(self.index.provides("libGL.so.1"))  # GL extension
        self.assertFalse(self.index.provides("libfake.so.1"))
        again = RuntimeIndex.load(self.index_path)
        self.assertEqual(again.sonames, self.index.sonames)

    # --- analysis
    def test_analyze_app(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyze(extract(self.fx.app_deb, t), self.index)
            self.assertEqual(a.kind, "elf")
            self.assertEqual(a.main_exec, "opt/Fake/launch.sh")
            self.assertTrue(a.main_exec_is_script)
            self.assertEqual(a.desktop_exec_env, {"FAKE_MODE": "1"})
            self.assertEqual(a.missing_hard, {"libfake.so.1"})
            self.assertFalse(a.blockers)
            ignored = {f.detail for f in a.findings if f.category == "ignore"}
            self.assertIn("linker cache; Flatpak builds its own", ignored)
            self.assertFalse([f for f in a.findings if f.category in ("warn", "blocker")])
            self.assertTrue(any(h.is_text and h.path.startswith("/opt/Fake") for h in a.hardcoded))

    def test_glibc_mismatch_is_a_blocker(self):
        crippled = RuntimeIndex.from_json(self.index.to_json())
        crippled.verdefs["libc.so.6"] = ["GLIBC_2.2.5"]
        with tempfile.TemporaryDirectory() as t:
            a = analyze(extract(self.fx.app_deb, t), crippled)
            self.assertTrue(any("GLIBC_" in b for b in a.blockers))

    def test_inspect_cli(self):
        code, out = run_cli("inspect", str(self.fx.app_deb), "--runtime-index", str(self.index_path))
        self.assertEqual(code, 0, out)
        self.assertIn("libfake.so.1", out)
        self.assertIn("looks convertible", out)
        code, out = run_cli("inspect", str(self.fx.app_deb), "--json")
        self.assertEqual(json.loads(out)["entry_point"], "opt/Fake/launch.sh")

    # --- conversion
    def test_convert_bundle(self):
        out = self.out_dir("bundle")
        code, log = run_cli("convert", str(self.fx.app_deb), "--app-id", "org.example.FakeApp",
                            "--runtime-index", str(self.index_path), "--deps-dir", str(self.fx.deps),
                            "-o", str(out))
        self.assertEqual(code, 0, log)
        m = json.loads((out / "org.example.FakeApp.json").read_text())
        self.assertEqual(m["runtime"], "org.test.Platform")
        self.assertEqual(m["sdk"], "org.test.Sdk")
        self.assertEqual(m["command"], "debpak-run")
        self.assertIn("--share=network", m["finish-args"])  # socket() import
        self.assertEqual(set(m["x-debpak"]["bundled-libraries"]), {"libfake.so.1", "libfakedep.so.2"})

        app = out / "app"
        wrapper = (app / "bin/debpak-run").read_text()
        self.assertIn('LD_LIBRARY_PATH="/app/lib/debpak', wrapper)
        self.assertIn("export FAKE_MODE=1", wrapper)
        self.assertIn("exec /app/opt/Fake/launch.sh", wrapper)
        self.assertTrue(os.access(app / "bin/debpak-run", os.X_OK))

        launch = (app / "opt/Fake/launch.sh").read_text()
        self.assertIn("cd /app/opt/Fake", launch)
        self.assertIn("exec /app/opt/Fake/fakeapp", launch)

        desktop = (app / "share/applications/org.example.FakeApp.desktop").read_text()
        self.assertIn('Exec=debpak-run --flag "a b" %U', desktop)
        self.assertIn("Icon=org.example.FakeApp", desktop)
        self.assertTrue((app / "share/icons/hicolor/64x64/apps/org.example.FakeApp.png").is_file())
        self.assertIn("<id>org.example.FakeApp</id>",
                      (app / "share/metainfo/org.example.FakeApp.metainfo.xml").read_text())

        self.assertFalse((app / "etc/cron.daily").exists())
        self.assertFalse((app / "share/applications/fakeapp.desktop").exists())
        self.assertTrue((app / "share/doc/fakeapp/copyright").is_file())
        link = app / "bin/fakeapp"
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), "../opt/Fake/launch.sh")

        # the bundled closure actually satisfies the binary's dependencies
        run = subprocess.run([str(app / "opt/Fake/fakeapp")], capture_output=True, text=True,
                             env={**os.environ, "LD_LIBRARY_PATH": str(app / "lib/debpak")})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), "fakeapp says 42 4")

    def test_convert_extra_data(self):
        out = self.out_dir("extra")
        code, log = run_cli("convert", str(self.fx.app_deb), "--app-id", "org.example.FakeApp",
                            "--runtime-index", str(self.index_path), "--deps-dir", str(self.fx.deps),
                            "--mode", "extra-data", "--url", "https://example.com/fakeapp.deb", "-o", str(out))
        self.assertEqual(code, 0, log)
        m = json.loads((out / "org.example.FakeApp.json").read_text())
        extra = [s for s in m["modules"][0]["sources"] if s["type"] == "extra-data"][0]
        self.assertEqual(extra["size"], self.fx.app_deb.stat().st_size)
        self.assertEqual(len(extra["sha256"]), 64)
        app = out / "app"
        self.assertFalse((app / "opt").exists())  # vendor payload is NOT redistributed
        apply_extra = (app / "bin/apply_extra").read_text()
        self.assertIn("bsdtar -Oxf fakeapp.deb", apply_extra)
        self.assertIn("rm -rf etc/cron.daily", apply_extra)
        self.assertIn("/app/extra/opt/Fake", apply_extra)
        self.assertIn("exec /app/extra/opt/Fake/launch.sh", (app / "bin/debpak-run").read_text())

        # the generated sed program really rewrites the launcher
        with tempfile.TemporaryDirectory() as t:
            pkg = extract(self.fx.app_deb, t)
            sed_line = next(ln for ln in apply_extra.splitlines() if ln.startswith("sed -i"))
            subprocess.run(sed_line, shell=True, cwd=pkg.root, check=True)
            text = (pkg.root / "opt/Fake/launch.sh").read_text()
            self.assertIn("cd /app/extra/opt/Fake\n", text)
            self.assertIn("exec /app/extra/opt/Fake/fakeapp", text)

    def test_convert_without_deps_is_incomplete(self):
        code, log = run_cli("convert", str(self.fx.app_deb), "--runtime-index", str(self.index_path),
                            "-o", str(self.out_dir("nodeps")))
        self.assertEqual(code, 2)
        self.assertIn("INCOMPLETE", log)
        self.assertFalse((self.out_dir("nodeps")).exists())

    def test_service_is_blocked(self):
        code, log = run_cli("convert", str(self.fx.service_deb), "--runtime-index", str(self.index_path),
                            "--deps-dir", str(self.fx.deps), "-o", str(self.out_dir("svc")))
        self.assertEqual(code, 2)
        self.assertIn("NOT CONVERTIBLE", log)
        self.assertIn("system service", log)

    def test_electron(self):
        out = self.out_dir("electron")
        code, log = run_cli("convert", str(self.fx.electron_deb), "--app-id", "com.example.Zap",
                            "--runtime-index", str(self.index_path), "-o", str(out))
        self.assertEqual(code, 0, log)
        m = json.loads((out / "com.example.Zap.json").read_text())
        self.assertEqual(m["base"], "org.electronjs.Electron2.BaseApp")
        self.assertIn("--device=dri", m["finish-args"])
        self.assertIn("exec zypak-wrapper /app/opt/Zap/zap", (out / "app/bin/debpak-run").read_text())
        self.assertIn("setuid helper", log)

    def test_electron_behind_a_launcher_script(self):
        # Running the script would start Electron without zypak, and Chromium aborts on its sandbox
        out = self.out_dir("electron-script")
        code, log = run_cli("convert", str(self.fx.electron_script_deb), "--app-id", "com.example.Zap",
                            "--runtime-index", str(self.index_path), "-o", str(out))
        self.assertEqual(code, 0, log)
        self.assertIn("exec zypak-wrapper /app/opt/Zap/zap ", (out / "app/bin/debpak-run").read_text())
        self.assertIn("is a script, so the launcher runs the Electron binary", log)


if __name__ == "__main__":
    unittest.main()
