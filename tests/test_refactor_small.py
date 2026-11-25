"""Edge cases of maintscripts, javart, monort and runtime that the complexity refactor kept as they were."""
import os
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path

from debpak import javart, maintscripts, monort
from debpak.pe_write import PeSpec, build_pe
from debpak.permissions import infer
from debpak.runtime import index_root


def jar(path: Path, java: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("a/A.class", b"\xca\xfe\xba\xbe\x00\x00" + (java + 44).to_bytes(2, "big"))


class TempRoot(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.root = Path(self.t.name)

    def tearDown(self):
        self.t.cleanup()

    def write(self, rel: str, text: str) -> Path:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p


class TestJarsAndAssemblies(TempRoot):
    def test_needed_version_reads_only_the_first_jars(self):
        jar(self.root / "a.jar", 11)
        jar(self.root / "b.jar", 21)
        (self.root / "c.jar").symlink_to(self.root / "b.jar")
        jar(self.root / "d.jar", 120)     # past 99: not a Java version
        self.assertEqual(javart.needed_version(self.root), 21)
        self.assertEqual(javart.needed_version(self.root, 1), 11)
        self.assertIsNone(javart.needed_version(self.root, 0))
        self.assertIsNone(javart.needed_version(self.root, -1))

    def test_assemblies_skip_links_and_native_files(self):
        dotnet = build_pe(PeSpec(arch="i386", dotnet=True, imports={"mscoree.dll": ["_CorExeMain"]}))
        (self.root / "A.exe").write_bytes(dotnet)
        (self.root / "B.DLL").write_bytes(dotnet)
        (self.root / "C.exe").write_bytes(b"MZ not a PE")
        (self.root / "D.exe").symlink_to(self.root / "A.exe")
        self.assertEqual([p.name for p in monort._assemblies(self.root)], ["A.exe", "B.DLL"])
        self.assertEqual([p.name for p in monort._assemblies(self.root, 1)], ["A.exe"])
        self.assertEqual(monort._assemblies(self.root, -1), [])


class TestUnits(TempRoot):
    def test_service_unit_kind(self):
        kind = maintscripts.service_unit_kind
        self.assertIsNone(kind(self.write("dbus.service", "[D-BUS Service]\nName=org.x\n")))
        self.assertEqual(kind(self.write("a.service", "[Service]\nUser=a\n[Install]\nWantedBy=default.target\n")),
                         "system")
        self.assertEqual(kind(self.write("b.service", "[Service]\n[Install]\nWantedBy=default.target\n")), "user")
        self.assertEqual(kind(self.write("c.service", "[Service]\n[Install]\nWantedBy=multi-user.target\n")),
                         "system")
        self.assertEqual(kind(self.write("d.service", "[Service]\nBusName=org.x\n")), "user")
        self.assertEqual(kind(self.write("e.service", "[Service]\nBusName=org.x\n[Install]\nWantedBy=a.target\n")),
                         "system")
        self.assertEqual(kind(self.write("systemd/user/f.service", "[Service]\n")), "user")
        self.assertIsNone(kind(self.write("big.service", "[Service]\n" + "#" * 70000)))
        self.assertIsNone(kind(self.root / "missing.service"))

    def test_payload_reports_each_kind_once_and_skips_leftover_units(self):
        self.write("lib/systemd/system/a.service", "[Service]\nExecStart=/opt/a/a\n")
        self.write("lib/systemd/system/b.service", "[Service]\nExecStart=/opt/a/b\n")
        self.write("opt/a/a", "")
        self.write("opt/a/script/ad.service", "[Service]\nExecStart=/opt/a/a\n[Install]\nWantedBy=multi-user.target\n")
        self.write("opt/a/script/getty.service", "[Service]\nExecStart=/sbin/agetty\n")
        self.write("opt/a/emergency.service", "[Service]\nExecStart=/opt/a/a\n")
        self.write("usr/share/doc/a/doc.service", "[Service]\nExecStart=/opt/a/a\n")
        got = [(f.category, f.where) for f in maintscripts.analyze_payload(self.root)]
        self.assertEqual(got, [("blocker", "lib/systemd/system/a.service"), ("blocker", "opt/a/script/ad.service")])
        got = [(f.category, f.where) for f in maintscripts.analyze_payload(self.root, units=False)]
        self.assertEqual(got, [("blocker", "lib/systemd/system/a.service")])
        self.assertEqual(maintscripts.system_services(self.root),
                         {"lib/systemd/system/a.service": "a", "lib/systemd/system/b.service": "b",
                          "opt/a/script/ad.service": "a"})

    def test_scripts_with_only_shell_syntax_get_no_warning(self):
        got = maintscripts.analyze_scripts({"postinst": "#!/bin/sh\nset -e\nif true; then\nfi\nexit 0\n",
                                            "prerm": "echo bye\n"})
        self.assertEqual([str(f) for f in got],
                         ["[warn] prerm: unrecognized maintainer script logic; review it manually"])


class TestPermissions(unittest.TestCase):
    def test_reasons_follow_the_first_that_applies(self):
        got = infer({"libnotify.so.4", "libsecret-1.so.0"}, {"_ZN15QSystemTrayIconC1Ev"}, "electron",
                    dlopened=frozenset({"libwayland-client.so.0"}))
        self.assertEqual([(p.arg, p.reason) for p in got if "talk-name" in p.arg], [
            ("--talk-name=org.freedesktop.Notifications", "Electron notifications"),
            ("--talk-name=org.kde.StatusNotifierWatcher", "tray icon support"),
            ("--talk-name=org.freedesktop.secrets", "links libsecret-1.so.0")])
        got = infer(set(), {"_ZN15QSystemTrayIconC1Ev"}, "native", dlopened=frozenset({"libwayland-client.so.0"}),
                    bus_clients=frozenset({"org.freedesktop.secrets"}))
        self.assertEqual([p.arg for p in got], [
            "--share=ipc", "--socket=wayland", "--socket=fallback-x11", "--talk-name=org.kde.StatusNotifierWatcher",
            "--talk-name=org.freedesktop.secrets", "--filesystem=xdg-download"])


@unittest.skipUnless(os.path.exists("/usr/lib/x86_64-linux-gnu/libc.so.6"), "needs an x86_64 libc")
class TestIndexRoot(TempRoot):
    def test_first_folder_wins_and_non_libraries_are_left_out(self):
        libc = Path("/usr/lib/x86_64-linux-gnu/libc.so.6")
        lib = self.root / "lib/x86_64-linux-gnu"
        lib.mkdir(parents=True)
        (self.root / "lib64").mkdir()
        shutil.copy(libc, lib / "libc.so.6")
        shutil.copy(libc, self.root / "lib64/libc.so.6")
        shutil.copy(libc, self.root / "lib64/libz.so.1")
        (lib / "libbroken.so.1").symlink_to("/nonexistent")
        (lib / "libtext.so").write_text("INPUT(-lc)")
        (lib / "README").write_bytes(libc.read_bytes())
        idx = index_root(self.root, "org.x/x86_64/1", "x86_64")
        self.assertEqual(idx.sonames, {"libc.so.6": "/usr/lib/x86_64-linux-gnu/libc.so.6",
                                       "libz.so.1": "/usr/lib64/libz.so.1"})
        self.assertTrue(idx.glibc.startswith("GLIBC_2."))
        self.assertEqual(index_root(self.root, "org.x/aarch64/1", "aarch64").sonames, {})


if __name__ == "__main__":
    unittest.main()
