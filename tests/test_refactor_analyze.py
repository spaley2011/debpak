"""Behavior of analyze.py helpers split up to reduce complexity: results must stay what they were."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from debpak import analyze


def _write(root: Path, rel: str, text: str = "x", mode: int = 0o644) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    p.chmod(mode)


class RefactorAnalyzeTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_kde_runtime_for_qt(self):
        f = analyze.kde_runtime_for_qt
        self.assertIsNone(f({}))
        self.assertIsNone(f({"libQt6Core.so.6": {"Qt_6.5", "Qt_6"}}))
        self.assertEqual(f({"libQt6Core.so.6": {"Qt_6.11"}, "libQt5Core.so.5": {"Qt_6.99"}}), "org.kde.Platform//6.11")
        self.assertIsNone(f({"libQt6Core.so.6": {"Qt_6.12"}}))
        # private API wins over the public versions, and must match a runtime exactly
        self.assertEqual(f({"libQt6Gui.so.6": {"Qt_6.6_PRIVATE_API", "Qt_6.11"}}), "org.kde.Platform//6.6")
        self.assertIsNone(f({"libQt6Gui.so.6": {"Qt_6.5_PRIVATE_API"}}))

    def test_package_depends(self):
        pkg = SimpleNamespace(control={"Depends": "foo (>= 1), bar:any | baz, ", "Pre-Depends": "qux [amd64]"},
                              extra={"requires": ["libx.so()(64bit)", "ok+", "/bin/sh"]})
        self.assertEqual(analyze.package_depends(pkg), {"foo", "bar", "baz", "qux", "ok+"})
        self.assertEqual(analyze.package_depends(SimpleNamespace()), set())

    def test_script_desktop_entry(self):
        scripts = {"preinst": 'D="/opt/Money"\ncat <<EOF\n[Desktop Entry]\nName=Money\nExec=$D/run %U\nEOF\n',
                   "postinst": "[Desktop Entry]\nExec=$UNSET/run\n"}
        pkg = SimpleNamespace(maintainer_script=scripts.get)
        self.assertEqual(analyze.script_desktop_entry(pkg), "[Desktop Entry]\nName=Money\nExec=/opt/Money/run %U\n")
        pkg = SimpleNamespace(maintainer_script={"postinst": "[Desktop Entry]\nExec=$UNSET/run\n"}.get)
        self.assertIsNone(analyze.script_desktop_entry(pkg))

    def test_relative_reference(self):
        _write(self.root, "lib/app.jar")
        script = self.root / "start.sh"
        script.write_text("#!/bin/sh\n# lib/app.jar\ncurl http://x/lib/app.jar\njava -jar ../lib/app.jar\n"
                          "exec java -jar lib/app.jar\n")
        self.assertEqual(analyze.relative_reference(script), "lib/app.jar")
        script.write_text('#!/bin/sh\ncd "$(dirname "$0")"\nexec java -jar lib/app.jar\n')
        self.assertIsNone(analyze.relative_reference(script))

    def test_package_usr_prefix(self):
        _write(self.root, "usr/lib/beyondcompare/BCompare")
        _write(self.root, "usr/lib/x86_64-linux-gnu/libx.so")
        _write(self.root, "usr/local/bin/tool")
        f = analyze.package_usr_prefix
        self.assertEqual(f(self.root, "/usr/lib/beyondcompare/BCompare"), "/usr/lib/beyondcompare")
        self.assertEqual(f(self.root, "/usr/lib/x86_64-linux-gnu/libx.so"), "/usr/lib/x86_64-linux-gnu/libx.so")
        self.assertIsNone(f(self.root, "/usr/lib/x86_64-linux-gnu"))
        self.assertEqual(f(self.root, "/usr/local/bin/tool"), "/usr/local/bin/tool")
        self.assertIsNone(f(self.root, "/usr/bin/env"))
        self.assertIsNone(f(self.root, "/opt/x/y"))

    def test_only_program_on_path(self):
        _write(self.root, "opt/ms/pwsh", "#!/bin/sh\n", 0o755)
        (self.root / "usr/bin").mkdir(parents=True)
        (self.root / "usr/bin/pwsh").symlink_to("/opt/ms/pwsh")
        _write(self.root, "usr/bin/readme", "text")             # not runnable
        self.assertEqual(analyze.only_program_on_path(self.root), "opt/ms/pwsh")
        _write(self.root, "bin/other", "#!/bin/sh\n", 0o755)
        self.assertIsNone(analyze.only_program_on_path(self.root))

    def test_bus_names(self):
        _write(self.root, "usr/bin/app", "#!/bin/sh\n", 0o755)
        _write(self.root, "usr/share/applications/org.example.App.desktop",
               "[Desktop Entry]\nIcon=org.example.Icon\nX-DBUS-ServiceName=org.kde.app\n")
        _write(self.root, "usr/share/metainfo/a.xml", "<component><id> io.example.Meta.desktop </id></component>")
        _write(self.root, "usr/share/dbus-1/services/x.service", "[D-BUS Service]\nName=net.example.Svc\nExec=/usr/bin/app\n")
        _write(self.root, "usr/share/dbus-1/services/y.service", "[D-BUS Service]\nName=net.example.No\nExec=/usr/bin/no\n")
        _write(self.root, "usr/share/dbus-1/services/z.service",
               "[D-BUS Service]\nName=org.freedesktop.Notifications\nExec=/usr/bin/app\n")
        _write(self.root, "etc/xdg/autostart/org.etc.App.desktop", "[Desktop Entry]\n")
        self.assertEqual(analyze.bus_names(self.root), {
            "io.example.Meta": "AppStream ID (usr/share/metainfo/a.xml)",
            "net.example.Svc": "D-Bus service file usr/share/dbus-1/services/x.service",
            "org.example.App": "desktop file ID (usr/share/applications/org.example.App.desktop)",
            "org.example.Icon": "Icon= in usr/share/applications/org.example.App.desktop",
            "org.kde.app": "X-DBUS-ServiceName= in usr/share/applications/org.example.App.desktop",
        })

    def test_privileged_parts(self):
        _write(self.root, "usr/bin/netbird-ui", "...unix:///var/run/netbird.sock...")
        pkg = SimpleNamespace(name="netbird-ui", control={"Depends": "libfoo"}, extra={})
        found = analyze.privileged_parts(pkg, self.root, ["usr/bin/netbird-ui", "usr/bin/missing"])
        self.assertEqual([(f.category, f.where) for f in found], [("blocker", "usr/bin/netbird-ui")])
        self.assertIn("talks to netbird through unix:///var/run/netbird.sock", found[0].detail)
        # a mount helper, and a package it fronts: the socket isn't looked at then
        _write(self.root, "sbin/mount.app")
        _write(self.root, "usr/sbin/mount.zzz")
        pkg = SimpleNamespace(name="netbird-ui", control={"Depends": "netbird"}, extra={})
        found = analyze.privileged_parts(pkg, self.root, ["usr/bin/netbird-ui"])
        self.assertEqual([(f.category, f.where) for f in found],
                         [("blocker", "sbin/mount.app"), ("blocker", "Depends: netbird")])


if __name__ == "__main__":
    unittest.main()
