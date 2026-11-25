"""Native Linux packages (.deb, .rpm, AppImage) that were refused, crashed or showed nothing."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from debpak.analyze import (analyze, built_for_musl, package_depends, parse_exec, scan_hardcoded,
                            script_desktop_entry)
from debpak.elf import ElfInfo
from debpak.maintscripts import analyze_scripts, fronts_daemon
from debpak.packages import Package
from debpak.selfcheck import Observation, apply, diagnose


def write(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)


def package(root: Path, name: str, scripts=None, fmt="rpm", requires=()) -> Package:
    pkg = Package(fmt, root / f"{name}.{fmt}", root, name, "1.0", "x86_64", scripts=dict(scripts or {}))
    pkg.extra["requires"] = list(requires)
    return pkg


class ServiceTests(unittest.TestCase):
    def test_removal_scripts_alone_dont_refuse(self):
        # LieNetwork's RPM: only %postun touches systemd, refused as "installs/starts a system service"
        (f,) = analyze_scripts({"postrm": "systemctl daemon-reload\n"})
        self.assertEqual(f.category, "warn")
        self.assertIn("only on removal", f.detail)
        found = analyze_scripts({"postinst": "systemctl enable --now x.service\n", "prerm": "systemctl stop x\n"})
        self.assertEqual({f.category for f in found}, {"blocker"})

    def test_front_end_names(self):
        for gui, daemon in (("teamviewer", "teamviewerd"), ("netbird-ui", "netbird"), ("foo", "foo-daemon")):
            self.assertTrue(fronts_daemon(gui, daemon), (gui, daemon))
        for gui, daemon in (("rudesktop", "rudesktop"), ("teleport-connect", "tsh"), ("selfservice", "ctxlogd"),
                            ("rudesktop", "ru")):
            self.assertFalse(fronts_daemon(gui, daemon), (gui, daemon))

    def gui_with_service(self, root: Path, daemon: str) -> Package:
        write(root / "usr/share/applications/rudesk.desktop", "[Desktop Entry]\nType=Application\nName=RuDesk\n"
                                                              "Exec=/usr/bin/rudesk %u\n")
        write(root / "usr/bin/rudesk", "#!/bin/sh\nexec true\n", 0o755)
        if daemon != "rudesk":
            write(root / f"usr/bin/{daemon}", "#!/bin/sh\nexec true\n", 0o755)
        write(root / "usr/share/rudesk/files/rudesk.service",
              f"[Unit]\nDescription=x\n\n[Service]\nExecStart=/usr/bin/{daemon} --service\n\n"
              "[Install]\nWantedBy=multi-user.target\n")
        return package(root, "rudesk", {"postinst": "#!/bin/sh\nsystemctl enable --now rudesk.service\n"})

    def test_gui_converts_without_its_service(self):
        # RuDesktop (its own program as a service), Teleport Connect (a VNet daemon), Citrix (logging)
        with tempfile.TemporaryDirectory() as t:
            a = analyze(self.gui_with_service(Path(t), "rudesk"))
            self.assertEqual(a.blockers, [])
            note = [f for f in a.findings if "left out: a Flatpak can't run them" in f.detail]
            self.assertEqual(len(note), 1, a.findings)
            self.assertIn("rudesk.service", note[0].detail)

    def test_front_end_of_its_daemon_stays_refused(self):
        # TeamViewer: teamviewer is nothing without teamviewerd
        with tempfile.TemporaryDirectory() as t:
            a = analyze(self.gui_with_service(Path(t), "rudeskd"))
            self.assertTrue(any("system service" in b for b in a.blockers), a.blockers)

    def test_front_end_of_another_package(self):
        # netbird-ui depends on netbird, the daemon, and talks to it at unix:///var/run/netbird.sock
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            write(root / "usr/share/applications/nb.desktop", "[Desktop Entry]\nName=NB\nExec=netbird-ui\n")
            write(root / "usr/bin/netbird-ui", "#!/bin/sh\n# daemon at unix:///var/run/netbird.socknetbird:x\n",
                  0o755)
            a = analyze(package(root, "netbird-ui", requires=["netbird", "libgtk-4.so.1()(64bit)"]))
            self.assertEqual(package_depends(a.pkg), {"netbird"})
            self.assertTrue(any("front end of netbird" in b for b in a.blockers), a.blockers)
            a = analyze(package(root, "netbird-ui"))
            self.assertTrue(any("unix:///var/run/netbird.sock" in b for b in a.blockers), a.blockers)
            a = analyze(package(root, "netbird-ui", requires=["netbird-common", "xdg-utils"]))
            self.assertTrue(any("netbird.sock" in b for b in a.blockers), a.blockers)

    def test_mount_helper_needs_root(self):
        # VeraCrypt converted and showed its window, but mounts with sudo, dmsetup and mount.veracrypt
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            write(root / "usr/share/applications/vc.desktop", "[Desktop Entry]\nName=VC\nExec=/usr/bin/vc %f\n")
            write(root / "usr/bin/vc", "#!/bin/sh\n", 0o755)
            write(root / "usr/sbin/mount.vc", "#!/bin/sh\n", 0o755)
            a = analyze(package(root, "vc"))
            self.assertTrue(any("mount helper" in b and "needs root" in b for b in a.blockers), a.blockers)


class EntryPointTests(unittest.TestCase):
    def test_menu_entry_runs_a_script_through_a_shell(self):
        # Angry IP Scanner: Exec=sh /usr/bin/ipscan; Moneydance: Exec=/bin/sh "/opt/Moneydance/Moneydance" %U
        self.assertEqual(parse_exec("sh /usr/bin/ipscan"), ({}, "/usr/bin/ipscan", []))
        self.assertEqual(parse_exec('/bin/sh "/opt/Moneydance/Moneydance" %U'), ({}, "/opt/Moneydance/Moneydance",
                                                                                ["%U"]))
        self.assertEqual(parse_exec("sh -c 'x y'"), ({}, "sh", ["-c", "x y"]))

    def test_menu_entry_written_by_postinst(self):
        # install4j's .deb: postinst writes the .desktop file; the entry point was the JDK's jspawnhelper
        postinst = ('#!/bin/sh\nI4J_INSTALL_LOCATION="/opt/Moneydance"\ncd "$I4J_INSTALL_LOCATION"\n'
                    'if [ "$1" = "configure" ]; then\n/bin/echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\n'
                    'Type=Application\nName=Moneydance\nExec=/bin/sh \\"$I4J_INSTALL_LOCATION/Moneydance\\" %U\n'
                    'Icon=$I4J_INSTALL_LOCATION/.install4j/Moneydance.png\n" > "$I4J_INSTALL_LOCATION/x.desktop"\nfi\n')
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            write(root / "opt/Moneydance/Moneydance", "#!/bin/sh\nexec java -jar x.jar\n", 0o755)
            write(root / "opt/Moneydance/jre/lib/jspawnhelper", "#!/bin/sh\n", 0o755)
            pkg = package(root, "moneydance", {"postinst": postinst}, fmt="deb")
            entry = script_desktop_entry(pkg)
            self.assertIn('Exec=/bin/sh "/opt/Moneydance/Moneydance" %U\n', entry)
            self.assertIn("Icon=/opt/Moneydance/.install4j/Moneydance.png\n", entry)
            a = analyze(pkg)
            self.assertEqual(a.main_exec, "opt/Moneydance/Moneydance")
            self.assertEqual(a.desktop_file, "usr/share/applications/moneydance.desktop")

    def test_launcher_script_without_its_x_bit(self):
        # TrueConf: Exec=trueconf runs opt/trueconf/client/trueconf, a 0644 script that sets the
        # library path; the largest program was started without it ("libopenvino.so: cannot open")
        from debpak.stage import stage
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"
            write(root / "usr/share/applications/trueconf.desktop", "[Desktop Entry]\nName=T\nExec=trueconf -- %u\n")
            write(root / "opt/trueconf/client/trueconf", "#!/bin/bash\nexec /opt/trueconf/client/TrueConf\n")
            a = analyze(package(root, "trueconf"))
            self.assertEqual(a.main_exec, "opt/trueconf/client/trueconf")
            out = Path(t) / "out"
            stage(a, out, "org.example.T", "org.freedesktop.Platform/x86_64/25.08", "bundle", [], {}, None)
            self.assertTrue(os.access(out / "app/opt/trueconf/client/trueconf", os.X_OK))

    def test_script_without_a_shebang(self):
        # Oracle SQL Developer's /usr/local/bin/sqldeveloper is just "/opt/sqldeveloper/sqldeveloper.sh"
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            write(root / "usr/local/bin/sqldeveloper", "/opt/sqldeveloper/sqldeveloper.sh\n", 0o755)
            write(root / "opt/sqldeveloper/sqldeveloper.sh", "#!/bin/bash\n", 0o755)
            hits = scan_hardcoded(root, {}, "sqldeveloper")
            self.assertIn(("usr/local/bin/sqldeveloper", "/opt/sqldeveloper/sqldeveloper.sh"),
                          [(h.file, h.path) for h in hits])

    def test_musl_builds_are_ignored(self):
        # Dev-Suite Dashboard was refused for libc.musl-x86_64.so.1, which a musl prebuild of a module needs
        self.assertTrue(built_for_musl(ElfInfo("x", "x86_64", 3, 64, needed=["libc.musl-x86_64.so.1"])))
        self.assertTrue(built_for_musl(ElfInfo("x", "x86_64", 2, 64, interp="/lib/ld-musl-x86_64.so.1")))
        self.assertFalse(built_for_musl(ElfInfo("x", "x86_64", 3, 64, needed=["libc.so.6"])))


class WrapperTests(unittest.TestCase):
    def analysis(self, root: Path, main: str, text: str):
        write(root / main, text, 0o755)
        write(root / "usr/share/applications/app.desktop", f"[Desktop Entry]\nName=A\nExec=/{main}\n")
        return analyze(package(root, "app"))

    def test_python_modules_of_the_package(self):
        # Ulauncher: "No module named 'ulauncher'", its modules being in /app/lib/python3/dist-packages
        from debpak.stage import wrapper_script
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "usr/lib/python3/dist-packages/ulauncher").mkdir(parents=True)
            a = self.analysis(root, "usr/bin/ulauncher", "#!/usr/bin/python3\nimport ulauncher\n")
            self.assertIn('export PYTHONPATH="/app/lib/python3/dist-packages${PYTHONPATH:+:$PYTHONPATH}"',
                          wrapper_script(a, "bundle", []))
            a = self.analysis(root, "usr/bin/ulauncher", "#!/bin/sh\nexec true\n")
            self.assertNotIn("PYTHONPATH", wrapper_script(a, "bundle", []))

    def test_fd_limit(self):
        # QDriverStation: "*** bit out of range 0 - FD_SETSIZE on fd_set ***: terminated"
        from debpak.stage import wrapper_script
        obs = Observation(False, 134, None, "*** bit out of range 0 - FD_SETSIZE on fd_set ***: terminated\n")
        (r,) = diagnose(obs, "elf", False, set()).remedies
        args = SimpleNamespace(fd_limit=None)
        apply(args, [r])
        self.assertEqual(args.fd_limit, 1024)
        with tempfile.TemporaryDirectory() as t:
            a = self.analysis(Path(t), "usr/bin/qds", "#!/bin/sh\n")
            a.fd_limit = 1024
            self.assertIn("ulimit -Sn 1024 2>/dev/null\n", wrapper_script(a, "bundle", []))

    def test_missing_library_of_a_module(self):
        # Slic3r: "Can't load '.../OpenGL.so' for module OpenGL: libGLU.so.1: cannot open shared object file"
        obs = Observation(False, 2, None, "Can't load '/app/x/OpenGL.so' for module OpenGL: libGLU.so.1: cannot "
                                          "open shared object file: No such file or directory at DynaLoader.pm\n")
        self.assertEqual([r.key for r in diagnose(obs, "elf", False, set()).remedies], ["lib:libGLU.so.1"])

    def test_jpackage_settings_with_windows_line_ends(self):
        # YPtun: "Invalid maximum heap size: -Xmx512m", the option carrying the CR of a CR LF
        from debpak.stage import stage
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"
            write(root / "opt/yptun/lib/app/YPtun.cfg", "[Application]\r\napp.mainclass=MainKt\r\n\r\n"
                                                        "[JavaOptions]\r\njava-options=-Xmx512m\r\n")
            a = self.analysis(root, "opt/yptun/bin/YPtun", "#!/bin/sh\n")
            out = Path(t) / "out"
            res = stage(a, out, "org.example.Y", "org.freedesktop.Platform/x86_64/25.08", "bundle", [], {}, None)
            self.assertNotIn(b"\r", (out / "app/opt/yptun/lib/app/YPtun.cfg").read_bytes())
            self.assertTrue(any("YPtun.cfg" in n for n in res.notes), res.notes)


class SourceTests(unittest.TestCase):
    def test_debian_and_fedora_after_ubuntu(self):
        # libpython3.11.so.1.0 (Snapmaker Luban) is only Debian bookworm's; libpcap.so.1 (Sniffnet's RPM)
        # only Fedora's
        from debpak.resolve import MirrorSource, RpmRepoSource, default_sources
        srcs = default_sources("x86_64", "amd64")
        self.assertEqual([(type(s).__name__, getattr(s, "suite", "")) for s in srcs],
                         [("MirrorSource", "noble"), ("MirrorSource", "jammy"), ("MirrorSource", "focal"),
                          ("MirrorSource", "bookworm"), ("MirrorSource", "bullseye"), ("RpmRepoSource", "")])
        self.assertEqual(srcs[3].mirror, "http://deb.debian.org/debian")
        self.assertIn("/fedora/linux/releases/42/Everything/x86_64/os", srcs[-1].base)
        self.assertEqual(len(default_sources("arm", "armhf")), 5)


if __name__ == "__main__":
    unittest.main()


class PythonModuleTests(unittest.TestCase):
    def test_modules_and_toolkit_runtime(self):
        # dupeGuru's .deb: "No module named 'PyQt5'"; it depends on python3-pyqt5 and two pure-Python modules
        from debpak import pydeps
        deps = {"libc6", "python3", "python3-pyqt5", "python3-mutagen", "python3-semantic-version"}
        self.assertEqual(pydeps.wanted(deps), ["python3-mutagen", "python3-pyqt5", "python3-semantic-version"])
        self.assertEqual(pydeps.toolkit_runtime(pydeps.wanted(deps)), "kde5")
        self.assertEqual(pydeps.toolkit_runtime(["python3-gi", "python3-dbus"]), "gnome")
        self.assertIsNone(pydeps.toolkit_runtime(["python3-requests"]))
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            write(root / "usr/share/applications/dg.desktop", "[Desktop Entry]\nName=D\nExec=/usr/bin/dupeguru\n")
            write(root / "usr/bin/dupeguru", "#!/usr/bin/python3\nimport PyQt5\n", 0o755)
            pkg = package(root, "dupeguru", requires=["python3", "python3-pyqt5", "python3-mutagen"])
            a = analyze(pkg)
            self.assertEqual(a.python_modules, ["python3-mutagen", "python3-pyqt5"])
            self.assertEqual(a.runtime_suggestion, "org.kde.Platform//5.15-25.08")

    def test_fetch_follows_python_dependencies(self):
        from debpak import pydeps
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            debs = {}
            for name, files in (("python3-pyqt5", ["PyQt5/__init__.py"]), ("python3-pyqt5.sip", ["PyQt5/sip.py"])):
                r = t / name / "root"
                for f in files:
                    write(r / pydeps.SITE / f, "")
                debs[name] = SimpleNamespace(root=r, version="5.15")

            class Source:
                suite = "trixie"
                _packages = {"python3-pyqt5": {"Depends": "python3-pyqt5.sip (>= 4.19), libqt5core5t64, python3:any"},
                             "python3-pyqt5.sip": {"Depends": "libc6"}}

                def _package(self, name):
                    return debs.get(name)

            got = pydeps.fetch(["python3-pyqt5", "python3-gi"], Source(), t / "site", "gnome")
            self.assertEqual(sorted(got.packages), ["python3-pyqt5", "python3-pyqt5.sip"])
            self.assertEqual(got.missing, [])
            self.assertTrue((t / "site/PyQt5/sip.py").is_file())


class HelperGlibcTests(unittest.TestCase):
    def test_helper_needing_newer_glibc_does_not_refuse(self):
        # OpenWhispr's .deb: resources/bin/qdrant-linux-x64 needs GLIBC_2.43, which no runtime has
        from debpak.analyze import Analysis
        main = ElfInfo("opt/O/openwhispr", "x86_64", 3, 64, interp="/lib64/ld-linux-x86-64.so.2")
        helper = ElfInfo("opt/O/resources/bin/qdrant", "x86_64", 3, 64, interp="/lib64/ld-linux-x86-64.so.2")
        a = Analysis(pkg=SimpleNamespace(root=Path("/nonexistent")), arch="x86_64")
        a.elfs = {"opt/O/openwhispr": main, "opt/O/resources/bin/qdrant": helper, "opt/O/libx.so": ElfInfo(
            "opt/O/libx.so", "x86_64", 3, 64)}
        a.main_exec = "opt/O/openwhispr"
        a.version_problems = ["opt/O/resources/bin/qdrant needs libm.so.6 GLIBC_2.43 (not provided)"]
        self.assertEqual(a.blockers, [])
        a.version_problems.append("opt/O/openwhispr needs libc.so.6 GLIBC_2.43 (not provided)")
        a.version_problems.append("opt/O/libx.so needs libc.so.6 GLIBC_2.43 (not provided)")
        self.assertEqual(len(a.blockers), 2)


class PythonAbiTests(unittest.TestCase):
    def test_modules_for_another_python(self):
        # dupeGuru 4.3.1's own core/pe/_block.cpython-37m-x86_64-linux-gnu.so, for Python 3.7
        from debpak import pydeps
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            write(root / "usr/share/dupeguru/core/pe/_block.cpython-37m-x86_64-linux-gnu.so", "")
            self.assertEqual(pydeps.foreign_abi(root), ("usr/share/dupeguru/core/pe/_block.cpython-37m-x86_64-linux-gnu.so",
                                                        "3.7"))
            write(root / "usr/share/dupeguru/core/pe/_block.cpython-37m-x86_64-linux-gnu.so", "")
            (root / "usr/share/dupeguru/core/pe/_block.cpython-37m-x86_64-linux-gnu.so").rename(
                root / "usr/share/dupeguru/core/pe/_block.cpython-313-x86_64-linux-gnu.so")
            self.assertIsNone(pydeps.foreign_abi(root))
