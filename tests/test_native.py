"""Native Linux packages (.deb, .rpm, AppImage) that were refused, crashed or showed nothing."""
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

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
        self.assertTrue(built_for_musl(ElfInfo("x.node", "x86_64", 3, 64, needed=["libstdc++.so.6", "libc.so"])))
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

    def test_gsettings_schemas_are_compiled(self):
        # GameHub: "Trace/breakpoint trap (core dumped)" at start, GLib's g_error for a settings schema that
        # was shipped as com.github.tkashkin.gamehub.gschema.xml but never compiled
        import json
        from debpak.stage import stage
        schema = ('<schemalist><schema id="com.example.gh" path="/com/example/gh/">'
                  '<key name="x" type="b"><default>true</default></key></schema></schemalist>\n')
        compile_step = ("glib-compile-schemas ${FLATPAK_DEST}/share/glib-2.0/schemas || "
                        "echo 'debpak: the GSettings schemas did not compile' >&2")
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"
            write(root / "usr/share/glib-2.0/schemas/com.example.gh.gschema.xml", schema)
            a = self.analysis(root, "usr/bin/gh", "#!/bin/sh\n")
            a.pkg.path.write_bytes(b"rpm")         # extra-data mode records its checksum
            for mode, url in (("bundle", None), ("extra-data", "https://example.com/gh.rpm")):
                out = Path(t) / mode
                res = stage(a, out, "org.example.G", "org.gnome.Platform/x86_64/49", mode, [], {}, None, url=url)
                cmds = json.loads(res.manifest_path.read_text())["modules"][0]["build-commands"]
                self.assertEqual(cmds[:3], ["cp -a . ${FLATPAK_DEST}/", "chmod +x ${FLATPAK_DEST}/bin/debpak-run",
                                            compile_step], mode)
                self.assertTrue((out / "app/share/glib-2.0/schemas/com.example.gh.gschema.xml").is_file(), mode)
            plain = Path(t) / "plain"
            a = self.analysis(plain, "usr/bin/gh", "#!/bin/sh\n")
            res = stage(a, Path(t) / "out-plain", "org.example.P", "org.gnome.Platform/x86_64/49", "bundle", [], {},
                        None)
            self.assertNotIn(compile_step, json.loads(res.manifest_path.read_text())["modules"][0]["build-commands"])


    def test_a_snaps_own_schemas_are_compiled_but_not_its_platform_copies(self):
        # GNOME Sudoku's snap: "Settings schema 'org.gnome.Sudoku' is not installed", its schemas in
        # share/glib-2.0/schemas of the snap, which goes under /app/opt
        from debpak.stage import gsettings_schemas, schema_commands
        schema = '<schemalist><schema id="{0}" path="/x/"/></schemalist>\n'
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"
            write(root / "share/glib-2.0/schemas/org.gnome.Sudoku.gschema.xml", schema.format("org.gnome.Sudoku"))
            write(root / "share/glib-2.0/schemas/org.gnome.desktop.interface.gschema.xml",
                  schema.format("org.gnome.desktop.interface"))
            write(root / "share/glib-2.0/schemas/gschemas.compiled", "")
            self.assertEqual([p.name for p in gsettings_schemas(root)], ["org.gnome.Sudoku.gschema.xml"])
            a = SimpleNamespace(root=root)
            app = Path(t) / "app"
            cmds = schema_commands(a, app, "bundle")
            self.assertTrue(cmds[0].startswith("glib-compile-schemas ${FLATPAK_DEST}/share/glib-2.0/schemas"))
            self.assertEqual(sorted(p.name for p in (app / "share/glib-2.0/schemas").iterdir()),
                             ["org.gnome.Sudoku.gschema.xml"])

    def test_a_schema_written_by_the_install_script_is_compiled(self):
        # gorsync's RPM (made with fpm) writes its schema from a here-document after installing; the
        # program crashed at start, its schema not installed
        from debpak.stage import stage
        script = ('#!/usr/bin/env sh\nget_schema()\n{\n    local EMBEDDED\n    EMBEDDED=$(cat << EndOfMsg\n'
                  '<?xml version="1.0" encoding="UTF-8"?>\n<schemalist gettext-domain="gorsync">\n'
                  '  <schema id="org.d2r2.gorsync" path="/org/d2r2/gorsync/">\n'
                  '    <key name="x" type="b"><default>true</default></key>\n  </schema>\n</schemalist>\n'
                  'EndOfMsg\n)\n}\nSCHEMA_PATH=${PREFIX}/share/glib-2.0/schemas\nglib-compile-schemas $SCHEMA_PATH\n'
                  'echo "<schemalist> broken"\n')
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"
            write(root / "usr/bin/gorsync", "#!/bin/sh\n", 0o755)
            write(root / "usr/share/applications/gorsync.desktop", "[Desktop Entry]\nName=G\nExec=gorsync\n")
            a = analyze(package(root, "gorsync", {"postinst": script}))
            made = root / "usr/share/glib-2.0/schemas/org.d2r2.gorsync.gschema.xml"
            self.assertTrue(made.is_file())
            self.assertIn('<schema id="org.d2r2.gorsync"', made.read_text())
            self.assertTrue(any("org.d2r2.gorsync.gschema.xml" in f.detail for f in a.findings))
            res = stage(a, Path(t) / "out", "org.example.G", "org.gnome.Platform/x86_64/49", "bundle", [], {}, None)
            import json
            cmds = json.loads(res.manifest_path.read_text())["modules"][0]["build-commands"]
            self.assertTrue(any(c.startswith("glib-compile-schemas") for c in cmds), cmds)
            # a schema the package ships itself stays as it is
            made.write_text("own")
            analyze(package(root, "gorsync", {"postinst": script}))
            self.assertEqual(made.read_text(), "own")


class SourceTests(unittest.TestCase):
    def test_debian_and_fedora_after_ubuntu(self):
        # libpython3.11.so.1.0 (Snapmaker Luban) is only Debian bookworm's; libpcap.so.1 (Sniffnet's RPM)
        # only Fedora's
        from debpak.resolve import default_sources
        srcs = default_sources("x86_64", "amd64")
        self.assertEqual([(type(s).__name__, getattr(s, "suite", "")) for s in srcs],
                         [("MirrorSource", "noble"), ("MirrorSource", "jammy"), ("MirrorSource", "focal"),
                          ("MirrorSource", "bookworm"), ("MirrorSource", "bullseye"), ("RpmRepoSource", ""),
                          ("MirrorSource", "trixie"), ("RpmRepoSource", "")])
        self.assertEqual(srcs[3].mirror, "http://deb.debian.org/debian")
        self.assertIn("/fedora/linux/releases/42/Everything/x86_64/os", srcs[-3].base)
        # libtinyxml2.so.11 (Besprited's tarball) is only in Debian's newest release, which comes last,
        # so what the others have still comes from them
        self.assertEqual(srcs[-2].mirror, "http://deb.debian.org/debian")
        # libicui18n.so.73 and libgettextlib-0.22.so (GSequencer's AppImage) are only Fedora 39's, after all
        self.assertIn("/fedora/linux/releases/39/Everything/x86_64/os", srcs[-1].base)
        self.assertEqual(len(default_sources("arm", "armhf")), 6)


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

    def test_python_of_the_release_for_its_modules(self):
        # dupeGuru 4.3.1's .deb has core.pe._block for Python 3.7 to 3.10 and none for 3.13: it gets
        # Ubuntu jammy's Python 3.10 and modules, and the launcher runs run.py with it
        from debpak import pydeps
        from debpak.stage import wrapper_script
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"
            for tag in ("37m", "38", "39", "310"):
                write(root / f"usr/share/dupeguru/core/pe/_block.cpython-{tag}-x86_64-linux-gnu.so", "")
            write(root / "usr/share/applications/dg.desktop", "[Desktop Entry]\nName=D\nExec=/usr/bin/dupeguru\n")
            write(root / "usr/bin/dupeguru", "#!/usr/bin/python3\nimport PyQt5\n", 0o755)
            self.assertEqual(pydeps.other_python(root), "3.10")
            self.assertEqual(pydeps.PYTHON_RELEASES["3.10"][:2], ("ubuntu", "jammy"))
            a = analyze(package(root, "dupeguru", requires=["python3", "python3-pyqt5"]))
            self.assertEqual(a.python_version, "3.10")
            self.assertEqual(a.blockers, [])
            a.python_home = Path(t) / "home"
            self.assertIn("/app/lib/debpak-python3.10/usr/bin/python3.10 /app/bin/dupeguru",
                          wrapper_script(a, "bundle", []).replace("/app/usr/bin/", "/app/bin/"))
            # with modules for the runtime's Python too, it needs nothing
            write(root / "usr/share/dupeguru/core/pe/_block.cpython-313-x86_64-linux-gnu.so", "")
            self.assertEqual(pydeps.other_python(root), "")
            # and none for a Python no release has
            other = Path(t) / "other"
            write(other / "m/_x.cpython-35m-x86_64-linux-gnu.so", "")
            self.assertEqual(pydeps.other_python(other), "")
            self.assertEqual(pydeps.foreign_abi(other)[1], "3.5")

    def test_fetch_interpreter(self):
        from debpak import pydeps
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            debs = {}
            for name, rel in (("python3.10-minimal", "usr/bin/python3.10"),
                              ("libpython3.10-minimal", "usr/lib/python3.10/os.py"),
                              ("libpython3.10-stdlib", "usr/lib/python3.10/json/__init__.py")):
                r = t / name / "root"
                write(r / rel, "")
                write(r / "usr/share/doc" / name / "copyright", "")
                debs[name] = SimpleNamespace(root=r, version="3.10.12")
            source = SimpleNamespace(_package=debs.get)
            missing, _needed = pydeps.fetch_interpreter("3.10", source, t / "home")
            self.assertEqual(missing, [])
            for rel in ("usr/bin/python3.10", "usr/lib/python3.10/os.py", "usr/lib/python3.10/json/__init__.py"):
                self.assertTrue((t / "home" / rel).is_file(), rel)
            self.assertFalse((t / "home/usr/share").exists())
            del debs["libpython3.10-stdlib"]
            self.assertEqual(pydeps.fetch_interpreter("3.10", source, t / "h2")[0], ["libpython3.10-stdlib"])


class WebEngineTests(unittest.TestCase):
    def test_webengine_brings_its_helper_and_data(self):
        # MindForger's RPM: "Could not find QtWebEngineProcess" with Ubuntu's libQt5WebEngineCore.so.5
        from debpak import resolve
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            lib = t / "core/root/usr/lib/x86_64-linux-gnu"
            write(lib / "libQt5WebEngineCore.so.5", "")
            write(lib / "qt5/libexec/QtWebEngineProcess", "")
            data = t / "data/root"
            write(data / "usr/share/qt5/resources/qtwebengine_resources.pak", "pak")
            write(data / "usr/share/qt5/translations/qtwebengine_locales/en-US.pak", "en")
            src = SimpleNamespace(_package=lambda name: SimpleNamespace(root=data) if name == "libqt5webengine-data"
                                  else None)
            found = resolve.Provided("libQt5WebEngineCore.so.5", lib / "libQt5WebEngineCore.so.5", "noble")
            staging = t / "staging"
            resolve._webengine_companions("libQt5WebEngineCore.so.5", found, src, staging)
            for f in ("libexec/QtWebEngineProcess", "resources/qtwebengine_resources.pak", "locales/en-US.pak"):
                self.assertTrue((staging / "qtwebengine" / f).is_file(), f)
            self.assertTrue(os.access(staging / "qtwebengine/libexec/QtWebEngineProcess", os.X_OK))


class JavaPromptTests(unittest.TestCase):
    def test_launcher_asking_for_a_jdk(self):
        # Oracle SQL Developer: a JNI library links GTK, so the package looked like a GTK app, not Java
        for text in ("Type the full pathname of a JDK installation (or Ctrl-C to quit), the path will be stored",
                     "You need Java/OpenJDK 25+ to run ipscan"):
            obs = Observation(False, 1, None, text)
            self.assertEqual([r.key for r in diagnose(obs, "gtk3", False, set()).remedies], ["java"])


class TypelibTests(unittest.TestCase):
    def test_typelibs_only_for_libraries_the_runtime_lacks(self):
        # Ulauncher depends on gir1.2-keybinder-3.0 (not in the GNOME runtime) and gir1.2-gtk-3.0 (in it)
        from debpak import pydeps
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            debs = {}
            for name, typelib, lib in (("gir1.2-keybinder-3.0", "Keybinder-3.0", "libkeybinder-3.0.so.0"),
                                       ("gir1.2-gtk-3.0", "Gtk-3.0", "libgtk-3.so.0")):
                r = t / name / "root"
                write(r / f"usr/lib/x86_64-linux-gnu/girepository-1.0/{typelib}.typelib", f"GOBJ\0{lib}\0")
                debs[name] = SimpleNamespace(root=r, version="1")

            class Source:
                suite = "trixie"
                _packages = {"gir1.2-keybinder-3.0": {"Depends": "gir1.2-gtk-3.0, libkeybinder-3.0-0"}}

                def _package(self, name):
                    return debs.get(name)

            self.assertEqual(pydeps.wanted({"gir1.2-keybinder-3.0", "python3-gi", "libgtk-3-0"}),
                             ["gir1.2-keybinder-3.0", "python3-gi"])
            got = pydeps.fetch(["gir1.2-keybinder-3.0"], Source(), t / "py/site", "gnome",
                               provides=lambda so: so == "libgtk-3.so.0")
            self.assertEqual(got.typelibs, ["Keybinder-3.0.typelib"])
            self.assertEqual(got.needed, {"libkeybinder-3.0.so.0"})
            self.assertTrue((t / "py/girepository-1.0/Keybinder-3.0.typelib").is_file())
            self.assertFalse((t / "py/girepository-1.0/Gtk-3.0.typelib").exists())


class SmallRemedyTests(unittest.TestCase):
    def test_library_looked_up_by_name(self):
        # Friture's AppImage: sounddevice's "OSError: PortAudio library not found"
        obs = Observation(False, 1, None, 'File "sounddevice.py", line 71\nOSError: PortAudio library not found\n')
        self.assertEqual([r.key for r in diagnose(obs, "elf", False, set()).remedies], ["lib:libportaudio.so.2"])

    def test_autostart_folder(self):
        # Coco AI panicked at start: "failed to fix inconsistent autostart state ... No such file or directory"
        from debpak.stage import wrapper_script
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            write(root / "usr/share/applications/coco.desktop", "[Desktop Entry]\nName=C\nExec=/usr/bin/coco\n")
            write(root / "usr/bin/coco", "#!/bin/sh\n# writes ~/.config/autostart/coco.desktop\n", 0o755)
            a = analyze(package(root, "coco"))
            self.assertFalse(a.autostart)       # a script names no program to look in
            a.autostart = True
            self.assertIn('mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/autostart" 2>/dev/null\n',
                          wrapper_script(a, "bundle", []))


class GoSignalStackTests(unittest.TestCase):
    """ProKZee, a Wails app: "signal 11 received but handler not on signal stack ... fatal error: non-Go code
    set up signal handler without SA_ONSTACK flag", WebKitGTK's JavaScriptCore having installed its SIGSEGV
    handler without SA_ONSTACK."""

    def wails_app(self, root: Path, go: bool = True, needed=("libwebkit2gtk-4.0.so.37", "libgtk-3.so.0")):
        from debpak.analyze import GO_BUILDINFO, go_webkit
        prog = "opt/prokzee/bin/ProKZee"
        write(root / prog, "\x7fELF...", 0o755)
        if go:
            with open(root / prog, "ab") as f:
                f.write(GO_BUILDINFO + b"\x08\x02github.com/wailsapp/wails/v2")
        info = ElfInfo(prog, "x86_64", 2, 64, interp="/lib64/ld-linux-x86-64.so.2", needed=list(needed))
        return go_webkit(root, {prog: info, "opt/prokzee/lib/libx.so": ElfInfo("x", "x86_64", 3, 64,
                                                                               needed=list(needed))})

    def test_go_programs_that_link_webkit(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(self.wails_app(Path(t) / "a"), "opt/prokzee/bin/ProKZee")
            self.assertEqual(self.wails_app(Path(t) / "b", needed=("libwebkitgtk-6.0.so.4",)),
                             "opt/prokzee/bin/ProKZee")
            self.assertEqual(self.wails_app(Path(t) / "c", go=False), "")          # a C or Rust (Tauri) program
            self.assertEqual(self.wails_app(Path(t) / "d", needed=("libgtk-3.so.0",)), "")   # Go without WebKit

    def test_launcher_preloads_the_shim_and_the_build_compiles_it(self):
        import json
        from debpak.stage import ONSTACK_SHIM, stage, wrapper_script
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"
            write(root / "usr/share/applications/p.desktop", "[Desktop Entry]\nName=P\nExec=/usr/bin/p\n")
            write(root / "usr/bin/p", "#!/bin/sh\n", 0o755)
            a = analyze(package(root, "p"))
            self.assertEqual(a.signal_onstack, "")
            self.assertNotIn("LD_PRELOAD", wrapper_script(a, "bundle", []))
            a.signal_onstack = "usr/bin/p is a Go program that links WebKitGTK"
            self.assertIn(f'export LD_PRELOAD="/app/lib/debpak/{ONSTACK_SHIM}${{LD_PRELOAD:+:$LD_PRELOAD}}"\n',
                          wrapper_script(a, "bundle", []))
            out = Path(t) / "out"
            res = stage(a, out, "org.example.P", "org.gnome.Platform/x86_64/49", "bundle", [], {}, None)
            cmds = json.loads(res.manifest_path.read_text())["modules"][0]["build-commands"]
            self.assertIn("cc -shared -fPIC -O2 -o ${FLATPAK_DEST}/lib/debpak/libdebpak-onstack.so "
                          "debpak-src/debpak-onstack.c -ldl", cmds)
            self.assertEqual(cmds[-1], "rm -rf ${FLATPAK_DEST}/debpak-src")
            self.assertIn("int sigaction(", (out / "app/debpak-src/debpak-onstack.c").read_text())

    def test_webkitgtk6_starts_its_web_process_without_its_own_sandbox(self):
        # YT-GO, a Wails 3 app: Flatpak's portal refused WebKitGTK 6.0's sandbox, whose bus name came from
        # the app's own ID ("Invalid sandbox a11y own name"), and the app stopped at a SIGTRAP
        from debpak.stage import stage
        for needed, expect in ((["libwebkitgtk-6.0.so.4"], True), (["libwebkit2gtk-4.1.so.0"], False)):
            with tempfile.TemporaryDirectory() as t:
                root = Path(t) / "root"
                write(root / "usr/share/applications/p.desktop", "[Desktop Entry]\nName=P\nExec=/usr/bin/p\n")
                write(root / "usr/bin/p", "#!/bin/sh\n", 0o755)
                a = analyze(package(root, "p"))
                a.elfs["usr/bin/q"] = ElfInfo("q", "x86_64", 2, 64, interp="/lib64/ld-linux-x86-64.so.2",
                                              needed=needed)
                out = Path(t) / "out"
                stage(a, out, "org.example.P", "org.gnome.Platform/x86_64/49", "bundle", [], {}, None)
                self.assertEqual("export WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=" in
                                 (out / "app/bin/debpak-run").read_text(), expect)

    def test_shim_adds_sa_onstack(self):
        import shutil
        import subprocess
        from debpak.stage import ONSTACK_SOURCE
        if not shutil.which("gcc"):
            self.skipTest("no gcc")
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            write(t / "shim.c", ONSTACK_SOURCE)
            write(t / "jsc.c", """#include <signal.h>
#include <stdio.h>
#include <string.h>
static void h(int s, siginfo_t *i, void *u) { (void)s; (void)i; (void)u; }
int main(void) {
    struct sigaction sa, q;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = h;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sa.sa_handler = SIG_DFL;
    sa.sa_flags = 0;
    sigaction(SIGUSR2, &sa, NULL);
    sigaction(SIGSEGV, NULL, &q);
    printf("%d", !!(q.sa_flags & SA_ONSTACK));
    sigaction(SIGUSR2, NULL, &q);
    printf("%d\\n", !!(q.sa_flags & SA_ONSTACK));
    return 0;
}
""")
            subprocess.run(["gcc", "-shared", "-fPIC", "-O2", "-o", str(t / "shim.so"), str(t / "shim.c"), "-ldl"],
                           check=True)
            subprocess.run(["gcc", "-o", str(t / "jsc"), str(t / "jsc.c")], check=True)
            run = lambda env: subprocess.run([str(t / "jsc")], env=env, capture_output=True, text=True).stdout
            self.assertEqual(run({}), "00\n")
            # a handler gets SA_ONSTACK; SIG_DFL is left as it was
            self.assertEqual(run({"LD_PRELOAD": str(t / "shim.so")}), "10\n")

    def test_a_qt_programs_own_copy_of_the_application_pointer_is_filled(self):
        # QPrompt's deb, built without -fPIC against Debian's Qt 6.8, holds its own copy of
        # QCoreApplication::self; the KDE runtime's libQt6Core sets only its own, libQt6Gui read the
        # empty copy, and the app crashed as its QApplication was made. Here a "Qt" bound to its own
        # variable (-Bsymbolic) and a "Gui" that reads it through the copy stand in for them
        import json
        import subprocess
        from debpak.analyze import qt_app_copy
        from debpak.elf import read_elf
        from debpak.stage import QT_SELF_SHIM, QT_SELF_SOURCE, stage, wrapper_script
        if not shutil.which("gcc"):
            self.skipTest("no gcc")
        self_sym = 'extern void *self_ __asm__("_ZN16QCoreApplication4selfE");\n'
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            write(t / "core.c", 'void *self_ __asm__("_ZN16QCoreApplication4selfE") = 0;\n'
                  'void make(void *o, int *c, char **v, int f) __asm__("_ZN12QApplicationC1ERiPPci");\n'
                  'void make(void *o, int *c, char **v, int f) { (void)c; (void)v; (void)f; self_ = o; }\n')
            write(t / "gui.c", self_sym + "void *gui_app(void) { return self_; }\n")
            write(t / "main.c", self_sym + 'void make(void *, int *, char **, int) __asm__("_ZN12QApplicationC1ERiPPci");\n'
                  "void *gui_app(void);\n"
                  "int main(void) { static char app[8]; int c = 0; make(app, &c, 0, 0);\n"
                  "  return gui_app() == app && self_ == app ? 0 : 1; }\n")
            write(t / "shim.c", QT_SELF_SOURCE)
            cc = lambda *args: subprocess.run(["gcc", "-O2", *map(str, args)], check=True)
            cc("-shared", "-fPIC", "-Wl,-Bsymbolic", "-Wl,-soname,libQt6Core.so.6", "-o", t / "libQt6Core.so.6",
               t / "core.c")
            cc("-shared", "-fPIC", "-o", t / "libgui.so", t / "gui.c", t / "libQt6Core.so.6")
            cc("-fPIE", "-pie", "-o", t / "app", t / "main.c", t / "libgui.so", t / "libQt6Core.so.6")
            cc("-shared", "-fPIC", "-o", t / "shim.so", t / "shim.c", "-ldl")
            run = lambda env: subprocess.run([str(t / "app")], env={"LD_LIBRARY_PATH": str(t), **env}).returncode
            self.assertEqual(run({}), 1)
            self.assertEqual(run({"LD_PRELOAD": str(t / "shim.so")}), 0)

            elfs = {"usr/bin/app": read_elf(t / "app"), "usr/lib/libQt6Core.so.6": read_elf(t / "libQt6Core.so.6")}
            self.assertTrue(elfs["usr/bin/app"].copies_qt_app)
            self.assertEqual(qt_app_copy(elfs, {}), "usr/bin/app")
            # a program that brings its own Qt has the Qt it was built with
            self.assertEqual(qt_app_copy(elfs, {"libQt6Core.so.6": "usr/lib/libQt6Core.so.6"}), "")

            root = t / "root"
            write(root / "usr/share/applications/p.desktop", "[Desktop Entry]\nName=P\nExec=/usr/bin/p\n")
            write(root / "usr/bin/p", "#!/bin/sh\n", 0o755)
            a = analyze(package(root, "p"))
            self.assertEqual(a.qt_app_copy, "")
            a.qt_app_copy, a.signal_onstack = "usr/bin/p", "usr/bin/p is a Go program that links WebKitGTK"
            self.assertIn(f'export LD_PRELOAD="/app/lib/debpak/{QT_SELF_SHIM}${{LD_PRELOAD:+:$LD_PRELOAD}}"\n',
                          wrapper_script(a, "bundle", []))
            res = stage(a, t / "out", "org.example.P", "org.kde.Platform/x86_64/6.10", "bundle", [], {}, None)
            cmds = json.loads(res.manifest_path.read_text())["modules"][0]["build-commands"]
            self.assertIn("cc -shared -fPIC -O2 -o ${FLATPAK_DEST}/lib/debpak/libdebpak-qtself.so "
                          "debpak-src/debpak-qtself.c -ldl", cmds)
            self.assertIn("cc -shared -fPIC -O2 -o ${FLATPAK_DEST}/lib/debpak/libdebpak-onstack.so "
                          "debpak-src/debpak-onstack.c -ldl", cmds)
            self.assertEqual(cmds.count("rm -rf ${FLATPAK_DEST}/debpak-src"), 1)
            self.assertEqual(cmds[-1], "rm -rf ${FLATPAK_DEST}/debpak-src")
            self.assertEqual((t / "out/app/debpak-src/debpak-qtself.c").read_text(), QT_SELF_SOURCE)

    def test_symptom_converts_again_with_the_shim(self):
        text = ("Overriding existing handler for signal 10. Set JSC_SIGNAL_FOR_GC if you want WebKit to use a "
                "different signal\nsignal 11 received but handler not on signal stack\nmp.gsignal stack "
                "[0xc000008000 0xc000010000], mp.g0 stack [0x7fff9e848000 0x7fff9f045f00], sp=0xc000038ad8\n"
                "fatal error: non-Go code set up signal handler without SA_ONSTACK flag\n")
        (r,) = diagnose(Observation(False, 2, None, text), "gtk3", False, set()).remedies
        self.assertEqual(r.key, "signal-onstack")
        args = SimpleNamespace(signal_onstack=False)
        apply(args, [r])
        self.assertTrue(args.signal_onstack)
        self.assertEqual(diagnose(Observation(False, 2, None, text), "gtk3", False, {"signal-onstack"}).remedies, [])


@unittest.skipUnless(shutil.which("gcc") and os.uname().machine == "x86_64", "needs gcc on x86_64")
class StaticXlibTests(unittest.TestCase):
    def test_library_with_its_own_xlib_gets_libx11_preloaded(self):
        # Mu Editor's AppImage: python-appimage's libpython3.8 carries Tk with an old static Xlib, and Qt's
        # xcb plugin crashed in _XLockDisplay, mixing it with the runtime's libX11
        import subprocess
        from debpak.analyze import xlib_copies
        from debpak.elf import read_elf
        from debpak.stage import wrapper_script
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            root = t / "root"
            (root / "usr/lib").mkdir(parents=True)
            src = t / "x.c"
            src.write_text("void *XOpenDisplay(const char *n) { return 0; }\n")
            fake_x11 = t / "libX11.so.6"
            subprocess.run(["gcc", "-shared", "-fPIC", "-Wl,-soname,libX11.so.6", "-o", str(fake_x11), str(src)],
                           check=True)
            subprocess.run(["gcc", "-shared", "-fPIC", "-o", str(root / "usr/lib/libpython3.8.so.1.0"), str(src)],
                           check=True)
            (t / "q.c").write_text("extern void *XOpenDisplay(const char *); void *f(void) { return XOpenDisplay(0); }\n")
            subprocess.run(["gcc", "-shared", "-fPIC", "-o", str(root / "usr/lib/libQt5XcbQpa.so.5"), str(t / "q.c"),
                            str(fake_x11)], check=True)
            elfs = {rel: read_elf(root / rel) for rel in ("usr/lib/libpython3.8.so.1.0", "usr/lib/libQt5XcbQpa.so.5")}
            self.assertEqual(xlib_copies(elfs), ["usr/lib/libpython3.8.so.1.0"])
            # libX11 itself, or no program using libX11, needs nothing
            self.assertTrue(read_elf(fake_x11).defines_xlib)
            self.assertEqual(xlib_copies({"usr/lib/libX11.so.6": read_elf(fake_x11),
                                          "usr/lib/libQt5XcbQpa.so.5": elfs["usr/lib/libQt5XcbQpa.so.5"]}), [])
            self.assertEqual(xlib_copies({"usr/lib/libpython3.8.so.1.0": elfs["usr/lib/libpython3.8.so.1.0"]}), [])
            write(root / "AppRun", "#!/bin/sh\nexec usr/bin/python3.8 -m mu\n", 0o755)
            write(root / "usr/share/applications/mu.desktop", "[Desktop Entry]\nName=Mu\nExec=/AppRun\n")
            a = analyze(package(root, "mu"))
            self.assertEqual(a.xlib_copies, ["usr/lib/libpython3.8.so.1.0"])
            self.assertIn('export LD_PRELOAD="libX11.so.6${LD_PRELOAD:+:$LD_PRELOAD}"', wrapper_script(a, "bundle", []))
