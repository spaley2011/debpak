"""Snaps: reading snap.yaml, converting an installed snap, the Flathub check,
the apps registry (list/update/uninstall) and `debpak desnap`.

Every outside tool (flatpak, flatpak-builder, snap, sudo, apt-get, dpkg-query)
is a stand-in script that logs its arguments, so nothing on the test machine
changes."""
import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from debpak.cli import main
from debpak.desnap import PIN_NAME, copy_data, installed_snaps, plan
from debpak.manage import flathub_match, load_registry, options_to_argv, snap_revision
from debpak.packages import PackageError, detect_format
from debpak.runtime import index_root
from debpak.snap import extract_snap, parse_yaml

from fixtures import Fixtures, have_toolchain, tiny_png

TRIPLET = "x86_64-linux-gnu"


def run_cli(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = main(list(argv))
    return code, out.getvalue()


def write(path: Path, text: str, mode: int = 0o644) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip("\n"))
    path.chmod(mode)
    return path


def make_snap(root: Path, name: str, rev: str = "12", program: Path | None = None, libs=(), title="",
              kind="app", apps=True, desktop_name=None) -> Path:
    """An installed snap as snapd mounts it: root/NAME/REV plus a `current` link."""
    d = root / name / rev
    if kind != "app" or not apps:
        write(d / "meta/snap.yaml", f"name: {name}\nversion: '1'\ntype: {kind}\n")
    else:
        write(d / "meta/snap.yaml", f"""
            name: {name}
            version: '2.5'
            title: "{title or name.title()}"
            summary: A test snap
            base: core22
            confinement: strict
            apps:
              {name}:
                command: bin/fakeapp --from-snap
                environment:
                  FAKE_MODE: "1"
              helper:
                command: bin/fakeapp
              sync:
                command: bin/fakeapp
                daemon: simple
            """)
        write(d / "meta/gui" / f"{name}.desktop", f"""
            [Desktop Entry]
            Type=Application
            Name={desktop_name or title or name.title()}
            Exec={name} %U
            Icon=${{SNAP}}/meta/gui/icon.png
            """)
        (d / "meta/gui/icon.png").write_bytes(tiny_png(64))
        (d / "bin").mkdir(parents=True)
        if program:
            shutil.copy2(program, d / "bin/fakeapp")
        else:
            write(d / "bin/fakeapp", "#!/bin/sh\necho hi\n", 0o755)
        lib = d / "usr/lib" / TRIPLET
        for f in libs:
            lib.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, lib / f.name)
    (root / name / "current").symlink_to(rev)
    return root / name / "current"


STUBS = {
    # flatpak: Flathub is configured; `search` answers from $FAKE_FLATHUB (TSV lines);
    # install/uninstall are logged and tracked in $STUB_STATE/installed
    "flatpak": r"""
        #!/bin/sh
        echo "flatpak $*" >> "$STUB_LOG"
        case "$1" in
          remotes) echo flathub ;;
          search) shift; for a; do t="$a"; done
                  grep -i -- "$t" "$FAKE_FLATHUB" 2>/dev/null | sed 's/$/\tflathub/' ;;
          install) for a; do id="$a"; done; echo "$id" >> "$STUB_STATE/installed" ;;
          info) grep -qx -- "$2" "$STUB_STATE/installed" 2>/dev/null ;;
          uninstall) for a; do id="$a"; done; grep -vx -- "$id" "$STUB_STATE/installed" > "$STUB_STATE/i2"
                     mv "$STUB_STATE/i2" "$STUB_STATE/installed" ;;
        esac
        exit 0
        """,
    # flatpak-builder: "installs" the manifest's app id with --install (convert builds into a repo
    # and installs from it with flatpak install, which the flatpak stub records)
    "flatpak-builder": r"""
        #!/bin/sh
        echo "flatpak-builder $*" >> "$STUB_LOG"
        for a; do m="$a"; done
        case " $* " in *" --install "*)
            python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$m" >> "$STUB_STATE/installed" ;;
        esac
        """,
    "sudo": '#!/bin/sh\necho "sudo $*" >> "$STUB_LOG"\nexec "$@"\n',
    "snap": '#!/bin/sh\necho "snap $*" >> "$STUB_LOG"\n'
            '[ "$1" = remove ] && rm -rf "$DEBPAK_SNAP_ROOT/$2"\nexit 0\n',
    "apt-get": '#!/bin/sh\necho "apt-get $*" >> "$STUB_LOG"\n'
               '[ "$1" = -s ] && printf "Purg snapd [2.6]\\nPurg ubuntu-desktop-thing [1]\\n"\nexit 0\n',
    "dpkg-query": '#!/bin/sh\nprintf "firefox\\t1:1snap1-0ubuntu5\\tii \\n"\n',
}


class StubTools:
    def __init__(self, base: Path, names=tuple(STUBS)):
        self.bin = base / "stub-bin"
        self.state = base / "stub-state"
        self.log = base / "stub.log"
        self.bin.mkdir(parents=True, exist_ok=True)
        self.state.mkdir(parents=True, exist_ok=True)
        for n in names:
            write(self.bin / n, STUBS[n], 0o755)
        self.flathub = base / "flathub.tsv"
        self.flathub.write_text("")
        self.env = {"PATH": f"{self.bin}:{os.environ['PATH']}", "STUB_LOG": str(self.log),
                    "STUB_STATE": str(self.state), "FAKE_FLATHUB": str(self.flathub)}

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines() if self.log.exists() else []

    def installed(self) -> list[str]:
        p = self.state / "installed"
        return p.read_text().split() if p.exists() else []


# ---------------------------------------------------------------------- no toolchain needed

class SnapYamlTests(unittest.TestCase):
    def test_mpris_slot_names_the_bus_name_the_app_owns(self):
        # Spotify quit at once, without a word, when it couldn't own org.mpris.MediaPlayer2.spotify
        from debpak.snap import mpris_names
        meta = parse_yaml(textwrap.dedent("""
            name: spotify
            slots:
              spotify-mpris:
                interface: mpris
                name: spotify
              player:
                interface: mpris
              other:
                interface: dbus
                name: com.example.x
            """))
        self.assertEqual(mpris_names(meta), {"org.mpris.MediaPlayer2.spotify": "mpris slot spotify-mpris in snap.yaml"})
        del meta["slots"]["spotify-mpris"]
        self.assertEqual(list(mpris_names(meta)), ["org.mpris.MediaPlayer2.spotify"])
        self.assertEqual(mpris_names({"name": "x"}), {})

    def test_parse(self):
        y = parse_yaml(textwrap.dedent("""
            name: my-app   # comment
            version: '1.0'
            title: "Café \\u00e9"
            architectures: [amd64, arm64]
            empty:
            plugs:
              - home
              - network
            apps:
              my-app:
                command: bin/run --x
                environment: {A: "1", B: two}
            description: |
              Line one.
              Line two.
            """))
        self.assertEqual(y["name"], "my-app")
        self.assertEqual(y["version"], "1.0")
        self.assertEqual(y["title"], "Café é")
        self.assertEqual(y["architectures"], ["amd64", "arm64"])
        self.assertIsNone(y["empty"])
        self.assertEqual(y["plugs"], ["home", "network"])
        self.assertEqual(y["apps"]["my-app"]["environment"], {"A": "1", "B": "two"})
        self.assertEqual(y["description"], "Line one.\nLine two.\n")
        # cool-retro-term: a quoted scalar over several lines, then the rest of the file
        y = parse_yaml(textwrap.dedent("""
            name: cool-retro-term
            description: 'cool-retro-term is a terminal emulator which mimics the look and feel
              of the old cathode tube screens. It''s eye-candy.

            '
            summary: plain text that goes
              on over two lines
            apps:
              cool-retro-term:
                command: command-cool-retro-term.wrapper
            """))
        self.assertEqual(y["description"], "cool-retro-term is a terminal emulator which mimics the look and feel "
                                           "of the old cathode tube screens. It's eye-candy. ")
        self.assertEqual(y["summary"], "plain text that goes on over two lines")
        self.assertEqual(y["apps"]["cool-retro-term"]["command"], "command-cool-retro-term.wrapper")

    def snap_dir(self, t: Path, yaml: str, files: dict[str, str] | None = None) -> Path:
        d = t / "snap/tool/1"
        write(d / "meta/snap.yaml", yaml)
        write(d / "bin/fakeapp", "#!/bin/sh\necho hi\n", 0o755)
        for rel, text in (files or {}).items():
            write(d / rel, text, 0o755)
        return d

    def test_user_service_started_by_dbus_is_started_by_the_launcher(self):
        # Firmware Updater's app runs `gapplication launch com.canonical.firmware_updater`, for which
        # snapd's session bus starts firmware-updater-app; it talks to the host's fwupd
        with tempfile.TemporaryDirectory() as t:
            d = self.snap_dir(Path(t), """
                name: tool
                version: '1'
                base: core24
                apps:
                  tool:
                    command: bin/fakeapp
                  tool-app:
                    command: bin/fakeapp --gapplication-service
                    daemon: dbus
                    daemon-scope: user
                    activates-on: [dbus-slot]
                    plugs: [fwupd, shutdown, upower-observe, sysbus]
                  notifier:
                    command: bin/fakeapp
                    daemon: simple
                    daemon-scope: user
                plugs:
                  sysbus:
                    interface: dbus
                    bus: system
                    name: org.example.Helper
                slots:
                  dbus-slot:
                    interface: dbus
                    bus: session
                    name: com.example.tool
                """)
            pkg = extract_snap(d, Path(t) / "work")
            launch = pkg.root / "opt/tool/.debpak-snap"
            self.assertEqual(sorted(p.name for p in launch.iterdir()), ["tool", "tool-app"])
            self.assertEqual(pkg.default_exec, "/opt/tool/.debpak-snap/tool")
            sh = (launch / "tool").read_text()
            self.assertIn('"$SNAP/.debpak-snap/tool-app" &', sh)
            self.assertIn("gdbus wait --session --timeout 20 com.example.tool", sh)
            self.assertNotIn("gdbus", (launch / "tool-app").read_text())
            self.assertIn("com.example.tool", pkg.extra["bus_names"])
            self.assertEqual(sorted(pkg.extra["bus_access"]),
                             ["--system-talk-name=org.example.Helper", "--system-talk-name=org.freedesktop.UPower",
                              "--system-talk-name=org.freedesktop.fwupd", "--system-talk-name=org.freedesktop.login1"])
            self.assertTrue(any("notifier" in n and "tool-app" not in n for n in pkg.notes))
            self.assertFalse(pkg.extra.get("findings"))
            from debpak.permissions import infer
            perms = infer(set(), set(), "elf", bus_access=pkg.extra["bus_access"])
            self.assertIn("--system-talk-name=org.freedesktop.fwupd", [p.arg for p in perms])

    def test_system_tools_are_refused(self):
        # Factory Reset Tools' window drives a root service the system bus starts; App Center drives
        # snapd; Ubuntu Budgie Welcome installs programs with Python's apt module
        def findings(yaml, files=None):
            with tempfile.TemporaryDirectory() as t:
                pkg = extract_snap(self.snap_dir(Path(t), yaml, files), Path(t) / "work")
                return " ".join(f[2] for f in pkg.extra.get("findings", []) if f[0] == "blocker")
        reset = findings("""
            name: tool
            version: '1'
            apps:
              tool:
                command: bin/fakeapp
                desktop: tool.desktop
              dbus-daemon:
                command: bin/fakeapp dbus
                daemon: simple
                activates-on: [service]
            slots:
              service:
                interface: dbus
                bus: system
                name: com.example.Reset
            """)
        self.assertIn("runs a system service (dbus-daemon)", reset)
        store = findings("""
            name: tool
            version: '1'
            apps:
              tool:
                command: bin/fakeapp
                plugs: [desktop, snapd-control]
            """)
        self.assertIn("app tool plugs snapd-control", store)
        welcome = findings("""
            name: tool
            version: '1'
            apps:
              tool:
                command: usr/bin/welcome
            """, {"usr/bin/welcome": "#! /usr/bin/python3\nimport re\nimport apt\n"})
        self.assertIn("usr/bin/welcome imports apt", welcome)
        self.assertEqual(findings("""
            name: tool
            version: '1'
            apps:
              tool:
                command: usr/bin/welcome
            """, {"usr/bin/welcome": "#!/usr/bin/python3\nimport aptly_client\n"}), "")

    def test_layout_paths_and_the_snaps_mount_point_are_pointed_at_app(self):
        # GIMP's layout binds /usr/lib/<triplet>/babl-0.1 to its own copy, where libbabl looks
        # ("babl installation seems broken"); Banshee's binds /usr/lib/cli, named by its Mono
        # .dll.config files; Facturel Soft's binds webkit2gtk-4.1 from an (empty) content snap
        # folder, and carries its own; Mousam's Python script names /snap/mousam/current
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            cur = make_snap(t / "snap", "tool")
            yml = cur / "meta/snap.yaml"
            yml.write_text(yml.read_text() + textwrap.dedent(f"""\
                layout:
                  /usr/lib/{TRIPLET}/babl-0.1:
                    bind: $SNAP/usr/lib/{TRIPLET}/babl-0.1
                  /usr/lib/cli:
                    bind: $SNAP/usr/lib/cli
                  /usr/lib/{TRIPLET}/webkit2gtk-4.1:
                    bind: $SNAP/gnome-platform/usr/lib/{TRIPLET}/webkit2gtk-4.1
                  /usr/share/libdrm:
                    bind: $SNAP/gpu-2404/libdrm
                  /etc/tool:
                    bind: $SNAP/etc/tool
                  /var/lib/tool:
                    bind: $SNAP_DATA/var/lib/tool
                """))
            write(cur / f"usr/lib/{TRIPLET}/babl-0.1/x86-64-v2/x.so", "x")
            (cur / f"gnome-platform/usr/lib/{TRIPLET}/webkit2gtk-4.1").mkdir(parents=True)
            (cur / "gpu-2404").mkdir()
            write(cur / f"usr/lib/{TRIPLET}/webkit2gtk-4.1/WebKitNetworkProcess", "x")
            write(cur / "usr/lib/cli/glib-sharp-2.0/glib-sharp.dll.config",
                  '<dllmap dll="glibsharpglue-2" target="/usr/lib/cli/glib-sharp-2.0/libglibsharpglue-2.so"/>\n'
                  '<dllmap dll="x" target="/usr/lib/cli-common/x.so"/>\n')
            babl = b"\x7fELF\0\0/usr/lib/" + TRIPLET.encode() + b"/babl-0.1\0/snap/core24/current/usr/lib/" \
                + TRIPLET.encode() + b"/babl-0.1\0" + b"/snap/tool/current/usr/share/tool\0/var/snap/tool/current\0"
            (cur / f"usr/lib/{TRIPLET}/libbabl-0.1.so.0").write_bytes(babl)
            write(cur / "usr/bin/tool.py", "#!/usr/bin/env python3\npkgdatadir = '/snap/tool/current/usr/share/tool'\n"
                  "uri = 'file:///snap/tool/current/x'\nother = '/snap/tool/current2/x'\n")
            write(cur / "bin/launch", 'for d in "$SNAP"/usr/lib/cli/*; do :; done\nls ${SNAP}/usr/lib/cli /usr/lib/cli\n', 0o755)
            pkg = extract_snap(cur, t / "work")
            root, opt = pkg.root, pkg.root / "opt/tool"
            self.assertEqual((opt / "bin/launch").read_text(),       # the snap's own folder already
                             'for d in "$SNAP"/usr/lib/cli/*; do :; done\nls ${SNAP}/usr/lib/cli /app/lib/cli\n')
            for path, target in ((f"usr/lib/{TRIPLET}/babl-0.1", f"opt/tool/usr/lib/{TRIPLET}/babl-0.1"),
                                 ("usr/lib/cli", "opt/tool/usr/lib/cli"),
                                 (f"usr/lib/{TRIPLET}/webkit2gtk-4.1", f"opt/tool/usr/lib/{TRIPLET}/webkit2gtk-4.1")):
                self.assertEqual(os.path.normpath((root / path).parent / os.readlink(root / path)),
                                 str(root / target))
            for absent in ("usr/share/libdrm", "etc/tool", "var/lib/tool"):
                self.assertFalse(os.path.lexists(root / absent), absent)
            config = (opt / "usr/lib/cli/glib-sharp-2.0/glib-sharp.dll.config").read_text()
            self.assertIn('target="/app/lib/cli/glib-sharp-2.0/libglibsharpglue-2.so"', config)
            self.assertIn('target="/usr/lib/cli-common/x.so"', config)          # another folder
            data = (opt / f"usr/lib/{TRIPLET}/libbabl-0.1.so.0").read_bytes()
            self.assertEqual(len(data), len(babl))
            self.assertIn(b"\0/app/lib/" + TRIPLET.encode() + b"/babl-0.1\0", data)
            self.assertIn(b"\0/snap/core24/current/usr/lib/", data)            # the base's, not the layout's
            self.assertIn(b"\0/app/opt/tool//////usr/share/tool\0", data)
            self.assertIn(b"\0/var/snap/tool/current\0", data)
            script = (opt / "usr/bin/tool.py").read_text()
            self.assertIn("pkgdatadir = '/app/opt/tool/usr/share/tool'", script)
            self.assertIn("uri = 'file:///app/opt/tool/x'", script)
            self.assertIn("'/snap/tool/current2/x'", script)
            self.assertIn("/snap/tool/current", (opt / "meta/snap.yaml").read_text() + "/snap/tool/current")
            self.assertTrue(any("layout" in n for n in pkg.notes))
            # libbabl builds its folder's path itself: BABL_PATH points it there too
            self.assertIn(f'export BABL_PATH="${{BABL_PATH:-$SNAP/usr/lib/{TRIPLET}/babl-0.1}}"',
                          (opt / ".debpak-snap/tool").read_text())

    def test_snaps_own_qt5_looks_in_the_snap(self):
        # ChartGeany's Qt 5 from Ubuntu stopped at "Could not find QtWebEngineProcess": its prefix
        # was /usr, and snapcraft's desktop-launch and layout had pointed it at the snap
        from debpak.snap import relocate_qt5
        with tempfile.TemporaryDirectory() as t:
            opt = Path(t) / "opt/chart"
            core = opt / f"usr/lib/{TRIPLET}/libQt5Core.so.5.12.8"
            core.parent.mkdir(parents=True)
            body = b"\x7fELF\0qt_prfxpath=/usr" + b"\0" * 64 + b"qt_epfxpath=/usr\0"
            core.write_bytes(body)
            (core.parent / "libQt5Core.so.5").symlink_to(core.name)
            self.assertEqual(relocate_qt5(opt, "/app/opt/chart"), [])         # no Qt folders in the snap
            (core.parent / "qt5/libexec").mkdir(parents=True)
            self.assertEqual(relocate_qt5(opt, "/app/opt/chart"), [f"usr/lib/{TRIPLET}/libQt5Core.so.5.12.8"])
            data = core.read_bytes()
            self.assertEqual(len(data), len(body))
            self.assertIn(b"\0qt_prfxpath=/app/opt/chart/usr\0", data)
            self.assertIn(b"\0qt_epfxpath=/usr\0", data)
            # a prefix with no room after it stays
            core.write_bytes(b"\x7fELF\0qt_prfxpath=/usr\0abc")
            self.assertEqual(relocate_qt5(opt, "/app/opt/chart"), [])

    def test_python_standard_library_comes_from_the_base(self):
        # MySQL Workbench's snap carries libpython3.10; core22 had the standard library and python3
        from types import SimpleNamespace
        from debpak.snap import add_base_python, python_without_stdlib
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            opt = t / "opt/mysql"
            write(opt / f"usr/lib/{TRIPLET}/libpython3.10.so.1.0", "elf")
            write(opt / "usr/lib/python3/dist-packages/x.py", "")
            self.assertEqual(python_without_stdlib(opt), ["3.10"])
            debs = {"libpython3.10-minimal": {"usr/lib/python3.10/os.py": ""},
                    "libpython3.10-stdlib": {"usr/lib/python3.10/json/__init__.py": ""},
                    "python3.10-minimal": {"usr/bin/python3.10": "#!/bin/sh\n"}}

            def fetch(name):
                if name not in debs:
                    return None
                for rel, text in debs[name].items():
                    write(t / "debs" / name / rel, text)
                return SimpleNamespace(name=name, version="3.10.12", root=t / "debs" / name)
            used = add_base_python(opt, ["3.10"], fetch)
            self.assertEqual(len(used), 3)
            self.assertTrue((opt / "usr/lib/python3.10/json/__init__.py").is_file())
            self.assertEqual(os.readlink(opt / "usr/bin/python3"), "python3.10")
            self.assertEqual(python_without_stdlib(opt), [])

    def test_python_venv_runs_on_the_bases_python(self):
        # File Vault's snap is a venv (snapcraft's python plugin) whose bin/python3 is core24's
        # /usr/bin/python3.12; the runtime's python3 knew nothing of it: "No module named 'PyQt6'"
        from types import SimpleNamespace
        from debpak.snap import add_base_python, base_venvs, point_venvs_at, python_without_stdlib
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            opt = t / "opt/filevault"
            write(opt / "pyvenv.cfg", "home = /usr/bin\ninclude-system-site-packages = false\nversion = 3.12.3\n")
            write(opt / "lib/python3.12/site-packages/PyQt6/__init__.py", "")
            (opt / "bin").mkdir()
            (opt / "bin/python3").symlink_to("/usr/bin/python3.12")
            (opt / "bin/python3.12").symlink_to("python3")
            self.assertEqual([v for _c, v in base_venvs(opt)], ["3.12"])
            self.assertEqual(python_without_stdlib(opt), ["3.12"])

            def fetch(name):
                files = {"libpython3.12-minimal": {"usr/lib/python3.12/os.py": ""},
                         "python3.12-minimal": {"usr/bin/python3.12": "#!/bin/sh\n"}}.get(name)
                if files is None:
                    return None
                for rel, text in files.items():
                    write(t / "debs" / name / rel, text)
                return SimpleNamespace(name=name, version="3.12.3", root=t / "debs" / name)
            self.assertEqual(len(add_base_python(opt, ["3.12"], fetch, link_python3=False)), 2)
            self.assertFalse(os.path.lexists(opt / "usr/bin/python3"))     # the venv's python3 is the one
            self.assertEqual(point_venvs_at(opt, "/app/opt/filevault"), ["."])
            self.assertEqual(os.readlink(opt / "bin/python3"), "../usr/bin/python3.12")
            self.assertEqual(os.readlink(opt / "bin/python3.12"), "python3")
            self.assertIn("home = /app/opt/filevault/usr/bin\n", (opt / "pyvenv.cfg").read_text())

    def test_runtime_copies_replace_the_snaps_ubuntu_libraries(self):
        # Tusk's snap (Ubuntu 16.04) brings its own GLib and fontconfig, which loaded in place of the
        # runtime's and left its window blank; Vectr's own librt.so.1 wanted a private part of glibc
        from debpak.elf import ElfInfo
        from debpak.runtime import RuntimeIndex
        from debpak.snap import runtime_copies

        def lib(rel, soname, verdef=(), verneed=None):
            return rel, ElfInfo(rel, "x86_64", 3, 64, soname=soname, verdef=set(verdef), verneed=verneed or {})
        o = "opt/tusk"
        elfs = dict([
            lib(f"{o}/usr/lib/{TRIPLET}/libglib-2.0.so.0.4800.2", "libglib-2.0.so.0"),
            lib(f"{o}/usr/lib/{TRIPLET}/libgnutls.so.30.6.2", "libgnutls.so.30", {"GNUTLS_3_4"}),
            lib(f"{o}/usr/lib/{TRIPLET}/libnew.so.1", "libnew.so.1", {"NEW_2"}),         # newer than the runtime's
            lib(f"{o}/usr/lib/{TRIPLET}/libQt5Core.so.5", "libQt5Core.so.5"),
            lib(f"{o}/lib/{TRIPLET}/librt.so.1", "librt.so.1", {"GLIBC_PRIVATE"}),
            lib(f"{o}/usr/lib/{TRIPLET}/libnode.so", "libnode.so"),                    # the runtime hasn't it
            lib(f"{o}/resources/libglib-2.0.so.0", "libglib-2.0.so.0"),               # not a library folder
            lib(f"{o}/tusk", None, verneed={"libgnutls.so.30": {"GNUTLS_3_4"}}),
        ])
        elfs[f"{o}/tusk"].interp = "/lib64/ld-linux-x86-64.so.2"
        sonames = {i.soname: r for r, i in elfs.items() if i.soname}
        sonames["libglib-2.0.so.0"] = f"{o}/usr/lib/{TRIPLET}/libglib-2.0.so.0.4800.2"
        rt = RuntimeIndex("org.test.Platform/x86_64/1", "x86_64",
                          sonames={n: f"/usr/lib/{n}" for n in ("libglib-2.0.so.0", "libgnutls.so.30", "libnew.so.1",
                                                                 "libQt5Core.so.5", "librt.so.1")},
                          verdefs={"libgnutls.so.30": ["GNUTLS_3_4", "GNUTLS_3_6_3"], "libnew.so.1": ["NEW_1"],
                                   "librt.so.1": ["GLIBC_2.2.5"]})
        got = runtime_copies(o, "core", elfs, sonames, rt, TRIPLET)
        self.assertEqual(sorted(Path(r).name for r in got),
                         ["libglib-2.0.so.0.4800.2", "libgnutls.so.30.6.2", "librt.so.1"])
        # a library without symbol versions from a base newer than the runtime stays
        got = runtime_copies(o, "core26", elfs, sonames, rt, TRIPLET)
        self.assertNotIn(f"{o}/usr/lib/{TRIPLET}/libglib-2.0.so.0.4800.2", got)
        # the snap's programs ask for a version the runtime's copy lacks
        elfs[f"{o}/tusk"].verneed["libgnutls.so.30"].add("GNUTLS_3_8")
        self.assertNotIn(f"{o}/usr/lib/{TRIPLET}/libgnutls.so.30.6.2",
                         runtime_copies(o, "core", elfs, sonames, rt, TRIPLET))

    def test_runtime_copies_replace_the_snaps_graphics_stack(self):
        # PWGen-Rust's snap (core22) carried Ubuntu's libdrm_amdgpu.so.1, and the GL extension's
        # libGLX_mesa.so.0 then failed to load (undefined symbol amdgpu_va_get_start_addr): no
        # OpenGL, "NoGlutinConfigs". Atomify's (Ubuntu 16.04) kept Mesa's libGL in usr/lib/<triplet>/mesa.
        from debpak.elf import ElfInfo
        from debpak.runtime import RuntimeIndex
        from debpak.snap import runtime_copies
        o = "opt/pwgen-rust"
        elfs = {r: ElfInfo(r, "x86_64", 3, 64, soname=so) for r, so in (
            (f"{o}/usr/lib/{TRIPLET}/libdrm_amdgpu.so.1.0.0", "libdrm_amdgpu.so.1"),
            (f"{o}/usr/lib/{TRIPLET}/mesa/libGL.so.1.2.0", "libGL.so.1"),
            (f"{o}/usr/lib/{TRIPLET}/mesa-egl/libEGL.so.1.0.0", "libEGL.so.1"),
            (f"{o}/usr/lib/{TRIPLET}/mesa/libother.so.1", "libother.so.1"),
            (f"{o}/resources/libdrm_intel.so.1", "libdrm_intel.so.1"))}
        sonames = {i.soname: r for r, i in elfs.items()}
        rt = RuntimeIndex("org.test.Platform/x86_64/1", "x86_64", sonames={"libother.so.1": "/usr/lib/libother.so.1"})
        for base in ("core22", "core26"):          # whatever the base, the extension's Mesa needs its own
            got = runtime_copies(o, base, elfs, sonames, rt, TRIPLET)
            self.assertEqual(sorted(Path(r).name for r in got),
                             ["libEGL.so.1.0.0", "libGL.so.1.2.0", "libdrm_amdgpu.so.1.0.0"])

    def test_desktop_launch_from_snapcraft_helpers_is_replaced(self):
        # Atomify and MiniZinc run through snapcraft-desktop-helpers' bin/desktop-launch, which
        # outside snapd spammed "ln: failed to create symbolic link ... File exists" for schemas,
        # failed at update-mime-database and pointed LIBGL_DRIVERS_PATH at the snap's own Mesa
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            cur = make_snap(t / "snap", "tool")
            yml = cur / "meta/snap.yaml"
            text = yml.read_text()
            yml.write_text(re.sub(r"(?m)^(\s+command:).*$", r"\1 bin/desktop-launch $SNAP/bin/fakeapp", text, count=1)
                           .replace('FAKE_MODE: "1"\n', 'FAKE_MODE: "1"\n      LIBGL_DRIVERS_PATH: $SNAP/usr/lib/dri\n'
                                    '      FONTCONFIG_FILE: $SNAP/etc/fonts/fonts.conf\n'))
            write(cur / "bin/desktop-launch", """
                #!/bin/bash
                . $SNAP_USER_DATA/.last_revision 2>/dev/null || true
                export LIBGL_DRIVERS_PATH=$SNAP/usr/lib/x86_64-linux-gnu/dri
                echo "SNAP_DESKTOP_LAST_REVISION=$SNAP_REVISION" > $SNAP_USER_DATA/.last_revision
                exec "$@"
                """, 0o755)
            write(cur / "usr/share/tool/data.txt", "x")
            write(cur / f"usr/lib/{TRIPLET}/qt5/plugins/platforms/README", "x")
            write(cur / "bin/fakeapp", '#!/bin/sh\necho "$XDG_DATA_DIRS|$QT_PLUGIN_PATH|${LIBGL_DRIVERS_PATH-unset}'
                                      '|${FONTCONFIG_FILE-unset}|$1"\n', 0o755)
            pkg = extract_snap(cur, t / "work")
            snap_dir = pkg.root / "opt/tool"
            self.assertIn("debpak put this in place", (snap_dir / "bin/desktop-launch").read_text())
            self.assertTrue(any("desktop-launch" in n for n in pkg.notes))
            r = subprocess.run([str(snap_dir / ".debpak-snap/tool"), "x"], capture_output=True, text=True,
                               env={**os.environ, "XDG_DATA_HOME": str(t / "data"), "XDG_DATA_DIRS": "/usr/share"})
            arch = os.uname().machine
            # the snap's data comes after the runtime's, whose GSettings schemas and themes are newer
            self.assertEqual(r.stdout.strip(), f"/usr/share:{snap_dir}/usr/share|"
                             f"{snap_dir}/usr/lib/{arch}-linux-gnu/qt5/plugins|unset|unset|x", r.stderr)
            # a launcher of the same name that isn't snapcraft's stays
            cur2 = make_snap(t / "snap2", "other")
            write(cur2 / "bin/desktop-launch", '#!/bin/sh\nexec "$@"\n', 0o755)
            pkg = extract_snap(cur2, t / "work2")
            self.assertEqual((pkg.root / "opt/other/bin/desktop-launch").read_text(), '#!/bin/sh\nexec "$@"\n')

    def test_extension_snap_gets_its_own_folders_and_loses_content_snap_paths(self):
        # KGoldrunner's snap (kde-neon-6 extension, kf6-core24) keeps its levels in
        # $SNAP/usr/share/kgoldrunner, which the extension's desktop-launch, skipped, put on
        # XDG_DATA_DIRS; its environment points QT_PLUGIN_PATH, LD_LIBRARY_PATH and ALSA_CONFIG_PATH
        # into the empty $SNAP/kf6 and $SNAP/lxqt-support-core24
        triplet = f"{os.uname().machine}-linux-gnu"
        env = (f'      QT_PLUGIN_PATH: $SNAP/lxqt-support-core24/usr/lib/{triplet}/qt6/plugins:${{QT_PLUGIN_PATH}}\n'
               f'      LD_LIBRARY_PATH: /snap/kf6-core24/current/usr/lib/{triplet}:$SNAP/kf6/usr/lib/{triplet}'
               ':${LD_LIBRARY_PATH}\n'
               '      ALSA_CONFIG_PATH: $SNAP/kf6/etc/asound.conf\n'
               '      XDG_DATA_DIRS: $SNAP/data-dir:$SNAP/kf6/usr/share:$XDG_DATA_DIRS\n'
               '      OWN_PATH: $SNAP/ffmpeg-platform/usr/bin:$PATH\n'
               '    command-chain:\n'
               '    - snap/command-chain/desktop-launch\n')
        plugs = ("plugs:\n"
                 "  kf6-core24:\n    interface: content\n    target: $SNAP/kf6\n    default-provider: kf6-core24\n"
                 "  lxqt-support-core24:\n    interface: content\n    target: $SNAP/lxqt-support-core24\n"
                 "    default-provider: lxqt-support-core24\n"
                 "  ffmpeg-2404:\n    interface: content\n    target: $SNAP/ffmpeg-platform\n"
                 "    default-provider: ffmpeg-2404\n")
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            cur = make_snap(t / "snap", "game")
            yml = cur / "meta/snap.yaml"
            yml.write_text(yml.read_text().replace('      FAKE_MODE: "1"\n', '      FAKE_MODE: "1"\n' + env, 1) + plugs)
            write(cur / "snap/command-chain/desktop-launch", '#!/bin/sh\necho extension; exit 1\n', 0o755)
            write(cur / "usr/share/game/levels.dat", "x")
            write(cur / f"usr/lib/{triplet}/qt6/plugins/kf6/README", "x")
            write(cur / f"usr/lib/{triplet}/girepository-1.0/Game-1.0.typelib", "x")
            write(cur / "ffmpeg-platform/usr/bin/ffmpeg", "#!/bin/sh\n", 0o755)   # the snap carries this one
            write(cur / "bin/fakeapp", '#!/bin/sh\necho "$XDG_DATA_DIRS|$QT_PLUGIN_PATH|${LD_LIBRARY_PATH-unset}'
                                      '|${ALSA_CONFIG_PATH-unset}|$OWN_PATH|$GI_TYPELIB_PATH"\n', 0o755)
            pkg = extract_snap(cur, t / "work")
            snap_dir = pkg.root / "opt/game"
            self.assertIn("debpak put this in place", (snap_dir / ".debpak-snap/.desktop-launch").read_text())
            r = subprocess.run([str(snap_dir / ".debpak-snap/game")], capture_output=True, text=True,
                               env={**os.environ, "XDG_DATA_HOME": str(t / "data"), "XDG_DATA_DIRS": "/usr/share",
                                    "PATH": "/usr/bin:/bin", "LD_LIBRARY_PATH": "/app/lib/debpak"})
            data, qt, ld, alsa, own, gi = r.stdout.strip().split("|")
            # the runtime's typelibs come first, the snap's fill in what it lacks
            self.assertEqual(gi, f"/usr/lib/{triplet}/girepository-1.0:{snap_dir}/usr/lib/{triplet}/girepository-1.0")
            self.assertEqual(data.split(":")[:2], [f"{snap_dir}/data-dir", "/usr/share"], r.stderr)
            self.assertEqual(data.split(":")[-1], f"{snap_dir}/usr/share")
            self.assertNotIn("kf6", data)
            self.assertEqual(qt, f"{snap_dir}/usr/lib/{triplet}/qt6/plugins")
            self.assertNotIn("kf6", ld)
            self.assertTrue(ld.endswith("/app/lib/debpak"), ld)
            self.assertEqual(alsa, "unset")
            self.assertTrue(own.startswith(f"{snap_dir}/ffmpeg-platform/usr/bin:"), own)
            self.assertTrue(any("kf6-core24 -> the KDE runtime" in n for n in pkg.notes), pkg.notes)

    def test_content_snaps_pick_the_runtime_of_their_toolkit(self):
        # Dialect's snap, a Python GTK app on gnome-42-2204, got the Freedesktop runtime and stopped
        # at "No module named 'gi'"; Glance Optimizer's (Tauri, gnome-46-2404) looked for
        # WebKitNetworkProcess where the GNOME runtime has it
        from debpak.analyze import DEFAULT_RUNTIMES, analyze
        from debpak.snapcontent import content_kind, runtime_for
        gnome = {"plugs": {"gnome-42-2204": {"interface": "content", "target": "$SNAP/gnome-platform",
                                             "default-provider": "gnome-42-2204"},
                           "gtk-3-themes": {"interface": "content", "target": "$SNAP/data-dir/themes",
                                            "default-provider": "gtk-common-themes"}}}
        self.assertEqual(runtime_for(gnome, "elf"), "gnome")
        self.assertEqual(runtime_for(gnome, "gtk3"), "gnome")
        self.assertIsNone(runtime_for(gnome, "electron"))     # the Electron base app is Freedesktop's
        kf6 = {"plugs": {"kf6-core24": {"interface": "content", "target": "$SNAP/kf6",
                                        "default-provider": "kf6-core24"}}}
        self.assertEqual(runtime_for(kf6, "elf"), "kde6")
        self.assertIsNone(runtime_for({"plugs": {"x": {"interface": "content",
                                                       "default-provider": "gtk-common-themes"}}}, "gtk3"))
        for name, kind in (("gnome-3-28-1804", "gnome"), ("gnome-46-2404", "gnome"), ("gnome-core26", "gnome"),
                           ("kf5-5-113-qt-5-15-11-core22", "kde5"), ("kde-frameworks-5-99-qt-5-15-7-core20", "kde5"),
                           ("kde-frameworks-5-core18", "kde5"), ("kf6-core22", "kde6"), ("mesa-2404", "gl"),
                           ("gpu-2404", "gl"), ("graphics-core22", "gl"), ("ffmpeg-2404", "codecs"),
                           ("gtk2-common-themes", "themes"), ("lxqt-support-core24", "qt-theme")):
            self.assertEqual(content_kind(name)[0], kind, name)
        self.assertIsNone(content_kind("wine-platform-runtime"))
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            cur = make_snap(t / "snap", "tool")
            yml = cur / "meta/snap.yaml"
            yml.write_text(yml.read_text() + "plugs:\n  gnome-42-2204:\n    interface: content\n"
                           "    target: $SNAP/gnome-platform\n    default-provider: gnome-42-2204\n")
            pkg = extract_snap(cur, t / "work")
            self.assertEqual(analyze(pkg, None).runtime_suggestion, DEFAULT_RUNTIMES["gnome"])
            plain = extract_snap(make_snap(t / "snap2", "tool"), t / "work2")
            self.assertEqual(analyze(plain, None).runtime_suggestion, DEFAULT_RUNTIMES["freedesktop"])

    def test_extract_installed_snap(self):
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            cur = make_snap(t / "snap", "tool", title="Tool")
            self.assertEqual(detect_format(cur), "snap")
            pkg = extract_snap(cur, t / "work")
            self.assertEqual((pkg.format, pkg.name, pkg.version), ("snap", "tool", "2.5"))
            self.assertEqual(pkg.extra["ubuntu_suite"], "jammy")
            self.assertEqual(pkg.default_exec, "/opt/tool/.debpak-snap/tool")
            launch = pkg.root / "opt/tool/.debpak-snap"
            self.assertEqual(sorted(p.name for p in launch.iterdir()), ["helper", "tool"])   # daemon skipped
            sh = (launch / "tool").read_text()
            self.assertIn('export FAKE_MODE="1"', sh)
            self.assertIn('exec "$SNAP/bin/fakeapp" --from-snap "$@"', sh)
            desk = (pkg.root / "usr/share/applications/tool_tool.desktop").read_text()
            self.assertIn("Exec=/opt/tool/.debpak-snap/tool %U", desk)
            self.assertIn("Icon=tool", desk)
            self.assertTrue(any("background services" in n for n in pkg.notes))

    def test_snap_on_wine_platform_is_refused(self):
        # Notepad++'s snap runs on Wine from the wine-platform snaps, which don't exist outside snapd
        from debpak.snap import platform_snaps
        y = parse_yaml(textwrap.dedent("""
            name: notepad-plus-plus
            plugs:
              wine-base-stable:
                interface: content
                target: $SNAP/wine-platform
                default-provider: wine-platform-9-stable
              gnome-46-2404:
                interface: content
                default-provider: gnome-46-2404
              home: null
            """))
        self.assertEqual(platform_snaps(y), {"wine-base-stable": "wine-platform-9-stable"})
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            cur = make_snap(t / "snap", "tool", title="Tool")
            yml = cur / "meta/snap.yaml"
            yml.write_text(yml.read_text() + "plugs:\n  wine-runtime:\n    interface: content\n"
                           "    default-provider: wine-platform-runtime-core22\n")
            pkg = extract_snap(cur, t / "work")
            (cat, _where, detail), = pkg.extra["findings"]
            self.assertEqual(cat, "blocker")
            self.assertIn("convert the Windows program itself", detail)

    def test_not_an_app_snap(self):
        with tempfile.TemporaryDirectory() as t:
            cur = make_snap(Path(t) / "snap", "core22", kind="base")
            with self.assertRaises(PackageError):
                extract_snap(cur, Path(t) / "work")

    def test_system_service_the_apps_need_is_refused(self):
        # Multipass: the CLI and the GUI only drive multipassd, a root service with kvm access
        from debpak.snap import system_services
        y = parse_yaml(textwrap.dedent("""
            apps:
              multipassd:
                command: bin/launch-multipassd
                daemon: simple
                plugs: [firewall-control, kvm, multipass-support, network-control]
              multipass:
                command: bin/launch-multipass
              gui:
                command: bin/bundle/multipass_gui
                desktop: usr/share/applications/multipass.gui.desktop
              agent:
                command: bin/agent
                daemon: simple
                daemon-scope: user
              sync:
                command: bin/sync
                daemon: simple
            """))
        self.assertEqual(system_services(y["apps"], has_gui=True), ["multipassd"])
        # a snap with no menu entry is a service plus its command-line clients (LXD, Docker)
        self.assertEqual(system_services(y["apps"], has_gui=False), ["multipassd", "sync"])
        # Plex Media Server: the menu entry opens the service's web page, and the service serves it
        plex = parse_yaml(textwrap.dedent("""
            apps:
              plexmediaserver:
                command: wrapper.sh
                daemon: simple
                plugs: [home-all, network, network-bind, opengl]
              pms-web:
                command: pms-web.sh
                plugs: [desktop]
            """))
        self.assertEqual(system_services(plex["apps"], has_gui=True), [])
        with tempfile.TemporaryDirectory() as t:
            from debpak.snap import opens_local_web_page
            (Path(t) / "pms-web.sh").write_text("#! /bin/sh\nxdg-open http://localhost:32400/web\n")
            self.assertTrue(opens_local_web_page(Path(t), plex["apps"]))
            (Path(t) / "pms-web.sh").write_text("#! /bin/sh\nexec $SNAP/bin/plex-gui\n")
            self.assertFalse(opens_local_web_page(Path(t), plex["apps"]))
        self.assertEqual(system_services(plex["apps"], has_gui=True, web_ui=True), ["plexmediaserver"])
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            cur = make_snap(t / "snap", "tool", title="Tool")
            yml = cur / "meta/snap.yaml"
            yml.write_text(yml.read_text().replace("    daemon: simple\n",
                                                   "    daemon: simple\n    plugs: [kvm, network-control]\n"))
            pkg = extract_snap(cur, t / "work")
            (cat, _where, detail), = pkg.extra["findings"]
            self.assertEqual(cat, "blocker")
            self.assertIn("runs a system service (sync)", detail)
            self.assertFalse(any("background services" in n for n in pkg.notes))

    def test_pcscd_in_the_snap_gives_way_to_the_hosts(self):
        # Cryptnox's snap runs its own pcscd for its card tools; their libpcsclite reaches the
        # host's just as well, which --socket=pcsc lets into the sandbox
        from debpak.permissions import infer
        from debpak.snap import host_services, system_services
        y = parse_yaml(textwrap.dedent("""
            apps:
              pcscd:
                command: usr/sbin/pcscd --foreground --auto-exit
                daemon: simple
                plugs: [raw-usb, hardware-observe]
              card:
                command: usr/bin/cryptnox
            """))
        self.assertEqual(system_services(y["apps"], has_gui=False), [])
        self.assertEqual(host_services(y["apps"]), {"pcscd": "--socket=pcsc"})
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            cur = make_snap(t / "snap", "tool")
            yml = cur / "meta/snap.yaml"
            yml.write_text(yml.read_text().replace("    command: bin/fakeapp\n    daemon: simple\n",
                                                   "    command: usr/sbin/pcscd --foreground\n    daemon: simple\n"
                                                   "    plugs: [raw-usb, kernel-module-control]\n"))
            self.assertIn("pcscd", yml.read_text())
            pkg = extract_snap(cur, t / "work")
            self.assertNotIn("findings", pkg.extra)
            self.assertIn("--socket=pcsc", pkg.extra["bus_access"])
        self.assertIn("--socket=pcsc", [p.arg for p in infer({"libpcsclite.so.1"}, set(), "elf")])

    def test_menu_entry_app_is_the_entry_point(self):
        # Multipass ran its CLI (`multipass`, named after the snap) instead of the GUI its menu entry opens
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            cur = make_snap(t / "snap", "tool")
            (cur / "meta/gui/tool.desktop").rename(cur / "meta/gui/tool_helper.desktop")
            desk = cur / "meta/gui/tool_helper.desktop"
            desk.write_text(desk.read_text().replace("Exec=tool %U", "Exec=tool.helper %U"))
            pkg = extract_snap(cur, t / "work")
            self.assertEqual(pkg.default_exec, "/opt/tool/.debpak-snap/helper")
            self.assertTrue((pkg.root / "opt/tool/.debpak-snap/tool").is_file())    # still there for --command

    def test_launcher_keeps_added_libraries_after_the_snap_library_path(self):
        # Multipass sets LD_LIBRARY_PATH to its own folders, which dropped /app/lib/debpak
        # (libapparmor.so.1, bundled from Ubuntu noble): "cannot open shared object file"
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            cur = make_snap(t / "snap", "tool")
            yml = cur / "meta/snap.yaml"
            yml.write_text(yml.read_text().replace('FAKE_MODE: "1"\n',
                                                   'FAKE_MODE: "1"\n      LD_LIBRARY_PATH: $SNAP/lib:$SNAP/usr/lib\n'))
            write(cur / "bin/fakeapp", '#!/bin/sh\necho "$LD_LIBRARY_PATH"\n', 0o755)
            # TiMidity++'s sets only $SNAP/usr/lib/<triplet>/pulseaudio, and snapcraft-runner, a
            # command-chain debpak skips, added the snap's library folders after it
            triplet = f"{os.uname().machine}-linux-gnu"
            write(cur / f"usr/lib/{triplet}/libown.so.1", "")
            pkg = extract_snap(cur, t / "work")
            snap_dir = pkg.root / "opt/tool"
            r = subprocess.run([str(snap_dir / ".debpak-snap/tool")], capture_output=True, text=True,
                               env={**os.environ, "XDG_DATA_HOME": str(t / "data"),
                                    "LD_LIBRARY_PATH": "/app/lib/debpak"})
            self.assertEqual(r.stdout.strip(), f"{snap_dir}/lib:{snap_dir}/usr/lib:{snap_dir}/usr/lib:{snap_dir}/usr/lib/{triplet}"
                             ":/app/lib/debpak", r.stderr)

    def test_command_arguments_expand_snap_variables(self):
        # Pick's command is "bin/desktop-launch $SNAP/bin/pick-colour-picker"; snapd expands $SNAP
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            cur = make_snap(t / "snap", "tool")
            yml = cur / "meta/snap.yaml"
            text = yml.read_text()
            yml.write_text(re.sub(r"(?m)^(\s+command:).*$", r"\1 bin/fakeapp $SNAP/bin/real plain", text, count=1))
            write(cur / "bin/fakeapp", '#!/bin/sh\necho "$1|$2"\n', 0o755)
            pkg = extract_snap(cur, t / "work")
            snap_dir = pkg.root / "opt/tool"
            r = subprocess.run([str(snap_dir / ".debpak-snap/tool")], capture_output=True, text=True,
                               env={**os.environ, "XDG_DATA_HOME": str(t / "data")})
            self.assertEqual(r.stdout.strip(), f"{snap_dir}/bin/real|plain", r.stderr)

    def test_launcher_runs_without_snapd(self):
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            cur = make_snap(t / "snap", "tool")
            write(cur / "bin/fakeapp", '#!/bin/sh\necho "$SNAP_NAME $FAKE_MODE $1 $SNAP_USER_DATA"\n', 0o755)
            pkg = extract_snap(cur, t / "work")
            r = subprocess.run([str(pkg.root / "opt/tool/.debpak-snap/tool"), "x"], capture_output=True,
                               text=True, env={**os.environ, "XDG_DATA_HOME": str(t / "data")})
            self.assertEqual(r.stdout.split(), ["tool", "1", "--from-snap", f"{t}/data/snap/current"])
            self.assertTrue((t / "data/snap/common").is_dir())

    def test_revision_and_options(self):
        with tempfile.TemporaryDirectory() as t:
            cur = make_snap(Path(t) / "snap", "tool", rev="345")
            self.assertEqual(snap_revision(cur), 345)
        self.assertEqual(snap_revision(Path("tool_77.snap")), 77)
        self.assertEqual(options_to_argv({"runtime": "r//1", "permissive": True, "deps_dir": ["a", "b"]}),
                         ["--runtime", "r//1", "--permissive", "--deps-dir", "a", "--deps-dir", "b"])


class FlathubMatchTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.stubs = StubTools(Path(self._tmp.name), names=("flatpak",))
        self.stubs.flathub.write_text("org.mozilla.firefox\tFirefox\n"
                                      "org.telegram.desktop\tTelegram Desktop\n"
                                      "com.example.FirefoxHelper\tFirefox Helper\n")
        self.env = mock.patch.dict(os.environ, self.stubs.env)
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self._tmp.cleanup()

    def test_exact_matches_only(self):
        self.assertEqual(flathub_match(["firefox"]).app_id, "org.mozilla.firefox")
        self.assertEqual(flathub_match(["telegram-desktop"]).app_id, "org.telegram.desktop")
        self.assertIsNone(flathub_match(["fire"]))
        self.assertIsNone(flathub_match(["something-else"]))

    def test_no_flatpak_means_no_match(self):
        with mock.patch.dict(os.environ, {"PATH": "/nonexistent"}):
            self.assertIsNone(flathub_match(["firefox"]))


class CopyDataTests(unittest.TestCase):
    def test_maps_like_flatpak_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as t:
            home = Path(t)
            write(home / "snap/foo/12/.config/foo/settings.ini", "old=1\n")
            write(home / "snap/foo/12/.local/share/foo/db", "data\n")
            write(home / "snap/foo/12/.cache/foo/junk", "x\n")
            write(home / "snap/foo/12/notes.txt", "n\n")
            (home / "snap/foo/current").symlink_to("12")
            write(home / "snap/foo/common/.mozilla/firefox/profiles.ini", "p\n")
            (home / "snap/foo/common/.mozilla/firefox/link").symlink_to("profiles.ini")
            write(home / ".var/app/org.foo.Foo/config/foo/settings.ini", "mine=1\n")

            copied, skipped = copy_data("foo", "org.foo.Foo", converted=False, home=home)
            dst = home / ".var/app/org.foo.Foo"
            self.assertEqual((dst / "config/foo/settings.ini").read_text(), "mine=1\n")     # kept
            self.assertEqual((dst / "data/foo/db").read_text(), "data\n")
            self.assertEqual((dst / ".mozilla/firefox/profiles.ini").read_text(), "p\n")
            self.assertEqual(os.readlink(dst / ".mozilla/firefox/link"), "profiles.ini")
            self.assertFalse((dst / "cache").exists() or (dst / ".cache").exists())
            self.assertFalse((dst / "data/snap").exists())                 # only converted snaps get these
            self.assertEqual((copied, skipped), (3, 1))

            copy_data("foo", "local.snap.foo", converted=True, home=home)
            self.assertEqual((home / ".var/app/local.snap.foo/data/snap/current/notes.txt").read_text(), "n\n")


# ---------------------------------------------------------------------- full conversions

@unittest.skipUnless(have_toolchain(), "needs gcc and dpkg-deb on x86_64")
class SnapConvertTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="debpak-snap-")
        cls.base = Path(cls._tmp.name)
        cls.fx = Fixtures(cls.base / "fx")
        cls.index_path = cls.base / "runtime.json"
        index_root(cls.fx.runtime_root, "org.test.Platform/x86_64/1", "x86_64").save(cls.index_path)
        s = cls.fx.src
        cls.program = s / "fakeapp"
        cls.libs = [s / "libfake.so.1.0.0", s / "libfakedep.so.2.0.0"]

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def setUp(self):
        self.t = Path(tempfile.mkdtemp(dir=self.base))
        self.stubs = StubTools(self.t)
        self.home = self.t / "home"
        self.home.mkdir()
        self.snaps = self.t / "snap"
        self.prefs = self.t / "preferences.d"
        self.prefs.mkdir()
        self.env = mock.patch.dict(os.environ, {**self.stubs.env, "HOME": str(self.home),
                                                "DEBPAK_PKG_MANAGER": "apt",
                                                "XDG_DATA_HOME": str(self.home / ".local/share"),
                                                "XDG_CACHE_HOME": str(self.base / "cache"),
                                                "DEBPAK_SNAP_ROOT": str(self.snaps),
                                                "DEBPAK_APT_PREFS_DIR": str(self.prefs)})
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def make_tool_snap(self, name="tool", rev="12", **kw):
        cur = make_snap(self.snaps, name, rev, program=self.program, **kw)
        for real, soname in ((self.libs[0], "libfake.so.1"), (self.libs[1], "libfakedep.so.2")):
            lib = cur / "usr/lib" / TRIPLET
            lib.mkdir(parents=True, exist_ok=True)
            shutil.copy2(real, lib / real.name)
            (lib / soname).symlink_to(real.name)
        return cur

    def test_convert_installs_and_records(self):
        cur = self.make_tool_snap()
        out = self.t / "out"
        code, log = run_cli("convert", str(cur), "--app-id", "org.example.Tool", "-o", str(out),
                            "--runtime-index", str(self.index_path), "--no-auto-mirror")
        self.assertEqual(code, 0, log)
        self.assertIn("Installed.", log)
        self.assertIn("org.example.Tool", self.stubs.installed())
        app = out / "app"
        r = subprocess.run([str(app / "opt/tool/.debpak-snap/tool")], capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), "fakeapp says 42 4", r.stderr)
        m = json.loads((out / "org.example.Tool.json").read_text())
        self.assertEqual(m["x-debpak"]["format"], "snap")
        entry = load_registry()["org.example.Tool"]
        self.assertEqual((entry["format"], entry["snap"], entry["snap_revision"]), ("snap", "tool", 12))

        code, log = run_cli("list")
        self.assertIn("org.example.Tool", log)
        self.assertIn("snap tool r12", log)

        code, log = run_cli("uninstall", "org.example.Tool", "--delete-build")
        self.assertEqual(code, 0, log)
        self.assertNotIn("org.example.Tool", self.stubs.installed())
        self.assertFalse(out.exists())
        self.assertNotIn("org.example.Tool", load_registry())
        code, log = run_cli("uninstall", "org.example.Tool")
        self.assertEqual(code, 1)

    def test_snaps_own_glibc_library_is_left_out(self):
        # Vectr's snap carries librt.so.1 from Ubuntu 16.04, which wanted GLIBC_PRIVATE of a newer libpthread
        cur = self.make_tool_snap()
        own = cur / "lib" / TRIPLET
        own.mkdir(parents=True)
        shutil.copy2(self.fx.runtime_root / "lib" / TRIPLET / "libdl.so.2", own / "libdl.so.2")
        out = self.t / "out"
        code, log = run_cli("convert", str(cur), "--app-id", "org.example.Tool", "-o", str(out),
                            "--runtime-index", str(self.index_path), "--no-auto-mirror", "--no-build")
        self.assertEqual(code, 0, log)
        self.assertIn("own copies of libraries the runtime has (libdl.so.2)", log)
        self.assertFalse((out / "app/opt/tool/lib" / TRIPLET / "libdl.so.2").exists())
        self.assertTrue((out / "app/opt/tool/usr/lib" / TRIPLET / "libfake.so.1").exists())

    def test_layout_folder_is_at_its_path_under_app(self):
        # Banshee's layout binds /usr/lib/cli; its .dll.config files name /usr/lib/cli/..., and its
        # launcher's "$SNAP"/usr/lib/cli/* is the snap's own folder already
        cur = self.make_tool_snap()
        yml = cur / "meta/snap.yaml"
        yml.write_text(yml.read_text() + "layout:\n  /usr/lib/cli:\n    bind: $SNAP/usr/lib/cli\n")
        write(cur / "usr/lib/cli/glib-sharp-2.0/glib-sharp.dll.config",
              '<dllmap dll="glue" target="/usr/lib/cli/glib-sharp-2.0/libglue.so"/>\n')
        write(cur / "bin/launch", '#!/bin/sh\nfor d in "$SNAP"/usr/lib/cli/*; do echo "$d"; done\n', 0o755)
        out = self.t / "out"
        code, log = run_cli("convert", str(cur), "--app-id", "org.example.Tool", "-o", str(out),
                            "--runtime-index", str(self.index_path), "--no-auto-mirror", "--no-build")
        self.assertEqual(code, 0, log)
        app = out / "app"
        self.assertEqual(os.readlink(app / "lib/cli"), "../opt/tool/usr/lib/cli")
        self.assertIn('target="/app/lib/cli/glib-sharp-2.0/libglue.so"',
                      (app / "lib/cli/glib-sharp-2.0/glib-sharp.dll.config").read_text())
        self.assertIn('"$SNAP"/usr/lib/cli/*', (app / "opt/tool/bin/launch").read_text())

    def test_no_build_and_auto_mirror_message(self):
        cur = self.make_tool_snap()
        with mock.patch("debpak.cli._load_runtime", side_effect=RuntimeError("stop here")):
            code, log = run_cli("convert", str(cur), "--app-id", "org.example.Tool", "-o", str(self.t / "o"))
        self.assertIn("missing libraries come from Ubuntu jammy", log)
        code, log = run_cli("convert", str(cur), "--app-id", "org.example.Tool2", "-o", str(self.t / "o2"),
                            "--runtime-index", str(self.index_path), "--no-auto-mirror", "--no-build")
        self.assertEqual(code, 0, log)
        self.assertEqual(self.stubs.installed(), [])
        self.assertEqual(load_registry(), {})

    def test_flathub_stops_conversion(self):
        self.stubs.flathub.write_text("org.mozilla.firefox\tFirefox\n")
        code, log = run_cli("convert", str(self.fx.app_deb), "--app-id", "org.example.Fake", "--no-build",
                            "--runtime-index", str(self.index_path), "--deps-dir", str(self.fx.deps),
                            "-o", str(self.t / "o"))
        self.assertEqual(code, 0, log)                 # "Fake App" isn't on (our fake) Flathub
        cur = self.make_tool_snap("firefox", title="Firefox")
        code, log = run_cli("convert", str(cur), "--app-id", "org.example.FF", "-o", str(self.t / "ff"),
                            "--runtime-index", str(self.index_path), "--no-auto-mirror")
        self.assertEqual(code, 4, log)
        self.assertIn("flatpak install flathub org.mozilla.firefox", log)
        code, log = run_cli("convert", str(cur), "--app-id", "org.example.FF", "-o", str(self.t / "ff"),
                            "--runtime-index", str(self.index_path), "--no-auto-mirror", "--anyway")
        self.assertEqual(code, 0, log)
        code, log = run_cli("inspect", str(cur), "--runtime-index", str(self.index_path))
        self.assertIn("already on Flathub as org.mozilla.firefox", log)

    def test_update_from_changed_local_file(self):
        out = self.t / "o"
        deb = self.t / "fakeapp.deb"
        shutil.copy2(self.fx.app_deb, deb)
        code, log = run_cli("convert", str(deb), "--app-id", "org.example.Fake",
                            "--runtime-index", str(self.index_path), "--deps-dir", str(self.fx.deps), "-o", str(out))
        self.assertEqual(code, 0, log)
        self.assertEqual(load_registry()["org.example.Fake"]["options"]["deps_dir"], [str(self.fx.deps)])
        code, log = run_cli("update", "--check")
        self.assertIn("can't check", log)                # unchanged local file, no URL
        with open(deb, "ab") as f:
            f.write(b"\0")                              # ar archives tolerate trailing padding
        code, log = run_cli("update", "--check")
        self.assertIn("update available", log)
        before = len(self.stubs.calls())
        code, log = run_cli("update", "org.example.Fake")
        self.assertEqual(code, 0, log)
        self.assertTrue(any(c.startswith("flatpak-builder") for c in self.stubs.calls()[before:]))
        code, log = run_cli("update", "org.example.Nope")
        self.assertEqual(code, 1)

    def test_update_snap_from_store(self):
        cur = self.make_tool_snap()
        out = self.t / "o"
        code, log = run_cli("convert", str(cur), "--app-id", "org.example.Tool", "-o", str(out),
                            "--runtime-index", str(self.index_path), "--no-auto-mirror")
        self.assertEqual(code, 0, log)
        info = {"version": "2.6", "revision": 13, "url": "https://x/tool_13.snap", "sha3_384": None, "size": 1}
        with mock.patch("debpak.snap.store_info", return_value=info):
            code, log = run_cli("update", "--check")
        self.assertIn("update available (tool 2.6 (revision 13, have 12))", log)
        info["revision"] = 12
        with mock.patch("debpak.snap.store_info", return_value=info):
            code, log = run_cli("update", "--check")
        self.assertIn("up to date", log)

    # ------------------------------------------------------------------ desnap
    def populate(self):
        self.stubs.flathub.write_text("org.mozilla.firefox\tFirefox\ncom.example.Chat\tChat Thing\n")
        self.make_tool_snap("firefox", title="Firefox")
        self.make_tool_snap("chat", desktop_name="Chat Thing")      # matched by its menu name
        self.make_tool_snap("tool")                                 # not on Flathub: converted
        make_snap(self.snaps, "snap-store", rev="1")
        make_snap(self.snaps, "core22", kind="base")
        make_snap(self.snaps, "gtk-common-themes", apps=False)
        write(self.home / "snap/firefox/common/.mozilla/firefox/profiles.ini", "p\n")
        write(self.home / "snap/tool/12/.config/tool/rc", "r\n")
        (self.home / "snap/tool/current").symlink_to("12")

    def desnap(self, *flags):
        return run_cli("desnap", "--runtime-index", str(self.index_path), "-o", str(self.t / "desnap"), *flags)

    def test_desnap_dry_run_changes_nothing(self):
        self.populate()
        code, log = self.desnap("--dry-run", "--remove-snaps", "--block-snapd")
        self.assertEqual(code, 0, log)
        self.assertIn("firefox                      -> org.mozilla.firefox  [firefox deb]", log)
        self.assertIn("chat                         -> com.example.Chat", log)
        self.assertIn("tool                         -> local.snap.tool", log)
        self.assertIn("snap-store", log)
        self.assertNotIn("core22", log)
        self.assertNotIn("gtk-common-themes", log)
        self.assertEqual([c for c in self.stubs.calls() if not c.startswith(("flatpak search", "flatpak remotes"))],
                         [])
        self.assertEqual(sorted(s.name for s in installed_snaps()),
                         ["chat", "core22", "firefox", "gtk-common-themes", "snap-store", "tool"])

    def test_content_providers_are_not_apps(self):
        # mesa-2404 declares helper apps but exists to give other snaps their graphics drivers
        write(self.snaps / "mesa-2404/30/meta/snap.yaml", """
            name: mesa-2404
            version: '24.2'
            type: app
            apps:
              drirc-tool:
                command: bin/drirc
            slots:
              gpu-2404:
                interface: content
                content: gpu-2404
            """)
        (self.snaps / "mesa-2404/current").symlink_to("30")
        make_snap(self.snaps, "chat", title="Chat")
        snaps = {s.name: s for s in installed_snaps()}
        self.assertTrue(snaps["mesa-2404"].provides_content)
        self.assertFalse(snaps["chat"].provides_content)
        self.assertEqual([i.snap for i in plan(list(snaps.values()), {}, True)], ["chat"])

    def test_desnap_without_a_terminal_asks_and_gets_no(self):
        self.populate()
        with mock.patch("sys.stdin", io.StringIO("")):
            code, log = self.desnap("--remove-snaps")
        self.assertEqual(code, 1)
        self.assertIn("pass --yes to agree", log)
        self.assertEqual(self.stubs.installed(), [])

    def test_desnap_keeps_snaps_by_default(self):
        self.populate()
        code, log = self.desnap("--yes")
        self.assertEqual(code, 0, log)
        self.assertEqual(sorted(self.stubs.installed()), ["com.example.Chat", "local.snap.tool", "org.mozilla.firefox"])
        calls = self.stubs.calls()
        self.assertFalse(any(c.startswith(("snap ", "apt-get", "sudo")) for c in calls), calls)
        self.assertEqual(len(installed_snaps()), 6)
        self.assertFalse((self.home / ".var/app/org.mozilla.firefox").exists())   # no --copy-data
        self.assertEqual(list(self.prefs.iterdir()), [])

    def test_desnap_all_the_way(self):
        self.populate()
        code, log = self.desnap("--yes", "--copy-data", "--remove-snaps", "--block-snapd")
        self.assertEqual(code, 0, log)
        calls = self.stubs.calls()
        self.assertIn("apt-get remove -y firefox", calls)
        for n in ("firefox", "chat", "tool", "snap-store"):
            self.assertIn(f"snap remove {n}", calls)
        self.assertNotIn("snap remove core22", calls)               # bases go with snapd
        self.assertIn("apt-get -s purge snapd", calls)
        self.assertIn("apt-get purge -y snapd", calls)
        self.assertIn("apt would remove: snapd ubuntu-desktop-thing", log)
        self.assertIn("Pin-Priority: -10", (self.prefs / PIN_NAME).read_text())
        v = self.home / ".var/app"
        self.assertEqual((v / "org.mozilla.firefox/.mozilla/firefox/profiles.ini").read_text(), "p\n")
        self.assertEqual((v / "local.snap.tool/config/tool/rc").read_text(), "r\n")
        self.assertEqual((v / "local.snap.tool/data/snap/current/.config/tool/rc").read_text(), "r\n")
        self.assertIn("local.snap.tool", load_registry())

    def test_desnap_keeps_snapd_while_snaps_remain(self):
        self.populate()
        code, log = self.desnap("--yes", "--remove-snaps", "--block-snapd", "--no-convert")
        self.assertEqual(code, 0, log)
        calls = self.stubs.calls()
        self.assertIn("snap remove firefox", calls)
        self.assertNotIn("snap remove tool", calls)
        self.assertNotIn("snap remove snap-store", calls)           # other app snaps are still there
        self.assertNotIn("apt-get purge -y snapd", calls)
        self.assertIn("snapd stays: still installed as snaps: snap-store, tool", log)
        self.assertTrue((self.prefs / PIN_NAME).exists())

    def _other_distro(self, kind: str, stubs: dict):
        for name, text in stubs.items():
            write(self.stubs.bin / name, text, 0o755)
        (self.stubs.bin / "dpkg-query").unlink()
        return mock.patch.dict(os.environ, {"DEBPAK_PKG_MANAGER": kind})

    def test_desnap_on_fedora(self):
        self.populate()
        dropins = self.t / "libdnf5.conf.d"
        dnf = ('#!/bin/sh\necho "dnf5 $*" >> "$STUB_LOG"\n'
               '[ "$2" = --assumeno ] && printf "Removing:\\n snapd   x86_64 2.66-1.fc43 fedora 30M\\n'
               ' snap-confine x86_64 2.66-1.fc43 fedora 1M\\n"\nexit 0\n')
        with self._other_distro("dnf", {"dnf5": dnf}), \
                mock.patch.dict(os.environ, {"DEBPAK_DNF_CONF_DIR": str(dropins)}):
            dropins.mkdir()
            code, log = self.desnap("--yes", "--remove-snaps", "--block-snapd")
        self.assertEqual(code, 0, log)
        calls = self.stubs.calls()
        self.assertFalse(any(c.startswith("apt-get") for c in calls), calls)    # no stub debs on Fedora
        self.assertIn("excludepkgs=snapd", (dropins / "debpak-no-snapd.conf").read_text())
        self.assertIn("dnf would remove: snapd snap-confine", log)
        self.assertIn("dnf5 remove -y snapd", calls)
        self.assertNotIn("[firefox deb]", log)

    def test_desnap_on_fedora_with_dnf4_only_explains(self):
        self.populate()
        with self._other_distro("dnf", {"dnf": '#!/bin/sh\necho "dnf $*" >> "$STUB_LOG"\nexit 0\n'}), \
                mock.patch("shutil.which", side_effect=lambda n, *a, **k: None if n == "dnf5" else
                           (str(self.stubs.bin / n) if (self.stubs.bin / n).exists() else None)):
            code, log = self.desnap("--yes", "--block-snapd", "--no-convert", "--only", "chat")
        self.assertIn("add this line under [main] there:\n  excludepkgs=snapd", log)

    def test_desnap_on_arch(self):
        self.populate()
        pacman = ('#!/bin/sh\necho "pacman $*" >> "$STUB_LOG"\n'
                  '[ "$1" = -Rsp ] && printf "snapd\\nsquashfs-tools\\n"\nexit 0\n')
        with self._other_distro("pacman", {"pacman": pacman}):
            code, log = self.desnap("--yes", "--remove-snaps", "--block-snapd")
        self.assertEqual(code, 0, log)
        self.assertIn("snapd only comes from the AUR", log)
        self.assertIn("pacman would remove: snapd squashfs-tools", log)
        self.assertIn("pacman -Rns --noconfirm snapd", self.stubs.calls())
        self.assertEqual(list(self.prefs.iterdir()), [])            # no apt pin

    def test_desnap_only(self):
        self.populate()
        code, log = self.desnap("--yes", "--only", "chat")
        self.assertEqual(code, 0, log)
        self.assertEqual(self.stubs.installed(), ["com.example.Chat"])
        code, log = self.desnap("--yes", "--only", "nope")
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
