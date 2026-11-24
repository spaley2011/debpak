"""Snaps: reading snap.yaml, converting an installed snap, the Flathub check,
the apps registry (list/update/uninstall) and `debpak desnap`.

Every outside tool (flatpak, flatpak-builder, snap, sudo, apt-get, dpkg-query)
is a stand-in script that logs its arguments, so nothing on the test machine
changes."""
import contextlib
import io
import json
import os
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
    # flatpak-builder: "installs" the manifest's app id
    "flatpak-builder": r"""
        #!/bin/sh
        echo "flatpak-builder $*" >> "$STUB_LOG"
        for a; do m="$a"; done
        python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$m" >> "$STUB_STATE/installed"
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
            pkg = extract_snap(cur, t / "work")
            snap_dir = pkg.root / "opt/tool"
            r = subprocess.run([str(snap_dir / ".debpak-snap/tool")], capture_output=True, text=True,
                               env={**os.environ, "XDG_DATA_HOME": str(t / "data"),
                                    "LD_LIBRARY_PATH": "/app/lib/debpak"})
            self.assertEqual(r.stdout.strip(), f"{snap_dir}/lib:{snap_dir}/usr/lib:/app/lib/debpak", r.stderr)

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
