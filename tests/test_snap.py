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
from debpak.desnap import PIN_NAME, copy_data, installed_snaps
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

    def test_not_an_app_snap(self):
        with tempfile.TemporaryDirectory() as t:
            cur = make_snap(Path(t) / "snap", "core22", kind="base")
            with self.assertRaises(PackageError):
                extract_snap(cur, Path(t) / "work")

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


