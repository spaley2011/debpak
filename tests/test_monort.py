"""Tests for the Mono runtime debpak adds to .NET apps that run under mono."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from debpak import monort, selfcheck
from debpak.pe_write import PeSpec, build_pe


def assembly(path: Path, type_refs=(), dll=False) -> None:
    path.write_bytes(build_pe(PeSpec(arch="i386", is_dll=dll, dotnet=True, type_refs=list(type_refs),
                                     imports={"mscoree.dll": ["_CorExeMain"]})))


class TestMono(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.root = Path(self.t.name)

    def tearDown(self):
        self.t.cleanup()

    def test_start_script_that_runs_mono(self):
        # BizHawk's EmuHawkMono.sh
        assembly(self.root / "EmuHawk.exe", [("System.Windows.Forms", "Form")])
        (self.root / "EmuHawkMono.sh").write_text(
            '#!/bin/sh\ncd "$(dirname "$0")"\nexport LD_LIBRARY_PATH="$PWD/dll"\n'
            'exec mono --debug EmuHawk.exe --mono-no-redirect "$@"\n')
        self.assertTrue(monort.needs_runtime(self.root, {}, "EmuHawkMono.sh"))
        s = monort.setup(self.root)
        self.assertEqual(s["extension"], "org.freedesktop.Sdk.Extension.mono6")
        self.assertIn("/usr/lib/sdk/mono6/install.sh $(ls /usr/lib/sdk/mono6/lib/mono/gac)", s["commands"])
        self.assertEqual(s["libraries"], ["libgdiplus.so.0"])

    def test_console_assembly_needs_no_gdiplus(self):
        assembly(self.root / "tool.exe", [("System.IO", "File")])
        self.assertTrue(monort.needs_runtime(self.root, {}, "tool.exe"))
        self.assertEqual(monort.setup(self.root)["libraries"], [])

    def test_bundled_mono_needs_none(self):
        (self.root / "run.sh").write_text("#!/bin/sh\nexec ./bin/mono App.exe\n")
        self.assertFalse(monort.needs_runtime(self.root, {"bin/mono": None}, "run.sh"))

    def test_script_without_mono_and_native_programs_need_none(self):
        (self.root / "run.sh").write_text("#!/bin/sh\n# monospace font\nexec ./app.bin\n")
        (self.root / "app").write_bytes(b"\x7fELF program")
        self.assertFalse(monort.needs_runtime(self.root, {}, "run.sh"))
        self.assertFalse(monort.needs_runtime(self.root, {"app": None}, "app"))

    def test_selfcheck_asks_for_mono(self):
        obs = selfcheck.Observation(False, 127, None, "./EmuHawkMono.sh: 30: mono: not found\n")
        d = selfcheck.diagnose(obs, "elf", False, set())
        self.assertEqual([r.key for r in d.remedies], ["mono"])
        args = SimpleNamespace()
        selfcheck.apply(args, d.remedies)
        self.assertTrue(args.mono)


if __name__ == "__main__":
    unittest.main()
