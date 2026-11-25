"""Pin down edge cases of stage.py, deb.py and rpm.py that the conversion tests don't reach."""
from __future__ import annotations

import bz2
import gzip
import io
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from debpak import rpm
from debpak.deb import DebError, extract, parse_control, resolve_in_root
from debpak.stage import _copy_payload, _unreachable_lib_dirs


def _ar(members: list[tuple[str, bytes]]) -> bytes:
    out = b"!<arch>\n"
    for name, data in members:
        out += f"{name:<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(data):<10}`\n".encode() + data
        out += b"\n" if len(data) & 1 else b""
    return out


def _tar(files: dict[str, bytes]) -> bytes:
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return bio.getvalue()


class ResolveInRootTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()
        (self.root / "usr/lib").mkdir(parents=True)
        (self.root / "usr/lib/libx.so.1").write_text("x")
        links = {"lib": "usr/lib", "abs": "/usr/lib/libx.so.1", "loop": "loop", "up": "../../..",
                 "c0": "c1", "c1": "c2", "c2": "usr/lib/libx.so.1"}
        for k, v in links.items():
            (self.root / k).symlink_to(v)

    def tearDown(self):
        self._tmp.cleanup()

    def rel(self, path: str, hops: int = 40):
        r = resolve_in_root(self.root, path, hops)
        return None if r is None else r.relative_to(self.root).as_posix()

    def test_links_dots_and_limits(self):
        self.assertEqual(self.rel("lib/libx.so.1"), "usr/lib/libx.so.1")
        self.assertEqual(self.rel("/abs"), "usr/lib/libx.so.1")
        self.assertEqual(self.rel("../../usr/./lib/../lib/libx.so.1"), "usr/lib/libx.so.1")   # never above root
        self.assertEqual(self.rel("up/usr"), "usr")
        self.assertEqual(self.rel(""), ".")
        self.assertIsNone(self.rel("loop"))
        self.assertIsNone(self.rel("usr/missing"))
        self.assertEqual(self.rel("c0", 3), "usr/lib/libx.so.1")
        self.assertIsNone(self.rel("c0", 2))


class ParseControlTests(unittest.TestCase):
    def test_stanza_edges(self):
        # a blank line only ends the stanza once a field was read
        self.assertEqual(parse_control("garbage\n\nPackage: q\n\nPackage: r\n"), {"Package": "q"})
        # a continuation before any field is a field line if it has a colon, else ignored
        self.assertEqual(parse_control(" Lead: v\n cont\n"), {"Lead": "v\ncont"})
        self.assertEqual(parse_control(" nothing\nA: 1\n\t.\n\tx\n"), {"A": "1\n\nx"})
        self.assertEqual(parse_control("Multi: a:b\nnocolon\n"), {"Multi": "a:b"})


class DebCompressionTests(unittest.TestCase):
    def test_bz2_member_and_unsupported(self):
        ctrl = _tar({"./control": b"Package: hand\nVersion: 1\n"})
        data = _tar({"./usr/bin/hand": b"#!/bin/sh\n"})
        with tempfile.TemporaryDirectory() as t:
            ok = Path(t) / "ok.deb"
            ok.write_bytes(_ar([("debian-binary", b"2.0\n"), ("control.tar.bz2", bz2.compress(ctrl)),
                                ("data.tar", data)]))
            pkg = extract(ok, Path(t) / "ok")
            self.assertEqual((pkg.name, pkg.version), ("hand", "1"))
            self.assertTrue((pkg.root / "usr/bin/hand").is_file())
            bad = Path(t) / "bad.deb"
            bad.write_bytes(_ar([("debian-binary", b"2.0\n"), ("control.tar.gz", gzip.compress(ctrl)),
                                 ("data.tar.lz4", b"xxxx")]))
            with self.assertRaises(DebError) as cm:
                extract(bad, Path(t) / "bad")
            self.assertEqual(str(cm.exception), "unsupported compression for data.tar.lz4")


class CopyPayloadTests(unittest.TestCase):
    def test_links_and_left_out_files(self):
        with tempfile.TemporaryDirectory() as t:
            root, dest = Path(t) / "root", Path(t) / "app"
            for f in ("usr/bin/app", "opt/My App/bin/prog", "usr/share/applications/app.desktop",
                      "usr/share/applications/readme", "usr/lib/systemd/system/x.service", "usr/lib/x/data"):
                (root / f).parent.mkdir(parents=True, exist_ok=True)
                (root / f).write_text(f)
            links = {"usr/bin/prog": "../../opt/My App/bin/prog", "usr/bin/abs": "/opt/My App/bin/prog",
                     "usr/bin/sys": "/lib64/ld-linux-x86-64.so.2", "usr/bin/esc": "../../../outside",
                     "usr/libdir": "lib/x", "usr/bin/app2": "app"}
            for k, v in links.items():
                (root / k).symlink_to(v)
            (dest / "bin").mkdir(parents=True)
            (dest / "bin/app2").write_text("replaced")
            _copy_payload(root, dest)
            self.assertEqual(os.readlink(dest / "bin/prog"), "../opt/My-App/bin/prog")
            self.assertEqual(os.readlink(dest / "bin/abs"), "../opt/My-App/bin/prog")
            self.assertEqual(os.readlink(dest / "bin/sys"), "/lib64/ld-linux-x86-64.so.2")
            self.assertEqual(os.readlink(dest / "libdir"), "lib/x")       # a symlinked folder stays a link
            self.assertEqual(os.readlink(dest / "bin/app2"), "app")
            self.assertFalse((dest / "bin/esc").is_symlink())
            self.assertFalse((dest / "share/applications/app.desktop").exists())
            self.assertTrue((dest / "share/applications/readme").is_file())
            self.assertFalse((dest / "lib/systemd").exists())


class UnreachableLibDirsTests(unittest.TestCase):
    def test_plugin_needs_outside_its_runpath(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            for d in ("opt/A", "opt/A/plugins", "opt/A/lib"):
                (root / d).mkdir(parents=True, exist_ok=True)

            def elf(needed, runpath=(), exe=False):
                return SimpleNamespace(needed=list(needed), rpath=[], runpath=list(runpath), is_executable=exe)
            a = SimpleNamespace(root=root, main_exec="opt/A/app", elfs={
                "opt/A/app": elf(["libQt5Core.so.5"], ["$ORIGIN/lib"], exe=True),
                "opt/A/lib/libQt5Core.so.5": elf([]),
                "opt/A/plugins/libqxcb.so": elf(["libQt5XcbQpa.so.5", "libQt5Core.so.5", "libstdc++.so.6"]),
                "opt/A/libQt5XcbQpa.so.5": elf([]),
            }, package_sonames={"libQt5Core.so.5": "opt/A/lib/libQt5Core.so.5", "libQt5XcbQpa.so.5":
                                "opt/A/libQt5XcbQpa.so.5", "libstdc++.so.6": "opt/A/lib/libstdc++.so.6"})
            # libQt5Core is already loaded by the program; the toolchain is the runtime's
            self.assertEqual(_unreachable_lib_dirs(a), {"opt/A"})


class RpmScriptsTests(unittest.TestCase):
    def test_interpreters_trans_and_triggers(self):
        info = rpm.RpmInfo.__new__(rpm.RpmInfo)
        info.tags = {rpm.PREIN: "echo pre", rpm.PREINPROG: ["/bin/bash"],
                     rpm.POSTIN: "print(1)", rpm.POSTINPROG: "<lua>",
                     rpm.PREUN: "x", rpm.PREUNPROG: "sh",
                     rpm.POSTUNPROG: ["<lua>"],
                     rpm.PRETRANS: "pt", rpm.POSTTRANS: "", rpm.TRIGGERSCRIPTS: ["t"]}
        out, notes = info.scripts()
        self.assertEqual(out, {"preinst": "#!/bin/bash\necho pre", "postinst": "print(1)\n# %pretrans\npt",
                               "prerm": "x"})
        self.assertEqual(notes, ["postinst scriptlet is Lua (run inside rpm); reviewed as text only",
                                 "postrm scriptlet is Lua (run inside rpm); reviewed as text only",
                                 "package has rpm triggers (scripts run when other packages change); "
                                 "a Flatpak can't run them"])


if __name__ == "__main__":
    unittest.main()
