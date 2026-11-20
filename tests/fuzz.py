#!/usr/bin/env python3
"""Fuzz debpak's readers of untrusted files.

Every target starts from valid samples built by the test fixtures, mutates
them (flipped bits, overwritten bytes, boundary integers, cut or spliced
data) and feeds them to a parser. A target lists the exceptions its parser
is documented to raise; anything else is a bug, and so is a call that runs
longer than the time limit. Targets that extract files also check that
nothing was written outside the destination folder and that no extracted
symlink points out of it.

    tests/fuzz.py                       every target, 2000 cases each
    tests/fuzz.py --only asar -n 50000  one target, longer
    tests/fuzz.py --save findings/      keep the inputs that failed

tests/test_fuzz.py runs a few hundred cases per target with a fixed seed on
every test run.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import random
import shutil
import signal
import struct
import sys
import tarfile
import tempfile
import traceback
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent / "src"), str(HERE), str(HERE / "integration")]

from debpak import asar, foreign, natives, packages, recipes, unpack, winres  # noqa: E402
from debpak.deb import DebError  # noqa: E402
from debpak.elf import ElfError, read_elf  # noqa: E402
from debpak.macho import MachOError, read_macho  # noqa: E402
from debpak.packages import PackageError  # noqa: E402
from debpak.pe import PeError, read_pe  # noqa: E402

TIME_LIMIT = 10


# --------------------------------------------------------------------------- mutation

INTERESTING = [0, 1, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]


def mutate(data: bytes, rng: random.Random) -> bytes:
    """Return data with one to four random mutations."""
    b = bytearray(data)
    for _ in range(rng.randint(1, 4)):
        if not b:
            b += bytes(rng.randrange(256) for _ in range(rng.randint(1, 64)))
            continue
        op = rng.randrange(7)
        i = rng.randrange(len(b))
        if op == 0:                                    # flip a bit
            b[i] ^= 1 << rng.randrange(8)
        elif op == 1:                                  # random byte
            b[i] = rng.randrange(256)
        elif op == 2 and len(b) >= 4:                  # boundary 32-bit integer
            i = rng.randrange(0, len(b) - 3) & ~3
            b[i:i + 4] = struct.pack("<I", rng.choice(INTERESTING))
        elif op == 3 and len(b) >= 2:                  # boundary 16-bit integer
            i = rng.randrange(0, len(b) - 1)
            b[i:i + 2] = struct.pack("<H", rng.choice(INTERESTING) & 0xFFFF)
        elif op == 4:                                  # truncate
            del b[rng.randrange(len(b)):]
        elif op == 5:                                  # duplicate a slice somewhere else
            j = rng.randrange(len(b))
            chunk = b[i:i + rng.randint(1, 256)]
            b[j:j] = chunk
        else:                                          # delete a slice
            del b[i:i + rng.randint(1, 256)]
    return bytes(b)


# --------------------------------------------------------------------------- seeds

def _tar(files: dict[str, bytes], links: dict[str, str] | None = None, mode: str = "w:gz") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as t:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
        for name, target in (links or {}).items():
            info = tarfile.TarInfo(name)
            info.type, info.linkname = tarfile.SYMTYPE, target
            t.addfile(info)
    return buf.getvalue()


def _zip(files: dict[str, bytes], prefix: bytes = b"") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return prefix + buf.getvalue()


def seeds_asar(tmp: Path) -> list[bytes]:
    p = tmp / "seed.asar"
    asar.write_asar(p, {"package.json": b'{"name": "x"}', "a/b/c.js": b"x" * 100, "n.node": b"\x7fELF"})
    return [p.read_bytes()]


def seeds_pe(tmp: Path) -> list[bytes]:
    from debpak.pe_write import PeSpec, build_pe, icon_resources, version_info
    from fixtures import tiny_png
    nupkg = _zip({"a.nuspec": b"<package/>", "lib/net45/app.exe": b"MZ"})
    return [build_pe(PeSpec(is_dll=False, imports={"kernel32.dll": ["ExitProcess"], "user32.dll": ["MessageBoxW"]},
                            resources=[version_info({"ProductName": "Fuzz", "ProductVersion": "1.2.3"})]
                            + icon_resources(tiny_png(32), 32))),
            build_pe(PeSpec(is_dll=False, resources=[(10, 131, nupkg)])),
            build_pe(PeSpec(is_dll=True, exports=["f", "g"], arch="i386"))]


def seeds_macho(tmp: Path) -> list[bytes]:
    from compat_fixtures import build_macho
    return [build_macho(dylibs=[("/usr/lib/libSystem.B.dylib", "load")], undefined=[("_printf", 1, False)],
                        rpaths=["@executable_path/../Frameworks"])]


def seeds_elf(tmp: Path) -> list[bytes]:
    for cand in ("/bin/true", "/usr/bin/true"):
        if os.path.isfile(cand):
            return [Path(cand).read_bytes()]
    return []


def seeds_makeself(tmp: Path) -> list[bytes]:
    import samples
    d = tmp / "payload"
    d.mkdir(exist_ok=True)
    (d / "app").write_bytes(b"\x7fELF" + bytes(60))
    (d / "setup.sh").write_text("#!/bin/sh\necho hi\n")
    out = samples.build_makeself(tmp / "seed.run", d, "Fuzz 1.0")
    gog = b"#!/bin/sh\n# Makeself 2.4.0\n# MojoSetup\nexit 0\n" + _zip(
        {"data/noarch/gameinfo": b"Fuzz\n1.0\n", "data/noarch/game/fuzz": b"\x7fELF" + bytes(60)})
    return [out.read_bytes(), gog]


def seeds_deb(tmp: Path) -> list[bytes]:
    import samples
    p = samples.build_deb(tmp / "seed.deb", "fuzz", "1.0", {"usr/bin/fuzz": (b"\x7fELF" + bytes(60), 0o755),
                                                           "usr/share/applications/fuzz.desktop":
                                                           (b"[Desktop Entry]\nName=Fuzz\nExec=fuzz\n", 0o644)},
                          "fuzz")
    return [p.read_bytes()]


def seeds_rpm(tmp: Path) -> list[bytes]:
    from format_fixtures import build_rpm
    tree = tmp / "rpmtree"
    (tree / "usr/bin").mkdir(parents=True, exist_ok=True)
    (tree / "usr/bin/fuzz").write_bytes(b"\x7fELF" + bytes(60))
    return [build_rpm(tree, tmp / "seed.rpm", "fuzz").read_bytes()]


def seeds_tarball(tmp: Path) -> list[bytes]:
    return [_tar({"fuzz-1.0/bin/fuzz": b"\x7fELF" + bytes(60), "fuzz-1.0/fuzz.desktop": b"[Desktop Entry]\n"},
                 {"fuzz-1.0/lib": "../../etc"})]


