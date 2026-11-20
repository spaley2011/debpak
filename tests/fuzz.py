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


def seeds_winzip(tmp: Path) -> list[bytes]:
    pe = seeds_pe(tmp)[0]
    return [_zip({"App/app.exe": pe, "App/resources/app.asar": seeds_asar(tmp)[0]}),
            _zip({"AppxManifest.xml": b'<Package><Identity Name="A" Version="1.0.0.0"/><Applications>'
                                      b'<Application Executable="a.exe"/></Applications></Package>', "a.exe": pe})]


def seeds_icns(tmp: Path) -> list[bytes]:
    from fixtures import tiny_png
    png = tiny_png(16)
    body = b"ic08" + struct.pack(">I", 8 + len(png)) + png
    return [b"icns" + struct.pack(">I", 8 + len(body)) + body]


def seeds_tgz(tmp: Path) -> list[bytes]:
    return [_tar({"package/package.json": b"{}", "package/prebuilds/linux-x64/a.node": b"\x7fELF" + bytes(60)})]


def seeds_json(tmp: Path) -> list[bytes]:
    return [json.dumps({"source": "in.zip", "steps": [{"kind": "zip"}], "take": "x", "target": "t",
                        "drop": ["y"], "natives": []}).encode()]


# --------------------------------------------------------------------------- targets

def escaped(root: Path, allowed: Path) -> list[str]:
    """Paths under root outside allowed (other than the input), and symlinks under allowed that leave it."""
    bad = []
    for dirpath, dirnames, filenames in os.walk(root):
        for n in dirnames + filenames:
            p = Path(dirpath) / n
            if p.is_symlink() and str(allowed) in str(p):
                target = (p.parent / os.readlink(p)).resolve()
                if not str(target).startswith(str(allowed.resolve())):
                    bad.append(f"symlink {p.relative_to(root)} -> {os.readlink(p)}")
    for p in root.iterdir():
        if p.name not in ("input", allowed.name, "seed-tmp"):
            bad.append(f"wrote {p.name} outside the destination")
    return bad


def run_asar(path: Path, tmp: Path):
    a = asar.Asar(path)
    for p, e in a.walk():
        if "link" not in e:
            try:
                a.read(p)
            except KeyError:
                pass
        a.head(p)


def run_asar_edit(path: Path, tmp: Path):
    a = asar.Asar(path)
    entries = [p for p, e in a.walk()][:3]
    unpack.asar_edit(path, unpack=entries[:1], add=["new/x.node", "../escape"][: 1 + (len(entries) % 2)])


def run_pe(path: Path, tmp: Path):
    read_pe(path)


def run_winres(path: Path, tmp: Path):
    winres.version_strings(path)
    winres.extract_png(path)
    try:
        winres.icon_images(path)
    except PeError:
        pass
    unpack.squirrel_nupkg(path.read_bytes())


def run_macho(path: Path, tmp: Path):
    read_macho(path)


def run_elf(path: Path, tmp: Path):
    read_elf(path)


def run_open(path: Path, tmp: Path):
    """detect_format + open_package into tmp/out (the extraction the CLI does)."""
    packages.open_package(path, tmp / "out")


def run_foreign_detect(path: Path, tmp: Path):
    foreign.detect(path)


def run_icns(path: Path, tmp: Path):
    foreign.icns_png(path)


def run_tgz(path: Path, tmp: Path):
    natives._tgz_members(path.read_bytes())


def run_unpack_plan(path: Path, tmp: Path):
    """A hostile plan for debpak-unpack: it must not write outside its working folder."""
    try:
        plan = json.loads(path.read_bytes())
    except (ValueError, UnicodeDecodeError):
        return
    if not isinstance(plan, dict):
        return
    cwd = tmp / "out"
    cwd.mkdir(exist_ok=True)
    (cwd / "in.zip").write_bytes(_zip({"x/a": b"a", "x/y/b": b"b"}))
    plan.setdefault("source", "in.zip")
    unpack.apply(plan, cwd)


def run_recipe(path: Path, tmp: Path):
    """A hostile recipe collection: download() must only write under its destination."""
    coll = tmp / "seed-tmp" / "coll"
    if coll.exists():
        shutil.rmtree(coll)
    (coll / "a.b.C/app/bin").mkdir(parents=True)
    (coll / "a.b.C/a.b.C.json").write_text(json.dumps({"id": "a.b.C", "modules": [{"name": "m", "sources": [
        {"type": "dir", "path": "app"}, {"type": "extra-data", "url": "u", "sha256": "0", "size": 1}]}]}))
    (coll / "a.b.C/app/bin/x").write_text("x")
    try:
        rj = json.loads(path.read_bytes())
    except (ValueError, UnicodeDecodeError):
        return
    data = json.dumps(rj).encode()
    (coll / "a.b.C/recipe.json").write_bytes(data)
    import hashlib
    entry = {"id": rj.get("id", "a.b.C") if isinstance(rj, dict) else "a.b.C",
             "recipe_sha256": hashlib.sha256(data).hexdigest()}
    if not isinstance(entry["id"], str):
        return
    recipes.download(str(coll), entry, tmp / "out")


def seeds_recipe(tmp: Path) -> list[bytes]:
    import hashlib
    files = {"a.b.C.json": None, "app/bin/x": "x"}
    m = json.dumps({"id": "a.b.C", "modules": [{"name": "m", "sources": [
        {"type": "dir", "path": "app"}, {"type": "extra-data", "url": "u", "sha256": "0", "size": 1}]}]})
    files["a.b.C.json"] = m
    return [json.dumps({"schema": 1, "id": "a.b.C", "files": {k: hashlib.sha256(v.encode()).hexdigest()
                                                            for k, v in files.items()}}).encode()]


# name: (seeds, run, allowed exceptions, extracts files)
TARGETS = {
    "asar": (seeds_asar, run_asar, (asar.AsarError,), False),
    "asar-edit": (seeds_asar, run_asar_edit, (asar.AsarError, unpack.UnpackError), False),
    "pe": (seeds_pe, run_pe, (PeError,), False),
    "winres": (seeds_pe, run_winres, (), False),
    "macho": (seeds_macho, run_macho, (MachOError,), False),
    "elf": (seeds_elf, run_elf, (ElfError,), False),
    "deb": (seeds_deb, run_open, (PackageError, DebError), True),
    "rpm": (seeds_rpm, run_open, (PackageError,), True),
    "tarball": (seeds_tarball, run_open, (PackageError,), True),
    "run": (seeds_makeself, run_open, (PackageError,), True),
    "windows-zip": (seeds_winzip, run_open, (PackageError,), True),
    "detect": (seeds_pe, run_foreign_detect, (), False),
    "icns": (seeds_icns, run_icns, (), False),
    "npm-tarball": (seeds_tgz, run_tgz, (tarfile.TarError, EOFError, OSError), False),
    "unpack-plan": (seeds_json, run_unpack_plan, (unpack.UnpackError, KeyError, zipfile.BadZipFile), True),
    "recipe": (seeds_recipe, run_recipe, (recipes.RecipeError,), True),
}
SUFFIX = {"deb": ".deb", "rpm": ".rpm", "tarball": ".tar.gz", "run": ".run", "windows-zip": ".zip",
          "icns": ".icns", "asar": ".asar", "asar-edit": ".asar"}


class Hang(Exception):
    pass


