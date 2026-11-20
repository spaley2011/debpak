#!/usr/bin/env python3
"""Unpack a vendor's download the way a debpak conversion did.

This file has two jobs. debpak imports it to unpack installers while
converting. And in extra-data mode, debpak copies it into the Flatpak as
/app/bin/debpak-unpack, where apply_extra runs it at install time to repeat
those steps on the user's machine. So it must stay a single file that needs
nothing beyond Python's standard library, plus 7z when a step names it.

At install time it reads a plan (JSON) such as:

    {"source": "vendor.exe",                 file Flatpak downloaded, in the cwd
     "steps": [{"kind": "7z"}, {"kind": "7z", "inner": "$PLUGINSDIR/app-64.7z"}],
     "take": "resources",                    folder of the unpacked tree to keep
     "target": "resources",                  where it goes, relative to the cwd
     "drop": ["default_app.asar"],           paths under target to delete
     "natives": [{"from": "/app/share/debpak/natives/0", "to": "app.asar.unpacked/x.node",
                  "asar_unpack": "x.node"}]}

Step kinds: zip, 7z (with an optional inner archive or disk image to open
next), squirrel (the .nupkg inside a Setup.exe), copy (a portable .exe),
makeself (offset and size of the tar payload).
"""
from __future__ import annotations

import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path


class UnpackError(Exception):
    """A step that can't be carried out."""


def _inside(base: Path, target: Path) -> bool:
    """Return True if target, with symlinks resolved, is base or inside it."""
    base, target = base.resolve(), target.resolve()
    return target == base or str(target).startswith(str(base) + os.sep)


def unzip(path: Path, dest: Path) -> None:
    """Extract a zip (self-extracting ones too) into dest, keeping Unix modes.

    Symbolic links are skipped rather than written as small text files.

    Raises:
        UnpackError: An entry would land outside dest.
    """
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            target = dest / info.filename
            if not _inside(dest, target):
                raise UnpackError(f"{Path(path).name}: unsafe path {info.filename!r}")
            mode = info.external_attr >> 16
            if (mode & 0o170000) == 0o120000:
                continue
            z.extract(info, dest)
            if mode & 0o777 and not info.is_dir():
                os.chmod(target, mode & 0o777)


def drop_escaping_links(root: Path) -> None:
    """Delete symbolic links under root that point outside it, so nothing reads host files through them."""
    for dirpath, dirnames, filenames in os.walk(root):
        for n in dirnames + filenames:
            p = Path(dirpath) / n
            if p.is_symlink() and not _inside(root, p.parent / os.readlink(p)):
                p.unlink()


def seven_zip() -> str | None:
    """Return the 7-Zip command on PATH (7z, 7zz or 7za), or None."""
    for name in ("7z", "7zz", "7za"):
        found = shutil.which(name)
        if found:
            return found
    return None


def run_7z(path: Path, dest: Path) -> None:
    """Extract an archive or disk image with 7z, then drop symlinks that leave dest.

    Raises:
        UnpackError: 7z is missing or fails.
    """
    exe = seven_zip()
    if not exe:
        raise UnpackError("7z isn't installed")
    dest.mkdir(parents=True, exist_ok=True)
    r = subprocess.run([exe, "x", "-y", f"-o{dest}", str(path)], capture_output=True, text=True)
    if r.returncode != 0:
        tail = " / ".join((r.stderr or r.stdout).strip().splitlines()[-3:])
        raise UnpackError(f"7z failed: {tail or f'exit status {r.returncode}'}")
    drop_escaping_links(dest)


# ----------------------------------------------------------------- Squirrel: a zip in a PE resource

def _rva_to_offset(sections, rva: int) -> int:
    """Return the file offset of an RVA, from (va, size, rawptr, rawsize) section tuples."""
    for va, size, rawptr, rawsize in sections:
        if va <= rva < va + size:
            if rva - va >= rawsize:
                break
            return rawptr + rva - va
    raise UnpackError(f"RVA {rva:#x} not in the file")


def squirrel_nupkg(data: bytes) -> bytes | None:
    """Return the .nupkg (a zip holding a .nuspec) stored in a Squirrel Setup.exe's resources, or None."""
    try:
        if data[:2] != b"MZ":
            return None
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            return None
        nsec, opt_size = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
        opt = pe + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        dirs = opt + (112 if magic == 0x20B else 96)
        rsrc = struct.unpack_from("<I", data, dirs + 8 * 2)[0]
        sections = []
        for i in range(nsec):
            vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, opt + opt_size + 40 * i + 8)
            sections.append((va, max(vsize, rawsize), rawptr, rawsize))
        if not rsrc:
            return None
        blobs = []

        def walk(rva: int, depth: int) -> None:
            """Collect (data RVA, size) for every leaf of the resource tree."""
            off = _rva_to_offset(sections, rva)
            n = sum(struct.unpack_from("<HH", data, off + 12))
            for i in range(n):
                _name, target = struct.unpack_from("<II", data, off + 16 + 8 * i)
                if target & 0x80000000:
                    if depth < 2:
                        walk(rsrc + (target & 0x7FFFFFFF), depth + 1)
                else:
                    data_rva, size = struct.unpack_from("<II", data, _rva_to_offset(sections, rsrc + target))
                    blobs.append((data_rva, size))
        walk(rsrc, 0)
        for data_rva, size in blobs:
            o = _rva_to_offset(sections, data_rva)
            blob = data[o:o + size]
            if blob[:2] == b"PK" and b".nuspec" in blob[-65536:] + blob[:4096]:
                return bytes(blob)
    except (struct.error, IndexError, UnpackError):
        return None
    return None


# ----------------------------------------------------------------- Makeself payloads

def untar(fileobj, dest: Path) -> None:
    """Extract a (possibly compressed) tar stream into dest, refusing paths that escape it."""
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=fileobj, mode="r|*") as tf:
        for m in tf:
            if hasattr(tarfile, "tar_filter"):
                tf.extract(m, dest, filter="tar")
            else:  # pragma: no cover - Python before 3.12 without the backport
                if not _inside(dest, dest / m.name) or m.issym() or m.islnk():
                    continue
                tf.extract(m, dest)


