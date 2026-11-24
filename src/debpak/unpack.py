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
                  "asar_unpack": "x.node"}]}         (or "asar_add" for a file the archive lacks)

Step kinds: zip, 7z (with an optional inner archive or disk image to open
next, and an optional offset where the archive starts, for a 7-Zip
self-extractor), squirrel (the .nupkg inside a Setup.exe), copy (a portable
.exe), makeself (offset and size of the tar payload).
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
import zlib
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
            # Zips made on Windows by some tools (Flow Launcher's, PowerShell 5's Compress-Archive)
            # separate folders with backslashes, which the zip format doesn't allow; read them as
            # folders rather than file names with backslashes in them
            info.filename = info.filename.replace("\\", "/")
            if not info.filename.strip("/") or "\0" in info.filename:
                continue                    # an entry with no usable name
            if info.flag_bits & 0x1:
                raise UnpackError(f"{Path(path).name}: {info.filename} is encrypted")
            target = dest / info.filename
            if not _inside(dest, target):
                raise UnpackError(f"{Path(path).name}: unsafe path {info.filename!r}")
            mode = info.external_attr >> 16
            if (mode & 0o170000) == 0o120000:
                continue
            try:
                z.extract(info, dest)
            except ValueError as e:
                raise UnpackError(f"{Path(path).name}: bad entry {info.filename!r} ({e})") from e
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


# ----------------------------------------------------------------- 7-Zip self-extractors

SEVEN_ZIP_MAGIC = b"7z\xbc\xaf\x27\x1c"


def _pe_end(f) -> int | None:
    """Return where a PE file's image ends (the end of its last section's data), or None if it isn't one."""
    f.seek(0)
    head = f.read(4096)
    try:
        if head[:2] != b"MZ":
            return None
        pe = struct.unpack_from("<I", head, 0x3C)[0]
        if pe > 1 << 20:
            return None
        f.seek(pe)
        hdr = f.read(24)
        if hdr[:4] != b"PE\0\0":
            return None
        nsec, opt_size = struct.unpack_from("<H", hdr, 6)[0], struct.unpack_from("<H", hdr, 20)[0]
        f.seek(pe + 24 + opt_size)
        table = f.read(40 * nsec)
        end = 0
        for i in range(nsec):
            rawsize, rawptr = struct.unpack_from("<II", table, 40 * i + 16)
            if rawsize:
                end = max(end, rawptr + rawsize)
        return end
    except struct.error:
        return None


def sfx_7z_offset(path: Path, limit: int = 1 << 20) -> int | None:
    """Return where the 7z archive of a 7-Zip self-extractor starts, or None if path isn't one.

    7-Zip's own installer and installers made with 7zS.sfx are a small PE
    program followed by a 7z archive (7zS.sfx puts a text config between
    them). The archive is looked for after the PE image only, since the
    program itself holds the signature as a constant, and its start header's
    CRC must match. limit caps how far past the image to look.
    """
    with open(path, "rb") as f:
        end = _pe_end(f)
        if end is None:
            return None
        f.seek(end)
        data = f.read(limit)
    pos = data.find(SEVEN_ZIP_MAGIC)
    while pos != -1:
        header = data[pos:pos + 32]
        if len(header) == 32 and header[6] == 0 and \
                zlib.crc32(header[12:32]) & 0xFFFFFFFF == struct.unpack_from("<I", header, 8)[0]:
            return end + pos
        pos = data.find(SEVEN_ZIP_MAGIC, pos + 1)
    return None


RAR_MAGIC = (b"Rar!\x1a\x07\x01\x00", b"Rar!\x1a\x07\x00")


def sfx_rar(path: Path, limit: int = 1 << 20) -> bool:
    """Return whether path is a RAR self-extractor (WinRAR's own installer is one).

    Like a 7-Zip self-extractor, it's a PE program followed by the archive;
    7z reads such a file directly when it has its RAR codec.
    """
    with open(path, "rb") as f:
        end = _pe_end(f)
        if end is None:
            return False
        f.seek(end)
        data = f.read(limit)
    return any(m in data for m in RAR_MAGIC)


def cut_7z(path: Path, offset: int, dest: Path) -> None:
    """Copy the 7z archive that starts at offset in path into dest.

    The archive's length comes from its start header (32 bytes, then the
    next header's offset and size), so whatever follows it, such as an
    Authenticode signature, is left out; 7z would warn about it and fail.

    Raises:
        UnpackError: There's no 7z archive at offset, or the file ends before the archive does.
    """
    with open(path, "rb") as f:
        f.seek(offset)
        header = f.read(32)
        if len(header) < 32 or header[:6] != SEVEN_ZIP_MAGIC:
            raise UnpackError(f"no 7z archive at offset {offset}")
        next_offset, next_size = struct.unpack_from("<QQ", header, 12)
        left = 32 + next_offset + next_size
        with open(dest, "wb") as out:
            out.write(header)
            left -= 32
            while left:
                chunk = f.read(min(left, 1 << 20))
                if not chunk:
                    raise UnpackError("the 7z archive is cut short")
                out.write(chunk)
                left -= len(chunk)


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
            blob = bytes(data[o:o + size])
            if blob[:2] != b"PK":
                continue
            # A .nupkg has a .nuspec at its top. Squirrel's releasify wraps it once more: the
            # resource is a zip of Update.exe and APP-VERSION-full.nupkg (GitHub Desktop, Figma),
            # and that inner package is the app. Read the zip's listing; searching the bytes for
            # ".nuspec" would also find a stored inner package's name.
            try:
                with zipfile.ZipFile(io.BytesIO(blob)) as z:
                    names = z.namelist()
                    if any(n.lower().endswith(".nuspec") and "/" not in n for n in names):
                        return blob
                    pkgs = sorted((n for n in names if n.lower().endswith(".nupkg") and "/" not in n),
                                  key=lambda n: (not n.lower().endswith("-full.nupkg"), n))
                    for n in pkgs:
                        if z.getinfo(n).file_size > 4 << 30:
                            continue
                        inner = z.read(n)
                        with zipfile.ZipFile(io.BytesIO(inner)) as iz:
                            if any(m.lower().endswith(".nuspec") and "/" not in m for m in iz.namelist()):
                                return inner
            except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, ValueError, NotImplementedError, EOFError,
                    RuntimeError, KeyError, struct.error, zlib.error):
                continue                                # damaged or encrypted: not a Squirrel package
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


def makeself(path: Path, offset: int, size: int, dest: Path) -> None:
    """Extract the tar payload of a Makeself installer (size bytes at offset).

    Raises:
        UnpackError: The file is shorter than the payload, or it's compressed with zstd.
    """
    with open(path, "rb") as f:
        f.seek(offset)
        payload = f.read(size)
    if len(payload) != size:
        raise UnpackError(f"payload is {len(payload)} bytes, expected {size}")
    if payload[:4] == b"\x28\xb5\x2f\xfd":
        raise UnpackError("zstd-compressed payload")
    untar(io.BytesIO(payload), dest)


# ----------------------------------------------------------------- plans

def unpack(source: Path, steps: list[dict], work: Path) -> Path:
    """Run unpacking steps on source inside work; return the folder holding the result.

    Raises:
        UnpackError: A step fails or names an unknown kind.
    """
    current = source
    out = work
    work.mkdir(parents=True, exist_ok=True)
    for i, step in enumerate(steps):
        out = work / f"step{i}"
        kind = step.get("kind")
        if kind == "zip":
            unzip(current, out)
        elif kind == "7z":
            if step.get("offset"):
                # a self-extractor: 7z reads the archive cut from the end of the .exe
                part = work / f"step{i}.7z"
                cut_7z(current, int(step["offset"]), part)
                run_7z(part, out)
                part.unlink()
            else:
                run_7z(current, out)
        elif kind == "squirrel":
            blob = squirrel_nupkg(Path(current).read_bytes())
            if blob is None:
                raise UnpackError("no .nupkg in this Setup.exe")
            nupkg = work / "setup.nupkg"
            nupkg.write_bytes(blob)
            unzip(nupkg, out)
        elif kind == "copy":
            out.mkdir(parents=True)
            shutil.copy2(current, out / step["name"])
        elif kind == "makeself":
            makeself(current, int(step["offset"]), int(step["size"]), out)
        else:
            raise UnpackError(f"unknown step {kind!r}")
        inner = step.get("inner")
        if inner:
            nxt = out / inner
            if not _inside(out, nxt) or not nxt.is_file():
                raise UnpackError(f"{inner} isn't in the unpacked files")
            current = nxt
        elif i + 1 < len(steps):
            raise UnpackError("only the last step may leave a folder")
    return out


def apply(plan: dict, cwd: Path) -> None:
    """Carry out a plan in cwd (apply_extra runs in /app/extra): unpack, keep one folder, patch, clean up.

    Raises:
        UnpackError: The plan can't be carried out.
    """
    name = plan.get("source")
    if not isinstance(name, str) or not name or "/" in name or name in (".", ".."):
        raise UnpackError(f"source must be a file name in {cwd}, not {name!r}")
    source = cwd / name
    if not source.is_file():
        raise UnpackError(f"{name} isn't in {cwd} (did Flatpak download it?)")
    if not isinstance(plan.get("steps"), list) or not all(isinstance(st, dict) for st in plan["steps"]):
        raise UnpackError("steps must be a list of objects")
    work = cwd / ".debpak-unpack"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir()
    try:
        if not isinstance(plan.get("target"), str) or not isinstance(plan.get("take", ""), str):
            raise UnpackError("take and target must be paths")
        tree = unpack(source, plan["steps"], work)
        take = tree / plan.get("take", "")
        target = cwd / plan["target"]
        if target.resolve() == cwd.resolve():
            raise UnpackError("target can't be the working folder itself")
        if not _inside(tree, take) or not take.exists():
            raise UnpackError(f"{plan.get('take')!r} isn't in the unpacked files")
        if not _inside(cwd, target):
            raise UnpackError(f"target {plan['target']!r} is outside {cwd}")
        if target.exists():
            shutil.rmtree(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(take), str(target))
        for rel in plan.get("drop", []):
            if not isinstance(rel, str):
                raise UnpackError("drop must be a list of paths")
            p = target / rel
            if _inside(target, p):
                if p.is_dir() and not p.is_symlink():
                    shutil.rmtree(p)
                elif p.exists() or p.is_symlink():
                    p.unlink()
        unpack_in_asar, add_to_asar = [], []
        for n in plan.get("natives", []):
            if not (isinstance(n, dict) and isinstance(n.get("to"), str) and isinstance(n.get("from"), str)):
                raise UnpackError("each native entry needs from and to paths")
            dest = target / n["to"]
            if not _inside(target, dest):
                raise UnpackError(f"native module target {n['to']!r} is outside {target}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists():
                dest.unlink()
            shutil.copy2(n["from"], dest)
            if n.get("asar_unpack"):
                unpack_in_asar.append(n["asar_unpack"])
            if n.get("asar_add"):
                add_to_asar.append(n["asar_add"])
        if unpack_in_asar or add_to_asar:
            asar_edit(target / "app.asar", unpack=unpack_in_asar, add=add_to_asar)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if plan.get("remove_source", True) and source.exists():
        source.unlink()


def asar_mark_unpacked(path: Path, entries: list[str]) -> None:
    """Rewrite an app.asar header so the given files load from app.asar.unpacked (see asar_edit)."""
    asar_edit(path, unpack=entries)


def asar_edit(path: Path, unpack: list[str] = (), add: list[str] = ()) -> None:
    """Rewrite an app.asar header; the file data is copied unchanged.

    Args:
        unpack: Existing entries to load from app.asar.unpacked from now on.
        add: New entries for files already placed in app.asar.unpacked, with
            any folders they need.

    Each changed entry's size is set from the file in app.asar.unpacked, and
    its integrity hash (which described the archived file) is dropped.

    Raises:
        UnpackError: The archive's header can't be read, an entry to unpack
            isn't in it, or a path to add would replace a folder.
    """
    real_root = path.with_name(path.name + ".unpacked")
    with open(path, "rb") as f:
        four, size, _payload, json_len = struct.unpack("<IIII", f.read(16))
        if four != 4 or json_len > size:
            raise UnpackError(f"{path.name}: not an asar archive")
        header = json.loads(f.read(json_len).decode("utf-8"))
        data_offset = 8 + size
        for p, create in [(p, False) for p in unpack] + [(p, True) for p in add]:
            parts = [x for x in p.split("/") if x]
            if not parts or any(x in (".", "..") for x in parts):
                raise UnpackError(f"bad asar path {p!r}")
            node = header
            for part in parts[:-1]:
                files = node.setdefault("files", {}) if create else node.get("files", {})
                if part not in files:
                    if not create:
                        raise UnpackError(f"{p} isn't in {path.name}")
                    files[part] = {"files": {}}
                node = files[part]
                if "files" not in node:
                    raise UnpackError(f"{p}: {part} is a file in {path.name}")
            files = node.setdefault("files", {}) if create else node.get("files", {})
            leaf = files.get(parts[-1])
            if leaf is None:
                if not create:
                    raise UnpackError(f"{p} isn't in {path.name}")
                leaf = files[parts[-1]] = {}
            elif "files" in leaf:
                raise UnpackError(f"{p} is a folder in {path.name}")
            leaf.pop("offset", None)
            leaf.pop("integrity", None)
            leaf["unpacked"] = True
            real = real_root / "/".join(parts)
            if real.is_file():
                leaf["size"] = real.stat().st_size
        js = json.dumps(header, separators=(",", ":")).encode()
        padded = js + b"\0" * (-len(js) % 4)
        pickle = struct.pack("<II", 4 + len(padded), len(js)) + padded
        tmp = path.with_name(path.name + ".new")
        with open(tmp, "wb") as out:
            out.write(struct.pack("<II", 4, len(pickle)) + pickle)
            f.seek(data_offset)
            shutil.copyfileobj(f, out)
    tmp.replace(path)


def install_helper(app: Path, plan: dict) -> None:
    """Put this file into a staged /app tree as bin/debpak-unpack, with the plan as share/debpak/unpack.json."""
    (app / "bin").mkdir(parents=True, exist_ok=True)
    helper = app / "bin" / "debpak-unpack"
    shutil.copyfile(Path(__file__), helper)
    helper.chmod(0o755)
    (app / "share" / "debpak").mkdir(parents=True, exist_ok=True)
    (app / "share" / "debpak" / "unpack.json").write_text(json.dumps(plan, indent=2) + "\n")


APPLY_EXTRA = """#!/bin/sh
# Generated by debpak: unpack the downloaded file the way the conversion did.
set -e
python3 /app/bin/debpak-unpack /app/share/debpak/unpack.json
"""


def main(argv: list[str]) -> int:
    """debpak-unpack PLAN.json: carry out the plan in the current folder."""
    if len(argv) != 1:
        print("usage: debpak-unpack PLAN.json", file=sys.stderr)
        return 2
    try:
        apply(json.loads(Path(argv[0]).read_text()), Path.cwd())
    except (UnpackError, OSError, KeyError, ValueError, zipfile.BadZipFile, tarfile.TarError) as e:
        print(f"debpak-unpack: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
