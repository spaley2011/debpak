#!/usr/bin/env python3
"""Unpack a vendor's download the way a debpak conversion did.

This file has two jobs. debpak imports it to unpack installers while
converting. And in extra-data mode, debpak copies it into the Flatpak as
/app/bin/debpak-unpack, where apply_extra runs it at install time to repeat
those steps on the user's machine. So it must stay a single file that needs
nothing beyond Python's standard library, plus 7z or bsdtar when a step names it.

At install time it reads a plan (JSON) such as:

    {"source": "vendor.exe",                 file Flatpak downloaded, in the cwd
     "steps": [{"kind": "7z"}, {"kind": "7z", "inner": "$PLUGINSDIR/app-64.7z"}],
     "take": "resources",                    folder of the unpacked tree to keep
     "target": "resources",                  where it goes, relative to the cwd
     "drop": ["default_app.asar"],           paths under target to delete
     "natives": [{"from": "/app/share/debpak/natives/0", "to": "app.asar.unpacked/x.node",
                  "asar_unpack": "x.node"}],         (or "asar_add" for a file the archive lacks)
     "main_shim": "..."}                     JavaScript to run before the app's main (install_main_shim)

Step kinds: zip, 7z (with an optional inner archive or disk image to open
next, and an optional offset where the archive starts, for a 7-Zip
self-extractor), bsdtar (a RAR self-extractor, which 7z can list but often
not decode, since distributions leave out its RAR codec; with an optional
offset where the archive starts), squirrel (the .nupkg
inside a Setup.exe), copy (a portable .exe), makeself (offset and size of the
tar payload).
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
from collections.abc import Iterator, Sequence
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
            _unzip_entry(z, info, path, dest)


def _unzip_entry(z: zipfile.ZipFile, info: zipfile.ZipInfo, path: Path, dest: Path) -> None:
    """Extract one entry of unzip's zip into dest, skipping nameless entries and symbolic links."""
    # Zips made on Windows by some tools (Flow Launcher's, PowerShell 5's Compress-Archive)
    # separate folders with backslashes, which the zip format doesn't allow; read them as
    # folders rather than file names with backslashes in them
    info.filename = info.filename.replace("\\", "/")
    if not info.filename.strip("/") or "\0" in info.filename:
        return                      # an entry with no usable name
    if info.flag_bits & 0x1:
        raise UnpackError(f"{Path(path).name}: {info.filename} is encrypted")
    target = dest / info.filename
    if not _inside(dest, target):
        raise UnpackError(f"{Path(path).name}: unsafe path {info.filename!r}")
    mode = info.external_attr >> 16
    if (mode & 0o170000) == 0o120000:
        return
    try:
        z.extract(info, dest)
    except ValueError as e:
        raise UnpackError(f"{Path(path).name}: bad entry {info.filename!r} ({e})") from e
    # only a zip made on Unix has Unix modes; a Windows tool's leaves stray bits there (mpv.net's
    # zip gives files 0o10 and 0o2, which nobody can read), and the owner must read and write
    if info.create_system == 3 and mode & 0o777 and not info.is_dir():
        os.chmod(target, (mode & 0o777) | 0o600)


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


def sfx_rar_offset(path: Path, limit: int = 1 << 20) -> int | None:
    """Return where the RAR archive of a RAR self-extractor starts, or None if path isn't one.

    WinRAR's own installer and EditPlus's are a PE program (WinRAR's SFX
    module) followed by a RAR archive. bsdtar reads the archive once it's cut
    from the program, but not always the whole .exe: it found no RAR header
    in EditPlus's epp610_0780_64bit.exe.
    """
    with open(path, "rb") as f:
        end = _pe_end(f)
        if end is None:
            return None
        f.seek(end)
        data = f.read(limit)
    found = [i for i in (data.find(m) for m in RAR_MAGIC) if i != -1]
    return end + min(found) if found else None


def sfx_rar(path: Path, limit: int = 1 << 20) -> bool:
    """Return whether path is a RAR self-extractor (sfx_rar_offset)."""
    return sfx_rar_offset(path, limit) is not None


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


# ----------------------------------------------------------------- WiX bundles (Burn)

BURN_MAGIC = 0x00F14300


def _burn_section(f) -> int | None:
    """Return where the .wixburn section of the open PE file f starts, or None if it has none."""
    f.seek(0)
    head = f.read(4096)
    try:
        if head[:2] != b"MZ":
            return None
        pe = struct.unpack_from("<I", head, 0x3C)[0]
        f.seek(pe)
        hdr = f.read(24)
        if hdr[:4] != b"PE\0\0":
            return None
        nsec, opt_size = struct.unpack_from("<H", hdr, 6)[0], struct.unpack_from("<H", hdr, 20)[0]
        f.seek(pe + 24 + opt_size)
        table = f.read(40 * nsec)
        return next((struct.unpack_from("<I", table, 40 * i + 20)[0] for i in range(nsec)
                     if table[40 * i:40 * i + 8] == b".wixburn"), None)
    except struct.error:
        return None


def is_burn_bundle(path: Path) -> bool:
    """Return whether path is a WiX bundle itself: a program with a .wixburn section.

    The name alone can be anywhere in a file: Rockstar Games Launcher's setup,
    an installer of its own making, carries the Visual C++ runtimes' bundles
    among its resources, and was run with /quiet /norestart as if it were one.
    """
    with open(path, "rb") as f:
        return _burn_section(f) is not None


def burn_containers(path: Path) -> list[tuple[int, int]] | None:
    """Return (offset, size) of each container a WiX bundle carries, or None if path isn't one.

    A Burn bundle's .wixburn section starts with a header: magic, version,
    bundle GUID, the size of the engine program (the stub), checksum and
    signature fields, the container format, then the count and size of the
    containers, which follow the stub in that order. The first holds the
    bundle's own interface and BurnManifest.xml (its file "0"); the second,
    when the bundle isn't a download stub, holds the packages. Both are
    cabinets. A signed bundle has its signature between the two (Foxit PDF
    Reader's), so each container after the first is the cabinet whose
    header gives its size, at or after where the one before it ends.
    """
    with open(path, "rb") as f:
        found = _burn_header(f)
        if found is None:
            return None
        stub, sizes = found
        out: list = []
        at = stub
        for size in sizes:
            start = _cabinet_at(f, at, size) if out else at
            if start is None:
                break
            out.append((start, size))
            at = start + size
    return out


def _burn_header(f) -> tuple[int, tuple[int, ...]] | None:
    """Return a WiX bundle's stub size and container sizes from its .wixburn header, or None if it isn't one."""
    rawptr = _burn_section(f)
    if rawptr is None:
        return None
    try:
        f.seek(rawptr)
        sec = f.read(4096)
        magic, _version, _guid, stub, *_rest, count = struct.unpack_from("<II16sIIIIII", sec)
        if magic != BURN_MAGIC or not 0 < count < 64:
            return None
        return stub, struct.unpack_from(f"<{count}I", sec, struct.calcsize("<II16sIIIIII"))
    except struct.error:
        return None


def _cabinet_at(f, at: int, size: int, limit: int = 1 << 20) -> int | None:
    """Return where the cabinet of the given size starts, at or within limit bytes after at, or None."""
    f.seek(at)
    data = f.read(limit + 12)
    i = data.find(b"MSCF\0\0\0\0")
    while i != -1:
        if struct.unpack_from("<I", data, i + 8)[0] == size:
            return at + i
        i = data.find(b"MSCF\0\0\0\0", i + 1)
    return None


def sfx_cabs(path: Path, limit: int = 64 << 20) -> list[tuple[int, int]]:
    """Return (offset, size) of each cabinet inside a program, the largest first.

    NCH Software's installers (WavePad, Express Scribe, ...) keep the whole
    program in a cabinet among their resources. Newer ones carry two: the
    program's (Doxillion.exe in doxpsetup.exe) and a larger one of the
    installer's own helpers (resource.dat), so each is worth a look. A
    cabinet's header has its signature, its size and version 1.3; only one
    that fits in the file counts.
    """
    total = path.stat().st_size
    found = []
    with open(path, "rb") as f:
        data = f.read(min(total, limit))
    i = data.find(b"MSCF\0\0\0\0")
    while i != -1:
        if i + 36 <= len(data):
            size = struct.unpack_from("<I", data, i + 8)[0]
            minor, major = data[i + 24], data[i + 25]
            if (major, minor) == (1, 3) and 36 < size <= total - i:
                found.append((i, size))
        i = data.find(b"MSCF\0\0\0\0", i + 1)
    return sorted(found, key=lambda c: (-c[1], c[0]))


def cut(path: Path, offset: int, size: int, dest: Path) -> None:
    """Copy size bytes of path, from offset, into dest.

    Raises:
        UnpackError: The file ends first.
    """
    with open(path, "rb") as f, open(dest, "wb") as out:
        f.seek(offset)
        left = size
        while left:
            chunk = f.read(min(left, 1 << 20))
            if not chunk:
                raise UnpackError(f"{path.name} ends before its data does")
            out.write(chunk)
            left -= len(chunk)


# ------------------------------------------- InstallShield Suite: files in an ISSetupStream overlay

ISSETUP_MAGIC = b"ISSetupStream\0"
_NIBBLE_SWAP = bytes(((b >> 4) | (b << 4)) & 0xFF for b in range(256))


def _issetup_key(name: str) -> bytes:
    """Return the key an ISSetupStream file is encoded with: its name, xored with 13 35 86 07, inverted."""
    seed = name.encode("latin-1", "replace")
    return bytes(~(s ^ (0x13, 0x35, 0x86, 0x07)[i % 4]) & 0xFF for i, s in enumerate(seed))


def _issetup_decode(data: bytes, unit: bytes) -> bytes:
    """Decode a run of an encoded file that starts where unit, the key's cycle, starts: nibbles swapped,
    then xored with unit over and over."""
    data = data.translate(_NIBBLE_SWAP)
    stream = (unit * (len(data) // len(unit) + 1))[:len(data)]
    return (int.from_bytes(data, "little") ^ int.from_bytes(stream, "little")).to_bytes(len(data), "little")


def issetup_stream(path: Path, dest: Path | None = None) -> list[str] | None:
    """Return the names of the files an InstallShield Suite setup.exe carries, extracting them into dest.

    Returns None if path isn't one. A Suite setup (Setup Suite Launcher;
    SketchUp 2023's SketchUpStudio.exe) keeps its files after the program,
    under a header "ISSetupStream": a count of files, then for each its name
    (UTF-16), flags and size, then its data. Data flagged 2 is encoded with a
    key made from the name, and flagged 4 is zlib-compressed, encoded a
    kilobyte at a time with the key starting afresh each time. Under Wine
    the setup that reads them failed ("Invalid handle" while staging its
    parts), so they're read here: SketchUp's carries SketchUp 2023.msi.

    Raises:
        UnpackError: The stream is cut short or a file won't decode.
    """
    with open(path, "rb") as f:
        end = _pe_end(f)
        if end is None:
            return None
        f.seek(end)
        head = f.read(46)
        if len(head) < 46 or not head.startswith(ISSETUP_MAGIC):
            return None
        count, kind = struct.unpack_from("<HI", head, 14)
        return [_issetup_entry(f, kind, path, dest) for _ in range(count)]


def _issetup_entry(f, kind: int, path: Path, dest: Path | None) -> str:
    """Read the ISSetupStream entry at f's position, extracting its file into dest; return its name."""
    attrs = f.read(48 if kind == 4 else 24)
    if len(attrs) < 24:
        raise UnpackError(f"{path.name}: its InstallShield stream ends early")
    name_len, flags, _, size = struct.unpack_from("<IIHI", attrs)
    name = f.read(name_len).decode("utf-16-le", "replace").rstrip("\0")
    if not name.strip("\\/."):
        raise UnpackError(f"{path.name}: a file in its InstallShield stream has no name")
    start = f.tell()
    if dest is not None:
        target = dest.joinpath(*(p for p in name.split("\\") if p not in ("", ".", "..")))
        target.parent.mkdir(parents=True, exist_ok=True)
        _issetup_file(f, size, flags, _issetup_key(name), target, path.name)
    f.seek(start + size)
    return name.replace("\\", "/")


def _issetup_file(f, size: int, flags: int, key: bytes, target: Path, source: str) -> None:
    """Copy one file of an ISSetupStream from f's position into target, decoded and inflated."""
    # compressed, the key starts afresh each kilobyte; otherwise it just repeats
    unit = (key * (1024 // len(key) + 1))[:1024] if flags & 4 else key
    inflate = zlib.decompressobj() if flags & 4 else None
    left = size
    with open(target, "wb") as out:
        while left:
            chunk = f.read(min(left, len(unit) * 1024))
            if not chunk:
                raise UnpackError(f"{source}: its InstallShield stream ends early")
            left -= len(chunk)
            out.write(_issetup_chunk(chunk, flags, unit, inflate, f"{source}: {target.name}"))
        if inflate:
            out.write(inflate.flush())


def _issetup_chunk(chunk: bytes, flags: int, unit: bytes, inflate, what: str) -> bytes:
    """Return a chunk of an ISSetupStream file decoded (flag 2) and inflated (when inflate is given)."""
    if flags & 2:
        chunk = _issetup_decode(chunk, unit)
    try:
        return inflate.decompress(chunk) if inflate else chunk
    except zlib.error as e:
        raise UnpackError(f"{what} in its InstallShield stream won't inflate: {e}") from e


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
        for blob in _resource_blobs(data):
            if blob[:2] != b"PK":
                continue
            try:
                if (pkg := _nupkg_in_zip(blob)) is not None:
                    return pkg
            except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, ValueError, NotImplementedError, EOFError,
                    RuntimeError, KeyError, struct.error, zlib.error):
                continue                                # damaged or encrypted: not a Squirrel package
    except (struct.error, IndexError, UnpackError):
        return None
    return None


def _resource_blobs(data: bytes) -> Iterator[bytes]:
    """Yield the data of every leaf in a PE file's resource tree (none if it isn't a PE file)."""
    # the work happens as the caller iterates, which stops at the first package it finds
    found = _resource_section(data)
    if found is None:
        return
    sections, rsrc = found
    leaves: list[tuple[int, int]] = []
    _walk_resource_tree(data, sections, rsrc, rsrc, 0, leaves)
    for data_rva, size in leaves:
        o = _rva_to_offset(sections, data_rva)
        yield bytes(data[o:o + size])


def _resource_section(data: bytes) -> tuple[list[tuple[int, int, int, int]], int] | None:
    """Return a PE file's sections, as _rva_to_offset takes them, and its resource RVA; None if it has neither."""
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
    return sections, rsrc


def _walk_resource_tree(data: bytes, sections: list, rsrc: int, rva: int, depth: int,
                        leaves: list[tuple[int, int]]) -> None:
    """Collect (data RVA, size) for every leaf of the resource tree."""
    off = _rva_to_offset(sections, rva)
    n = sum(struct.unpack_from("<HH", data, off + 12))
    for i in range(n):
        _name, target = struct.unpack_from("<II", data, off + 16 + 8 * i)
        if not target & 0x80000000:
            leaves.append(struct.unpack_from("<II", data, _rva_to_offset(sections, rsrc + target)))
        elif depth < 2:
            _walk_resource_tree(data, sections, rsrc, rsrc + (target & 0x7FFFFFFF), depth + 1, leaves)


def _nupkg_in_zip(blob: bytes) -> bytes | None:
    """Return blob if it's a .nupkg, or the app's .nupkg inside it, or None.

    A .nupkg has a .nuspec at its top. Squirrel's releasify wraps it once more: the
    resource is a zip of Update.exe and APP-VERSION-full.nupkg (GitHub Desktop, Figma),
    and that inner package is the app. Read the zip's listing; searching the bytes for
    ".nuspec" would also find a stored inner package's name.
    """
    def has_nuspec(names: list[str]) -> bool:
        return any(n.lower().endswith(".nuspec") and "/" not in n for n in names)
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        names = z.namelist()
        if has_nuspec(names):
            return blob
        pkgs = sorted((n for n in names if n.lower().endswith(".nupkg") and "/" not in n),
                      key=lambda n: (not n.lower().endswith("-full.nupkg"), n))
        for n in pkgs:
            if z.getinfo(n).file_size > 4 << 30:
                continue
            inner = z.read(n)
            with zipfile.ZipFile(io.BytesIO(inner)) as iz:
                if has_nuspec(iz.namelist()):
                    return inner
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

def run_bsdtar(path: Path, dest: Path) -> None:
    """Extract an archive with libarchive's bsdtar, which refuses absolute and ../ paths.

    Raises:
        UnpackError: bsdtar is missing or fails.
    """
    exe = shutil.which("bsdtar")
    if not exe:
        raise UnpackError("bsdtar isn't installed")
    dest.mkdir(parents=True, exist_ok=True)
    r = subprocess.run([exe, "-x", "-C", str(dest), "-f", str(path)], capture_output=True, text=True)
    if r.returncode != 0:
        tail = " / ".join((r.stderr or r.stdout).strip().splitlines()[-3:])
        raise UnpackError(f"bsdtar failed: {tail or f'exit status {r.returncode}'}")
    drop_escaping_links(dest)


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
        _run_step(step, current, out, work, i)
        inner = step.get("inner")
        if inner:
            current = _inner_file(out, inner)
        elif i + 1 < len(steps):
            raise UnpackError("only the last step may leave a folder")
    return out


def _run_step(step: dict, current: Path, out: Path, work: Path, i: int) -> None:
    """Carry out unpack's step number i on current, into out (work holds any scratch files)."""
    kind = step.get("kind")
    if kind == "zip":
        unzip(current, out)
    elif kind == "bsdtar":
        _bsdtar_step(step, current, out, work / f"step{i}.rar")
    elif kind == "7z":
        _seven_zip_step(step, current, out, work / f"step{i}.7z")
    elif kind == "squirrel":
        _squirrel_step(current, out, work)
    elif kind == "copy":
        out.mkdir(parents=True)
        shutil.copy2(current, out / step["name"])
    elif kind == "makeself":
        makeself(current, int(step["offset"]), int(step["size"]), out)
    else:
        raise UnpackError(f"unknown step {kind!r}")


def _bsdtar_step(step: dict, current: Path, out: Path, part: Path) -> None:
    """Extract current with bsdtar; with an offset, extract the archive cut from there into part instead."""
    if not step.get("offset"):
        run_bsdtar(current, out)
        return
    # a RAR self-extractor: bsdtar reads the archive cut from the end of the .exe
    cut(current, int(step["offset"]), Path(current).stat().st_size - int(step["offset"]), part)
    run_bsdtar(part, out)
    part.unlink()


def _seven_zip_step(step: dict, current: Path, out: Path, part: Path) -> None:
    """Extract current with 7z; with an offset, extract the archive cut from there into part instead."""
    if not step.get("offset"):
        run_7z(current, out)
        return
    # a self-extractor: 7z reads the archive cut from the end of the .exe
    cut_7z(current, int(step["offset"]), part)
    run_7z(part, out)
    part.unlink()


def _squirrel_step(current: Path, out: Path, work: Path) -> None:
    """Extract the .nupkg inside a Squirrel Setup.exe into out."""
    blob = squirrel_nupkg(Path(current).read_bytes())
    if blob is None:
        raise UnpackError("no .nupkg in this Setup.exe")
    nupkg = work / "setup.nupkg"
    nupkg.write_bytes(blob)
    unzip(nupkg, out)


def _inner_file(out: Path, inner: str) -> Path:
    """Return the file a step names as the next one to open, which must be in the step's output."""
    nxt = out / inner
    if not _inside(out, nxt) or not nxt.is_file():
        raise UnpackError(f"{inner} isn't in the unpacked files")
    return nxt


def apply(plan: dict, cwd: Path) -> None:
    """Carry out a plan in cwd (apply_extra runs in /app/extra): unpack, keep one folder, patch, clean up.

    Raises:
        UnpackError: The plan can't be carried out.
    """
    source = _plan_source(plan, cwd)
    work = cwd / ".debpak-unpack"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir()
    try:
        if not isinstance(plan.get("target"), str) or not isinstance(plan.get("take", ""), str):
            raise UnpackError("take and target must be paths")
        target = _place(unpack(source, plan["steps"], work), plan, cwd)
        _drop(target, plan.get("drop", []))
        _install_natives(target, plan.get("natives", []))
        if plan.get("main_shim"):
            if not isinstance(plan["main_shim"], str):
                raise UnpackError("main_shim must be JavaScript text")
            install_main_shim(target, plan["main_shim"])
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if plan.get("remove_source", True) and source.exists():
        source.unlink()


def _plan_source(plan: dict, cwd: Path) -> Path:
    """Return the downloaded file a plan unpacks, checking the plan's source and steps."""
    name = plan.get("source")
    if not isinstance(name, str) or not name or "/" in name or name in (".", ".."):
        raise UnpackError(f"source must be a file name in {cwd}, not {name!r}")
    source = cwd / name
    if not source.is_file():
        raise UnpackError(f"{name} isn't in {cwd} (did Flatpak download it?)")
    if not isinstance(plan.get("steps"), list) or not all(isinstance(st, dict) for st in plan["steps"]):
        raise UnpackError("steps must be a list of objects")
    return source


def _place(tree: Path, plan: dict, cwd: Path) -> Path:
    """Move the folder the plan keeps from the unpacked tree to its target; return the target."""
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
    return target


def _drop(target: Path, drop: list) -> None:
    for rel in drop:
        if not isinstance(rel, str):
            raise UnpackError("drop must be a list of paths")
        p = target / rel
        if _inside(target, p):
            _remove(p)


def _remove(p: Path) -> None:
    """Delete a file, link or folder, if it's there."""
    if p.is_dir() and not p.is_symlink():
        shutil.rmtree(p)
    elif p.exists() or p.is_symlink():
        p.unlink()


def _install_natives(target: Path, natives: list) -> None:
    """Copy the Linux builds of native modules in, and point app.asar at them."""
    unpack_in_asar, add_to_asar = [], []
    for n in natives:
        _copy_native(target, n)
        if n.get("asar_unpack"):
            unpack_in_asar.append(n["asar_unpack"])
        if n.get("asar_add"):
            add_to_asar.append(n["asar_add"])
    if unpack_in_asar or add_to_asar:
        asar_edit(target / "app.asar", unpack=unpack_in_asar, add=add_to_asar)


def _copy_native(target: Path, n) -> None:
    """Copy one native module entry's file to its place under target, replacing what's there."""
    if not (isinstance(n, dict) and isinstance(n.get("to"), str) and isinstance(n.get("from"), str)):
        raise UnpackError("each native entry needs from and to paths")
    dest = target / n["to"]
    if not _inside(target, dest):
        raise UnpackError(f"native module target {n['to']!r} is outside {target}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        dest.unlink()
    shutil.copy2(n["from"], dest)


def _asar_entry(header: dict, p: str, create: bool, archive: str) -> dict:
    """Return the file entry for path p in an asar header, creating it and its folders when create is set."""
    parts = [x for x in p.split("/") if x]
    if not parts or any(x in (".", "..") for x in parts):
        raise UnpackError(f"bad asar path {p!r}")
    node = _asar_folder(header, p, parts[:-1], create, archive)
    files = _asar_files(node, create)
    leaf = files.get(parts[-1])
    if leaf is None:
        if not create:
            raise UnpackError(f"{p} isn't in {archive}")
        leaf = files[parts[-1]] = {}
    elif "files" in leaf:
        raise UnpackError(f"{p} is a folder in {archive}")
    return leaf


def _asar_files(node: dict, create: bool) -> dict:
    """Return a header node's "files" map, adding an empty one when create is set and it has none."""
    return node.setdefault("files", {}) if create else node.get("files", {})


def _asar_folder(header: dict, p: str, folders: list[str], create: bool, archive: str) -> dict:
    """Return the header node of the folder holding p, creating the folders on the way when create is set."""
    node = header
    for part in folders:
        files = _asar_files(node, create)
        if part not in files and not create:
            raise UnpackError(f"{p} isn't in {archive}")
        if part not in files:
            files[part] = {"files": {}}
        node = files[part]
        if "files" not in node:
            raise UnpackError(f"{p}: {part} is a file in {archive}")
    return node


def asar_edit(path: Path, unpack: Sequence[str] = (), add: Sequence[str] = ()) -> None:
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
            leaf = _asar_entry(header, p, create, path.name)
            leaf.pop("offset", None)
            leaf.pop("integrity", None)
            leaf["unpacked"] = True
            real = real_root / "/".join(x for x in p.split("/") if x)
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


SHIM_NAME = "debpak-shim"


def _asar_read(path: Path, inner: str) -> bytes:
    """Return a file stored in an app.asar (packed or unpacked), or raise UnpackError."""
    with open(path, "rb") as f:
        four, size, _payload, json_len = struct.unpack("<IIII", f.read(16))
        if four != 4 or json_len > size:
            raise UnpackError(f"{path.name}: not an asar archive")
        node = json.loads(f.read(json_len).decode("utf-8"))
        for part in inner.split("/"):
            node = (node.get("files") or {}).get(part)
            if not isinstance(node, dict):
                raise UnpackError(f"{inner} isn't in {path.name}")
        if node.get("unpacked"):
            return (path.with_name(path.name + ".unpacked") / inner).read_bytes()
        f.seek(8 + size + int(node["offset"]))
        return f.read(int(node["size"]))


def install_main_shim(res: Path, shim: str) -> None:
    """Make the app start through shim, which then loads the app's own main script.

    The app's package.json gets "main" pointed at a new file beside it, and
    the original main is loaded at the end of that file. In an app.asar both
    files go in app.asar.unpacked and the header is rewritten to point at
    them (see asar_edit), so the archived code stays byte for byte the same.
    An app whose main is an ES module is loaded with import() instead.

    Raises:
        UnpackError: Neither app.asar nor app/package.json can be read.
    """
    asar = res / "app.asar"
    pj, folder = _app_package_json(res, asar)
    main: str = pj["main"] if isinstance(pj.get("main"), str) else "index.js"
    esm = pj.get("type") == "module" or main.endswith(".mjs")
    # .cjs so the shim stays CommonJS even in a "type": "module" package
    name = SHIM_NAME + (".cjs" if esm else ".js")
    target = f"require('path').join(__dirname, {json.dumps(main)})"
    load = (f"import(require('url').pathToFileURL({target}).href);\n" if esm else f"require({target});\n")
    pj["main"] = name
    folder.mkdir(parents=True, exist_ok=True)
    for f in (name, "package.json"):        # may be hard links to the original: never write through them
        (folder / f).unlink(missing_ok=True)
    (folder / name).write_text(shim.rstrip("\n") + "\n// then the app's own main script\n" + load, "utf-8")
    (folder / "package.json").write_text(json.dumps(pj, indent=2) + "\n", "utf-8")
    if asar.is_file():
        asar_edit(asar, unpack=["package.json"], add=[name])


def _app_package_json(res: Path, asar: Path) -> tuple[dict, Path]:
    """Return the app's package.json, and the folder its shim goes in (app.asar.unpacked or app)."""
    try:
        if asar.is_file():
            pj = json.loads(_asar_read(asar, "package.json"))
            folder = res / "app.asar.unpacked"
        else:
            folder = res / "app"
            pj = json.loads((folder / "package.json").read_text("utf-8"))
    except (OSError, ValueError, KeyError) as e:
        raise UnpackError(f"can't read the app's package.json: {e}") from None
    if not isinstance(pj, dict):
        raise UnpackError("the app's package.json isn't an object")
    return pj, folder


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
