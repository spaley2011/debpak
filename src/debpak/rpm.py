""".rpm reading and extraction, in pure Python.

An RPM file is: a 96-byte lead, a signature header (padded to 8 bytes), the
main header, and a compressed cpio ("newc") archive of the files. Headers are
an index of (tag, type, offset, count) entries over a data store. The payload
compressor is found from its magic bytes (gzip, xz, legacy lzma, bzip2, zstd).

When the package carries them, the SHA-256 digests of the main header and of
the compressed payload are checked before anything is written, so a damaged
download stops with an error and leaves no half-extracted tree. Extraction refuses paths that leave the
destination (`..`, writes through symlinks) and strips setuid/setgid bits.
"""
from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import lzma
import os
import stat
import struct
import zlib
from pathlib import Path

from .packages import Package, PackageError

LEAD_MAGIC = b"\xed\xab\xee\xdb"
HEADER_MAGIC = b"\x8e\xad\xe8\x01"

# header tags
NAME, VERSION, RELEASE, EPOCH, SUMMARY, DESCRIPTION = 1000, 1001, 1002, 1003, 1004, 1005
LICENSE, URL, ARCH = 1014, 1020, 1022
PREIN, POSTIN, PREUN, POSTUN = 1023, 1024, 1025, 1026
PREINPROG, POSTINPROG, PREUNPROG, POSTUNPROG = 1085, 1086, 1087, 1088
TRIGGERSCRIPTS = 1065
PAYLOADFORMAT, PAYLOADCOMPRESSOR = 1124, 1125
PRETRANS, POSTTRANS = 1151, 1152
PAYLOADDIGEST, PAYLOADDIGESTALGO = 5092, 5093
SIG_SHA256 = 273        # signature-header tag: hex SHA-256 of the main header

# RPM scriptlets under the Debian names the host-integration checks use
SCRIPT_TAGS = {"preinst": (PREIN, PREINPROG), "postinst": (POSTIN, POSTINPROG),
               "prerm": (PREUN, PREUNPROG), "postrm": (POSTUN, POSTUNPROG)}
MAX_HEADER = 256 * 1024 * 1024


def _read_exact(f, n: int) -> bytes:
    """Read exactly n bytes.

    Raises:
        PackageError: The file ends first.
    """
    b = f.read(n)
    if len(b) != n:
        raise PackageError("truncated RPM")
    return b


def read_header(f) -> tuple[dict[int, object], bytes]:
    """Read one RPM header structure at the current position.

    Returns:
        ({tag: value}, the header's raw bytes). The raw bytes are what the
        signature header's SHA-256 covers.

    Raises:
        PackageError: Bad magic, an implausible size, or an entry pointing
            outside the header.
    """
    head = _read_exact(f, 16)
    if head[:4] != HEADER_MAGIC:
        raise PackageError("bad RPM header magic")
    nindex, hsize = struct.unpack(">II", head[8:16])
    if nindex > 100000 or hsize > MAX_HEADER:
        raise PackageError("implausible RPM header size")
    index = _read_exact(f, 16 * nindex)
    store = _read_exact(f, hsize)
    tags: dict[int, object] = {}
    for i in range(nindex):
        tag, typ, off, count = struct.unpack(">IIII", index[16 * i:16 * i + 16])
        if off > hsize:
            raise PackageError(f"RPM header entry {tag} points outside the header")
        tags[tag] = _value(store, typ, off, count)
    return tags, head + index + store


def _value(store: bytes, typ: int, off: int, count: int):
    """Decode one header entry from the data store by its type (string, string array, integers, binary).

    Raises:
        PackageError: The entry runs past the end of the data store.
    """
    try:
        return _decode(store, typ, off, count)
    except (ValueError, struct.error) as e:
        raise PackageError(f"damaged RPM header entry ({e})") from e


def _decode(store: bytes, typ: int, off: int, count: int):
    if typ == 6:                                    # STRING
        end = store.index(b"\0", off)
        return store[off:end].decode("utf-8", "replace")
    if typ in (8, 9):                               # STRING_ARRAY, I18NSTRING
        out = []
        for _ in range(count):
            end = store.index(b"\0", off)
            out.append(store[off:end].decode("utf-8", "replace"))
            off = end + 1
        return out
    if typ == 4:
        return list(struct.unpack(f">{count}I", store[off:off + 4 * count]))
    if typ == 3:
        return list(struct.unpack(f">{count}H", store[off:off + 2 * count]))
    if typ == 5:
        return list(struct.unpack(f">{count}Q", store[off:off + 8 * count]))
    if typ in (1, 2, 7):                            # CHAR, INT8, BIN
        return store[off:off + count]
    return None


def _s(tags: dict, tag: int, default: str = "") -> str:
    """Return a header tag as a string (the first item of an array), or default."""
    v = tags.get(tag)
    if isinstance(v, list):
        return v[0] if v and isinstance(v[0], str) else default
    return v if isinstance(v, str) else default


def _decompressor(raw, head: bytes):
    """Wrap the payload in the decompressor its first bytes call for.

    Raises:
        _NeedZstdTool: The payload is zstd and no Python zstd module is installed.
        PackageError: The compression isn't one debpak knows.
    """
    if head[:2] == b"\x1f\x8b":
        return gzip.GzipFile(fileobj=raw)
    if head[:6] == b"\xfd7zXZ\x00":
        return lzma.LZMAFile(raw, format=lzma.FORMAT_XZ)
    if head[:3] == b"BZh":
        return bz2.BZ2File(raw)
    if head[:4] == b"\x28\xb5\x2f\xfd":
        from .deb import _zstd_stream
        s = _zstd_stream(raw)
        if s is None:
            raise _NeedZstdTool()
        return s
    if head[:4] == b"0707":
        return raw
    if head[:1] == b"\x5d":                                     # legacy .lzma
        return lzma.LZMAFile(raw, format=lzma.FORMAT_ALONE)
    raise PackageError("payload is damaged or uses an unknown compression")


class _NeedZstdTool(Exception):
    """zstd payload, and no Python zstd module: decompress with the zstd command instead."""


class RpmInfo:
    """An RPM's lead, signature header and main header.

    Reading it checks the main header against the signature's SHA-256, so a
    damaged download fails before anything is extracted.

    Attributes:
        sig: The signature header's tags.
        tags: The main header's tags.
        payload_offset: Where the compressed cpio payload starts.

    Raises:
        PackageError: Not an RPM, truncated, or the header checksum doesn't match.
    """
    def __init__(self, path: Path):
        self.path = path
        with open(path, "rb") as f:
            lead = _read_exact(f, 96)
            if lead[:4] != LEAD_MAGIC:
                raise PackageError(f"{path.name}: not an RPM file")
            self.sig, raw_sig = read_header(f)
            pad = (8 - len(raw_sig) % 8) % 8
            _read_exact(f, pad)
            self.tags, raw_header = read_header(f)
            self.payload_offset = f.tell()
        want = self.sig.get(SIG_SHA256)
        if isinstance(want, str) and want and hashlib.sha256(raw_header).hexdigest() != want.lower():
            raise PackageError(f"{path.name}: header checksum mismatch (corrupted download?)")

    @property
    def name(self) -> str:
        return _s(self.tags, NAME, self.path.stem)

    @property
    def version(self) -> str:
        """Return [epoch:]version[-release]."""
        v, r = _s(self.tags, VERSION, "0"), _s(self.tags, RELEASE)
        e = self.tags.get(EPOCH)
        epoch = f"{e[0]}:" if isinstance(e, list) and e else ""
        return f"{epoch}{v}-{r}" if r else f"{epoch}{v}"

    def scripts(self) -> tuple[dict[str, str], list[str]]:
        """Return the scriptlets under Debian's names, and notes about the ones debpak can't check.

        %pretrans and %posttrans are appended to postinst. Lua scriptlets are kept as
        text, and triggers only produce a note, since a Flatpak can't run either.
        """
        out, notes = {}, []
        for deb_name, (tag, prog_tag) in SCRIPT_TAGS.items():
            body = _s(self.tags, tag)
            prog = self.tags.get(prog_tag)
            prog = prog[0] if isinstance(prog, list) and prog else (prog if isinstance(prog, str) else "")
            if prog == "<lua>":
                notes.append(f"{deb_name} scriptlet is Lua (run inside rpm); reviewed as text only")
            if body:
                out[deb_name] = (f"#!{prog}\n" if prog and prog.startswith("/") else "") + body
        for tag, label in ((PRETRANS, "%pretrans"), (POSTTRANS, "%posttrans")):
            if _s(self.tags, tag):
                out.setdefault("postinst", "")
                out["postinst"] += f"\n# {label}\n" + _s(self.tags, tag)
        if self.tags.get(TRIGGERSCRIPTS):
            notes.append("package has rpm triggers (scripts run when other packages change); "
                         "a Flatpak can't run them")
        return out, notes


def extract_rpm(path: str | Path, dest: str | Path) -> Package:
    """Unpack an RPM's payload into dest/root.

    The payload's SHA-256 is checked before anything is written, when the
    package records one. Paths that would leave the destination are refused and
    setuid/setgid bits are stripped.

    Raises:
        PackageError: The file is damaged, a delta RPM, or uses a compression
            debpak can't read.
    """
    path, dest = Path(path), Path(dest)
    info = RpmInfo(path)
    fmt = _s(info.tags, PAYLOADFORMAT, "cpio")
    if fmt not in ("cpio", ""):
        raise PackageError(f"{path.name}: payload format {fmt!r} isn't supported (delta RPM?)")
    root = dest / "root"
    root.mkdir(parents=True, exist_ok=True)
    algo = info.tags.get(PAYLOADDIGESTALGO)
    want = info.tags.get(PAYLOADDIGEST)
    want = want[0].lower() if isinstance(want, list) and want and algo in ([8], 8) else None
    notes: list[str] = []
    if want:     # check the payload before unpacking anything from it
        h = hashlib.sha256()
        with open(path, "rb") as f:
            f.seek(info.payload_offset)
            while chunk := f.read(1 << 20):
                h.update(chunk)
        if h.hexdigest() != want:
            raise PackageError(f"{path.name}: payload checksum mismatch (corrupted download?)")
    with open(path, "rb") as f:
        f.seek(info.payload_offset)
        buf = io.BufferedReader(f, buffer_size=1 << 16)
        head = buf.peek(8)[:8]
        try:
            try:
                stream = _decompressor(buf, head)
            except _NeedZstdTool:
                notes += _extract_with_zstd_tool(path, info.payload_offset, root)
                stream = None
            if stream is not None:
                notes += _extract_cpio(stream, root)
        except (OSError, EOFError, lzma.LZMAError, zlib.error, ValueError, struct.error) as e:
            raise PackageError(f"{path.name}: damaged payload ({e})") from e
        except PackageError as e:
            raise PackageError(f"{path.name}: damaged or unsupported payload ({e})") from e
    scripts, more = info.scripts()
    pkg = Package("rpm", path, root, info.name, info.version, _s(info.tags, ARCH, ""),
                  _s(info.tags, SUMMARY), _s(info.tags, DESCRIPTION), _s(info.tags, URL),
                  _s(info.tags, LICENSE), scripts)
    pkg.notes += notes + more
    return pkg


def _extract_with_zstd_tool(path: Path, offset: int, root: Path) -> list[str]:
    """Unpack a zstd payload by piping it through the zstd command.

    Raises:
        PackageError: zstd isn't installed, or it failed before producing any files.
    """
    import shutil
    import subprocess
    zstd = shutil.which("zstd")
    if not zstd:
        raise PackageError("payload is zstd-compressed (Fedora's default); install the zstd command or "
                           "the 'zstandard' Python module (pip install debpak[zstd]), or use Python 3.14+")
    import threading

    # Feed the payload through a pipe rather than handing over the file at an
    # offset: not every tool reads stdin from its current position (uutils'
    # tail, Ubuntu's coreutils since 25.10, rereads the file from the start).
    proc = subprocess.Popen([zstd, "-dc"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)

    def feed():
        try:
            with open(path, "rb") as src:
                src.seek(offset)
                shutil.copyfileobj(src, proc.stdin, 1 << 20)
        except (BrokenPipeError, OSError):
            pass                       # zstd stopped reading; its exit status says why
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

    errs: list[bytes] = []
    feeder = threading.Thread(target=feed, daemon=True)
    drain = threading.Thread(target=lambda: errs.append(proc.stderr.read()), daemon=True)
    feeder.start()
    drain.start()
    try:
        notes = _extract_cpio(proc.stdout, root)
    finally:
        proc.stdout.close()
        feeder.join()
        drain.join()
        proc.stderr.close()
        proc.wait()
    err = b"".join(errs).decode(errors="replace")
    if proc.returncode not in (0, None) and not notes:
        raise PackageError(f"zstd failed: {err.strip()[-300:]}")
    return notes


# --------------------------------------------------------------------------- cpio (newc)

def _safe_target(root: Path, name: str) -> Path | None:
    """Return root/name if writing there can't leave root (no '..', no symlinked parent folders), else None."""
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        return None
    cur = root
    for p in parts[:-1]:
        cur = cur / p
        if cur.is_symlink():
            return None
        if not cur.exists():
            cur.mkdir(mode=0o755)
    return cur / parts[-1]


def _extract_cpio(f, root: Path) -> list[str]:
    """Unpack a cpio "newc" stream into root; return notes for the report.

    Hard links are recreated (copied if linking fails), and a link whose data
    arrives later in the archive is filled in when it does. Folder modes are set
    at the end, so a read-only folder doesn't block its own contents.
    """
    notes: list[str] = []
    skipped: list[str] = []
    dir_modes: dict[Path, int] = {}
    written: dict[tuple[int, int, int], Path] = {}       # (dev, dev, ino) -> first path with data
    pending: dict[tuple[int, int, int], list[Path]] = {}  # hard links seen before their data
    suid = 0
    while True:
        hdr = f.read(110)
        if len(hdr) < 110:
            raise PackageError("cpio archive ends early")
        magic = hdr[:6]
        if magic == b"07070X":
            raise PackageError("this RPM uses the large-file payload format (files over 4 GB), "
                               "which isn't supported")
        if magic not in (b"070701", b"070702"):
            raise PackageError(f"bad cpio header {magic!r}")
        fields = [int(hdr[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
        ino, mode, _uid, _gid, nlink, _mtime, size, dmaj, dmin, _rmaj, _rmin, namesize, _chk = fields
        name = f.read(namesize)[:-1].decode("utf-8", "surrogateescape")
        f.read((4 - (110 + namesize) % 4) % 4)
        if name == "TRAILER!!!":
            break
        data_pad = (4 - size % 4) % 4
        kind = stat.S_IFMT(mode)
        target = _safe_target(root, name)
        if target is None:
            _skip(f, size + data_pad)
            skipped.append(name)
            continue
        key = (dmaj, dmin, ino)
        if kind == stat.S_IFDIR:
            if target.is_symlink():
                target.unlink()
            target.mkdir(exist_ok=True)
            dir_modes[target] = mode & 0o777
            _skip(f, size + data_pad)
        elif kind == stat.S_IFLNK:
            link = f.read(size).decode("utf-8", "surrogateescape")
            f.read(data_pad)
            if target.is_symlink() or target.exists():
                target.unlink()
            os.symlink(link, target)
        elif kind == stat.S_IFREG:
            if nlink > 1 and size == 0:
                if key in written:
                    _link(written[key], target)
                else:
                    pending.setdefault(key, []).append(target)
                f.read(data_pad)
                continue
            if target.is_symlink():
                target.unlink()
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as out:
                left = size
                while left:
                    chunk = f.read(min(left, 1 << 20))
                    if not chunk:
                        raise PackageError(f"cpio data for {name} ends early")
                    out.write(chunk)
                    left -= len(chunk)
            f.read(data_pad)
            if mode & 0o6000:
                suid += 1
            os.chmod(target, mode & 0o777)
            if nlink > 1:
                written.setdefault(key, target)
                for other in pending.pop(key, []):
                    _link(target, other)
        else:   # devices, fifos, sockets: not meaningful in an app bundle
            _skip(f, size + data_pad)
            skipped.append(name)
    for paths in pending.values():      # links whose data never came: empty files, like rpm would
        for p in paths:
            p.touch()
    for d, m in sorted(dir_modes.items(), key=lambda kv: -len(kv[0].parts)):
        os.chmod(d, m | 0o700)
    if suid:
        notes.append(f"setuid/setgid bits removed from {suid} file(s) (Flatpak doesn't allow them)")
    if skipped:
        notes.append(f"skipped {len(skipped)} entr{'y' if len(skipped) == 1 else 'ies'} that were unsafe or "
                     f"not regular files: {', '.join(skipped[:5])}")
    return notes


def _skip(f, n: int) -> None:
    """Read and discard n bytes from a stream that can't seek."""
    while n > 0:
        chunk = f.read(min(n, 1 << 20))
        if not chunk:
            break
        n -= len(chunk)


def _link(src: Path, dst: Path) -> None:
    """Hard-link src to dst, replacing dst; copy if the file system can't link."""
    if dst.is_symlink() or dst.exists():
        dst.unlink()
    try:
        os.link(src, dst)
    except OSError:
        import shutil
        shutil.copy2(src, dst)
