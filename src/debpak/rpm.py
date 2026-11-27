""".rpm reading and extraction, in pure Python.

An RPM file is: a 96-byte lead, a signature header (padded to 8 bytes), the
main header, and a compressed cpio ("newc") archive of the files. Headers are
an index of (tag, type, offset, count) entries over a data store. The payload
compressor is found from its magic bytes (gzip, xz, legacy lzma, bzip2, zstd).

Packages with 64-bit file sizes (rpm's LONGFILESIZES tag: files over 4 GB, or
the RPM v6 format of rpm 6.0) use a "stripped" cpio instead: each entry is just
the magic "07070X" and the file's index into the main header's file list, and
the name, mode, size and link target come from the header.

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
REQUIRENAME = 1049
PREIN, POSTIN, PREUN, POSTUN = 1023, 1024, 1025, 1026
PREINPROG, POSTINPROG, PREUNPROG, POSTUNPROG = 1085, 1086, 1087, 1088
TRIGGERSCRIPTS = 1065
PAYLOADFORMAT, PAYLOADCOMPRESSOR = 1124, 1125
PRETRANS, POSTTRANS = 1151, 1152
PAYLOADDIGEST, PAYLOADDIGESTALGO = 5092, 5093
# file list tags, which the stripped cpio format reads names and modes from
OLDFILENAMES, FILESIZES, FILEMODES, FILEFLAGS, FILELINKTOS = 1027, 1028, 1030, 1037, 1036
FILEDEVICES, FILEINODES, DIRINDEXES, BASENAMES, DIRNAMES = 1095, 1096, 1116, 1117, 1118
LONGFILESIZES = 5008
RPMFILE_GHOST = 1 << 6
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
            prog = _interpreter(self.tags.get(prog_tag))
            if prog == "<lua>":
                notes.append(f"{deb_name} scriptlet is Lua (run inside rpm); reviewed as text only")
            if body:
                out[deb_name] = _shebang(prog) + body
        for tag, label in ((PRETRANS, "%pretrans"), (POSTTRANS, "%posttrans")):
            if _s(self.tags, tag):
                out.setdefault("postinst", "")
                out["postinst"] += f"\n# {label}\n" + _s(self.tags, tag)
        if self.tags.get(TRIGGERSCRIPTS):
            notes.append("package has rpm triggers (scripts run when other packages change); "
                         "a Flatpak can't run them")
        return out, notes


def _interpreter(prog):
    """Return a scriptlet's interpreter from its *PROG header tag (a string or a list), or ""."""
    return prog[0] if isinstance(prog, list) and prog else (prog if isinstance(prog, str) else "")


def _shebang(prog) -> str:
    """Return the #! line for a scriptlet run by prog, or "" when prog isn't an absolute path."""
    return f"#!{prog}\n" if prog and prog.startswith("/") else ""


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
    _check_payload_digest(path, info)
    notes = _unpack_payload(path, info, root)
    scripts, more = info.scripts()
    pkg = Package("rpm", path, root, info.name, info.version, _s(info.tags, ARCH, ""),
                  _s(info.tags, SUMMARY), _s(info.tags, DESCRIPTION), _s(info.tags, URL),
                  _s(info.tags, LICENSE), scripts)
    pkg.notes += notes + more
    req = info.tags.get(REQUIRENAME)
    pkg.extra["requires"] = [r for r in req if isinstance(r, str)] if isinstance(req, list) else []
    return pkg


def _check_payload_digest(path: Path, info: RpmInfo) -> None:
    """Check the payload against the SHA-256 the header records, if any, before anything is unpacked from it.

    Raises:
        PackageError: The payload doesn't match.
    """
    algo = info.tags.get(PAYLOADDIGESTALGO)
    want = info.tags.get(PAYLOADDIGEST)
    want = want[0].lower() if isinstance(want, list) and want and algo in ([8], 8) else None
    if not want:
        return
    h = hashlib.sha256()
    with open(path, "rb") as f:
        f.seek(info.payload_offset)
        while chunk := f.read(1 << 20):
            h.update(chunk)
    if h.hexdigest() != want:
        raise PackageError(f"{path.name}: payload checksum mismatch (corrupted download?)")


def _unpack_payload(path: Path, info: RpmInfo, root: Path) -> list[str]:
    """Decompress the payload and unpack its cpio archive into root; return notes for the report.

    Raises:
        PackageError: The payload is damaged or uses a compression debpak can't read.
    """
    notes: list[str] = []
    with open(path, "rb") as f:
        f.seek(info.payload_offset)
        buf = io.BufferedReader(f, buffer_size=1 << 16)
        head = buf.peek(8)[:8]
        try:
            try:
                stream = _decompressor(buf, head)
            except _NeedZstdTool:
                notes += _extract_with_zstd_tool(path, info.payload_offset, root, info.tags)
                stream = None
            if stream is not None:
                notes += _extract_cpio(stream, root, info.tags)
        except (OSError, EOFError, lzma.LZMAError, zlib.error, ValueError, struct.error) as e:
            raise PackageError(f"{path.name}: damaged payload ({e})") from e
        except PackageError as e:
            raise PackageError(f"{path.name}: damaged or unsupported payload ({e})") from e
    return notes


def _extract_with_zstd_tool(path: Path, offset: int, root: Path, tags: dict | None = None) -> list[str]:
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
    assert proc.stdin and proc.stdout and proc.stderr       # all three are pipes
    stdin, stderr = proc.stdin, proc.stderr

    def feed():
        try:
            with open(path, "rb") as src:
                src.seek(offset)
                shutil.copyfileobj(src, stdin, 1 << 20)
        except (BrokenPipeError, OSError):
            pass                       # zstd stopped reading; its exit status says why
        finally:
            try:
                stdin.close()
            except OSError:
                pass

    errs: list[bytes] = []
    feeder = threading.Thread(target=feed, daemon=True)
    drain = threading.Thread(target=lambda: errs.append(stderr.read()), daemon=True)
    feeder.start()
    drain.start()
    try:
        notes = _extract_cpio(proc.stdout, root, tags)
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


class _FileList:
    """The main header's file list, for the stripped cpio format.

    rpm writes data for a regular file only on the last entry of a hard-link set
    (files sharing a device and inode), and a symlink's target as its data.

    Raises:
        PackageError: The header has no usable file list.
    """
    def __init__(self, tags: dict):
        self.names = self._file_names(tags)
        n = len(self.names)
        sizes = self._ints(tags, LONGFILESIZES, n) or self._ints(tags, FILESIZES, n)
        modes = self._ints(tags, FILEMODES, n)
        if sizes is None or modes is None:
            raise PackageError("stripped cpio payload, but the RPM header has no file sizes or modes")
        self.sizes, self.modes = sizes, modes
        links = tags.get(FILELINKTOS)
        self.linktos = links if isinstance(links, list) and len(links) == n else [""] * n
        self.link_set = self._link_sets(tags, n)

    @staticmethod
    def _file_names(tags: dict) -> list[str]:
        names = tags.get(BASENAMES)
        dirs, dirindex = tags.get(DIRNAMES), tags.get(DIRINDEXES)
        if isinstance(names, list) and isinstance(dirs, list) and isinstance(dirindex, list):
            try:
                return [dirs[d] + b for d, b in zip(dirindex, names, strict=True)]
            except (IndexError, ValueError) as e:
                raise PackageError("damaged file list in the RPM header") from e
        if isinstance(tags.get(OLDFILENAMES), list):
            return tags[OLDFILENAMES]
        raise PackageError("stripped cpio payload, but the RPM header has no file list")

    def _link_sets(self, tags: dict, n: int) -> dict[int, tuple[tuple[int, int], list[int]]]:
        """Return, for each file in a hard-link set (regular files sharing a device and inode), its set."""
        flags = self._ints(tags, FILEFLAGS, n) or [0] * n
        devs, inodes = self._ints(tags, FILEDEVICES, n), self._ints(tags, FILEINODES, n)
        sets: dict[tuple[int, int], list[int]] = {}
        if devs and inodes:
            for i in range(n):
                if stat.S_ISREG(self.modes[i]) and not flags[i] & RPMFILE_GHOST and inodes[i] > 0:
                    sets.setdefault((devs[i], inodes[i]), []).append(i)
        return {i: (key, members) for key, members in sets.items() if len(members) > 1 for i in members}

    @staticmethod
    def _ints(tags: dict, tag: int, n: int) -> list[int] | None:
        v = tags.get(tag)
        return v if isinstance(v, list) and len(v) == n else None

    def entry(self, fx: int) -> tuple[str, int, int, int, tuple]:
        """Return (name, mode, size of its data in the archive, link count, hard-link key) for file fx.

        Raises:
            PackageError: fx isn't in the file list.
        """
        if not 0 <= fx < len(self.names):
            raise PackageError(f"stripped cpio entry {fx} isn't in the RPM header's file list")
        mode = self.modes[fx]
        size = self.sizes[fx] if stat.S_ISREG(mode) or stat.S_ISLNK(mode) else 0
        nlink = 1
        key: tuple = ("fx", fx)
        if fx in self.link_set:
            (dev, ino), members = self.link_set[fx]
            nlink, key = len(members), ("set", dev, ino)
            if fx != members[-1]:
                size = 0
        return self.names[fx], mode, size, nlink, key


def _extract_cpio(f, root: Path, tags: dict | None = None) -> list[str]:
    """Unpack a cpio "newc" stream into root; return notes for the report.

    Entries in rpm's stripped format (magic 07070X) take their name, mode and
    size from the RPM header's file list (tags). Hard links are recreated
    (copied if linking fails), and a link whose data arrives later in the
    archive is filled in when it does. Folder modes are set at the end, so a
    read-only folder doesn't block its own contents.
    """
    x = _CpioExtractor(f, root, tags)
    while (entry := x.next_entry()) is not None:
        x.write(*entry)
    return x.finish()


class _CpioExtractor:
    """The state _extract_cpio keeps while it unpacks one archive."""

    def __init__(self, f, root: Path, tags: dict | None):
        self.f, self.root, self.tags = f, root, tags
        self.skipped: list[str] = []
        self.dir_modes: dict[Path, int] = {}
        self.written: dict[tuple, Path] = {}         # (dev, dev, ino) -> first path with data
        self.pending: dict[tuple, list[Path]] = {}   # hard links seen before their data
        self.files: _FileList | None = None
        self.suid = 0

    def next_entry(self) -> tuple[str, int, int, int, tuple, str] | None:
        """Read the next header: (name, mode, data size, link count, hard-link key, symlink target), or None at the end."""
        f = self.f
        magic = f.read(6)
        if len(magic) < 6:
            raise PackageError("cpio archive ends early")
        if magic == b"07070X":
            return self._stripped_entry()
        if magic not in (b"070701", b"070702"):
            raise PackageError(f"bad cpio header {magic!r}")
        hdr = magic + f.read(104)
        if len(hdr) < 110:
            raise PackageError("cpio archive ends early")
        fields = [int(hdr[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
        ino, mode, _uid, _gid, nlink, _mtime, size, dmaj, dmin, _rmaj, _rmin, namesize, _chk = fields
        name = f.read(namesize)[:-1].decode("utf-8", "surrogateescape")
        f.read((4 - (110 + namesize) % 4) % 4)
        if name == "TRAILER!!!":
            return None
        return name, mode, size, nlink, (dmaj, dmin, ino), ""

    def _stripped_entry(self) -> tuple[str, int, int, int, tuple, str] | None:
        hdr = self.f.read(10)              # 8 hex digits of the file index, then padding to 4 bytes
        if len(hdr) < 10:
            raise PackageError("cpio archive ends early")
        if self.files is None:
            if self.tags is None:
                raise PackageError("stripped cpio payload without an RPM header")
            self.files = _FileList(self.tags)
        fx = int(hdr[:8], 16)
        if fx == 0xFFFFFFFF:          # rpm's reader also takes index -1 as the end
            return None
        name, mode, size, nlink, key = self.files.entry(fx)
        return name, mode, size, nlink, key, self.files.linktos[fx]

    def write(self, name: str, mode: int, size: int, nlink: int, key: tuple, linkto: str) -> None:
        """Write one entry's file, folder or symlink, or skip it."""
        f = self.f
        data_pad = (4 - size % 4) % 4
        kind = stat.S_IFMT(mode)
        target = _safe_target(self.root, name)
        if target is None or kind not in (stat.S_IFDIR, stat.S_IFLNK, stat.S_IFREG):
            # unsafe, or devices, fifos, sockets: not meaningful in an app bundle
            _skip(f, size + data_pad)
            self.skipped.append(name)
        elif kind == stat.S_IFDIR:
            self._write_dir(target, mode)
            _skip(f, size + data_pad)
        elif kind == stat.S_IFLNK:
            self._write_symlink(target, size, data_pad, linkto)
        elif nlink > 1 and size == 0:
            self._write_hard_link(target, key)
            f.read(data_pad)
        else:
            self._write_file(name, target, mode, size, nlink, key)
            f.read(data_pad)

    def _write_dir(self, target: Path, mode: int) -> None:
        """Make the folder target (its mode is set in finish)."""
        if target.is_symlink():
            target.unlink()
        target.mkdir(exist_ok=True)
        self.dir_modes[target] = mode & 0o777

    def _write_symlink(self, target: Path, size: int, data_pad: int, linkto: str) -> None:
        """Read a symlink's target from the archive (or take linkto, from the header) and make the link."""
        link = self.f.read(size).decode("utf-8", "surrogateescape")
        self.f.read(data_pad)
        if target.is_symlink() or target.exists():
            target.unlink()
        os.symlink(linkto or link, target)

    def _write_hard_link(self, target: Path, key: tuple) -> None:
        """Link target to the file of its hard-link set already written, or wait for that file's data."""
        if key in self.written:
            _link(self.written[key], target)
        else:
            self.pending.setdefault(key, []).append(target)

    def _write_file(self, name: str, target: Path, mode: int, size: int, nlink: int, key: tuple) -> None:
        if target.is_symlink():
            target.unlink()
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as out:
            left = size
            while left:
                chunk = self.f.read(min(left, 1 << 20))
                if not chunk:
                    raise PackageError(f"cpio data for {name} ends early")
                out.write(chunk)
                left -= len(chunk)
        if mode & 0o6000:
            self.suid += 1
        os.chmod(target, mode & 0o777)
        if nlink > 1:
            self.written.setdefault(key, target)
            for other in self.pending.pop(key, []):
                _link(target, other)

    def finish(self) -> list[str]:
        """Fill in links whose data never came, set folder modes, and return the notes."""
        for paths in self.pending.values():      # links whose data never came: empty files, like rpm would
            for p in paths:
                p.touch()
        for d, m in sorted(self.dir_modes.items(), key=lambda kv: -len(kv[0].parts)):
            os.chmod(d, m | 0o700)
        notes = []
        if self.suid:
            notes.append(f"setuid/setgid bits removed from {self.suid} file(s) (Flatpak doesn't allow them)")
        if self.skipped:
            n = len(self.skipped)
            notes.append(f"skipped {n} entr{'y' if n == 1 else 'ies'} that were unsafe or "
                         f"not regular files: {', '.join(self.skipped[:5])}")
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
