"""Read and write Electron's app.asar archives.

An asar file is a JSON directory tree followed by the file contents. The
header is wrapped in two Chromium "pickles":

    uint32 4              size of the next field
    uint32 N              size of the header pickle that follows
    uint32 M              payload size inside that pickle
    uint32 L              length of the JSON string
    L bytes               JSON, padded to 4 bytes
    file data             starts at offset 8 + N

Each file entry has a size and an offset (a decimal string, relative to the
start of the file data). Entries marked "unpacked" live beside the archive in
app.asar.unpacked/ instead, which is where Electron apps keep native modules.
"""
from __future__ import annotations

import json
import struct
from pathlib import Path
from collections.abc import Iterator
from collections.abc import Set as AbstractSet


class AsarError(Exception):
    """A file that isn't a readable asar archive."""


class Asar:
    """An opened app.asar.

    Raises:
        AsarError: The header is missing or its JSON can't be parsed.
    """
    def __init__(self, path: str | Path):
        self.path = Path(path)
        with open(self.path, "rb") as f:
            head = f.read(16)
            if len(head) < 16:
                raise AsarError(f"{self.path}: too short to be an asar archive")
            four, size, _payload, json_len = struct.unpack("<IIII", head)
            if four != 4 or json_len > size or size > 256 * 1024 * 1024:
                raise AsarError(f"{self.path}: not an asar archive")
            try:
                self.header = json.loads(f.read(json_len).decode("utf-8"))
            except (UnicodeDecodeError, ValueError, RecursionError) as e:
                raise AsarError(f"{self.path}: bad header ({e})") from e
            if not isinstance(self.header, dict):
                raise AsarError(f"{self.path}: bad header (not an object)")
        self.data_offset = 8 + size

    @staticmethod
    def _children(node, where: str) -> dict:
        files = node.get("files", {}) if isinstance(node, dict) else None
        if not isinstance(files, dict):
            raise AsarError(f"bad folder entry at {where or '/'}")
        for name, entry in files.items():
            # a name like ".." would let a path from the header reach outside app.asar.unpacked
            if not name or name in (".", "..") or any(c in name for c in "/\\\0") or not isinstance(entry, dict):
                raise AsarError(f"unsafe entry {name!r} at {where or '/'}")
        return files

    def walk(self) -> Iterator[tuple[str, dict]]:
        """Yield (path, entry) for every file and link, with paths like 'node_modules/x/index.js'.

        Raises:
            AsarError: An entry name could escape the archive's folder, or an entry is malformed.
        """
        stack = [("", self.header)]
        while stack:
            prefix, node = stack.pop()
            for name, entry in sorted(self._children(node, prefix).items()):
                p = f"{prefix}{name}"
                if "files" in entry:
                    stack.append((p + "/", entry))
                else:
                    yield p, entry

    def entry(self, path: str) -> dict | None:
        """Return the entry for a path, or None if it isn't in the archive.

        Raises:
            AsarError: The header is malformed along the way.
        """
        node = self.header
        where = ""
        for part in path.strip("/").split("/"):
            node = self._children(node, where).get(part)
            where += part + "/"
            if node is None:
                return None
        return node

    def _span(self, e: dict, path: str) -> tuple[int, int]:
        """Return (absolute offset, size) of a packed file, checking they're sane numbers."""
        try:
            offset, size = int(e["offset"]), int(e["size"])
        except (KeyError, ValueError, TypeError) as err:
            raise AsarError(f"{path}: bad offset or size in the header ({err})") from err
        if offset < 0 or size < 0:
            raise AsarError(f"{path}: negative offset or size in the header")
        return self.data_offset + offset, size

    def read(self, path: str) -> bytes:
        """Return a file's contents, from the archive or from app.asar.unpacked.

        Raises:
            KeyError: The path isn't a file in the archive.
            AsarError: Its header entry is malformed.
        """
        e = self.entry(path)
        if e is None or "files" in e or "link" in e:
            raise KeyError(path)
        if e.get("unpacked"):
            return (self.path.parent / (self.path.name + ".unpacked") / path).read_bytes()
        offset, size = self._span(e, path)
        with open(self.path, "rb") as f:
            f.seek(offset)
            return f.read(size)

    def head(self, path: str, n: int = 64) -> bytes:
        """Return the first n bytes of a file (for magic-byte checks), or b'' when it can't be read."""
        try:
            e = self.entry(path)
            if e is None or "link" in e or "files" in e:
                return b""
            if e.get("unpacked"):
                with open(self.path.parent / (self.path.name + ".unpacked") / path, "rb") as f:
                    return f.read(n)
            offset, size = self._span(e, path)
            with open(self.path, "rb") as f:
                f.seek(offset)
                return f.read(min(n, size))
        except (OSError, KeyError, ValueError, AsarError):
            return b""


def write_asar(dest: str | Path, files: dict[str, bytes], unpacked: AbstractSet[str] = frozenset()) -> None:
    """Write an asar archive (the tests build fake Electron apps with this).

    Args:
        dest: The app.asar to write. Unpacked files go in dest + ".unpacked".
        files: Path -> contents.
        unpacked: Paths to store beside the archive instead of in it.
    """
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    root: dict = {"files": {}}
    blobs = []
    offset = 0
    for path in sorted(files):
        node = root
        parts = path.split("/")
        for part in parts[:-1]:
            node = node["files"].setdefault(part, {"files": {}})
        data = files[path]
        if path in unpacked:
            node["files"][parts[-1]] = {"size": len(data), "unpacked": True}
            out = dest.parent / (dest.name + ".unpacked") / path
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)
        else:
            node["files"][parts[-1]] = {"size": len(data), "offset": str(offset)}
            blobs.append(data)
            offset += len(data)
    js = json.dumps(root, separators=(",", ":")).encode()
    padded = js + b"\0" * (-len(js) % 4)
    pickle = struct.pack("<II", 4 + len(padded), len(js)) + padded
    dest.write_bytes(struct.pack("<II", 4, len(pickle)) + pickle + b"".join(blobs))
