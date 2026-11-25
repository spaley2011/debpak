"""Flatpak runtime indexing.

An index records which library file names a runtime makes available on the
default linker search path, plus the symbol versions each library defines.
It is built by scanning an installed runtime's `files/` directory (which is
mounted at /usr inside the sandbox) on the host, so nothing has to run inside
the sandbox. Indexes are cached as JSON.
"""
from __future__ import annotations

import json
import os
import platform
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .elf import ElfError, is_elf, read_elf

TRIPLETS = {
    "x86_64": "x86_64-linux-gnu",
    "aarch64": "aarch64-linux-gnu",
    "i386": "i386-linux-gnu",
    "arm": "arm-linux-gnueabihf",
}

# Provided at runtime by the GL extension (org.freedesktop.Platform.GL.*)
# or by the host driver stack, never bundled.
EXTENSION_PROVIDED_PREFIXES = (
    "libGL.so", "libGLX", "libEGL.so", "libGLESv1_CM.so", "libGLESv2.so",
    "libOpenGL.so", "libGLdispatch.so", "libvulkan.so", "libgbm.so",
    "libcuda.so", "libnvidia-", "libnvcuvid.so", "libva.so", "libva-",
    "libvdpau.so", "libOpenCL.so",
)

INDEX_FORMAT = 1


def host_arch() -> str:
    """Return this machine's architecture under Flatpak's name (x86_64, aarch64, ...)."""
    m = platform.machine()
    return {"amd64": "x86_64", "arm64": "aarch64"}.get(m, m)


def parse_ref(ref: str, arch: str | None = None) -> tuple[str, str, str]:
    """Split a runtime ref into (id, arch, branch).

    Accepts ID//BRANCH, which takes arch (or this machine's), and ID/ARCH/BRANCH.

    Raises:
        ValueError: The ref has neither form.
    """
    parts = ref.split("/")
    if len(parts) == 3:
        rid, rarch, branch = parts
        return rid, rarch or arch or host_arch(), branch
    raise ValueError(f"runtime ref must look like ID//BRANCH or ID/ARCH/BRANCH, got {ref!r}")


def sdk_for(runtime_id: str) -> str:
    """Return the SDK that goes with a runtime: org.freedesktop.Platform -> org.freedesktop.Sdk."""
    return runtime_id.replace(".Platform", ".Sdk") if ".Platform" in runtime_id else runtime_id + ".Sdk"


@dataclass
class RuntimeIndex:
    """Which libraries a Flatpak runtime provides, and their symbol versions.

    Attributes:
        ref: The full ref, ID/ARCH/BRANCH.
        sonames: Library file name -> its path inside the sandbox (/usr/lib/...).
        verdefs: Library file name -> the symbol versions it defines.
        glibc: The highest GLIBC_ version the runtime's libc defines.
    """
    ref: str
    arch: str
    sonames: dict[str, str] = field(default_factory=dict)      # file name -> path inside runtime
    verdefs: dict[str, list[str]] = field(default_factory=dict)  # file name -> version names
    glibc: str | None = None

    @property
    def id(self) -> str:
        return self.ref.split("/")[0]

    @property
    def branch(self) -> str:
        return self.ref.split("/")[-1]

    def provides(self, soname: str) -> bool:
        """Return True if the sandbox will have soname.

        GL, Vulkan and driver libraries count as provided even when the runtime
        lacks them, because the GL extension supplies them at run time.
        """
        return soname in self.sonames or soname.startswith(EXTENSION_PROVIDED_PREFIXES)

    def versions_of(self, soname: str) -> set[str] | None:
        """Return the symbol versions soname defines, or None if the runtime doesn't have it."""
        v = self.verdefs.get(soname)
        return set(v) if v is not None else None

    def to_json(self) -> dict:
        return {"format": INDEX_FORMAT, "ref": self.ref, "arch": self.arch, "glibc": self.glibc,
                "sonames": self.sonames, "verdefs": self.verdefs}

    @classmethod
    def from_json(cls, d: dict) -> RuntimeIndex:
        """Read an index saved by to_json().

        Raises:
            ValueError: The index was written by an incompatible debpak version.
        """
        if d.get("format") != INDEX_FORMAT:
            raise ValueError("runtime index format mismatch; rebuild it")
        return cls(ref=d["ref"], arch=d["arch"], sonames=d["sonames"], verdefs=d["verdefs"],
                   glibc=d.get("glibc"))

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_json(), indent=1, sort_keys=True))

    @classmethod
    def load(cls, path: Path) -> RuntimeIndex:
        return cls.from_json(json.loads(Path(path).read_text()))


def library_dirs(root: Path, arch: str) -> list[Path]:
    """Return the default library search folders inside a runtime's files/ (its /usr), those that exist."""
    triplet = TRIPLETS.get(arch, f"{arch}-linux-gnu")
    candidates = [root / "lib" / triplet, root / "lib64", root / "lib"]
    return [d for d in candidates if d.is_dir()]


def index_root(root: str | Path, ref: str, arch: str) -> RuntimeIndex:
    """Index a runtime's usr tree (the `files/` dir of an installed runtime)."""
    root = Path(root)
    idx = RuntimeIndex(ref=ref, arch=arch)
    for d in library_dirs(root, arch):
        for entry in os.scandir(d):
            name = entry.name
            if ".so" not in name or name in idx.sonames:
                continue
            real = Path(entry.path).resolve()
            if not real.is_file() or not is_elf(real):
                continue
            try:
                info = read_elf(real, want_symbols=False)
            except ElfError:
                continue
            if info.machine != arch:
                continue
            idx.sonames[name] = "/usr/" + str(Path(entry.path).relative_to(root))
            if info.verdef:
                idx.verdefs[name] = sorted(info.verdef)
    libc_versions = idx.versions_of("libc.so.6") or set()
    from .elf import max_version

    idx.glibc = max_version(libc_versions, "GLIBC")
    return idx


def installed_runtime_location(ref: str, arch: str) -> Path:
    """Return the files/ folder of an installed runtime (mounted as /usr in the sandbox).

    Raises:
        RuntimeError: flatpak isn't installed, or the runtime isn't; the
            message says how to install it.
    """
    rid, _, branch = parse_ref(ref, arch)
    full = f"{rid}/{arch}/{branch}"
    try:
        from . import host
        out = subprocess.run(host.command(["flatpak", "info", "--show-location", full]),
                             check=True, capture_output=True, text=True).stdout.strip()
    except FileNotFoundError as e:
        raise RuntimeError("flatpak is not installed; pass --runtime-index FILE instead") from e
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"runtime {full} is not installed. Install it with:\n"
            f"  flatpak install flathub {full}\n{e.stderr.strip()}"
        ) from e
    files = Path(out) / "files"
    if not files.is_dir():
        raise RuntimeError(f"unexpected runtime layout at {out}")
    return files


def cache_dir() -> Path:
    """Return debpak's cache folder (~/.cache/debpak)."""
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "debpak"


def get_index(ref: str, arch: str, rebuild: bool = False) -> RuntimeIndex:
    """Return the index of an installed runtime, building and caching it on first use.

    Raises:
        RuntimeError: See installed_runtime_location.
    """
    rid, arch, branch = parse_ref(ref, arch)
    full = f"{rid}/{arch}/{branch}"
    cached = cache_dir() / "runtimes" / f"{rid}_{arch}_{branch}.json"
    if cached.is_file() and not rebuild:
        return RuntimeIndex.load(cached)
    idx = index_root(installed_runtime_location(full, arch), full, arch)
    idx.save(cached)
    return idx
