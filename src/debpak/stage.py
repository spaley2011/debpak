"""Lay out the /app tree and write the flatpak-builder manifest.

Two modes:
  bundle      - the vendor payload is copied into the Flatpak (simple; you
                are redistributing the vendor's binaries).
  extra-data  - the manifest references the vendor's .deb by URL + sha256
                and an apply_extra script unpacks it at install time on the
                user's machine (how Flathub ships Chrome, Slack, etc.).
Bundled gap-filling libraries always go in /app/lib/debpak.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__
from .analyze import Analysis, desktop_entry_value
from .desktop import app_display_name, install_icons, install_mime, metainfo, rewrite_desktop
from .deb import resolve_in_root
from .maintscripts import STRIP_PREFIXES
from .permissions import Permission
from .runtime import TRIPLETS, parse_ref, sdk_for

WRAPPER = "debpak-run"
BUNDLED_LIBDIR = "lib/debpak"
ELECTRON_BASE = "org.electronjs.Electron2.BaseApp"


@dataclass
class StageResult:
    manifest_path: Path
    notes: list[str] = field(default_factory=list)


def map_bundle(rel: str) -> str:
    """Payload-relative path -> path relative to /app in bundle mode."""
    rel = rel.strip("/")
    if rel.startswith("usr/local/"):
        return rel[len("usr/local/"):]
    if rel.startswith("usr/"):
        return rel[len("usr/"):]
    return rel


def install_path(rel: str, mode: str) -> str:
    return "/app/extra/" + rel.strip("/") if mode == "extra-data" else "/app/" + map_bundle(rel)


def _stripped(rel: str) -> bool:
    return any(rel == p or rel.startswith(p + "/") for p in STRIP_PREFIXES)


def _copy_payload(root: Path, dest: Path) -> None:
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        keep_dirs = []
        for d in dirnames:
            rel = f"{rel_dir}/{d}".lstrip("/")
            if _stripped(rel):
                continue
            if (Path(dirpath) / d).is_symlink():
                filenames.append(d)
            else:
                keep_dirs.append(d)
        dirnames[:] = keep_dirs
        for fn in filenames:
            rel = f"{rel_dir}/{fn}".lstrip("/")
            if _stripped(rel) or (rel.startswith("usr/share/applications/") and rel.endswith(".desktop")):
                continue
            src = Path(dirpath) / fn
            out = dest / map_bundle(rel)
            out.parent.mkdir(parents=True, exist_ok=True)
            if src.is_symlink():
                target = os.readlink(src)
                target_rel = (target.lstrip("/") if target.startswith("/")
                              else os.path.normpath(os.path.join(rel_dir, target)))
                if target_rel.startswith(".."):
                    continue  # escapes the payload; drop it
                mapped_target = map_bundle(target_rel)
                link = os.path.relpath(mapped_target, os.path.dirname(map_bundle(rel)) or ".")
                if out.exists() or out.is_symlink():
                    out.unlink()
                os.symlink(link, out)
            elif src.is_file():
                shutil.copy2(src, out)


def _rewrite_prefixes(a: Analysis, mode: str) -> list[tuple[str, str]]:
    pairs = set()
    for h in a.hardcoded:
        for prefix in _prefix_candidates(h.path, a.pkg.name):
            pairs.add((prefix, install_path(prefix, mode)))
    return sorted(pairs, key=lambda p: -len(p[0]))


def _prefix_candidates(path: str, pkg_name: str) -> list[str]:
    parts = path.strip("/").split("/")
    if parts[0] == "opt" and len(parts) >= 2:
        return ["/" + "/".join(parts[:2])]
    if parts[:2] in (["usr", "share"], ["usr", "lib"]) and len(parts) >= 3 and parts[2] == pkg_name:
        return ["/" + "/".join(parts[:3])]
    return []


def library_path_dirs(a: Analysis, mode: str, have_bundled: bool) -> list[str]:
    dirs: list[str] = []
    if have_bundled:
        dirs.append("/app/" + BUNDLED_LIBDIR)
    triplet = TRIPLETS.get(a.arch, f"{a.arch}-linux-gnu")
    standard = {"usr/lib", "lib", f"usr/lib/{triplet}", f"lib/{triplet}", "usr/lib64", "lib64"}
    needed_pkg_dirs = set()
    for soname, rel in a.package_sonames.items():
        d = os.path.dirname(rel)
        if d in standard and (soname in _all_needed(a)):
            needed_pkg_dirs.add(d)
    for rp in sorted(a.abs_rpath_dirs):
        rel = rp.strip("/")
        if (a.root / rel).is_dir():
            needed_pkg_dirs.add(rel)
    for d in sorted(needed_pkg_dirs):
        p = install_path(d, mode)
        if mode == "bundle" and p in ("/app/lib",):
            continue  # already on the default search path
        if p not in dirs:
            dirs.append(p)
    return dirs


def _all_needed(a: Analysis) -> set[str]:
    s: set[str] = set()
    for info in a.elfs.values():
        s.update(info.needed)
    return s


def wrapper_script(a: Analysis, mode: str, lib_dirs: list[str]) -> str:
    target = install_path(a.main_exec, mode)
    lines = ["#!/bin/sh", f"# Generated by debpak {__version__} for {a.pkg.name} {a.pkg.version}"]
    if lib_dirs:
        lines.append(f'export LD_LIBRARY_PATH="{":".join(lib_dirs)}${{LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}}"')
    for k, v in sorted(a.desktop_exec_env.items()):
        lines.append(f"export {k}={shlex.quote(v)}")
    launcher = "zypak-wrapper " if a.kind == "electron" and not a.main_exec_is_script else ""
    lines.append(f'exec {launcher}{shlex.quote(target)} "$@"')
    return "\n".join(lines) + "\n"


def apply_extra_script(a: Analysis, deb_filename: str) -> str:
    lines = ["#!/bin/sh", "set -e", f"# Generated by debpak {__version__}: unpack {a.pkg.name} at install time",
             f"bsdtar -Oxf {shlex.quote(deb_filename)} 'data.tar*' | bsdtar -xf -",
             f"rm -f {shlex.quote(deb_filename)}"]
    strip = [p for p in STRIP_PREFIXES if (a.root / p).exists()]
    if strip:
        lines.append("rm -rf " + " ".join(shlex.quote(p) for p in strip))
    pairs = _rewrite_prefixes(a, "extra-data")
    text_files = sorted({h.file for h in a.hardcoded if h.is_text})
    if pairs and text_files:
        expr = " ".join("-e " + shlex.quote(f"s#{old}\\([^A-Za-z0-9._-]\\|$\\)#{new}\\1#g")
                        for old, new in pairs)
        for f in text_files:
            lines.append(f"sed -i {expr} {shlex.quote(f)}")
    return "\n".join(lines) + "\n"


