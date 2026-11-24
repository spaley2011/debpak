"""Lay out the /app tree and write the flatpak-builder manifest.

Two modes:
  bundle      the vendor's files are copied into the Flatpak. Simple, but you
              are redistributing the vendor's binaries.
  extra-data  the manifest names the vendor's file by URL and sha256, and an
              apply_extra script unpacks it on the user's machine at install
              time (how Flathub ships Chrome and Slack).
Libraries added to fill gaps always go in /app/lib/debpak.
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
from .analyze import CHROMIUM_KINDS, Analysis, desktop_entry_value
from . import net
from .desktop import app_display_name, install_icons, install_mime, metainfo, placeholder_icon, rewrite_desktop
from .deb import resolve_in_root
from .maintscripts import STRIP_PREFIXES
from .permissions import Permission
from .runtime import TRIPLETS, parse_ref, sdk_for

WRAPPER = "debpak-run"
BUNDLED_LIBDIR = "lib/debpak"
ELECTRON_BASE = "org.electronjs.Electron2.BaseApp"


@dataclass
class StageResult:
    """Where stage() wrote the manifest, and notes for the report."""
    manifest_path: Path
    notes: list[str] = field(default_factory=list)


def map_bundle(rel: str) -> str:
    """Map a payload path to its place under /app in bundle mode: usr/bin/x -> bin/x, opt/V -> opt/V."""
    rel = rel.strip("/")
    if rel.startswith("usr/local/"):
        return rel[len("usr/local/"):]
    if rel.startswith("usr/"):
        return rel[len("usr/"):]
    return rel


def install_path(rel: str, mode: str) -> str:
    """Return where a payload path ends up in the sandbox: under /app in bundle mode, /app/extra in extra-data mode."""
    return "/app/extra/" + rel.strip("/") if mode == "extra-data" else "/app/" + map_bundle(rel)


def _stripped(rel: str) -> bool:
    """Return True for payload paths in STRIP_PREFIXES (cron jobs, systemd units, ...), which aren't copied."""
    return any(rel == p or rel.startswith(p + "/") for p in STRIP_PREFIXES)


def _copy_payload(root: Path, dest: Path) -> None:
    """Copy the package's files into the /app tree, mapped with map_bundle.

    Stripped paths and the original .desktop files (stage writes its own) are
    left out. Symlinks are rewritten as relative links to the target's new place;
    a link that points outside the package is dropped.
    """
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
    """Return (old, new) install prefixes for the hardcoded paths found, longest first so nested prefixes rewrite correctly."""
    pairs = set()
    for h in a.hardcoded:
        for prefix in _prefix_candidates(h.path, a.pkg.name):
            pairs.add((prefix, install_path(prefix, mode)))
    return sorted(pairs, key=lambda p: -len(p[0]))


def _prefix_candidates(path: str, pkg_name: str) -> list[str]:
    """Return the install prefix a hardcoded path sits under (/opt/<dir>, /usr/share/<pkg> or /usr/lib/<pkg>), if any."""
    parts = path.strip("/").split("/")
    if parts[0] == "opt" and len(parts) >= 2:
        return ["/" + "/".join(parts[:2])]
    if parts[:2] in (["usr", "share"], ["usr", "lib"]) and len(parts) >= 3 and parts[2] == pkg_name:
        return ["/" + "/".join(parts[:3])]
    return []


def library_path_dirs(a: Analysis, mode: str, have_bundled: bool) -> list[str]:
    """Return the folders the wrapper puts on LD_LIBRARY_PATH.

    That's the bundle's lib/debpak when libraries were added, the package's own
    library folders that hold a needed soname, and any absolute RPATH folder
    the package ships. /app/lib is left out, being on the default path already.
    """
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
    """Return every DT_NEEDED soname across the package's ELF files."""
    s: set[str] = set()
    for info in a.elfs.values():
        s.update(info.needed)
    return s


def wrapper_script(a: Analysis, mode: str, lib_dirs: list[str]) -> str:
    """Write the launcher script that the Flatpak's command and .desktop file run.

    It sets LD_LIBRARY_PATH and any env VAR=... from the original Exec= line,
    then runs the entry point (through zypak-wrapper for Electron and CEF
    binaries; zypak needs ZYPAK_CEF_LIBRARY_PATH to find a CEF app's libcef.so).
    """
    target = install_path(a.main_exec, mode)
    lines = ["#!/bin/sh", f"# Generated by debpak {__version__} for {a.pkg.name} {a.pkg.version}"]
    if lib_dirs:
        lines.append(f'export LD_LIBRARY_PATH="{":".join(lib_dirs)}${{LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}}"')
    for k, v in sorted(a.desktop_exec_env.items()):
        lines.append(f"export {k}={shlex.quote(v)}")
    if a.kind == "cef" and (cef := a.package_sonames.get("libcef.so")):
        lines.append(f"export ZYPAK_CEF_LIBRARY_PATH={shlex.quote(install_path(cef, mode))}")
    launcher = "zypak-wrapper " if a.kind in CHROMIUM_KINDS and not a.main_exec_is_script else ""
    lines.append(f'exec {launcher}{shlex.quote(target)} "$@"')
    return "\n".join(lines) + "\n"


def extra_filename(pkg) -> str:
    """Return the vendor file's name in /app/extra, with the extension its format needs."""
    fmt = getattr(pkg, "format", "deb")
    if fmt == "deb":
        return f"{pkg.name}.deb"
    if fmt == "rpm":
        return f"{pkg.name}.rpm"
    if fmt == "appimage":
        return f"{pkg.name}.AppImage"
    m = re.search(r"(\.pkg\.tar(?:\.\w+)?|\.tar\.\w+|\.tgz|\.txz|\.tbz2?|\.tar|\.zip)$", pkg.path.name, re.I)
    return pkg.name + (m.group(1) if m else ".archive")


def apply_extra_script(a: Analysis, filename: str) -> str:
    """Unpack the vendor's file inside /app/extra at install time, into the same layout
    debpak analyzed (usr/..., opt/NAME/...)."""
    pkg = a.pkg
    fmt = getattr(pkg, "format", "deb")
    f = shlex.quote(filename)
    lines = ["#!/bin/sh", "set -e", f"# Generated by debpak {__version__}: unpack {pkg.name} ({fmt}) at install time"]
    if fmt == "deb":
        lines.append(f"bsdtar -Oxf {f} 'data.tar*' | bsdtar -xf -")
    elif fmt == "rpm":
        lines.append(f"bsdtar -xf {f}")                      # libarchive reads RPM payloads
    elif fmt == "pacman":
        lines.append(f"bsdtar -xf {f} --exclude .PKGINFO --exclude .MTREE --exclude .BUILDINFO "
                     "--exclude .INSTALL --exclude .CHANGELOG")
    elif fmt == "run":
        if "replay" not in pkg.extra:
            raise ValueError("--mode extra-data can't unpack this .run installer at install time (its payload "
                             "is zstd-compressed); use the default bundle mode")
        lines.append("python3 /app/bin/debpak-unpack /app/share/debpak/unpack.json")
    elif fmt == "appimage":
        opt = shlex.quote(f"opt/{pkg.extra['opt_name']}")
        # uruntime ("anylinux") AppImages unpack into AppDir and leave squashfs-root as a symlink to it
        lines += [f"chmod +x {f}", f"./{filename} --appimage-extract >/dev/null",
                  f'mkdir -p opt && rm -rf {opt} && mv "$(readlink -f squashfs-root)" {opt} && rm -f squashfs-root']
    else:   # plain archive
        opt = shlex.quote(f"opt/{pkg.extra['opt_name']}")
        strip = int(pkg.extra.get("strip", 0))
        lines += [f"mkdir -p {opt}",
                  f"bsdtar -xf {f} -C {opt}" + (f" --strip-components {strip}" if strip else "")]
    lines.append(f"rm -f {f}")
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


def _write_exec(path: Path, text: str) -> None:
    """Write text to path and make it executable."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755)


def stage(a: Analysis, out: Path, app_id: str, runtime_ref: str, mode: str,
          permissions: list[Permission], bundled: dict[str, str], bundled_libdir: Path | None,
          url: str | None = None) -> StageResult:
    """Write the /app tree and the flatpak-builder manifest into out.

    Args:
        a: The analysis of the package.
        out: The output folder; out/app is replaced.
        app_id: The Flatpak app ID.
        runtime_ref: The runtime to build against.
        mode: "bundle" copies the package into the Flatpak; "extra-data" has the
            user's machine download it at install time, from url.
        permissions: finish-args, from permissions.infer.
        bundled: Soname -> origin of the libraries fill_gaps added.
        bundled_libdir: Where fill_gaps put those libraries.
        url: The vendor's download URL (extra-data mode only).

    Raises:
        ValueError: extra-data mode without a url.
    """
    res = StageResult(manifest_path=out / f"{app_id}.json")
    app = out / "app"
    if app.exists():
        shutil.rmtree(app)
    app.mkdir(parents=True)
    root = a.root

    # payload
    if mode == "bundle":
        _copy_payload(root, app)
        text_files = sorted({h.file for h in a.hardcoded if h.is_text})
        for f in text_files:
            p = app / map_bundle(f)
            if p.is_file() and not p.is_symlink():
                data = p.read_bytes()
                for old, new in _rewrite_prefixes(a, "bundle"):
                    data = re.sub(rb"(?<![A-Za-z0-9._/-])" + re.escape(old.encode()) + rb"(?![A-Za-z0-9._-])",
                                  new.encode(), data)
                p.write_bytes(data)
        binary_hits = sorted({h.file for h in a.hardcoded if not h.is_text})
        if binary_hits:
            res.notes.append("binaries contain hardcoded install paths that cannot be rewritten: "
                             + ", ".join(binary_hits[:5]) + ("..." if len(binary_hits) > 5 else ""))
    else:
        (app / "extra").mkdir()  # placeholder so the dir exists at build time

    # gap-filling libraries
    if bundled and bundled_libdir:
        dest = app / BUNDLED_LIBDIR
        dest.mkdir(parents=True, exist_ok=True)
        for so in bundled:
            shutil.copy2(bundled_libdir / so, dest / so)

    # launcher
    lib_dirs = library_path_dirs(a, mode, bool(bundled))
    _write_exec(app / "bin" / WRAPPER, wrapper_script(a, mode, lib_dirs))

    # desktop integration
    share = app / "share"
    name = app_display_name(root, a.desktop_file, a.pkg.name)
    has_desktop = False
    if a.desktop_file:
        text = (root / a.desktop_file).read_text("utf-8", "replace")
        icon = desktop_entry_value(text, "Icon")
        dest = share / "applications" / f"{app_id}.desktop"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(rewrite_desktop(text, app_id, WRAPPER))
        has_desktop = True
        icons, warns = install_icons(root, icon, share, app_id)
        res.notes += warns
        if not icons:
            d = share / "icons/hicolor/128x128/apps"
            d.mkdir(parents=True, exist_ok=True)
            (d / f"{app_id}.png").write_bytes(placeholder_icon(app_id))
            res.notes.append("made a plain placeholder icon, since AppStream won't accept an app without one")
    else:
        res.notes.append("package ships no .desktop file; the app will only be runnable via `flatpak run`")
    install_mime(root, share, app_id)
    md = share / "metainfo" / f"{app_id}.metainfo.xml"
    md.parent.mkdir(parents=True, exist_ok=True)
    md.write_text(metainfo(a.pkg, app_id, name, has_desktop))

    # manifest
    rid, _arch, branch = parse_ref(runtime_ref, a.arch)
    sources: list[dict] = [{"type": "dir", "path": "app"}]
    build_commands = [
        "cp -a . ${FLATPAK_DEST}/",
        f"chmod +x ${{FLATPAK_DEST}}/bin/{WRAPPER}",
    ]
    if mode == "extra-data":
        if not url:
            raise ValueError("extra-data mode needs --url pointing at the vendor's download")
        extra_name = extra_filename(a.pkg)
        data = a.pkg.path.read_bytes()
        sources.append({"type": "extra-data", "filename": extra_name, "url": net.quote_url(url),
                        "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
        _write_exec(app / "bin" / "apply_extra", apply_extra_script(a, extra_name))
        build_commands.append("chmod +x ${FLATPAK_DEST}/bin/apply_extra")
        if getattr(a.pkg, "format", "") == "run":
            from .unpack import install_helper
            r = a.pkg.extra["replay"]
            install_helper(app, {"source": extra_name, "steps": r["steps"], "take": r["take"],
                                 "target": f"opt/{a.pkg.extra['opt_name']}", "drop": r["drop"]})
        shutil.rmtree(app / "extra")

    manifest: dict = {
        "id": app_id,
        "runtime": rid,
        "runtime-version": branch,
        "sdk": sdk_for(rid),
    }
    if a.kind in CHROMIUM_KINDS:
        manifest["base"] = ELECTRON_BASE
        manifest["base-version"] = branch
        if rid != "org.freedesktop.Platform":
            res.notes.append(f"{ELECTRON_BASE} expects org.freedesktop.Platform; runtime is {rid}")
    manifest.update({
        "command": WRAPPER,
        "separate-locales": False,
        "finish-args": [p.arg for p in permissions],
        "modules": [{
            "name": a.pkg.name,
            "buildsystem": "simple",
            "build-commands": build_commands,
            "sources": sources,
        }],
        "x-debpak": {
            "generator": f"debpak {__version__}",
            "source-deb" if getattr(a.pkg, "format", "deb") == "deb" else "source-package": a.pkg.path.name,
            "format": getattr(a.pkg, "format", "deb"),
            "package": f"{a.pkg.name} {a.pkg.version}",
            "mode": mode,
            "kind": a.kind,
            "entry-point": a.main_exec,
            "permission-reasons": {p.arg: p.reason for p in permissions},
            "bundled-libraries": bundled,
        },
    })
    res.manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    return res
