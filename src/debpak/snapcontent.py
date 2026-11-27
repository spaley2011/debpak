"""The content snaps a snap runs on, and what in a Flatpak stands in for each.

Most graphical snaps are built with one of snapcraft's extensions (gnome, kde-neon,
kde-neon-6), which plug content snaps for their toolkit (gnome-46-2404, kf6-core24, ...),
their themes (gtk-common-themes) and their graphics stack (mesa-2404), and run the app
through the extension's desktop-launch, which points the app at those snaps and at its
own folders. None of those snaps exist next to a Flatpak, so each is mapped to what
does:

- a toolkit platform (GNOME, KDE Frameworks, Qt) to the Flatpak runtime of the same
  toolkit, whose libraries are newer; what the content snap had that the runtime lacks is
  found like any missing library, from the Ubuntu release the snap was built on first;
- the graphics stack (mesa-*, gpu-2404, graphics-core22) to the runtime's GL extension
  (org.freedesktop.Platform.GL.default), which the runtime finds by itself;
- theme snaps and the other platform snaps (FFmpeg, LXQt's Qt plugins, WebKitGTK) to the
  runtime's own copies, found on the runtime's default paths.

So the snap's environment loses the entries that point into the content snaps' mount
folders, which are empty in the snap (the runtime's own folders are searched anyway), and
the extension's desktop-launch, which debpak skips, is stood in for by what of it is
about the snap's own folders (snap.DESKTOP_LAUNCH). Wine's platform snaps have no stand-in
(see snap.PLATFORM_SNAPS).
"""
from __future__ import annotations

import re
from pathlib import Path

# (default-provider pattern, what it is, what stands in for it). The kind decides the rest:
# gnome, kde5 and kde6 pick a runtime (see runtime_for); the others need nothing but the
# runtime's own copies
CONTENT_SNAPS = (
    # gnome-3-28-1804, gnome-3-34-1804, gnome-3-38-2004, gnome-42-2204, gnome-46-2404, gnome-core26
    (r"gnome-\d+(-\d+)*-\d{4}(-sdk)?|gnome-core\d\d(-sdk)?", "gnome", "the GNOME runtime"),
    (r"webkitgtk-\d+-gnome-\d{4}(-sdk)?", "gnome", "the GNOME runtime's WebKitGTK"),
    # kde-frameworks-5-core18, kde-frameworks-5-99-qt-5-15-7-core20, kf5-5-113-qt-5-15-11-core22, qt515-core20
    (r"kde-frameworks-5(-[\w.-]+)?-core\d\d|kf5(-[\w.-]+)?-core\d\d|qt5\d*-core\d\d|qt5-\w+", "kde5",
     "the KDE runtime (Qt 5.15)"),
    (r"kf6-core\d\d|kde-frameworks-6(-[\w.-]+)?-core\d\d|qt6\d*-core\d\d|qt6-\w+", "kde6", "the KDE runtime (Qt 6)"),
    (r"mesa-\d{4}|mesa-core\d\d|gpu-\d{4}|graphics-core\d\d", "gl", "the runtime's GL extension"),
    (r"gtk-common-themes|gtk2-common-themes|icon-themes|sound-themes", "themes", "the runtime's themes and icons"),
    (r"lxqt-support(-core\d\d)?", "qt-theme", "the KDE runtime's Qt platform themes"),
    (r"ffmpeg-\d{4}|chromium-ffmpeg", "codecs", "the runtime's FFmpeg"),
)

# what the runtime ref for a kind is, in analyze.DEFAULT_RUNTIMES
RUNTIME_KINDS = {"gnome": "gnome", "kde5": "kde5", "kde6": "kde6"}
# the app kinds (analyze.classify) a toolkit content snap decides the runtime for: a GTK or
# plain program and scripts; Qt apps already get KDE's, and Chromium apps run on the Electron
# base app, which is built for the Freedesktop runtime
DECIDES_FOR = {"gnome": ("gtk3", "gtk4", "elf"), "kde5": ("elf",), "kde6": ("elf",)}


def content_kind(provider: str) -> tuple[str, str] | None:
    """Return (kind, what stands in for it) for a content snap's name, or None for one debpak doesn't know."""
    for pattern, kind, stand_in in CONTENT_SNAPS:
        if re.fullmatch(pattern, provider):
            return kind, stand_in
    return None


def content_plugs(meta: dict) -> list[dict]:
    """Return the snap's content plugs: {plug, provider, target (relative to $SNAP, or ""), kind, stand_in}.

    The provider is the plug's default-provider; a plug without one is named
    after its content (gpu-2404 plugs often have only that). kind and stand_in
    are None for a content snap debpak has no mapping for.
    """
    plugs = meta.get("plugs") if isinstance(meta.get("plugs"), dict) else {}
    out = []
    for plug, spec in plugs.items():
        if not isinstance(spec, dict) or spec.get("interface") != "content":
            continue
        provider = str(spec.get("default-provider") or spec.get("content") or plug).split(":")[0]
        m = re.fullmatch(r"\$(?:SNAP|\{SNAP\})/(.+?)/?", str(spec.get("target") or ""))
        known = content_kind(provider) or content_kind(str(spec.get("content") or plug))
        out.append({"plug": str(plug), "provider": provider, "target": m.group(1) if m else "",
                    "kind": known[0] if known else None, "stand_in": known[1] if known else None})
    return out


def runtime_for(meta: dict, kind: str) -> str | None:
    """Return the DEFAULT_RUNTIMES key of the runtime the snap's toolkit content snap maps to, or None.

    Dialect's snap (a Python GTK app) plugs gnome-42-2204, which brought it PyGObject,
    libadwaita and the rest of GNOME; on the Freedesktop runtime, picked because the app
    links nothing of GTK itself, it stopped at "No module named 'gi'". Glance Optimizer's and
    Facturel Soft's (Tauri apps on gnome-46-2404) carry their own WebKitGTK, whose helper
    programs were in the content snap: they crashed with "Failed to spawn child process
    .../webkit2gtk-4.1/WebKitNetworkProcess", which the GNOME runtime has. A snap built on a
    GNOME, KDE Frameworks or Qt content snap now gets that toolkit's runtime, unless the
    kind of app (see DECIDES_FOR) has its own rule.
    """
    for p in content_plugs(meta):
        if p["kind"] in RUNTIME_KINDS and kind in DECIDES_FOR[p["kind"]]:
            return RUNTIME_KINDS[p["kind"]]
    return None


def _mount_folders(meta: dict, opt: Path | None) -> list[str]:
    """Return the content plugs' folders, relative to $SNAP, that a known content snap fills and the snap doesn't."""
    out = []
    for p in content_plugs(meta):
        if not p["kind"] or not p["target"] or p["target"] in (".", ""):
            continue
        d = opt / p["target"] if opt is not None else None
        try:
            if d is not None and d.is_dir() and not d.is_symlink() and any(d.iterdir()):
                continue        # the snap carries what the content snap would have brought
        except OSError:
            pass
        out.append(p["target"])
    return out


def split_path_list(v: str) -> list[str]:
    """Split a colon-separated list, not inside ${...}: "$SNAP/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" is one entry."""
    parts, cur, depth, i = [], "", 0, 0
    while i < len(v):
        if v.startswith("${", i):
            depth += 1
            cur += "${"
            i += 2
            continue
        ch = v[i]
        if ch == "}" and depth:
            depth -= 1
        if ch == ":" and not depth:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
        i += 1
    parts.append(cur)
    return parts


def _providers(meta: dict) -> list[str]:
    return [p["provider"] for p in content_plugs(meta) if p["kind"]]


def content_environment(env: dict, meta: dict, opt: Path | None = None) -> tuple[dict, list[str]]:
    """Return the snap's environment without what points into the folders of its content snaps.

    Snaps on kf6-core24 (KGoldrunner, Kubrick, QElectroTech) set
    QT_PLUGIN_PATH=$SNAP/lxqt-support-core24/usr/lib/<triplet>/qt6/plugins:${QT_PLUGIN_PATH},
    LD_LIBRARY_PATH and ALSA_CONFIG_PATH into $SNAP/kf6; gnome ones PYTHONPATH,
    FONTCONFIG_PATH and XDG_DATA_DIRS into $SNAP/gnome-platform; some name the content
    snap's own mount (/snap/kf6-core24/current/usr/lib/<triplet>). Those folders are empty
    outside snapd, and the runtime that stands in for the content snap (see
    CONTENT_SNAPS) is found on its default paths, so each such entry of a list goes,
    and a variable left with nothing but its own old value, or that names one such
    path, goes too. A content folder the snap fills itself stays.

    Returns:
        (the environment, the variables changed).
    """
    folders = _mount_folders(meta, opt)
    providers = _providers(meta)
    if not folders and not providers:
        return dict(env), []
    alts = [r"\$(?:SNAP|\{SNAP\})/" + re.escape(f) for f in folders] + \
           [r"/snap/" + re.escape(p) + r"/(?:current|\d+|x\d+)" for p in providers]
    into = re.compile(r"^(?:" + "|".join(alts) + r")(?:/|$)") if alts else None
    out, changed = {}, []
    for k, v in env.items():
        v = str(v)
        if into is None or str(k) == "SNAP_DESKTOP_RUNTIME":
            out[k] = v
            continue
        parts = split_path_list(v)
        kept = [x for x in parts if not into.match(x)]
        if len(kept) == len(parts):
            out[k] = v
            continue
        changed.append(str(k))
        own = re.compile(r"^\$\{?" + re.escape(str(k)) + r"(?::[-+][^}]*)?\}?$")
        if any(x and not own.match(x) for x in kept):
            out[k] = ":".join(x for x in kept if x or len(kept) == 1)
    return out, changed


def describe(meta: dict) -> str:
    """Return a note on the content snaps the snap plugs and what stands in for each, or ""."""
    seen, parts = set(), []
    for p in content_plugs(meta):
        if p["kind"] and p["provider"] not in seen:
            seen.add(p["provider"])
            parts.append(f"{p['provider']} -> {p['stand_in']}")
    return ("the snap's content snaps are stood in for by the runtime: " + ", ".join(parts)) if parts else ""


def extension_desktop_launch(spec: dict) -> bool:
    """Return True if the app runs through a snapcraft extension's desktop-launch (snap/command-chain/desktop-launch)."""
    return any(re.fullmatch(r"snap/command-chain/desktop-launch\d*", str(c)) for c in spec.get("command-chain") or [])

