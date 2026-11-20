"""debpak desnap: swap every installed snap for a Flatpak.

For each app snap, Flathub's build wins when Flathub has the app; otherwise the
snap itself is converted (`debpak convert /snap/NAME/current`). Snap metadata
(plugs, slots, interfaces) is ignored: permissions come from what the binaries
link against, as with any other package.

Nothing is removed unless asked for:

  --copy-data     copy ~/snap/NAME into ~/.var/app/ID. Existing files are never
                  overwritten.
  --remove-snaps  `snap remove` each snap whose Flatpak installed. snapd keeps
                  an automatic snapshot of the snap's data for 31 days.
  --block-snapd   pin snapd to priority -10 in apt, so the snap-only debs
                  (firefox, chromium-browser, thunderbird) can't pull it back
                  in. With --remove-snaps, once no app snaps are left, it also
                  offers to purge snapd, after showing what apt would remove.

The whole plan is printed first, and each kind of change is confirmed
separately unless --yes is given.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .manage import flathub_install_cmd, flathub_match
from .snap import parse_yaml, snap_root

FLATHUB_URL = "https://dl.flathub.org/repo/flathub.flatpakrepo"

# Ubuntu's own snap tooling: nothing to replace, and gone with snapd.
TOOLING = {
    "snap-store": "for a store app, use GNOME Software with its Flatpak plugin "
                  "(sudo apt install gnome-software gnome-software-plugin-flatpak)",
    "snapd-desktop-integration": "",
    "prompting-client": "",
    "desktop-security-center": "",
    "firmware-updater": "firmware updates also work with fwupdmgr (package fwupd)",
}

# debs that Ubuntu ships as installers for a snap: deb name -> snap name
SNAP_STUB_DEBS = {"firefox": "firefox", "chromium-browser": "chromium", "thunderbird": "thunderbird"}

PIN_NAME = "debpak-no-snapd.pref"
PIN_TEXT = """\
# Written by `debpak desnap --block-snapd`. Keeps snapd off this system, which also
# stops apt from installing debs that only exist to install a snap (Ubuntu's
# firefox, chromium-browser and thunderbird). Delete this file to undo.
Package: snapd
Pin: release a=*
Pin-Priority: -10
"""


@dataclass
class Snap:
    name: str
    revision: str
    kind: str                       # app, base, os, snapd, gadget, kernel
    title: str = ""
    desktop_names: list[str] = field(default_factory=list)
    has_apps: bool = False
    path: Path | None = None


@dataclass
class Item:
    snap: str
    action: str                     # flathub | convert | leave | tooling
    app_id: str = ""
    note: str = ""
    stub_deb: str = ""
    ok: bool | None = None


# --------------------------------------------------------------------------- survey

def installed_snaps(root: Path | None = None) -> list[Snap]:
    root = root or snap_root()
    out = []
    if not root.is_dir():
        return out
    for d in sorted(root.iterdir()):
        cur = d / "current"
        yml = cur / "meta" / "snap.yaml"
        if not yml.is_file():
            continue
        try:
            meta = parse_yaml(yml.read_text("utf-8", "replace"))
        except Exception:
            continue
        if not isinstance(meta, dict):
            continue
        try:
            rev = os.readlink(cur)
        except OSError:
            rev = "?"
        names = []
        for desk in sorted((cur / "meta" / "gui").glob("*.desktop")):
            m = re.search(r"^Name=(.+)$", desk.read_text("utf-8", "replace"), re.M)
            if m:
                names.append(m.group(1).strip())
        out.append(Snap(name=str(meta.get("name") or d.name), revision=Path(rev).name,
                        kind=str(meta.get("type") or "app"), title=str(meta.get("title") or ""),
                        desktop_names=names, has_apps=bool(meta.get("apps")), path=cur))
    return out


def snap_stub_debs() -> dict[str, str]:
    """Installed snap-installer debs: {deb name: version}."""
    dq = shutil.which("dpkg-query")
    if not dq:
        return {}
    r = subprocess.run([dq, "-W", "-f=${Package}\t${Version}\t${db:Status-Abbrev}\n", *SNAP_STUB_DEBS],
                       capture_output=True, text=True)
    found = {}
    for line in r.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[2].startswith("ii") and "snap" in parts[1]:
            found[parts[0]] = parts[1]
    return found


def flathub_configured() -> bool:
    r = subprocess.run(["flatpak", "remotes", "--columns=name"], capture_output=True, text=True)
    return any(line.strip() == "flathub" for line in r.stdout.splitlines())


def converted_id(snap_name: str) -> str:
    last = snap_name if re.match(r"[A-Za-z_]", snap_name) else "_" + snap_name
    return "local.snap." + last


def plan(snaps: list[Snap], stubs: dict[str, str], convert: bool) -> list[Item]:
    items = []
    stub_for = {v: k for k, v in SNAP_STUB_DEBS.items() if k in stubs}
    names = {s.name for s in snaps}
    for s in snaps:
        if s.kind != "app" or not s.has_apps:
            continue                                    # bases, snapd, content/theme snaps
        if s.name in TOOLING:
            items.append(Item(s.name, "tooling", note=TOOLING[s.name]))
            continue
        hit = flathub_match([s.name, s.title, *s.desktop_names])
        if hit:
            items.append(Item(s.name, "flathub", hit.app_id, f"{hit.name} on Flathub",
                              stub_deb=stub_for.get(s.name, "")))
        elif convert:
            items.append(Item(s.name, "convert", converted_id(s.name), "not on Flathub",
                              stub_deb=stub_for.get(s.name, "")))
        else:
            items.append(Item(s.name, "leave", note="not on Flathub (--no-convert)",
                              stub_deb=stub_for.get(s.name, "")))
    # a snap-installer deb whose snap is already gone still gets its Flathub version offered
    for deb in stubs:
        snap_name = SNAP_STUB_DEBS[deb]
        if snap_name in names:
            continue
        hit = flathub_match([snap_name])
        if hit:
            items.append(Item(snap_name, "flathub", hit.app_id, f"{hit.name} on Flathub; the {deb} deb only "
                              "installs a snap", stub_deb=deb))
    return items


# --------------------------------------------------------------------------- doing it

