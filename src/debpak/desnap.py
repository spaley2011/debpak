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
    """An installed snap, read from its meta/snap.yaml."""
    name: str
    revision: str
    kind: str                       # app, base, os, snapd, gadget, kernel
    title: str = ""
    desktop_names: list[str] = field(default_factory=list)
    has_apps: bool = False
    path: Path | None = None


@dataclass
class Item:
    """One snap in the desnap plan, and what happened to it.

    Attributes:
        action: flathub (install Flathub's build), convert (convert the snap),
            leave (--no-convert and Flathub lacks it) or tooling (Ubuntu's own
            snap tools, which have no replacement).
        app_id: The Flatpak that replaces the snap.
        stub_deb: The Ubuntu deb that only installs this snap, if installed.
        ok: True once the replacement is installed, False if that failed, None
            before it was tried.
    """
    snap: str
    action: str
    app_id: str = ""
    note: str = ""
    stub_deb: str = ""
    ok: bool | None = None


# --------------------------------------------------------------------------- survey

def installed_snaps(root: Path | None = None) -> list[Snap]:
    """Read every installed snap from its mounted meta/snap.yaml (under snap_root() by default)."""
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
    """Return the installed debs that only exist to install a snap, as {deb name: version}."""
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
    """Return True if a remote named flathub is set up, for the user or system-wide."""
    r = subprocess.run(["flatpak", "remotes", "--columns=name"], capture_output=True, text=True)
    return any(line.strip() == "flathub" for line in r.stdout.splitlines())


def converted_id(snap_name: str) -> str:
    """Return the app ID for a converted snap: local.snap.<name>."""
    last = snap_name if re.match(r"[A-Za-z_]", snap_name) else "_" + snap_name
    return "local.snap." + last


def plan(snaps: list[Snap], stubs: dict[str, str], convert: bool) -> list[Item]:
    """Decide what to do with each app snap.

    Bases, snapd, and theme or content snaps (no apps) aren't in the plan. A
    snap-installer deb whose snap is already gone still gets its Flathub
    replacement offered.

    Args:
        snaps: The installed snaps.
        stubs: The installed snap-installer debs, from snap_stub_debs().
        convert: Convert snaps that Flathub lacks (False for --no-convert).
    """
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

def _sudo(cmd: list[str]) -> list[str]:
    """Prefix cmd with sudo unless we already run as root."""
    return cmd if os.geteuid() == 0 else ["sudo", *cmd]


def _run(cmd: list[str]) -> int:
    """Print and run a command; return its exit status, or 127 if it couldn't start."""
    print("$ " + " ".join(cmd), flush=True)
    try:
        return subprocess.call(cmd)
    except OSError as e:
        print(f"  {cmd[0]}: {e}", file=sys.stderr)
        return 127


def is_installed(app_id: str) -> bool:
    """Return True if a Flatpak with this app ID is installed."""
    return subprocess.run(["flatpak", "info", app_id], capture_output=True).returncode == 0


def copy_data(snap_name: str, app_id: str, converted: bool, home: Path | None = None) -> tuple[int, int]:
    """Copy ~/snap/NAME into ~/.var/app/APP_ID; returns (copied, skipped because they exist).

    Strict snaps run with HOME=~/snap/NAME/current, so their dot-folders map the
    way Flatpak maps them: .config -> config, .local/share -> data,
    .local/state -> .local/state, any other dot-folder (.mozilla, .thunderbird)
    stays as is (Flathub apps keep those with --persist). .cache isn't copied.
    A converted snap also gets the raw folders where its launcher points
    SNAP_USER_DATA and SNAP_USER_COMMON.
    """
    home = home or Path.home()
    src_base = home / "snap" / snap_name
    dst_base = home / ".var" / "app" / app_id
    pairs: list[tuple[Path, Path]] = []
    for part in ("current", "common"):
        src = src_base / part
        if not src.is_dir():
            continue
        if converted:
            pairs.append((src, dst_base / "data" / "snap" / part))
        for entry in sorted(src.iterdir()):
            if entry.name == ".config":
                pairs.append((entry, dst_base / "config"))
            elif entry.name == ".local":
                for sub, to in (("share", dst_base / "data"), ("state", dst_base / ".local" / "state")):
                    if (entry / sub).is_dir():
                        pairs.append((entry / sub, to))
            elif entry.name.startswith(".") and entry.name not in (".cache",) and entry.is_dir():
                pairs.append((entry, dst_base / entry.name))
    copied = skipped = 0
    for src, dst in pairs:
        c, s = _copy_tree_no_clobber(src, dst)
        copied += c
        skipped += s
    return copied, skipped


def _copy_tree_no_clobber(src: Path, dst: Path) -> tuple[int, int]:
    """Copy src into dst, skipping every file that already exists; return (copied, skipped)."""
    copied = skipped = 0
    for dirpath, dirnames, filenames in os.walk(src):
        rel = Path(dirpath).relative_to(src)
        target_dir = dst / rel
        target_dir.mkdir(parents=True, exist_ok=True)
        for name in filenames + [d for d in dirnames if (Path(dirpath) / d).is_symlink()]:
            s, t = Path(dirpath) / name, target_dir / name
            if t.exists() or t.is_symlink():
                skipped += 1
                continue
            if s.is_symlink():
                os.symlink(os.readlink(s), t)
            else:
                shutil.copy2(s, t)
            copied += 1
        dirnames[:] = [d for d in dirnames if not (Path(dirpath) / d).is_symlink()]
    return copied, skipped


def write_pin(prefs_dir: Path) -> int:
    """Write the apt pin that keeps snapd off the system, through sudo if needed; return the exit status."""
    target = prefs_dir / PIN_NAME
    if os.access(prefs_dir, os.W_OK):
        target.write_text(PIN_TEXT)
        print(f"wrote {target}")
        return 0
    print(f"$ sudo tee {target}", flush=True)
    try:
        return subprocess.run(_sudo(["tee", str(target)]), input=PIN_TEXT, text=True,
                              stdout=subprocess.DEVNULL).returncode
    except OSError as e:
        print(f"  {e}", file=sys.stderr)
        return 1


def apt_purge_preview() -> list[str]:
    """Return the packages `apt-get purge snapd` would remove, from a simulated run."""
    r = subprocess.run(["apt-get", "-s", "purge", "snapd"], capture_output=True, text=True)
    return [line.split()[1] for line in r.stdout.splitlines() if line.startswith(("Purg ", "Remv "))]


# --------------------------------------------------------------------------- the command

def _ask(args, question: str) -> bool:
    """Ask a yes/no question. --yes answers yes; with no terminal the answer is no."""
    if args.yes:
        return True
    if not sys.stdin.isatty():
        print(f"{question} -> no (not a terminal; pass --yes to agree)")
        return False
    try:
        return input(f"{question} [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


def _print_plan(items: list[Item], args, stubs: dict[str, str]) -> None:
    """Print the plan, grouped by action, and the optional steps that follow."""
    groups = [("From Flathub", "flathub"), ("Converted from the snap (not on Flathub)", "convert"),
              ("Left alone", "leave"), ("Ubuntu snap tooling (nothing to replace)", "tooling")]
    for title, action in groups:
        rows = [i for i in items if i.action == action]
        if not rows:
            continue
        print(f"\n{title}:")
        for i in rows:
            extra = f"  ({i.note})" if i.note and action in ("leave", "tooling") else ""
            stub = f"  [{i.stub_deb} deb]" if i.stub_deb else ""
            print(f"  {i.snap:<28} {'-> ' + i.app_id if i.app_id else ''}{stub}{extra}")
    replaceable = [i for i in items if i.action in ("flathub", "convert")]
    print("\nThen:")
    print(f"  {'copy' if args.copy_data else 'leave'} each app's data in ~/snap"
          f"{' into ~/.var/app (existing files are kept)' if args.copy_data else ' (--copy-data to copy it)'}")
    if args.remove_snaps:
        print(f"  remove the {len(replaceable)} replaced snap(s), plus their snap-installer debs; "
              "snapd keeps a snapshot of their data for 31 days")
    else:
        print("  keep the snaps installed (--remove-snaps to remove each one once its Flatpak works)")
    if args.block_snapd:
        print(f"  pin snapd out of apt ({PIN_NAME}), and with no app snaps left, offer to purge snapd")
    elif stubs:
        print(f"  {', '.join(stubs)}: installed as snap-installer debs; --block-snapd stops apt "
              "from bringing snapd back through them")


def run(args) -> int:
    """Run `debpak desnap`.

    Steps, each asked about first unless --yes is given:
        1. Install Flathub's build of each app snap, or convert the snap.
        2. With --copy-data, copy each snap's data into the new app's folder.
        3. With --remove-snaps, remove the replaced snaps and their stub debs.
        4. With --block-snapd, pin snapd out of apt, and if no app snaps are
           left (and --remove-snaps was given), offer to purge snapd.

    Returns:
        0 if every requested step worked, else 1.
    """
    from . import cli
    if not shutil.which("flatpak"):
        return cli._err("flatpak isn't installed (sudo apt install flatpak)")
    out_root = Path(args.output or Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share")
                    / "debpak" / "desnap")
    snaps = installed_snaps()
    if args.only:
        missing = set(args.only) - {s.name for s in snaps}
        if missing:
            return cli._err(f"not installed as snaps: {', '.join(sorted(missing))}")
        snaps = [s for s in snaps if s.name in args.only]
    stubs = snap_stub_debs()
    if args.only:
        stubs = {d: v for d, v in stubs.items() if SNAP_STUB_DEBS[d] in args.only}
    if not snaps and not stubs:
        print(f"no snaps installed (looked in {snap_root()})")
        return 0

    if not flathub_configured():
        print("Flathub isn't set up, and desnap needs it to look apps up.")
        if args.dry_run or not _ask(args, "Add the Flathub remote for your user?"):
            print(f"  flatpak remote-add --user --if-not-exists flathub {FLATHUB_URL}")
            return 1
        if _run(["flatpak", "remote-add", "--user", "--if-not-exists", "flathub", FLATHUB_URL]) != 0:
            return cli._err("couldn't add Flathub")
        _run(["flatpak", "update", "--user", "--appstream", "flathub"])

    items = plan(snaps, stubs, convert=not args.no_convert)
    _print_plan(items, args, stubs)
    work = [i for i in items if i.action in ("flathub", "convert")]
    if args.dry_run or not work:
        return 0
    if not _ask(args, f"\nInstall {len(work)} Flatpak(s)?"):
        return 1

    for i in work:
        print(f"\n== {i.snap} -> {i.app_id}")
        if i.action == "flathub":
            i.ok = all(_run(c) == 0 for c in flathub_install_cmd(i.app_id))
        else:
            snap = next(s for s in snaps if s.name == i.snap)
            argv = ["convert", str(snap.path), "--app-id", i.app_id, "-o", str(out_root / i.snap),
                    "--anyway", "--no-flathub-check"]
            if args.runtime_index:
                argv += ["--runtime-index", args.runtime_index]
            for d in args.deps_dir or []:
                argv += ["--deps-dir", d]
            if args.no_build:
                argv.append("--no-build")
            rc = cli.main(argv)
            i.ok = rc == 0 and is_installed(i.app_id)
            if rc == 0 and not i.ok:
                print(f"  {i.snap}: manifest written to {out_root / i.snap} but nothing was installed "
                      "(flatpak-builder missing?)")
        if i.ok and args.copy_data:
            c, s = copy_data(i.snap, i.app_id, converted=i.action == "convert")
            print(f"  data: copied {c} file(s) from ~/snap/{i.snap}"
                  f"{f', kept {s} that already existed' if s else ''}")

    done = [i for i in work if i.ok]
    failed = [i for i in work if not i.ok]
    print(f"\n{len(done)} of {len(work)} installed" + (f"; failed: {', '.join(i.snap for i in failed)}"
                                                      if failed else ""))
    rc = 1 if failed else 0

    if args.remove_snaps and done:
        names = [i.snap for i in done if i.snap in {s.name for s in snaps}]
        debs = [i.stub_deb for i in done if i.stub_deb]
        all_apps_gone = not failed and not any(i.action == "leave" for i in items) and not args.only
        tooling = [i.snap for i in items if i.action == "tooling"] if all_apps_gone else []
        listing = ", ".join(names + tooling + [f"{d} (deb)" for d in debs])
        if _ask(args, f"\nRemove {listing}? snapd keeps a snapshot of the snaps' data for 31 days."):
            if debs and _run(_sudo(["apt-get", "remove", "-y", *debs])) != 0:
                rc = 1
            for n in names + tooling:
                if _run(_sudo(["snap", "remove", n])) != 0:
                    rc = 1

    if args.block_snapd:
        prefs = Path(os.environ.get("DEBPAK_APT_PREFS_DIR", "/etc/apt/preferences.d"))
        if not prefs.is_dir():
            print(f"\n{prefs} doesn't exist; --block-snapd only knows apt, so snapd isn't pinned")
        elif _ask(args, f"\nPin snapd out of apt ({prefs / PIN_NAME})?"):
            rc = write_pin(prefs) or rc
        left = [s.name for s in installed_snaps() if s.kind == "app" and s.has_apps]
        if args.remove_snaps and not left and shutil.which("apt-get"):
            gone = apt_purge_preview()
            if gone:
                print(f"\napt would remove: {' '.join(gone)}")
            if _ask(args, "Purge snapd (removes the remaining base snaps and snapd itself)?"):
                rc = _run(_sudo(["apt-get", "purge", "-y", "snapd"])) or rc
        elif left:
            print(f"\nsnapd stays: still installed as snaps: {', '.join(left)}")
    if done:
        print("\nThe new apps are in your launcher; snaps you kept still have their own entries.")
    return rc
