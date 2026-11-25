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
  --block-snapd   keep snapd from coming back. On Debian and Ubuntu that's an
                  apt pin at priority -10, which also stops the snap-only debs
                  (firefox, chromium-browser, thunderbird) from pulling it in.
                  On Fedora with dnf5 it's a drop-in with excludepkgs=snapd
                  (dnf4 has no drop-ins, so the line to add is printed). On
                  Arch nothing is needed: snapd only comes from the AUR. With
                  --remove-snaps, once no app snaps are left, it also offers to
                  remove snapd, after showing what the package manager would
                  remove with it.

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
    provides_content: bool = False  # offers files to other snaps (mesa-2404, gnome-46-2404, themes)


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
    out: list[Snap] = []
    if not root.is_dir():
        return out
    for d in sorted(root.iterdir()):
        snap = _read_installed(d)
        if snap is not None:
            out.append(snap)
    return out


def _read_installed(d: Path) -> Snap | None:
    """Read the snap installed in folder d from its current/meta/snap.yaml; None if that's missing or unreadable."""
    cur = d / "current"
    yml = cur / "meta" / "snap.yaml"
    if not yml.is_file():
        return None
    try:
        meta = parse_yaml(yml.read_text("utf-8", "replace"))
    except Exception:
        return None
    if not isinstance(meta, dict):
        return None
    try:
        rev = os.readlink(cur)
    except OSError:
        rev = "?"
    names = _desktop_names(cur)
    return Snap(name=str(meta.get("name") or d.name), revision=Path(rev).name,
                kind=str(meta.get("type") or "app"), title=str(meta.get("title") or ""),
                desktop_names=names, has_apps=bool(meta.get("apps")), path=cur,
                provides_content=_provides_content(meta))


def _desktop_names(cur: Path) -> list[str]:
    """Return the Name= of each of the snap's menu entries (meta/gui/*.desktop)."""
    names = []
    for desk in sorted((cur / "meta" / "gui").glob("*.desktop")):
        m = re.search(r"^Name=(.+)$", desk.read_text("utf-8", "replace"), re.M)
        if m:
            names.append(m.group(1).strip())
    return names


def _provides_content(meta: dict) -> bool:
    """Return whether the snap has a content slot: it offers files to other snaps."""
    slots: dict = meta["slots"] if isinstance(meta.get("slots"), dict) else {}
    return any(v == "content" or (isinstance(v, dict) and v.get("interface") == "content")
               or (v is None and k == "content") for k, v in slots.items())


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

    Bases, snapd, theme snaps, and snaps that only provide content to other
    snaps (mesa-2404's helper apps don't make it an app) aren't in the plan. A
    snap-installer deb whose snap is already gone still gets its Flathub
    replacement offered.

    Args:
        snaps: The installed snaps.
        stubs: The installed snap-installer debs, from snap_stub_debs().
        convert: Convert snaps that Flathub lacks (False for --no-convert).
    """
    stub_for = {v: k for k, v in SNAP_STUB_DEBS.items() if k in stubs}
    items = [item for s in snaps if (item := _plan_item(s, stub_for, convert)) is not None]
    # a snap-installer deb whose snap is already gone still gets its Flathub version offered
    return items + _orphan_stub_items(stubs, {s.name for s in snaps})


def _plan_item(s: Snap, stub_for: dict[str, str], convert: bool) -> Item | None:
    """Return what to do with one snap, or None if it isn't an app snap (see plan)."""
    if s.kind != "app" or not s.has_apps:
        return None                                     # bases, snapd, content/theme snaps
    if s.provides_content and not s.desktop_names:
        return None                                     # runtimes for other snaps, such as mesa-2404
    if s.name in TOOLING:
        return Item(s.name, "tooling", note=TOOLING[s.name])
    hit = flathub_match([s.name, s.title, *s.desktop_names])
    if hit:
        return Item(s.name, "flathub", hit.app_id, f"{hit.name} on Flathub", stub_deb=stub_for.get(s.name, ""))
    if convert:
        return Item(s.name, "convert", converted_id(s.name), "not on Flathub", stub_deb=stub_for.get(s.name, ""))
    return Item(s.name, "leave", note="not on Flathub (--no-convert)", stub_deb=stub_for.get(s.name, ""))


def _orphan_stub_items(stubs: dict[str, str], names: set[str]) -> list[Item]:
    """Return Flathub replacements for the snap-installer debs whose snap isn't installed."""
    items = []
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
            pairs += _data_pairs(entry, dst_base)
    copied = skipped = 0
    for src, dst in pairs:
        c, s = _copy_tree_no_clobber(src, dst)
        copied += c
        skipped += s
    return copied, skipped


def _data_pairs(entry: Path, dst_base: Path) -> list[tuple[Path, Path]]:
    """Return (from, to) for the folders of one entry in the snap's HOME that go into the Flatpak's (see copy_data)."""
    if entry.name == ".config":
        return [(entry, dst_base / "config")]
    if entry.name == ".local":
        return [(entry / sub, to) for sub, to in (("share", dst_base / "data"), ("state", dst_base / ".local" / "state"))
                if (entry / sub).is_dir()]
    if entry.name.startswith(".") and entry.name not in (".cache",) and entry.is_dir():
        return [(entry, dst_base / entry.name)]
    return []


def _copy_tree_no_clobber(src: Path, dst: Path) -> tuple[int, int]:
    """Copy src into dst, skipping every file that already exists; return (copied, skipped)."""
    copied = skipped = 0
    for dirpath, dirnames, filenames in os.walk(src):
        rel = Path(dirpath).relative_to(src)
        target_dir = dst / rel
        target_dir.mkdir(parents=True, exist_ok=True)
        for name in filenames + [d for d in dirnames if (Path(dirpath) / d).is_symlink()]:
            if _copy_no_clobber(Path(dirpath) / name, target_dir / name):
                copied += 1
            else:
                skipped += 1
        dirnames[:] = [d for d in dirnames if not (Path(dirpath) / d).is_symlink()]
    return copied, skipped


def _copy_no_clobber(s: Path, t: Path) -> bool:
    """Copy file or symlink s to t unless t exists; return whether it was copied."""
    if t.exists() or t.is_symlink():
        return False
    if s.is_symlink():
        os.symlink(os.readlink(s), t)
    else:
        shutil.copy2(s, t)
    return True


DNF_DROPIN = "debpak-no-snapd.conf"
DNF_TEXT = """\
# Written by `debpak desnap --block-snapd`: keeps snapd off this system. Delete this file to undo.
[main]
excludepkgs=snapd
"""


def _write_root_file(target: Path, text: str) -> int:
    """Write a file, through sudo if needed (creating its folder too); return the exit status."""
    if os.access(target.parent, os.W_OK):
        target.write_text(text)
        print(f"wrote {target}")
        return 0
    try:
        if not target.parent.is_dir() and _run(_sudo(["mkdir", "-p", str(target.parent)])) != 0:
            return 1
        print(f"$ sudo tee {target}", flush=True)
        return subprocess.run(_sudo(["tee", str(target)]), input=text, text=True,
                              stdout=subprocess.DEVNULL).returncode
    except OSError as e:
        print(f"  {e}", file=sys.stderr)
        return 1


class PackageManager:
    """What desnap needs from the system's package manager. Subclasses: Apt, Dnf, Pacman."""
    name = ""

    def install_hint(self, package: str) -> str:
        """Return the command that installs a package."""
        raise NotImplementedError

    def block(self, ask) -> int:
        """Keep snapd from being installed again; return the exit status."""
        raise NotImplementedError

    def purge_preview(self) -> list[str]:
        """Return the packages that removing snapd would remove."""
        raise NotImplementedError

    def purge_cmd(self) -> list[str]:
        """Return the command that removes snapd (run through sudo)."""
        raise NotImplementedError


class Apt(PackageManager):
    name = "apt"

    def install_hint(self, package: str) -> str:
        return f"sudo apt install {package}"

    def block(self, ask) -> int:
        prefs = Path(os.environ.get("DEBPAK_APT_PREFS_DIR", "/etc/apt/preferences.d"))
        if not prefs.is_dir():
            print(f"\n{prefs} doesn't exist, so snapd isn't pinned")
            return 0
        if ask(f"\nPin snapd out of apt ({prefs / PIN_NAME})?"):
            return write_pin(prefs)
        return 0

    def purge_preview(self) -> list[str]:
        return apt_purge_preview()

    def purge_cmd(self) -> list[str]:
        return ["apt-get", "purge", "-y", "snapd"]


class Dnf(PackageManager):
    name = "dnf"

    def __init__(self):
        exe = shutil.which("dnf5") or shutil.which("dnf") or "dnf"
        self.exe = exe
        self.dnf5 = Path(exe).name == "dnf5" or Path(exe).resolve().name == "dnf5"

    def install_hint(self, package: str) -> str:
        return f"sudo dnf install {package}"

    def block(self, ask) -> int:
        if not self.dnf5:
            print("\ndnf4 has no drop-in configuration, so debpak doesn't edit /etc/dnf/dnf.conf. To keep "
                  "snapd off, add this line under [main] there:\n  excludepkgs=snapd")
            return 0
        target = Path(os.environ.get("DEBPAK_DNF_CONF_DIR", "/etc/dnf/libdnf5.conf.d")) / DNF_DROPIN
        if ask(f"\nKeep snapd out of dnf ({target})?"):
            return _write_root_file(target, DNF_TEXT)
        return 0

    def purge_preview(self) -> list[str]:
        r = subprocess.run([self.exe, "remove", "--assumeno", "snapd"], capture_output=True, text=True)
        rows = re.findall(r"^\s+(\S+)\s+(?:x86_64|aarch64|noarch|i686)\s", r.stdout, re.M)
        return list(dict.fromkeys(rows))

    def purge_cmd(self) -> list[str]:
        return [Path(self.exe).name, "remove", "-y", "snapd"]


class Pacman(PackageManager):
    name = "pacman"

    def install_hint(self, package: str) -> str:
        return f"sudo pacman -S {package}"

    def block(self, ask) -> int:
        print("\nOn Arch, snapd only comes from the AUR, so nothing installs it again unless you do; "
              "there's nothing to pin.")
        return 0

    def purge_preview(self) -> list[str]:
        r = subprocess.run(["pacman", "-Rsp", "--print-format", "%n", "snapd"], capture_output=True, text=True)
        return [line.strip() for line in r.stdout.splitlines() if line.strip()]

    def purge_cmd(self) -> list[str]:
        return ["pacman", "-Rns", "--noconfirm", "snapd"]


def package_manager() -> PackageManager | None:
    """Return the system's package manager ($DEBPAK_PKG_MANAGER overrides the guess), or None."""
    forced = os.environ.get("DEBPAK_PKG_MANAGER")
    kinds = {"apt": Apt, "dnf": Dnf, "pacman": Pacman}
    if forced in kinds:
        return kinds[forced]()
    if shutil.which("apt-get") and shutil.which("dpkg"):
        return Apt()
    if shutil.which("dnf5") or shutil.which("dnf"):
        return Dnf()
    if shutil.which("pacman"):
        return Pacman()
    return None


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
        _print_group(title, action, [i for i in items if i.action == action])
    replaceable = [i for i in items if i.action in ("flathub", "convert")]
    print("\nThen:")
    print(f"  {'copy' if args.copy_data else 'leave'} each app's data in ~/snap"
          f"{' into ~/.var/app (existing files are kept)' if args.copy_data else ' (--copy-data to copy it)'}")
    if args.remove_snaps:
        print(f"  remove the {len(replaceable)} replaced snap(s), plus their snap-installer debs; "
              "snapd keeps a snapshot of their data for 31 days")
    else:
        print("  keep the snaps installed (--remove-snaps to remove each one once its Flatpak works)")
    _print_block_step(args, stubs)


def _print_group(title: str, action: str, rows: list[Item]) -> None:
    """Print the plan's items for one action, if there are any."""
    if not rows:
        return
    print(f"\n{title}:")
    for i in rows:
        extra = f"  ({i.note})" if i.note and action in ("leave", "tooling") else ""
        stub = f"  [{i.stub_deb} deb]" if i.stub_deb else ""
        print(f"  {i.snap:<28} {'-> ' + i.app_id if i.app_id else ''}{stub}{extra}")


def _print_block_step(args, stubs: dict[str, str]) -> None:
    """Print the plan's last step: blocking snapd, or a hint about the snap-installer debs."""
    if args.block_snapd:
        how = {"apt": f"pin snapd out of apt ({PIN_NAME})",
               "dnf": f"keep snapd out of dnf ({DNF_DROPIN})",
               "pacman": "nothing to pin on Arch (snapd comes from the AUR)"}.get(
            getattr(package_manager(), "name", ""), "keep snapd from coming back")
        print(f"  {how}, and with no app snaps left, offer to remove snapd")
    elif stubs:
        print(f"  {', '.join(stubs)}: installed as snap-installer debs; --block-snapd stops apt "
              "from bringing snapd back through them")


def run(args) -> int:
    """Run `debpak desnap`.

    Steps, each asked about first unless --yes is given:
        1. Install Flathub's build of each app snap, or convert the snap.
        2. With --copy-data, copy each snap's data into the new app's folder.
        3. With --remove-snaps, remove the replaced snaps and their stub debs.
        4. With --block-snapd, keep snapd from coming back (see the module
           docstring for each package manager), and if no app snaps are left
           (and --remove-snaps was given), offer to remove snapd.

    Returns:
        0 if every requested step worked, else 1.
    """
    pm = package_manager()
    if (rc := _cant_run(pm)) is not None:
        return rc
    found = _snaps_to_replace(args, pm)
    if isinstance(found, int):
        return found
    snaps, stubs = found
    if (rc := _ensure_flathub(args)) is not None:
        return rc

    items = plan(snaps, stubs, convert=not args.no_convert)
    _print_plan(items, args, stubs)
    work = [i for i in items if i.action in ("flathub", "convert")]
    if args.dry_run or not work:
        return 0
    if not _ask(args, f"\nInstall {len(work)} Flatpak(s)?"):
        return 1
    out_root = Path(args.output or _data_home() / "debpak" / "desnap")
    for i in work:
        _install_one(i, snaps, args, out_root)
    return _finish(args, pm, items, work, snaps)


def _finish(args, pm, items: list[Item], work: list[Item], snaps: list[Snap]) -> int:
    """Report what got installed, then remove the replaced snaps and block snapd if asked; return the exit status."""
    done, failed = [i for i in work if i.ok], [i for i in work if not i.ok]
    _print_installed(done, failed)
    rc = 1 if failed else 0
    if args.remove_snaps and done:
        rc = _remove_replaced(args, items, done, bool(failed), snaps) or rc
    if args.block_snapd:
        rc = _block_snapd(args, pm) or rc
    if done:
        print("\nThe new apps are in your launcher; snaps you kept still have their own entries.")
    return rc


def _cant_run(pm) -> int | None:
    """Return an exit status if desnap can't run here (inside a Flatpak, or without flatpak), else None."""
    from . import cli, host
    if host.in_flatpak():
        # snap, apt-get, dnf and sudo are host programs, and so are the files desnap reads
        # under /snap and /etc: it has to run from debpak installed on the host
        return cli._err("desnap changes the host's packages, so it can't run from the debpak Flatpak; "
                        "install debpak on the host with pip (see README.md) and run it from there")
    if not shutil.which("flatpak"):
        return cli._err("flatpak isn't installed" + (f" ({pm.install_hint('flatpak')})" if pm else ""))
    return None


def _data_home() -> Path:
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share")


def _print_installed(done: list[Item], failed: list[Item]) -> None:
    failures = f"; failed: {', '.join(i.snap for i in failed)}" if failed else ""
    print(f"\n{len(done)} of {len(done) + len(failed)} installed{failures}")


def _snaps_to_replace(args, pm) -> tuple[list[Snap], dict[str, str]] | int:
    """Return the installed snaps and snap-installer debs desnap works on, or an exit status to stop with."""
    from . import cli
    snaps = installed_snaps()
    if args.only:
        missing = set(args.only) - {s.name for s in snaps}
        if missing:
            return cli._err(f"not installed as snaps: {', '.join(sorted(missing))}")
        snaps = [s for s in snaps if s.name in args.only]
    stubs = snap_stub_debs() if isinstance(pm, Apt) else {}
    if args.only:
        stubs = {d: v for d, v in stubs.items() if SNAP_STUB_DEBS[d] in args.only}
    if not snaps and not stubs:
        print(f"no snaps installed (looked in {snap_root()})")
        return 0
    return snaps, stubs


def _ensure_flathub(args) -> int | None:
    """Add the Flathub remote if it's missing; return an exit status to stop with, or None to go on."""
    from . import cli
    if flathub_configured():
        return None
    print("Flathub isn't set up, and desnap needs it to look apps up.")
    if args.dry_run or not _ask(args, "Add the Flathub remote for your user?"):
        print(f"  flatpak remote-add --user --if-not-exists flathub {FLATHUB_URL}")
        return 1
    if _run(["flatpak", "remote-add", "--user", "--if-not-exists", "flathub", FLATHUB_URL]) != 0:
        return cli._err("couldn't add Flathub")
    _run(["flatpak", "update", "--user", "--appstream", "flathub"])
    return None


def _install_one(i: Item, snaps: list[Snap], args, out_root: Path) -> None:
    """Install Flathub's build of one snap or convert it, set i.ok, and copy its data if asked."""
    print(f"\n== {i.snap} -> {i.app_id}")
    if i.action == "flathub":
        i.ok = all(_run(c) == 0 for c in flathub_install_cmd(i.app_id))
    else:
        i.ok = _convert_one(i, snaps, args, out_root)
    if i.ok and args.copy_data:
        c, s = copy_data(i.snap, i.app_id, converted=i.action == "convert")
        print(f"  data: copied {c} file(s) from ~/snap/{i.snap}"
              f"{f', kept {s} that already existed' if s else ''}")


def _convert_one(i: Item, snaps: list[Snap], args, out_root: Path) -> bool:
    """Convert one snap with `debpak convert` and install it; return whether its Flatpak is installed."""
    from . import cli
    snap = next(s for s in snaps if s.name == i.snap)
    rc = cli.main(_convert_argv(i, snap, args, out_root))
    ok = rc == 0 and is_installed(i.app_id)
    if rc == 0 and not ok:
        print(f"  {i.snap}: manifest written to {out_root / i.snap} but nothing was installed "
              "(flatpak-builder missing?)")
    return ok


def _convert_argv(i: Item, snap: Snap, args, out_root: Path) -> list[str]:
    """Return the `debpak convert` arguments for one snap, passing on desnap's options."""
    argv = ["convert", str(snap.path), "--app-id", i.app_id, "-o", str(out_root / i.snap),
            "--anyway", "--no-flathub-check"]
    if args.runtime_index:
        argv += ["--runtime-index", args.runtime_index]
    for d in args.deps_dir or []:
        argv += ["--deps-dir", d]
    if args.no_build:
        argv.append("--no-build")
    return argv


def _remove_replaced(args, items: list[Item], done: list[Item], any_failed: bool, snaps: list[Snap]) -> int:
    """Offer to remove the replaced snaps (and Ubuntu's tooling snaps once no apps are left); return 1 on failure."""
    names = [i.snap for i in done if i.snap in {s.name for s in snaps}]
    debs = [i.stub_deb for i in done if i.stub_deb]
    tooling = [i.snap for i in items if i.action == "tooling"] if _all_apps_gone(args, items, any_failed) else []
    listing = ", ".join(names + tooling + [f"{d} (deb)" for d in debs])
    if not _ask(args, f"\nRemove {listing}? snapd keeps a snapshot of the snaps' data for 31 days."):
        return 0
    return _remove(debs, names + tooling)


def _remove(debs: list[str], snap_names: list[str]) -> int:
    """Remove the debs, then each snap; return 1 if any removal failed."""
    rc = 0
    if debs and _run(_sudo(["apt-get", "remove", "-y", *debs])) != 0:
        rc = 1
    for n in snap_names:
        if _run(_sudo(["snap", "remove", n])) != 0:
            rc = 1
    return rc


def _all_apps_gone(args, items: list[Item], any_failed: bool) -> bool:
    """Return whether no app snaps will be left once the replaced ones are removed."""
    return not any_failed and not any(i.action == "leave" for i in items) and not args.only


def _block_snapd(args, pm) -> int:
    """Keep snapd from coming back, and offer to remove it when no app snaps are left; return 1 on failure."""
    rc = 0
    if pm is None:
        print("\nno apt, dnf or pacman found, so snapd isn't blocked")
    else:
        rc = pm.block(lambda q: _ask(args, q)) or rc
    left = [s.name for s in installed_snaps() if s.kind == "app" and s.has_apps]
    if args.remove_snaps and not left and pm is not None:
        rc = _purge_snapd(args, pm) or rc
    elif left:
        print(f"\nsnapd stays: still installed as snaps: {', '.join(left)}")
    return rc


def _purge_snapd(args, pm) -> int:
    """Show what removing snapd would take with it, and remove it if the user agrees; return the exit status."""
    gone = pm.purge_preview()
    if gone:
        print(f"\n{pm.name} would remove: {' '.join(gone)}")
    if _ask(args, "Remove snapd (and the remaining base snaps with it)?"):
        return _run(_sudo(pm.purge_cmd()))
    return 0
