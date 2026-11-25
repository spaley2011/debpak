"""Running a Windows installer under Wine when no tool can unpack it.

Some installers have no reader: Inno Setup newer than innoextract knows, WiX
bundles, InstallShield, and installers with formats of their own. For those,
debpak runs the installer silently in a new Wine prefix and takes the folder
it installed, the way a person would install it in Wine and convert the
installed folder.

The installer runs in org.winehq.Wine's own Flatpak sandbox (`flatpak run
--sandbox`), which sees nothing of the host but the prefix's folder, at
first with no network. One that installs nothing that way runs again with
the network, with the switches that let it finish rather than wait: a
downloader (Battle.net's, GOG Galaxy's) fetches the program, and others
fetch a prerequisite first (ActivePresenter, the WebView2 runtime). Its windows
go to a virtual display (xvfb-run) when the host has one, else to the
user's display. winedbg is turned off, so an installer that crashes ends
instead of waiting on a crash dialog. An installer that installs nothing with
any silent switch is then clicked through on the virtual display, with
xdotool pressing Alt+A for the licence and Return for each page, as a person
would.

What it installed is found by listing the prefix before and after: the
folder under Program Files, AppData\\Local\\Programs, AppData or
ProgramData, or a new folder of its own in C:\\ (Laragon's C:\\laragon),
with the most new files, preferring the one a new Start menu or desktop
shortcut points into, whose target becomes the main program. Registry
entries and files the installer put elsewhere (in Windows\\System32, say)
aren't kept.
"""
from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
from pathlib import Path

from . import host

# Inno Setup writes what it did here, and why it stopped ("PrepareToInstall failed: ...")
INNO_LOG = "/LOG=C:\\debpak-setup.log"

# the switches that make each kind of installer run without asking anything; an installer of
# unknown kind gets each set in turn until one installs something
SILENT = {
    "inno": [["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-", "/CURRENTUSER", INNO_LOG]],
    "wix": [["/quiet", "/norestart"]],
    "installshield": [["/s", "/v/qn"]],
    "nsis": [["/S"]],
    "advanced-installer": [["/exenoui", "/qn"]],
    # BitRock InstallBuilder (DeepSkyStacker, Scrivener) takes options of its own, Unix style
    "installbuilder": [["--mode", "unattended", "--unattendedmodeui", "none"]],
    "other": [["/S"], ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-"], ["/quiet", "/norestart"],
              ["/silent"]],
}
# seconds an installer of a known kind may take, and each guess for one of unknown kind
TIMEOUT = 600
GUESS_TIMEOUT = 180
# folders a new Wine prefix has, or that installers fill with things that aren't the program
NOT_PROGRAM = {"common files", "internet explorer", "windows media player", "windows nt", "microsoft",
               "microsoft.net", "temp", "package cache", "windowsapps", "wine", "packages", "crashdumps"}

# runs inside the sandbox: $1 the list of files before, $2 seconds allowed, then the installer and its switches
SCRIPT = """\
wineboot -i >/dev/null 2>&1
wineserver -w
find "$WINEPREFIX/drive_c" -type f -printf '%P\\n' > "$1"
timeout "$2" wine "${@:3}"
echo "debpak: installer exit status $?"
# a program the installer started when it finished (Inno's [Run]) would keep Wine running
timeout 30 wineserver -w || wineserver -k
"""


class InstallError(Exception):
    pass


def kind_of(path: Path, marker: bytes | None) -> str:
    """Return the SILENT key for an installer, from the marker foreign.py found in it, or "other"."""
    if marker == b"Inno Setup Setup Data":
        return "inno"
    if marker == b".wixburn":
        return "wix"
    if marker == b"InstallShield":
        return "installshield"
    if marker in (b"NullsoftInst", b"Nullsoft Install System"):
        return "nsis"
    with open(path, "rb") as f:
        head = f.read(4 << 20)
    if b"Advanced Installer" in head:
        return "advanced-installer"
    if b"BitRock" in head or b"InstallBuilder" in head:
        return "installbuilder"
    return "other"


def missing() -> str | None:
    """Return what's missing for running installers (a sentence), or None when everything is there."""
    if not host.which("flatpak"):
        return "running it needs flatpak"
    return None


def wine_ready(branch: str) -> bool:
    """Return whether org.winehq.Wine//branch is installed, installing it from Flathub if not.

    The build needs it anyway, as the base app, and would install it itself.
    """
    ref = f"org.winehq.Wine//{branch}"
    if subprocess.run(host.command(["flatpak", "info", ref]), capture_output=True).returncode == 0:
        return True
    print(f"(installing {ref} from Flathub to run the installer; the build needs it anyway)")
    return subprocess.run(host.command(["flatpak", "install", "--user", "-y", "--noninteractive", "flathub", ref]),
                          capture_output=True).returncode == 0


def install(installer: Path, work: Path, kind: str, branch: str) -> tuple[Path, str | None, str, bool]:
    """Run installer silently in a new prefix under work and return what it installed.

    Returns:
        (the program's folder, its main .exe relative to that folder when a
        new shortcut names one, the switches that worked, whether it needed
        the network).

    Raises:
        InstallError: Nothing could run it, or it installed no program.
    """
    if (why := missing()):
        raise InstallError(why)
    if not wine_ready(branch):
        raise InstallError(f"running it needs org.winehq.Wine//{branch}, which couldn't be installed from Flathub")
    work.mkdir(parents=True, exist_ok=True)
    (work / "in").mkdir(exist_ok=True)
    # Wine couldn't open osu!install.exe by that name (exit status 53); a plain name always works
    setup = work / "in" / (re.sub(r"[^A-Za-z0-9._-]", "_", installer.stem) + installer.suffix.lower())
    shutil.copyfile(installer, setup)
    script = work / "install.sh"
    script.write_text(SCRIPT)
    prefix = work / "prefix"
    tries = SILENT.get(kind, SILENT["other"])
    seconds = GUESS_TIMEOUT if kind == "other" else TIMEOUT
    log, finished = [], []
    for switches in tries:
        before = work / "before.txt"
        out = _run(setup, switches, prefix, script, before, seconds, branch)
        log.append(out)
        if not before.is_file():
            raise InstallError("Wine didn't start: " + _tail(out))
        found = installed(prefix, set(before.read_text().splitlines()))
        if found:
            return (*found, " ".join(switches), False)
        if "installer exit status 124" not in out and "didn't finish" not in out:
            finished.append(switches)
    # the network, for a downloader (Battle.net's, GOG Galaxy's) or for an installer that fetches a
    # prerequisite first (ActivePresenter's needs the WebView2 runtime: "PrepareToInstall failed")
    for switches in finished:
        before = work / "before.txt"
        out = _run(setup, switches, prefix, script, before, seconds, branch, network=True)
        log.append(out)
        found = installed(prefix, set(before.read_text().splitlines())) if before.is_file() else None
        if found:
            return (*found, " ".join(switches), True)
    if clicker_ready():
        # an installer that ignores every silent switch, or has none, or asks a question no switch
        # answers (TypingMaster's offer of Opera), is clicked through as a person would: accept the
        # licence and press the default button until it's done
        before = work / "before.txt"
        out = _run(setup, [], prefix, script, before, TIMEOUT, branch, network=True, click=True)
        log.append(out)
        found = installed(prefix, set(before.read_text().splitlines())) if before.is_file() else None
        if found:
            return (*found, "(clicked through)", True)
    why = _setup_log(prefix) or _tail(log[-1])
    raise InstallError("it ran under Wine but installed no program"
                       + (" with any of the usual silent switches" if len(tries) > 1 else
                          f" ({' '.join(tries[0])})") + (" or by clicking through it" if clicker_ready() else "")
                       + (": " + why if why else ""))


# runs on the host under xvfb-run: $1 seconds, then the flatpak command. While the installer runs, it
# presses Alt+A (the accelerator of "I accept" / "I Agree" in Inno, NSIS, MSI and InstallShield licence
# pages) and Return (the default button: Next, Install, Finish) in each window on the virtual screen
CLICKER = """\
secs=$1; shift
"$@" &
pid=$!
end=$(( $(date +%s) + secs ))
while kill -0 "$pid" 2>/dev/null && [ "$(date +%s)" -lt "$end" ]; do
    sleep 4
    for w in $(xdotool search --onlyvisible --name "" 2>/dev/null | tail -n 3); do
        xdotool windowfocus "$w" 2>/dev/null
        xdotool key --clearmodifiers alt+a 2>/dev/null
        sleep 0.5
        xdotool key --clearmodifiers Return 2>/dev/null
        sleep 0.5
    done
done
wait "$pid"
"""


def clicker_ready() -> bool:
    """True if installers can be clicked through: a virtual screen (xvfb-run) and xdotool on the host."""
    return bool(host.which("xvfb-run") and host.which("xdotool"))


def _run(setup: Path, switches: list[str], prefix: Path, script: Path, before: Path, seconds: int,
         branch: str, network: bool = False, click: bool = False) -> str:
    """Run one attempt and return its output; with click, press through its windows (CLICKER)."""
    work = prefix.parent
    xvfb = host.which("xvfb-run")
    clicker = []
    if click:
        (work / "click.sh").write_text(CLICKER)
        clicker = ["sh", str(work / "click.sh"), str(seconds + 60)]
    cmd = [*(["xvfb-run", "-a", "-s", "-screen 0 1280x1024x24"] if xvfb else []), *clicker,
           "flatpak", "run", "--sandbox", "--socket=x11", "--share=network" if network else "--unshare=network",
           f"--filesystem={work}",
           f"--env=WINEPREFIX={prefix}", "--env=WINEDEBUG=-all",
           "--env=WINEDLLOVERRIDES=winedbg.exe,winemenubuilder.exe=d", "--command=bash",
           f"org.winehq.Wine//{branch}", str(script), str(before), str(seconds), str(setup), *switches]
    # the script stops the installer itself; this is for Wine hanging on the way out, and its
    # own process group lets the whole sandbox be stopped without touching other Wine programs
    proc = subprocess.Popen(host.command(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            errors="replace", start_new_session=True)
    try:
        return proc.communicate(timeout=seconds + 240)[0]
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        return (proc.communicate()[0] or "") + f"\n(it didn't finish in {seconds + 240} seconds)"


def _setup_log(prefix: Path) -> str:
    """Return the line of Inno Setup's log (INNO_LOG) that says why it stopped, or ""."""
    f = prefix / "drive_c/debpak-setup.log"
    try:
        lines = f.read_text("utf-8", "replace").splitlines()
    except OSError:
        return ""
    hits = [ln.split("   ", 1)[-1].strip() for ln in lines if re.search(r"failed|error|abort|cannot", ln, re.I)
            and "DLL" not in ln]
    return hits[0][:300] if hits else ""


# Wine's and Xvfb's chatter, left out of what an error quotes
NOISE = re.compile(r"ALSA|PulseAudio|session bus|^X|XIO|after \d+ requests|debpak: installer exit status 0")


def _tail(out: str) -> str:
    """Return the last two lines of an attempt's output that say something."""
    keep = [ln.strip() for ln in out.splitlines() if ln.strip() and not NOISE.search(ln)]
    return " / ".join(keep[-2:])


def installed(prefix: Path, before: set[str]) -> tuple[Path, str | None] | None:
    """Return (program folder, main .exe in it or None) from the files new in prefix, or None."""
    drive = prefix / "drive_c"
    sizes: dict[Path, int] = {}
    exes: dict[Path, int] = {}
    links = []
    for f in drive.rglob("*"):
        if not f.is_file() or f.is_symlink():
            continue
        rel = f.relative_to(drive).as_posix()
        if rel in before or rel.lower().startswith("windows/"):
            continue
        if f.suffix.lower() == ".lnk":
            links.append(f)
            continue
        root = _program_root(f.relative_to(drive).parts)
        if root is None:
            continue
        sizes[root] = sizes.get(root, 0) + f.stat().st_size
        if f.suffix.lower() == ".exe" and not re.match(r"(?i)unins|uninst", f.stem):
            exes[root] = exes.get(root, 0) + 1
    if not exes:
        return None
    for lnk in sorted(links):
        target = _lnk_target(lnk, drive)
        if target is None:
            continue
        rel = target.relative_to(drive).parts
        root = _program_root(rel)
        if root in exes:
            return drive.joinpath(*root), Path(*rel[len(root):]).as_posix()
    best = max(exes, key=lambda r: sizes.get(r, 0))
    return drive.joinpath(*best), None


# drive_c's own folders; a new folder beside them is a program's own (Laragon installs to C:\laragon)
DRIVE_C = {"program files", "program files (x86)", "programdata", "users", "windows"}


def _program_root(parts: tuple[str, ...]) -> tuple[str, ...] | None:
    """Return the parts of the folder a program installed under drive_c lives in, or None."""
    low = [p.lower() for p in parts]
    n = None
    if low[0] in ("program files", "program files (x86)", "programdata"):
        n = 2
    elif low[0] not in DRIVE_C and len(parts) > 1:
        n = 1
    elif low[0] == "users" and len(low) > 4 and low[2:4] == ["appdata", "local"] and low[4] == "programs":
        n = 6
    elif low[0] == "users" and len(low) > 3 and low[2] == "appdata" and low[3] in ("local", "roaming"):
        n = 5
    if n is None or len(parts) <= n or low[n - 1] in NOT_PROGRAM | DRIVE_C:
        return None
    return tuple(parts[:n])


def _lnk_target(lnk: Path, drive: Path) -> Path | None:
    """Return the .exe a Windows shortcut points to, inside drive, or None."""
    data = lnk.read_bytes()
    texts = [data.decode("latin-1"), data.decode("utf-16-le", errors="ignore"),
             data[1:].decode("utf-16-le", errors="ignore")]
    for text in texts:
        for m in re.finditer(r"[A-Za-z]:\\[^\x00-\x1f\"*?<>|]+?\.exe", text, re.I):
            path = m.group(0)
            if path[0].lower() != "c":
                continue
            found = _case_insensitive(drive, path[3:].split("\\"))
            if found:
                return found
    return None


def _case_insensitive(base: Path, parts: list[str]) -> Path | None:
    """Return base/parts matched without regard to case (Windows paths), or None."""
    p = base
    for part in parts:
        if not part:
            continue
        if (p / part).exists():
            p = p / part
            continue
        hit = next((c for c in p.iterdir() if c.name.lower() == part.lower()), None) if p.is_dir() else None
        if hit is None:
            return None
        p = hit
    return p if p.is_file() else None
