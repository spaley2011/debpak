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
xdotool pressing the keys a person would try (Alt+A for the licence, Space
for a checkbox, Return for each page), a different set each time round.

What it installed is found by listing the prefix before and after: the
folder under Program Files, AppData\\Local\\Programs, AppData or
ProgramData, or a new folder of its own in C:\\ (Laragon's C:\\laragon),
with the most new files, preferring the one a new Start menu or desktop
shortcut points into, whose target becomes the main program. A folder with
no program but an app package (.msix), which the installer goes on to
register with PowerShell's Add-AppxPackage, gives that package, which
convert unpacks. Registry entries and files the installer put elsewhere
aren't kept, but for the libraries it put in Windows\\System32 or SysWOW64,
which are kept aside in case the program needs one to start (see
take_system_files).
"""
from __future__ import annotations

import mmap
import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path

from . import host

# Inno Setup writes what it did here, and why it stopped ("PrepareToInstall failed: ...")
INNO_LOG = "/LOG=C:\\debpak-setup.log"

# the switches that make each kind of installer run without asking anything; an installer of
# unknown kind gets each set in turn until one installs something
SILENT = {
    "inno": [["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-", "/CURRENTUSER", INNO_LOG]],
    "wix": [["/quiet", "/norestart"]],
    # an InstallShield setup.exe around an .msi takes /s /v/qn; a Suite (Advanced UI) one /silent;
    # an InstallScript one only /s, and only with a recorded answer file, else it's clicked through
    "installshield": [["/s", "/v/qn"], ["/silent"]],
    "nsis": [["/S"]],
    "advanced-installer": [["/exenoui", "/qn"]],
    # BitRock InstallBuilder (DeepSkyStacker, Scrivener) takes options of its own, Unix style
    "installbuilder": [["--mode", "unattended", "--unattendedmodeui", "none"]],
    "setup-factory": [["/S"]],
    "wise": [["/s"]],
    "smart-install-maker": [["/s"]],
    "installaware": [["/s"]],
    "clickteam": [["/S"]],
    "actual-installer": [["/S"]],
    # MetaQuotes' setup for MetaTrader 4 and 5, and the copies brokers hand out under their own
    # names: /auto installs to the default folder without a page
    "metaquotes": [["/auto"]],
    # a Windows Installer package is installed by msiexec (see SCRIPT); /qn shows no window at all
    "msi": [["/qn", "/norestart"]],
    # install4j (FAF Client) runs unattended with -q, into its default folder
    "install4j": [["-q"], ["-q", "-console"]],
    "other": [["/S"], ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-"], ["/quiet", "/norestart"],
              ["/silent"]],
}
# what in an installer tells its kind, after the markers foreign.py looks for
KIND_MARKERS = [
    (b"Advanced Installer", "advanced-installer"),
    (b"BitRock", "installbuilder"), (b"InstallBuilder", "installbuilder"),
    (b"install4j", "install4j"),
    (b"Setup Factory", "setup-factory"),
    (b"WiseMain", "wise"), (b"Wise Installation", "wise"),
    (b"Smart Install Maker", "smart-install-maker"),
    (b"InstallAware", "installaware"),
    (b"Clickteam Install Creator", "clickteam"),
    (b"Actual Installer", "actual-installer"),
    (b"MetaTrader Setup", "metaquotes"),
    (b"InstallShield", "installshield"),
]
# a silent switch an installer of unknown kind names as a string of its own (between NULs, as a
# program keeps the words it compares its arguments with), or in the usage it prints for a switch
# it doesn't know, is tried before the usual guesses: Amazon Games' setup names /silent, Internet
# Download Manager's -skipdlgs; Bitvise's prints its usage, where -acceptEULA is the one that lets it
# install without a page
SWITCH_WORDS = ("verysilent", "silent", "quiet", "unattended", "skipdlgs", "accepteula", "auto")


def _switch_pattern(utf16: bool, strict: bool) -> re.Pattern:
    """Return a pattern whose group 1 is a switch made of SWITCH_WORDS, in ASCII or UTF-16 text.

    strict wants a NUL on both sides (a string of a program's own); else
    anything but a letter, - or / will do (a usage message).
    """
    z = b"\\x00" if utf16 else b""

    def letters(w: str) -> bytes:
        return b"".join(f"[{c.lower()}{c.upper()}]".encode() + z for c in w)
    switch = b"((?:[-/]" + z + b"){1,2}(?:" + b"|".join(letters(w) for w in SWITCH_WORDS) + b"))"
    if strict:
        return re.compile(b"(?<=\\x00" + z + b")" + switch + b"(?=\\x00" + z + b")")
    return re.compile(rb"(?<![\w/-])" + switch + rb"(?![\w/=-])")


NAMED_SWITCH = [_switch_pattern(False, True), _switch_pattern(True, True)]
PRINTED_SWITCH = [_switch_pattern(False, False)]
# an option a usage gives for the folder to install to, which such an installer can want along with
# its silent switch: Bitvise's usage begins "BvSshClient-Inst -installDir=directory [-acceptEULA]",
# and -acceptEULA alone was a usage error (exit status 220)
INSTALL_DIR_OPTION = re.compile(rb"(?<![\w/-])((?:[-/]){1,2}(?:install|target|dest(?:ination)?)[-_]?"
                                rb"(?:dir|directory|folder|path))=", re.I)
# a sandbox that failed to start for a reason of Flatpak's own, not the installer's: Battle.net's
# setup, run while other Flatpak apps started and stopped, failed with "bwrap: Can't get type of
# source /run/user/1000/.flatpak/1334214619", an instance folder Flatpak cleared away as the sandbox
# was set up. Such a start is tried again, START_TRIES times in all
FLATPAK_RACE = re.compile(r"^bwrap: (Can't|Failed to)|^error: .*(instance|/run/user/\d+/\.flatpak)", re.M)
START_TRIES = 3
# seconds an installer of a known kind may take, and each guess for one of unknown kind
TIMEOUT = 600
GUESS_TIMEOUT = 180
# seconds an installer may go without writing a file before it's taken to be waiting on a window
# no key answers (TypingMaster's message box, a wizard ignoring the switch it was given, a
# downloader's "no connection" box); clicking through gets longer, as a wizard's first pages
# write nothing
IDLE = 60
CLICK_IDLE = 150
# folders a new Wine prefix has, or that installers fill with things that aren't the program
NOT_PROGRAM = {"common files", "internet explorer", "windows media player", "windows nt", "microsoft",
               "microsoft.net", "temp", "package cache", "windowsapps", "wine", "packages", "crashdumps"}

# runs inside the sandbox: $1 the list of files before, $2 seconds allowed, $3 seconds it may write
# nothing, then the installer and its switches. An installer that writes nothing for $3 seconds is
# stopped: one that waits for an answer would otherwise take all of $2 (OpenIV's, TypingMaster's
# took the whole of a compat run's time over their guesses). A log doesn't count: ActivePresenter's,
# waiting for the WebView2 runtime, had EdgeUpdate write its log every few seconds for ten minutes
SCRIPT = """\
wineboot -i >/dev/null 2>&1
wineserver -w
find "$WINEPREFIX/drive_c" -type f -printf '%P\\n' > "$1"
mark="$1.mark"
touch "$mark"
# an .msi isn't a program: msiexec installs it, with the switches after it
case "$4" in
    *.msi) wine msiexec /i "${@:4}" & ;;
    *) wine "${@:4}" & ;;
esac
pid=$!
waited=0
idle=0
status=
while kill -0 "$pid" 2>/dev/null; do
    sleep 5
    waited=$((waited + 5))
    if [ -n "$(find "$WINEPREFIX/drive_c" -newer "$mark" -type f ! -iname '*.log' -print -quit 2>/dev/null)" ]; then
        touch "$mark"
        idle=0
    else
        idle=$((idle + 5))
    fi
    if [ "$idle" -ge "$3" ]; then
        status="idle (it wrote nothing for $idle seconds, waiting on a window)"
    elif [ "$waited" -ge "$2" ]; then
        status=124
    fi
    if [ -n "$status" ]; then
        kill "$pid" 2>/dev/null
        wineserver -k
        break
    fi
done
wait "$pid"
echo "debpak: installer exit status ${status:-$?}"
# a program the installer started when it finished (Inno's [Run]) would keep Wine running
timeout 30 wineserver -w || wineserver -k
"""
# what a Windows Installer package (.msi) starts with, an OLE compound file
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


class InstallError(Exception):
    pass


def kind_of(path: Path, marker: bytes | None) -> str:
    """Return the SILENT key for an installer, from the marker foreign.py found in it, or "other"."""
    with open(path, "rb") as f:
        if f.read(8) == OLE_MAGIC:
            return "msi"
    if marker == b"Inno Setup Setup Data":
        return "inno"
    if marker == b".wixburn":
        return "wix"
    if marker in (b"NullsoftInst", b"Nullsoft Install System"):
        return "nsis"
    with open(path, "rb") as f:
        try:
            m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError:      # empty file
            return "other"
        with m:
            for needle, kind in KIND_MARKERS:
                if m.find(needle) != -1 or m.find(needle.decode().encode("utf-16-le")) != -1:
                    return kind
    return "other"


def named_switches(text: bytes | mmap.mmap, patterns: list[re.Pattern] = PRINTED_SWITCH,
                   folder: str | None = None) -> list[list[str]]:
    """Return the silent switches named in text, each as a try: in what an installer printed, or
    with NAMED_SWITCH among an installer's own strings.

    With folder, a usage that also names an option for the folder to install
    to (INSTALL_DIR_OPTION) has each try give it C:\\Program Files\\folder.
    """
    found: list[list[str]] = []
    for pattern in patterns:
        for m in pattern.finditer(text):
            word = m.group(1).replace(b"\0", b"").decode()
            if word.lower() not in (f[0].lower() for f in found) and len(found) < 3:
                found.append([word])
    if folder and found and (opt := INSTALL_DIR_OPTION.search(text)):
        found = [t + [f"{opt.group(1).decode()}=C:\\Program Files\\{folder}"] for t in found]
    return found


def folder_name(installer: Path) -> str:
    """Return a folder name for installer's program: its file name less "-Inst", "Setup" and the like."""
    stem = re.sub(r"(?i)[-_. ]*(inst|install|installer|setup)$", "", installer.stem)
    return re.sub(r"[^A-Za-z0-9 ._-]", "_", stem).strip(" .") or "Program"


def _named_in(path: Path) -> list[list[str]]:
    """Return the silent switches path names among its own strings (NAMED_SWITCH)."""
    with open(path, "rb") as f:
        try:
            m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError:
            return []
        with m:
            return named_switches(m, NAMED_SWITCH)


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
    # (SCRIPT knows an .msi by its name, so one has it whatever it was called)
    setup = work / "in" / (re.sub(r"[^A-Za-z0-9._-]", "_", installer.stem)
                           + (".msi" if kind == "msi" else installer.suffix.lower()))
    script = work / "install.sh"
    script.write_text(SCRIPT)
    prefix = work / "prefix"
    tries = _silent_tries(installer, kind)
    seconds = GUESS_TIMEOUT if kind == "other" else TIMEOUT
    # with a virtual screen and xdotool, keys are pressed in any window even while a silent switch
    # is tried: a message box the switches don't suppress (TypingMaster's) gets its default answer
    click = clicker_ready()
    log: list[str] = []
    finished: list[list[str]] = []

    def attempt(switches: list[str], secs: int, idle: int, network: bool) -> tuple[str, tuple | None]:
        before = work / "before.txt"
        for n in range(START_TRIES):
            before.unlink(missing_ok=True)
            _clear_temp(prefix)
            # each attempt gets the installer afresh: osu!'s moves itself into the folder it installs
            # to, and every attempt after the first found nothing to run ("wine: failed to open")
            shutil.copyfile(installer, setup)
            out = _run(setup, switches, prefix, script, before, secs, idle, branch, network=network, click=click)
            log.append(out)
            if before.is_file() or not FLATPAK_RACE.search(out):
                break
            time.sleep(5 * (n + 1))
        if not before.is_file():
            raise InstallError("Wine didn't start: " + _tail(out))
        listed, since = set(before.read_text().splitlines()), before.stat().st_mtime
        found = installed(prefix, listed, since)
        if found:
            take_system_files(prefix, listed, since, work / SYSTEM_FILES)
        return out, found

    if (done := _try_silent(attempt, tries, installer, seconds, finished)):
        return done
    # the network, for a downloader (Battle.net's, GOG Galaxy's) or for an installer that fetches a
    # prerequisite first (ActivePresenter's needs the WebView2 runtime: "PrepareToInstall failed"); one
    # that stopped for writing nothing may have been waiting on a "no connection" box
    # it's given the full time, as a download keeps it busy (Amazon Games' setup was still fetching
    # after three minutes); one that waits instead is stopped all the same
    for switches in finished:
        _out, found = attempt(switches, TIMEOUT, IDLE, True)
        if found:
            return (*found, " ".join(switches), True)
    if click:
        # an installer that ignores every silent switch, or has none, or asks a question no switch
        # answers (TypingMaster's offer of Opera), is clicked through as a person would: accept the
        # licence and press the default button until it's done
        _out, found = attempt([], TIMEOUT, CLICK_IDLE, True)
        if found:
            return (*found, "(clicked through)", True)
    why = _setup_log(prefix) or _tail(log[-1])
    raise InstallError("it ran under Wine but installed no program"
                       + (" with any of the usual silent switches" if len(tries) > 1 else
                          f" ({' '.join(tries[0])})") + (" or by clicking through it" if click else "")
                       + (": " + why if why else ""))


def _silent_tries(installer: Path, kind: str) -> list[list[str]]:
    """Return the silent switches to try for an installer of kind: SILENT's, after those it names itself."""
    tries = [list(t) for t in SILENT.get(kind, SILENT["other"])]
    if kind == "other":
        named = _named_in(installer)
        tries = named + [t for t in tries if t not in named]
    return tries


def _try_silent(attempt, tries: list[list[str]], installer: Path, seconds: int,
                finished: list[list[str]]) -> tuple[Path, str | None, str, bool] | None:
    """Try each set of silent switches without the network; return install's result, or None.

    The sets that ran to their end are added to finished, and the switches an installer's usage names
    are tried next.
    """
    i = 0
    while i < len(tries):
        switches = tries[i]
        i += 1
        out, found = attempt(switches, seconds, IDLE, False)
        if found:
            return (*found, " ".join(switches), False)
        if "installer exit status 124" not in out and "didn't finish" not in out:
            finished.append(switches)
        # one that prints its usage for a switch it doesn't know: the silent switch the usage names
        # is tried next
        for t in reversed(named_switches(out.encode("utf-8", "replace"), folder=folder_name(installer))):
            if t not in tries:
                tries.insert(i, t)
    return None


def _clear_temp(prefix: Path) -> None:
    """Empty the prefix's Temp folders, where an earlier attempt's leftovers would trip the next.

    Unreal Commander's web installer, run again after an attempt that was
    stopped, found its uncom.tmp folder from before and quit with exit status 5.
    """
    drive = prefix / "drive_c"
    if not drive.is_dir():
        return
    temps = [drive / "windows/temp"] + [u / "AppData/Local/Temp" for u in (drive / "users").glob("*")]
    for t in temps:
        if not t.is_dir() or t.is_symlink():
            continue
        _empty_folder(t)


# runs on the host under xvfb-run: $1 seconds, then the flatpak command. While the installer runs, it
# presses keys in each window on the virtual screen, a different set each time round, as a person
# would try: Alt+A (the accelerator of "I accept" / "I Agree" in Inno, NSIS, MSI and InstallShield
# licence pages) and Return (the default button: Next, Install, Finish); Space (a focused checkbox,
# like FastCopy's "I agree to the license", or a focused button) and Return; Tab and Return; and the
# accelerators of Next, Install and Finish
CLICKER = """\
secs=$1; shift
"$@" &
pid=$!
end=$(( $(date +%s) + secs ))
round=0
tick=0
while kill -0 "$pid" 2>/dev/null && [ "$(date +%s)" -lt "$end" ]; do
    sleep 1
    tick=$((tick + 1))
    [ $((tick % 4)) -eq 0 ] || continue
    case $((round % 4)) in
        0) keys="alt+a Return" ;;
        1) keys="space Return" ;;
        2) keys="Tab Return" ;;
        3) keys="alt+n alt+i alt+f" ;;
    esac
    round=$((round + 1))
    for w in $(xdotool search --onlyvisible --name "" 2>/dev/null | tail -n 3); do
        xdotool windowfocus "$w" 2>/dev/null
        for k in $keys; do
            xdotool key --clearmodifiers "$k" 2>/dev/null
            sleep 0.5
        done
    done
done
wait "$pid"
"""


def clicker_ready() -> bool:
    """True if installers can be clicked through: a virtual screen (xvfb-run) and xdotool on the host."""
    return bool(host.which("xvfb-run") and host.which("xdotool"))


def _run(setup: Path, switches: list[str], prefix: Path, script: Path, before: Path, seconds: int, idle: int,
         branch: str, network: bool = False, click: bool = False) -> str:
    """Run one attempt and return its output; with click, press keys in its windows (CLICKER).

    It's stopped after seconds, or once it has written nothing for idle seconds (SCRIPT).
    """
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
           f"org.winehq.Wine//{branch}", str(script), str(before), str(seconds), str(idle),
           str(setup), *switches]
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
    if hits:
        return hits[0][:300]
    # none of those words: where it stopped is the next best thing. Lamina's Inno Setup 6.7 setup
    # quit with exit status 5 three times over, and all the error said was that number
    said = [ln.split("   ", 1)[-1].strip() for ln in lines]
    said = [s for s in said if s and not SETUP_LOG_END.match(s)]
    return f"its log ends with \"{said[-1][:200]}\"" if said else ""


# the lines Inno Setup ends every log with, which say nothing of how it went
SETUP_LOG_END = re.compile(r"(?i)(Deinitializing Setup|Log closed|Log opened|Setup version|Original Setup EXE|"
                           r"Setup command line|Windows version|64-bit Windows|Processor architecture|"
                           r"User privileges|Administrative install mode|Install mode root key)")


# Wine's and Xvfb's chatter, left out of what an error quotes
NOISE = re.compile(r"ALSA|PulseAudio|session bus|^X|XIO|after \d+ requests|debpak: installer exit status 0")


def _tail(out: str) -> str:
    """Return the last two lines of an attempt's output that say something."""
    keep = [ln.strip() for ln in out.splitlines() if ln.strip() and not NOISE.search(ln)]
    return " / ".join(keep[-2:])


# an installer's uninstaller, which is no program of the app's (Inno Setup's unins000.exe)
UNINSTALLER = re.compile(r"(?i)unins|uninst")
# a Windows app package, which an installer can put in its folder and hand to Add-AppxPackage: Hardware
# Monitor's Inno setup installs HardwareMonitorExtension.msix and a certificate, nothing else, and
# registers the package with PowerShell, which Wine doesn't have
APP_PACKAGE = (".msix", ".appx", ".msixbundle", ".appxbundle")


# Windows' system folders, where an installer may put libraries its program loads by name from
# anywhere: Brinno Video Player's DeployMaster setup put C++Builder 5's runtime packages there
# (VCL50.BPL, VCLX50.BPL), and bvplay.exe, taken from its own folder alone, was refused for lacking them
SYSTEM_DIRS = ("windows/system32", "windows/syswow64")
SYSTEM_SUFFIXES = (".dll", ".bpl", ".ocx")
# where install() keeps them, beside the prefix, as SYSTEM_DIRS' own names
SYSTEM_FILES = "system-files"


def take_system_files(prefix: Path, before: set[str], since: float | None, out: Path) -> list[Path]:
    """Copy the libraries the installer put in Windows' system folders (SYSTEM_DIRS) to out; return the copies.

    They're new since before as installed() counts files, and they're only
    candidates: convert puts one beside the program only when the program
    needs it to start and neither it nor Wine has it (see
    winapp._missing_dlls). The 32-bit and 64-bit ones keep their folders apart.
    """
    shutil.rmtree(out, ignore_errors=True)
    drive = prefix / "drive_c"
    taken = []
    for sub in SYSTEM_DIRS:
        folder: Path | None = drive
        for part in sub.split("/"):
            folder = next((c for c in folder.iterdir() if c.name.lower() == part and c.is_dir()), None) \
                if folder is not None and folder.is_dir() else None
        if folder is None:
            continue
        for f in sorted(folder.iterdir()):
            if not f.is_file() or f.is_symlink() or f.suffix.lower() not in SYSTEM_SUFFIXES:
                continue
            rel = f.relative_to(drive).as_posix()
            if rel in before and (since is None or f.stat().st_ctime < since):
                continue
            dest = out / sub.split("/")[1] / f.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(f, dest)
            except OSError:
                continue
            taken.append(dest)
    return taken


def installed(prefix: Path, before: set[str], since: float | None = None) -> tuple[Path, str | None] | None:
    """Return (program folder, main .exe in it or None) from the files new in prefix, or None.

    A file listed before counts too when it changed after since: an earlier
    attempt, stopped for waiting on a window, may have written the same files
    the one that finished wrote again. The inode's change time tells, as
    installers set a file's modification time to the one it was built with.
    """
    drive = prefix / "drive_c"
    sizes: dict[tuple[str, ...], int] = {}
    exes: dict[tuple[str, ...], int] = {}
    packages: dict[tuple[str, ...], Path] = {}
    links = []
    for f in drive.rglob("*"):
        if not f.is_file() or f.is_symlink():
            continue
        rel = f.relative_to(drive).as_posix()
        if rel.lower().startswith("windows/"):
            continue
        if rel in before and (since is None or f.stat().st_ctime < since):
            continue
        if f.suffix.lower() == ".lnk":
            links.append(f)
            continue
        root = _program_root(f.relative_to(drive).parts)
        if root is None:
            continue
        sizes[root] = sizes.get(root, 0) + f.stat().st_size
        if f.suffix.lower() == ".exe" and not UNINSTALLER.match(f.stem):
            exes[root] = exes.get(root, 0) + 1
        elif f.suffix.lower() in APP_PACKAGE and (root not in packages
                                                  or f.stat().st_size > packages[root].stat().st_size):
            packages[root] = f
    if not exes and packages:
        # no program, but the app package the installer meant to register, which convert unpacks
        best = max(packages, key=lambda r: packages[r].stat().st_size)
        return drive.joinpath(*best), packages[best].relative_to(drive.joinpath(*best)).as_posix()
    if not exes:
        return None
    for lnk in sorted(links):
        target = _lnk_target(lnk, drive)
        # v2rayA's only Start menu shortcut is "Uninstall v2rayA", and its unins000.exe became the program
        if target is None or UNINSTALLER.match(target.stem):
            continue
        parts = target.relative_to(drive).parts
        root = _program_root(parts)
        if root is not None and root in exes:
            return drive.joinpath(*root), Path(*parts[len(root):]).as_posix()
    best = max(exes, key=lambda r: sizes.get(r, 0))
    return drive.joinpath(*best), None


# drive_c's own folders; a new folder beside them is a program's own (Laragon installs to C:\laragon)
DRIVE_C = {"program files", "program files (x86)", "programdata", "users", "windows"}


# a Windows user's own folders, which hold no program of their own
USER_FOLDERS = {"appdata", "desktop", "documents", "downloads", "music", "pictures", "videos", "favorites",
                "links", "saved games", "searches", "contacts", "start menu", "temp", "my documents"}


def _program_root(parts: tuple[str, ...]) -> tuple[str, ...] | None:
    """Return the parts of the folder a program installed under drive_c lives in, or None."""
    low = [p.lower() for p in parts]
    n: int | None
    if low[0] in ("program files", "program files (x86)", "programdata"):
        n = 2
    elif low[0] not in DRIVE_C and len(parts) > 1:
        n = 1
    else:
        n = _user_root_depth(low)
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
        hit = _child(p, part)
        if hit is None:
            return None
        p = hit
    return p if p.is_file() else None


def _empty_folder(folder: Path) -> None:
    """Delete everything in folder, not following links."""
    for f in folder.iterdir():
        if f.is_dir() and not f.is_symlink():
            shutil.rmtree(f, ignore_errors=True)
        else:
            f.unlink(missing_ok=True)


def _user_root_depth(low: list[str]) -> int | None:
    """Return how many parts (lowercase) of a path under drive_c/users make up its program's folder, or None."""
    if low[0] == "users" and len(low) > 4 and low[2:4] == ["appdata", "local"] and low[4] == "programs":
        return 6
    if low[0] == "users" and len(low) > 3 and low[2] == "appdata" and low[3] in ("local", "roaming"):
        return 5
    if low[0] == "users" and len(low) > 3 and low[2] not in USER_FOLDERS:
        return 3            # FastCopy installs for the current user to C:\Users\NAME\FastCopy
    return None


def _child(p: Path, part: str) -> Path | None:
    """Return p/part, or the entry of p whose name matches part without regard to case, or None."""
    if (p / part).exists():
        return p / part
    return next((c for c in p.iterdir() if c.name.lower() == part.lower()), None) if p.is_dir() else None
