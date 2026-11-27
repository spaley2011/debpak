"""Check a converted app by starting it, and work out what to change when it doesn't start.

What a package looks like varies without end, but the ways a converted app
fails to start are few: a library it loads isn't there, it needs Java or
Mono, it can't reach the display, its Qt or glibc is newer than the runtime's, Chromium's
sandbox can't start, it writes into its own read-only folder, a Windows
program imports a DLL Wine lacks. Each shows itself in what the app prints
(or, run again with the loader's or Wine's logging on, in what that prints),
and each has a remedy that is a convert option.

convert --verify (on by default when the host has xvfb-run) starts the
installed app on a virtual display for a while, looks for a window with
xdotool when the host has it, and when the app crashed, quit or showed
nothing, runs it once more with LD_DEBUG or WINEDEBUG on. diagnose() reads
the output for those signatures and returns the remedies not tried yet;
convert applies them to its own options and builds again, a few times at
most.
"""
from __future__ import annotations

import random
import re
import subprocess
import tempfile
from dataclasses import dataclass, field, replace
from pathlib import Path

from . import host
from .winrt import INSTALLING, PREFIX_DONE, PREFIX_SET_UP

# seconds the app gets before it's judged; a Windows program's first start sets up its Wine prefix
SECONDS = {"wine": 90}
# the most a Windows program's first start may spend installing runtimes before the check stops waiting
INSTALL_SECONDS = 1500
DEFAULT_SECONDS = 40
ROUNDS = 3

# runs on the host under xvfb-run: $1 seconds, $2 output file, $3 a command that ends the app
# cleanly (or ""), then the flatpak command. Windows are looked for by class as well as by name:
# xdotool's search by name skips a window whose WM_NAME it can't decode, and Ren'Py's launcher,
# whose WM_NAME has the type UTF-8, was judged to have none.
# While the file DEBPAK_CHECK_BUSY names is there (a Windows program's launcher installing its
# runtimes on first start, see winrt.INSTALLING), the app gets its seconds again from when it goes,
# up to DEBPAK_CHECK_INSTALL seconds in all, and windows shown meanwhile (an installer's) don't
# count: DYMO ID's first start installs dotnet48, and the check cut it short twice
OBSERVER = """\
secs=$1; out=$2; stop=$3; early=${DEBPAK_CHECK_SETTLE:-8}; shift 3
busy=${DEBPAK_CHECK_BUSY:-}; most=${DEBPAK_CHECK_INSTALL:-1500}
cap=${DEBPAK_CHECK_MEMORY_KB:-8388608}
"$@" >"$out" 2>&1 </dev/null &
pid=$!
# the resident memory of the app's processes together, in kB: FoliCon.exe took 20 GB in 82 seconds
# under Wine and left the machine none, so an app past the cap (8 GB) is stopped and said to be
tree_rss() {
    ps -eo pid=,ppid=,rss= 2>/dev/null | awk -v r="$pid" '{ up[$1] = $2; m[$1] = $3 }
        END { t = 0; for (k in up) { x = k; i = 0; while (x != r && x > 1 && i++ < 64) x = up[x]; if (x == r) t += m[k] } print t }'
}
n=0; shown=0; end=$secs
while [ "$n" -lt "$end" ] && kill -0 "$pid" 2>/dev/null; do
    sleep 1; n=$((n+1))
    if [ $((n % 2)) -eq 0 ]; then
        used=$(tree_rss)
        if [ "${used:-0}" -gt "$cap" ]; then
            echo "DEBPAK-MEMORY $used"
            for k in $(ps -eo pid=,ppid= | awk -v r="$pid" '{ up[$1] = $2 } END { for (k in up) { x = k; i = 0; while (x != r && x > 1 && i++ < 64) x = up[x]; if (x == r) print k } }'); do
                kill -9 "$k" 2>/dev/null
            done
            wait "$pid" 2>/dev/null
            echo "DEBPAK-EXIT 137 AFTER $n"
            exit 0
        fi
    fi
    if [ -n "$busy" ] && [ -e "$busy" ] && [ "$n" -lt "$most" ]; then
        end=$((n+secs)); shown=0; continue
    fi
    # a titled window that stays up for 8 seconds is what the check waits for: stop waiting then
    if [ $((n % 2)) -eq 0 ] && command -v xdotool >/dev/null 2>&1; then
        if xdotool search --onlyvisible --name "." >/dev/null 2>&1; then shown=$((shown+2)); else shown=0; fi
        [ "$shown" -ge "$early" ] && break
    fi
done
if kill -0 "$pid" 2>/dev/null; then
    echo "DEBPAK-RUNNING"
    # a program whose window is a page it serves on this machine, opened in the web browser (see SERVED)
    url=$(grep -aoE 'https?://(127\\.0\\.0\\.1|localhost|0\\.0\\.0\\.0):[0-9]+[^][:space:]"<>'"'"'()]*' "$out" 2>/dev/null \
          | head -n 1 | sed 's#//0\\.0\\.0\\.0:#//127.0.0.1:#')
    if [ -n "$url" ] && command -v curl >/dev/null 2>&1; then
        echo "DEBPAK-SERVED $url $(curl -sSkL --noproxy '*' -m 10 -o /dev/null -w '%{http_code} %{content_type}' "$url" 2>/dev/null)"
    fi
    if command -v xdotool >/dev/null 2>&1; then
        echo "DEBPAK-XDOTOOL"
        for w in $( { xdotool search --onlyvisible --name ""; xdotool search --onlyvisible --classname ""; } \
                    2>/dev/null | sort -u); do
            echo "DEBPAK-WINDOW $(xdotool getwindowname "$w" 2>/dev/null)"
        done
    fi
    if [ -n "$stop" ]; then
        timeout 60 sh -c "$stop" >/dev/null 2>&1
        n=0
        while [ "$n" -lt 10 ] && kill -0 "$pid" 2>/dev/null; do sleep 1; n=$((n+1)); done
    fi
    # the app itself is asked to end first. Ending flatpak run (bwrap) ends the sandbox with
    # SIGKILL, so the app never cleans up: Mira's QLockFile stayed behind naming PID 2, which in
    # the next sandbox is Mira again, so its next start took the lock for held and quit
    all=$(ps -eo pid=,ppid= 2>/dev/null); kids=$pid; inside=
    while [ -n "$kids" ]; do
        next=
        for k in $kids; do next="$next $(echo "$all" | awk -v p="$k" '$2 == p { print $1 }')"; done
        kids=$(echo $next); inside="$inside $kids"
    done
    if [ -n "$(echo $inside)" ]; then
        kill -TERM $inside 2>/dev/null
        n=0
        while [ "$n" -lt 5 ] && kill -0 "$pid" 2>/dev/null; do sleep 1; n=$((n+1)); done
    fi
    kill "$pid" 2>/dev/null
    sleep 2
    kill -9 "$pid" 2>/dev/null
else
    wait "$pid"
    echo "DEBPAK-EXIT $? AFTER $n"
fi
"""

# "TEdit Error Reporting" asks, on the first start, whether to send error reports, and so does QtMesh
# Editor's "Crash Reporting" (a crash reporter's own window, "Crash Reporter", still counts);
# a Wails app without WebView2 says "Missing Requirements"
ERROR_TITLE = re.compile(r"(?i)\b(error(?! report)|exception|crash(ed)?(?! reporting\b)|fatal|failed|problem"
                         r"|missing requirements?"
                         r"|not writable)\b")
# a window saying the folder the app keeps its data in can't be written: Fjord Launcher's "The launcher
# data folder is not writable!", in portable mode in its read-only folder
NOT_WRITABLE_TITLE = re.compile(r"(?i)\bnot writable\b")
# a program that won't use a file of its own that has other hard links, which every file in a Flatpak's
# /app has (they are links into the OSTree repository it was installed from): Open CoDesign reads its
# templates only from files whose link count is 1, and stopped at start with "Expected an unlinked
# regular file: /app/opt/Open-CoDesign/resources/templates/skills/...". A copy of its folder has its own
HARD_LINKED = re.compile(r"(?i)[^\n]*\b(?:unlinked|hard[- ]?link(?:s|ed)?|nlink)\b[^\n]*?/app/[^\s'\"]+")


# a window that asks whether to send crash reports: Kimitzu Client's "Crash Reporting" asks "Do you
# want to send the crash reports to the developers?" at first start, beside its main window
CRASH_CONSENT = re.compile(r"(?i)\bcrash[ -]?report")


# a window that offers add-ons the app works without: OpenChrom's "Vendor plugins missing" asks, beside
# its main window, "You currently have no proprietary converters installed ... Do you want to install
# converter plug-ins now?"
_ADDON = r"\b(?:vendor |optional |proprietary )?(?:plug-?ins?|add-?ons?|extensions?|converters?)\b"
ADDON_OFFER = re.compile(r"(?i)" + _ADDON + r".{0,40}\bmissing\b|\bmissing\b.{0,40}" + _ADDON)


def error_windows(titles: list[str], error_title: re.Pattern = ERROR_TITLE) -> list[str]:
    """Return the titles among titles that name an error.

    One that asks about crash reports (CRASH_CONSENT), or offers add-ons the app
    can do without (ADDON_OFFER), is a question the app asks at first start while
    another of its windows, which names no error, is open; alone, it is what an
    app shows after it crashed (Mozilla's Crash Reporter) or couldn't start.
    """
    bad = [t for t in titles if t.strip() and error_title.search(t)]
    if any(t.strip() and t not in bad for t in titles):
        bad = [t for t in bad if not CRASH_CONSENT.search(t) and not ADDON_OFFER.search(t)]
    return bad


@dataclass
class Observation:
    """What one start of the app showed."""
    running: bool
    code: int | None
    windows: list[str] | None        # None: no xdotool to look with
    output: str
    seconds: int | None = None       # how long it ran before it exited, to the second
    served: str | None = None        # the page on this machine it serves as its window (see SERVED)

    @property
    def ok(self) -> bool:
        if not self.running:
            return False
        if self.windows is None:
            return True
        titled = [w for w in self.windows if w.strip() and w.strip() != "Wine"]
        if error_windows(titled):
            return False
        return bool(titled) or bool(self.served)

    def describe(self) -> str:
        if self.ok and self.served and not any(w.strip() for w in self.windows or []):
            return f"running, serving its window as a web page at {self.served}, which it opens in the web browser"
        if self.ok:
            return "running" + (f", showing {', '.join(w for w in self.windows if w)[:120]}" if self.windows else "")
        if not self.running:
            return f"exited with status {self.code}"
        bad = error_windows([w for w in self.windows or [] if w.strip() != "Wine"])
        return f"showing an error ({', '.join(bad)[:120]})" if bad else "running, but with no window"


# what a command-line program prints when started with no arguments or with --help: Arkloop's
# "usage: ark <command> [flags]", appimagetool's "Usage:" over "appimagetool [OPTION...] SOURCE",
# or, with no usage line, a heading of options over the first of them: zsync2's "OPTIONS:", a
# blank line, then "-h, --help   Display this help menu."
USAGE = re.compile(r"(?im)^\s*usage:(?:\s*$|\s+\S)|^[ \t]*(?:[\w ]{0,20}\s)?options:[ \t]*\n(?:[ \t]*\n)?[ \t]+--?\w")
# what convert prints, and the compat suite looks for, when the app is one
COMMAND_LINE = "a command-line program"
# and why, when it is one that runs on (see command_line)
SERVER = "nothing in the package opens a window, and it ran on without one, as a server does"
# and why, when its only menu entries run it in a terminal (see command_line)
TERMINAL_ONLY = "its menu entries run it in a terminal, and nothing in the package opens a window"
QUICK_SECONDS = 5


# what a program that runs in a terminal says when it has none: superfile, a text interface, "bubbletea:
# could not open TTY: open /dev/tty: no such device or address"; or what it writes to draw in one:
# MeshTalk, an OpenTUI interface, wrote its terminal queries and switched to the alternate screen
# (ESC [?1049h), the way a full-screen text interface starts, and waited for answers no terminal gave.
# Cryptnox's snap, an interactive prompt ("cryptnox > "), read its first command with Python's input()
# and stopped at "EOFError: EOF when reading a line", the end of an input no one types into
NEEDS_TERMINAL = re.compile(r"(?i)\b(?:could not|couldn't|can't|cannot|unable to|failed to|error) open(?:ing)? "
                            r"(?:a |the )?(?:tty|/dev/tty|terminal)\b|open /dev/tty: |"
                            r"(?:stdin|standard input|input) is not a (?:tty|terminal)\b|"
                            r"must be run (?:in|from) a terminal|\x1b\[\?(?:1049|1047|47)h|"
                            r"EOFError: EOF when reading a line")


def terminal_need(output: str) -> str:
    """Say what in a program's output shows it runs in a terminal (see NEEDS_TERMINAL); "" if nothing does."""
    if not (m := NEEDS_TERMINAL.search(output)):
        return ""
    return "it switched a terminal to a full-screen text interface" if m.group(0).startswith("\x1b") \
        else m.group(0).strip()


# what a program that wanted a window says without one; a program that never names a display isn't
# looking for one
DISPLAY_WORDS = re.compile(r"(?i)display|wayland|\bx11\b|\bxcb\b|\bgtk|\bqt\b|\bqpa\b|\bwindow|\bopengl|\begl\b|\bglfw|\bsdl")


# a list of options, one to a line, as Go's flag package prints it without a usage line ("  -angle
# float", its text on the next line) and as most option parsers do: three of them make a list
OPTION_LINE = re.compile(r"(?m)^[ \t]{1,8}--?[A-Za-z][\w.-]*(?:[ =,][^\n]*)?$")


def option_list(output: str) -> bool:
    """True if what a program printed holds a list of its options (see OPTION_LINE)."""
    return len(OPTION_LINE.findall(output)) >= 3


# a usage that names commands of the program's own, as clap and other argument parsers print it:
# MolvAI's molva, "Usage: molva <COMMAND>" over "Commands:"
SUBCOMMANDS = re.compile(r"(?im)^\s*usage:.*<(?:command|subcommand|cmd)>|^\s*(?:available |sub)?commands:\s*$")


# Windows console programs: the launcher runs one in a console window of Wine's own (wineconsole) when
# no terminal started it, and what it prints goes there; with this the check reads it instead
CONSOLE_ENV = {"DEBPAK_WINECONSOLE": "0"}
# a Windows program needs a moment more than a Linux one to start under Wine, even in a set-up prefix
CONSOLE_QUICK_SECONDS = 10
# Wine's and the launcher's own lines in what a Windows program printed
WINE_NOISE = re.compile(r"^\s*(?:[0-9a-f]{4}:(?:err|fixme|warn|trace):|wine: |Setting up Wine|Installing .* into the "
                        r"Wine prefix|Copying .* into the Wine prefix|MESA|pci id for|X connection to|XIO: |"
                        r"after \d+ requests|Fontconfig )")
# what a Windows program that broke prints: a loader failure, an exception, a script's traceback
WINE_FAILED = re.compile(r"(?i)err:module:|err:seh:|could not load \S+\.dll|status c0000\w+|unhandled exception|"
                         r"Traceback \(most recent call last\)|Failed to execute script|\bpanicked at\b")
WINE_DLL_NOT_FOUND = 53        # STATUS_DLL_NOT_FOUND (c0000135), as Wine's exit status


def _own_lines(output: str) -> list[str]:
    return [ln for ln in output.splitlines() if ln.strip() and not WINE_NOISE.search(ln)]


def _console_program(bare: Observation, helped: Observation | None) -> str:
    """Say why a Windows console program that ended at once is a command-line program; "" if it isn't one.

    fio, from its .msi, and TrId2Console, from a zip, are console programs (the
    mark Windows itself goes by to give a program a console), and both ended
    within a second: fio printed its options and exited with status 1, and
    TrId2Console said "file is required" and exited with 0. Neither prints a
    "usage:" line. Both counted as crashed or quit GUI apps. A console program
    that ended at once of itself and printed something of its own, with no
    sign that it broke (a DLL Wine couldn't load, an exception, a Python
    traceback, as GAM's frozen Python printed), is one; so is one that says
    something with --help and exits with 0.
    """
    def clean(o: Observation | None) -> bool:
        return o is not None and not o.running and o.code is not None and 0 <= o.code < 128 \
            and o.code != WINE_DLL_NOT_FOUND and not WINE_FAILED.search(o.output) \
            and not any(w.strip() for w in o.windows or [])
    if not clean(bare) or (bare.seconds is not None and bare.seconds > CONSOLE_QUICK_SECONDS):
        return ""
    if USAGE.search(bare.output):
        return "it prints how to use it"
    if _own_lines(bare.output):
        return "Windows marks it as a console program, and it ended at once with something to say"
    if clean(helped) and helped.code == 0 and _own_lines(helped.output):
        return "Windows marks it as a console program, and it says how to use it when asked with --help"
    return ""


def command_line(bare: Observation, helped: Observation | None, terminal_entry: bool = False,
                 windowless: bool = False, graphical: bool = False, console: bool = False) -> str:
    """Say why what the app did shows it's a command-line program rather than a broken graphical app; "" if it doesn't.

    bare is a start with no arguments and helped one with --help (None if it
    wasn't needed). Arkloop's ark, from a tarball, printed "usage: ark
    <command> [flags]" and exited with status 2; appimagetool, whose menu entry
    says Terminal=true, said "ERROR: SOURCE is missing" and exited with 1, and
    with --help printed its usage and exited with 0. Both counted as crashed
    GUI apps. The evidence has to be strong: it exited within a few seconds
    without a window, and printed a usage line, then or when asked with --help
    (and convert asks only when the package has no menu entry for a graphical app).
    A program that says it has no terminal to use (NEEDS_TERMINAL) is one, and so
    is one whose menu entry runs it in a terminal (terminal_entry) and that ended
    cleanly at once: Curv's prompt ends at the end of its input, which a check
    gives it at once; or that ended at once and, asked with --help, printed
    something and ended with 0 (Tizonia's snap, whose help has no usage line). So is one that can't open a window at all (windowless:
    no display in its sandbox, as debpak found nothing graphical in the package,
    and no menu entry) and that ended of itself, however long it took, without a word about a
    display or a toolkit: faynoSync, a server, stopped at "JWT_SECRET is
    empty", and weiback-rs's db-upgrade-tool ended with status 0 and said
    nothing; both counted as GUI apps that failed. Such a program that runs on,
    with no window it could open, is a server: lingma-proxy, a local proxy,
    counted as an app that showed no window. A program whose menu entries all
    run it in a terminal and that can't open a window (terminal_entry and
    windowless together) is a terminal program however it fared without one:
    Amfora's snap, a Gemini browser drawn in the terminal, ran on waiting for
    one in the cloud and on the test PC stopped with status 2 at its text
    interface's start, and counted as a crashed app.

    A program that can open windows (graphical: a display in its sandbox, and
    no menu entry) is one only when it ended at once with a usage that names
    commands of its own, or a list of its options: a graphical app that prints
    its usage wants a file to open, but an app isn't driven by subcommands, and
    one that needs options to do anything and that no menu entry starts is a
    command-line program that can show a window. MolvAI's tarball holds molva,
    its command line, which links X11 to type the text it hears into other
    windows, and printed "Usage: molva <COMMAND>" and its commands.

    A Windows console program (console), started outside the console window
    Wine would give it, has a rule of its own: see _console_program.
    """
    if console:
        return _console_program(bare, helped)
    if (need := terminal_need(bare.output)) and not any(w.strip() for w in bare.windows or []):
        return f"it needs a terminal ({need})"
    if terminal_entry and windowless and not any(w.strip() for w in bare.windows or []) \
            and not DISPLAY_WORDS.search(bare.output) \
            and (bare.running or (bare.code is not None and 0 <= bare.code < 128)):
        return TERMINAL_ONLY
    if windowless and bare.running and not any(w.strip() for w in bare.windows or []) \
            and not DISPLAY_WORDS.search(bare.output):
        # lingma-proxy, from a tarball, said "listening on http://127.0.0.1:8095" and served on
        return SERVER
    if windowless and not bare.running and bare.code is not None and 0 <= bare.code < 128 \
            and not DISPLAY_WORDS.search(bare.output):
        # however long it took: one that ran on would be a server, as above. Recoll's tarball holds only
        # recollindex and recollq, and recollindex stopped at "Configuration problem" with status 1 at
        # once, but the check counted the seconds the sandbox took to start too, and on a busy PC
        # (the first start of an app with libraries of its own sets up its linker cache) that was more
        # than QUICK_SECONDS
        return "nothing in the package opens a window, and it ended by itself without asking for a display"
    if bare.running or (bare.seconds is not None and bare.seconds > QUICK_SECONDS):
        return ""
    if graphical:
        ended = bare.code is not None and 0 <= bare.code < 128
        if SUBCOMMANDS.search(bare.output) and USAGE.search(bare.output) and ended:
            return "it prints the commands it takes"
        # caire's snap, an image resizer that can show its work in a window, printed its options in
        # Go's flag format and "Please provide a width, height or percentage" and ended with status 1
        return "it prints the options it takes" if option_list(bare.output) and ended else ""
    if USAGE.search(bare.output):
        return "it prints how to use it"
    if terminal_entry and bare.code == 0:
        return "its menu entry runs it in a terminal, and it ended at once at the end of its input"
    if terminal_entry and bare.code is not None and 0 <= bare.code < 128 and helped is not None \
            and not helped.running and helped.code == 0 and helped.output.strip() \
            and not any(w.strip() for w in (bare.windows or []) + (helped.windows or [])):
        # Tizonia's snap, a music player for the terminal (its menu entry says so), printed its help
        # topics and "Use "tizonia --help topic"" with status 1, and the same with --help and status 0
        return "its menu entry runs it in a terminal, and it prints its help when asked"
    if helped is not None and not helped.running and helped.code == 0 and bool(USAGE.search(helped.output)):
        return "it prints how to use it"
    return ""


# and why, when a terminal program that failed with no terminal ran on in one (see in_terminal)
IN_TERMINAL = "its menu entries run it in a terminal, nothing in the package opens a window, and in a terminal it ran"


def in_terminal(obs: Observation) -> str:
    """Say why a terminal program that failed with no terminal works in one; "" if it didn't there either.

    LE, a text editor whose only menu entry says Terminal=true and which links
    nothing but ncurses, ended at "le: Caught signal 11" when the check started
    it with no terminal, and counted as a crashed app; started in a terminal it
    draws its screen and waits for keys. A program with no display in its
    sandbox, whose menu entries all run it in a terminal, is started a second
    time in a pseudo-terminal (observe with terminal), and is a command-line
    program that works when it ran on there, or ended there by itself with
    status 0, without a word about a display. One that crashed in the terminal
    too is broken.
    """
    if any(w.strip() for w in obs.windows or []) or DISPLAY.search(obs.output):
        return ""
    if obs.running or obs.code == 0:
        return IN_TERMINAL
    return ""


def available() -> bool:
    """True if the host can start apps on a virtual display (xvfb-run) to check them."""
    return bool(host.which("xvfb-run") and host.which("flatpak"))


# what a desktop session sets that a check started from a terminal or SSH may lack: Fluxy reads
# DESKTOP_SESSION (to ask Deepin for its scale factor) and stopped at "Error: EnvVar(NotPresent)"
SESSION_DEFAULTS = {"DESKTOP_SESSION": "debpak-check"}


def session_env(environ=None) -> dict[str, str]:
    """Return SESSION_DEFAULTS that environ (os.environ) lacks, for the app a check starts."""
    import os
    environ = os.environ if environ is None else environ
    return {k: v for k, v in SESSION_DEFAULTS.items() if not environ.get(k)}


# run inside a Windows program's sandbox when the check is over, to end it as Windows ends a session:
# its windows are asked to close (WM_QUERYENDSESSION, WM_ENDSESSION), then Wine is waited for,
# and only then told to stop (SIGTERM, on which wineserver saves the registry), then killed.
# VidCutter showed its window to the check, which then killed the sandbox outright, wineserver and
# all, and in the start that followed (the compat suite's) it showed none: a program killed in the
# middle leaves its prefix as it was at that moment (a registry not yet saved, its own lock and
# settings files half done), which the user's first start then inherits.
# flatpak enter gives the shell it starts none of the app's environment (no FLATPAK_ID, no HOME, a PATH
# without /app/bin), so this did nothing: wineboot and wineserver weren't found, the WINEPREFIX
# it made up was /.var/app//data/wine, and the sandbox was killed as before. Whisperi, a Tauri app, lost
# the WebView2 runtime's registration its first start had made (the launcher's marker and the runtime's
# folder stayed, the registry entry didn't) and its next start said "Could not find the WebView2
# Runtime". The environment of the sandbox's own processes is taken first (bash, for read -d '')
WINE_STOP = """\
if [ -z "${FLATPAK_ID-}" ]; then
    for e in "${DEBPAK_PROC:-/proc}"/[0-9]*/environ; do
        grep -qz '^FLATPAK_ID=' "$e" 2>/dev/null || continue
        while IFS= read -r -d '' kv; do export "$kv" 2>/dev/null; done < "$e"
        break
    done
fi
export WINEPREFIX="${WINEPREFIX:-${XDG_DATA_HOME:-$HOME/.var/app/$FLATPAK_ID/data}/wine}"
timeout 20 wineboot --end-session --force --shutdown
timeout 15 wineserver -w && exit 0
wineserver -k15
timeout 10 wineserver -w || wineserver -k
"""


def stop_command(app_id: str) -> str:
    """Return the host command that ends a running Windows program's sandbox cleanly (see WINE_STOP)."""
    import shlex
    return shlex.join(["flatpak", "enter", app_id, "bash", "-c", WINE_STOP])


# A Windows program on the check's virtual display draws OpenGL (and Direct3D, which Wine turns into
# OpenGL) in software. Wine's EGL takes the GPU at /dev/dri, and on the test PC that is an NVIDIA card
# whose driver the sandbox doesn't have: "pci id for fd 35: 10de:1cb3, driver (null)", "egl: failed
# to create dri2 screen", and the program is left with no OpenGL at all. TouchOSC then crashed into
# its crash reporter and vimacc's Administration Center ran on with no window, while both showed
# their windows on a virtual display with no GPU to take. An X server with no DRI3 can't show what
# a GPU draws anyway, and the user's own desktop has the driver.
VIRTUAL_DISPLAY_WINE_ENV = {"LIBGL_ALWAYS_SOFTWARE": "1"}


# what the check's observer says of a page the app serves on this machine: "DEBPAK-SERVED URL STATUS TYPE".
# 121GW Companion, a frozen Python program, has no window of its own: it said "121GW Companion:
# http://127.0.0.1:8221/" and asked the desktop's portal to open that in the web browser, which the
# check's virtual display has none of, and counted as an app that showed nothing. A page that answers
# there, as HTML, is its window
SERVED = re.compile(r"^DEBPAK-SERVED (\S+) ([23]\d\d) [^\n]*\bhtml\b", re.M | re.I)


def served_page(marks: str) -> str | None:
    """Return the URL of the web page the app served on this machine, from the observer's marks; None if none."""
    m = SERVED.search(marks)
    return m.group(1) if m else None


# a terminal of a common size and kind for a program started in one (see in_terminal): with no size
# from a terminal of its own, script's pseudo-terminal has 0 rows and 0 columns
TERMINAL_ENV = {"TERM": "xterm-256color"}
TERMINAL_SIZE = "stty rows 24 cols 80 2>/dev/null; exec "


def can_give_terminal() -> bool:
    """True if the host has script (util-linux), which starts a program in a pseudo-terminal of its own."""
    return bool(host.which("script"))


def observe(app_id: str, seconds: int, env: dict[str, str] | None = None,
            args: list[str] | None = None, wine: bool = False, terminal: bool = False) -> Observation:
    """Start the installed app (with args) on a virtual display for seconds and report what it did.

    A Windows program (wine) still running at the end is stopped cleanly
    (stop_command) before its sandbox is killed, and draws in software
    (VIRTUAL_DISPLAY_WINE_ENV). With terminal, the app starts in a
    pseudo-terminal of script's (see in_terminal), and what it drew there is
    its output.
    """
    import shlex
    env = {**session_env(), **(VIRTUAL_DISPLAY_WINE_ENV if wine else {}), **(TERMINAL_ENV if terminal else {}),
           **(env or {})}
    work = Path(tempfile.mkdtemp(prefix="debpak-check-"))
    script, out = work / "observe.sh", work / "output.txt"
    script.write_text(OBSERVER)
    # -a looks for a free display from -n on: a random start keeps checks run side by side (and the
    # test suite's own screens, from :90) from reaching for the same one
    start = str(random.randint(300, 900))
    # the launcher's marker in the app's prefix, as the host sees it (see OBSERVER)
    busy = ["env", f"DEBPAK_CHECK_BUSY={Path.home()}/.var/app/{app_id}/data/wine/{INSTALLING}",
            f"DEBPAK_CHECK_INSTALL={INSTALL_SECONDS}"] if wine else []
    run = ["flatpak", "run", "--user", *[f"--env={k}={v}" for k, v in (env or {}).items()], app_id, *(args or [])]
    clear_runtime_dir(app_id)
    if terminal:
        run = ["script", "-q", "-e", "-c", TERMINAL_SIZE + shlex.join(run), "/dev/null"]
    cmd = ["xvfb-run", "-a", "-n", start, "-s", "-screen 0 1920x1080x24", *busy, "sh", str(script), str(seconds),
           str(out), stop_command(app_id) if wine else "", *run]
    try:
        r = subprocess.run(host.command(cmd), capture_output=True, text=True, errors="replace",
                           timeout=seconds + 120 + (80 + INSTALL_SECONDS if wine else 0))
        marks = r.stdout
    except subprocess.TimeoutExpired:
        marks = "DEBPAK-RUNNING"
    subprocess.run(host.command(["flatpak", "kill", app_id]), capture_output=True)
    clear_runtime_dir(app_id)
    try:
        output = out.read_text("utf-8", "replace")
    except OSError:
        output = ""
    finally:
        import shutil
        shutil.rmtree(work, ignore_errors=True)
    if (big := re.search(r"^DEBPAK-MEMORY (\d+)", marks, re.M)):
        # say so where the diagnosis and the user read the output (see OBSERVER's cap)
        output += (f"\n(debpak's check stopped the app: its processes held {int(big.group(1)) >> 20} GB of "
                   "memory, past the check's limit)\n")
    running = "DEBPAK-RUNNING" in marks
    m = re.search(r"DEBPAK-EXIT (\d+)(?: AFTER (\d+))?", marks)
    windows = re.findall(r"^DEBPAK-WINDOW ?(.*)$", marks, re.M) if "DEBPAK-XDOTOOL" in marks else None
    return Observation(running, int(m.group(1)) if m else None, windows, output[-(8 << 20):],
                       int(m.group(2)) if m and m.group(2) else None, served_page(marks) if running else None)


# run in the app's own sandbox, where the launcher keeps its Wine prefix
PREFIX_EXISTS = 'test -e "$XDG_DATA_HOME/wine"'
# a prefix whose setup a check cut short: wineboot never got as far as system.reg, or as kernel32.dll
# (Intel's BCT: it had its registry, and every start after said "could not load kernel32.dll"), or
# didn't finish (no winrt.PREFIX_DONE, and none of what wine.inf registers: Racemo's next start found
# no RpcSs service), or the launcher installs Windows runtimes and hadn't yet written the marker that
# says they're in
UNFINISHED_PREFIX = f"""\
p="$XDG_DATA_HOME/wine"
[ -d "$p" ] || exit 1
done=1
[ -f "$p/system.reg" ] || done=
[ -e "$p/drive_c/windows/system32/kernel32.dll" ] || done=
[ -e "$p/{PREFIX_DONE}" ] || grep -qsF '{PREFIX_SET_UP}' "$p/system.reg" || done=
if [ -n "$done" ] && [ ! -f "$p/.debpak-runtimes" ] && grep -qs '^RUNTIMES=' /app/bin/*; then done=; fi
[ -e "$p/.debpak-installing" ] && done=
[ -z "$done" ] && rm -rf "$p"
"""


def _in_app(app_id: str, script: str) -> int:
    try:
        return subprocess.run(host.command(["flatpak", "run", "--user", "--command=sh", app_id, "-c", script]),
                              capture_output=True, timeout=300).returncode
    except (OSError, subprocess.TimeoutExpired):
        return -1


def wine_prefix_exists(app_id: str) -> bool:
    """Whether the Windows program's Wine prefix is there already, before a check starts it."""
    return _in_app(app_id, PREFIX_EXISTS) != 1


def drop_unfinished_wine_prefix(app_id: str) -> bool:
    """Remove the Wine prefix a check began, if the check stopped the app before its first-start setup was done.

    A check ends each start after a minute and a half, and DYMO ID's first start
    installs dotnet48, which takes longer: two checks cut it short (the second
    found a half-downloaded installer), and on the third start winetricks' dotnet40
    step failed with status 53 and the program with "could not load kernel32.dll,
    status c0000135". The user's first start should begin from nothing, as it
    would have without the check. Returns whether it was removed.
    """
    return _in_app(app_id, UNFINISHED_PREFIX) == 0


# whether the app's own folder (~/.var/app/<id>) holds no file yet, and the emptying of it again (see
# clear_check_data); inside the sandbox, as the Wine prefix's scripts above. What flatpak itself writes
# there at every start is no file of the app's: config/user-dirs.dirs, and the linker's cache in .ld.so.
# Every check found config/user-dirs.dirs, from the start that asked, and so no app was ever cleared
FLATPAK_OWN = '! -path "$d/config/user-dirs.dirs" ! -path "$d/.ld.so" ! -path "$d/.ld.so/*"'
APP_DATA_EMPTY = 'd="$HOME/.var/app/$FLATPAK_ID"; [ -d "$d" ] || exit 0; ' \
                 f'[ -z "$(find "$d" -mindepth 1 ! -type d {FLATPAK_OWN} 2>/dev/null | head -n 1)" ]'
CLEAR_APP_DATA = 'd="$HOME/.var/app/$FLATPAK_ID"; [ -d "$d" ] || exit 1; ' \
                 f'find "$d" -mindepth 1 ! -type d {FLATPAK_OWN} -delete && ' \
                 f'find "$d" -mindepth 2 -depth -type d -empty {FLATPAK_OWN} -delete'
# What the app left in its runtime folder ($XDG_RUNTIME_DIR), inside the sandbox. Flatpak 1.16 keeps an
# app's runtime folder on the host, in $XDG_RUNTIME_DIR/.flatpak/<id>/xdg-run, from one start to the next,
# and after the app is uninstalled: Mira keeps its QLockFile there (mira/mira-gui.lock), and the check that
# ended it left the lock naming PID 4, which Mira is in every sandbox. Its next start took the lock for
# held and quit at once. Flatpak's own entries there are links (bus, doc, .flatpak, ...), which stay, and
# so does anything with a mount point in it: a host folder mounted there is not the app's to empty
CLEAR_RUNTIME_DIR = """\
r="${XDG_RUNTIME_DIR:-}"
[ -n "$r" ] && [ -d "$r" ] && [ ! -L "$r" ] || exit 1
mounts=$(cut -d' ' -f5 "${DEBPAK_MOUNTINFO:-/proc/self/mountinfo}" 2>/dev/null)
for e in "$r"/* "$r"/.[!.]*; do
    [ -L "$e" ] && continue
    [ -e "$e" ] || continue
    if printf '%s\\n' "$mounts" | grep -q -F -x -e "$e"; then continue; fi
    if printf '%s\\n' "$mounts" | grep -q -F -e "$e/"; then continue; fi
    rm -rf "$e"
done
exit 0
"""


def app_data_empty(app_id: str) -> bool:
    """Whether the app has kept nothing in its own folder yet, before a check starts it."""
    return _in_app(app_id, APP_DATA_EMPTY) == 0


def clear_check_data(app_id: str) -> bool:
    """Empty the app's own folder of what the check's starts left there; returns whether it did.

    Clipboard's rpm, a Tauri app, ran in the check; the check ended it, and with
    no handler for the signal it left its lock naming PID 4, the PID it gets in
    every sandbox. The compat suite's next start found itself named there:
    "another instance is already running (PID: 4)", and it aborted. Mira's
    QLockFile did the same (see OBSERVER). The user's first start should begin
    from nothing, as it would have without the check, so what an app that had
    kept nothing before the check wrote in its own folder goes; files it wrote
    elsewhere stay.
    """
    return _in_app(app_id, CLEAR_APP_DATA) == 0


def clear_runtime_dir(app_id: str) -> bool:
    """Empty the app's runtime folder of what its starts left there (see CLEAR_RUNTIME_DIR); returns
    whether the script ran. The check does so before and after each start: a lock a start left there
    would stop the next one, the check's own or the user's first."""
    return _in_app(app_id, CLEAR_RUNTIME_DIR) == 0


@dataclass
class Remedy:
    """A change to convert's options, and why."""
    key: str                  # what it changes, so the same remedy isn't tried twice
    why: str
    option: str               # the args attribute
    value: object             # True, a str for a single value, or an item to append to a list


# A graphical app that quits at once, saying nothing, often couldn't find or write the files it keeps
# beside itself (OpenTaiko's Config.ini and save database); run from a copy of its folder, started
# there, it has both. Only tried when nothing else points anywhere.
QUIT_AT_ONCE = Remedy("writable", "it quit at once without a window or a word, as a portable app does when it "
                      "can't use the files beside it", "writable", True)


# The same for a Windows program: ExpertGPS, installed under Wine, and AcFun's face-capture tool, unpacked
# from its Inno setup, ended a few seconds after they started with status 1, no window, and nothing
# printed but what Wine says on every start. Under Wine the user is an administrator, so a program may
# count on writing in its folder under Program Files, which here is read-only /app.
WINE_QUIT_AT_ONCE = Remedy("writable", "it ended at once with an error status, without a window or a word of its "
                           "own, as a program does when it can't write in its own folder", "writable", True)
# A Windows program unpacked from its installer has its files but not what the installer's own steps
# make: DBT (Duxbury's braille translator), unpacked from its .msi, showed "can't open file ...\DBT
# 15.1\version.xml" and nothing else, a file a custom action of the package writes as it installs.
# Installed under Wine (msiexec, or the setup itself with its silent switches), those steps run. Only
# tried when nothing else points anywhere, for a program that showed an error or ended with an error
# status; Wine's own crash box (WINE_CRASH_TITLE) is a crash, which installing it again won't mend.
INSTALL_IN_WINE = Remedy("install-in-wine", "it was unpacked from its installer, whose own steps (files and registry "
                         "entries it makes as it installs) didn't run; installed under Wine, they do",
                         "install_in_wine", True)
# the kinds of installer debpak unpacks and can run under Wine instead (see foreign.unpack_windows)
INSTALLER_UNPACKED = ("msi", "inno", "nsis")
WINE_CRASH_TITLE = "Program Error"


def installer_steps_may_help(obs: Observation) -> bool:
    """Whether a Windows program unpacked from its installer failed as one missing the installer's steps may:
    an error box of its own, or an exit with an error status."""
    bad = error_windows([w for w in obs.windows or [] if w.strip() not in ("Wine", WINE_CRASH_TITLE)])
    return bool(bad) or (not obs.running and obs.code not in (None, 0))


# what Wine says on any start, which is no word of the program's: wineboot's "Error running cmd
# ...winemenubuilder.exe", "ZwLoadDriver failed to create driver ...winebth", its notes on what it
# hasn't implemented, and the loader's log
WINE_OWN_LINE = re.compile(r"^\s*[0-9A-Fa-f]{4}:(?:fixme:|trace:loaddll:|err:wineboot:|err:ntoskrnl:)")
# how long "at once" is, for a start whose prefix is set up already
WINE_QUIT_SECONDS = 30


def quit_without_a_word(obs: Observation) -> bool:
    """Whether a Windows program ended soon with an error status, having shown no window and said nothing of its own."""
    return not obs.running and obs.code not in (None, 0) and obs.seconds is not None \
        and obs.seconds <= WINE_QUIT_SECONDS and not obs.windows \
        and all(WINE_OWN_LINE.match(ln) for ln in obs.output.splitlines() if ln.strip())


@dataclass
class Diagnosis:
    remedies: list[Remedy] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def add(self, r: Remedy, tried: set[str]) -> None:
        if r.key not in tried and all(x.key != r.key for x in self.remedies):
            self.remedies.append(r)


# a program's own needs ("error while loading shared libraries: X: cannot open"), or a module's that the
# app loads itself: Slic3r's Perl OpenGL module, "Can't load '.../OpenGL.so' for module OpenGL: libGLU.so.1:
# cannot open shared object file"
MISSING_LIB = re.compile(r"(?:error while loading shared libraries|: )\s*(lib[\w.+-]*\.so[\w.]*): cannot open")
FD_SETSIZE = re.compile(r"bit out of range 0 - FD_SETSIZE on fd_set")
# Go ending a program because a C library's signal handler ran its own off Go's signal stack (ProKZee, a
# Wails app, under WebKitGTK's JavaScriptCore; see stage.ONSTACK_SHIM)
NOT_ON_STACK = re.compile(r"non-Go code set up signal handler without SA_ONSTACK flag|"
                          r"signal \d+ received but handler not on signal stack")
# libraries Python modules look up by name with ctypes.util.find_library, and the message they then give:
# Friture (sounddevice): "OSError: PortAudio library not found"
FOUND_BY_NAME = ((re.compile(r"PortAudio library not found"), "libportaudio.so.2"),
                 (re.compile(r"(?i)\bno library called \"?sndfile\"? was found|sndfile library not found"),
                  "libsndfile.so.1"))
QT_VERSION = re.compile(r"version `Qt_6\.(\d+)(_PRIVATE_API)?' not found")
GLIBC_VERSION = re.compile(r"version `GLIBC_2\.(\d+)' not found")
JAVA = re.compile(r"(?i)cannot find java|java(?: command)?: (?:command )?not found|INSTALL4J_JAVA_HOME|"
                  r"No Java runtime|JAVA_HOME (?:is not set|.*not.*valid)|Unable to locate a Java|"
                  # SQL Developer's launcher asks for one; Angry IP Scanner's says so with notify-send
                  r"full pathname of a J[DR]K installation|You need Java")
MONO = re.compile(r"\bmono(?:-sgen)?: (?:command )?not found|'mono(?:-sgen)?': No such file or directory")
DISPLAY = re.compile(r"(?i)cannot open display|No available video device|Failed to connect to (?:the )?display|"
                     r"could not connect to display|Can't open display|unable to open display|"
                     r"X11: Failed to open display|Could not open X display")
# a program that wants the user's Documents folder and wasn't told where it is: without
# --filesystem=xdg-documents, the user-dirs.dirs Flatpak gives the app names only the folders it may
# use, and Rust's dirs crate then has no Documents folder (AQBot, a Tauri app, panicked: "Could not
# determine Documents directory")
DOCUMENTS = re.compile(r"(?i)(?:could not|couldn't|can't|cannot|unable to|failed to) (?:determine|find|get|locate|"
                       r"resolve) (?:the )?(?:user'?s? )?documents? (?:dir(?:ectory)?|folder|path)")
OWN_NAME = re.compile(r"(?:Failed to register|Could not acquire name|Failed to acquire (?:bus )?name)[^\n]*?"
                      r"\b((?:[A-Za-z][\w-]*\.){2,}[A-Za-z][\w-]*)")
# WebKitGTK's web process sandbox, refused by Flatpak's portal for a bus name outside the Flatpak's ID
# (see stage.WEBKIT_NO_SANDBOX)
WEBKIT_A11Y_NAME = re.compile(r"Invalid sandbox a11y own name")
# what a shell prints for a program the kernel stopped with SIGSYS
BAD_SYSTEM_CALL = re.compile(r"\bBad system call\b")
# GApplication's failure to take its application ID, which it doesn't name: the Flatpak's bus proxy
# answers ServiceUnknown for a name the app may not own (PyGlossary's apps.pyglossary)
GAPPLICATION_UNREGISTERED = re.compile(r"Failed to register: GDBus\.Error:org\.freedesktop\.DBus\.Error\."
                                       r"(?:ServiceUnknown|AccessDenied)")
# what Chromium prints when its sandbox can't start, and zypak's own failures: Spotify's CEF and
# WeWeChat's old Electron left zypak with "zypak-helper: Wait found events, but sd-event found none".
# A GPU process that keeps crashing is one too: Fether's Electron 7 showed no window and ended at
# "The display compositor is frequently crashing. Goodbye.", as an old Chromium's sandbox (its
# seccomp filter) kills a child process for a system call a newer glibc makes and the filter
# doesn't know; started with --no-sandbox, the children run without that filter
CHROMIUM_SANDBOX = re.compile(r"No usable sandbox|setuid sandbox|The SUID sandbox helper|"
                              r"Failed to move to new namespace|zygote_host_impl|"
                              r"Wait found events, but sd-event found none|"
                              r"display compositor is frequently crashing|GPU process isn't usable")
READ_ONLY = re.compile(r"(?:Read-only file system|EROFS)[^\n]*|/app/[^\s:'\"]+[^\n]*(?:Read-only|Permission denied)")
# a path relative to the folder it was started in that isn't there: "./start.sh: 3: ./mercury/mercury: not found"
# (the shell's own "./start.sh: 3:" before it is not one), "Could not open data/fonts/main.ttf"
_RELATIVE = r"""(?<![\w./-])(\./[\w.+-]+(?:/[\w.+-]+)*|[\w+-][\w.+-]*(?:/[\w.+-]+)+)"""
RELATIVE_MISSING = re.compile(_RELATIVE + r"""['"`]?: (?:not found|No such file or directory|cannot open)""")
RELATIVE_UNOPENED = re.compile(r"""(?i:cannot open|could not (?:open|find|load)|failed to (?:open|load)|"""
                               r"""unable to (?:open|load)) (?:file )?['"`]?""" + _RELATIVE)
# the same under Wine, where the program's folder is Z:\app\opt\NAME and the launcher starts it there:
# UVR, a frozen Python program, failed with "PermissionError: [Errno 13] Permission denied: 'data.pkl'",
# and .NET says "Access to the path 'Z:\app\...' is denied"
WINE_READ_ONLY = re.compile(r"PermissionError: \[Errno 13\] Permission denied: '(?![A-Za-z]:|\\\\)[^'\n]+'|"
                            r"(?i:Access to the path '[Zz]:\\{1,2}app\\{1,2}[^'\n]*' is denied)|"
                            r"[Zz]:\\{1,2}app\\{1,2}[^\n]*?(?i:Permission denied|Access is denied|access denied)|"
                            # a log file it couldn't open or make: vimacc's Admin Center said only "Error
                            # opening logfile:  3" (Windows' "path not found": it keeps its logs in a
                            # folder beside itself and couldn't make one in read-only /app) and quit.
                            # Every program writes its log, so this is never a file it only reads
                            r"(?i:\b(?:error|failed|failure|unable|can ?not|can't|could ?n[o']t)\b[^\n]{0,20}?"
                            r"\b(?:open|creat|writ)\w*[^\n]{0,12}?\blog ?file\b[^\n]*)|"
                            # the same in a .NET Framework program's stack trace, which names no path: ABB's
                            # i-bus Tool made its log folder beside itself and stopped at
                            # "System.UnauthorizedAccessException", "at System.IO.__Error.WinIOError", "at
                            # System.IO.Directory.InternalCreateDirectory", "at ibusTool.Base.Logger.Logger.GetLogFilePath()"
                            r"UnauthorizedAccessException[^\n]*\n(?:[^\n]*\n){0,2}?[^\n]*\bat System\.IO\.__Error\.WinIOError"
                            r"[^\n]*\n(?:[^\n]*\n){0,4}?[^\n]*\bat [\w.+<>`]*?Log")
# a path in the home folder's top level that couldn't be opened: what a relative path becomes when the
# app is started from the home folder (".var" and dot folders are the app's own settings)
HOME_MISSING = re.compile(r"""(?i:cannot open|could not (?:open|find|load)|failed to (?:open|load)|unable to (?:open|load)|"""
                          r"""no such file)[^\n]*?['"`]?/home/[^/\s'"`]+/((?!\.)[\w+-][\w.+-]*/[\w.+/-]+)""")
# a file in a dot folder of the home folder that a program stopped without: clrsync's GUI said "Fatal error:
# File does not exist [/home/USER/.config/clrsync/config.toml]" (the folder is the one in the home folder;
# the app's own, under .var, is not one the user sets up)
HOME_DOT_PATH = re.compile(r"""/home/[^/\s'"`\]\[]+/(\.(?!var/)[\w.+-]+(?:/[\w.+-]+)*/[\w+-][\w.+-]*)""")
MISSING_WORDS = re.compile(r"(?i)does ?n[o']t exist|does not exist|not found|no such file|is missing|\bmissing\b|"
                           r"(?:cannot|can't|could not|couldn't|failed to|unable to) (?:open|find|read|load)")


# a program the app runs and looked for on PATH, in what it printed or in a window's title: rkdeveloptool-gui's
# dialog "Error: rkdeveloptool not found" ("The program depends on 'rkdeveloptool', but it was not found
# on your system"), a shell's "sh: 1: rsync: not found" and "rsync: command not found", and a quoted
# name that wasn't found. A word that names a kind of thing (a file, a module) is no program
_PROGRAM = r"([a-z][a-z0-9+_.-]{1,40}[a-z0-9])"
PROGRAM_NOT_FOUND = re.compile(
    r"(?:^|\b(?:sh|bash|exec|env)(?:: \d+)?: )" + _PROGRAM + r": (?:command )?not found\b"
    r"|(?:^|[\s:])['\"`]" + _PROGRAM + r"['\"`](?: command| program| executable)? (?:was |is )?not (?:found|installed)\b"
    r"|\bdepends on ['\"`]" + _PROGRAM + r"['\"`]"
    r"|^(?:error|fatal|missing)[: ]+" + _PROGRAM + r" (?:not found|is not installed|missing)\s*$", re.I | re.M)
NOT_PROGRAMS = frozenset({"file", "module", "config", "configuration", "display", "device", "path", "directory",
                          "folder", "font", "image", "command", "program", "library", "resource", "key", "user",
                          "page", "profile", "plugin", "package", "settings", "data", "theme", "icon", "session",
                          "server", "service", "network", "account", "license", "script", "executable", "binary",
                          # what a script shows its errors with when it can (a dialog it does without), and the
                          # runtimes that remedies of their own bring (--java, --mono, Wine)
                          "zenity", "kdialog", "xdialog", "yad", "xmessage", "notify-send", "gxmessage",
                          "java", "mono", "mono-sgen", "wine", "wine64"})


def missing_programs(obs: Observation) -> list[str]:
    """Return the programs the app looked for on PATH and didn't find (see PROGRAM_NOT_FOUND)."""
    texts = [obs.output, *[w for w in obs.windows or [] if w.strip()]]
    out = []
    for text in texts:
        for m in PROGRAM_NOT_FOUND.finditer(text):
            name = next(g for g in m.groups() if g)
            # a program's name is written as it is typed, and one named after a kind of thing ("theme
            # 'Adwaita' not found") is that thing
            before = re.findall(r"\w+", text[max(0, m.start() - 40):m.start() + 1])
            if name != name.lower() or (before and before[-1].lower() in NOT_PROGRAMS):
                continue
            if name not in NOT_PROGRAMS and not name.startswith("lib") and "." not in name.strip("."):
                out.append(name)
    return list(dict.fromkeys(out))


def missing_home_files(text: str) -> list[str]:
    """Return the files under the home folder's dot folders (.config/NAME/FILE) that the app said it lacks."""
    out = []
    for line in text.splitlines():
        if MISSING_WORDS.search(line):
            out += [m.group(1) for m in HOME_DOT_PATH.finditer(line) if len(Path(m.group(1)).parts) >= 3]
    return list(dict.fromkeys(out))


# WebKitGTK as the loader's log names it (file=libwebkit2gtk-4.1.so.0 [0]; needed by ...)
WEBKITGTK = re.compile(r"\blib(?:webkit2gtk-4\.[01]|webkitgtk-6\.0)\.so")
WEBKIT_SOFTWARE = ("WEBKIT_DISABLE_DMABUF_RENDERER", "WEBKIT_DISABLE_COMPOSITING_MODE")
WINE_DLL = re.compile(r"err:module:import_dll Library (\S+?\.dll) \(which is needed by", re.I)
# where Wine says a program crashed: "wine: Unhandled page fault on read access to 0000000000000000 at
# address 00006FFFFB07D096 (thread 0024), starting debugger...", or an exception "... at address X"
WINE_CRASH = re.compile(r"Unhandled (?:page fault|exception|stack overflow|illegal instruction|privileged "
                        r"instruction|division by zero)[^\n]*? at address ([0-9A-Fa-f]{8,16})\b(?: \(thread ([0-9A-Fa-f]{4})\))?")
# each DLL Wine loads, as WINEDEBUG=+loaddll logs it (see diagnostic_env):
# 0024:trace:loaddll:build_module Loaded L"C:\\windows\\system32\\dwrite.dll" at 00006FFFFB000000: builtin
WINE_LOADED = re.compile(r'^([0-9A-Fa-f]{4}):trace:loaddll:\w+ Loaded L"([^"\n]+)" at ([0-9A-Fa-f]{8,16}): '
                         r"(builtin|native)", re.M)
WINE_LOADDLL_LINE = re.compile(r"^[0-9A-Fa-f]{4}:trace:loaddll:[^\n]*\n?", re.M)
# Wine DLLs that a winetricks verb replaces with Microsoft's, beyond those RUNTIME_FOR and INSTALL_FOR name
CRASH_VERBS = {"msxml3.dll": "msxml3", "msxml6.dll": "msxml6", "riched20.dll": "riched20",
               "d3dcompiler_43.dll": "d3dcompiler_43"}
# no DLL is this big: a crash further than this past the nearest DLL's start is in none of them
DLL_SPAN = 0x4000000


def crash_site(output: str) -> tuple[str, bool, int, list[str]] | None:
    """Return the DLL a Windows program crashed inside, whether it is Wine's own, the crash's offset in it,
    and the last DLLs the crashing thread loaded before it, from a +loaddll log.

    OmaWrite crashed as it started with "Unhandled page fault on read access to
    0000000000000000 at address 00006FFFFB07D096" twice, before and after the
    launcher had its Qt Quick draw with OpenGL, and what it printed said nothing
    of which DLL that address is in. Wine's loader log gives where each DLL was
    loaded, and the crash is in the one loaded nearest below its address. The
    crashing thread's own loads count first, as a DLL's address can differ
    from one process to another. Named, it was the program's own qwindows.dll,
    Qt's platform plugin, which says little alone: the offset finds the function
    in that build of Qt, and the DLLs loaded just before say what it was doing
    (fonts with dwrite.dll, OpenGL with opengl32.dll, accessibility with
    uiautomationcore.dll).
    """
    m = WINE_CRASH.search(output)
    if not m:
        return None
    addr, thread = int(m.group(1), 16), (m.group(2) or "").lower()
    loads = [(t.lower(), path, int(base, 16), how, pos)
             for t, path, base, how, pos in ((*x.groups(), x.start()) for x in WINE_LOADED.finditer(output))]

    def name(path: str) -> str:
        return re.split(r"\\+|/", path)[-1].lower()
    for pool in ([x for x in loads if x[0] == thread], loads):
        below = [x for x in pool if x[2] <= addr < x[2] + DLL_SPAN]
        if below:
            _t, path, base, how, _pos = max(below, key=lambda x: x[2])
            before = [name(x[1]) for x in pool if x[4] < m.start()]
            return name(path), how == "builtin", addr - base, list(dict.fromkeys(reversed(before)))[:LAST_LOADS][::-1]
    return None


# how many of the DLLs loaded last before a crash the report names
LAST_LOADS = 4


def crash_module(output: str) -> tuple[str, bool] | None:
    """Return the DLL a Windows program crashed inside and whether it is Wine's own (see crash_site)."""
    site = crash_site(output)
    return site[:2] if site else None


def _wine_crash(d: Diagnosis, output: str, tried: set[str]) -> None:
    """Say which DLL a Windows program crashed inside, and if it is Wine's own of a runtime, install Microsoft's."""
    from .winapp import RUNTIME_FOR, wine_lacks
    from .winrt import install_verb
    site = crash_site(output)
    if not site:
        return
    dll, builtin, offset, last = site
    where = f"{dll} (at +{offset:#x}" + (f", after it loaded {', '.join(last)})" if last else ")")
    d.evidence.append(f"it crashed inside Wine's own {where}" if builtin else f"it crashed inside {where}")
    if not builtin:
        return
    verb = install_verb(dll) or wine_lacks(dll) or CRASH_VERBS.get(dll) \
        or next((v for pat, v in RUNTIME_FOR if re.match(pat, dll)), None)
    if verb:
        d.add(Remedy(f"wine:{verb}", f"it crashed inside Wine's own {dll}, which {verb} replaces with Microsoft's",
                     "wine_runtime", verb), tried)
WINE_DOTNET = re.compile(r"(?i)mscoree\.dll|\.NET Framework|This application requires .*\.NET|CLR error")
# what wine-mono prints when a .NET Framework program fails on it: its own assertions (AdiIRC:
# "wine-mono-10.4.1/mono/mono/eglib/gpath.c:115: assertion 'filename != NULL' failed", then its
# crash dialog), a mixed-mode C++/CLI assembly it can't load (Snagit: "field __ImageBase in <Module>
# should have RVA data, but hasn't"), and an exception nothing caught, with Mono's "in <module id>:0"
# stack frames; or an exception about one of wine-mono's own files (Creallo Atlas, a Python program whose
# pywebview loads System.Windows.Forms through pythonnet: "System.BadImageFormatException: Invalid Image:
# Z:\app\share\wine\mono\wine-mono-10.4.1\lib\mono\4.5\System.Windows.Forms.dll")
WINE_MONO = re.compile(r"/wine-mono[-\d.]*/mono/[^\n]*|\[ERROR\] FATAL UNHANDLED EXCEPTION[^\n]*|"
                       r"\b[\w.]+Exception: [^\n]*[\\/]wine-mono-[\d.]+[\\/][^\n]*|"
                       r"field \S+ in <Module> should have RVA data, but hasn't|"
                       r"^Unhandled Exception:\s*\n\S[^\n]*(?=(?:\n[^\n]*){0,40}? in <[0-9a-f]{32}>:0)", re.M)

# a function Wine's own version of a runtime DLL lacks, which the real runtime has (Wine aborts on
# the call): "wine: Call from 00006FFFFFF9DDAA to unimplemented function msvcp140.dll.?_Xbad_function_call"
WINE_UNIMPLEMENTED = re.compile(r"unimplemented function (\w+\.dll)\.", re.I)
# what .NET's apphost says, in a console or in the event log Wine prints, when the framework a
# program was built for isn't there: "Framework: 'Microsoft.WindowsDesktop.App', version '8.0.0'
# (x64)", or from older hosts "The framework 'Microsoft.NETCore.App', version '6.0.0' was not found";
# OpenDirectoryDownloader 5.1, given .NET 11 alone, ended with status 150 at "Framework:
# 'Microsoft.AspNetCore.App', version '11.0.0' (x64)"
DOTNET_FRAMEWORK = re.compile(r"(?:Framework: |The framework )'(Microsoft\.(?:WindowsDesktop|AspNetCore|NETCore)\.App)', "
                              r"version '(\d+)\.")
# and when it finds no .NET at all it names only its own version, which is the runtime's: OpenDirectoryDownloader
# 5.1 said "You must install .NET to run this application" over "App host version: 11.0.0"
DOTNET_NONE = re.compile(r"You must install \.NET to run this application[\s\S]{0,800}?App host version: (\d+)\.")
# what a WebView2 program shows or says without the runtime: Wails apps a "Missing Requirements"
# box (Swiss Knife Graph, QShell), others name it
WEBVIEW2 = re.compile(r"(?i)\bWebView2\b[^\n]{0,80}(?:runtime|not (?:found|installed)|missing|failed|error)|"
                      r"CreateCoreWebView2Environment[^\n]*(?:fail|error|0x8)")


def _wine_runtimes(d: Diagnosis, obs: Observation, tried: set[str]) -> None:
    """Add the Windows runtimes a Windows program's failure points to (see winrt), or say why none will do."""
    from .winapp import DOTNET_MAJORS, RUNTIME_FOR, SHARED_FRAMEWORKS, wine_lacks
    from .winrt import install_verb
    text = obs.output
    for dll in dict.fromkeys(x.lower() for x in WINE_UNIMPLEMENTED.findall(text)):
        verb = install_verb(dll) or wine_lacks(dll) or next((v for pat, v in RUNTIME_FOR if re.match(pat, dll)), None)
        if verb:
            d.evidence.append(f"Wine's {dll} lacks a function it calls")
            d.add(Remedy(f"wine:{verb}", f"it calls a function of {dll} that only the real runtime has",
                         "wine_runtime", verb), tried)
    found = DOTNET_FRAMEWORK.findall(text) or [("Microsoft.NETCore.App", m) for m in DOTNET_NONE.findall(text)]
    for fw, major in dict.fromkeys(found):
        if int(major) in DOTNET_MAJORS:
            verb = dict(SHARED_FRAMEWORKS)[fw] + major
            d.evidence.append(f"it asks for {fw} {major}")
            d.add(Remedy(f"wine:{verb}", f"it was built for {fw} {major}", "wine_runtime", verb), tried)
    if WEBVIEW2.search(text) or any(w.strip() == "Missing Requirements" for w in obs.windows or []):
        # nothing to add: a program the plan finds WebView2 in gets the runtime on first start (see
        # winrt.webview2_lines), so a window that still says so means the download failed
        d.evidence.append("it needs Microsoft's WebView2 runtime, which its first start downloads into the Wine prefix")


def diagnose(obs: Observation, kind: str, wine: bool, tried: set[str], kde_runtime: str | None = None) -> Diagnosis:
    """Return the remedies the output points to that haven't been tried."""
    d = Diagnosis()
    if wine:
        _wine_crash(d, obs.output, tried)
        # the loader's lines name every DLL it loads (mscoree.dll among them), which isn't what failed
        obs = replace(obs, output=WINE_LOADDLL_LINE.sub("", obs.output))
    text = obs.output
    for so in dict.fromkeys(MISSING_LIB.findall(text)):
        d.evidence.append(f"{so} wasn't found")
        d.add(Remedy(f"lib:{so}", f"the app needs {so}, which wasn't found", "add_library", so), tried)
    for pattern, so in FOUND_BY_NAME:
        if pattern.search(text):
            d.evidence.append(f"it looked for {so} by name")
            d.add(Remedy(f"lib:{so}", f"it looks for {so} by name", "add_library", so), tried)
    if FD_SETSIZE.search(text):
        d.evidence.append("it select()ed on a file number past FD_SETSIZE")
        d.add(Remedy("fd-limit", "it can't use more than 1024 open files", "fd_limit", 1024), tried)
    if (m := NOT_ON_STACK.search(text)):
        d.evidence.append(m.group(0))
        d.add(Remedy("signal-onstack", "a C library's signal handlers don't run on Go's signal stack",
                     "signal_onstack", True), tried)
    if (m := QT_VERSION.search(text)):
        minor = int(m.group(1))
        d.evidence.append(m.group(0))
        d.add(Remedy(f"runtime:kde6.{minor}", f"it was built against Qt 6.{minor}", "runtime",
                     f"org.kde.Platform//6.{minor}"), tried)
    if (m := GLIBC_VERSION.search(text)):
        d.evidence.append(m.group(0))
        d.add(Remedy("runtime:fd26.08", "it needs a newer glibc", "runtime", "org.freedesktop.Platform//26.08"), tried)
    if JAVA.search(text):
        d.evidence.append("it looked for Java")
        d.add(Remedy("java", "it looks for a Java runtime", "java", True), tried)
    if MONO.search(text):
        d.evidence.append("it looked for mono")
        d.add(Remedy("mono", "it runs a .NET program with mono", "mono", True), tried)
    if DISPLAY.search(text):
        d.evidence.append("it couldn't open the display")
        d.add(Remedy("perm:x11", "it couldn't open the display", "add_permission", "--socket=x11"), tried)
        d.add(Remedy("perm:ipc", "X11 shared memory", "add_permission", "--share=ipc"), tried)
    if (m := DOCUMENTS.search(text)):
        d.evidence.append(m.group(0))
        d.add(Remedy("perm:xdg-documents", "it needs the Documents folder", "add_permission",
                     "--filesystem=xdg-documents"), tried)
    if WEBKIT_A11Y_NAME.search(text):
        # a WebKitGTK 4.1 app that asks for the web process sandbox, which stage leaves out only for 6.0
        d.evidence.append("Flatpak's portal refused WebKitGTK's sandbox for its web process")
        d.add(Remedy("env:WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS", "Flatpak's portal refused WebKitGTK's own "
                     "sandbox, whose bus name is the app's own ID", "add_permission",
                     "--env=WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1"), tried)
    if not wine and (obs.code == 128 + 31 or BAD_SYSTEM_CALL.search(text)):
        # SIGSYS: Flatpak's seccomp filter kills a call made for an architecture it wasn't told about,
        # as it killed the Wine of Subway Surfers' AppImage running a 32-bit game (see
        # analyze.multiarch_reason, which grants it up front when it sees 32-bit code)
        d.evidence.append("a system call was refused (SIGSYS)")
        d.add(Remedy("perm:multiarch", "the sandbox killed it for a system call of 32-bit x86 code",
                     "add_permission", "--allow=multiarch"), tried)
    named = False
    # KDBusService in a Flatpak puts the bus connection's unique name after the app's (KGoldrunner:
    # org.kde.kgoldrunner.kdbus-_1_7), which differs at every start: the app gets every name under its own
    for name in dict.fromkeys(re.sub(r"\.kdbus-[\w-]*$", ".*", n) for n in OWN_NAME.findall(text)):
        if name.startswith("org.freedesktop."):
            continue
        named = True
        d.evidence.append(f"it couldn't take the bus name {name}")
        d.add(Remedy(f"own:{name}", f"it registers {name} on the session bus", "add_permission",
                     f"--own-name={name}"), tried)
    if not named and GAPPLICATION_UNREGISTERED.search(text):
        # PyGlossary's AppImage, a Nuitka build, registers apps.pyglossary, an ID written nowhere a
        # --own-name could be found from (two parts, inside the compiled program), and GApplication
        # names none when the bus proxy refuses it: the app talks to the session bus directly
        d.evidence.append("it couldn't register its application ID on the session bus")
        d.add(Remedy("perm:session-bus", "it couldn't register its application ID, which it doesn't name, "
                     "on the session bus", "add_permission", "--socket=session-bus"), tried)
    # a crash at start (SIGSEGV, SIGTRAP, SIGILL, SIGABRT) is what zypak's sandbox does to a Chromium it
    # doesn't suit (PlayMe: "Segmentation fault ... zypak-wrapper", nothing else). While the app runs,
    # only a FATAL line counts: Gitify, a tray app with no window, printed a harmless sandbox line, and
    # Dialpad went on after zypak's "Wait found events"
    sandbox = [ln for ln in text.splitlines() if CHROMIUM_SANDBOX.search(ln)]
    if kind in ("electron", "cef") and (
            (not obs.running and (sandbox or obs.code in (133, 139, 132, 134)))
            or (obs.running and any("FATAL" in ln for ln in sandbox))):
        d.evidence.append("Chromium's sandbox didn't start")
        d.add(Remedy("no-chromium-sandbox", "Chromium's sandbox can't start here", "no_chromium_sandbox", True), tried)
    if obs.running and obs.windows is not None and not obs.ok and not any(w.strip() for w in obs.windows) \
            and WEBKITGTK.search(text):
        # a WebKitGTK app (a Tauri app) that runs and shows nothing: gg and Agentero keep their window
        # hidden until the page has loaded, and on the test PC's virtual screen, with its GPU at
        # /dev/dri, the page never came (not a line from the page's scripts in Agentero's log,
        # which prints them). WebKit's GPU paths, the DMA-BUF renderer and accelerated compositing,
        # fail without a word on an X server with no DRI3; drawing in software is what the
        # WebKitGTK and Tauri projects advise then, and it costs only speed
        d.evidence.append("it's a WebKitGTK app that drew no window")
        for var in WEBKIT_SOFTWARE:
            d.add(Remedy(f"env:{var}", "WebKitGTK's GPU drawing can fail without a word", "add_permission",
                         f"--env={var}=1"), tried)
    if not wine:
        for name in missing_programs(obs)[:3]:
            # convert brings the program from a distribution's package of that name, if one has it
            d.evidence.append(f"it looked for the program {name}")
            d.add(Remedy(f"program:{name}", f"it runs {name}, which isn't in the Flatpak", "add_program", name),
                  tried)
        for rel in missing_home_files(text)[:3]:
            # convert copies the package's own copy there at first start, if it has one (see analyze.home_seed)
            d.evidence.append(f"it lacks ~/{rel}")
            d.add(Remedy(f"seed:{rel}", f"it wants ~/{rel}, which the user would copy from the package",
                         "seed_home", rel), tried)
    if not wine and (m := HARD_LINKED.search(text)):
        d.evidence.append(m.group(0).strip()[:120])
        d.add(Remedy("writable", "it refuses its own files, which are hard links in a Flatpak", "writable", True),
              tried)
    if (m := READ_ONLY.search(text)) or (wine and (m := WINE_READ_ONLY.search(text))) \
            or (m := next((NOT_WRITABLE_TITLE.search(w) for w in obs.windows or [] if NOT_WRITABLE_TITLE.search(w)),
                          None)):
        d.evidence.append(m.group(0).strip()[:120])
        d.add(Remedy("writable", "it writes into its own folder, which is read-only in a Flatpak", "writable", True),
              tried)
    rel = next((m.group(1) for r in (RELATIVE_MISSING, RELATIVE_UNOPENED) for m in r.finditer(text)
                if not m.group(1).startswith(("usr/", "proc/", "dev/", "etc/"))), None)
    if not rel and (m := HOME_MISSING.search(text)):
        # a path made from the folder it was started in, the home folder: RockBot looked for
        # "/home/USER/fonts/pressstart2p.ttf", its own fonts/ folder
        rel = m.group(1)
    if not rel and (m := re.search(r"Could not load module (\w+)@", text)):
        rel = f"{m.group(1)}.ndll"          # a Haxe program's module (Psych Engine's lime.ndll)
    if not wine and rel:
        d.evidence.append(f"it looked for {rel} in the folder it was started in")
        d.add(Remedy("chdir", "it finds its files relative to the folder it's started in", "chdir", True), tried)
    if wine:
        from .winapp import RUNTIME_FOR, wine_lacks
        for dll in dict.fromkeys(x.lower() for x in WINE_DLL.findall(text)):
            verb = wine_lacks(dll) or next((v for pat, v in RUNTIME_FOR if re.match(pat, dll)), None)
            d.evidence.append(f"Wine couldn't load {dll}")
            if verb:
                d.add(Remedy(f"wine:{verb}", f"it imports {dll}", "wine_runtime", verb), tried)
        _wine_runtimes(d, obs, tried)
        if WINE_DOTNET.search(text):
            d.evidence.append("it looks for the .NET Framework")
            d.add(Remedy("wine:dotnet48", "it needs the .NET Framework", "wine_runtime", "dotnet48"), tried)
        if (m := WINE_MONO.search(text)):
            # only a .NET Framework program runs on wine-mono, and the real Framework is the remedy
            d.evidence.append(f"it failed on wine-mono ({m.group(0).strip().splitlines()[-1][:120]})")
            d.add(Remedy("wine:dotnet48", "it fails on wine-mono, Wine's stand-in for the .NET Framework",
                         "wine_runtime", "dotnet48"), tried)
        if not obs.running and obs.code in (5,):
            # Wine exits with the low byte of the exception that ended the program, here
            # 0xc0000005, an access violation; a program that crashes when it can't write beside
            # itself is the one case debpak can remedy
            d.evidence.append(f"it exited with status {obs.code} (an access violation)")
            d.add(Remedy("writable", "it may crash when it can't write into its own folder", "writable", True),
                  tried)
    return d


# options that take one value, which a remedy replaces (the rest are lists it adds to)
SINGLE_VALUED = ("runtime", "fd_limit")


def apply(args, remedies: list[Remedy]) -> None:
    """Set the remedies' options on args (an argparse namespace)."""
    for r in remedies:
        cur = getattr(args, r.option, None)
        if isinstance(r.value, bool) or r.option in SINGLE_VALUED:
            setattr(args, r.option, r.value)
        else:
            setattr(args, r.option, [*(cur or []), r.value])


# lines of an app's output that say nothing about why it failed: Wine's notes on what it hasn't
# implemented, Mesa's on the virtual display having no GPU, and Wine's loader log of each DLL it loads
OUTPUT_NOISE = re.compile(r"^\s*(?:[0-9a-f]{4}:)?fixme:|^\s*MESA[-\w]*: warning|^\s*pci id for fd \d+|"
                          r"^\s*libEGL warning|^DEBPAK-|^[0-9a-fA-F]{4}:trace:loaddll:")


def output_tail(output: str, lines: int = 25, width: int = 240) -> list[str]:
    """Return the last lines of what the app printed, less noise and repeats, for the user to read.

    When nothing points to a remedy, these lines are what's left to go on:
    VSeeFace and XMedia Recode exited with status 1 and 66 under Wine, and
    convert's output said only that nothing pointed anywhere.
    """
    out: list[str] = []
    for ln in output.splitlines():
        ln = ln.rstrip()
        if not ln.strip() or OUTPUT_NOISE.search(ln) or (out and out[-1] == ln[:width]):
            continue
        out.append(ln[:width])
    return out[-lines:]


def diagnostic_env(wine: bool) -> dict[str, str]:
    """The environment for the second, logged start: the loader's log, or Wine's errors and the DLLs it loads.

    Where each DLL was loaded tells which one a crash's address is in (see crash_module).
    """
    return {"WINEDEBUG": "err+module,+loaddll,-fixme"} if wine else {"LD_DEBUG": "libs,files"}


# a library's name: libfoo.so, libfoo.so.2.1. The log of a Qt app also shows its plugins asked for
# as libqxcb.so.avx2 and the like, copies built for newer processors that no distribution has;
# dupeGuru, Snipaste and Mu were converted again with --add-library for each, to no effect.
SONAME = re.compile(r"lib[\w.+-]*?\.so(?:\.\d+)*")


def failed_loads(output: str, kind: str = "") -> list[str]:
    """Return the libraries an LD_DEBUG=libs log shows the app asked for and never loaded.

    glibc's own libraries (libnss_myhostname.so.2) are left out: debpak never
    bundles them, and asking for one made the conversion refuse. For a
    Chromium app (kind electron or cef) only libraries a program needed at
    start count: Chromium tries dozens with dlopen() and goes on without them
    (ANGLE's GL and GLES translators, NSS's libnssckbi.so), and IGdm was
    converted again for each, then refused.
    """
    from .analyze import is_never_bundle
    from .smoke import PROBES, parse_ld_debug
    log = parse_ld_debug(output.splitlines())
    names = set(log.failed_needed) if kind in ("electron", "cef") else set(log.failed) | set(log.failed_needed)
    return sorted(n for n in names if SONAME.fullmatch(n) and not PROBES.match(n)
                  and not is_never_bundle(n) and not n.startswith("libnss_"))
