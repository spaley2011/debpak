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
from dataclasses import dataclass, field
from pathlib import Path

from . import host

# seconds the app gets before it's judged; a Windows program's first start sets up its Wine prefix
SECONDS = {"wine": 90}
DEFAULT_SECONDS = 40
ROUNDS = 3

# runs on the host under xvfb-run: $1 seconds, $2 output file, then the flatpak command
OBSERVER = """\
secs=$1; out=$2; shift 2
"$@" >"$out" 2>&1 </dev/null &
pid=$!
n=0
while [ "$n" -lt "$secs" ] && kill -0 "$pid" 2>/dev/null; do sleep 1; n=$((n+1)); done
if kill -0 "$pid" 2>/dev/null; then
    echo "DEBPAK-RUNNING"
    if command -v xdotool >/dev/null 2>&1; then
        echo "DEBPAK-XDOTOOL"
        for w in $(xdotool search --onlyvisible --name "" 2>/dev/null); do
            echo "DEBPAK-WINDOW $(xdotool getwindowname "$w" 2>/dev/null)"
        done
    fi
    kill "$pid" 2>/dev/null
    sleep 2
    kill -9 "$pid" 2>/dev/null
else
    wait "$pid"
    echo "DEBPAK-EXIT $?"
fi
"""

ERROR_TITLE = re.compile(r"(?i)\b(error|exception|crash(ed)?|fatal|failed|problem)\b")


@dataclass
class Observation:
    """What one start of the app showed."""
    running: bool
    code: int | None
    windows: list[str] | None        # None: no xdotool to look with
    output: str

    @property
    def ok(self) -> bool:
        if not self.running:
            return False
        if self.windows is None:
            return True
        titled = [w for w in self.windows if w.strip() and w.strip() != "Wine"]
        return bool(titled) and not any(ERROR_TITLE.search(w) for w in titled)

    def describe(self) -> str:
        if self.ok:
            return "running" + (f", showing {', '.join(w for w in self.windows if w)[:120]}" if self.windows else "")
        if not self.running:
            return f"exited with status {self.code}"
        bad = [w for w in self.windows or [] if ERROR_TITLE.search(w)]
        return f"showing an error ({', '.join(bad)[:120]})" if bad else "running, but with no window"


def available() -> bool:
    """True if the host can start apps on a virtual display (xvfb-run) to check them."""
    return bool(host.which("xvfb-run") and host.which("flatpak"))


def observe(app_id: str, seconds: int, env: dict[str, str] | None = None) -> Observation:
    """Start the installed app on a virtual display for seconds and report what it did."""
    work = Path(tempfile.mkdtemp(prefix="debpak-check-"))
    script, out = work / "observe.sh", work / "output.txt"
    script.write_text(OBSERVER)
    # -a looks for a free display from -n on: a random start keeps checks run side by side (and the
    # test suite's own screens, from :90) from reaching for the same one
    start = str(random.randint(300, 900))
    cmd = ["xvfb-run", "-a", "-n", start, "-s", "-screen 0 1920x1080x24", "sh", str(script), str(seconds), str(out),
           "flatpak", "run", "--user", *[f"--env={k}={v}" for k, v in (env or {}).items()], app_id]
    try:
        r = subprocess.run(host.command(cmd), capture_output=True, text=True, errors="replace",
                           timeout=seconds + 120)
        marks = r.stdout
    except subprocess.TimeoutExpired:
        marks = "DEBPAK-RUNNING"
    subprocess.run(host.command(["flatpak", "kill", app_id]), capture_output=True)
    try:
        output = out.read_text("utf-8", "replace")
    except OSError:
        output = ""
    finally:
        import shutil
        shutil.rmtree(work, ignore_errors=True)
    running = "DEBPAK-RUNNING" in marks
    m = re.search(r"DEBPAK-EXIT (\d+)", marks)
    windows = re.findall(r"^DEBPAK-WINDOW ?(.*)$", marks, re.M) if "DEBPAK-XDOTOOL" in marks else None
    return Observation(running, int(m.group(1)) if m else None, windows, output[-(8 << 20):])


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


@dataclass
class Diagnosis:
    remedies: list[Remedy] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def add(self, r: Remedy, tried: set[str]) -> None:
        if r.key not in tried and all(x.key != r.key for x in self.remedies):
            self.remedies.append(r)


MISSING_LIB = re.compile(r"error while loading shared libraries: ([^:\s]+): cannot open")
QT_VERSION = re.compile(r"version `Qt_6\.(\d+)(_PRIVATE_API)?' not found")
GLIBC_VERSION = re.compile(r"version `GLIBC_2\.(\d+)' not found")
JAVA = re.compile(r"(?i)cannot find java|java(?: command)?: (?:command )?not found|INSTALL4J_JAVA_HOME|"
                  r"No Java runtime|JAVA_HOME (?:is not set|.*not.*valid)|Unable to locate a Java")
MONO = re.compile(r"\bmono(?:-sgen)?: (?:command )?not found|'mono(?:-sgen)?': No such file or directory")
DISPLAY = re.compile(r"(?i)cannot open display|No available video device|Failed to connect to (?:the )?display|"
                     r"could not connect to display|Can't open display|unable to open display|"
                     r"X11: Failed to open display|Could not open X display")
OWN_NAME = re.compile(r"(?:Failed to register|Could not acquire name|Failed to acquire (?:bus )?name)[^\n]*?"
                      r"\b((?:[A-Za-z][\w-]*\.){2,}[A-Za-z][\w-]*)")
# what Chromium prints when its sandbox can't start, and zypak's own failures: Spotify's CEF and
# WeWeChat's old Electron left zypak with "zypak-helper: Wait found events, but sd-event found none"
CHROMIUM_SANDBOX = re.compile(r"No usable sandbox|setuid sandbox|The SUID sandbox helper|"
                              r"Failed to move to new namespace|zygote_host_impl|"
                              r"Wait found events, but sd-event found none")
READ_ONLY = re.compile(r"(?:Read-only file system|EROFS)[^\n]*|/app/[^\s:'\"]+[^\n]*(?:Read-only|Permission denied)")
# a path relative to the folder it was started in that isn't there: "./start.sh: 3: ./mercury/mercury: not found"
# (the shell's own "./start.sh: 3:" before it is not one), "Could not open data/fonts/main.ttf"
_RELATIVE = r"""(?<![\w./-])(\./[\w.+-]+(?:/[\w.+-]+)*|[\w+-][\w.+-]*(?:/[\w.+-]+)+)"""
RELATIVE_MISSING = re.compile(_RELATIVE + r"""['"`]?: (?:not found|No such file or directory|cannot open)""")
RELATIVE_UNOPENED = re.compile(r"""(?i:cannot open|could not (?:open|find|load)|failed to (?:open|load)|"""
                               r"""unable to (?:open|load)) (?:file )?['"`]?""" + _RELATIVE)
WINE_DLL = re.compile(r"err:module:import_dll Library (\S+?\.dll) \(which is needed by", re.I)
WINE_DOTNET = re.compile(r"(?i)mscoree\.dll|\.NET Framework|This application requires .*\.NET|CLR error")


def diagnose(obs: Observation, kind: str, wine: bool, tried: set[str], kde_runtime: str | None = None) -> Diagnosis:
    """Return the remedies the output points to that haven't been tried."""
    d = Diagnosis()
    text = obs.output
    for so in dict.fromkeys(MISSING_LIB.findall(text)):
        d.evidence.append(f"{so} wasn't found")
        d.add(Remedy(f"lib:{so}", f"the app needs {so}, which wasn't found", "add_library", so), tried)
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
    for name in dict.fromkeys(OWN_NAME.findall(text)):
        if name.startswith("org.freedesktop."):
            continue
        d.evidence.append(f"it couldn't take the bus name {name}")
        d.add(Remedy(f"own:{name}", f"it registers {name} on the session bus", "add_permission",
                     f"--own-name={name}"), tried)
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
    if (m := READ_ONLY.search(text)):
        d.evidence.append(m.group(0).strip()[:120])
        d.add(Remedy("writable", "it writes into its own folder, which is read-only in a Flatpak", "writable", True),
              tried)
    rel = next((m.group(1) for r in (RELATIVE_MISSING, RELATIVE_UNOPENED) for m in r.finditer(text)
                if not m.group(1).startswith(("usr/", "proc/", "dev/", "etc/"))), None)
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
        if WINE_DOTNET.search(text):
            d.evidence.append("it looks for the .NET Framework")
            d.add(Remedy("wine:dotnet48", "it needs the .NET Framework", "wine_runtime", "dotnet48"), tried)
        if not obs.running and obs.code in (5,):
            # ERROR_ACCESS_DENIED: NCH's programs write beside themselves
            d.evidence.append(f"it exited with status {obs.code} (access denied)")
            d.add(Remedy("writable", "it writes into its own folder", "writable", True), tried)
    return d


def apply(args, remedies: list[Remedy]) -> None:
    """Set the remedies' options on args (an argparse namespace)."""
    for r in remedies:
        cur = getattr(args, r.option, None)
        if isinstance(r.value, bool) or r.option == "runtime":
            setattr(args, r.option, r.value)
        else:
            setattr(args, r.option, [*(cur or []), r.value])


def diagnostic_env(wine: bool) -> dict[str, str]:
    """The environment for the second, logged start: the loader's log, or Wine's errors."""
    return {"WINEDEBUG": "err+module,err+loaddll,-fixme"} if wine else {"LD_DEBUG": "libs,files"}


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
    return sorted(n for n in names if n.startswith("lib") and ".so" in n and not PROBES.match(n)
                  and not is_never_bundle(n) and not n.startswith("libnss_"))
