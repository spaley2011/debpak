"""Rank the causes of first-try failures across batches, so fixes go to the ones that recur.

Usage: causes.py COMPAT_DIR [COMPAT_DIR ...]

For each folder it takes each app's first-try result (results.firstpass.json when the batch has
one, else results.json) and reduces the note to a signature: the route, the status, and the gist
of the error with names, numbers and paths taken out ("crashed: libfoo.so.N missing", "wine: status
N"). Signatures shared by more apps come first, with up to four example keys, so a fix agent can
start with what helps the most apps debpak hasn't seen.
"""
import collections
import json
import re
import sys
from pathlib import Path

PASS = {"works", "exited", "refused-expected", "cli", "not-an-app"}
NOT_DEBPAK = {"lookup-failed", "download-failed"}

# the gist of a note, most specific first: (pattern, signature with \1 for a captured name)
GIST = [
    (r"error while loading shared libraries: ([\w.+-]+?)\.so", r"missing library \1"),
    (r"needs (lib[\w.+-]+?)\.so[.\d]* (GLIBC|GLIBCXX|CXXABI|Qt)_", r"needs newer \2 (\1)"),
    (r"No module named '([\w.]+)'", r"Python module missing: \1"),
    (r"Could not load file or assembly '([\w.]+)", r"Mono/.NET assembly missing: \1"),
    (r"could not load kernel32\.dll", "wine: kernel32 c0000135"),
    (r"Could not initialize GLX|NoGlutinConfigs|failed to create (an )?EGL", "no GL/GLX/EGL context"),
    (r"Settings schema '[^']+' is not installed", "GSettings schema missing"),
    (r"Trace/breakpoint trap", "trap (GLib g_error, Chromium CHECK)"),
    (r"Segmentation fault", "segfault"),
    (r"\bAborted\b", "abort"),
    (r"panic|RUST_BACKTRACE", "Rust/Go panic"),
    (r"exited with status (\d+): \(DISPLAY", r"wine: exit status \1"),
    (r"window says: (\w+)", r"error dialog: \1"),
    (r"no program \(\.exe\) found in [^ ]+\.zip", "zip holding only an installer"),
    (r"no program \(\.exe\) found in [^ ]+\.msi", "MSI with no program picked"),
    (r"installer debpak can't unpack", "installer: unpack and Wine install both failed"),
    (r"WiX bundle", "WiX bundle"),
    (r"system service", "system service"),
    (r"kernel module", "kernel module"),
    (r"native module .* built for (Windows|Mac)", r"Electron: native module built for \1 only"),
    (r"type 1 AppImage", "type 1 AppImage"),
    (r"appstreamcli compose failed", "appstream compose failed"),
    (r"Child process exited with code 1|exit 1$", "build failed (see log)"),
    (r"still running, but no visible window", "no window"),
    (r"exited cleanly without showing a window", "quit without a window"),
]


def gist(note: str) -> str:
    for pat, sig in GIST:
        m = re.search(pat, note)
        if m:
            return m.expand(sig) if "\\" in sig else sig
    s = re.sub(r"/[\w./+-]+", "PATH", note)
    s = re.sub(r"\d+", "N", s)
    return s[:70]


def first_try(folder: Path) -> dict:
    f = folder / "results.firstpass.json"
    return json.load(open(f if f.is_file() else folder / "results.json"))


def main(folders: list[str]) -> None:
    causes: dict[tuple[str, str, str], list[str]] = collections.defaultdict(list)
    total = 0
    for d in map(Path, folders):
        for key, r in first_try(d).items():
            if r["status"] in PASS or r["status"] in NOT_DEBPAK:
                continue
            total += 1
            causes[(r["route"], r["status"], gist(r.get("note") or ""))].append(f"{d.name}:{key}")
    print(f"{total} first-try failures in {len(folders)} batches, {len(causes)} signatures\n")
    for (route, status, sig), keys in sorted(causes.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        print(f"{len(keys):3}  {route:9} {status:13} {sig}")
        print("       " + ", ".join(k.split(":", 1)[1] for k in keys[:4]) + (" ..." if len(keys) > 4 else ""))


if __name__ == "__main__":
    main(sys.argv[1:])
