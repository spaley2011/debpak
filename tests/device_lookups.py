#!/usr/bin/env python3
"""Live lookups for tests/device-check.sh.

Checks what the unit tests can only fake: Electron's release list, the
native-module lookup against the real npm registry and GitHub, the version
checks for the candidate recipes, and debpak's Flathub search. Prints one
line per check and writes the download URLs it found to a JSON file for the
real-app step.

    PYTHONPATH=src python3 tests/device_lookups.py OUT.json

Exit status: 1 if a check marked "expected" failed, else 0. Checks marked
"informational" show what happens with modules debpak may not handle yet.
"""
from __future__ import annotations

import json
import platform
import sys
import urllib.request

from debpak import electron, manage, natives, recipes

failures = 0


def line(status, what, detail=""):
    print(f"{status:<5} {what}" + (f"\n      {detail}" if detail else ""), flush=True)


def get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "debpak-device-check"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


# ---- Electron -------------------------------------------------------------
# Projects publish prebuilt modules some weeks after an Electron release, so the
# expected checks use an Electron three majors back, closer to what apps ship;
# the newest is informational.
targets = []
try:
    releases = electron.release_list()
    stable = [r["version"] for r in releases if "-" not in r["version"]]
    newest = stable[0]
    older = next((v for v in stable if int(v.split(".")[0]) <= int(newest.split(".")[0]) - 3), newest)
    for v, counts in ((older, True), (newest, False)):
        abi = natives.electron_abi(v, releases)
        targets.append((v, abi, counts))
        line("ok", f"Electron {v} (ABI {abi}): " + ("used for the expected checks" if counts else "newest stable"))
except Exception as e:
    line("FAIL", "Electron release list (the native-module checks need it, so they're skipped)", repr(e))
    failures += 1

# ---- native modules ---------------------------------------------------------
# (path of the Windows build inside an app's resources, npm version to use, expected?)
MODULES = [
    ("app.asar.unpacked/node_modules/@img/sharp-win32-x64/lib/sharp-win32-x64.node", None, True),
    ("app.asar.unpacked/node_modules/@parcel/watcher-win32-x64/watcher.node", None, True),
    # informational: v13.2.0 (Nov 2026) was published with no prebuilt files at all
    ("app.asar.unpacked/node_modules/better-sqlite3/build/Release/better_sqlite3.node", None, False),
    ("app.asar.unpacked/node_modules/sqlite3/build/Release/node_sqlite3.node", None, True),
    ("app.asar.unpacked/node_modules/bcrypt/lib/binding/napi-v3/bcrypt_lib.node", "5.1.1", False),
    ("app.asar.unpacked/node_modules/keytar/build/Release/keytar.node", None, False),
    ("app.asar.unpacked/node_modules/node-pty/prebuilds/win32-x64/pty.node", None, False),
]
pinned = {}
for rel, ver, _ in MODULES:
    name, _dir = natives.package_of(rel)
    if ver:
        pinned[name] = ver
_pj_cache: dict[str, dict] = {}


def read_pj(pkg_dir: str) -> dict:
    name = pkg_dir.rsplit("node_modules/", 1)[-1]
    if name not in _pj_cache:
        try:
            _pj_cache[name] = get_json(f"https://registry.npmjs.org/{name}/{pinned.get(name, 'latest')}")
        except Exception:
            _pj_cache[name] = {}
    return _pj_cache[name]


for (version, abi, counts), (rel, _, expected) in ((t, m) for t in targets for m in MODULES):
    name, _dir = natives.package_of(rel)
    expected = expected and counts
    r = natives.Resolver(read_pj, version, abi)
    try:
        ok = r.resolve(rel)
    except Exception as e:
        ok, r.res.unresolved[rel] = False, f"crashed: {e!r}"
    label = f"native module {name}, Electron {version.split('.')[0]}" + ("" if expected else " (informational)")
    if ok:
        files = ", ".join(f"{f.to.split('node_modules/', 1)[-1]} ({len(f.data)} bytes)" for f in r.res.files[:4])
        srcs = "; ".join(f"{s.url} [{s.checked}]" for s in r.res.sources[:3])
        line("ok", label, f"files: {files}\n      from: {srcs}")
    else:
        line("FAIL" if expected else "no", label, r.res.unresolved.get(rel, "no reason recorded"))
        failures += expected

# ---- recipe version checks ----------------------------------------------------
urls = {}
CHECKS = {
    "notepadpp": {"type": "github", "repo": "notepad-plus-plus/notepad-plus-plus",
                  "asset": r"^npp\.[0-9.]+\.portable\.x64\.zip$"},
    "notion": {"type": "redirect", "url": "https://www.notion.so/desktop/windows/download",
               "version": r"([0-9]+\.[0-9]+\.[0-9]+)"},
}
for key, check in CHECKS.items():
    try:
        url, ver = recipes.find_latest(check)
        urls[key] = url
        line("ok", f"recipe check {key} ({check['type']}): {ver}", url)
    except Exception as e:
        line("FAIL", f"recipe check {key} ({check['type']})", str(e))
        failures += 1

# Cursor's key names aren't confirmed yet, so print what the endpoint returns
try:
    plat = "linux-arm64" if platform.machine() == "aarch64" else "linux-x64"
    data = get_json(f"https://www.cursor.com/api/download?platform={plat}&releaseTrack=stable")
    line("ok", "Cursor download API", json.dumps(data)[:600])
    found = [v for v in data.values() if isinstance(v, str) and v.split("?")[0].endswith(".deb")] \
        if isinstance(data, dict) else []
    if found:
        urls["cursor"] = found[0]
    else:
        line("no", "Cursor: no .deb URL among the top-level values (see above for the key names)")
except Exception as e:
    line("no", "Cursor download API (informational)", repr(e))

# ---- Flathub search -----------------------------------------------------------
for names, should_match in ((["Firefox"], True), (["Notepad++"], False), (["Notion"], False), (["Cursor"], False)):
    try:
        hit = manage.flathub_match(names)
        got = f"{hit.app_id} ({hit.name})" if hit else "no match"
        status = "ok" if bool(hit) == should_match else ("FAIL" if should_match else "note")
        line(status, f"Flathub match for {names[0]}: {got}")
        failures += status == "FAIL"
    except Exception as e:
        line("FAIL", f"Flathub match for {names[0]}", repr(e))
        failures += 1

if len(sys.argv) > 1:
    with open(sys.argv[1], "w") as f:
        json.dump(urls, f, indent=1)
sys.exit(1 if failures else 0)
