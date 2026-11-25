"""Random sample of winget GUI apps for the wine route. Usage: winget_sample.py index.db USED.json N SEED OUT.json"""

import json
import random
import re
import sqlite3
import sys
import urllib.parse
import urllib.request
import yaml

db, used_f, n, seed, out_f = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
used = json.load(open(used_f))
used_names = {re.sub(r"[^a-z0-9]", "", x.lower()) for x in used["names"]}
used_files = set(used["files"])
c = sqlite3.connect(db)
parts = {r: (p, s) for r, p, s in c.execute("select rowid, parent, pathpart from pathparts")}


def path(r):
    out = []
    while r is not None:
        p, s = parts[r]
        out.append(s)
        r = p
    return "/".join(reversed(out))


with_cmd = {m for (m,) in c.execute("select distinct manifest from commands_map")}


def vkey(v):
    return [int(x) if x.isdigit() else -1 for x in re.split(r"[.\-+]", v)]


latest = {}
for mid, pid, ver, pp in c.execute(
    "select m.rowid, i.id, v.version, m.pathpart from manifest m join ids i on m.id=i.rowid join versions v on m.version=v.rowid"
):
    cmd = mid in with_cmd
    cur = latest.get(pid)
    if cur is None or vkey(ver) > vkey(cur[0]):
        latest[pid] = (ver, pp, cmd or (cur[2] if cur else False))
    elif cmd:
        latest[pid] = (cur[0], cur[1], True)
ids = sorted(latest)
random.Random(seed).shuffle(ids)
NOT_APP = re.compile(
    r"(?i)\b(driver|drivers|runtime|redistributable|redist|sdk|server|cli|font|fonts|plugin|plug-in|extension|add-?in|jdk|jre|toolkit|library|framework|webview2|vc\+\+|directx|codec|codecs|bootstrapper|beta|preview|nightly|insiders?|canary|dev)\b"
)
OK_TYPES = {"exe", "inno", "nullsoft", "msi", "wix", "burn", "zip", "portable"}
picked = []
for pid in ids:
    if len(picked) >= n:
        break
    ver, pp, cmd = latest[pid]
    if cmd or NOT_APP.search(pid.replace(".", " ")):
        continue
    url = "https://cdn.winget.microsoft.com/cache/" + path(pp)
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            m = yaml.safe_load(r.read())
    except Exception as e:
        print("skip", pid, e, file=sys.stderr)
        continue
    name = m.get("PackageName") or pid
    if NOT_APP.search(name) or re.sub(r"[^a-z0-9]", "", name.lower()) in used_names:
        continue
    tags = " ".join(map(str, m.get("Tags") or [])).lower()
    if re.search(r"\b(cli|command-line|terminal-tool)\b", tags):
        continue
    inst = m.get("Installers") or []

    def ok(i, m=m):
        t = (i.get("InstallerType") or m.get("InstallerType") or "").lower()
        return t in OK_TYPES and i.get("InstallerUrl") and "apps.microsoft.com" not in i["InstallerUrl"]

    cands = [i for i in inst if ok(i) and i.get("Architecture") in ("x64", "neutral")] or [
        i for i in inst if ok(i) and i.get("Architecture") == "x86"
    ]
    if not cands:
        continue
    i = cands[0]
    u = i["InstallerUrl"]
    fname = urllib.parse.unquote(urllib.parse.urlparse(u).path.rsplit("/", 1)[-1]).lower()
    if fname in used_files:
        continue
    key = re.sub(r"[^a-z0-9]+", "-", pid.lower()).strip("-")
    picked.append(
        {
            "key": "w-" + key,
            "name": name,
            "route": "wine",
            "why": f"winget sample {pid} {ver}",
            "source": {"type": "url", "url": u},
        }
    )
    print(len(picked), pid, (i.get("InstallerType") or m.get("InstallerType")), file=sys.stderr, flush=True)
json.dump({"apps": picked}, open(out_f, "w"), indent=1)
