"""Draw the final test set and the training batches from the pools.

Usage: batches.py linux-assets.json wine-pool.json snaps-gui.txt used2.json holdout-v.json SEED [MAX_NEW]
Writes holdout-t.json (45 per route, untouched until the end) and batches/batch-NN.json (200 apps each,
an even mix of routes), from what's left. Already-written batches are kept as they are: running it
again with bigger pools only adds batches after them.
"""

import json
import os
import random
import re
import sys
import collections

assets_f, wine_f, snaps_f, used_f, v_f, seed = sys.argv[1:7]
max_new = int(sys.argv[7]) if len(sys.argv) > 7 else 99
rnd = random.Random(int(seed))


def norm(s):
    return re.sub(r"[^a-z0-9]", "", s.lower())


NOT_GUI = re.compile(
    r"(?i)(\b|[-_.])(cli|server|daemon|headless|tui|agent|bot|sdk|lib|api|proxy|sshfs|ctl)(\b|[-_.])"
    r"|tui(\b|[-_.])|^lazy"
)
used = json.load(open(used_f))
taken_names = {norm(n) for n in used["names"]}
taken_repos = {r.lower() for r in used["repos"]}
taken_snaps = set(used["snaps"])


def take(a):
    taken_names.add(norm(a["name"]))
    if a["source"]["type"] == "snap":
        taken_snaps.add(a["source"]["name"])
    if "github.com/" in a["why"]:
        taken_repos.add(a["why"].split("github.com/")[1].lower())


existing = []
os.makedirs("batches", exist_ok=True)
for f in [v_f, "holdout-t.json"] + sorted(f"batches/{x}" for x in os.listdir("batches")):
    if os.path.exists(f):
        for a in json.load(open(f))["apps"]:
            take(a)

# candidates per route, in a fixed random order
cands = collections.defaultdict(list)
repos = sorted(json.load(open(assets_f)).items())
rnd.shuffle(repos)
for repo, fmts in repos:
    for f, url in fmts.items():
        cands[f].append(
            {
                "key": f"h-{f[:3]}-" + re.sub(r"[^a-z0-9]+", "-", repo.lower()).strip("-"),
                "name": repo.split("/")[1],
                "route": f,
                "why": f"holdout sample: github.com/{repo}",
                "source": {"type": "url", "url": url},
                "_repo": repo.lower(),
            }
        )
for a in json.load(open(wine_f))["apps"]:
    if NOT_GUI.search(a["name"]) or re.search(r"(?i)driver|visa|\bwsl\b|systemupdate|signing|pkgconf|exiv2", a["why"]):
        continue
    a["_base"] = ".".join(a["why"].split()[2].split(".")[:2])
    cands["wine"].append(a)
rnd.shuffle(cands["wine"])
snaps = sorted({l.split()[0] for l in open(snaps_f) if l.strip()})
rnd.shuffle(snaps)
for s in snaps:
    if not NOT_GUI.search(s):
        cands["snap"].append(
            {
                "key": "h-snap-" + s,
                "name": s,
                "route": "snap",
                "why": "holdout sample: snap store",
                "source": {"type": "snap", "name": s},
            }
        )
ROUTES = ["appimage", "deb", "rpm", "tarball", "snap", "wine"]
seen_bases = set()


def draw(route):
    while cands[route]:
        a = cands[route].pop(0)
        if norm(a["name"]) in taken_names or a.get("_repo", "") in taken_repos:
            continue
        if route == "snap" and a["source"]["name"] in taken_snaps:
            continue
        if a.get("_base"):
            if a["_base"] in seen_bases:
                continue
            seen_bases.add(a["_base"])
        take(a)
        return {k: v for k, v in a.items() if not k.startswith("_")}
    return None


if not os.path.exists("holdout-t.json"):
    t = [x for r in ROUTES for x in (draw(r) for _ in range(45)) if x]
    json.dump({"apps": t}, open("holdout-t.json", "w"), indent=1)
    print("holdout-t:", collections.Counter(a["route"] for a in t))
n = len(os.listdir("batches"))
made = 0
while made < max_new:
    batch = []
    for i in range(200):
        r = ROUTES[(i + n) % len(ROUTES)]
        a = draw(r)
        if a is None:  # this route has run out: stop, rather than tilt the mix
            print(f"{r} has run out")
            break
        batch.append(a)
    if len(batch) < 200:
        print(f"left over: {len(batch)} (not enough for another batch)")
        break
    n += 1
    made += 1
    json.dump({"apps": batch}, open(f"batches/batch-{n:02}.json", "w"), indent=1)
    print(f"batch-{n:02}:", dict(collections.Counter(a["route"] for a in batch)))
