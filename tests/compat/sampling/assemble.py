"""Build holdout-v.json and holdout-t.json. Usage: assemble.py linux-assets.json wine.json snaps-all.txt used.json PER_ROUTE SEED OUT [ALREADY_DRAWN.json...]"""
import json, random, re, sys, collections, urllib.parse
assets, wine_f, snaps_f, used_f, per, seed = sys.argv[1:7]
per, rnd = int(per), random.Random(int(seed))
used = json.load(open(used_f))
for extra in sys.argv[8:]:          # catalogs already drawn (the validation set, when drawing the test set)
    for a in json.load(open(extra))["apps"]:
        used["names"].append(a["name"]); s = a["source"]
        if s["type"] == "snap": used["snaps"].append(s["name"])
        if "github.com/" in a["why"]: used["repos"].append(a["why"].split("github.com/")[1].lower())
used_snaps = set(used["snaps"]); used_repos = set(used["repos"])
used_names = {re.sub(r"[^a-z0-9]", "", n.lower()) for n in used["names"]}
norm = lambda s: re.sub(r"[^a-z0-9]", "", s.lower())
NOT_GUI = re.compile(r"(?i)(\b|[-_.])(cli|server|daemon|headless|tui|agent|bot|sdk|lib|api|proxy|sshfs|ctl)(\b|[-_.])|tui(\b|[-_.])|^lazy")
picked = collections.defaultdict(list); names = set()
repos = sorted(json.load(open(assets)).items()); rnd.shuffle(repos)
for repo, fmts in repos:
    n = norm(repo.split("/")[1])
    if n in names or n in used_names or repo.lower() in used_repos: continue
    open_ = [f for f in fmts if len(picked[f]) < per]
    if not open_: continue
    least = min(len(picked[f]) for f in open_)
    f = rnd.choice([f for f in open_ if len(picked[f]) == least])
    names.add(n)
    picked[f].append({"key": f"h-{f[:3]}-" + re.sub(r"[^a-z0-9]+", "-", repo.lower()).strip("-"),
                      "name": repo.split("/")[1], "route": f, "why": f"holdout sample: github.com/{repo}",
                      "source": {"type": "url", "url": fmts[f]}})
seen_ids = set()
for a in json.load(open(wine_f))["apps"]:
    base = ".".join(a["why"].split()[2].split(".")[:2])       # Mozilla.Firefox.ESR.an -> Mozilla.Firefox
    if NOT_GUI.search(a["name"]) or re.search(r"(?i)driver|visa|\bwsl\b|systemupdate|signing|pkgconf|exiv2", a["why"]): continue
    if base in seen_ids or norm(a["name"]) in names or norm(a["name"]) in used_names or len(picked["wine"]) >= per: continue
    seen_ids.add(base); names.add(norm(a["name"])); picked["wine"].append(a)
snaps = sorted({l.split()[0] for l in open(snaps_f) if l.strip()} - used_snaps); rnd.shuffle(snaps)
for s in snaps:
    if len(picked["snap"]) >= per: break
    if norm(s) in used_names or norm(s) in names or NOT_GUI.search(s): continue
    names.add(norm(s))
    picked["snap"].append({"key": "h-snap-" + s, "name": s, "route": "snap", "why": "holdout sample: snap store",
                           "source": {"type": "snap", "name": s}})
out = sys.argv[7]
apps = [a for route in sorted(picked) for a in picked[route]]
json.dump({"apps": apps}, open(out, "w"), indent=1)
print({r: len(p) for r, p in picked.items()}, len(apps), "->", out)
