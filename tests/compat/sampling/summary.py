"""Pass rates by route for a compat folder: first try (from run*.log) and now (results.json).
Usage: summary.py COMPAT_DIR"""
import json, re, sys, collections
from pathlib import Path
d = Path(sys.argv[1])
PASS = {"works", "exited", "refused-expected"}
# the network's doing, not a first try; and a command-line program the sample took for a GUI app
# (debpak reports it as one), or a theme snap with no apps, is left out of the rate rather than counted as a pass
NOT_DEBPAK = {"lookup-failed", "download-failed", "cli", "not-an-app"}
res = json.load(open(d / "results.json")) if (d / "results.json").is_file() else {}
for v in res.values():                  # results recorded before compat knew the status
    if "snap with no apps (a base, runtime" in (v.get("note") or ""):
        v["status"] = "not-an-app"
names = {v["name"]: k for k, v in res.items()}
first = {}
for log in sorted(d.glob("run*.log")):
    for line in open(log, errors="replace"):
        m = re.match(r"\[ *\d+/\d+\] (.*?): ([a-z-]+): ", line)
        if m and m.group(1) in names and names[m.group(1)] not in first and m.group(2) not in NOT_DEBPAK:
            first[names[m.group(1)]] = m.group(2)
tot, f_ok, n_ok = collections.Counter(), collections.Counter(), collections.Counter()
for k, v in res.items():
    if v["status"] in NOT_DEBPAK:
        continue
    r = v["route"]; tot[r] += 1
    f_ok[r] += first.get(k, v["status"]) in PASS
    n_ok[r] += v["status"] in PASS
pct = lambda a, b: f"{a}/{b} ({100 * a // b}%)" if b else "-"
print(f"{'route':10}{'first try':>18}{'now':>18}")
for r in sorted(tot):
    print(f"{r:10}{pct(f_ok[r], tot[r]):>18}{pct(n_ok[r], tot[r]):>18}")
print(f"{'all':10}{pct(sum(f_ok.values()), sum(tot.values())):>18}{pct(sum(n_ok.values()), sum(tot.values())):>18}")
left = collections.Counter(v["status"] for v in res.values() if v["status"] in NOT_DEBPAK)
if left:
    print("left out: " + ", ".join(f"{n} {s}" for s, n in sorted(left.items())))
# the bar a batch has to clear before the next one starts: 190 of 200, or 95% of the apps left once
# those that can't work outside their own OS are dropped (dropped.json in the folder, a list of keys,
# by the user's rule). A command-line program that converts and runs counts as a pass here, and a
# snap with no apps (a theme) is no app at all; failed lookups and downloads count against it.
dropped = set(json.load(open(d / "dropped.json"))) if (d / "dropped.json").is_file() else set()
apps = {k: v for k, v in res.items() if k not in dropped and v["status"] != "not-an-app"}
# a refusal is a pass only for a system service or a driver (the user's rule): something a Flatpak
# can't be, whatever the converter did
SERVICE = re.compile(r"(?i)system service|daemon|kernel module|loads a kernel|driver|mount helper")
ok = sum(v["status"] in PASS | {"cli"} or (v["status"] == "refused" and bool(SERVICE.search(v.get("note") or "")))
         for v in apps.values())
need = -(-95 * len(apps) // 100)
print(f"bar: {ok}/{len(apps)} pass ({len(dropped)} dropped), {need} needed" + (" - CLEARED" if ok >= need else ""))
