"""Pass rates by route for a compat folder: first try (from run*.log) and now (results.json).
Usage: summary.py COMPAT_DIR"""

import json
import re
import sys
import collections
from pathlib import Path

d = Path(sys.argv[1])
PASS = {"works", "exited", "refused-expected"}
NOT_DEBPAK = {"lookup-failed", "download-failed"}  # the network's doing, not a first try
res = json.load(open(d / "results.json")) if (d / "results.json").is_file() else {}
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
    r = v["route"]
    tot[r] += 1
    f_ok[r] += first.get(k, v["status"]) in PASS
    n_ok[r] += v["status"] in PASS


def pct(a, b):
    return f"{a}/{b} ({100 * a // b}%)" if b else "-"


print(f"{'route':10}{'first try':>18}{'now':>18}")
for r in sorted(tot):
    print(f"{r:10}{pct(f_ok[r], tot[r]):>18}{pct(n_ok[r], tot[r]):>18}")
print(f"{'all':10}{pct(sum(f_ok.values()), sum(tot.values())):>18}{pct(sum(n_ok.values()), sum(tot.values())):>18}")
