"""Show why apps failed in a compat run. Usage: why.py COMPAT_DIR [KEY-SUBSTRING...] [-n LINES] [--convert]"""
import json, re, sys
from pathlib import Path
args = sys.argv[1:]
n = 25
if "-n" in args:
    i = args.index("-n"); n = int(args[i + 1]); del args[i:i + 2]
conv = "--convert" in args
args = [a for a in args if a != "--convert"]
d = Path(args[0]); keys = args[1:]
PASS = {"works", "exited", "refused-expected"}
res = json.load(open(d / "results.json")) if (d / "results.json").is_file() else {}
for k, v in sorted(res.items(), key=lambda kv: (kv[1]["route"], kv[0])):
    if keys and not any(s in k for s in keys): continue
    if not keys and v["status"] in PASS: continue
    print(f"##### {k} | {v['route']} | {v['status']} | {(v.get('note') or '')[:200]}")
    t = (d / "logs" / f"{k}.log").read_text("utf-8", "replace") if (d / "logs" / f"{k}.log").is_file() else ""
    t = re.sub(r"\x1b\[[0-9;]*m", "", t)
    if conv:
        part = t.split("$ flatpak run --user")[0]
    else:
        part = t.split("$ flatpak run --user", 1)[-1] if "$ flatpak run --user" in t else t
        part = part.split("$ debpak uninstall")[0]
    seen, out = set(), []
    for l in part.splitlines():
        key = re.sub(r"[\d.:]+", "#", l.strip())
        if not l.strip() or key in seen: continue
        seen.add(key); out.append(l)
    for l in out[-n:]: print("   ", l[:240])
