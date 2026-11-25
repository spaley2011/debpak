"""Find each repo's latest release assets from github.com pages (no API). Usage: releases_html.py OUT N SEED REPOS.txt"""
import json, random, re, sys, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor
out_path, n, seed, listf = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
repos = [l.strip() for l in open(listf) if l.strip().count("/") == 1]
random.Random(seed).shuffle(repos)
import os
done = {}
if os.path.exists(out_path):
    done = json.load(open(out_path))
skip = set(done) | {l.strip() for l in open(out_path + ".none")} if os.path.exists(out_path + ".none") else set(done)
repos = [r for r in repos if r not in skip][:n]
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) debpak-compat"}
def fetch(url, tries=4):
    for t in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=30) as r:
                return r.geturl(), r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None, None
            time.sleep(5 * (t + 1) + (30 if e.code == 429 else 0))
        except Exception:
            time.sleep(3 * (t + 1))
    return None, None
def get(r):
    final, _ = fetch(f"https://github.com/{r}/releases/latest")
    if not final or "/releases/tag/" not in final:
        return r, None
    tag = final.split("/releases/tag/", 1)[1]
    _, page = fetch(f"https://github.com/{r}/releases/expanded_assets/{tag}")
    if page is None:
        return r, None
    assets = sorted(set(re.findall(r'href="(/[^"]+/releases/download/[^"]+)"', page)))
    return r, {"tag": urllib.request.unquote(tag), "assets": ["https://github.com" + a for a in assets]}
out = dict(done)
none = open(out_path + ".none", "a")
with ThreadPoolExecutor(6) as ex:
    for i, (r, v) in enumerate(ex.map(get, repos)):
        if v:
            out[r] = v
        else:
            none.write(r + "\n")
        if i % 250 == 0:
            print(i, len(out), file=sys.stderr, flush=True)
            json.dump(out, open(out_path, "w"))
json.dump(out, open(out_path, "w"))
print(len(repos), len(out))
