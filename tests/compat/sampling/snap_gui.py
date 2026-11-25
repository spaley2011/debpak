"""Keep snaps whose store page has a screenshot (a fair sign of a GUI app). Usage: snap_gui.py snaps-all.txt OUT"""

import json
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor

names = [l.split()[0] for l in open(sys.argv[1]) if l.strip()]


def info(n):
    req = urllib.request.Request(
        f"https://api.snapcraft.io/v2/snaps/info/{n}?fields=media,store-url", headers={"Snap-Device-Series": "16"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.load(r)
    except Exception:
        return n, False
    media = d.get("snap", {}).get("media") or []
    return n, any(m.get("type") == "screenshot" for m in media)


with ThreadPoolExecutor(8) as ex:
    keep = [n for n, ok in ex.map(info, names) if ok]
open(sys.argv[2], "w").write("\n".join(keep) + "\n")
print(len(names), "->", len(keep))
