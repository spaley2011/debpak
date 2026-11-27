"""Keep snaps whose store page has a screenshot (a fair sign of a GUI app). Usage: snap_gui.py snaps-all.txt OUT

A snap is kept only if the store has a release of it for amd64, the machine the batches run on, in
any channel: the compat run takes the most stable channel a snap has (knotter and opentubex are
only in beta, libretextus only in edge), but a snap with no amd64 release can't be fetched at all.
A store request that times out is tried again, so a slow answer doesn't drop a snap from the pool.
"""
import json
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

ARCH = "amd64"


def store_info(n, tries=4):
    """The store's record of snap n (its media and channel map), or None if it has none or won't say."""
    req = urllib.request.Request(f"https://api.snapcraft.io/v2/snaps/info/{n}?fields=media,store-url",
                                 headers={"Snap-Device-Series": "16"})
    for t in range(tries):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code not in (429, 500, 502, 503, 504):
                return None
        except (OSError, ValueError):
            pass
        time.sleep(5 * (t + 1))
    return None


def keep(d, arch=ARCH):
    """True if a store record has a screenshot and a release for arch."""
    if not d:
        return False
    media = d.get("snap", {}).get("media") or []
    has_arch = any(c.get("channel", {}).get("architecture") == arch for c in d.get("channel-map", []))
    return has_arch and any(m.get("type") == "screenshot" for m in media)


def main(argv):
    names = [l.split()[0] for l in open(argv[1]) if l.strip()]
    with ThreadPoolExecutor(8) as ex:
        kept = [n for n, ok in zip(names, ex.map(lambda n: keep(store_info(n)), names), strict=True) if ok]
    open(argv[2], "w").write("\n".join(kept) + "\n")
    print(len(names), "->", len(kept))


if __name__ == "__main__":
    main(sys.argv)
