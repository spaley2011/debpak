"""Finding Linux builds of an Electron app's Windows native modules (natives.py).

A fake npm registry and GitHub answer the downloads with real tarballs, so
each strategy runs end to end: the conversion in bundle mode, and the same
files reached through extra-data mode's install-time replay.
"""
import base64
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from unittest import mock

from debpak import electron, natives
from debpak.asar import Asar
from test_foreign import SUMS, Base, dll_bytes, electron_win_folder, tree

ELF64 = b"\x7fELF\x02\x01\x01" + bytes(9) + b"\x03\x00\x3e\x00" + bytes(44)       # x86-64 shared object
ELF_ARM = b"\x7fELF\x02\x01\x01" + bytes(9) + b"\x03\x00\xb7\x00" + bytes(44)     # aarch64


def tgz(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class FakeNet:
    """npm registry + GitHub + Electron's release list, served from dicts."""
    def __init__(self):
        self.urls: dict[str, bytes] = {
            "https://github.com/electron/electron/releases/download/v30.1.2/SHASUMS256.txt":
                "".join(f"{h} *{n}\n" for n, h in SUMS.items()).encode(),
            electron.RELEASE_LIST: json.dumps([{"version": "30.1.2", "chrome": "124.0.6367.243",
                                               "modules": "123"}]).encode(),
        }
        self.seen: list[str] = []

    def npm(self, name: str, version: str, files: dict[str, bytes], bad_integrity=False):
        blob = tgz(files)
        url = f"https://registry.npmjs.org/{name}/-/{name.split('/')[-1]}-{version}.tgz"
        digest = base64.b64encode(hashlib.sha512(blob + (b"x" if bad_integrity else b"")).digest()).decode()
        from urllib.parse import quote
        self.urls[f"{natives.NPM}/{quote(name, safe='@')}/{version}"] = json.dumps(
            {"name": name, "version": version, "dist": {"tarball": url, "integrity": "sha512-" + digest}}).encode()
        self.urls[url] = blob

    def __call__(self, url: str) -> bytes:
        self.seen.append(url)
        if url in self.urls:
            return self.urls[url]
        raise OSError(f"404 {url}")


class NativeTests(Base):
    def setUp(self):
        super().setUp()
        self.net = FakeNet()
        for mod in (electron, natives):
            p = mock.patch.object(mod, "fetch", self.net)
            p.start()
            self.addCleanup(p.stop)

    def app(self, natives_in_asar: dict, unpacked=(), extra_pj: dict | None = None) -> Path:
        files = {}
        for path, data in natives_in_asar.items():
            files[path] = data
        for pj_path, pj in (extra_pj or {}).items():
            files[pj_path] = json.dumps(pj).encode()
        return electron_win_folder(self.tmp / "app", files, unpacked=set(unpacked))

    def test_sibling_package_with_its_dependency(self):
        src = self.app({"node_modules/@img/sharp-win32-x64/lib/sharp-win32-x64.node": dll_bytes()},
                       extra_pj={"node_modules/@img/sharp-win32-x64/package.json":
                                 {"name": "@img/sharp-win32-x64", "version": "0.34.1"}})
        self.net.npm("@img/sharp-linux-x64", "0.34.1", {
            "package/package.json": json.dumps({"name": "@img/sharp-linux-x64", "version": "0.34.1",
                                                "optionalDependencies": {"@img/sharp-libvips-linux-x64": "1.2.0"}
                                                }).encode(),
            "package/lib/sharp-linux-x64.node": ELF64})
        self.net.npm("@img/sharp-libvips-linux-x64", "1.2.0", {
            "package/package.json": b'{"name": "@img/sharp-libvips-linux-x64"}',
            "package/lib/libvips-cpp.so.8.17.0": ELF64})
        code, text, out = self.convert(src)
        self.assertEqual(code, 0, text)
        self.assertIn("added @img/sharp-linux-x64@0.34.1 from npm (2 files, npm registry SHA-512)", text)
        self.assertIn("added @img/sharp-libvips-linux-x64@1.2.0", text)
        a = Asar(out / "app/resources/app.asar")
        self.assertEqual(a.read("node_modules/@img/sharp-linux-x64/lib/sharp-linux-x64.node"), ELF64)
        self.assertEqual(a.read("node_modules/@img/sharp-libvips-linux-x64/lib/libvips-cpp.so.8.17.0"), ELF64)
        self.assertEqual(json.loads(a.read("package.json"))["name"], "acme-notes")

    def test_sibling_with_a_libc_suffix(self):
        # @parcel/watcher publishes watcher-linux-x64-glibc and -musl, not watcher-linux-x64
        src = self.app({"node_modules/@parcel/watcher-win32-x64/watcher.node": dll_bytes()},
                       extra_pj={"node_modules/@parcel/watcher-win32-x64/package.json":
                                 {"name": "@parcel/watcher-win32-x64", "version": "2.5.1"}})
        self.net.npm("@parcel/watcher-linux-x64-glibc", "2.5.1", {
            "package/package.json": b'{"name": "@parcel/watcher-linux-x64-glibc"}',
            "package/watcher.node": ELF64})
        code, text, out = self.convert(src)
        self.assertEqual(code, 0, text)
        self.assertIn("added @parcel/watcher-linux-x64-glibc@2.5.1 from npm", text)
        a = Asar(out / "app/resources/app.asar")
        self.assertEqual(a.read("node_modules/@parcel/watcher-linux-x64-glibc/watcher.node"), ELF64)
        lookups = [u for u in self.net.seen if u.startswith(natives.NPM) and u.endswith("/2.5.1")]
        self.assertEqual(lookups, [f"{natives.NPM}/@parcel%2Fwatcher-linux-x64{s}/2.5.1"
                                   for s in ("", "-gnu", "-glibc")])

    def test_prebuilds_from_the_npm_tarball(self):
        src = self.app({"node_modules/classic-level/prebuilds/win32-x64/node.napi.node": dll_bytes(),
                        "node_modules/classic-level/prebuilds/win32-x64/other.node": dll_bytes()},
                       extra_pj={"node_modules/classic-level/package.json": {"name": "classic-level",
                                                                             "version": "1.4.1"}})
        self.net.npm("classic-level", "1.4.1", {"package/prebuilds/linux-x64/node.napi.glibc.node": ELF64,
                                                "package/prebuilds/darwin-x64/node.napi.node": b"x"})
        code, text, out = self.convert(src)
        self.assertEqual(code, 0, text)
        self.assertEqual(text.count("added prebuilds/linux-x64"), 1)       # once per package
        a = Asar(out / "app/resources/app.asar")
        self.assertEqual(a.read("node_modules/classic-level/prebuilds/linux-x64/node.napi.glibc.node"), ELF64)
        self.assertIsNone(a.entry("node_modules/classic-level/prebuilds/darwin-x64/node.napi.node"))

    def sqlite_app(self):
        return self.app({"node_modules/better-sqlite3/build/Release/better_sqlite3.node": dll_bytes()},
                        extra_pj={"node_modules/better-sqlite3/package.json": {
                            "name": "better-sqlite3", "version": "11.0.0",
                            "repository": {"url": "git+https://github.com/WiseLibs/better-sqlite3.git"}}})

    def test_prebuild_release_asset_and_extra_data_replay(self):
        src = self.sqlite_app()
        asset = ("https://github.com/WiseLibs/better-sqlite3/releases/download/v11.0.0/"
                 "better-sqlite3-v11.0.0-electron-v123-linux-x64.tar.gz")
        self.net.urls[asset] = tgz({"build/Release/better_sqlite3.node": ELF64})
        code, text, out = self.convert(src)
        self.assertEqual(code, 0, text)
        self.assertIn("no published checksum (GitHub release asset)", text)
        a = Asar(out / "app/resources/app.asar")
        e = a.entry("node_modules/better-sqlite3/build/Release/better_sqlite3.node")
        self.assertTrue(e["unpacked"])
        self.assertEqual(e["size"], len(ELF64))
        bundle = tree(out / "app/resources")

        # extra-data: the asset becomes a pinned source; the replay gives the same files
        zipped = self.tmp / "app.zip"
        shutil.make_archive(str(zipped.with_suffix("")), "zip", src)
        code, text, xout = self.convert(zipped, "--mode", "extra-data", "--url", "https://acme.example/app.zip")
        self.assertEqual(code, 0, text)
        m = json.loads(next(p for p in xout.glob("*.json") if p.name != "report.json").read_text())
        app_mod = m["modules"][-1]
        archive = [s for s in app_mod["sources"] if s["type"] == "archive"]
        self.assertEqual([(s["url"], s["dest"]) for s in archive], [(asset, "natives-src/0")])
        self.assertEqual(archive[0]["sha256"], hashlib.sha256(self.net.urls[asset]).hexdigest())
        self.assertFalse(list((xout / "app").rglob("*.node")))     # nothing binary carried in the Flatpak
        plan = json.loads((xout / "app/share/debpak/unpack.json").read_text())
        fake_app = self.tmp / "fake-app"                            # what flatpak-builder would unpack
        with tarfile.open(fileobj=io.BytesIO(self.net.urls[asset])) as t:
            t.extractall(fake_app / "share/debpak/natives-src/0", filter="data")
        for n in plan["natives"]:
            n["from"] = str(fake_app / n["from"].removeprefix("/app/"))
        cwd = self.tmp / "extra"
        cwd.mkdir()
        shutil.copy2(zipped, cwd / plan["source"])
        (self.tmp / "plan.json").write_text(json.dumps(plan))
        r = subprocess.run([sys.executable, str(xout / "app/bin/debpak-unpack"), str(self.tmp / "plan.json")],
                           cwd=cwd, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(tree(cwd / "resources"), bundle)

    def test_node_pre_gyp(self):
        src = self.app({"node_modules/sqlite3/lib/binding/napi-v6-win32-unknown-x64/node_sqlite3.node": dll_bytes()},
                       extra_pj={"node_modules/sqlite3/package.json": {
                           "name": "sqlite3", "version": "5.1.7",
                           "binary": {"module_name": "node_sqlite3",
                                      "module_path": "./lib/binding/{node_abi}-{platform}-{arch}",
                                      "host": "https://mapbox-node-binary.s3.amazonaws.com",
                                      "remote_path": "./{name}/v{version}/",
                                      "package_name": "{module_name}-v{version}-{node_abi}-{platform}-{arch}.tar.gz"}}})
        url = ("https://mapbox-node-binary.s3.amazonaws.com/sqlite3/v5.1.7/"
               "node_sqlite3-v5.1.7-electron-v30.1-linux-x64.tar.gz")
        self.net.urls[url] = tgz({"electron-v30.1-linux-x64/node_sqlite3.node": ELF64})
        code, text, out = self.convert(src)
        self.assertEqual(code, 0, text)
        self.assertIn(url, self.net.seen)
        self.assertIn("no published checksum (node-pre-gyp download)", text)
        a = Asar(out / "app/resources/app.asar")      # where node-pre-gyp looks on Linux
        self.assertEqual(a.read("node_modules/sqlite3/lib/binding/electron-v30.1-linux-x64/node_sqlite3.node"),
                         ELF64)

    def test_failures_block_with_what_was_tried(self):
        src = self.sqlite_app()
        code, text, _ = self.convert(src)
        self.assertEqual(code, 2)
        self.assertIn("no Linux build was found (prebuild release asset: better-sqlite3-v11.0.0-electron-v123-"
                      "linux-x64.tar.gz: 404", text)
        self.assertIn("node-pre-gyp download: not applicable", text)
        asset = ("https://github.com/WiseLibs/better-sqlite3/releases/download/v11.0.0/"
                 "better-sqlite3-v11.0.0-electron-v123-linux-x64.tar.gz")
        self.net.urls[asset] = tgz({"build/Release/better_sqlite3.node": ELF_ARM})
        code, text, _ = self.convert(src)
        self.assertEqual(code, 2)
        self.assertIn("has no x86-64 Linux better_sqlite3.node", text)
        self.net.urls[asset] = tgz({"build/Release/better_sqlite3.node": ELF64})
        code, text, _ = self.convert(src, "--no-fetch-natives")
        self.assertEqual(code, 2)
        self.assertIn("looking online is turned off", text)

    def test_bad_integrity_is_refused(self):
        src = self.app({"node_modules/classic-level/prebuilds/win32-x64/node.napi.node": dll_bytes()},
                       extra_pj={"node_modules/classic-level/package.json": {"name": "classic-level",
                                                                             "version": "1.4.1"}})
        self.net.npm("classic-level", "1.4.1", {"package/prebuilds/linux-x64/node.napi.node": ELF64},
                     bad_integrity=True)
        code, text, _ = self.convert(src)
        self.assertEqual(code, 2)
        self.assertIn("doesn't match the registry's SHA-512", text)

    def test_hostile_dependency_names_are_refused(self):
        src = self.app({"node_modules/@img/sharp-win32-x64/lib/sharp-win32-x64.node": dll_bytes()},
                       extra_pj={"node_modules/@img/sharp-win32-x64/package.json":
                                 {"name": "@img/sharp-win32-x64", "version": "0.34.1"}})
        self.net.npm("@img/sharp-linux-x64", "0.34.1", {
            "package/package.json": json.dumps({"optionalDependencies": {"../../../../escape-linux-x64": "1.0.0"}
                                                }).encode(),
            "package/lib/sharp-linux-x64.node": ELF64})
        code, text, out = self.convert(src)
        self.assertIn("not a valid npm package: '../../../../escape-linux-x64'", text)
        self.assertFalse(list(self.tmp.rglob("escape-linux-x64")))

    def test_helpers(self):
        self.assertTrue(natives.is_linux_x64(ELF64))
        self.assertFalse(natives.is_linux_x64(ELF_ARM))
        self.assertFalse(natives.is_linux_x64(dll_bytes()))
        self.assertEqual(natives.package_of("app.asar/node_modules/a/node_modules/@s/b/x.node"),
                         ("@s/b", "app.asar/node_modules/a/node_modules/@s/b"))
        self.assertIsNone(natives.package_of("app.asar/build/x.node"))
        self.assertEqual(natives._repo_url({"repository": "owner/name"}), "https://github.com/owner/name")
        self.assertEqual(natives._repo_url({"repository": {"url": "git@github.com:o/n.git"}}),
                         "https://github.com/o/n")
        self.assertEqual(natives.electron_abi("30.1.2", [{"version": "30.1.2", "modules": "123"}]), "123")
        members = natives._tgz_members(tgz({"../evil": b"x", "./ok/a": b"y", "/abs": b"z"}))
        self.assertEqual(members, {"ok/a": b"y"})
