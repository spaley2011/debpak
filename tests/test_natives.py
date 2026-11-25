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
import urllib.request
from pathlib import Path
from unittest import mock

from debpak import electron, natives
from debpak.asar import Asar
from test_foreign import SUMS, Base, dll_bytes, electron_win_folder, tree

ELF64 = b"\x7fELF\x02\x01\x01" + bytes(9) + b"\x03\x00\x3e\x00" + bytes(44)       # x86-64 shared object
ELF_ARM = b"\x7fELF\x02\x01\x01" + bytes(9) + b"\x03\x00\xb7\x00" + bytes(44)     # aarch64


def elf_so(imports=(), needed=()) -> bytes:
    """An x86-64 shared object with a dynamic symbol table (imports) and DT_NEEDED entries."""
    import struct
    strtab = b"\0"
    offs = {}
    for name in [*imports, *needed]:
        offs[name] = len(strtab)
        strtab += name.encode() + b"\0"
    dynsym = bytes(24) + b"".join(struct.pack("<IBBHQQ", offs[n], 0x12, 0, 0, 0, 0) for n in imports)
    dynamic = b"".join(struct.pack("<qQ", 1, offs[n]) for n in needed) + struct.pack("<qQ", 0, 0)
    body_off = 64
    str_off, sym_off = body_off, body_off + len(strtab)
    dyn_off = sym_off + len(dynsym)
    sh_off = dyn_off + len(dynamic)
    head = b"\x7fELF\x02\x01\x01" + bytes(9) + struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0, 0, sh_off, 0, 64,
                                                             56, 0, 64, 4, 0)

    def sh(kind, off, size, link=0, entsize=0):
        return struct.pack("<IIQQQQIIQQ", 0, kind, 0, 0, off, size, link, 0, 8, entsize)
    sections = bytes(64) + sh(3, str_off, len(strtab)) + sh(11, sym_off, len(dynsym), 1, 24) + \
        sh(6, dyn_off, len(dynamic), 1, 16)
    return head + strtab + dynsym + dynamic + sections


NAPI_SO = elf_so(["napi_create_function", "napi_define_properties"], ["libc.so.6", "libstdc++.so.6"])
V8_SO = elf_so(["_ZN2v87Isolate10GetCurrentEv", "node_module_register"], ["libc.so.6"])


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

    def test_linux_twin_from_the_npm_tarball(self):
        # Motion's Windows build kept only Koffi's build/koffi/win32_x64; Koffi's npm tarball has a
        # build for every platform, and on Linux it loads build/koffi/linux_x64/koffi.node
        src = self.app({"node_modules/koffi/build/koffi/win32_x64/koffi.node": dll_bytes(),
                        "node_modules/xxhash-addon/bin/win32-x64-123/xxhash-addon.node": dll_bytes()},
                       extra_pj={"node_modules/koffi/package.json": {"name": "koffi", "version": "2.9.0"},
                                 "node_modules/xxhash-addon/package.json": {"name": "xxhash-addon",
                                                                            "version": "2.1.0"}})
        self.net.npm("koffi", "2.9.0", {"package/build/koffi/linux_x64/koffi.node": NAPI_SO,
                                        "package/build/koffi/darwin_arm64/koffi.node": b"x"})
        # not N-API, but built for this Electron's ABI (123), which its path names as the app's copy's does
        self.net.npm("xxhash-addon", "2.1.0", {"package/bin/linux-x64-123/xxhash-addon.node": V8_SO})
        code, text, out = self.convert(src)
        self.assertEqual(code, 0, text)
        self.assertIn("koffi: added build/koffi/linux_x64/koffi.node from its npm tarball", text)
        a = Asar(out / "app/resources/app.asar")
        self.assertEqual(a.read("node_modules/koffi/build/koffi/linux_x64/koffi.node"), NAPI_SO)
        self.assertEqual(a.read("node_modules/xxhash-addon/bin/linux-x64-123/xxhash-addon.node"), V8_SO)
        self.assertEqual(natives.twin_paths("build/Release/addon.node"), [])
        self.assertEqual(natives.twin_paths("prebuilds/darwin-arm64/pty.node"), ["prebuilds/linux-x64/pty.node"])

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

    def test_downloads_identify_as_debpak(self):
        # Notion's CDN refuses Python-urllib's User-Agent with 403
        from debpak import net
        seen = []
        with mock.patch("urllib.request.urlopen", lambda req, timeout: seen.append(req) or io.BytesIO(b"x")):
            net.urlopen("https://example.com/a")
            net.urlopen(urllib.request.Request("https://example.com/b", headers={"User-Agent": "custom"}))
        self.assertEqual(seen[0].get_header("User-agent"), net.USER_AGENT)
        self.assertTrue(net.USER_AGENT.startswith("debpak/"))
        self.assertEqual(seen[1].get_header("User-agent"), "custom")

    def test_extra_data_urls_are_encoded(self):
        from debpak.net import quote_url
        self.assertEqual(quote_url("http://h:8/Debpak Hello Setup 1.0.exe"), "http://h:8/Debpak%20Hello%20Setup%201.0.exe")
        done = "https://desktop-release.notion-static.com/Notion%20Setup%207.44.1.exe?x=1&y=a+b#f"
        self.assertEqual(quote_url(done), done)

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


SQLITE_GYP = b"""{
  'includes': ['deps/common.gypi'],
  'targets': [
    {'target_name': 'better_sqlite3', 'sources': ['src/better_sqlite3.cpp'],
     'include_dirs': ["<!@(node -p \\"require('node-addon-api').include\\")"]},
    {'target_name': 'test_extension', 'sources': ['deps/test_extension.c']},
  ],
}"""


class WindowsOnlyAndBuildTests(NativeTests):
    """Windows-only modules (natives.windows_only), N-API builds from npm tarballs, and builds from source."""

    def test_windows_only_evidence(self):
        wo = natives.windows_only
        self.assertIn("so npm installs it only on Windows", wo("app.asar/node_modules/x/build/Release/x.node",
                                                                {"os": ["win32"]}))
        self.assertIsNotNone(wo("app.asar/node_modules/x/x.node", {"os": ["!linux", "!darwin"]}))
        # Windows and macOS: an app shipping for both may load it unconditionally
        self.assertIsNone(wo("app.asar/node_modules/x/x.node", {"os": ["darwin", "win32"]}))
        self.assertIsNone(wo("app.asar/node_modules/x/x.node", {"os": ["linux", "win32"]}))
        self.assertIn("win_utils, says it's for Windows",
                      wo("app.asar/node_modules/@notionhq/desktop-native/build/Release/win_utils.node", {}))
        self.assertIn("says it's for Windows", wo("app/windows-argv-parser.node", {}))
        self.assertEqual(wo("app/copilot/prebuilds/win32-x64/dpapi.node", {}), "dpapi is a Windows-only API")
        for rel in ("app.asar/bindings.node",                                   # Figma's own module
                    "app.asar/node_modules/@ant/claude-native/claude-native-binding.node",
                    "app.asar/node_modules/classic-level/prebuilds/win32-x64/node.napi.node",
                    "app.asar/node_modules/better-sqlite3/prebuilds/win32-x64.node",
                    "app.asar/node_modules/@img/sharp-win32-x64/lib/sharp-win32-x64.node",
                    "app/registry.node", "app/winston.node", "app/darwin_utils.node"):
            self.assertIsNone(wo(rel, {}), rel)

    def test_windows_only_modules_are_notes(self):
        src = self.app({"node_modules/@notionhq/desktop-native/build/Release/win_utils.node": dll_bytes(),
                        "node_modules/taskbar/build/Release/taskbar.node": dll_bytes(),
                        "copilot/prebuilds/win32-x64/dpapi.node": dll_bytes()},
                       extra_pj={"node_modules/taskbar/package.json": {"name": "taskbar", "version": "1.0.0",
                                                                       "os": ["win32"]}})
        code, text, _ = self.convert(src)
        self.assertEqual(code, 0, text)
        self.assertIn("win_utils.node is Windows-only (its file name, win_utils, says it's for Windows)", text)
        self.assertIn('taskbar.node is Windows-only (its package.json says "os": ["win32"]', text)
        self.assertIn("dpapi.node is Windows-only (dpapi is a Windows-only API)", text)

    def test_skipped_on_linux_evidence(self):
        sol = natives.skipped_on_linux
        rel = "app.asar/bindings.node"
        # Figma: the test sits in a variable, and the stub branch comes first
        figma = ('var TC=process.platform==="linux"||process.env.NODE_ENV==="test";function Rrt(){return{}}'
                 'var _e=TC?Rrt():app.isPackaged?require("./bindings.node"):require("../build/Release/bindings.node");')
        self.assertEqual(sol(rel, [("app.asar/main.js", figma)]), "app.asar/main.js checks for Linux before loading it")
        worker = 'var O=_(()=>{if(process.platform==="linux")return{};try{return require("./bindings.node")}catch{}});'
        self.assertEqual(sol(rel, [("app.asar/main.js", figma), ("app.asar/worker.js", worker)]),
                         "app.asar/main.js and app.asar/worker.js check for Linux before loading it")
        self.assertIsNotNone(sol(rel, [("a.js", "const isLinux = 'linux' === process.platform;\n"
                                                 "module.exports = isLinux ? {} : require(`./bindings.node`);")]))
        # an unguarded load anywhere, a test too far away, or no script naming the file: no evidence
        self.assertIsNone(sol(rel, [("app.asar/main.js", figma), ("b.js", 'require("./bindings.node")')]))
        far = 'if(process.platform==="linux")x();' + "y();" * 200 + 'require("./bindings.node")'
        self.assertIsNone(sol(rel, [("c.js", far)]))
        self.assertIsNone(sol(rel, [("d.js", 'module.exports=require("bindings")("bindings")')]))
        # another file whose name only ends the same way doesn't count as a reference
        self.assertIsNone(sol(rel, [("e.js", 'TC=process.platform==="linux";require("./my-bindings.node")')]))

    def test_module_the_app_skips_on_linux_is_a_note(self):
        main = (b'var TC=process.platform==="linux";'
                b'var _e=TC?{}:require("./bindings.node");')
        src = self.app({"main.js": main, "bindings.node": dll_bytes()})
        code, text, _ = self.convert(src)
        self.assertEqual(code, 0, text)
        self.assertIn("native module app.asar/bindings.node is built for Windows and has no Linux build, but the app "
                      "doesn't load it on Linux (app.asar/main.js checks for Linux before loading it)",
                      " ".join(text.split()))

    def test_no_evidence_still_blocks(self):
        src = self.app({"bindings.node": dll_bytes(),
                        "node_modules/@ant/claude-native/claude-native-binding.node": dll_bytes(),
                        "copilot/prebuilds/win32-x64/runtime.node": dll_bytes()},
                       extra_pj={"node_modules/@ant/claude-native/package.json": {
                           "name": "@ant/claude-native", "version": "1.0.0", "os": ["darwin", "win32"]}})
        code, text, _ = self.convert(src)
        self.assertEqual(code, 2, text)
        for rel in ("app.asar/bindings.node", "claude-native/claude-native-binding.node",
                    "copilot/prebuilds/win32-x64/runtime.node"):
            self.assertRegex(text, rf"native module \S*{rel} is built for Windows")

    def napi_sqlite(self, extra=None):
        src = self.app({"node_modules/better-sqlite3/build/Release/better_sqlite3.node": dll_bytes()},
                       extra_pj={"node_modules/better-sqlite3/package.json": {
                           "name": "better-sqlite3", "version": "13.0.1",
                           "repository": {"url": "git://github.com/WiseLibs/better-sqlite3.git"}}})
        self.net.npm("better-sqlite3", "13.0.1", {"package/binding.gyp": SQLITE_GYP,
                                                  "package/prebuilds/linux-x64.node": NAPI_SO,
                                                  "package/prebuilds/linuxmusl-x64.node": NAPI_SO + b"m",
                                                  "package/prebuilds/linux-arm64.node": ELF_ARM,
                                                  "package/prebuilds/win32-x64.node": dll_bytes(), **(extra or {})})
        return src

    def test_napi_build_from_the_npm_tarball(self):
        # better-sqlite3 13: N-API, prebuilds/linux-x64.node in the npm tarball, no electron-vABI assets
        src = self.napi_sqlite()
        code, text, out = self.convert(src)
        self.assertEqual(code, 0, text)
        self.assertIn("better-sqlite3-v13.0.1-electron-v123-linux-x64.tar.gz", "".join(self.net.seen))
        self.assertIn("Linux build from better-sqlite3@13.0.1's npm tarball (prebuilds/linux-x64.node, N-API, "
                      "npm registry SHA-512)\n", text)
        a = Asar(out / "app/resources/app.asar")
        e = a.entry("node_modules/better-sqlite3/build/Release/better_sqlite3.node")
        self.assertTrue(e["unpacked"])
        self.assertEqual(a.read("node_modules/better-sqlite3/build/Release/better_sqlite3.node"), NAPI_SO)
        self.assertNotIn("sdk-extensions", self.manifest(out))

    def test_v8_build_in_the_tarball_is_not_used(self):
        self.napi_sqlite({"package/prebuilds/linux-x64.node": V8_SO})
        r = natives.Resolver(lambda d: {"version": "13.0.1"}, "30.1.2", "123")
        with self.assertRaisesRegex(ValueError, "neither N-API nor for Electron ABI 123"):
            r.npm_prebuild("app.asar/node_modules/better-sqlite3/build/Release/better_sqlite3.node",
                           "better-sqlite3", "app.asar/node_modules/better-sqlite3")
        self.assertEqual(natives.abi_kind(V8_SO), "v8")
        self.assertEqual(natives.abi_kind(NAPI_SO), "napi")
        self.assertEqual(natives.abi_kind(ELF64), "unknown")

    def test_wrong_target_is_not_replaced(self):
        self.napi_sqlite()
        r = natives.Resolver(lambda d: {"version": "13.0.1"}, "30.1.2", "123")
        with self.assertRaisesRegex(ValueError, "doesn't build other.node"):
            r.npm_prebuild("app.asar/node_modules/better-sqlite3/build/Release/other.node", "better-sqlite3",
                           "app.asar/node_modules/better-sqlite3")
        with self.assertRaisesRegex(ValueError, "can't tell that"):
            r.npm_prebuild("app.asar/node_modules/better-sqlite3/build/Release/test_extension.node",
                           "better-sqlite3", "app.asar/node_modules/better-sqlite3")

    def progress_bar(self):
        gyp = b"""{"targets": [{"target_name": "progress_bar", "conditions": [['OS=="linux"', {
            "cflags": ["<!@(pkg-config --cflags gtk4 libadwaita-1)"]}]]}]}"""
        self.net.npm("@jasonscheirer/native-progress-bar", "1.1.2", {
            "package/binding.gyp": gyp,
            "package/prebuilds/linux-x64/@jasonscheirer+native-progress-bar.node":
                elf_so(["napi_create_object"], ["libgtk-4.so.1", "libadwaita-1.so.0", "libc.so.6"]),
            "package/prebuilds/win32-x64/@jasonscheirer+native-progress-bar.node": dll_bytes()})
        return self.app({"node_modules/@jasonscheirer/native-progress-bar/build/Release/progress_bar.node":
                         dll_bytes()},
                        extra_pj={"node_modules/@jasonscheirer/native-progress-bar/package.json": {
                            "name": "@jasonscheirer/native-progress-bar", "version": "1.1.2"}})

    def test_linux_build_missing_a_runtime_library_blocks(self):
        # cross-platform, not Windows-only: its Linux build links GTK 4 and libadwaita (Notion), so the
        # app moves to the GNOME runtime on the same freedesktop base
        src = self.progress_bar()
        code, text, out = self.convert(src)
        self.assertEqual(code, 0, text)
        self.assertIn("so the app runs on org.gnome.Platform//49, which is built on org.freedesktop.Platform//25.08",
                      text)
        m = self.manifest(out)
        self.assertEqual((m["runtime"], m["runtime-version"], m["sdk"], m["base-version"]),
                         ("org.gnome.Platform", "49", "org.gnome.Sdk", "25.08"))
        # with the runtime chosen by hand, it stays blocked and says why
        code, text, _ = self.convert(src, "--runtime", "org.freedesktop.Platform//25.08")
        self.assertEqual(code, 2, text)
        self.assertIn("needs libadwaita-1.so.0, which org.freedesktop.Platform doesn't have "
                      "(org.gnome.Platform does)", text)
        self.assertIn("binding.gyp runs 'pkg-config --cflags gtk4 libadwaita-1' at build time", text)
        r = natives.Resolver(lambda d: {"version": "1.1.2"}, "30.1.2", "123", runtime="org.gnome.Platform")
        pkg = "app.asar/node_modules/@jasonscheirer/native-progress-bar"
        self.assertTrue(r.npm_prebuild(f"{pkg}/build/Release/progress_bar.node",
                                       "@jasonscheirer/native-progress-bar", pkg))
        self.assertIn("it links libgtk-4.so.1, libadwaita-1.so.0", r.res.notes[0])

    def v8_sqlite(self):
        gyp = SQLITE_GYP.replace(b"<!@(node -p \\\"require('node-addon-api').include\\\")",
                                 b"<!(node -p \\\"require('nan')\\\")")
        self.net.npm("better-sqlite3", "12.4.1", {
            "package/binding.gyp": gyp,
            "package/deps/sqlite3.gyp": b"{'targets': [{'target_name': 'sqlite3', 'actions': [{'action': "
                                        b"['node', 'copy.js', '<(SHARED_INTERMEDIATE_DIR)/sqlite3', '']}]}]}",
            "package/src/better_sqlite3.cpp": b"//"})
        self.net.npm("nan", "2.22.0", {"package/nan.h": b"//"})
        sums = "".join(f"{'%064x' % i}  {n}\n" for i, n in enumerate(
            ["node-v30.1.2.tar.gz", "node-v30.1.2-headers.tar.gz", "x64/node.lib"]))
        self.net.urls[f"{natives.HEADERS}/v30.1.2/SHASUMS256.txt"] = sums.encode()
        return self.app({"node_modules/better-sqlite3/build/Release/better_sqlite3.node": dll_bytes()},
                        extra_pj={"node_modules/better-sqlite3/package.json": {
                            "name": "better-sqlite3", "version": "12.4.1",
                            "repository": {"url": "git+https://github.com/WiseLibs/better-sqlite3.git"}},
                            "node_modules/nan/package.json": {"name": "nan", "version": "2.22.0"}})

    def test_build_from_source(self):
        # better-sqlite3 12 is written against V8; no electron-v123 asset, no Linux build in the tarball
        src = self.v8_sqlite()
        code, text, out = self.convert(src)
        self.assertEqual(code, 0, text)
        self.assertIn("flatpak-builder builds better-sqlite3@12.4.1 from its npm tarball (npm registry SHA-512) "
                      "against Electron's headers", text)
        m = self.manifest(out)
        self.assertEqual(m["sdk-extensions"], [natives.NODE_SDK])
        self.assertEqual(m["x-debpak"]["native-builds"], ["better-sqlite3@12.4.1"])
        mod = m["modules"][0]
        self.assertEqual((mod["name"], mod["subdir"], mod["build-options"]),
                         ("native-0-better-sqlite3", "package", {"append-path": "/usr/lib/sdk/node24/bin"}))
        tarball = "https://registry.npmjs.org/better-sqlite3/-/better-sqlite3-12.4.1.tgz"
        self.assertEqual(mod["sources"], [
            {"type": "archive", "url": tarball, "sha256": hashlib.sha256(self.net.urls[tarball]).hexdigest(),
             "dest": "package"},
            {"type": "archive", "url": "https://registry.npmjs.org/nan/-/nan-2.22.0.tgz",
             "sha256": hashlib.sha256(self.net.urls["https://registry.npmjs.org/nan/-/nan-2.22.0.tgz"]).hexdigest(),
             "dest": "package/node_modules/nan"},
            {"type": "archive", "url": f"{natives.HEADERS}/v30.1.2/node-v30.1.2-headers.tar.gz",
             "sha256": "%064x" % 1, "dest": "electron-headers"}])
        self.assertIn(f"node {natives.NODE_GYP} rebuild --release", mod["build-commands"][0])
        self.assertIn('--nodedir="$PWD/../electron-headers"', mod["build-commands"][0])
        self.assertEqual(mod["build-commands"][1], "install -Dm755 build/Release/better_sqlite3.node "
                         "${FLATPAK_DEST}/share/debpak/natives-built/0/better_sqlite3.node")
        self.assertEqual([x["name"] for x in m["modules"][1:]], ["electron", "acme-notes"])
        self.assertIn("install -Dm755 /app/share/debpak/natives-built/0/better_sqlite3.node ${FLATPAK_DEST}/lib/"
                      "acme-notes/resources/app.asar.unpacked/node_modules/better-sqlite3/build/Release/"
                      "better_sqlite3.node", m["modules"][-1]["build-commands"])
        a = Asar(out / "app/resources/app.asar")
        self.assertTrue(a.entry("node_modules/better-sqlite3/build/Release/better_sqlite3.node")["unpacked"])

        # extra-data: apply_extra copies the built file into place
        zipped = self.tmp / "app.zip"
        shutil.make_archive(str(zipped.with_suffix("")), "zip", src)
        code, text, xout = self.convert(zipped, "--mode", "extra-data", "--url", "https://acme.example/app.zip")
        self.assertEqual(code, 0, text)
        plan = json.loads((xout / "app/share/debpak/unpack.json").read_text())
        self.assertEqual(plan["natives"], [{
            "from": "/app/share/debpak/natives-built/0/better_sqlite3.node",
            "to": "app.asar.unpacked/node_modules/better-sqlite3/build/Release/better_sqlite3.node",
            "asar_unpack": "node_modules/better-sqlite3/build/Release/better_sqlite3.node"}])
        self.assertEqual(self.manifest(xout)["modules"][0]["name"], "native-0-better-sqlite3")

    def test_source_build_for_a_prebuilds_folder(self):
        # ComfyUI's node-pty 1.1.0 ships prebuilds for Mac and Windows only; on Linux it loads
        # prebuilds/linux-x64/pty.node, which is where the build goes
        self.v8_sqlite()            # Electron 30.1.2's headers
        self.net.npm("node-pty", "1.1.0", {"package/binding.gyp": b"{'targets': [{'target_name': 'pty'}]}",
                                           "package/src/unix/pty.cc": b"//",
                                           # only Windows builds it, so its Windows command doesn't count
                                           "package/deps/winpty/src/winpty.gyp":
                                               b"{'variables': {'h': '<!(cmd /c \"cd shared && GetCommitHash.bat\")'}}"})
        pkg = "app.asar/node_modules/node-pty"
        r = natives.Resolver(lambda d: {"version": "1.1.0"} if d == pkg else {}, "30.1.2", "123")
        self.assertTrue(r.source_build(f"{pkg}/prebuilds/darwin-arm64/pty.node", "node-pty", pkg))
        f = r.res.files[-1]
        self.assertEqual((f.to, f.new, f.built), ("app.asar.unpacked/node_modules/node-pty/prebuilds/linux-x64/"
                                                  "pty.node", True, 0))
        # the package's Windows builds (conpty.node) then don't block
        self.assertTrue(r.resolve(f"{pkg}/prebuilds/win32-x64/conpty.node"))
        # Evernote's @ronomon/opened keeps binding.node at its top: the build goes in its place
        self.net.npm("@ronomon/opened", "1.5.2", {"package/binding.gyp": b"{'targets': [{'target_name': 'binding'}]}",
                                                  "package/binding.c": b"//"})
        opened = "app.asar/node_modules/@ronomon/opened"
        r = natives.Resolver(lambda d: {"version": "1.5.2"} if d == opened else {}, "30.1.2", "123")
        self.assertTrue(r.source_build(f"{opened}/binding.node", "@ronomon/opened", opened))
        f = r.res.files[-1]
        self.assertEqual((f.to, f.new), ("app.asar.unpacked/node_modules/@ronomon/opened/binding.node", False))

    def test_source_build_refusals(self):
        self.v8_sqlite()
        pkg = "app.asar/node_modules/better-sqlite3"
        r = natives.Resolver(lambda d: {"version": "12.4.1"} if d == pkg else {}, "30.1.2", "123")
        with self.assertRaisesRegex(ValueError, "needs nan to build, which the app doesn't include"):
            r.source_build(f"{pkg}/build/Release/better_sqlite3.node", "better-sqlite3", pkg)
        with self.assertRaisesRegex(ValueError, "isn't better-sqlite3's own file"):
            r.source_build(f"{pkg}/node_modules/x/better_sqlite3.node", "better-sqlite3", pkg)
        self.assertFalse(natives.Resolver(lambda d: {"version": "12.4.1"}, "0.0.0", None).source_build(
            f"{pkg}/build/Release/better_sqlite3.node", "better-sqlite3", pkg))
        self.assertEqual(natives._dep_dirs("app.asar/node_modules/a/node_modules/b", "nan"),
                         ["app.asar/node_modules/a/node_modules/b/node_modules/nan",
                          "app.asar/node_modules/a/node_modules/nan", "app.asar/node_modules/nan"])
        self.assertIsNone(natives.gyp_commands("{'x': '<!(echo a'}"))
        # node-pty 1.1: a command with text after it, and one inside a string with escaped quotes
        gyp = ("""{'dependencies': ["<!(node -p \\"require('node-addon-api').targets\\"):node_addon_api_except"],"""
               """ 'include_dirs': ['<!(node -p "require(\\'node-addon-api\\').include_dir")']}""")
        self.assertEqual(natives.gyp_commands(gyp), ["node -p \"require('node-addon-api').targets\"",
                                                     "node -p \"require('node-addon-api').include_dir\""])
