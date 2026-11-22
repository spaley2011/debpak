# Candidates for the first recipes

Researched in November 2026. Each of these is widely used, isn't on Flathub,
and has a download URL that stays put, which a recipe needs. None has been
converted yet. Anything marked "to confirm" comes from second-hand sources and
should be checked against the vendor's site before the recipe goes in.

Start with the first three. They cover the three routes, from the easiest
case to the hardest.

## 1. Notepad++ (Wine, from a zip)

Windows only. The Snap Store has an unofficial Wine build. Flathub only has
Notepad Next, which is a separate reimplementation. Every GitHub release
carries `npp.VERSION.portable.x64.zip` with SHA-256 digests, so it's the
simplest possible Wine recipe: a zip, no installer.

Portable Notepad++ keeps its settings next to notepad++.exe, so it needs
`--writable`. debpak's Flathub check may match Notepad Next by name; pass
`--anyway`.

```sh
debpak convert npp.8.9.8.portable.x64.zip --app-id org.notepad_plus_plus.NotepadPlusPlus \
    --writable --anyway --mode extra-data \
    --url https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.9.8/npp.8.9.8.portable.x64.zip
debpak recipe make out/ --to recipes/ \
    --check '{"type": "github", "repo": "notepad-plus-plus/notepad-plus-plus", "asset": "^npp\\.[0-9.]+\\.portable\\.x64\\.zip$"}'
```

## 2. Notion (Electron, from the Windows installer)

There's no official Linux app, only unofficial web wrappers. The Windows
installer is NSIS (electron-builder), and `https://www.notion.so/desktop/windows/download`
redirects to the current version, which is what Chocolatey uses. That makes
it the test case for the Electron route in extra-data mode, including the
7-Zip module.

Notion very likely ships native Node modules (SQLite at least). debpak now
looks for their Linux builds on npm and in prebuild downloads, and in
extra-data mode those become pinned downloads in the manifest rather than
files in the recipe. If a module still has no Linux build, the report says
what was tried, and it needs `--native-dir`, which a recipe can only carry
with `--allow-binaries`.

Check block (the version pattern is to confirm against the redirect's real
target):

```json
{"type": "redirect", "url": "https://www.notion.so/desktop/windows/download", "version": "([0-9]+\\.[0-9]+\\.[0-9]+)"}
```

## 3. Cursor (Linux .deb)

Cursor ships .deb, .rpm and AppImage, but nothing on Flathub. There are
reports of unofficial Flatpak and Snap builds that were malicious, which is a
good reason to have a reviewed recipe. An official endpoint,
`https://www.cursor.com/api/download?platform=linux-x64&releaseTrack=stable`,
returns JSON with `version` and a link for each format (`debUrl`,
`rpmUrl`, `downloadUrl` for the AppImage), checked on 2026-11-22. The check
block is

    {"type": "json",
     "url": "https://www.cursor.com/api/download?platform=linux-x64&releaseTrack=stable",
     "url-key": "debUrl", "version-key": "version"}

and `platform=linux-arm64` gives the arm64 builds.

An editor in a sandbox can't see your projects or run your tools by default.
Flathub's VS Code handles this with `--filesystem=home` and flatpak-spawn.
The recipe will need the same, so convert with `--permissive` and check what
the report suggests.

## Next in line

Linear is Electron for macOS and Windows only; it's a second Electron test
once Notion works. Mp3tag is Windows-only, and its author says it works well
in Wine; check what kind of installer it uses first. Warp, a terminal, ships
.deb and .rpm from stable links like `https://app.warp.dev/download?package=deb`
but has the same sandbox problem as Cursor, worse, since a terminal needs a
host shell.

## Ruled out

- Synology Drive: already on Flathub (an unofficial, outdated build), so
  debpak would point there.
- Proton Pass: on Flathub, unofficially.
- 1Password: its browser integration can't work when the app is sandboxed,
  by the vendor's own account.
- VPN clients (NordVPN, Mullvad, Tailscale): they need a system service,
  which a Flatpak can't run.
- DaVinci Resolve: downloads need a registration form, so there's no stable
  URL to pin.
