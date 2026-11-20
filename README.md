# debpak

debpak turns the Linux packages vendors hand out into Flatpaks. It reads .deb,
.rpm and Arch packages, AppImages, snaps, .run installers, and plain tarballs
or zips. Then it works out which libraries the Flatpak runtime is missing,
copies in just those, and writes a flatpak-builder manifest. If
flatpak-builder is installed, it builds and installs the result too.

It also takes apps that were never meant for Linux. An Electron app from a
Windows installer or a Mac .dmg gets the Linux build of Electron in place of
the one it shipped with, and any other Windows program gets packaged with
Wine.

Most of the reason it exists is snaps. `debpak desnap` goes through the snaps
on your system and swaps each one for the Flathub version, or for a converted
copy when Flathub doesn't have it.

Once someone has converted an app and checked that it works, they can share
the conversion as a recipe, and everyone else gets it with
`debpak install NAME`. A recipe holds no vendor files, only debpak's part and
the vendor's download link.

The same analysis works for other platforms, so the repo also has three
smaller tools. winegap checks a Windows app against Wine, and machgap checks a
macOS app against Darling. gaprank takes reports from all of them and tells you
which missing piece blocks the most apps.

Here's what `debpak inspect` says about Ubuntu's jq package:

```console
$ debpak inspect jq_1.7.1-3ubuntu0.24.04.2_amd64.deb
jq 1.7.1-3ubuntu0.24.04.2 (amd64, .deb)
  lightweight and flexible command-line JSON processor

== Application =================================================
  kind:         elf (plain ELF application)
  entry point:  usr/bin/jq  [binary named after the package]
  desktop file: (none)
  ELF files:    1  (package provides 0 library names)
  requires:     GLIBC_2.38 / -

== Runtime =====================================================
  suggested:    org.freedesktop.Platform//25.08
  (no runtime index: pass --runtime REF or --runtime-index FILE for gap analysis)
  external libraries needed (2): libc.so.6, libjq.so.1

== Suggested permissions =======================================
  --filesystem=xdg-download                     # conservative default: file access via portals + Downloads

== Verdict =====================================================
  looks convertible
```

Give it a runtime and it also tells you which of those libraries the runtime
lacks.

This is early (version 0.1). The test suite builds real packages and runs the
converted binaries, but not many real apps have been through flatpak-builder
yet, so read the manifest before you trust it. desnap has only been tested
against stand-in versions of snap, apt-get and flatpak, so run it with
`--dry-run` first.

## Installing

```sh
pip install .
```

That gives you debpak, winegap, machgap and gaprank. They need Python 3.10 or
newer and nothing else, though `pip install '.[zstd]'` adds a zstd module for
packages compressed with zstd (otherwise debpak uses the zstd command, and
Python 3.14 has it built in). AppImages and .snap files need unsquashfs, from
squashfs-tools. Windows installers and Mac disk images need the tool that
opens them: 7z for .dmg files and NSIS installers, innoextract for Inno Setup
installers, and msiextract (from msitools) for .msi files.

Every command takes `--help` for the full list of options. To check a package
against a runtime, the runtime has to be installed:

```sh
flatpak install flathub org.freedesktop.Platform//25.08
```

## Converting a package

```sh
debpak inspect vendor-app_1.0_amd64.deb
debpak convert vendor-app_1.0_amd64.deb --app-id com.vendor.App -o out/
```

Every format works the same way, so the file can just as well be an .rpm, an
AppImage or a tarball. Before converting, debpak searches Flathub (using the
catalogue flatpak already downloaded) and stops with exit status 4 if the app
is there, since a Flathub build has someone maintaining it. `--anyway`
converts regardless.

If flatpak-builder is installed, convert builds the Flatpak and installs it
for your user. With `--no-build` it stops after writing the manifest, the
staged /app tree and a report into out/, and you can build it yourself:

```sh
flatpak-builder --user --install --force-clean --install-deps-from=flathub out/build-dir out/com.vendor.App.json
```

The libraries the runtime lacks have to come from somewhere. You can point
debpak at packages you downloaded yourself (any mix of .deb, .rpm and Arch
packages), at a Debian or Ubuntu mirror, or at an RPM repository:

```sh
debpak convert vendor-app_1.0_amd64.deb --app-id com.vendor.App --deps-dir ./debs -o out/
debpak convert vendor-app_1.0_amd64.deb --app-id com.vendor.App \
    --mirror https://deb.debian.org/debian --suite stable -o out/
debpak convert vendor-app-1.0-1.x86_64.rpm --app-id com.vendor.App \
    --rpm-repo https://dl.fedoraproject.org/pub/fedora/linux/releases/41/Everything/x86_64/os -o out/
```

Only the library files get copied, never whole packages, and never glibc.

If you'd rather not redistribute the vendor's binaries, `--mode extra-data`
makes the Flatpak download the original file when it's installed. That's how
Flathub ships Chrome and Slack. It works for every input that comes as a
single download, Windows and Mac ones included, and it's what recipes use.

```sh
debpak convert vendor-app_1.0_amd64.deb --app-id com.vendor.App \
    --mode extra-data --url https://vendor.example/app_1.0_amd64.deb -o out/
```

Snaps convert like anything else. Pass an installed snap's folder or a .snap
file:

```sh
debpak convert /snap/some-app/current --app-id com.example.SomeApp -o out/
```

debpak ignores the snap's plugs and slots and works out permissions from what
the binaries link against. The libraries a snap expects from its base snap
come from the matching Ubuntu release (core22 is jammy, core24 is noble).

A .run installer is unpacked without being run and then treated like a
tarball. debpak reads Makeself installers and GOG's game installers. A
Makeself installer usually has a setup script, and debpak checks it the way it
checks a package's install scripts, so one that sets up a system service is
reported rather than silently dropped.

## Windows and Mac apps

convert takes Windows programs and macOS Electron apps too, and sends each one
down one of two routes.

Electron apps don't need Wine. An Electron app is mostly JavaScript, and every Electron release
also comes in a Linux build. debpak keeps the app's resources folder and puts
it next to the Linux build of the same Electron version, on Flathub's Electron
base app. The app can come as a .dmg, an .app (zipped or not), a Windows
installer, or a folder where it's already installed.

```sh
debpak convert "Vendor App-2.3.1.dmg" --app-id com.vendor.App -o out/
debpak convert "Vendor App Setup 2.3.1.exe" --app-id com.vendor.App -o out/
```

debpak reads the Electron version from the app and looks up the matching
Linux zip and its checksum in Electron's GitHub releases; flatpak-builder
downloads the zip when it builds. If the app doesn't say which version it
uses, pass `--electron-version`. `--electron-zip` uses a zip you already have.

What stops an Electron conversion is native code. Some apps include Node
modules (.node files) compiled for Windows or macOS, and those can't load on
Linux. A module that only exists on one platform, like fsevents, doesn't
matter, because the app never loads it on Linux. For the others, debpak
refuses until you give it Linux builds of the same modules with
`--native-dir`, a folder laid out like the app's node_modules. A file with the
same name anywhere in that folder also counts. You get those builds by
installing the same module versions on Linux and rebuilding them for the
app's Electron version with @electron/rebuild.

Every other Windows program runs under Wine, from Flathub's org.winehq.Wine
base app. debpak unpacks the installer without running it, picks the main
.exe (`--exec` picks another), names the app from the .exe's version
information, and writes a launcher that keeps the Wine prefix in
~/.var/app/ID/data/wine. It reads .msix, .appx and Squirrel installers by
itself.

```sh
debpak convert VendorTool-4.2.exe --app-id com.vendor.Tool -o out/
debpak convert ~/.wine/drive_c/Program\ Files/Vendor\ Tool --app-id com.vendor.Tool -o out/
```

Unpacking an installer skips whatever else it would have done, such as
registry entries or installing a runtime the program needs, and some
installers can't be unpacked at all. For those, install the program in Wine
yourself and convert the installed folder, as in the second line.

The Flatpak keeps the program in /app, which is read-only. A program that
saves files next to its .exe needs `--writable`, which copies it into the
prefix's C: drive on first run. When an update brings a new version, the copy
is refreshed, except for files you've changed since the last one.

If you've built a Wine index with winegap (see below), convert checks the
program's imports against it and stops when Wine lacks a DLL or function the
program needs to start. Without an index the report says the check was
skipped.

The Wine base app defaults to its wow64-25.08 branch, a 64-bit Wine that also
runs 32-bit programs. `--runtime org.freedesktop.Platform//26.08` moves to
Wine 11 on stable-26.08, and `--wine-branch` picks any branch.

Mac apps that aren't Electron can't be converted. Darling runs some
command-line Mac programs but not graphical ones, so debpak refuses them and
points to machgap, which shows what such an app would need.

In extra-data mode the Flatpak holds no part of the app. When it's installed,
Flatpak downloads the original installer or disk image, and a small script
debpak puts in the Flatpak unpacks it the same way the conversion did. That
works for .dmg files, zipped apps, NSIS, Squirrel, .msix and .appx installers,
and plain .exe programs. Inno Setup and .msi files can't be unpacked inside
the Flatpak, so they need the default bundle mode. Unpacking a .dmg or an NSIS
installer at install time needs 7-Zip, which the Wine base app already has;
for an Electron app, debpak adds a 7-Zip build to the manifest.

## Installing from recipes

```sh
debpak recipe list
debpak install "Vendor App"
```

install finds the recipe by name or app ID, downloads it, and checks each
file against the hashes in the recipe. It shows where the app will be
downloaded from and what it'll be allowed to do, and asks before building
(`--yes` skips the question). Then flatpak-builder builds it, and Flatpak
downloads the app itself from the vendor, checked against the SHA-256 the
recipe pins. `debpak update` notices when a recipe changes.

The recipes come from the recipes folder of this repository, which is empty
so far. `--recipes` or `$DEBPAK_RECIPES` points at another collection, either
a URL or a local folder.

To share a conversion, convert in extra-data mode with the vendor's URL,
install it and use it for a while, then:

```sh
debpak recipe make out/ --to recipes/ --note "what you tested"
```

That refuses a conversion that would carry the vendor's files, or binaries
such as libraries debpak had to bundle (`--allow-binaries` accepts those if
you may redistribute them). [recipes/README.md](recipes/README.md) covers
adding one to the collection.

## Getting rid of snaps

```sh
debpak desnap --dry-run
```

That prints what desnap would do and changes nothing. For each app snap, it
installs the Flathub version if there is one, matching on the snap's name,
title and menu name. Otherwise it converts the installed snap and installs it
as local.snap.NAME (or leaves it alone if you pass `--no-convert`). Base snaps,
themes and Ubuntu's own snap tools are left out, since there's nothing to
replace them with.

By default it only installs the replacements and keeps your snaps. These
options go further, and desnap asks before each kind of change unless you
pass `--yes`:

- `--copy-data` copies ~/snap/NAME into ~/.var/app/ID, renamed the way Flatpak
  lays it out (.config becomes config, .local/share becomes data). It skips
  .cache and never overwrites a file that's already there.
- `--remove-snaps` removes each snap once its replacement is installed, along
  with Ubuntu's firefox, chromium-browser and thunderbird debs, which exist only
  to install the snap. snapd keeps a snapshot of a removed snap's data for 31
  days (`snap saved` lists them).
- `--block-snapd` writes /etc/apt/preferences.d/debpak-no-snapd.pref, which
  pins snapd so apt won't install it again. Delete the file to undo it.

Together, `--remove-snaps` and `--block-snapd` also offer to purge snapd once
no app snaps are left. desnap shows what `apt-get purge snapd` would remove
first. The whole thing in one go:

```sh
debpak desnap --copy-data --remove-snaps --block-snapd
```

`--only` limits it to the snaps you name. Anything that needs root goes
through sudo.

## Keeping converted apps up to date

debpak remembers each app it installs, in ~/.local/share/debpak/apps.json,
along with how you converted it.

```sh
debpak list
debpak update --check
debpak update
debpak uninstall com.vendor.App
```

Converted snaps update from the Snap Store, apps installed from a recipe
from its collection, and apps converted with `--url` from that URL. If you downloaded the package yourself, put the new version
over the old file and run update. `uninstall --delete-data` also removes the
app's data in ~/.var/app.

## When an app runs but something's missing

Plugins, codecs and GPU libraries get loaded with dlopen() while the app runs,
so reading the binaries can't find them. `debpak smoke` runs the app with the
dynamic loader's logging turned on and lists every library it asked for and
didn't get.

```sh
debpak smoke com.vendor.App
debpak smoke com.vendor.App -- --open notes.txt
debpak smoke --exec out/app/bin/vendor-app
debpak smoke --log ld-debug.log
```

It runs for 20 seconds by default (`--timeout 0` waits until you close the
app), and it only sees what that run loaded, so use the features you care
about while it's running. The last two lines run an unpacked app without
Flatpak, and read a log you already have.

## Windows apps: winegap

winegap needs to know what Wine provides, which it reads from a Wine source
tree. The .spec files in it say which functions are only stubs.

```sh
git clone --depth 1 https://gitlab.winehq.org/wine/wine.git
winegap index --wine-source wine --arch x86_64
winegap index --wine-source wine --arch i386
```

Then point it at an installed app, for example inside a prefix:

```sh
winegap scan ~/.wine/drive_c/Program\ Files/Vendor/App \
    --index ~/.cache/debpak/wine/11.8_x86_64.json --index ~/.cache/debpak/wine/11.8_i386.json
```

Installers have to be run (or extracted) first, because winegap reads the
installed files. `--stubs DIR` writes placeholder DLLs for the ones Wine
doesn't have, which can get an app past the loader.

A scan only predicts. To see what breaks in practice, `winegap trace` starts
the app with Wine's debug logging on, closes it after the timeout, and reports the
unimplemented functions it called, the stubs it hit, the DLLs and COM objects
that failed to load, and any crash:

```sh
winegap trace --prefix ~/.wine-app --timeout 300 ~/.wine-app/drive_c/Program\ Files/Vendor/App.exe
```

Use the app while it runs. Add `--index` to merge the trace with a scan, or
`--log FILE` to read a log you already have, such as Proton's
steam-APPID.log.

## macOS apps: machgap

```sh
machgap index --darling-root /usr/local/libexec/darling --arch x86_64
machgap scan Some.app --index ~/.cache/debpak/darling/installed_x86_64.json
```

A zipped .app works too. For a .dmg, extract it first (7z x works).

## Which gaps matter most: gaprank

Save reports with `-o` from any of the tools, then:

```sh
gaprank reports/
```

It ranks each missing library or function by how many apps it blocks. The sole
column counts the apps for which it's the only thing stopping them from
starting, so fixing that one gap gets them running.

## When things go wrong

If convert exits with status 2 and says it isn't writing a manifest, it found
something it can't handle: a library it couldn't find, or a part of the
package that needs the host system, like a systemd service. The report says
which. Give it somewhere to find the library, or pass `--force` and fix the
manifest by hand.

Status 4 means Flathub already has the app. Install that one, or use
`--anyway`.

If an AppImage or snap won't unpack, install squashfs-tools. An AppImage can
also unpack itself with `--allow-run`, but that means running it.

If the app starts but a feature doesn't work, it's probably a library loaded at
runtime. Run `debpak smoke` while you use that feature, then add the library
with `--deps-dir`.

If a Windows installer won't unpack, the error names the tool to install. If
debpak doesn't know the installer at all, or the converted program misses
something its installer would have set up, install it in Wine and convert the
installed folder instead. A program that complains it can't save its settings
needs `--writable`.

If an Electron app converts but shows a blank window or quits at once, the
cause is usually a native module debpak couldn't check, or a wrong Electron
version. `flatpak run com.vendor.App` prints Electron's own errors.

If `winegap trace` comes back empty, Wine's debug output never reached it.
Some launchers write Wine's output to their own log file. Find that file and
pass it with `--log`.

## Limitations

Paths compiled into a binary can't be rewritten. Anything that needs the host
system, like drivers, VPN clients or system services, can't run in a Flatpak,
and debpak says so instead of trying. The metainfo it writes falls back to a
proprietary license when the package doesn't name a valid SPDX one, so check
it before you publish. The default runtime versions live in analyze.py and need
updating when new ones come out.

The Windows and Mac routes have their own limits. A converted Electron app
can't update itself, so `debpak update` has to do it, and any app code that
assumes Windows or macOS (paths, menus, helper programs it ships) stays that
way. Wine programs get Documents and Downloads but not the rest of your home
folder, since Wine's file dialogs can't use Flatpak's portals; `--permissive`
gives them all of it.

For how the analysis works, see [docs/how-it-works.md](docs/how-it-works.md).

## Plans

- Scan a large set of apps and publish gaprank tables for Wine and Darling.
- A runtime check for Darling, like winegap trace.
- Real names for COM classes in traces, from the prefix's registry.
- Arch repositories as a library source, like `--rpm-repo`.
- desnap for Fedora and Arch.
- A route for command-line Mac programs through Darling, installed on the host.
- Recipes for the apps people ask for most, and a Flatpak repository built
  from them, so `flatpak install` works without debpak.

## Development

```sh
PYTHONPATH=src:tests python3 -m unittest discover -s tests -v
```

Most tests need nothing installed: the PE and Mach-O files come from small
writers in the repo, and Wine traces come from recorded log lines. The debpak
tests need gcc and dpkg-deb on x86_64. They compile a small app and two
libraries, package them in every format, convert them and run the result.
Anything that would touch the system (flatpak, snap, sudo, apt-get) is replaced
by a stand-in script, and so are the installer tools (7z, innoextract,
msiextract). Electron's downloads are answered by a fake, so no test needs
the network. Set `DEBPAK_RPM_SAMPLES` to a folder of real RPMs to test
those as well.

## License

MIT
