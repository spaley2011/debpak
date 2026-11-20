# debpak

debpak turns the Linux packages vendors ship (`.deb`, `.rpm`, Arch packages,
AppImages, snaps and plain archives) into Flatpaks, filling in the libraries the
Flatpak runtime lacks. It can also replace every snap on your system with a
Flatpak. Three companion tools use the same engine to check Windows apps
against Wine (winegap) and macOS apps against Darling (machgap), and to rank
what's missing across many apps (gaprank).

Quick links: [Install](#install) · [How to use](#how-to-use) ·
[Troubleshooting](#troubleshooting) · [How it works](docs/how-it-works.md)

## Features

- Reads `.deb`, `.rpm`, Arch `.pkg.tar.*`, AppImage, `.snap` (or an installed
  snap) and `.tar.*`/`.zip` archives, all in Python with no dependencies.
- Finds the libraries the runtime lacks and copies just those in, from packages
  you downloaded, a Debian or Ubuntu mirror, or an RPM repository.
- Checks symbol versions, so a binary built against a newer glibc is caught
  before you build.
- Works out sandbox permissions from what the binaries link against, and
  records the reason for each one.
- Checks Flathub first, and builds and installs the result for your user.
- Replaces your snaps with Flatpaks: Flathub's build where there is one, a
  converted snap where there isn't.
- Confirms its predictions by running the app with the loader's or Wine's
  logging on.

## Example

`inspect` shows what a conversion involves. Here it is on Ubuntu's jq package:

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

With `--runtime`, the report also lists which of those libraries the runtime
lacks.

## Status

Early MVP (0.1). The Wine and Darling backends are tested against synthetic
binaries built to spec (and against `objdump` for PE), not yet against a corpus
of real apps. An end-to-end suite that builds real `.deb` fixtures covers the
analysis, gap filling and manifest generation, but few real apps have been
through `flatpak-builder` yet, so read a generated manifest before you trust
it. The `desnap` tests run against stand-in `snap`, `apt-get` and `flatpak`
commands and haven't touched a real Ubuntu install; start with `--dry-run`.

## Install

```sh
pip install .            # installs debpak, winegap, machgap, gaprank; no runtime dependencies
pip install '.[zstd]'    # optional: Python zstd (otherwise uses the zstd command; Python 3.14+ has it built in)
```

debpak needs Python 3.10 or newer. Gap analysis needs the target runtime
installed (`flatpak install flathub org.freedesktop.Platform//25.08`) or a saved
index file. AppImages and `.snap` files need `unsquashfs` (package
squashfs-tools); an installed snap doesn't.

## How to use

### Check a package before converting

```sh
debpak inspect vendor-app_1.0_amd64.deb
debpak inspect vendor-app_1.0_amd64.deb --runtime org.freedesktop.Platform//25.08
```

Every format works the same way: `.rpm`, `.pkg.tar.zst`, `.AppImage`, `.snap`,
`.tar.gz` or `.zip`.

### Convert a package

```sh
debpak convert vendor-app_1.0_amd64.deb --app-id com.vendor.App -o out/
```

With `flatpak-builder` installed, `convert` builds the Flatpak, installs it for
your user, and records it for `debpak update` (`--build` makes a missing
`flatpak-builder` an error). `--no-build` stops after writing the manifest and
the staged tree, which you can build yourself:

```sh
debpak convert vendor-app_1.0_amd64.deb --app-id com.vendor.App --no-build -o out/
flatpak-builder --user --install --force-clean --install-deps-from=flathub out/build-dir out/com.vendor.App.json
```

Either way, the output folder holds:

```
out/
  com.vendor.App.json   flatpak-builder manifest (x-debpak block records reasons & provenance)
  app/                  staged /app tree (dir source of the manifest)
  report.txt            human-readable analysis
  report.json           machine-readable analysis
```

Before converting, debpak searches Flathub with `flatpak search`, which reads
the catalogue already on your machine. If Flathub has the app, `convert`
prints the install command and stops, because the Flathub build has a
maintainer who tests it. Pass `--anyway` to convert regardless, or
`--no-flathub-check` to skip the search.

### Fill in missing libraries

Point debpak at somewhere to take the missing libraries from:

```sh
# packages you downloaded (apt download, dnf download, pacman's cache), any mix of formats
debpak convert vendor-app_1.0_amd64.deb --app-id com.vendor.App --deps-dir ./debs -o out/

# a Debian or Ubuntu mirror
debpak convert vendor-app_1.0_amd64.deb --app-id com.vendor.App \
    --mirror https://deb.debian.org/debian --suite stable -o out/

# an RPM repository (the folder that contains repodata/)
debpak convert vendor-app-1.0-1.x86_64.rpm --app-id com.vendor.App \
    --rpm-repo https://dl.fedoraproject.org/pub/fedora/linux/releases/41/Everything/x86_64/os -o out/
```

debpak copies only the library files, never whole packages, and never core
glibc libraries.

### Don't redistribute the vendor's binaries

`--mode extra-data` makes the Flatpak download the vendor's file when it's
installed, the way Flathub ships Chrome and Slack:

```sh
debpak convert vendor-app_1.0_amd64.deb --app-id com.vendor.App \
    --mode extra-data --url https://vendor.example/app_1.0_amd64.deb -o out/
```

### Convert a snap

```sh
debpak convert /snap/some-app/current --app-id com.example.SomeApp -o out/
debpak convert some-app_42.snap --app-id com.example.SomeApp -o out/
```

debpak ignores the snap's plugs and slots and works out permissions from the
binaries. Libraries the snap expected from its base snap come from the matching
Ubuntu release (`core22` is jammy).

### Replace all your snaps

```sh
debpak desnap --dry-run                       # show the plan; changes nothing
debpak desnap                                 # install the replacements, keep the snaps
debpak desnap --copy-data --remove-snaps      # move your app data over, then remove the snaps
debpak desnap --remove-snaps --block-snapd    # and stop apt from bringing snapd back
debpak desnap --only spotify code             # only these snaps
```

For each app snap you have installed, `desnap` installs the Flathub version
when Flathub has one; it matches on the snap's name, title and menu name.
Otherwise it converts the installed snap and installs the result as
`local.snap.NAME`. With `--no-convert` it leaves those snaps alone instead.
`desnap` doesn't replace base snaps, theme and content snaps, or Ubuntu's snap
tools (`snap-store`, `snapd-desktop-integration`, `firmware-updater` and so
on). `--remove-snaps` removes the snap tools once every app snap has a
replacement, and purging snapd removes the rest.

`desnap` prints the whole plan, then asks before each kind of change:
installing, removing snaps, pinning apt, and purging snapd. `--yes` answers yes
to all of them. Without a terminal and without `--yes`, `desnap` answers no.
Steps that need root go through `sudo`.

`desnap` removes and copies nothing unless you ask:

- `--copy-data` copies `~/snap/NAME` into `~/.var/app/ID`, laid out the way
  Flatpak expects: `.config` becomes `config`, `.local/share` becomes `data`,
  and other dot-folders such as `.mozilla` keep their names. It skips `.cache`
  and leaves any file that already exists in `~/.var/app/ID` as it is.
- `--remove-snaps` runs `snap remove` for each snap whose replacement
  installed, and removes the matching Ubuntu deb (Ubuntu's `firefox`,
  `chromium-browser` and `thunderbird` debs only install a snap). snapd keeps a
  snapshot of each removed snap's data for 31 days; `snap saved` lists them.
- `--block-snapd` writes `/etc/apt/preferences.d/debpak-no-snapd.pref`, which
  gives snapd an apt priority of -10. apt then won't install snapd again, even as
  a dependency of those debs. If `--remove-snaps` left no app snaps, `desnap`
  also shows what `apt-get purge snapd` would remove and asks before running
  it. Delete the file to undo the pin.

### Keep converted apps updated

```sh
debpak list                         # apps debpak installed, and what each was converted from
debpak update --check               # which ones have a newer version
debpak update                       # download, convert and reinstall the ones that changed
debpak uninstall com.vendor.App     # --delete-data also removes ~/.var/app/com.vendor.App
```

Converted snaps update from the Snap Store, and apps converted with `--url`
from that URL. If you downloaded the package yourself, download the new version
over the old file and run `debpak update`.

### Find libraries an app loads while it runs

Static analysis can't see plugins, codecs and GPU libraries loaded with
`dlopen()`. `debpak smoke` runs the app with the loader's logging on and
reports each library it asked for and didn't get:

```sh
debpak smoke com.vendor.App                  # the installed Flatpak, for 20 s (--timeout 0: until you close it)
debpak smoke com.vendor.App -- --open f.txt  # with arguments
debpak smoke --exec "out/app/bin/vendor-app" # an unpacked app, without Flatpak
debpak smoke --log ld-debug.log              # an existing LD_DEBUG=libs,files log
```

Use the app's features while it runs; the report only covers what that run
loaded.

### Check a Windows app against Wine

```sh
# index a Wine or Proton-wine source tree (its .spec files mark stubs)
git clone --depth 1 https://gitlab.winehq.org/wine/wine.git
winegap index --wine-source wine --arch x86_64
winegap index --wine-source wine --arch i386

# scan an installed app, for example inside a prefix's drive_c
winegap scan ~/.wine/drive_c/Program\ Files/Vendor/App --index ~/.cache/debpak/wine/11.8_x86_64.json \
    --index ~/.cache/debpak/wine/11.8_i386.json -o app.gap.json

# or index on the fly, and write stub DLLs for the DLLs Wine lacks
winegap scan ./App --wine-source wine --stubs ./stubs
```

Run an installer, or extract it, before scanning: winegap reads the installed
files.

### See what fails when a Windows app runs

```sh
# run it in its prefix for up to 5 minutes; use the features you care about meanwhile
winegap trace --prefix ~/.wine-app --timeout 300 \
    ~/.wine-app/drive_c/Program\ Files/Vendor/App.exe -- --some-arg

# merge the trace with a static scan of the app's folder (needs an index)
winegap trace --prefix ~/.wine-app --index ~/.cache/debpak/wine/11.8_x86_64.json App.exe -o app.gap.json

# or read a log you already have: Proton's steam-<appid>.log, a launcher's log, or
# WINEDEBUG=err+all,fixme+all,warn+module,+loaddll wine App.exe 2> app.log
winegap trace --log app.log --name "Vendor App" --index ...
```

The trace reports unimplemented functions the app called, stubs, DLLs and COM
objects that failed to load, and crashes. Launch scripts and Proton pass
`WINEDEBUG` through, so you can trace an app through them and read their output
with `--log`.

### Check a macOS app against Darling

```sh
machgap index --darling-root /usr/local/libexec/darling --arch x86_64
machgap scan Some.app --index ~/.cache/debpak/darling/installed_x86_64.json -o some.gap.json
machgap scan Some.zip --index ...         # a .zip containing an .app works too
```

Extract a `.dmg` first, for example with `7z x`.

### Decide what to fix first

```sh
gaprank reports/          # any mix of winegap / machgap / debpak report JSONs
```

gaprank lists gaps by how many apps they block. Its `sole` column counts the
apps for which a gap is the only fatal one, so fixing that gap alone makes them
start.

Every command has `--help` with the full list of options. For what the checks
mean and how each tool decides, see [How it works](docs/how-it-works.md).

## Troubleshooting

### `convert` says "Not writing a manifest" and exits with status 2

debpak found a blocker (such as a systemd service or a kernel module) or a
library it couldn't find. The report above the message says which. Give it a
library source (see [Fill in missing libraries](#fill-in-missing-libraries)),
or pass `--force` to write the manifest anyway and fix it by hand.

### `convert` stops with status 4 and an install command

Flathub already has the app. Install that, or pass `--anyway` to convert the
package regardless.

### "runtime ... is not installed"

Install the runtime the message names (`flatpak install flathub
org.freedesktop.Platform//25.08`), or pass `--runtime-index` with a saved
index.

### An AppImage or snap won't unpack

Install squashfs-tools for `unsquashfs`. For an AppImage you can instead pass
`--allow-run`, which lets the AppImage unpack itself by running it.

### The app starts, but a feature doesn't work

The feature probably loads a library with `dlopen()`, which static analysis
can't see. Run `debpak smoke APP_ID`, use the feature, and add the missing
library with `--deps-dir`.

### `winegap trace` reports nothing

The log has no Wine debug output, so `WINEDEBUG` didn't reach Wine. Some
launchers write Wine's output to their own log file; read that file with
`winegap trace --log`.

## Limitations

- Paths compiled into binaries can't be rewritten.
- Packages that need host integration (drivers, VPNs that manage network
  interfaces, system daemons) can't become Flatpaks, and debpak reports them as
  blockers.
- The generated metainfo uses `LicenseRef-proprietary` when the package's
  license isn't valid SPDX; change it before you publish.
- The default runtime branches in `analyze.py` need bumping when new runtime
  branches come out.
- A Wine trace only covers what that run did, and Wine doesn't log a function
  that returns a different result than Windows would.

## Roadmap

- A corpus runner that scans many apps and publishes `gaprank` tables for Wine and Darling.
- Runtime checks for Darling (`DYLD_PRINT_*` logs), like `winegap trace` and `debpak smoke`.
- Names for COM classes in traces, from a CLSID table or the prefix's registry.
- `x-checker-data` for extra-data sources (flatpak-external-data-checker).
- Automatic runtime choice, by comparing gap sizes across installed runtimes.
- Arch repository databases as a library source (`--arch-repo`), like `--rpm-repo`.
- `desnap` on Fedora and Arch: the dnf and pacman equivalents of the apt pin.

## Development

```sh
PYTHONPATH=src:tests python3 -m unittest discover -s tests -v
```

The Wine, Darling, ranking and trace tests need nothing installed. Traces use
recorded Wine log lines and a stand-in `wine`, and the PE and Mach-O files come
from the built-in writers (PE output is cross-checked with `objdump` when it's
available). The `debpak smoke` tests compile small C programs with `gcc` and
read real glibc loader output.

The debpak integration tests need `gcc` and `dpkg-deb` on x86_64. They compile a
small app and two libraries, package them as real `.deb`s (xz and zstd),
convert them, and run the converted binary against the bundled libraries. The
format tests build RPMs, Arch packages, tarballs and AppImages from the same
app with the writers in `tests/format_fixtures.py`, and serve RPMs from a local
`file://` repository. Set `DEBPAK_RPM_SAMPLES` to a folder of real RPMs (rpm's
own `tests/data/RPMS`, say) to test those too. The snap tests build installed
snaps around the same app; they and the `update` and `desnap` tests swap
`flatpak`, `flatpak-builder`, `snap`, `sudo`, `apt-get` and `dpkg-query` for
stand-in scripts, so nothing on the machine changes.

## License

MIT
