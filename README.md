# debpak

debpak turns the Linux packages vendors hand out into Flatpaks. It reads .deb,
.rpm and Arch packages, AppImages, snaps, and plain tarballs or zips. Then it
works out which libraries the Flatpak runtime is missing, copies in just
those, and writes a flatpak-builder manifest. If flatpak-builder is installed,
it builds and installs the result too.

Most of the reason it exists is snaps. `debpak desnap` goes through the snaps
on your system and swaps each one for the Flathub version, or for a converted
copy when Flathub doesn't have it.

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
squashfs-tools.

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
Flathub ships Chrome and Slack.

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

Converted snaps update from the Snap Store, and apps converted with `--url`
from that URL. If you downloaded the package yourself, put the new version
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

For how the analysis works, see [docs/how-it-works.md](docs/how-it-works.md).

## Plans

- Scan a large set of apps and publish gaprank tables for Wine and Darling.
- A runtime check for Darling, like winegap trace.
- Real names for COM classes in traces, from the prefix's registry.
- Arch repositories as a library source, like `--rpm-repo`.
- desnap for Fedora and Arch.

## Development

```sh
PYTHONPATH=src:tests python3 -m unittest discover -s tests -v
```

Most tests need nothing installed: the PE and Mach-O files come from small
writers in the repo, and Wine traces come from recorded log lines. The debpak
tests need gcc and dpkg-deb on x86_64. They compile a small app and two
libraries, package them in every format, convert them and run the result.
Anything that would touch the system (flatpak, snap, sudo, apt-get) is replaced
by a stand-in script. Set `DEBPAK_RPM_SAMPLES` to a folder of real RPMs to test
those as well.

## License

MIT
