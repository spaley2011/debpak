# debpak

Import-gap analysis for running software outside its home platform. Four
command-line tools share one engine:

| Tool      | Input                         | Target                    | What it answers |
|-----------|-------------------------------|---------------------------|-----------------|
| `debpak`  | Linux app: `.deb`, `.rpm`, Arch `.pkg.tar.*`, AppImage, snap, `.tar.gz`/`.zip` | Flatpak runtime | Which libraries are missing? Builds and installs the Flatpak, and can replace your snaps. |
| `winegap` | Windows app (PE), or a Wine log | Wine / Proton           | Will it start? Which functions are stubs? What failed when it ran? Writes stub DLLs. |
| `machgap` | macOS `.app` (Mach-O)         | Darling                   | Will dyld load it? Which symbols and classes are missing or stubbed? |
| `gaprank` | reports from the other three  | Wine and Darling developers | Which single fix unblocks the most apps? |

Each tool reads what a binary imports (ELF `DT_NEEDED` and symbol versions, PE
import and delay-import tables, Mach-O linked dylibs and two-level namespace
bindings) and compares it with an index of what the target provides. Every gap
gets a tier from how that platform's loader would react:

- `fatal`: the app won't start. A library is missing, or a non-weak Mach-O
  symbol is, since dyld binds every symbol at launch.
- `crash`: the app starts, then aborts if it reaches the function (Wine stubs
  and missing exports).
- `degraded`: the app runs without a feature. A stub returns nil or 0 (Darling
  stubs, Wine's `fixme ... stub`), or a library or COM object failed to load
  while it ran.
- `optional`: the import is weak or delay-loaded, or only a plugin needs it.

That analysis is a prediction. `winegap trace` and `debpak smoke` check it by
running the app with Wine's or the Linux loader's logging on. Each gap records
where it came from (predicted, seen running, both, or a guess), and `gaprank`
puts the ones seen in real runs first.

The ELF, PE and Mach-O readers (universal binaries and export tries included)
are written in Python with no dependencies.

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
index file.

## debpak: Linux packages to Flatpak

debpak reads the formats vendors ship:

| Input | Recognised by | Unpacked |
|---|---|---|
| `.deb` | `ar` archive | `data.tar.*` → `/`; maintainer scripts from `control.tar.*` |
| `.rpm` (Fedora, RHEL, openSUSE) | RPM lead | cpio payload (gzip, xz, lzma, bzip2, zstd) → `/`; `%pre`/`%post`/... checked like Debian's scripts; header and payload SHA-256 verified |
| `.pkg.tar.{zst,xz,gz}` (Arch) | file name | payload → `/`; `.PKGINFO` for name, version, URL, license; `.INSTALL` checked |
| `.AppImage` | ELF with AppImage magic | squashfs after the runtime → `/opt/NAME`, with its `.desktop` file pointing at `AppRun` and its icon installed |
| `.snap`, or an installed snap (`/snap/NAME/current`) | squashfs magic, or `meta/snap.yaml` | → `/opt/NAME`, with a launcher per app that sets the `$SNAP` variables snapd would; menu entries and icon from `meta/gui` |
| `.tar.gz`, `.tar.xz`, `.tar.zst`, `.zip` | file name / magic | → `/opt/NAME` (a single top folder is stripped); entry point is the executable named like the app, or the largest one (`--exec` to choose) |

Zstd needs the `zstd` command, the `zstandard` module, or Python 3.14. AppImages
and `.snap` files need `unsquashfs` from squashfs-tools. An AppImage can unpack
itself instead if you pass `--allow-run`, which runs it. An installed snap needs
nothing extra.

For a snap, debpak ignores the permission metadata (plugs, slots, interfaces)
and works out permissions from what the binaries link against, as it does for
every other format. A snap expects some libraries from its base snap; debpak
fetches those from the Ubuntu release the base is built on (`core22` is jammy,
`core24` is noble) unless you pass `--deps-dir`, `--mirror` or
`--no-auto-mirror`. Background services (`daemon:` apps) aren't converted.
debpak also skips snapcraft's desktop-extension launchers, since the Flatpak
runtime provides GTK and Qt.

```sh
# What would conversion involve? (no runtime needed for a basic report)
debpak inspect vendor-app_1.0_amd64.deb
debpak inspect vendor-app_1.0_amd64.deb --runtime org.freedesktop.Platform//25.08

# any format works the same way
debpak inspect vendor-app-1.0-1.x86_64.rpm
debpak inspect Vendor_App-1.0-x86_64.AppImage
debpak convert vendor-app-1.0-linux-x64.tar.gz --app-id com.vendor.App -o out/

# Convert, filling library gaps from a Debian mirror...
debpak convert vendor-app_1.0_amd64.deb --app-id com.vendor.App \
    --mirror https://deb.debian.org/debian --suite stable -o out/

# ...or from an RPM repository (the folder that contains repodata/)...
debpak convert vendor-app-1.0-1.x86_64.rpm --app-id com.vendor.App \
    --rpm-repo https://dl.fedoraproject.org/pub/fedora/linux/releases/41/Everything/x86_64/os -o out/

# ...or from packages you downloaded yourself (`apt download`, `dnf download`, pacman's cache):
# a folder of .deb, .rpm and .pkg.tar.* files, mixed as you like
debpak convert vendor-app_1.0_amd64.deb --app-id com.vendor.App --deps-dir ./debs -o out/

# Don't redistribute the vendor's binaries: download the file at install time (any format)
debpak convert vendor-app_1.0_amd64.deb --app-id com.vendor.App \
    --mode extra-data --url https://vendor.example/app_1.0_amd64.deb -o out/

# An installed snap, or a .snap file
debpak convert /snap/some-app/current --app-id com.example.SomeApp -o out/

# Write the manifest only. convert otherwise runs this itself when flatpak-builder is installed:
debpak convert vendor-app_1.0_amd64.deb --app-id com.vendor.App --no-build -o out/
flatpak-builder --user --install --force-clean --install-deps-from=flathub out/build-dir out/com.vendor.App.json
```

Before converting, debpak searches Flathub with `flatpak search`, which reads
the catalogue already on your machine. If Flathub has the app, `convert` prints
the install command and exits with status 4, because the Flathub build has a
maintainer who tests it. Pass `--anyway` to convert regardless, or
`--no-flathub-check` to skip the search.

With `flatpak-builder` installed, `convert` builds the Flatpak, installs it for
your user, and records it for `debpak update`. Without `flatpak-builder` it
prints the build command, or fails if you passed `--build`.

If debpak finds blockers or required libraries it can't resolve, `convert`
writes nothing and exits with status 2. `--force` writes the manifest anyway.

### Output

```
out/
  com.vendor.App.json   flatpak-builder manifest (x-debpak block records reasons & provenance)
  app/                  staged /app tree (dir source of the manifest)
  report.txt            human-readable analysis
  report.json           machine-readable analysis
```

### How debpak works

1. Extract. A reader for each format unpacks the package into the layout of an
   installed system. It refuses paths that leave the destination and writes
   through symlinks.
2. Analyze. debpak's ELF reader collects `DT_NEEDED`, sonames, RPATH/RUNPATH,
   symbol-version requirements and imported symbols from every ELF file in the
   package. Executables are the dependency roots; libraries that only plugins
   need count as optional.
3. Classify. debpak sorts the app into Electron, Qt5/Qt6, GTK3/GTK4, Java or
   plain ELF. The class picks the suggested runtime and any special handling
   (Electron gets `zypak` and the Electron BaseApp).
4. Index the runtime. debpak scans the installed runtime's `files/` tree on the
   host and caches the library names and symbol versions it provides in
   `~/.cache/debpak`. GL, Vulkan and driver libraries count as provided by the
   GL extension.
5. Fill gaps. debpak looks up each missing soname in your local packages or a
   mirror's `Contents-<arch>` index, copies only the matching library files into
   `/app/lib/debpak`, and repeats for their own dependencies. It never bundles
   the core glibc libraries.
6. Check versions. Each required symbol version (`GLIBC_2.38`,
   `GLIBCXX_3.4.32`) must exist in the runtime or the bundle. A glibc mismatch
   is a blocker; a newer runtime branch fixes it.
7. Check host integration. debpak sorts maintainer scripts and payload paths:
   it ignores cache refreshes, handles setuid sandboxes, and reports systemd
   units, kernel modules, PAM and udev rules as blockers or warnings.
8. Map paths. `usr/*` goes to `/app/*` and `opt/*` to `/app/opt/*`. debpak
   rewrites hardcoded `/opt/...` paths in shell scripts and reports the ones
   compiled into binaries.
9. Integrate with the desktop. debpak renames the `.desktop` file to the app
   ID, points its `Exec=` at a generated wrapper, and moves any `env VAR=...`
   prefix into that wrapper. It exports the icons under the app ID and writes an
   AppStream metainfo file.
10. Infer permissions from linked libraries and imported symbols. The manifest
    and the report give the reason for each one. debpak only grants
    `--filesystem=home` if you pass `--permissive`.

### Keeping converted apps updated

```sh
debpak list                         # apps debpak installed, and what each was converted from
debpak update --check               # which ones have a newer version
debpak update                       # download, convert and reinstall the ones that changed
debpak uninstall com.vendor.App     # --delete-data also removes ~/.var/app/com.vendor.App
```

debpak records each app it installs in `~/.local/share/debpak/apps.json`,
with the options you converted it with. For a converted snap, `update` asks the
Snap Store for the current revision (snapd isn't needed). For an app converted
with `--url`, it downloads the file again and compares checksums. Otherwise it
checks whether the original file changed on disk, so if you downloaded the
package yourself, download the new version over the old file and run `update`.

### debpak smoke: libraries loaded at runtime

Apps load plugins, codecs and GPU libraries with `dlopen()` while they run, so
the import scan can't see them. `debpak smoke` runs the converted app with the
loader's own logging on (`LD_DEBUG=libs,files`) and reports each library the
app asked for and didn't get:

```sh
debpak smoke com.vendor.App                  # the installed Flatpak, for 20 s (--timeout 0: until you close it)
debpak smoke com.vendor.App -- --open f.txt  # with arguments
debpak smoke --exec "out/app/bin/vendor-app" # an unpacked app, without Flatpak
debpak smoke --log ld-debug.log              # an existing LD_DEBUG=libs,files log
```

A missing library the app needs at startup is `fatal`. One it loaded on demand
and didn't find is `degraded`, since that feature won't work. Common GPU and
desktop probes (`libcuda`, `libnvidia-*`, `libappindicator`, ...) are
`optional`, because apps run fine without them. An `undefined symbol` error is a
`crash` and usually means a bundled library is too old. The report only covers
what that run loaded.

### Limitations

- Paths compiled into binaries can't be rewritten.
- Packages that need host integration (drivers, VPNs that manage network
  interfaces, system daemons) can't become Flatpaks, and debpak reports them as
  blockers.
- The generated metainfo uses `LicenseRef-proprietary`; change it before you
  publish.
- The default runtime branches in `analyze.py` need bumping when new runtime
  branches come out.

## debpak desnap: replace your snaps with Flatpaks

```sh
debpak desnap --dry-run                       # show the plan; changes nothing
debpak desnap                                 # install the replacements, keep the snaps
debpak desnap --copy-data --remove-snaps      # move your app data over, then remove the snaps
debpak desnap --remove-snaps --block-snapd    # and stop apt from bringing snapd back
debpak desnap --only spotify code             # only these snaps
```

For each app snap you have installed, desnap installs the Flathub version when
Flathub has one; it matches on the snap's name, title and menu name. Otherwise
it converts the installed snap and installs the result as `local.snap.NAME`.
With `--no-convert` it leaves those snaps alone instead. desnap doesn't replace
base snaps, theme and content snaps, or Ubuntu's snap tools (`snap-store`,
`snapd-desktop-integration`, `firmware-updater` and so on). `--remove-snaps`
removes the snap tools once every app snap has a replacement, and purging
snapd removes the rest.

desnap prints the whole plan, then asks before each kind of change: installing,
removing snaps, pinning apt, and purging snapd. `--yes` answers yes to all of
them. Without a terminal and without `--yes`, desnap answers no. Steps that need
root go through `sudo`.

desnap removes and copies nothing unless you ask:

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
  a dependency of those debs. If `--remove-snaps` left no app snaps, desnap
  also shows what `apt-get purge snapd` would remove and asks before running
  it. Delete the file to undo the pin.

## winegap: Windows apps on Wine/Proton

```sh
# index a Wine or Proton-wine source tree (its .spec files mark stubs)
git clone --depth 1 https://gitlab.winehq.org/wine/wine.git
winegap index --wine-source wine --arch x86_64
winegap index --wine-source wine --arch i386

# scan an installed app (e.g. inside a prefix's drive_c)
winegap scan ~/.wine/drive_c/Program\ Files/Vendor/App --index ~/.cache/debpak/wine/11.8_x86_64.json \
    --index ~/.cache/debpak/wine/11.8_i386.json -o app.gap.json

# or index on the fly, and write loader-satisfying stub DLLs for DLLs Wine lacks
winegap scan ./App --wine-source wine --stubs ./stubs
```

The scanner follows the rules of Wine's loader:

- If a DLL the app imports statically is in neither Wine nor the app's folder,
  the app doesn't start.
- A function that a DLL stubs or lacks gets an "unimplemented function" thunk,
  which aborts only when the app calls it.
- A delay-loaded DLL fails on first use.
- A DLL in the app's folder wins over Wine's builtin.

winegap follows forwarders (such as kernel32 to kernelbase) and resolves imports
by ordinal. It checks each module against the index for that module's
architecture, so 32-bit helpers in a 64-bit app get the right answer.

### Stub DLLs

`--stubs` writes a minimal PE DLL for each missing DLL that exports the names
and ordinals the app imports. Guides for running Lightroom on Wine do this by
hand. Stubs return 0, or trap with `--stub-mode trap`. 32-bit x86 stubs always
trap, because a stdcall stub can't know how many argument bytes to pop. A stub
DLL only gets the app past the loader; the features that call it still won't
work.

### Runtime lookups (guesses)

`scan` also reads the strings in each binary. A DLL name near a function name
(`LoadLibrary("dwmapi.dll")` with `GetProcAddress(h, "DwmFlush")`) suggests a
function the app looks up at runtime. winegap reports these only when Wine has
the function as a stub, which aborts if called. They're tagged `[guess]` and
sit in the `optional` tier, so they never change the verdict. `--no-guess`
turns them off.

### winegap trace: what failed when the app ran

Import analysis misses what an app does while it runs: functions it looks up
with `GetProcAddress`, DLLs it loads on demand, COM objects, and Wine functions
that exist but are only partly implemented. With debug logging on, Wine reports
most of these as they happen. `winegap trace` runs the app that way and turns
the log into the same gap report:

```sh
# run it (in its prefix) for up to 5 minutes; use the features you care about meanwhile
winegap trace --prefix ~/.wine-app --timeout 300 \
    ~/.wine-app/drive_c/Program\ Files/Vendor/App.exe -- --some-arg

# add the static scan of the app's folder and merge the two (needs an index)
winegap trace --prefix ~/.wine-app --index ~/.cache/debpak/wine/11.8_x86_64.json App.exe -o app.gap.json

# or read a log you already have: Proton's steam-<appid>.log, a launcher's log, or
# WINEDEBUG=err+all,fixme+all,warn+module,+loaddll wine App.exe 2> app.log
winegap trace --log app.log --name "Vendor App" --index ...
```

| Seen in the log | Gap |
|---|---|
| `Call from ... to unimplemented function X.dll.Func, aborting` | `crash`, X.dll!Func |
| `err:module:import_dll Library X.dll (which is needed by ...) not found` | `fatal` if the .exe needs it, else `degraded` |
| `warn:module:load_dll Failed to load module "X.dll"` (LoadLibrary) | `degraded` |
| `fixme:<channel>:Func ... stub` | `degraded`; the Wine index names the DLL |
| `no instance created ... of class {CLSID}` / `class {CLSID} not registered` | `degraded`, com!{CLSID} |
| `wine: Unhandled page fault ...` + backtrace | `crash` in the module of frame 0 |
| other `fixme` lines | counted and listed in the notes (usually harmless) |

With an index, a gap the static scan predicted and the trace confirmed is
marked `both`; the others are `runtime`. Run counts show as `[seen running x3]`.
At the timeout, winegap stops the app, and with `--prefix` it also shuts
down that prefix's `wineserver`. Launch scripts and Proton pass
`WINEDEBUG` through, so you can trace an app through them and read their output
with `--log`.

A trace only covers what that run did, so open your documents and use the
features you need while it runs. Wine doesn't log a function that returns a
different result than Windows would; finding that takes the same task run on
Windows. winegap flags .NET assemblies and kernel drivers (anti-cheat, DRM,
hardware) but doesn't analyze managed P/Invoke calls. Run an installer, or
extract it, before scanning: winegap reads the installed files.

## machgap: macOS apps on Darling

```sh
machgap index --darling-root /usr/local/libexec/darling --arch x86_64
machgap scan Some.app --index ~/.cache/debpak/darling/installed_x86_64.json -o some.gap.json
machgap scan Some.zip --index ...         # a .zip containing an .app works too
```

The scanner handles universal (fat) binaries; `@rpath`, `@loader_path` and
`@executable_path` inside the bundle; re-exported libraries (libSystem); weak
linking; flat-namespace lookups; and platform checks. It rejects iOS and
Catalyst binaries, and apps with no slice for the index's architecture.

machgap recognises Darling's stubs by the log string each one prints,
`STUB: <name> called`. If your Darling version words it differently, pass
`--stub-pattern REGEX`.

Objective-C dispatches methods by selector at runtime, so a class that exists
can still lack a method the app calls. The report warns about this whenever an
app references ObjC classes. Extract a `.dmg` first (for example with `7z x`).

## gaprank: what to fix first

```sh
gaprank reports/          # any mix of winegap / machgap / debpak report JSONs
```

`gaprank` ranks gaps by how many apps they affect. The `sole` column counts the
apps for which a gap is the only fatal one: fixing that gap alone makes them
start. The `seen` column counts apps where a traced run (`winegap trace`,
`debpak smoke`) hit the gap; within a tier, those rank first. Run it over a set
of popular apps and Wine or Darling developers get a to-do list in priority
order.

## Roadmap

- A corpus runner that scans many apps and publishes `gaprank` tables for Wine and Darling.
- Runtime checks for Darling (`DYLD_PRINT_*` logs), like `winegap trace` and `debpak smoke`.
- Names for COM classes in traces, from a CLSID table or the prefix's registry.
- Scripted UI actions during a trace, to reach more of the app.
- `x-checker-data` for extra-data sources (flatpak-external-data-checker).
- Automatic runtime choice, by comparing gap sizes across installed runtimes.
- More maintainer-script patterns, and GSettings schema compilation.
- Arch repository databases as a library source (`--arch-repo`), like `--rpm-repo`.
- desnap on Fedora and Arch: the dnf and pacman equivalents of the apt pin.

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
snaps around the same app; they and the update and desnap tests swap
`flatpak`, `flatpak-builder`, `snap`, `sudo`, `apt-get` and `dpkg-query` for
stand-in scripts, so nothing on the machine changes.

## License

MIT
