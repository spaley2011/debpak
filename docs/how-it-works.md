# How debpak works

This is the reference for what the tools check and why. The
[README](../README.md) covers how to use them.

- [Gap tiers and evidence](#gap-tiers-and-evidence)
- [debpak: the conversion pipeline](#debpak-the-conversion-pipeline)
- [Recipes](#recipes)
- [debpak smoke](#debpak-smoke)
- [winegap](#winegap)
- [machgap](#machgap)
- [gaprank](#gaprank)

## Gap tiers and evidence

Each tool reads what a binary imports (ELF DT_NEEDED and symbol versions, PE
import and delay-import tables, Mach-O linked dylibs and two-level namespace
bindings) and compares it with an index of what the target provides. Every gap
gets a tier from how that platform's loader would react:

| Tier | Meaning |
|---|---|
| fatal | The app won't start. A library is missing, or a non-weak Mach-O symbol is, since dyld binds every symbol at launch. |
| crash | The app starts, then aborts if it reaches the function (Wine stubs and missing exports). |
| degraded | The app runs without a feature. A stub returns nil or 0 (Darling stubs, Wine's `fixme ... stub`), or a library or COM object failed to load while it ran. |
| optional | The import is weak or delay-loaded, or only a plugin needs it. |

Each gap also records where it came from:

| Evidence | Meaning |
|---|---|
| static | Predicted from the imports. |
| runtime | Seen while the app ran (winegap trace, debpak smoke). |
| both | Predicted, then seen. |
| guess | A function name found as text in the binary, probably looked up at runtime. |

The ELF, PE and Mach-O readers (universal binaries and export tries included)
are written in Python with no dependencies. Their output format, gapreport/1,
is the same for every tool, so gaprank can rank them together.

## debpak: the conversion pipeline

1. A reader for the package's format unpacks it into the layout of an
   installed system. It refuses paths that leave the destination and writes
   through symlinks.
2. debpak's ELF reader collects DT_NEEDED, sonames, RPATH/RUNPATH,
   symbol-version requirements and imported symbols from every ELF file in the
   package. Executables are the dependency roots; libraries that only plugins
   need count as optional.
3. The app gets sorted into Electron, Qt5/Qt6, GTK3/GTK4, Java or plain ELF.
   That decides the suggested runtime and any special handling (Electron gets
   zypak and the Electron BaseApp; a CEF app gets zypak only when its package
   keeps Chromium's sandbox, by shipping chrome-sandbox or loading an AppArmor
   profile for it).
4. debpak scans the installed runtime's `files/` tree on the host and caches
   the library names and symbol versions it provides in `~/.cache/debpak`.
   GL, Vulkan and driver libraries count as provided, since the GL extension
   supplies them.
5. Each missing soname is looked up in your local packages, an RPM
   repository, or a Debian mirror's `Contents-<arch>` index; with none given,
   the programs' own needs are looked up in Ubuntu noble. Only the matching
   library files are copied into `/app/lib/debpak`, and then the same happens
   for their own dependencies. The core glibc libraries are never bundled.
   `/app/etc/ld.so.conf` names that folder, so Flatpak puts it in the app's
   linker cache and a program started with its own `LD_LIBRARY_PATH` (Zoom's
   launcher) still finds them.
6. Every required symbol version (`GLIBC_2.38`, `GLIBCXX_3.4.32`) has to exist
   in the runtime or the bundle. A glibc mismatch is a blocker, and a newer
   runtime branch fixes it.
7. Maintainer scripts and payload paths get sorted: cache refreshes are
   ignored, setuid sandboxes are handled, and systemd units, kernel modules,
   PAM and udev rules are reported as blockers or warnings. A system unit kept
   outside the systemd folders (TeamViewer's `/opt/teamviewer/tv_bin/script/
   teamviewerd.service`) and a script that installs one itself
   (`teamviewer daemon enable`) are blockers too, as is a program that says it
   only works as root and asks for sudo or pkexec (Raspberry Pi Imager), since
   nothing in a Flatpak runs as root.
8. Paths are mapped: `usr/*` goes to `/app/*` and `opt/*` to `/app/opt/*`.
   Hardcoded `/opt/...` paths in shell scripts are rewritten, as are `/usr/...`
   paths to files the package ships (`BC_LIB=/usr/lib/beyondcompare` becomes
   `/app/lib/beyondcompare`; `/usr/bin/env` stays the runtime's). The ones
   compiled into binaries are reported.
9. The .desktop file is renamed to the app ID, its `Exec=` points at a
   generated wrapper, and any `env VAR=...` prefix moves into that wrapper.
   Started with no arguments (`flatpak run`), the wrapper passes the ones the
   menu entry gives (Espanso's `espanso launcher`). Icons are exported under
   the app ID (an SVG that isn't square is centred on a square canvas, since
   Flatpak refuses it), and an AppStream metainfo file is written.
   When the program exits, the wrapper waits for any process it left running
   in the sandbox: Flatpak ends the sandbox when its first process exits, and
   Sublime Text forks into the background while Rocket.Chat restarts itself.
   First-run files a package keeps in `usr/share/NAME/skel` (Parsec) are copied
   into `~/.NAME`, which is kept with `--persist`.
10. Permissions are inferred from linked libraries and imported symbols, and
    the manifest and report give the reason for each. `--filesystem=home` is
    only granted if you pass `--permissive`. The app's own reverse-DNS names
    (its desktop file ID, AppStream ID, `X-DBUS-ServiceName=`, D-Bus service
    files that run its programs) get `--own-name`: GApplication and KDE apps
    exit when they can't register their name, and the Flatpak's app ID
    usually differs from it. A program that checks for `/.flatpak-info` and
    then runs its commands with `flatpak-spawn --host` (WezTerm opens each
    terminal's shell that way) gets `--talk-name=org.freedesktop.Flatpak`, and
    the report warns that this lets the app run programs outside the sandbox.
    Without it the shell exits at once, and WezTerm closes its only window and
    quits without showing anything.

### What each format unpacks to

| Input | Recognised by | Unpacked |
|---|---|---|
| `.deb` | ar archive | `data.tar.*` into `/`; maintainer scripts from `control.tar.*` |
| `.rpm` (Fedora, RHEL, openSUSE) | RPM lead | cpio payload (gzip, xz, lzma, bzip2, zstd) into `/`; `%pre`/`%post`/... checked like Debian's scripts; header and payload SHA-256 verified |
| `.pkg.tar.{zst,xz,gz}` (Arch) | file name | payload into `/`; `.PKGINFO` for name, version, URL, license; `.INSTALL` checked |
| `.AppImage` | ELF with AppImage magic | squashfs after the runtime, into `/opt/NAME`, with its .desktop file pointing at AppRun and its icon installed |
| `.snap`, or an installed snap (`/snap/NAME/current`) | squashfs magic, or `meta/snap.yaml` | `/opt/NAME`, with a launcher per app that sets the `$SNAP` variables snapd would; menu entries and icon from `meta/gui` |
| `.tar.gz`, `.tar.xz`, `.tar.zst`, `.zip` | file name / magic | `/opt/NAME` (a single top folder is stripped); entry point is the program a .desktop file in the archive runs, else the one named like the app, else the largest that isn't a helper, looking in the top folder and `bin/` (`--exec` to choose) |
| `.run` (Makeself) | `#!` script naming Makeself, or `filesizes=` | the tar payload after the header (its length comes from `skip=` or `head -n`), into `/opt/NAME` like a tarball; the setup script is checked as `postinst`, never run; encrypted payloads are refused |
| `.sh` / `.run` (GOG, MojoSetup) | a zip after the script | `data/noarch/game` into `/opt/NAME`; name and version from `data/noarch/gameinfo` |

Windows and Mac inputs (`.exe`, `.msi`, `.msix`, `.appx`, `.nupkg`, `.dmg`,
`.app`, a zip holding an `.app` or `.exe` files, or a folder with either) go
to a separate path, described under [Windows and Mac apps](#windows-and-mac-apps).
A zip that holds `.exe` files but also Linux pieces (`.so` files, `.desktop`
files, shell scripts) stays a tarball.

### Snaps

debpak ignores a snap's permission metadata (plugs, slots, interfaces) and
works out permissions from what the binaries link against, as it does for every
other format. A snap expects some libraries from its base snap; debpak fetches
those from the Ubuntu release the base is built on (core22 is jammy,
core24 is noble) unless you pass `--deps-dir`, `--mirror` or
`--no-auto-mirror`. Background services (daemon: apps) aren't converted, and a
system service the snap can't do without is a blocker: one in a snap with no
menu entry, or one that plugs kvm, firewall-control, network-control or a
`*-support` interface (Multipass's multipassd, which its CLI and GUI only drive).
debpak also skips snapcraft's desktop-extension launchers, since the Flatpak
runtime provides GTK and Qt.

desnap finds the package manager (apt with dpkg, then dnf5 or dnf, then
pacman; `$DEBPAK_PKG_MANAGER` overrides) for the parts that need it.

| | apt | dnf | pacman |
|---|---|---|---|
| snap-installer packages | firefox, chromium-browser, thunderbird debs are found with dpkg-query and removed with the snaps | none | none |
| `--block-snapd` | pin file in /etc/apt/preferences.d | dnf5: excludepkgs drop-in in /etc/dnf/libdnf5.conf.d; dnf4: prints the line for dnf.conf | nothing (snapd is in the AUR) |
| preview, then removal | `apt-get -s purge`, `apt-get purge -y snapd` | `dnf remove --assumeno`, `dnf remove -y snapd` | `pacman -Rsp`, `pacman -Rns --noconfirm snapd` |

### Windows and Mac apps

None of the ELF analysis applies here. foreign.py unpacks the input, and the
app takes one of two routes depending on what's inside.

| Input | Unpacked with |
|---|---|
| `.dmg` | 7z (older 7-Zip versions leave a partition image, which is opened in a second pass) |
| `.app`, zipped `.app` | nothing; symlinks in the zip are skipped |
| Inno Setup `.exe` | innoextract; the program is the `{app}` folder |
| NSIS `.exe` | 7z; electron-builder's `$PLUGINSDIR/app-64.7z` is unpacked in turn |
| Squirrel `Setup.exe` | the `.nupkg` in its resources, read in Python; the program is `lib/net45` |
| `.msi` | msiextract (7z gives internal file IDs instead of names, so it isn't used) |
| `.msix`, `.appx`, `.nupkg` | zip; name, version and executable from `AppxManifest.xml` or the `.nuspec` |
| self-extracting zip `.exe` | zip, once the installer markers above have been ruled out |
| 7-Zip self-extractor `.exe` (7-Zip's own installer, 7zS.sfx) | 7z, on the 7z archive found after the program's sections (its start header's CRC must match); the cut-out archive is unpacked at install time too |
| RAR self-extractor `.exe` (WinRAR's installer) | bsdtar; 7z lists the files, but the 7z that Debian and Ubuntu ship can't decode RAR, so every file comes out empty |
| WiX bundles, InstallShield, anything named or described as a setup program | refused, with the advice to install it in Wine and convert the folder |
| any other `.exe` | taken as a portable program |

After 7z, bsdtar, innoextract or msiextract, any symlink pointing outside the
extracted folder is deleted, so nothing reads host files through one.

If the unpacked files have a `resources` folder with `app.asar` or
`app/package.json` in it, it's an Electron app; a Mac app also has to have the
Electron framework in `Contents/Frameworks`. A Mac app without the framework is native and refused. Anything
else from Windows goes to Wine.

The Electron route:

1. The Electron version is taken from `--electron-version`; then the Electron
   framework's `Info.plist` (Mac) or a `version` file (Windows); then an
   `Electron/x.y.z` string in the binary; then the Chromium version in the
   binary, looked up in releases.electronjs.org/releases.json; then the
   `electron` entry in the app's package.json. With none of these it's a
   blocker.
2. Every `.node` file inside `app.asar`, in `app.asar.unpacked` or in an
   unpacked `resources/app` is classified by its magic bytes. Linux builds
   pass. A Windows or Mac build in a package that only exists for one
   platform (judged by the package's name: fsevents, win-ca and the like)
   gets a note. Other Windows or Mac executables in `resources` get a note
   too. For every other Windows or Mac module, debpak takes a replacement
   from `--native-dir` if there is one, and otherwise looks one up
   (natives.py):
   - For a per-platform package such as `@img/sharp-win32-x64`, it adds
     `@img/sharp-linux-x64` from npm at the same version, plus that package's
     own Linux-only dependencies (sharp's libvips package).
   - For a prebuildify module whose `prebuilds/win32-x64/` is all the app
     shipped, it adds `prebuilds/linux-x64/` from the module's npm tarball.
   - Otherwise it tries a prebuild release asset,
     `NAME-vVERSION-electron-vABI-linux-x64.tar.gz` (the ABI comes from
     Electron's release list), then `napi-vN` builds, under the repository's
     vVERSION release.
   - Last, it tries node-pre-gyp: host, remote_path and package_name from
     the module's package.json, expanded for Electron on Linux. The file goes
     where node-pre-gyp will look on Linux (module_path expanded the same
     way), not where the Windows build was.

   npm tarballs must match the registry's SHA-512 integrity hash. GitHub and
   node-pre-gyp downloads have no published checksum, and the report says
   so. Every library taken must be an x86-64 ELF file, and package names and
   paths are checked before they become URLs or file names. A module nothing
   was found for is a blocker that lists what was tried.
3. Linux builds are written into `app.asar.unpacked`. The asar header is
   rewritten so existing entries are marked unpacked and added files get
   new entries, with their sizes; the file data is copied unchanged. Stock
   Linux Electron doesn't check the header's integrity hashes, so this
   loads. In extra-data mode, downloaded builds become archive sources in the
   manifest, pinned by SHA-256, and debpak-unpack puts them in place at
   install time; only `--native-dir` files are carried in the Flatpak.
4. The manifest has two modules. The first downloads
   `electron-vVERSION-linux-{x64,arm64}.zip` from GitHub (one source per
   architecture, with the SHA-256 from that release's `SHASUMS256.txt` and
   `strip-components: 0`) into `/app/lib/NAME`, and deletes
   `default_app.asar`. The second copies the app's resources over Electron's,
   plus the launcher, desktop file, icon and metainfo.
5. The launcher sets `TMPDIR` to the app's runtime folder (where Chromium keeps
   its single-instance lock) and runs Electron through zypak-wrapper. The base
   is org.electronjs.Electron2.BaseApp on the runtime's branch.
6. The name, summary, homepage and license come from the package's own
   metadata (a Mac app's `Info.plist`, a Squirrel `.nuspec`, an
   `AppxManifest.xml`), then the app's package.json. The icon is the largest PNG of at
   most 512 pixels from the `.icns`, or the largest one in the `.exe`.

The Wine route:

1. The main `.exe` is the one `--exec` or the package's manifest names.
   Otherwise uninstallers, updaters, crash handlers and redistributables are
   dropped, and the pick is an `.exe` named like the product, then a GUI
   program nearest the top, largest first.
2. The name and version come from the installer's metadata, then the `.exe`'s
   version resource (ProductName, ProductVersion), then the file name.
3. An ARM64 program is a blocker, since the Wine base app is built for x86_64
   only. A 32-bit program runs through WoW64. A .NET program gets a note that
   it runs on wine-mono.
4. Permissions: IPC, X11, the GPU and PulseAudio always; the network when any
   PE file imports a networking DLL (ws2_32, wininet, winhttp and others);
   Documents and Downloads, or the whole home folder with `--permissive`.
5. If winegap has cached a Wine index in `~/.cache/debpak/wine`, the program
   folder is scanned against the newest one per architecture, and a fatal gap
   is a blocker.
6. The base is org.winehq.Wine. Runtime 24.08 or 25.08 picks its `wow64-`
   branch, and later runtimes pick `stable-BRANCH`; `--wine-branch` sets it
   and the runtime branch follows. The manifest inherits the base's gecko and
   mono extensions (named with `-wow64` on the wow64 branches).
7. The launcher creates the prefix in `$XDG_DATA_HOME/wine` on first run.
   With `--wine-runtime`, it then runs the Wine base app's winetricks
   (`-q --unattended`) with those verbs, once: it records them in the prefix
   only when winetricks succeeds, so a failed install is retried on the next
   start. The report suggests verbs for runtime DLLs the program imports but
   doesn't ship (msvcp140.dll suggests vcrun2022, d3dx9_43.dll d3dx9), and
   dotnet48 for .NET programs. `--wine-runtime wine-mono` isn't passed to
   winetricks: it stops the automatic .NET runtime install, so the program
   runs on wine-mono. It also adds network access, since winetricks
   downloads them. The launcher then turns arguments that are existing files
   into Windows paths with winepath, changes to the `.exe`'s folder and runs
   it. Paths and names from the installer are shell-quoted, and names are
   cut to one line wherever they go into comments or desktop files. With `--writable`, it first
   copies the program into `drive_c/Program Files/NAME`. It records an MD5
   list of what it copied, and on a later version it overwrites only files
   whose checksum still matches that list. A file the user changed is kept.

### Extra-data for Windows, Mac and .run inputs

In extra-data mode the vendor's file is downloaded by Flatpak at install
time, so whatever unpacked it during the conversion has to run again inside
the sandbox, where innoextract and msiextract don't exist. unpack.py does
both jobs. During the conversion foreign.py and the .run reader decide on a
list of steps (zip, 7z with an optional inner archive or disk image,
bsdtar, squirrel, copy, makeself) and run them through unpack.py. In extra-data mode
debpak also writes them to `app/share/debpak/unpack.json`, with the folder to
keep, where it goes, the paths to delete and any native modules to put in
place. It copies unpack.py itself to `/app/bin/debpak-unpack`, and
`apply_extra` runs it in `/app/extra`. unpack.py uses only Python's standard
library and the Platform runtime's python3, plus 7z when a step needs it.

Where the files end up:

| Route | Bundle mode | Extra-data mode |
|---|---|---|
| Electron | `/app/lib/NAME/resources` holds the app's resources | `/app/lib/NAME/resources` links to `/app/extra/resources` |
| Wine | `/app/opt/NAME` holds the program | `/app/opt/NAME` links to `/app/extra/program` |
| .run | `/app/opt/NAME` | `/app/extra/opt/NAME`, like any extra-data archive |

Electron manifests that unpack a .dmg or an NSIS installer get a 7-Zip
module, pinned to the same commit and built the same way as in Flathub's
org.winehq.Wine manifest. The Wine base app ships 7z already. On the 26.08
branch and later, the module overrides `CFLAGS_WARN_WALL` to build without
`-Werror`, because GCC 16 reports a false array-bounds warning in 7-Zip. That
variant hasn't been built here yet.

The tests convert each kind of input both ways, run the shipped helper
the way apply_extra would, and check that the result is byte for byte what
bundle mode copied.

### Output

```
out/
  com.vendor.App.json   flatpak-builder manifest (x-debpak block records reasons & provenance)
  app/                  staged /app tree (dir source of the manifest)
  report.txt            human-readable analysis
  report.json           machine-readable analysis
```

### The registry

debpak records each app it installs in `~/.local/share/debpak/apps.json`, with
the options you converted it with. debpak update uses it to redo the
conversion. For a converted snap, update asks the Snap Store for the current
revision (snapd isn't needed). For an app converted with `--url`, it downloads
the file again and compares checksums. Otherwise it checks whether the original
file changed on disk.

## Recipes

A recipe is a conversion's output folder minus build products, plus
recipe.json. `recipe make` refuses one when:

- the manifest has no extra-data source, so it would carry the vendor's files;
- a source is a local file or patch, a git source isn't pinned to a commit, or
  an archive or file source has no URL and SHA-256;
- `app/` holds a binary file other than an icon (unless `--allow-binaries`), a
  symbolic link, or more than 5 MiB in total.

recipe.json records the name, version, summary, route, the extra-data URL,
size and SHA-256, the permissions with debpak's reasons, an optional note, and
the SHA-256 of every file. index.json lists each recipe with the SHA-256 of
its recipe.json.

`debpak install` reads index.json from the collection (an HTTPS URL or a
folder), matches the name against app IDs, names and the last part of IDs,
then downloads recipe.json and checks it against the index. Every file it
lists is then checked against its own hash, and only the manifest and files
under `app/` are accepted, with no `..` or absolute paths. The manifest gets
the same source checks as `recipe make`. `app/bin/debpak-unpack` is replaced
by the installed debpak's own unpack.py, so the only install-time code a
reviewer has to read is the launchers and apply_extra. The recipe is kept in
`~/.local/share/debpak/recipes/ID`, built with flatpak-builder, and recorded
in the registry. `debpak update` compares the recipe's hash in the index with
the one installed.

The hashes make sure you get the recipe as the collection published it. They
can't tell you whether the collection itself is trustworthy; that comes from
reviewing pull requests to it.

Every manifest debpak writes records, under `x-debpak`, the app ID and the
convert options that can be repeated on another machine. Options naming local
paths (`--native-dir`, `--deps-dir`, `--runtime-index`) are listed separately,
and `--url` is left out because it changes with each version. `recipe make`
copies both into recipe.json, along with the check block. `recipe check
--apply` finds the newest download with the check, and if its URL differs from
the recipe's, downloads it and runs `convert` with the recorded options plus
`--mode extra-data --url NEW`. It then runs `recipe make` over the old
recipe, keeping its check block and marking the note as untested.

`recipe publish` builds each recipe with `flatpak-builder --repo`, signing
when given a key, then runs `flatpak build-update-repo --prune`. It writes
`debpak.flatpakrepo` (with the public key, base64-encoded), one `.flatpakref`
per app that names Flathub as the runtime source, and an index.html. A Flatpak
built on a base app contains the base, so a repository with Wine apps carries
Wine. OSTree stores identical files once, so the cost is per base app rather
than per app.

## debpak smoke

Apps load plugins, codecs and GPU libraries with dlopen() while they run, so
the import scan can't see them. debpak smoke runs the converted app with the
loader's own logging on (`LD_DEBUG=libs,files`). glibc logs every request and
every successful load, so a request with no load after it failed.

A missing library the app needs at startup is fatal. One it loaded on demand
and didn't find is degraded, since that feature won't work. Common GPU and
desktop probes (libcuda, libnvidia-*, libappindicator, ...) are
optional, because apps run fine without them. An undefined symbol error is a
crash and usually means a bundled library is too old. The report only covers
what that run loaded.

## winegap

The scanner follows the rules of Wine's loader:

- If a DLL the app imports statically is in neither Wine nor the app's folder,
  the app doesn't start.
- A function that a DLL stubs or lacks gets an "unimplemented function" thunk,
  which aborts only when the app calls it.
- A delay-loaded DLL fails on first use.
- A DLL in the app's folder wins over Wine's builtin.

winegap follows forwarders (such as kernel32 to kernelbase) and resolves imports
by ordinal. It checks each module against the index for that module's
architecture, so 32-bit helpers in a 64-bit app get the right answer. The index
comes from a Wine source tree, where each DLL's `.spec` file marks its stubs; an
index of installed DLLs can't tell stubs from real functions.

### Stub DLLs

`--stubs` writes a minimal PE DLL for each missing DLL that exports the names
and ordinals the app imports. Guides for running Lightroom on Wine do this by
hand. Stubs return 0, or trap with `--stub-mode trap`. 32-bit x86 stubs always
trap, because a stdcall stub can't know how many argument bytes to pop. A stub
DLL only gets the app past the loader; the features that call it still won't
work.

### Runtime lookups (guesses)

scan also reads the strings in each binary. A DLL name near a function name
(`LoadLibrary("dwmapi.dll")` with `GetProcAddress(h, "DwmFlush")`) suggests a
function the app looks up at runtime. winegap reports these only when Wine has
the function as a stub, which aborts if called; a function Wine lacks entirely
makes GetProcAddress return NULL, which apps usually check. They're tagged
`[guess]` and sit in the optional tier, so they never change the verdict.
`--no-guess` turns them off.

### What winegap trace reads from the log

| Seen in the log | Gap |
|---|---|
| `Call from ... to unimplemented function X.dll.Func, aborting` | crash, X.dll!Func |
| `err:module:import_dll Library X.dll (which is needed by ...) not found` | fatal if the .exe needs it, else degraded |
| `warn:module:load_dll Failed to load module "X.dll"` (LoadLibrary) | degraded |
| `fixme:<channel>:Func ... stub` | degraded; the Wine index names the DLL |
| `no instance created ... of class {CLSID}` / `class {CLSID} not registered` | degraded, com!{CLSID} |
| `wine: Unhandled page fault ...` + backtrace | crash in the module of frame 0 |
| other fixme lines | counted and listed in the notes (usually harmless) |

With an index, a gap the static scan predicted and the trace confirmed is
marked both; the others are runtime. Run counts show as `[seen running x3]`.
At the timeout, winegap stops the app, and with `--prefix` it also shuts down
that prefix's wineserver.

Wine doesn't log a function that returns a different result than Windows
would; finding that takes the same task run on Windows. winegap flags .NET
assemblies and kernel drivers (anti-cheat, DRM, hardware) but doesn't analyze
managed P/Invoke calls.

## machgap

The scanner handles universal (fat) binaries; `@rpath`, `@loader_path` and
`@executable_path` inside the bundle; re-exported libraries (libSystem); weak
linking; flat-namespace lookups; and platform checks. It rejects iOS and
Catalyst binaries, and apps with no slice for the index's architecture.

machgap recognises Darling's stubs by the log string each one prints,
`STUB: <name> called`. If your Darling version words it differently, pass
`--stub-pattern REGEX`.

Objective-C dispatches methods by selector at runtime, so a class that exists
can still lack a method the app calls. The report warns about this whenever an
app references ObjC classes.

## gaprank

gaprank ranks gaps by how many apps they affect. The sole column counts the
apps for which a gap is the only fatal one: fixing that gap alone makes them
start. The seen column counts apps where a traced run hit the gap. Rows sort
by tier, then sole, then seen, then the number of apps.
