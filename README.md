# debpak

Import-gap analysis for running software outside its home platform. One engine has three backends:

| Tool      | Input                         | Target                    | What it answers |
|-----------|-------------------------------|---------------------------|-----------------|
| `debpak`  | Linux `.deb` (ELF)            | Flatpak runtime           | Which libraries are missing? Builds the Flatpak manifest. |
| `winegap` | Windows app (PE)              | Wine / Proton             | Will it start? Which functions are stubs? Generates stub DLLs. |
| `machgap` | macOS `.app` (Mach-O)         | Darling                   | Will dyld load it? Which symbols and classes are missing or stubbed? |
| `gaprank` | reports from any of the above | the maintainers           | Which single fix unblocks the most apps? |

It also ships **`appbridge`**, a launcher (CLI and Qt GUI) for Microsoft 365,
Adobe Creative Cloud and other Windows-only work apps. It drives the community
projects that make those apps run (forked under [`third_party/`](third_party/README.md))
and puts the apps in your desktop's app menu. [Jump to appbridge](#appbridge-windows-work-apps-on-the-linux-desktop).

Each backend parses what a binary imports (ELF `DT_NEEDED` and symbol versions,
PE import and delay-import tables, Mach-O linked dylibs and two-level
namespace bindings). It compares that against an index of what the target
environment provides, and classifies every gap by how the platform's loader
would react:

- **fatal**: the app won't start (a missing library, or a missing non-weak
  Mach-O symbol, since dyld binds at launch).
- **crash**: the app starts but aborts if it reaches the function (Wine stubs
  and missing exports).
- **degraded**: the function exists as a stub that returns nil/0 (Darling stubs).
- **optional**: the gap is in a weak or delay-loaded import, or in a plugin
  that nothing links statically.

All parsers (ELF, PE, Mach-O including universal binaries, and export tries)
are pure Python with no dependencies.

## Status

Early MVP (0.1). The Wine and Darling backends are tested against spec-conformant
synthetic binaries (and `objdump` for PE), not yet against a real app corpus. The analysis, gap resolution and manifest generation are
covered by an end-to-end test suite that builds real `.deb` fixtures. Real-world
builds with `flatpak-builder` have **not** been validated broadly yet, so treat
generated manifests as a strong first draft and review them.

## Install

```sh
pip install .            # installs debpak, winegap, machgap, gaprank, appbridge; no runtime dependencies
pip install '.[gui]'     # adds PySide6 for appbridge-gui (on KDE, prefer your distro's PySide6/PyQt6, see below)
pip install '.[zstd]'    # optional: pure-Python zstd (otherwise uses the zstd or dpkg-deb binary)
```

Requires Python 3.10+. Gap analysis needs the target runtime installed
(`flatpak install flathub org.freedesktop.Platform//25.08`) or a saved index file.

## debpak: .deb to Flatpak

```sh
# What would conversion involve? (no runtime needed for a basic report)
debpak inspect vendor-app_1.0_amd64.deb
debpak inspect vendor-app_1.0_amd64.deb --runtime org.freedesktop.Platform//25.08

# Convert, filling library gaps from a Debian mirror...
debpak convert vendor-app_1.0_amd64.deb --app-id com.vendor.App \
    --mirror https://deb.debian.org/debian --suite stable -o out/

# ...or from .debs you downloaded yourself (e.g. with `apt download`)
debpak convert vendor-app_1.0_amd64.deb --app-id com.vendor.App --deps-dir ./debs -o out/

# Don't redistribute the vendor's binaries: download the .deb at install time
debpak convert vendor-app_1.0_amd64.deb --app-id com.vendor.App \
    --mode extra-data --url https://vendor.example/app_1.0_amd64.deb -o out/

# Build and install
flatpak-builder --user --install --force-clean --install-deps-from=flathub out/build-dir out/com.vendor.App.json
```

`convert` exits with status 2 and writes nothing if it finds blockers or
unresolvable required libraries. Use `--force` to write a manifest anyway.

### Output

```
out/
  com.vendor.App.json   flatpak-builder manifest (x-debpak block records reasons & provenance)
  app/                  staged /app tree (dir source of the manifest)
  report.txt            human-readable analysis
  report.json           machine-readable analysis
```

### How debpak works

1. **Extract**: pure-Python `ar` parsing; gz/xz/bz2/zstd data members.
2. **Analyze**: a built-in, dependency-free ELF reader collects `DT_NEEDED`,
   sonames, RPATH/RUNPATH, symbol-version requirements and imported symbols
   from every ELF in the package. Executables are dependency roots.
   Libraries needed only by plugins are tracked separately as optional.
3. **Classify**: Electron, Qt5/Qt6, GTK3/GTK4, Java or plain ELF. This drives the
   runtime suggestion and special handling (Electron → `zypak` + Electron BaseApp).
4. **Runtime index**: scans the installed runtime's `files/` tree on the host
   and caches the library names and symbol versions it provides in
   `~/.cache/debpak`. GL/Vulkan/driver libraries count as provided by the GL extension.
5. **Gap fill**: missing sonames are looked up in local `.deb`s or a mirror's
   `Contents-<arch>` index. Only the matching library files are copied into
   `/app/lib/debpak`, and their own dependencies are resolved iteratively.
   Core glibc libraries are never bundled.
6. **Version check**: every required symbol version (for example `GLIBC_2.38` or
   `GLIBCXX_3.4.32`) is checked against what the runtime or bundle defines. A
   glibc mismatch is a blocker, and the fix is a newer runtime branch.
7. **Host integration**: maintainer scripts and payload paths are classified.
   Cache refreshes are ignored, setuid sandboxes are handled, and systemd units,
   kernel modules, PAM, and udev are flagged as blockers or warnings.
8. **Paths**: the payload maps to `/app` (`usr/*` → `/app/*`, `opt/*` → `/app/opt/*`).
   Hardcoded `/opt/...` paths in shell scripts are rewritten, and paths hardcoded
   in binaries are reported.
9. **Desktop integration**: the `.desktop` file is renamed to the app ID and its
   `Exec=` points to a generated wrapper. `env VAR=...` prefixes move into the
   wrapper. Icons are exported under the app ID and an AppStream metainfo file
   is generated.
10. **Permissions**: inferred from linked libraries and imported symbols. Each
    permission's reason is recorded in the manifest and report. debpak never
    grants `--filesystem=home` unless you pass `--permissive`.


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

The scanner models Wine's loader behavior:
- A statically imported DLL that exists neither in Wine nor next to the app
  prevents startup.
- A function that is stubbed or missing in an existing DLL gets an
  "unimplemented function" thunk that aborts only when called.
- Delay-loaded DLLs fail on first use.
- DLLs shipped in the app directory take precedence over builtins.

Forwarders (such as kernel32 to kernelbase) are followed, and imports by
ordinal are resolved. Each module is checked against the index for its own
architecture, so 32-bit helpers are handled.

**Stub DLLs.** The `--stubs` option writes a minimal PE DLL for each missing DLL,
exporting exactly the names and ordinals the app imports. This automates the
manual fix from the widely shared Lightroom-on-Linux recipe. Stubs return 0,
or trap with `--stub-mode trap`. 32-bit x86 stubs always trap, because a
stdcall stub can't know how many argument bytes to pop. Stub DLLs only get
the app past the loader; features that call them won't work.

**Limitations.** Functions resolved with `GetProcAddress` at runtime, COM
interfaces, and behavioral bugs in implemented functions are not visible to
import analysis. .NET assemblies are flagged, but their managed P/Invoke
calls are not analyzed. Kernel drivers (anti-cheat, DRM, hardware) are
flagged. Installers must be installed or extracted first.

## machgap: macOS apps on Darling

```sh
machgap index --darling-root /usr/local/libexec/darling --arch x86_64
machgap scan Some.app --index ~/.cache/debpak/darling/installed_x86_64.json -o some.gap.json
machgap scan Some.zip --index ...         # a .zip containing an .app works too
```

The scanner handles universal (fat) binaries, `@rpath`, `@loader_path` and
`@executable_path` resolution inside the bundle, re-exported libraries
(libSystem), weak linking, flat-namespace lookups, and platform checks. It
rejects iOS or Catalyst binaries, and apps without a slice for the index's
architecture.

**Stub detection.** Darling stubs are detected heuristically from
generated log strings of the form `STUB: <name> called`. Pass
`--stub-pattern REGEX` if a Darling version logs stubs differently.

**Limitations.** Objective-C methods are dispatched by selector at runtime,
so a class that exists can still lack methods the app calls. The report says
so whenever an app references ObjC classes. `.dmg` files must be extracted
first (for example with `7z x`).

## gaprank: what to fix first

```sh
gaprank reports/          # any mix of winegap / machgap / debpak report JSONs
```

`gaprank` ranks gaps by how many apps they affect. The **sole** column
counts apps for which a gap is the *only* fatal one, meaning fixing it alone
makes those apps start. Run it across a corpus of popular apps to get a
prioritized to-do list for Wine or Darling developers.

## appbridge: Windows work apps on the Linux desktop

Running Office or Photoshop on Linux takes a different project for each app,
each with its own commands, prefixes and shortcuts. `appbridge` puts one
launcher in front of all of them. It knows several ways to run each app, checks
which ones are set up on your machine, and uses the best one that works:

| Apps | Ways to run them, best first |
|---|---|
| Word, Excel, PowerPoint, Outlook, OneNote, Access, Publisher | Wine/Proton via [office365_flake](https://github.com/Tombert/office365_flake) (no VM) → Windows VM via [LinOffice](https://github.com/eylenburg/linoffice) → Windows VM via [WinApps](https://github.com/winapps-org/winapps). Outlook and OneNote also fall back to [Prospect Mail](https://github.com/julian-alarcon/prospect-mail) and [P3X OneNote](https://github.com/patrikx3/onenote). |
| Photoshop, Illustrator, Premiere Pro, After Effects, InDesign, InCopy, Animate, Audition, Media Encoder, Bridge, Lightroom (Classic), Acrobat, Creative Cloud | Wine via [LinDobe](https://github.com/le-birnes/LinDobe) (built on [PhialsBasement's patches](https://github.com/PhialsBasement/wine-adobe-installers)) → WinApps |
| Teams, OneDrive | [teams-for-linux](https://github.com/IsmaelMartinez/teams-for-linux) (Flathub or native); [onedrive](https://github.com/abraunegg/onedrive) as a systemd user service |
| Visio, Project, Power BI, SQL Server Management Studio, Visual Studio, full Windows desktop | WinApps (Wine can't run these) |
| Your company's own Windows tools | Wine or Proton (umu-launcher), in a prefix per app: `appbridge add` |

appbridge doesn't install or crack anything itself: you bring your own Microsoft
365 and Adobe subscriptions, and the upstream project does the installing.

### Command line

```sh
appbridge list                       # every app, its status, and how it would run
appbridge info word                  # all the ways Word can run here and what each one is missing
appbridge install word               # runs the backend's installer (here: ms365 install)
appbridge launch word ~/report.docx  # open files; `--backend winapps` to force a route
appbridge stop photoshop             # close Adobe apps cleanly (adobewine off)
appbridge prefer word winapps        # always use the VM for Word (`auto` to undo)
appbridge integrate                  # add every ready app to the app menu
appbridge integrate --default-handlers word excel   # ...and make them the default for .docx/.xlsx
appbridge integrate --remove         # take all of appbridge's entries out again
appbridge doctor                     # what's installed: Nix, Flatpak, FreeRDP, KVM, kbuildsycoca, ...

# your own Windows app
appbridge add expenses --name "Expense Reports" --exe 'C:\Program Files\Acme\Expenses.exe' \
    --installer ~/Downloads/AcmeSetup.exe --runner umu --mime application/x-acme-expense
appbridge install expenses           # runs the installer in its own prefix
appbridge run expenses regedit       # any program in that prefix

# which Windows functions is Wine missing for an installed app? (winegap, see below)
appbridge gap photoshop --index ~/.cache/debpak/wine/11.8_x86_64.json
```

`launch` exits with status 3 and says what's missing when an app isn't ready.
When it was started from the app menu, it shows that as a desktop notification.

### Window and tray

`appbridge-gui` (or `appbridge gui`) lists the apps by suite with search and
their status. For the selected app you can open it or a file, install or
repair it, stop it, choose how it runs, add it to the app menu, or make it the
default for its file types. You can also drop files onto an app in the list to
open them there. Steps that ask questions, such as WinApps setup or the
OneDrive sign-in, open in Konsole (or your desktop's terminal). The tray menu
launches any ready app. `appbridge-gui --tray` starts the tray only, so you can
put it in Autostart.

The window uses Qt 6 through PySide6 or PyQt6. On KDE Plasma, install them from
your distribution (`python3-pyside6`, `pyside6`, `python3-pyqt6`) rather than
pip. The distro build uses the system Qt, so you get the Breeze style and your
Plasma colours and fonts. The pip wheels bring their own Qt without Plasma's
platform theme.

### Desktop integration

`appbridge integrate` writes standard freedesktop entries to
`~/.local/share/applications/appbridge-<app>.desktop`. Plasma, GNOME, Xfce,
Cinnamon and others read these:

- The apps appear in the app menu (Kickoff, Activities), in KRunner and GNOME
  search, and in Dolphin's and Nautilus' **Open With** for their file types.
- `StartupWMClass` matches the window class Wine gives each app (`winword.exe`),
  so the task manager groups the windows under the right icon and pinned
  launchers work.
- Right-click actions offer the other ready backends ("Open with Windows VM
  (WinApps)") and *Stop*.
- Icons come from the installed app's own `.exe` (extracted from its icon
  resources by debpak's PE reader) or from the WinApps icon. If neither exists,
  a theme icon is used. Nothing proprietary ships with appbridge.
- Afterwards it runs `kbuildsycoca6` (or 5) so Plasma sees the change right
  away, plus `update-desktop-database` and `xdg-desktop-menu forceupdate`.

Apps that install their own entry (Teams, Prospect Mail and other Flatpak or
native packages) are skipped. So are apps that already have an entry with the
same name, for example from `adobewine launchers` or the flake's `shortcuts`.
Pass `--force` to add an appbridge entry anyway.

### Configuration

- `~/.config/appbridge/config.json`: preferred backend per app.
- `~/.config/appbridge/apps.json`: your custom apps.
- Logs of apps launched from the menu or window: `~/.local/state/appbridge/logs/<app>.log`.
- Every backend honours its project's own variables (`MS365_PREFIX`,
  `ADOBEWINE_HOME`, `~/.config/winapps/winapps.conf`, ...).

### The forks

`third_party/` holds each upstream project as a submodule pinned to a tested
commit. Their licenses are GPL, LGPL, AGPL and MIT, and none of their code is
copied into debpak.

```sh
scripts/fork-upstreams.sh            # fork them all into your GitHub account (needs `gh auth login`)
git commit -am "third_party: use forks"
scripts/fork-upstreams.sh --sync     # later: pull upstream fixes into your forks
```

Once the submodules point at your forks, appbridge uses them too. For example,
the Microsoft 365 backend runs `nix run github:<you>/office365_flake#ms365`, or
the checked-out submodule when it's present.

### Limits

- appbridge can only be as good as the project behind each route. Microsoft 365
  on Proton and Adobe on LinDobe are new and move fast; see their own READMEs
  for what works. The VM routes run real Windows and are the most compatible.
- Whether an app is installed inside a Windows VM is known only after WinApps
  setup has scanned the VM. Until then appbridge assumes it is.
- So far the Qt window has only been tested against a stand-in for Qt. Run `tests/test_appbridge_gui.py` with PySide6 or PyQt6 installed to test it
  for real (offscreen).

## debpak limitations

- Static analysis can't see `dlopen()`. Smoke-test the result
  (`flatpak run --env=LD_DEBUG=libs <app-id>` shows failed loads).
- Paths hardcoded inside binaries can't be rewritten.
- Packages that need host integration (drivers, VPNs that manage interfaces,
  system daemons) can't be Flatpaks. debpak says so instead of guessing.
- The generated metainfo uses `LicenseRef-proprietary`; fix it before publishing.
- Default runtime branches in `analyze.py` need occasional bumping.

## Roadmap

- Build a corpus runner that scans many apps and publishes `gaprank` tables for Wine and Darling.
- Add runtime confirmation: run under `WINEDEBUG`, `DYLD_PRINT_*`, or `LD_DEBUG`, and merge the observed failures into the report.
- `debpak smoke` command: run the built app under `LD_DEBUG` and report
  `dlopen` failures.
- Emit `x-checker-data` for extra-data sources (flatpak-external-data-checker).
- Pick the runtime automatically by comparing gap sizes across installed runtimes.
- Translate more maintainer-script patterns; add GSettings schema compilation.
- AppImage input.

## Development

```sh
PYTHONPATH=src:tests python3 -m unittest discover -s tests -v
```

The Wine, Darling, ranking and appbridge tests need nothing extra (appbridge's
tests fake a whole desktop in a temporary home; the GUI test uses real Qt
offscreen when PySide6 or PyQt6 is installed, a stand-in otherwise). They generate PE and
Mach-O files with the built-in writers, and PE output is cross-checked with
`objdump` when it's available. The debpak integration tests need `gcc` and `dpkg-deb` on x86_64. They compile
small C programs and libraries, package them as real `.deb`s (xz and zstd), and
check the whole pipeline. The tests include running the converted binary
against the bundled libraries.

## License

MIT
