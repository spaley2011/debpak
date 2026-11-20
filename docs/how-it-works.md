# How debpak works

This is the reference for what the tools check and why. The
[README](../README.md) covers how to use them.

- [Gap tiers and evidence](#gap-tiers-and-evidence)
- [debpak: the conversion pipeline](#debpak-the-conversion-pipeline)
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
   zypak and the Electron BaseApp).
4. debpak scans the installed runtime's `files/` tree on the host and caches
   the library names and symbol versions it provides in `~/.cache/debpak`.
   GL, Vulkan and driver libraries count as provided, since the GL extension
   supplies them.
5. Each missing soname is looked up in your local packages, an RPM
   repository, or a Debian mirror's `Contents-<arch>` index. Only the matching
   library files are copied into `/app/lib/debpak`, and then the same happens
   for their own dependencies. The core glibc libraries are never bundled.
6. Every required symbol version (`GLIBC_2.38`, `GLIBCXX_3.4.32`) has to exist
   in the runtime or the bundle. A glibc mismatch is a blocker, and a newer
   runtime branch fixes it.
7. Maintainer scripts and payload paths get sorted: cache refreshes are
   ignored, setuid sandboxes are handled, and systemd units, kernel modules,
   PAM and udev rules are reported as blockers or warnings.
8. Paths are mapped: `usr/*` goes to `/app/*` and `opt/*` to `/app/opt/*`.
   Hardcoded `/opt/...` paths in shell scripts are rewritten, and the ones
   compiled into binaries are reported.
9. The .desktop file is renamed to the app ID, its `Exec=` points at a
   generated wrapper, and any `env VAR=...` prefix moves into that wrapper.
   Icons are exported under the app ID, and an AppStream metainfo file is
   written.
10. Permissions are inferred from linked libraries and imported symbols, and
    the manifest and report give the reason for each. `--filesystem=home` is
    only granted if you pass `--permissive`.

### What each format unpacks to

| Input | Recognised by | Unpacked |
|---|---|---|
| `.deb` | ar archive | `data.tar.*` into `/`; maintainer scripts from `control.tar.*` |
| `.rpm` (Fedora, RHEL, openSUSE) | RPM lead | cpio payload (gzip, xz, lzma, bzip2, zstd) into `/`; `%pre`/`%post`/... checked like Debian's scripts; header and payload SHA-256 verified |
| `.pkg.tar.{zst,xz,gz}` (Arch) | file name | payload into `/`; `.PKGINFO` for name, version, URL, license; `.INSTALL` checked |
| `.AppImage` | ELF with AppImage magic | squashfs after the runtime, into `/opt/NAME`, with its .desktop file pointing at AppRun and its icon installed |
| `.snap`, or an installed snap (`/snap/NAME/current`) | squashfs magic, or `meta/snap.yaml` | `/opt/NAME`, with a launcher per app that sets the `$SNAP` variables snapd would; menu entries and icon from `meta/gui` |
| `.tar.gz`, `.tar.xz`, `.tar.zst`, `.zip` | file name / magic | `/opt/NAME` (a single top folder is stripped); entry point is the executable named like the app, or the largest one (`--exec` to choose) |

### Snaps

debpak ignores a snap's permission metadata (plugs, slots, interfaces) and
works out permissions from what the binaries link against, as it does for every
other format. A snap expects some libraries from its base snap; debpak fetches
those from the Ubuntu release the base is built on (core22 is jammy,
core24 is noble) unless you pass `--deps-dir`, `--mirror` or
`--no-auto-mirror`. Background services (daemon: apps) aren't converted.
debpak also skips snapcraft's desktop-extension launchers, since the Flatpak
runtime provides GTK and Qt.

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
