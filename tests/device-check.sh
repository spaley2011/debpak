#!/usr/bin/env bash
# Run the checks that need a real Linux machine, for debpak and appbridge,
# and write a report to send back.
#
#   tests/device-check.sh                setup, unit tests, live lookups, integration builds,
#                                        desnap dry run, appbridge
#   tests/device-check.sh --quick        skip the integration builds (they download several GB
#                                        of Flatpak runtimes and take a while)
#   tests/device-check.sh --real-apps    also convert, install and start Notepad++, Notion and
#                                        Cursor from the vendors' own downloads
#   tests/device-check.sh --sudo-checks  also check the apt pin or dnf5 drop-in against the real
#                                        package manager (asks for your password, writes one test
#                                        file under /etc and removes it again)
#   tests/device-check.sh --keep         leave the test apps installed
#
# Nothing outside your home folder changes without --sudo-checks. Test apps go
# into your user Flatpak installation and are removed again afterwards. The
# report is ~/debpak-device-report/report.txt (DEBPAK_REPORT_DIR to change it).
set -u

REPO=$(cd "$(dirname "$0")/.." && pwd)
OUT=${DEBPAK_REPORT_DIR:-$HOME/debpak-device-report}
QUICK=0 REAL=0 SUDO=0 KEEP=0
for a in "$@"; do
  case $a in
    --quick) QUICK=1 ;;
    --real-apps) REAL=1 ;;
    --sudo-checks) SUDO=1 ;;
    --keep) KEEP=1 ;;
    -h|--help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $a (see --help)" >&2; exit 2 ;;
  esac
done

mkdir -p "$OUT/logs" "$OUT/real"
REPORT=$OUT/report.txt
DETAILS=$OUT/.details
: > "$DETAILS"
SUMMARY=()
export PYTHONPATH="$REPO/src"
have() { command -v "$1" >/dev/null 2>&1; }

# step [-v] NAME "description" CMD...
# Runs CMD with its output in logs/NAME.log. -v copies the whole log into the
# report; otherwise only the last 60 lines, and only when it fails.
step() {
  local verbose=0
  if [ "$1" = -v ]; then verbose=1; shift; fi
  local name=$1 desc=$2; shift 2
  local log=$OUT/logs/$name.log start=$SECONDS rc st
  printf '%-44s ' "$desc"
  ( cd "$REPO" && "$@" ) > "$log" 2>&1
  rc=$?
  if [ $rc -eq 0 ]; then st=pass; else st=FAIL; fi
  echo "$st ($((SECONDS - start))s)"
  SUMMARY+=("$(printf '%-5s %-44s %6ss' "$st" "$desc" "$((SECONDS - start))")")
  {
    echo
    echo "===== $desc: $st (exit $rc, $((SECONDS - start))s, logs/$name.log)"
    if [ $verbose = 1 ]; then cat "$log"; elif [ $rc -ne 0 ]; then tail -n 60 "$log"; fi
  } >> "$DETAILS"
  return $rc
}

skip() {
  printf '%-44s skip: %s\n' "$1" "$2"
  SUMMARY+=("$(printf '%-5s %-44s  %s' skip "$1" "$2")")
}

# ---------------------------------------------------------------- environment
environment() {
  . /etc/os-release 2>/dev/null
  echo "system:      ${PRETTY_NAME:-unknown}, kernel $(uname -r), $(uname -m)"
  [ "$(uname -m)" = x86_64 ] || echo "WARNING: not x86_64; the Wine and Electron routes only target x86_64"
  for py in python3 python3.10 python3.11 python3.12 python3.13 python3.14; do
    have $py && echo "$py:$(printf '%*s' $((12 - ${#py})) '')$($py --version 2>&1)"
  done
  echo "flatpak:     $(flatpak --version 2>&1 || echo missing)"
  echo "builder:     $(flatpak-builder --version 2>&1 || echo missing)"
  echo "remotes:     user: $(flatpak remotes --user --columns=name 2>/dev/null | tr '\n' ' ')" \
       " system: $(flatpak remotes --system --columns=name 2>/dev/null | tr '\n' ' ')"
  echo "disk free:   $(df -h --output=avail "$HOME" | tail -1 | tr -d ' ') in $HOME"
  local f=/proc/sys/kernel/apparmor_restrict_unprivileged_userns
  [ -r $f ] && echo "apparmor_restrict_unprivileged_userns = $(cat $f)"
  if have bwrap; then
    if bwrap --ro-bind / / --unshare-user --uid 0 true 2>/dev/null; then echo "bwrap:       user namespaces work"
    else echo "bwrap:       CAN'T create a user namespace; Flatpak builds will fail" \
              "(on Ubuntu: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0)"; fi
  fi
  echo
  echo "tools for the sample apps (a missing one only skips the cases that need it):"
  local t missing=()
  for t in flatpak flatpak-builder xvfb-run cc x86_64-w64-mingw32-gcc makensis 7z innoextract msiextract \
           wixl unsquashfs curl git; do
    if have $t || { [ $t = 7z ] && { have 7zz || have 7za; }; }; then echo "  ok      $t"
    else echo "  missing $t"; missing+=("$t"); fi
  done
  if [ ${#missing[@]} -gt 0 ]; then
    echo
    echo "to install them (package names from memory; adjust if yours differ):"
    if have apt-get; then
      echo "  sudo apt install flatpak flatpak-builder xvfb xauth gcc gcc-mingw-w64-x86-64 nsis 7zip" \
           "innoextract msitools wixl squashfs-tools curl git"
    elif have dnf; then
      echo "  sudo dnf install flatpak flatpak-builder xorg-x11-server-Xvfb xorg-x11-xauth gcc mingw64-gcc" \
           "mingw32-nsis 7zip innoextract msitools squashfs-tools curl git"
    elif have pacman; then
      echo "  sudo pacman -S flatpak flatpak-builder xorg-server-xvfb xorg-xauth gcc mingw-w64-gcc 7zip" \
           "innoextract msitools squashfs-tools curl git   (nsis is in the AUR)"
    fi
  fi
  return 0
}

# ---------------------------------------------------------------- unit tests
unit_tests() {   # unit_tests PYTHON DIR
  PYTHONPATH="$2/src:$2/tests" "$1" -m unittest discover -s "$2/tests"
}

# ---------------------------------------------------------------- real apps
url_for() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2], ""))' "$OUT/urls.json" "$1" \
    2>/dev/null
}

# real_app KEY APP_ID SECONDS MODE [convert options...]
# Downloads the vendor's file, converts, builds and installs it, then starts
# it under xvfb-run. Still running after SECONDS counts as started.
real_app() {
  local key=$1 id=$2 secs=$3 mode=$4; shift 4
  local url file rc
  url=$(url_for "$key")
  if [ -z "$url" ]; then echo "no download URL (the lookup step failed for $key)"; return 1; fi
  file="$OUT/real/$(basename "${url%%\?*}")"
  echo "\$ curl $url"
  curl -fL --retry 2 -A debpak-device-check -o "$file" "$url" || return 1
  ls -l "$file"
  local args=(convert "$file" --app-id "$id" --anyway -o "$OUT/real/$key-out" "$@")
  [ "$mode" = extra-data ] && args+=(--mode extra-data --url "$url")
  echo "\$ debpak ${args[*]}"
  python3 -m debpak "${args[@]}" || return 1
  flatpak info --user "$id" || return 1
  echo "\$ xvfb-run -a timeout $secs flatpak run --user $id"
  xvfb-run -a timeout "$secs" flatpak run --user "$id"
  rc=$?
  if [ "$key" = cursor ]; then
    echo "\$ debpak smoke $id"
    xvfb-run -a python3 -m debpak smoke "$id" --timeout 30
  fi
  [ $KEEP = 1 ] || python3 -m debpak uninstall "$id" --delete-data
  case $rc in
    124) echo "RESULT: still running after ${secs}s, so it started"; return 0 ;;
    0)   echo "RESULT: exited cleanly within ${secs}s"; return 0 ;;
    *)   echo "RESULT: exited with status $rc within ${secs}s"; return 1 ;;
  esac
}

# ---------------------------------------------------------------- desnap
desnap_pm() {
  python3 - <<'EOF'
from debpak.desnap import package_manager
pm = package_manager()
print("package manager:", pm.name if pm else "none detected")
if pm:
    print("install hint:", pm.install_hint("example"))
    print("purge command:", " ".join(pm.purge_cmd()))
    try:
        print("removing snapd would remove:", pm.purge_preview() or "(nothing)")
    except Exception as e:
        print("purge preview failed:", repr(e))
EOF
}

sudo_block_check() {
  local pm
  pm=$(python3 -c 'from debpak.desnap import package_manager as p; m = p(); print(m.name if m else "")')
  case $pm in
    apt)
      local f=/etc/apt/preferences.d/debpak-device-check.pref
      [ -e $f ] && { echo "$f already exists; not touching it"; return 1; }
      echo "before:"; apt-cache policy snapd
      python3 -c 'from debpak.desnap import PIN_TEXT; print(PIN_TEXT, end="")' | sudo tee $f
      echo "with the pin:"; apt-cache policy snapd | tee "$OUT/logs/.pin"
      sudo rm -f $f
      echo "after removing it:"; apt-cache policy snapd
      grep -q 'Candidate: (none)' "$OUT/logs/.pin"
      ;;
    dnf)
      local d=/etc/dnf/libdnf5.conf.d made=0
      local f=$d/debpak-device-check.conf
      have dnf5 || { echo "dnf4 system: desnap prints the line to add instead of writing a drop-in"; return 0; }
      [ -e $f ] && { echo "$f already exists; not touching it"; return 1; }
      [ -d $d ] || { echo "$d doesn't exist yet; creating it for the test"; sudo mkdir -p $d && made=1; }
      echo "before:"; dnf5 -q repoquery snapd | tee "$OUT/logs/.before"
      python3 -c 'from debpak.desnap import DNF_TEXT; print(DNF_TEXT, end="")' | sudo tee $f
      echo "with the drop-in:"; dnf5 -q repoquery snapd | tee "$OUT/logs/.after"
      dnf5 --dump-main-config 2>/dev/null | grep -i excludepkgs
      sudo rm -f $f
      [ $made = 1 ] && sudo rmdir $d
      [ -s "$OUT/logs/.before" ] && [ ! -s "$OUT/logs/.after" ]
      ;;
    pacman)
      echo "Arch: expecting snapd not to be in the official repositories"
      ! pacman -Si snapd
      ;;
    *) echo "no supported package manager"; return 1 ;;
  esac
}

# ================================================================ run
echo "Report: $REPORT"
echo
step -v env "machine and tools" environment
REV_D=$(git -C "$REPO" log -1 --format='%h %s' 2>/dev/null)

for py in python3 python3.10 python3.11 python3.12 python3.13 python3.14; do
  have $py || continue
  [ "$py" != python3 ] && [ "$(readlink -f "$(command -v $py)")" = "$(readlink -f "$(command -v python3)")" ] && continue
  "$py" -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null || continue
  step "unit-debpak-$py" "debpak unit tests ($py)" unit_tests "$py" "$REPO"
done

APPBRIDGE=${APPBRIDGE_DIR:-$REPO/../appbridge}
if [ ! -d "$APPBRIDGE/src/appbridge" ]; then
  APPBRIDGE=$OUT/appbridge
  [ -d "$APPBRIDGE" ] || git clone -q --depth 1 https://github.com/spaley2011/appbridge "$APPBRIDGE"
fi
REV_A=$(git -C "$APPBRIDGE" log -1 --format='%h %s' 2>/dev/null)
step appbridge-unit "appbridge unit tests" unit_tests python3 "$APPBRIDGE"
step -v appbridge-doctor "appbridge doctor and list" \
  bash -c "cd '$APPBRIDGE' && PYTHONPATH=src python3 -m appbridge doctor; echo '[exit '\$?']';
           PYTHONPATH=src python3 -m appbridge list; echo '[exit '\$?']';
           python3 -c 'import PySide6' 2>/dev/null && echo 'Qt: PySide6 (GUI test drove the real window)' ||
           { python3 -c 'import PyQt6' 2>/dev/null && echo 'Qt: PyQt6 (GUI test drove the real window)' ||
             echo 'Qt: none installed, so the GUI test only checked the missing-Qt message'; }; true"

step -v lookups "live lookups (npm, GitHub, Flathub)" python3 tests/device_lookups.py "$OUT/urls.json"

ARCH=$(uname -m)
FLATPAK_OK=1
{ have flatpak && have flatpak-builder; } || FLATPAK_OK=0
if have bwrap && ! bwrap --ro-bind / / --unshare-user --uid 0 true 2>/dev/null; then FLATPAK_OK=0; fi
KEEPARG=(); [ $KEEP = 1 ] && KEEPARG=(--keep)

if [ $QUICK = 1 ]; then
  skip "integration builds" "--quick"
elif [ $FLATPAK_OK = 0 ]; then
  skip "integration builds" "flatpak, flatpak-builder or user namespaces missing (see machine and tools)"
else
  echo "(the integration builds download the Flatpak runtimes and base apps the first time: several GB)"
  [ "$ARCH" = x86_64 ] || echo "(on $ARCH the Wine cases are skipped: the Wine base app is x86_64 only)"
  step -v integ-25.08 "integration builds, runtime 25.08" \
    python3 tests/integration/run.py --work "$OUT/integration" "${KEEPARG[@]}"
  SUBSET=(--only deb --only electron-nsis-extra)
  [ "$ARCH" = x86_64 ] && SUBSET+=(--only wine-exe)
  step -v integ-26.08 "integration builds, runtime 26.08 (subset)" \
    python3 tests/integration/run.py --work "$OUT/integration-26.08" --branch 26.08 \
      "${SUBSET[@]}" "${KEEPARG[@]}"
  for w in "$OUT/integration" "$OUT/integration-26.08"; do
    [ -f "$w/results.json" ] || continue
    for c in $(python3 -c 'import json,sys; print(" ".join(r["case"] for r in json.load(open(sys.argv[1]))["results"] if r["status"] == "fail"))' "$w/results.json"); do
      { echo; echo "----- failed case $c ($w/$c.log), last 80 lines:"; tail -n 80 "$w/$c.log"; } >> "$DETAILS"
    done
  done
fi

if [ $REAL = 0 ]; then
  skip "real apps" "not asked for (--real-apps)"
elif [ $FLATPAK_OK = 0 ] || ! have xvfb-run || ! have curl; then
  skip "real apps" "needs flatpak, flatpak-builder, user namespaces, xvfb-run and curl"
else
  if [ "$ARCH" = x86_64 ]; then
    step -v real-notepadpp "real app: Notepad++ (Wine, zip)" \
      real_app notepadpp org.debpak.real.NotepadPlusPlus 90 bundle --writable
    step -v real-notion "real app: Notion (Electron, extra-data)" \
      real_app notion org.debpak.real.Notion 60 extra-data
  else
    skip "real app: Notepad++ (Wine, zip)" "the Wine base app is x86_64 only"
    skip "real app: Notion (Electron, extra-data)" "its native modules only have x86_64 Linux builds"
  fi
  if [ -n "$(url_for cursor)" ]; then
    step -v real-cursor "real app: Cursor (.deb)" real_app cursor org.debpak.real.Cursor 60 bundle
  else
    skip "real app: Cursor (.deb)" "no .deb URL found (see live lookups)"
  fi
fi

step -v desnap-pm "desnap: package manager" desnap_pm
if have snap && snap list >/dev/null 2>&1; then
  step -v desnap-dry "desnap --dry-run (changes nothing)" python3 -m debpak desnap --dry-run
else
  skip "desnap --dry-run" "snapd isn't installed or running"
fi
if [ $SUDO = 1 ]; then
  if sudo -v; then step -v sudo-block "keep snapd out (real package manager)" sudo_block_check
  else skip "keep snapd out (real package manager)" "sudo wasn't available"; fi
else
  skip "keep snapd out (real package manager)" "not asked for (--sudo-checks)"
fi

{
  echo "debpak device check, $(date '+%Y-%m-%d %H:%M %Z') on $(hostname)"
  echo "debpak:    $REV_D"
  echo "appbridge: $REV_A"
  echo "options:   quick=$QUICK real-apps=$REAL sudo-checks=$SUDO keep=$KEEP"
  echo
  printf '%s\n' "${SUMMARY[@]}"
  cat "$DETAILS"
} > "$REPORT"
rm -f "$DETAILS" "$OUT/logs/.pin" "$OUT/logs/.before" "$OUT/logs/.after"
echo
echo "Done. Send back $REPORT ($(du -h "$REPORT" | cut -f1))."
echo "To free the space the runtimes use afterwards: flatpak uninstall --user --unused"
