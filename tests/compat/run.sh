#!/usr/bin/env bash
# Run the compatibility suite (tests/compat/compat.py) inside tmux, so it
# survives a dropped SSH connection. Options go to compat.py; see --help.
#
#   tests/compat/run.sh --check
#   tests/compat/run.sh --send-to sophiap@sophia-macbookpro183.fios-router.home:Downloads/
#
# Detach with Ctrl+B then D; come back with: tmux attach -t debpak-compat
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
SESSION=debpak-compat

case " $* " in *" --help "*|*" -h "*|*" --check "*) exec python3 "$HERE/compat.py" "$@" ;; esac

if [ -n "${TMUX:-}" ]; then
  # keep the machine from suspending while the run goes on (desktops count an SSH session as idle)
  if command -v systemd-inhibit >/dev/null && systemd-inhibit --what=sleep:idle true 2>/dev/null; then
    exec systemd-inhibit --what=sleep:idle --who=debpak --why="compatibility run" \
      python3 "$HERE/compat.py" "$@"
  fi
  echo "(couldn't block sleep; if the machine suspends, run this again to continue where it stopped)"
  exec python3 "$HERE/compat.py" "$@"
fi
command -v tmux >/dev/null || { echo "tmux isn't installed: sudo apt install tmux"; exit 1; }
# terminals tmux doesn't know (kitty over SSH) make it refuse to start
infocmp "$TERM" >/dev/null 2>&1 || export TERM=xterm-256color
if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "A run is already going; attaching to it (Ctrl+B then D to leave it running)."
  exec tmux attach -t "$SESSION"
fi
# inside tmux this script runs again and takes the TMUX branch above
cmd="$(printf '%q ' "$HERE/run.sh" "$@"); echo; echo 'Finished. Press Enter to close this window.'; read -r"
exec tmux new-session -s "$SESSION" "$cmd"
