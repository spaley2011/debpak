#!/usr/bin/env bash
# Fork every project under third_party/ into your GitHub account and point
# the submodules at the forks. Safe to re-run: GitHub returns the existing
# fork if there already is one.
#
#   scripts/fork-upstreams.sh            fork, repoint .gitmodules, add "upstream" remotes
#   scripts/fork-upstreams.sh --sync     update each fork's default branch from its upstream
#   scripts/fork-upstreams.sh --dry-run  show what would happen
#
# Needs: gh (logged in with `gh auth login`), git. Set OWNER to fork into an
# organization instead of your user account.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

mode=fork
case "${1:-}" in
  --sync) mode=sync ;;
  --dry-run) mode=dry ;;
  "") ;;
  *) echo "usage: $0 [--sync|--dry-run]" >&2; exit 2 ;;
esac

command -v gh >/dev/null || { echo "gh is not installed: https://cli.github.com" >&2; exit 1; }
OWNER="${OWNER:-$(gh api user --jq .login)}"
org_arg=()
[ "$OWNER" != "$(gh api user --jq .login)" ] && org_arg=(-f organization="$OWNER")

slug() { sed -E 's#^https://github.com/##; s#\.git$##' <<<"$1"; }

git config -f .gitmodules --get-regexp '\.path$' | while read -r _ path; do
  upstream_url=$(git config -f .gitmodules "submodule.$path.upstream" || git config -f .gitmodules "submodule.$path.url")
  up=$(slug "$upstream_url")
  case "$mode" in
    dry)
      echo "$path: fork $up -> $OWNER/${up#*/}" ;;
    sync)
      fork=$(slug "$(git config -f .gitmodules "submodule.$path.url")")
      if [ "${fork%%/*}" = "$OWNER" ]; then
        echo "$path: syncing $fork from $up"
        gh repo sync "$fork" --source "$up" || echo "  (sync failed; resolve it on GitHub)" >&2
      else
        echo "$path: not forked yet, skipping"
      fi ;;
    fork)
      # POST /forks is idempotent and returns the fork's name right away
      # (GitHub finishes copying in the background).
      fork=$(gh api -X POST "repos/$up/forks" -F default_branch_only=true "${org_arg[@]}" --jq .full_name)
      echo "$path: $up -> $fork"
      git submodule set-url "$path" "https://github.com/$fork.git"
      git config -f .gitmodules "submodule.$path.upstream" "https://github.com/$up.git"
      if [ -e "$path/.git" ]; then
        git -C "$path" remote set-url origin "https://github.com/$fork.git"
        git -C "$path" remote add upstream "https://github.com/$up.git" 2>/dev/null ||
          git -C "$path" remote set-url upstream "https://github.com/$up.git"
      fi ;;
  esac
done

if [ "$mode" = fork ]; then
  git add .gitmodules
  echo
  echo "Submodules now point at your forks. Review and commit:"
  echo "  git diff --cached .gitmodules && git commit -m 'third_party: use forks'"
fi
