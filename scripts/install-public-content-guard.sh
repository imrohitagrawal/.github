#!/usr/bin/env bash
# install-public-content-guard.sh - install the public-content guard's git pre-push hook on
# this machine.
#
# What it does (and nothing else):
#   1. Checks git >= 2.54 (older git ignores hook.* config, so the guard would silently not
#      run), gitleaks, gh and python3 >= 3.9. Missing anything: exits non-zero, changes nothing.
#   2. Sets GLOBAL git config keys, through `git config --global` only:
#        hook.public-content.command = this checkout's hooks/pre-push
#        hook.public-content.event   = pre-push   (exactly once)
#        public-content.notesDir     = $PRIVATE_NOTES_DIR (only when that is set)
#      A config-based hook runs for every repository, BEFORE the repo's own pre-push hook
#      (which still runs), and is not switched off by core.hooksPath. core.hooksPath is never
#      touched. If hook.public-content.command or public-content.notesDir already holds a
#      different value, it refuses and changes nothing.
#
# PRIVATE_NOTES_DIR, when set at install time, is written into the hook command, so the hook
# reads the private term list from there. It is also recorded as public-content.notesDir:
# the scanner then refuses to run when PRIVATE_NOTES_DIR names a different folder, so a
# stray variable cannot switch the private terms off. Running it again changes nothing.
# See docs/public-content-guard.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREPUSH="$ROOT/hooks/pre-push"

die() {
  echo "install-public-content-guard: $*" >&2
  exit 1
}

# quote WORD: WORD as one shell word (single quotes, embedded ' escaped).
quote() {
  local q="'\\''"
  printf "'%s'" "${1//\'/$q}"
}

# ---------------------------------------------------------------- requirements
command -v git >/dev/null 2>&1 || die "git is not on PATH"
gv="$(git --version 2>/dev/null | awk '{print $3}')"
gmaj="${gv%%.*}"
grest="${gv#*.}"
gmin="${grest%%.*}"
case "$gmaj$gmin" in
  '' | *[!0-9]*) die "could not read the git version from '$(git --version 2>/dev/null)'; git 2.54 or newer is required" ;;
esac
if [ "$gmaj" -lt 2 ] || { [ "$gmaj" -eq 2 ] && [ "$gmin" -lt 54 ]; }; then
  die "git $gv is too old: git 2.54 or newer is required (older git ignores hook.* config, so the guard would not run)"
fi
command -v gitleaks >/dev/null 2>&1 || die "gitleaks is not on PATH (the guard needs it; without it every push would be blocked)"
command -v gh >/dev/null 2>&1 || die "gh is not on PATH (the guard uses it to learn a repository's visibility)"
command -v python3 >/dev/null 2>&1 || die "python3 is not on PATH"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' ||
  die "python3 $(python3 -c 'import platform; print(platform.python_version())') is too old: 3.9 or newer is required"
[ -x "$PREPUSH" ] || die "$PREPUSH is missing or not executable"

# ---------------------------------------------------------------- git config (global)
notes="${PRIVATE_NOTES_DIR:-}"
envp=""
[ -z "$notes" ] || envp="PRIVATE_NOTES_DIR=$(quote "$notes") "
want="${envp}$(quote "$PREPUSH")"

# Check everything first, so a refusal changes nothing.
have="$(git config --global --get hook.public-content.command 2>/dev/null || true)"
if [ -n "$have" ] && [ "$have" != "$want" ]; then
  echo "install-public-content-guard: hook.public-content.command is already set to a different value:" >&2
  echo "  $have" >&2
  echo "Not changing it. Remove it first (git config --global --unset hook.public-content.command) if it should be replaced." >&2
  exit 1
fi
have_notes="$(git config --global --get public-content.notesDir 2>/dev/null || true)"
if [ -n "$notes" ] && [ -n "$have_notes" ] && [ "$have_notes" != "$notes" ]; then
  echo "install-public-content-guard: public-content.notesDir is already set to a different folder:" >&2
  echo "  $have_notes" >&2
  echo "Not changing it. Remove it first (git config --global --unset public-content.notesDir) if it should be replaced." >&2
  exit 1
fi

[ -n "$have" ] || git config --global hook.public-content.command "$want"
events="$(git config --global --get-all hook.public-content.event 2>/dev/null | grep -c '^pre-push$' || true)"
[ "${events:-0}" -gt 0 ] || git config --global --add hook.public-content.event pre-push
if [ -n "$notes" ] && [ -z "$have_notes" ]; then
  git config --global public-content.notesDir "$notes"
fi

echo "git: hook.public-content.command = $want"
echo "git: hook.public-content.event = pre-push"
if [ -n "$notes" ]; then
  echo "git: public-content.notesDir = $notes"
else
  echo "note: PRIVATE_NOTES_DIR is not set, so the hook checks the public rules only (no private terms)."
fi
echo "Check it with: git hook list pre-push"
