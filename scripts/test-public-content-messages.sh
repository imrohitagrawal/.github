#!/usr/bin/env bash
# test-public-content-messages.sh - when the guard blocks, its message must name the real cause,
# so the person or agent fixes that cause instead of bypassing the guard: a destination whose
# visibility could not be learnt (gh missing, signed out or failing) is named as such; a gitleaks
# that prints an unexpected warning is named with its version and the line it printed; and every
# "open an issue" hint says not to paste the matched text. It shares the harness in
# lib-public-content-test.sh with the other public-content suites.
#
# Runs on bash 3.2 and 5, macOS and Linux, against throwaway repositories under mktemp, with the
# REAL gitleaks from PATH and the harness's fake gh. Leaks are ASSEMBLED AT RUN TIME.

# shellcheck source=scripts/lib-public-content-test.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-public-content-test.sh"

echo "test-public-content-messages.sh"

echo "== a destination whose visibility could not be learnt"
# acme/unknown is not in the fake gh's table, so gh answers 404: the guard treats it as public.
mkpush unk "$(gh_url acme/unknown)"
printf 'see %s\n' "$HOMEP" >"$P/unk/notes.md"
git -C "$P/unk" add notes.md && git -C "$P/unk" commit -q -m "notes"
gpush "$P/unk" "$P/unk.git" origin main
# RED WHEN: a block on a destination gh could not answer for does not say so.
expect_rc "messages: a block on an unknown-visibility destination says so" 1 home-folder-path \
  "visibility could not be learnt" "gh auth status"

vis acme/known public
mkpush kn "$(gh_url acme/known)"
printf 'see %s\n' "$HOMEP" >"$P/kn/notes.md"
git -C "$P/kn" add notes.md && git -C "$P/kn" commit -q -m "notes"
gpush "$P/kn" "$P/kn.git" origin main
# RED WHEN: the visibility note is printed even when gh answered (partner of the case above).
expect_rc "messages: a block on a known public destination has no visibility note" 1 home-folder-path
if grep -q "visibility could not be learnt" "$ERR"; then
  bad "messages: the visibility note is absent when gh answered" "note printed"
else
  ok "messages: the visibility note is absent when gh answered"
fi

echo "== a gitleaks that prints an unexpected warning"
WRAP="$WORK/bin-wrn"
mkdir -p "$WRAP"
{
  printf '#!/bin/sh\nREAL=%s\n' "'$REAL_GITLEAKS'"
  cat <<'EOF'
if [ "$1" = version ]; then exec "$REAL" "$@"; fi
"$REAL" "$@"
rc=$?
echo "10:00AM WRN this flag is deprecated and will be removed" >&2
exit $rc
EOF
} >"$WRAP/gitleaks"
chmod +x "$WRAP/gitleaks"
printf 'All tests pass.\n' >"$WORK/clean.txt"
(PATH="$WRAP:$PATH" _run python3 "$SCAN" text --label demo <"$WORK/clean.txt")
# RED WHEN: an unexpected gitleaks warning blocks without naming the version or the line.
expect_rc "messages: an unexpected gitleaks warning is named with its version" 2 "could not check" \
  "8.30.1" "WRN" "deprecated"

echo "== issue hints say not to paste the matched text"
gpush "$P/kn" "$P/kn.git" origin main
# RED WHEN: the push block's "open an issue" hint does not warn against pasting the match.
expect_rc "messages: the push hint warns against pasting the matched text" 1 home-folder-path \
  "do not paste the matched text"

echo
echo "${PASS} passed, ${FAIL} failed, ${SKIPPED} skipped"
[ "$FAIL" -eq 0 ]
