#!/usr/bin/env bash
# test-uv-detection.sh - table tests for reusable-pr-quality.yml's uv
# detection (compute_uses_uv / compute_has_uv_cache_target).
#
# WHY THIS EXISTS (issue #23): `enable-cache` on the setup-uv step is wired
# directly to has_uv_cache_target, and setup-uv THROWS when
# cache-dependency-glob is non-empty but matches zero files. The guard against
# that has one case it must get right, and that case had NEVER executed:
#
#     uses_uv == true via the root-Makefile grep, with NO python manifest
#     anywhere in python-directory -> has_uv_cache_target MUST be false
#
# A self-test fixture cannot reach it. uses_uv's Makefile branch is
# root-scoped, so making it true requires this repo's own root Makefile to
# mention `uv`, which would turn uv detection on for every self-test job at
# once (see self-test.yml's root-makefile-and-semgrep comment for why the
# equivalent trade-off was already paid once and is not worth paying again).
# So it is tested here instead, against the real functions extracted from the
# workflow - never a copy, which would drift.
#
# WHICH CHANGE TURNS THIS RED: drop the `[ -f "$1/uv.lock" ] ||` /
# `[ -f "$1/pyproject.toml" ] ||` guards from compute_has_uv_cache_target so
# it always returns true, and U01 fails - which is precisely the shape that
# hard-fails the setup-uv step for a repo whose Makefile mentions uv before
# any manifest exists. Remove the word-boundary guard from compute_uses_uv's
# grep and U07 fails.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="$REPO_ROOT/.github/workflows/reusable-pr-quality.yml"
HELPERS="$(mktemp)"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$HELPERS" "$SCRATCH"' EXIT

sed -n '/# BEGIN uv-detection-helpers/,/# END uv-detection-helpers/p' "$WORKFLOW" >"$HELPERS"

# Same guard discipline as scripts/test-makefile-trust.sh: prove the
# extraction really found the block before trusting a single result, and check
# the END marker separately - `sed` with an unmatched closing address runs to
# end of file, which would otherwise pass the other two guards while sourcing
# the whole workflow as shell.
if [ ! -s "$HELPERS" ]; then
	echo "FATAL: extracted zero lines from $WORKFLOW - the BEGIN/END uv-detection-helpers markers are missing or renamed." >&2
	exit 1
fi
if ! grep -q '# END uv-detection-helpers' "$HELPERS"; then
	echo "FATAL: extraction from $WORKFLOW ran past the end of the helper block - the '# END uv-detection-helpers' marker is missing or renamed." >&2
	exit 1
fi
for fn in compute_uses_uv compute_has_uv_cache_target; do
	if ! grep -q "^[[:space:]]*${fn}() {" "$HELPERS"; then
		echo "FATAL: extracted block from $WORKFLOW does not define ${fn}() - markers no longer bracket the real helpers." >&2
		exit 1
	fi
done
echo "Extracted $(wc -l <"$HELPERS") lines of helpers from ${WORKFLOW#"$REPO_ROOT"/}"

# shellcheck source=/dev/null
. "$HELPERS"

FAILURES=0
CASES=0

# assert_uv <name> <makefile-content|-> <files-in-pythondir,comma-sep|-> \
#           <expected-uses_uv> <expected-has_uv_cache_target>
#
# Builds a throwaway tree with a root Makefile and a `pydir/` subdirectory,
# then runs the extracted functions against it exactly as the workflow's
# "Detect project layout" step does.
assert_uv() {
	local name="$1" makefile="$2" files="$3" want_uses="$4" want_cache="$5"
	CASES=$((CASES + 1))

	local root="$SCRATCH/case"
	rm -rf "$root"
	mkdir -p "$root/pydir"
	if [ "$makefile" != "-" ]; then
		# %b, not %s: the table writes recipes as '...\n\tuv run pytest', and
		# a literal backslash-t would put the LETTER 't' immediately before
		# 'uv', which the word-boundary grep then correctly rejects - making
		# every Makefile case silently test the wrong thing. Caught by U01
		# failing on first run.
		printf '%b\n' "$makefile" >"$root/Makefile"
	fi
	if [ "$files" != "-" ]; then
		local f
		# shellcheck disable=SC2001 # a tr-based split would mangle nothing here, but sed is clearer
		for f in $(echo "$files" | tr ',' ' '); do
			: >"$root/pydir/$f"
		done
	fi

	local got_uses got_cache
	got_uses="$(cd "$root" && compute_uses_uv pydir)"
	got_cache="$(cd "$root" && compute_has_uv_cache_target pydir)"

	if [ "$got_uses" = "$want_uses" ] && [ "$got_cache" = "$want_cache" ]; then
		printf 'ok   %-56s uses_uv=%-5s cache_target=%s\n' "$name" "$got_uses" "$got_cache"
	else
		printf 'FAIL %-56s expected uses_uv=%s/cache=%s, got uses_uv=%s/cache=%s\n' \
			"$name" "$want_uses" "$want_cache" "$got_uses" "$got_cache"
		FAILURES=$((FAILURES + 1))
	fi
}

echo
echo "--- the case CI cannot reach: uv via Makefile, no manifest at all ---"
# THE one that matters. enable-cache is wired straight to the second value, so
# a true here is the zero-match-glob hard failure the guard exists to prevent.
assert_uv "U01 Makefile says uv, pydir empty"        'ci:\n\tuv run pytest' -                    true  false
assert_uv "U02 Makefile mentions uv in a comment"    '# uses uv for envs'  -                     true  false
assert_uv "U03 Makefile var named uv_version"        'uv_version := 0.12'  -                     true  false

echo
echo "--- uv via Makefile, with something for the glob to match ---"
assert_uv "U04 Makefile says uv + requirements.txt"  'ci:\n\tuv run pytest' requirements.txt      true  true
assert_uv "U05 Makefile says uv + pyproject.toml"    'ci:\n\tuv run pytest' pyproject.toml        true  true
assert_uv "U06 Makefile says uv + requirements-dev"  'ci:\n\tuv run pytest' requirements-dev.txt  true  true

echo
echo "--- word-boundary: a longer word containing 'uv' is not uv ---"
assert_uv "U07 uvicorn must not count as uv"         'ci:\n\tuvicorn app:x' -                     false false
assert_uv "U08 'nouv' must not count as uv"          'ci:\n\tnouv thing'    -                     false false

echo
echo "--- no Makefile signal: the pyproject.toml + uv.lock branch ---"
assert_uv "U09 pyproject + uv.lock, no Makefile"     -                     pyproject.toml,uv.lock true  true
assert_uv "U10 pyproject only, no Makefile"          -                     pyproject.toml         false true
assert_uv "U11 uv.lock only, no Makefile"            -                     uv.lock                false true
assert_uv "U12 nothing anywhere"                     -                     -                      false false
assert_uv "U13 unrelated Makefile + pyproject"       'ci:\n\tpytest'       pyproject.toml         false true

echo
if [ "$FAILURES" -ne 0 ]; then
	echo "::error::$FAILURES of $CASES uv-detection cases FAILED."
	exit 1
fi
echo "All $CASES uv-detection cases passed."
