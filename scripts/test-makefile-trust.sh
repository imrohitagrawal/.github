#!/usr/bin/env bash
# test-makefile-trust.sh - table tests for reusable-pr-quality.yml's
# Makefile-trust helpers (extract_makefile_recipe / is_trivial_makefile_recipe
# / escape_for_ere / compute_makefile_trust).
#
# WHY THIS EXISTS (round-4, HIGH): compute_makefile_trust decides whether the
# native lint/typecheck/test step is SKIPPED in favour of a root Makefile
# target. Getting it wrong in the permissive direction is a silent false
# green - the gate reports success while the check that would have caught the
# bug never ran. Three separate bugs of exactly that shape have now shipped
# in this function (unescaped `.` in a directory value acting as a regex
# wildcard; `-` treated as a word boundary so `backend` matched
# `backend-legacy`; and Make's `-` ignore-error prefix not recognised, so a
# `-true` recipe earned full trust). All three were found by hand-reproducing
# the function in a scratch directory - never by a test, because there was no
# test.
#
# The functions live inside a `run:` block in the workflow YAML, so they
# cannot be sourced directly. This script EXTRACTS them from the real file
# between the `# BEGIN makefile-trust-helpers` / `# END makefile-trust-helpers`
# markers and runs THAT - a copy would drift, and a drifted copy testing
# itself is worth nothing.
#
# It also covers the one case CI fixtures structurally cannot: directory ==
# '.', which needs a Python/Node manifest at this repo's own root to be
# observable from a self-test job (see self-test.yml's comment on the
# root-makefile-and-semgrep job for why adding one is not free).
#
# WHICH CHANGE TURNS THIS RED: revert the `([-@+][[:space:]]*)*` prefix class
# in is_trivial_makefile_recipe back to `@?` and cases 4-9 fail; revert
# escape_for_ere to a bare `printf` and case 17 fails; narrow the boundary
# class back to `[^A-Za-z0-9_.]` and case 18 fails.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="$REPO_ROOT/.github/workflows/reusable-pr-quality.yml"
HELPERS="$(mktemp)"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$HELPERS" "$SCRATCH"' EXIT

sed -n '/# BEGIN makefile-trust-helpers/,/# END makefile-trust-helpers/p' "$WORKFLOW" >"$HELPERS"

# A silently-empty extraction would make every case below "pass" against
# nothing, so prove the block is really there before trusting a single result
# (this repo's own rule: a check that counts nothing needs a partner proving
# the thing counted exists).
if [ ! -s "$HELPERS" ]; then
	echo "FATAL: extracted zero lines from $WORKFLOW - the BEGIN/END makefile-trust-helpers markers are missing or renamed." >&2
	exit 1
fi
for fn in extract_makefile_recipe is_trivial_makefile_recipe escape_for_ere compute_makefile_trust; do
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

# assert_trust <case-name> <target> <directory> <expected> <recipe-line>...
#
# Writes a throwaway Makefile containing ONLY the named target with the given
# recipe lines (real tabs), then runs the extracted compute_makefile_trust
# against it exactly as the workflow's "Detect project layout" step does.
assert_trust() {
	local name="$1" target="$2" dir="$3" expected="$4"
	shift 4
	CASES=$((CASES + 1))

	local makefile="$SCRATCH/Makefile"
	{
		printf '%s:\n' "$target"
		local line
		for line in "$@"; do
			printf '\t%s\n' "$line"
		done
		# A following non-indented line, so extract_makefile_recipe's
		# "stop at the first non-indented line" branch is exercised too.
		printf 'unrelated-sentinel:\n\techo sentinel\n'
	} >"$makefile"

	# The three has_makefile_<check> values the real step computes by
	# grepping the Makefile; here the target is written by definition, so
	# exactly the one under test is true.
	local has_lint=false has_typecheck=false has_test=false
	case "$target" in
	lint) has_lint=true ;;
	typecheck) has_typecheck=true ;;
	test) has_test=true ;;
	esac

	local actual
	actual="$(
		cd "$SCRATCH" || exit 1
		HAS_MAKEFILE_LINT="$has_lint" HAS_MAKEFILE_TYPECHECK="$has_typecheck" \
			HAS_MAKEFILE_TEST="$has_test" compute_makefile_trust "$target" "$dir"
	)"

	if [ "$actual" = "$expected" ]; then
		printf 'ok   %-52s trust=%s\n' "$name" "$actual"
	else
		printf 'FAIL %-52s expected trust=%s, got trust=%s\n' "$name" "$expected" "$actual"
		FAILURES=$((FAILURES + 1))
	fi
}

# assert_absent_target <case-name> - a target that does not exist at all must
# never be trusted, regardless of what else the Makefile contains.
assert_absent_target() {
	CASES=$((CASES + 1))
	printf 'lint:\n\tcd backend && ruff check .\n' >"$SCRATCH/Makefile"
	local actual
	actual="$(
		cd "$SCRATCH" || exit 1
		HAS_MAKEFILE_LINT=true HAS_MAKEFILE_TYPECHECK=false HAS_MAKEFILE_TEST=false \
			compute_makefile_trust test backend
	)"
	if [ "$actual" = false ]; then
		printf 'ok   %-52s trust=%s\n' "$1" "$actual"
	else
		printf 'FAIL %-52s expected trust=false, got trust=%s\n' "$1" "$actual"
		FAILURES=$((FAILURES + 1))
	fi
}

echo
echo "--- trivial recipes must NOT be trusted (H2 false-green class) ---"
assert_trust "T01 @true, root"                    test . false '@true'
assert_trust "T02 bare true, root"                test . false 'true'
assert_trust "T03 @echo, root"                    lint . false '@echo nothing to lint'
assert_trust "T04 -true, root"                    test . false '-true'
assert_trust "T05 -true, non-root (dir in text)"  test backend false '-true # backend'
assert_trust "T06 @-true, root"                   test . false '@-true'
assert_trust "T07 -@true, non-root"               test backend false '-@true # backend'
assert_trust "T08 +true, root"                    test . false '+true'
assert_trust "T09 - true (space after prefix)"    test . false '- true'
assert_trust "T10 exit 0, root"                   test . false 'exit 0'
assert_trust "T11 colon no-op, root"              test . false ':'
assert_trust "T12 comment-only recipe"            test . false '# nothing here' '@true'
assert_trust "T13 empty recipe"                   test . false ''

echo
echo "--- real recipes MUST be trusted (H7 redundant-work class) ---"
assert_trust "T14 real recipe, root"              test . true 'pytest -q'
assert_trust "T15 real recipe names the dir"      test backend true 'cd backend && uv run pytest'
assert_trust "T16 prefixed real recipe"           test . true '-pytest -q'
assert_trust "T17 real recipe, mixed with no-op"  test . true '@echo running' 'pytest -q'

echo
echo "--- directory matching must be literal and boundary-correct ---"
assert_trust "T18 dot is literal, not a wildcard" test api.old false 'cd apiXold && pytest'
assert_trust "T19 dot matches itself"             test api.old true 'cd api.old && pytest'
assert_trust "T20 dash is part of the word"       test backend false 'cd backend-legacy && pytest'
assert_trust "T21 nested path matches"            test src/backend true 'cd src/backend && pytest'
assert_trust "T22 unrelated recipe, non-root"     test backend false 'pytest -q'
assert_absent_target "T23 target absent entirely"

echo
if [ "$FAILURES" -ne 0 ]; then
	echo "::error::$FAILURES of $CASES makefile-trust cases FAILED."
	exit 1
fi
echo "All $CASES makefile-trust cases passed."
