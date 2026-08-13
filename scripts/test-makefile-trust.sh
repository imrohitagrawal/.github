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
# WHICH CHANGE TURNS THIS RED - each one run, not reasoned about (an earlier
# version of this comment named cases 17 and 18 from memory and was wrong on
# both; a review caught it, which is the whole argument for running the
# mutation instead of writing down what you expect):
#   - revert the `([-@+][[:space:]]*)*` prefix class in
#     is_trivial_makefile_recipe to `@?`          -> T04-T09 fail (6 cases)
#   - revert escape_for_ere to a bare `printf`    -> T18 fails
#   - narrow the boundary class to `[^A-Za-z0-9_.]` -> T20 fails
#   - delete the root Makefile's `-` prefix, delete the directory name from
#     its `lint:` recipe comment, or retarget that name at a path INSIDE the
#     fixture directory                           -> T25 fails (T26 does not,
#     and an earlier version of this line wrongly named both - the third
#     asserted-not-observed claim of round 4, caught by review)
#   - sabotage extract_makefile_recipe to return a fixed non-empty recipe
#     -> T24 fails, and T23 stays GREEN. That contrast is the whole point of
#     issue #23's L4: T23 was NAMED for the missing-target case but
#     short-circuits on the has_makefile_<check> flag before ever calling
#     extract_makefile_recipe, so it could not fail for that reason. (The
#     blunt sabotage reds 19 cases in total; T23 not being one of them is
#     the observation that matters.)
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
# The END marker needs its own check (review finding). `sed` with an
# unmatched closing address runs to end of file, so deleting or renaming only
# the END marker yields an extraction that is non-empty AND defines all four
# functions - both guards below pass - while actually sourcing ~900 lines of
# workflow YAML as shell. On bash 5 that aborts loudly; on bash 3.2 the EXIT
# trap's own `rm` resets `$?` and this script exits 0 having run zero cases.
if ! grep -q '# END makefile-trust-helpers' "$HELPERS"; then
	echo "FATAL: extraction from $WORKFLOW ran past the end of the helper block - the '# END makefile-trust-helpers' marker is missing or renamed." >&2
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

# assert_flag_gate <case-name> <has-flag-value>
#
# ISSUE #23 (L4): this was called assert_absent_target and its case was named
# "target absent entirely", but with has_makefile_test=false it returns at the
# FIRST gate and never calls extract_makefile_recipe at all - sabotaging that
# function left the case green. It tests the has_makefile_<check> flag gate,
# which is worth testing, so it is renamed to say so, and the genuinely-absent
# target it claimed to cover is now T24 below.
assert_flag_gate() {
	CASES=$((CASES + 1))
	printf 'lint:\n\tcd backend && ruff check .\n' >"$SCRATCH/Makefile"
	local actual
	actual="$(
		cd "$SCRATCH" || exit 1
		HAS_MAKEFILE_LINT=true HAS_MAKEFILE_TYPECHECK=false HAS_MAKEFILE_TEST="$2" \
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
assert_flag_gate "T23 has_makefile_test=false short-circuits" false
# T24 is the case T23 was misnamed for: the flag says the target exists,
# so the short-circuit does NOT fire and extract_makefile_recipe really
# runs - against a Makefile with no `test:` target at all. It must return
# an empty recipe, which is_trivial_makefile_recipe then classifies as
# trivial, giving trust=false. Sabotaging extract_makefile_recipe turns
# THIS red, which is what L4 said T23 could not do.
assert_flag_gate "T24 flag true but target genuinely absent" true

echo
echo "--- the CI fixture's coupling to the REAL root Makefile still holds ---"
# Review finding: the makefile-trust-dash-negative self-test fixture only
# DISCRIMINATES between the old and new regex while this repo's own root
# Makefile keeps BOTH halves of its `lint:` recipe - the `-` prefix and the
# comment naming that fixture's directory. Drop the comment (it reads as
# stray) and trust goes false under the OLD regex too, for the unrelated
# reason that the directory is no longer mentioned: ruff still runs, the
# fixture's F401 still fires, its assert job still passes, and the `-`-prefix
# proof silently evaporates with nothing going red. Nothing pinned that, so
# these two cases do - against the real file, not a fixture.
#
# T25 + T26 together mean exactly "old regex -> trusted, new regex ->
# untrusted", which is what makes that fixture worth running at all.
FIXTURE_DIR=".github/self-test-fixtures/makefile-trust-dash-negative"

# The pre-round-4 implementation, kept ONLY as a discriminator. Never used to
# classify anything for real - if this ever needs to change to match the live
# one, that is the signal these two cases have stopped meaning anything.
is_trivial_at_prefix_only() {
	! grep -vqE '^[[:space:]]*(@?[[:space:]]*(#.*)?$|@?[[:space:]]*(echo|true|:|exit[[:space:]]+0)([[:space:]].*)?$)'
}

# Review finding on the first version of this case (then numbered T24): it hand-rolled the second half
# of the check as `grep -qF "$FIXTURE_DIR"`, which is plain containment and
# NOT what compute_makefile_trust does - that uses a boundary-aware match. So
# retargeting the comment at, say, "<dir>/requirements.txt" left T24 green
# (the substring is still there) while the real function correctly stopped
# matching, and the fixture silently stopped discriminating: exactly the decay
# T25 exists to prevent. Fixed by running the REAL compute_makefile_trust with
# only is_trivial_makefile_recipe swapped for the legacy one - so every other
# part of the decision, boundary matching included, is the shipping code.
CASES=$((CASES + 1))
root_lint_recipe="$(cd "$REPO_ROOT" && extract_makefile_recipe lint)"
legacy_trust="$(
	cd "$REPO_ROOT" || exit 1
	# shellcheck disable=SC2329 # invoked indirectly: compute_makefile_trust
	# calls is_trivial_makefile_recipe by name, and bash resolves that at
	# call time, so this subshell-local redefinition is what runs.
	is_trivial_makefile_recipe() { is_trivial_at_prefix_only; }
	HAS_MAKEFILE_LINT=true HAS_MAKEFILE_TYPECHECK=false HAS_MAKEFILE_TEST=false \
		compute_makefile_trust lint "$FIXTURE_DIR"
)"
if [ "$legacy_trust" = true ]; then
	printf 'ok   %-52s trust=%s\n' "T25 root lint: TRUSTED under the pre-fix regex" "$legacy_trust"
else
	printf 'FAIL %-52s expected trust=true, got trust=%s\n' "T25 root lint: TRUSTED under the pre-fix regex" "$legacy_trust"
	printf '     %s\n' "-- the root Makefile's lint: recipe must keep BOTH a Make prefix char that only the NEW regex strips AND a boundary-matched mention of '$FIXTURE_DIR', or makefile-trust-dash-negative stops proving anything. Recipe is now: $(printf '%s' "$root_lint_recipe" | tr '\n' ';')"
	FAILURES=$((FAILURES + 1))
fi

CASES=$((CASES + 1))
root_lint_trust="$(cd "$REPO_ROOT" && HAS_MAKEFILE_LINT=true HAS_MAKEFILE_TYPECHECK=false HAS_MAKEFILE_TEST=false \
	compute_makefile_trust lint "$FIXTURE_DIR")"
if [ "$root_lint_trust" = false ]; then
	printf 'ok   %-52s trust=%s\n' "T26 root lint: UNTRUSTED for the fixture today" "$root_lint_trust"
else
	printf 'FAIL %-52s expected trust=false, got trust=%s\n' "T26 root lint: UNTRUSTED for the fixture today" "$root_lint_trust"
	FAILURES=$((FAILURES + 1))
fi

echo
if [ "$FAILURES" -ne 0 ]; then
	echo "::error::$FAILURES of $CASES makefile-trust cases FAILED."
	exit 1
fi
echo "All $CASES makefile-trust cases passed."
