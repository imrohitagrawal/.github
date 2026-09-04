#!/usr/bin/env bash
# test-advisory-crash-path.sh - table tests for reusable-pr-quality.yml's
# advisory-crash-verdict helper (issue #26).
#
# WHY THIS EXISTS. The two ADVISORY scanner steps (npm audit, pip-audit) exit 0
# on a real high-severity finding - deliberately, so an unfixable transitive
# advisory cannot block every unrelated PR - but used to exit NON-ZERO when the
# scanner failed to RUN. "I could not look" was therefore treated as strictly
# more severe than "I found a high-severity CVE". A registry.npmjs.org 503
# blocked three unrelated PRs on imrohitagrawal/citevyn in 24 hours; all three
# went green on an unchanged re-run.
#
# No self-test fixture can reach this path: making `npm audit` fail to run needs
# an unreachable registry, and `npm ci` in the same job needs a reachable one. A
# fixture whose only dependency is a `file:` path does not reproduce it either -
# npm short-circuits and never contacts the registry (verified: exit 0, with a
# "vulnerabilities" key). So it is tested here, against the real helper extracted
# from the workflow - never a copy, which would drift.
#
# WHICH CHANGE TURNS THIS RED - run, not reasoned about. Each line below was
# produced by applying the mutation and reading the EXIT CODE, not by grepping
# the output for "FAIL" - see the subshell note further down for why that
# distinction is not pedantry.
#   - restore `exit "$2"` as the last line of advisory_scanner_crashed
#       -> A01, A02 AND A07 fail (an earlier version of this comment said "A01
#          and A02"; A07 exercises the same helper with GITHUB_STEP_SUMMARY
#          unset and reds too. Corrected by running it).
#   - drop the $GITHUB_STEP_SUMMARY block
#       -> A03 fails. This is the half that preserves the ORIGINAL design intent
#          (a dead tool must not be indistinguishable from a clean run); without
#          it this change would trade a false failure for silent blindness.
#   - change ::warning:: back to ::error::
#       -> A04 fails.
#   - make the two helper copies differ by one byte
#       -> A05 fails.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="$ROOT/.github/workflows/reusable-pr-quality.yml"
HELPERS="$(mktemp)"
trap 'rm -f "$HELPERS"' EXIT

sed -n '/# BEGIN advisory-crash-verdict/,/# END advisory-crash-verdict/p' "$WORKFLOW" >"$HELPERS"

# Same guard discipline as scripts/test-uv-detection.sh: prove the extraction
# really found the block before trusting a single result, and check the END
# marker separately - `sed` with an unmatched closing address runs to end of
# file, which would pass an is-non-empty check while sourcing the whole
# workflow as shell.
if [ ! -s "$HELPERS" ]; then
	echo "FATAL: extracted zero lines from $WORKFLOW - the BEGIN/END advisory-crash-verdict markers are missing or renamed." >&2
	exit 1
fi
if ! grep -q '# END advisory-crash-verdict' "$HELPERS"; then
	echo "FATAL: extraction ran to end of file - the END advisory-crash-verdict marker is missing." >&2
	exit 1
fi
if ! grep -q 'advisory_scanner_crashed()' "$HELPERS"; then
	echo "FATAL: extracted block does not define advisory_scanner_crashed." >&2
	exit 1
fi

# shellcheck disable=SC1090
. "$HELPERS"

FAILED=0
check() { # id, description, condition-result
	if [ "$3" = "0" ]; then printf '  ok   %s  %s\n' "$1" "$2"
	else printf '  FAIL %s  %s\n' "$1" "$2"; FAILED=1; fi
}

# A real npm 503 body, captured verbatim from run 33813062396.
NPM_503='{"message":"503 Service Unavailable - POST https://registry.npmjs.org/-/npm/v1/security/audits/quick - Service Unavailable","statusCode":503,"error":{"summary":"","detail":""}}'

echo "advisory-crash-verdict:"

# A01/A02 - the whole point: a scanner that could not run must NOT fail the job.
SUMMARY="$(mktemp)"; export GITHUB_STEP_SUMMARY="$SUMMARY"
# EVERY call goes through a subshell, deliberately. If the helper regresses to
# `exit "$2"`, a DIRECT call terminates this whole script at that line - before
# a single check runs - and a caller grepping for "FAIL" then reads the corpse
# as a clean pass. A subshell contains the exit so it becomes a measurable
# return code instead of a dead harness. (Found the hard way: an earlier version
# called pip-audit directly and the M1 mutation silently "passed".)
set +e
OUT_NPM="$(advisory_scanner_crashed "npm audit" 1 "$NPM_503" 2>&1)"; RC_NPM=$?
OUT_PIP="$(advisory_scanner_crashed "pip-audit" 2 "VulnServiceConnectionError" 2>&1)"; RC_PIP=$?
set -e
: "${OUT_PIP:?}"   # referenced so shellcheck sees a use; the assertion is on RC_PIP
check A01 "npm audit crash does not fail the step (exit 0)" "$([ "$RC_NPM" -eq 0 ] && echo 0 || echo 1)"
check A02 "pip-audit crash does not fail the step (exit 0)" "$([ "$RC_PIP" -eq 0 ] && echo 0 || echo 1)"

# A03 - the half that preserves the original intent: the coverage gap must stay
# VISIBLE. Without this the change trades a false failure for silent blindness.
check A03 "the lost coverage is recorded in GITHUB_STEP_SUMMARY" \
	"$(grep -q 'did not run' "$SUMMARY" && grep -q 'no npm audit coverage' "$SUMMARY" && echo 0 || echo 1)"

# A04 - severity: a warning annotation, never an error one.
check A04 "annotates ::warning:: and never ::error::" \
	"$(printf '%s' "$OUT_NPM" | grep -q '::warning::' && ! printf '%s' "$OUT_NPM" | grep -q '::error::' && echo 0 || echo 1)"

# A06 - the tool's own output still reaches the log, so a human can see WHY.
check A06 "the scanner's raw output is still printed" \
	"$(printf '%s' "$OUT_NPM" | grep -q '503 Service Unavailable' && echo 0 || echo 1)"

# A07 - it must not silently swallow a MISSING summary file (local runs, act, etc.)
unset GITHUB_STEP_SUMMARY
set +e
(advisory_scanner_crashed "npm audit" 1 "$NPM_503" >/dev/null 2>&1); RC_NOSUM=$?
set -e
check A07 "works with GITHUB_STEP_SUMMARY unset (exit 0, no crash)" \
	"$([ "$RC_NOSUM" -eq 0 ] && echo 0 || echo 1)"
export GITHUB_STEP_SUMMARY="$SUMMARY"

# A05 - the helper is duplicated into both advisory steps because shell
# functions do not persist across steps. Assert the copies cannot drift.
COPIES="$(awk '/# BEGIN advisory-crash-verdict/{n++} END{print n+0}' "$WORKFLOW")"
_uniq="$(awk '
	/# BEGIN advisory-crash-verdict/{cap=1; blk=""}
	cap{blk=blk $0 "\n"}
	/# END advisory-crash-verdict/{if(cap){printf "%s\x00", blk; cap=0}}
' "$WORKFLOW" | tr '\0' '\n' | sort -u | grep -c 'advisory_scanner_crashed()' || true)"
check A05 "both copies of the helper are byte-identical (found $COPIES copies, $_uniq distinct)" \
	"$([ "$COPIES" -eq 2 ] && [ "$_uniq" -eq 1 ] && echo 0 || echo 1)"

rm -f "$SUMMARY"
[ "$FAILED" -eq 0 ] || { echo "advisory-crash-verdict: FAILURES above." >&2; exit 1; }
echo "advisory-crash-verdict: all checks passed."
