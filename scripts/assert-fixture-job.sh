#!/usr/bin/env bash
# assert-fixture-job.sh - assert a self-test fixture job produced the RIGHT
# result for the RIGHT reason.
#
# ROUND-4 FIX (HIGH, real CI evidence). Every assert job in self-test.yml
# used to check only `needs.<fixture-job>.result`, which cannot tell a
# genuine finding from an unrelated crash. That gap was not hypothetical: the
# python-pip-audit-blocking fixture spent its entire life hitting the
# reusable workflow's pip-audit CRASH branch (a dependency-resolution
# failure, "::error::pip-audit failed to run") rather than its FINDING branch
# - and the assert job reported success every single time, because the job
# was red either way. See self-test.yml's "STRUCTURAL LIMITATION" comment for
# the shape of the problem, and the python-pip-audit-blocking fixture's own
# requirements.txt for the specific bug.
#
# This closes it without needing `outputs:` on reusable-pr-quality.yml (the
# fix that comment proposed and deferred as out of scope): it reads the
# fixture job's REAL log from the Actions API and greps it for a marker only
# the intended step can emit.
#
# Inputs (all environment variables):
#   GH_TOKEN         required - a token with `actions: read` on GITHUB_REPO.
#   GITHUB_REPO      required - owner/repo.
#   RUN_ID           required - the workflow run containing the fixture job.
#   RUN_ATTEMPT      required - the run attempt (a re-run gets a new attempt,
#                    and an unpinned jobs listing would otherwise mix them).
#   TARGET_JOB       required - the fixture job's exact display name. For a
#                    job that calls a reusable workflow via `uses:`, GitHub
#                    names it "<job-id> / <inner-job-name>", e.g.
#                    "python-pip-audit-blocking / quality-gate".
#   ACTUAL_RESULT    required - the observed result, i.e. the caller's
#                    `needs.<fixture-job>.result`.
#   EXPECT_RESULT    required - the expected result, e.g. "failure".
#   EXPECT_PATTERN   required - ERE that MUST match somewhere in the log.
#   FORBID_PATTERN   optional - ERE that must NOT match anywhere in the log.
#   FAILURE_HINT     optional - extra context printed when an assertion fails.
#
# Pattern-writing rule, learned the hard way: a `run:` step's SCRIPT TEXT is
# echoed into the log verbatim, so grepping for the literal text of an
# `echo "::error::..."` line matches even when that branch never executed.
# Match the RENDERED annotation ("##[error]...") or genuine tool output
# instead - never the source of the echo.
set -euo pipefail

for var in GH_TOKEN GITHUB_REPO RUN_ID RUN_ATTEMPT TARGET_JOB ACTUAL_RESULT EXPECT_RESULT EXPECT_PATTERN; do
	if [ -z "${!var:-}" ]; then
		echo "::error::assert-fixture-job.sh: required environment variable $var is empty or unset."
		exit 1
	fi
done

FORBID_PATTERN="${FORBID_PATTERN:-}"
FAILURE_HINT="${FAILURE_HINT:-}"

fail() {
	echo "::error::$1"
	if [ -n "$FAILURE_HINT" ]; then
		echo "::error::$FAILURE_HINT"
	fi
	exit 1
}

echo "Job '$TARGET_JOB' reported result: $ACTUAL_RESULT (expected: $EXPECT_RESULT)"
if [ "$ACTUAL_RESULT" != "$EXPECT_RESULT" ]; then
	fail "Expected job '$TARGET_JOB' to have result '$EXPECT_RESULT' but it was '$ACTUAL_RESULT'."
fi

# The jobs listing is attempt-scoped on purpose: re-running a SINGLE failed
# job creates a new attempt in which the untouched jobs still belong to the
# previous one, so pinning the attempt keeps "which job did I just wait on"
# unambiguous. per_page=100 + --paginate because this workflow already has
# more jobs than one default page holds.
JOB_ID="$(TARGET_JOB="$TARGET_JOB" gh api --paginate \
	"repos/${GITHUB_REPO}/actions/runs/${RUN_ID}/attempts/${RUN_ATTEMPT}/jobs?per_page=100" \
	--jq '.jobs[] | select(.name == env.TARGET_JOB) | .id' | head -n 1)"

if [ -z "$JOB_ID" ]; then
	fail "assert-fixture-job.sh: no job named '$TARGET_JOB' found in run ${RUN_ID} attempt ${RUN_ATTEMPT}. If that job was renamed in self-test.yml, this assert job's TARGET_JOB must be renamed with it."
fi

RAW_LOG="$(mktemp)"
LOG_FILE="$(mktemp)"
trap 'rm -f "$RAW_LOG" "$LOG_FILE"' EXIT

# Log availability can lag job completion by a few seconds; retry rather than
# flake. Deliberately bounded - a log that genuinely never materializes is a
# failure to report, not something to wait out indefinitely.
DOWNLOADED=false
for attempt in 1 2 3 4 5; do
	if gh api "repos/${GITHUB_REPO}/actions/jobs/${JOB_ID}/logs" >"$RAW_LOG" 2>/dev/null && [ -s "$RAW_LOG" ]; then
		DOWNLOADED=true
		break
	fi
	echo "Log for job ${JOB_ID} not available yet (attempt ${attempt}/5); retrying in 10s."
	sleep 10
done

if [ "$DOWNLOADED" != true ]; then
	fail "assert-fixture-job.sh: could not download the log for job '$TARGET_JOB' (id ${JOB_ID}) after 5 attempts."
fi

# Strip ANSI colour codes: the runner colourises the echoed `run:` script
# body, and an escape sequence landing inside a pattern's match window would
# silently defeat an otherwise-correct grep.
ESC="$(printf '\033')"
sed -e "s/${ESC}\\[[0-9;]*m//g" "$RAW_LOG" >"$LOG_FILE"

echo "Downloaded log for job id ${JOB_ID}: $(wc -l <"$LOG_FILE") lines."

if ! grep -qE "$EXPECT_PATTERN" "$LOG_FILE"; then
	echo "----- last 40 log lines -----"
	tail -n 40 "$LOG_FILE"
	echo "-----------------------------"
	fail "Job '$TARGET_JOB' produced result '$ACTUAL_RESULT' as expected, but its log does NOT match the required marker /${EXPECT_PATTERN}/ - so it did not reach that result for the reason this fixture exists to prove."
fi

if [ -n "$FORBID_PATTERN" ] && grep -qE "$FORBID_PATTERN" "$LOG_FILE"; then
	echo "----- matching lines -----"
	grep -nE "$FORBID_PATTERN" "$LOG_FILE" | head -n 10
	echo "--------------------------"
	fail "Job '$TARGET_JOB' log matched the FORBIDDEN marker /${FORBID_PATTERN}/ - the fixture reached a code path it is specifically asserted not to reach."
fi

echo "Confirmed: '$TARGET_JOB' resulted in '$ACTUAL_RESULT' AND its log matches /${EXPECT_PATTERN}/."
