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
#
# ISSUE #23 (M6): this call used to be bare. Under `set -euo pipefail` a
# transient 502/403 killed the script with gh's raw exit code and no
# `::error::` annotation at all - so API flake was presented to whoever
# opened the run exactly like a gate regression, on a check that blocks
# merges. It now retries, and separates the two outcomes that need
# different responses: the API call FAILING (infra, retry, and say so) from
# it succeeding but listing no such job (a real, permanent naming mismatch -
# fail immediately, retrying cannot help).
#
# The output is captured whole and split afterwards rather than piped into
# `head -n 1`, which also removes the SIGPIPE-under-pipefail hazard a review
# raised against the previous form.
LIST_ERR="$(mktemp)"
trap 'rm -f "$LIST_ERR"' EXIT
JOB_ID=""
LIST_OK=false
LIST_ATTEMPTS=4
for attempt in $(seq 1 "$LIST_ATTEMPTS"); do
	set +e
	LIST_OUT="$(TARGET_JOB="$TARGET_JOB" gh api --paginate \
		"repos/${GITHUB_REPO}/actions/runs/${RUN_ID}/attempts/${RUN_ATTEMPT}/jobs?per_page=100" \
		--jq '.jobs[] | select(.name == env.TARGET_JOB) | .id' 2>"$LIST_ERR")"
	LIST_EXIT=$?
	set -e
	if [ "$LIST_EXIT" -eq 0 ]; then
		LIST_OK=true
		JOB_ID="$(printf '%s\n' "$LIST_OUT" | head -n 1)"
		break
	fi
	if [ "$attempt" -lt "$LIST_ATTEMPTS" ]; then
		echo "Jobs listing failed (gh exit ${LIST_EXIT}, attempt ${attempt}/${LIST_ATTEMPTS}); retrying in 10s. Last error: $(head -n 1 "$LIST_ERR")"
		sleep 10
	fi
done

if [ "$LIST_OK" != true ]; then
	# Infrastructure, not a fixture verdict - so no FAILURE_HINT, same
	# reasoning as the log-download failure below.
	echo "----- last gh error -----"
	head -n 10 "$LIST_ERR"
	echo "-------------------------"
	echo "::error::assert-fixture-job.sh: could not list jobs for run ${RUN_ID} attempt ${RUN_ATTEMPT} after ${LIST_ATTEMPTS} attempts (last gh exit ${LIST_EXIT}). This says nothing about whether the fixture behaved correctly."
	exit 1
fi

if [ -z "$JOB_ID" ]; then
	fail "assert-fixture-job.sh: the jobs listing for run ${RUN_ID} attempt ${RUN_ATTEMPT} succeeded but contains no job named '$TARGET_JOB'. If that job was renamed in self-test.yml, this assert job's TARGET_JOB must be renamed with it."
fi

RAW_LOG="$(mktemp)"
LOG_FILE="$(mktemp)"
trap 'rm -f "$LIST_ERR" "$RAW_LOG" "$LOG_FILE"' EXIT

# curl, not `gh api`, for THIS request specifically - and not a style choice.
# Job logs are plain text containing the runner's own ANSI colour codes, and
# newer `gh` refuses to emit any response carrying terminal escape sequences
# ("the response contains terminal escape sequences; pass
# --allow-escape-sequences to output it anyway"). That flag does not exist in
# older gh (2.96.0 does not have it), so keying on it would make this script
# work on exactly one gh version and fail on both sides of it. Observed for
# real: the runner's gh refused every fixture log this way, which first looked
# like a log-availability lag until the error text was actually printed.
#
# The endpoint 302s to a pre-signed blob URL. `curl -L` drops the
# Authorization header when the redirect crosses to a different host, which is
# both correct and required here - the blob URL carries its own signature and
# rejects an extra Authorization header.
#
# The retry loop stays, for the genuinely-transient case (a log that is still
# being finalised right after the job ends), but is no longer the explanation
# for anything observed so far.
DOWNLOAD_ATTEMPTS=6
DOWNLOADED=false
for attempt in $(seq 1 "$DOWNLOAD_ATTEMPTS"); do
	# `|| true`, not `|| echo 000` (review finding): curl already writes its
	# own "000" via -w when the transfer never completes, so the extra echo
	# concatenated into "000000" - garbling the one field a responder needs
	# to tell 404 from 403 from a network failure. The `||` itself is still
	# required, since `set -e` aborts on a failing command substitution.
	#
	# --connect-timeout/--max-time (review finding): without them a stalled
	# transfer never returns, so the retry loop below never re-fires and the
	# required `self-test` check hangs to the job timeout on a PR with no
	# defect at all.
	set +e
	HTTP_CODE="$(curl -sS -L \
		--connect-timeout 10 --max-time 120 \
		-H "Authorization: Bearer ${GH_TOKEN}" \
		-H "Accept: application/vnd.github+json" \
		-H "X-GitHub-Api-Version: 2022-11-28" \
		-o "$RAW_LOG" -w '%{http_code}' \
		"https://api.github.com/repos/${GITHUB_REPO}/actions/jobs/${JOB_ID}/logs")"
	CURL_EXIT=$?
	set -e
	[ -n "$HTTP_CODE" ] || HTTP_CODE=000
	# CURL_EXIT is checked as well as the status code, and that is not
	# belt-and-braces (review finding): --max-time can abort a transfer that
	# already received its 200 response line, leaving %{http_code} == 200 and
	# a TRUNCATED body on disk. Accepting that would mean asserting against
	# half a log - a missing marker would then read as a gate regression. curl
	# exits 28 in that case, so requiring exit 0 sends it back through the
	# retry loop instead.
	if [ "$CURL_EXIT" -eq 0 ] && [ "$HTTP_CODE" = 200 ] && [ -s "$RAW_LOG" ]; then
		DOWNLOADED=true
		break
	fi
	if [ "$attempt" -lt "$DOWNLOAD_ATTEMPTS" ]; then
		echo "Log for job ${JOB_ID} not ready (HTTP ${HTTP_CODE}, curl exit ${CURL_EXIT}, attempt ${attempt}/${DOWNLOAD_ATTEMPTS}); retrying in 10s."
		sleep 10
	fi
done

if [ "$DOWNLOADED" != true ]; then
	# Deliberately NOT routed through fail(): this is an infrastructure
	# problem, and printing FAILURE_HINT here would assert something about
	# the fixture's behaviour that was never actually observed.
	echo "----- last response body (first 20 lines) -----"
	head -n 20 "$RAW_LOG" || true
	echo "-----------------------------------------------"
	echo "::error::assert-fixture-job.sh: could not download the log for job '$TARGET_JOB' (id ${JOB_ID}) after ${DOWNLOAD_ATTEMPTS} attempts (last HTTP ${HTTP_CODE}, curl exit ${CURL_EXIT}). This says nothing about whether the fixture behaved correctly."
	exit 1
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
