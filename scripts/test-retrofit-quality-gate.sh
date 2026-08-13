#!/usr/bin/env bash
#
# test-retrofit-quality-gate.sh -- functional test suite for
# scripts/retrofit-quality-gate.sh (H4: that script had zero test coverage of
# any kind before this). Every test builds a throwaway scratch git repo under
# a mktemp directory and runs the REAL script against it -- never the actual
# dot-github checkout. Run directly: `scripts/test-retrofit-quality-gate.sh`.
#
# Hand-rolled bash rather than a framework (bats etc.): this repo has no
# package.json/pyproject.toml of its own (see AGENTS.md) and no other test
# framework dependency yet -- consistent with that, not a new one.

set -uo pipefail
# Deliberately NOT `set -e` at the top level: every test invokes the real
# script (which itself uses `set -euo pipefail` and is EXPECTED to exit
# non-zero in several tests) and needs to capture that exit code, not have it
# kill this harness. `set -e` is used locally inside test bodies where it's
# safe (no expected-failing command in that scope).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RETROFIT_SCRIPT="$SCRIPT_DIR/retrofit-quality-gate.sh"

PASS=0
FAIL=0
FAILED_TESTS=()

# ---------- assertion helpers ----------

pass() {
	PASS=$((PASS + 1))
	echo "  PASS: $1"
}

fail() {
	FAIL=$((FAIL + 1))
	FAILED_TESTS+=("$CURRENT_TEST: $1")
	echo "  FAIL: $1" >&2
}

assert_exit_code() {
	# assert_exit_code LABEL EXPECTED ACTUAL
	if [ "$3" = "$2" ]; then
		pass "$1 (exit $3)"
	else
		fail "$1 -- expected exit $2, got $3"
	fi
}

assert_file_exists() {
	if [ -e "$1" ]; then
		pass "$2 (file exists: $1)"
	else
		fail "$2 -- expected file to exist: $1"
	fi
}

assert_file_absent() {
	if [ ! -e "$1" ]; then
		pass "$2 (file absent: $1)"
	else
		fail "$2 -- expected file to NOT exist: $1"
	fi
}

assert_contains() {
	# assert_contains LABEL HAYSTACK NEEDLE
	if printf '%s' "$2" | grep -qF "$3"; then
		pass "$1 (found: '$3')"
	else
		fail "$1 -- expected output to contain: '$3'"
	fi
}

assert_not_contains() {
	if printf '%s' "$2" | grep -qF "$3"; then
		fail "$1 -- expected output to NOT contain: '$3'"
	else
		pass "$1 (absent: '$3')"
	fi
}

assert_eq() {
	# assert_eq LABEL EXPECTED ACTUAL
	if [ "$2" = "$3" ]; then
		pass "$1"
	else
		fail "$1 -- expected '$2', got '$3'"
	fi
}

# ---------- scratch-repo helpers ----------

new_scratch_repo() {
	# Creates a fresh git repo under a mktemp dir, on branch 'main', one
	# initial commit, clean tree. Prints its path.
	local dir
	dir="$(mktemp -d)"
	git -C "$dir" init -q -b main
	git -C "$dir" config user.email "test@example.com"
	git -C "$dir" config user.name "test"
	echo "# scratch repo" >"$dir/README.md"
	git -C "$dir" add -A
	git -C "$dir" commit -q -m "init"
	echo "$dir"
}

run_script() {
	# run_script REPO ARGS... -- invokes the real script, capturing combined
	# stdout+stderr into SCRIPT_OUTPUT and the exit code into SCRIPT_EXIT,
	# without `set -e` killing this harness on the (often expected) non-zero
	# exits.
	local repo="$1"
	shift
	set +e
	SCRIPT_OUTPUT="$(cd "$repo" && "$RETROFIT_SCRIPT" --repo "$repo" "$@" 2>&1)"
	SCRIPT_EXIT=$?
	set -e
}

cleanup_dirs=()
# shellcheck disable=SC2329 # invoked indirectly via `trap ... EXIT` below
cleanup() {
	local d
	for d in "${cleanup_dirs[@]}"; do
		rm -rf "$d"
	done
}
trap cleanup EXIT

track() {
	cleanup_dirs+=("$1")
}

# ============================================================================

CURRENT_TEST="T1 (happy path: Node-only)"
echo "$CURRENT_TEST"
repo="$(new_scratch_repo)"
track "$repo"
echo '{"name": "x", "scripts": {}}' >"$repo/package.json"
git -C "$repo" add -A && git -C "$repo" commit -q -m "add package.json"
run_script "$repo" --no-commit
assert_exit_code "script succeeds" 0 "$SCRIPT_EXIT"
assert_file_exists "$repo/AGENTS.md" "AGENTS.md copied"
assert_file_exists "$repo/.github/CODEOWNERS" "CODEOWNERS copied"
assert_file_exists "$repo/.github/dependabot.yml" "dependabot.yml copied"
assert_file_exists "$repo/.github/workflows/pr-quality.yml" "caller workflow copied"
assert_file_exists "$repo/Makefile" "Makefile (Node) copied"
assert_file_absent "$repo/Makefile.python" "no Makefile.python for a Node-only repo"

# ============================================================================

CURRENT_TEST="T2 (happy path: Python-only)"
echo "$CURRENT_TEST"
repo="$(new_scratch_repo)"
track "$repo"
echo '[project]' >"$repo/pyproject.toml"
echo 'name = "x"' >>"$repo/pyproject.toml"
git -C "$repo" add -A && git -C "$repo" commit -q -m "add pyproject.toml"
run_script "$repo" --no-commit
assert_exit_code "script succeeds" 0 "$SCRIPT_EXIT"
assert_file_exists "$repo/Makefile" "Makefile (Python) copied"
if [ -e "$repo/Makefile" ]; then
	if diff -q "$REPO_ROOT/templates/Makefile.python" "$repo/Makefile" >/dev/null 2>&1; then
		pass "Makefile content matches templates/Makefile.python"
	else
		fail "Makefile content does not match templates/Makefile.python"
	fi
fi

# ============================================================================

CURRENT_TEST="T3 (monorepo: both manifests, unconditional exit 3)"
echo "$CURRENT_TEST"
repo="$(new_scratch_repo)"
track "$repo"
echo '{"name": "x"}' >"$repo/package.json"
echo '[project]' >"$repo/pyproject.toml"
git -C "$repo" add -A && git -C "$repo" commit -q -m "monorepo manifests"
run_script "$repo" --no-commit
assert_exit_code "exits 3 for an unresolved monorepo" 3 "$SCRIPT_EXIT"
assert_file_exists "$repo/Makefile.python" "Makefile.python copied under its own name"
assert_file_exists "$repo/Makefile.node" "Makefile.node copied under its own name"
assert_file_absent "$repo/Makefile" "no single 'Makefile' guessed for a monorepo"
assert_contains "prints the merge-by-hand note" "$SCRIPT_OUTPUT" "Merge them into a"

# ============================================================================

CURRENT_TEST="T4 (no stack detected)"
echo "$CURRENT_TEST"
repo="$(new_scratch_repo)"
track "$repo"
run_script "$repo" --no-commit
assert_exit_code "exits 0, not an error" 0 "$SCRIPT_EXIT"
assert_file_absent "$repo/Makefile" "no Makefile guessed with nothing to detect"
assert_file_exists "$repo/AGENTS.md" "AGENTS.md still copied (language-independent)"
assert_contains "prints 'Other language' guidance" "$SCRIPT_OUTPUT" "no Makefile copied"

# ============================================================================

CURRENT_TEST="T5 (idempotency, --force + .bak handling)"
echo "$CURRENT_TEST"
repo="$(new_scratch_repo)"
track "$repo"
echo '{"name": "x"}' >"$repo/package.json"
git -C "$repo" add -A && git -C "$repo" commit -q -m "add package.json"

# 5a: first real run (commits)
run_script "$repo"
assert_exit_code "first run succeeds" 0 "$SCRIPT_EXIT"
assert_contains "first run commits" "$SCRIPT_OUTPUT" "Committed on branch"

# 5b: second run, nothing changed -- idempotent, no new commit
HEAD_BEFORE="$(git -C "$repo" rev-parse HEAD)"
run_script "$repo"
assert_exit_code "second run succeeds" 0 "$SCRIPT_EXIT"
assert_contains "second run makes no new commit" "$SCRIPT_OUTPUT" "Nothing new to commit"
HEAD_AFTER="$(git -C "$repo" rev-parse HEAD)"
assert_eq "HEAD unchanged on a no-op rerun" "$HEAD_BEFORE" "$HEAD_AFTER"

# 5c: modify a copied file, commit the modification (clean tree required),
# rerun with --force -- expect a .bak with the ORIGINAL (pre-force) content
echo "local addition" >>"$repo/AGENTS.md"
git -C "$repo" commit -q -am "locally modify AGENTS.md"
MODIFIED_CONTENT="$(cat "$repo/AGENTS.md")"
run_script "$repo" --force
assert_exit_code "--force run succeeds" 0 "$SCRIPT_EXIT"
assert_contains "reports OVERWRITTEN for AGENTS.md" "$SCRIPT_OUTPUT" "OVERWRITTEN"
assert_file_exists "$repo/AGENTS.md.bak" ".bak created"
if [ -e "$repo/AGENTS.md.bak" ]; then
	assert_eq "the .bak holds the pre-force (modified) content" "$MODIFIED_CONTENT" "$(cat "$repo/AGENTS.md.bak")"
fi
if [ -e "$repo/AGENTS.md.bak" ]; then
	if git -C "$repo" ls-files --error-unmatch AGENTS.md.bak >/dev/null 2>&1; then
		pass ".bak is committed, not left untracked"
	else
		fail ".bak should have been committed alongside the overwrite"
	fi
fi

# 5d: modify again, commit, --force again -- a stale .bak already exists ->
# must be SKIPPED, never silently clobbered
echo "second local addition" >>"$repo/AGENTS.md"
git -C "$repo" commit -q -am "locally modify AGENTS.md again"
run_script "$repo" --force
assert_contains "second --force with an existing .bak is SKIPPED" "$SCRIPT_OUTPUT" "stale .bak present"

# ============================================================================

CURRENT_TEST="T6 (dirty tree guard)"
echo "$CURRENT_TEST"
repo="$(new_scratch_repo)"
track "$repo"
echo "uncommitted" >"$repo/scratch.txt"
run_script "$repo" --no-commit
assert_exit_code "refuses a dirty tree" 2 "$SCRIPT_EXIT"
assert_file_absent "$repo/AGENTS.md" "nothing written when refusing"

# ============================================================================

CURRENT_TEST="T7 (detached HEAD guard)"
echo "$CURRENT_TEST"
repo="$(new_scratch_repo)"
track "$repo"
git -C "$repo" checkout -q --detach
run_script "$repo" --no-commit
assert_exit_code "refuses a detached HEAD" 2 "$SCRIPT_EXIT"

# ============================================================================

CURRENT_TEST="T8 (unsafe --branch guard)"
echo "$CURRENT_TEST"
repo="$(new_scratch_repo)"
track "$repo"
run_script "$repo" --branch main --no-commit
assert_exit_code "refuses --branch main" 2 "$SCRIPT_EXIT"

# ============================================================================

CURRENT_TEST="T9 (symlinked ancestor escape)"
echo "$CURRENT_TEST"
repo="$(new_scratch_repo)"
track "$repo"
outside="$(mktemp -d)"
track "$outside"
rm -rf "$repo/.github"
ln -s "$outside" "$repo/.github"
git -C "$repo" add -A && git -C "$repo" commit -q -m "make .github a symlink"
run_script "$repo" --no-commit
assert_contains "reports the symlinked ancestor as SKIPPED" "$SCRIPT_OUTPUT" "symlinked ancestor"
if [ -z "$(ls -A "$outside" 2>/dev/null)" ]; then
	pass "nothing was written into the symlink target"
else
	fail "something was written outside the repo, into: $outside"
fi

# ============================================================================

CURRENT_TEST="T10 (destination-itself-symlink)"
echo "$CURRENT_TEST"
repo="$(new_scratch_repo)"
track "$repo"
outside_file="$(mktemp)"
track "$outside_file"
echo "not managed by this repo" >"$outside_file"
ln -s "$outside_file" "$repo/AGENTS.md"
git -C "$repo" add -A && git -C "$repo" commit -q -m "AGENTS.md is a symlink"
run_script "$repo" --force --no-commit
assert_contains "refuses to overwrite through the symlink, even with --force" "$SCRIPT_OUTPUT" "refusing to overwrite through it"
if [ -L "$repo/AGENTS.md" ]; then
	pass "AGENTS.md is still a symlink (untouched)"
else
	fail "AGENTS.md should still be a symlink -- it was overwritten"
fi

# ============================================================================

CURRENT_TEST="T11 (caller-workflow pin substitution correctness -- regression test for the doubled-comment bug)"
echo "$CURRENT_TEST"
repo="$(new_scratch_repo)"
track "$repo"
echo '{"name": "x"}' >"$repo/package.json"
git -C "$repo" add -A && git -C "$repo" commit -q -m "add package.json"
run_script "$repo" --no-commit
PINNED_SHA="$(grep -oE '^PINNED_SHA="[0-9a-f]{40}"' "$RETROFIT_SCRIPT" | grep -oE '[0-9a-f]{40}')"
PINNED_TAG="$(grep -oE '^PINNED_TAG="v[0-9]+"' "$RETROFIT_SCRIPT" | grep -oE 'v[0-9]+')"
EXPECTED_LINE="uses: imrohitagrawal/.github/.github/workflows/reusable-pr-quality.yml@${PINNED_SHA} # ${PINNED_TAG}"
if [ -f "$repo/.github/workflows/pr-quality.yml" ]; then
	ACTUAL_LINE="$(grep -m1 'uses: imrohitagrawal/\.github/\.github/workflows/reusable-pr-quality\.yml@' "$repo/.github/workflows/pr-quality.yml" | sed -E 's/^[[:space:]]*//;s/[[:space:]]*$//')"
	assert_eq "generated 'uses:' line matches PINNED_SHA/PINNED_TAG exactly (no doubled comment)" "$EXPECTED_LINE" "$ACTUAL_LINE"
	HASH_COUNT="$(grep -o '#' <<<"$ACTUAL_LINE" | wc -l | tr -d ' ')"
	assert_eq "exactly one '#' in the pin line" "1" "$HASH_COUNT"

	# Every other line should be byte-identical to templates/caller-pr-quality.yml
	DIFF_OUTPUT="$(diff <(grep -v "$ACTUAL_LINE" "$REPO_ROOT/templates/caller-pr-quality.yml") \
		<(grep -v "$ACTUAL_LINE" "$repo/.github/workflows/pr-quality.yml") || true)"
	assert_eq "every non-pin line is byte-identical to templates/caller-pr-quality.yml" "" "$DIFF_OUTPUT"
else
	fail "caller workflow was not generated -- can't check pin substitution"
fi
# PINNED_SHA should resolve to the real commit behind PINNED_TAG in this
# repo's own history (catches "silently drift behind the others" -- the
# script's own comment's stated worry -- not just internal self-consistency).
#
# The tag comes from PINNED_TAG, not a literal. It used to be hardcoded `v6`,
# which meant the very first tag bump made this assertion fail for the one
# reason it must not: the pins were correct and the test was stale. Caught by
# cutting v7. A hardcoded tag also silently stops testing anything the moment
# it is bumped, which is the failure mode this whole suite exists to prevent.
if git -C "$REPO_ROOT" rev-parse -q --verify "${PINNED_TAG}^{commit}" >/dev/null 2>&1; then
	TAG_SHA="$(git -C "$REPO_ROOT" rev-parse "${PINNED_TAG}^{commit}")"
	assert_eq "PINNED_SHA matches tag ${PINNED_TAG}'s actual commit in this repo's history" "$TAG_SHA" "$PINNED_SHA"
else
	# Review finding: this branch used to be reached unconditionally, so
	# setting PINNED_TAG to a tag that does not exist made the whole
	# cross-check VANISH - the suite still exited 0, one assertion lighter,
	# with no other signal. That is the "check that cannot fail" class this
	# repo keeps getting bitten by. A shallow clone is a real reason to skip;
	# a full clone missing the tag means the tag was never cut, or
	# PINNED_TAG is wrong, and both deserve a red build.
	if [ "$(git -C "$REPO_ROOT" rev-parse --is-shallow-repository 2>/dev/null)" = "true" ]; then
		echo "  SKIP: tag ${PINNED_TAG} not resolvable in a SHALLOW clone -- skipping the tag cross-check"
	else
		fail "PINNED_TAG is '${PINNED_TAG}' but no such tag exists in this full clone -- the tag was never cut, or PINNED_TAG is wrong"
	fi
fi

# ============================================================================

CURRENT_TEST="T12 (--push guards fire before any network push)"
echo "$CURRENT_TEST"

# 12a: caller workflow conflicts (no --force) -> refuse to push
repo="$(new_scratch_repo)"
track "$repo"
echo '{"name": "x"}' >"$repo/package.json"
mkdir -p "$repo/.github/workflows"
echo "not the real caller workflow" >"$repo/.github/workflows/pr-quality.yml"
git -C "$repo" add -A && git -C "$repo" commit -q -m "pre-existing conflicting caller workflow"
run_script "$repo" --push
assert_exit_code "refuses to push when the caller workflow is SKIPPED" 2 "$SCRIPT_EXIT"
assert_contains "explains why" "$SCRIPT_OUTPUT" "refusing to push -- .github/workflows/pr-quality.yml was not installed"
assert_not_contains "never attempted a real git push (no origin configured -- would say so distinctly)" "$SCRIPT_OUTPUT" "No configured push destination"

# 12b: monorepo -> refuse to push
repo="$(new_scratch_repo)"
track "$repo"
echo '{"name": "x"}' >"$repo/package.json"
echo '[project]' >"$repo/pyproject.toml"
git -C "$repo" add -A && git -C "$repo" commit -q -m "monorepo manifests"
run_script "$repo" --push
assert_exit_code "refuses to push for an unresolved monorepo" 3 "$SCRIPT_EXIT"
assert_contains "explains why" "$SCRIPT_OUTPUT" "refusing to push -- monorepo detected"
assert_not_contains "never attempted a real git push" "$SCRIPT_OUTPUT" "No configured push destination"

# ============================================================================
# T13: the Makefile this script actually copies dispatches on the repo's real
# package manager (round-4, MEDIUM).
#
# WHY: H1 taught the reusable workflow to dispatch on pnpm/yarn/npm at all six
# of its native `run:` sites, but templates/Makefile.node - the file THIS
# script copies verbatim into any repo with a package.json - kept hardcoding
# `npm ci`. So a pnpm-only or yarn-only repo that onboarded through this
# script and adopted the recommended root Makefile reproduced the original H1
# hard failure (`npm ci` against a repo with no package-lock.json) through the
# Makefile route instead of the native one. These cases run the REAL copied
# Makefile through `make -n` (dry run - nothing is installed, no network) and
# read back which manager it resolved to.
#
# WHICH CHANGE TURNS THESE RED: revert templates/Makefile.node's PKG_MANAGER
# detection to a bare `npm ci` install target and ALL FIVE fail - run, not
# assumed (an earlier version of this comment said three, on the reasoning
# that npm-shaped repos would still pass; wrong, because every case asserts
# the literal `case "<manager>" in` line, which a bare `npm ci` recipe never
# prints for any manager).

makefile_pm_case() {
	# makefile_pm_case NAME EXPECTED_MANAGER PACKAGE_JSON [LOCKFILE]
	local name="$1" expected="$2" pkgjson="$3" lockfile="${4:-}"
	CURRENT_TEST="$name"
	echo "$CURRENT_TEST"
	local repo
	repo="$(new_scratch_repo)"
	track "$repo"
	printf '%s' "$pkgjson" >"$repo/package.json"
	if [ -n "$lockfile" ]; then
		: >"$repo/$lockfile"
	fi
	git -C "$repo" add -A && git -C "$repo" commit -q -m "node manifest"
	run_script "$repo"
	assert_exit_code "$name: retrofit succeeded" 0 "$SCRIPT_EXIT"
	assert_file_exists "$repo/Makefile" "$name: Makefile copied"

	local dry
	set +e
	dry="$(cd "$repo" && make -n install 2>&1)"
	set -e
	assert_contains "$name: install dispatches to $expected" "$dry" "case \"$expected\" in"
}

makefile_pm_case "T13a pnpm lockfile" pnpm \
	'{"name":"x","version":"1.0.0"}' pnpm-lock.yaml
makefile_pm_case "T13b yarn lockfile" yarn \
	'{"name":"x","version":"1.0.0"}' yarn.lock
makefile_pm_case "T13c npm lockfile" npm \
	'{"name":"x","version":"1.0.0"}' package-lock.json
# packageManager wins over a contradicting lockfile, matching the reusable
# workflow's own precedence (Corepack's field first, lockfile inference second).
makefile_pm_case "T13d packageManager beats lockfile" pnpm \
	'{"name":"x","version":"1.0.0","packageManager":"pnpm@9.1.0"}' package-lock.json
# An unrecognised packageManager must fall back to npm, never be passed
# through - the value reaches a `case` statement and comes from repo content.
makefile_pm_case "T13e unknown packageManager falls back to npm" npm \
	'{"name":"x","version":"1.0.0","packageManager":"bun@1.0.0"}' ""

# ============================================================================
# T14: the copied Makefile REALLY enforces yarn lockfile integrity (round-4,
# P1 from Codex review on PR #21, independently found by that round's SRE lens).
#
# T13 only inspects `make -n` output, which cannot catch a runtime flag that
# the tool accepts and ignores - and that was exactly the bug: `--immutable` is
# a Yarn Berry flag, and Yarn Classic accepts it, ignores it, and rewrites the
# lockfile. Measured against real yarn 1.22.22:
#   yarn install --immutable       -> exit 0, "success Saved lockfile", rewritten
#   yarn install --frozen-lockfile -> exit 1, "Your lockfile needs to be updated"
#
# This case asserts the PROPERTY, not the flag: whatever yarn ends up on PATH,
# a package.json whose dependency is absent from yarn.lock must FAIL `make
# install` and must not rewrite the lockfile. That statement is true for Yarn
# Classic (--frozen-lockfile) and Berry (--immutable) alike, so this test does
# not need updating when the runner's default yarn major changes.
#
# WHICH CHANGE TURNS THIS RED: revert templates/Makefile.node's install target
# to an unconditional `yarn install --immutable`. Verified.
#
# Yarn source: the runner's preinstalled yarn if present (ubuntu-latest ships
# 1.22.22), else a pinned `npx yarn@1.22.22` shim - so this runs everywhere
# rather than silently skipping on a machine without yarn.
yarn_shim_dir=""
if command -v yarn >/dev/null 2>&1; then
	echo "T14: using preinstalled yarn $(yarn --version 2>/dev/null)"
else
	yarn_shim_dir="$(mktemp -d)"
	track "$yarn_shim_dir"
	printf '#!/bin/sh\nexec npx --yes yarn@1.22.22 "$@"\n' >"$yarn_shim_dir/yarn"
	chmod +x "$yarn_shim_dir/yarn"
	echo "T14: no yarn on PATH; using a pinned npx yarn@1.22.22 shim"
fi

CURRENT_TEST="T14 (yarn lockfile integrity is really enforced)"
echo "$CURRENT_TEST"
repo="$(new_scratch_repo)"
track "$repo"
# A declared dependency that the lockfile does not cover: the minimal input
# every yarn major must refuse under an immutable-install flag.
printf '{"name":"y","version":"1.0.0","dependencies":{"is-odd":"3.0.1"}}' >"$repo/package.json"
printf '# yarn lockfile v1\n' >"$repo/yarn.lock"
git -C "$repo" add -A && git -C "$repo" commit -q -m "yarn manifest with a stale lockfile"
run_script "$repo"
assert_exit_code "T14: retrofit succeeded" 0 "$SCRIPT_EXIT"

lock_before="$(cksum <"$repo/yarn.lock")"
set +e
if [ -n "$yarn_shim_dir" ]; then
	YARN_INSTALL_OUTPUT="$(cd "$repo" && PATH="$yarn_shim_dir:$PATH" make install 2>&1)"
else
	YARN_INSTALL_OUTPUT="$(cd "$repo" && make install 2>&1)"
fi
YARN_INSTALL_EXIT=$?
set -e
lock_after="$(cksum <"$repo/yarn.lock")"

if [ "$YARN_INSTALL_EXIT" -ne 0 ]; then
	pass "T14: stale yarn.lock fails make install (exit $YARN_INSTALL_EXIT)"
else
	fail "T14: stale yarn.lock did NOT fail make install -- yarn accepted an install flag it ignores, so this repo's lockfile integrity is not enforced at all. Output: $(printf '%s' "$YARN_INSTALL_OUTPUT" | tail -3 | tr '\n' ' ')"
fi
assert_eq "T14: yarn.lock was not rewritten" "$lock_before" "$lock_after"

# ============================================================================

echo ""
echo "============================================================"
echo "Results: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
	echo ""
	echo "Failed:"
	for t in "${FAILED_TESTS[@]}"; do
		echo "  - $t"
	done
	exit 1
fi
exit 0
