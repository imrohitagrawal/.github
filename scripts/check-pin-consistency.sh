#!/usr/bin/env bash
#
# check-pin-consistency.sh -- self-lint check: fails if the reusable-workflow
# self-reference pin, or any of the CI tool-version pins that are duplicated
# between reusable-pr-quality.yml and the Makefile templates, have drifted
# out of sync. This exact class of drift already bit this repo once (PR #19:
# templates/caller-pr-quality.yml was left at a stale @v4 pin while
# scripts/retrofit-quality-gate.sh's PINNED_SHA/PINNED_TAG and repo-template's
# own caller workflow had both already been bumped to v6) -- this script is
# the mechanical backstop so the next tag bump can't repeat that silently.
#
# Scope, deliberately: within THIS repo only. repo-template is a separate
# repo; an automated network check against its live content was considered
# and rejected in favor of the existing manual bump-checklist comment in
# templates/caller-pr-quality.yml (see there) -- that would give this repo's
# own CI a new external-network dependency for a value that only changes
# when a human deliberately cuts a new tag, not continuous drift. Revisit
# only if repo-template's pin actually drifts again in practice.
#
# Exit codes: 0 all pins agree; 1 a pin mismatch was found (see stderr for
# which one); 2 an expected value could not be extracted at all (a file's
# format changed in a way this script doesn't recognize -- fail loudly
# rather than silently skip a check it can no longer perform).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

FAIL=0

fail() {
	echo "::error::$1" >&2
	FAIL=1
}

# ---------- (a) reusable-workflow self-reference pin ----------
# templates/caller-pr-quality.yml's own
# `uses: .../reusable-pr-quality.yml@<sha> # <tag>` line, compared against
# scripts/retrofit-quality-gate.sh's PINNED_SHA/PINNED_TAG constants.
CALLER_LINE="$(grep -oE 'uses: imrohitagrawal/\.github/\.github/workflows/reusable-pr-quality\.yml@[0-9a-f]{40} # v[0-9]+' templates/caller-pr-quality.yml || true)"
if [ -z "$CALLER_LINE" ]; then
	fail "templates/caller-pr-quality.yml: could not find a 'uses: .../reusable-pr-quality.yml@<40-char-sha> # vN' line in the expected format -- has the file's format changed?"
	exit 2
fi
CALLER_SHA="$(echo "$CALLER_LINE" | grep -oE '@[0-9a-f]{40}' | tr -d '@')"
CALLER_TAG="$(echo "$CALLER_LINE" | grep -oE '# v[0-9]+' | tr -d '# ')"

SCRIPT_SHA="$(grep -oE '^PINNED_SHA="[0-9a-f]{40}"' scripts/retrofit-quality-gate.sh | grep -oE '[0-9a-f]{40}' || true)"
SCRIPT_TAG="$(grep -oE '^PINNED_TAG="v[0-9]+"' scripts/retrofit-quality-gate.sh | grep -oE 'v[0-9]+' || true)"
if [ -z "$SCRIPT_SHA" ] || [ -z "$SCRIPT_TAG" ]; then
	fail "scripts/retrofit-quality-gate.sh: could not find PINNED_SHA=\"...\" / PINNED_TAG=\"...\" in the expected format -- has the script's format changed?"
	exit 2
fi

if [ "$CALLER_SHA" != "$SCRIPT_SHA" ]; then
	fail "reusable-workflow pin SHA mismatch: templates/caller-pr-quality.yml has $CALLER_SHA, scripts/retrofit-quality-gate.sh's PINNED_SHA has $SCRIPT_SHA"
fi
if [ "$CALLER_TAG" != "$SCRIPT_TAG" ]; then
	fail "reusable-workflow pin TAG mismatch: templates/caller-pr-quality.yml has $CALLER_TAG, scripts/retrofit-quality-gate.sh's PINNED_TAG has $SCRIPT_TAG"
fi

# ---------- (b) duplicated CI tool version pins ----------
# Python: ruff/pytest/mypy/bandit/pip-audit, pinned independently in the
# reusable workflow's native install step and in templates/Makefile.python's
# own install target. Extract just the tool==version tokens, not the full
# line -- the two files' surrounding shell syntax (indentation, `pip
# install` vs a Makefile recipe prefix) legitimately differs.
PY_TOOLS_RE='ruff==[0-9.]+ pytest==[0-9.]+ mypy==[0-9.]+ bandit==[0-9.]+ pip-audit==[0-9.]+'
WORKFLOW_PY_TOOLS="$(grep -oE "$PY_TOOLS_RE" .github/workflows/reusable-pr-quality.yml || true)"
MAKEFILE_PY_TOOLS="$(grep -oE "$PY_TOOLS_RE" templates/Makefile.python || true)"
if [ -z "$WORKFLOW_PY_TOOLS" ] || [ -z "$MAKEFILE_PY_TOOLS" ]; then
	fail "could not find the expected 'ruff==X pytest==X mypy==X bandit==X pip-audit==X' pin in reusable-pr-quality.yml and/or templates/Makefile.python -- has the pin format changed?"
	exit 2
fi
if [ "$WORKFLOW_PY_TOOLS" != "$MAKEFILE_PY_TOOLS" ]; then
	fail "Python tool version pins differ: reusable-pr-quality.yml has '$WORKFLOW_PY_TOOLS', templates/Makefile.python has '$MAKEFILE_PY_TOOLS'"
fi

# Node: audit-ci, pinned independently in the reusable workflow's blocking
# npm-audit step and in templates/Makefile.node's own audit target.
AUDIT_CI_RE='audit-ci@[0-9.]+'
WORKFLOW_AUDIT_CI="$(grep -oE "$AUDIT_CI_RE" .github/workflows/reusable-pr-quality.yml | head -1 || true)"
MAKEFILE_AUDIT_CI="$(grep -oE "$AUDIT_CI_RE" templates/Makefile.node | head -1 || true)"
if [ -z "$WORKFLOW_AUDIT_CI" ] || [ -z "$MAKEFILE_AUDIT_CI" ]; then
	fail "could not find the expected 'audit-ci@X.Y.Z' pin in reusable-pr-quality.yml and/or templates/Makefile.node -- has the pin format changed?"
	exit 2
fi
if [ "$WORKFLOW_AUDIT_CI" != "$MAKEFILE_AUDIT_CI" ]; then
	fail "audit-ci version pins differ: reusable-pr-quality.yml has '$WORKFLOW_AUDIT_CI', templates/Makefile.node has '$MAKEFILE_AUDIT_CI'"
fi

if [ "$FAIL" -eq 1 ]; then
	echo "::error::Pin consistency check failed -- see the errors above. This is exactly the class of drift that already caused PR #19 (templates/caller-pr-quality.yml left at a stale @v4 pin). Fix the mismatched file(s) before merging." >&2
	exit 1
fi

echo "Pin consistency check passed: reusable-workflow self-reference pin and all duplicated CI tool version pins agree."
