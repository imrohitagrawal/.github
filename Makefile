# C1 (review finding): this repo's own root had no Makefile, which meant
# self-test could never exercise reusable-pr-quality.yml's WP7 Makefile-
# dispatch path (has_makefile_ci/lint/typecheck/test are unconditionally
# root-scoped -- see reusable-pr-quality.yml's "Detect project layout" step)
# against anything real, proven by mutation. This Makefile closes that.
#
# Targets are genuinely no-ops, deliberately: this repo's own first-party
# quality gate already lives in .github/workflows/self-lint.yml (actionlint,
# shellcheck, markdownlint, the pin-consistency check) -- this file exists
# to be DISPATCHED TO by the reusable workflow's own logic, proving the
# mechanism works end-to-end against a real root Makefile, not to duplicate
# that gate a second time under a different name.
#
# Adding this file is a real, one-time trade-off, not a free lunch: since
# has_makefile_ci is root-scoped unconditionally (ignores every job's own
# python-directory/node-directory input), every self-test job now sees this
# Makefile -- and the "no recognized project files, fall back to secret-scan
# only" branch (reusable-pr-quality.yml's final elif/else) becomes
# structurally unreachable by self-test from this point forward, because
# there is no longer a way to construct a fixture whose has_makefile_ci
# evaluates false. See self-test.yml's own comment on the job this replaced
# (formerly `no-manifest`) for the full trade-off.
.PHONY: ci lint typecheck test

ci: lint typecheck test

lint:
	@true

typecheck:
	@true

# H7 review fix (test coverage, review finding): genuinely non-trivial (per
# compute_makefile_trust's own is_trivial_makefile_recipe check) and names
# .github/self-test-fixtures/makefile-trust-positive by path, so that ONE
# fixture's trust_makefile_test_for_python evaluates true - proving the
# actual trust=true skip path fires in CI, not just that the underlying
# logic is correct in isolation. Every other job's directory string doesn't
# appear here, so this target stays untrusted (and thus harmless) for them -
# `cd`ing into this directory and succeeding is universally safe regardless
# of which fixture a given job is otherwise exercising, since it always runs
# from the repo root.
test:
	cd .github/self-test-fixtures/makefile-trust-positive && true
