# AGENTS.md

> **This file is consumed by Codex (ChatGPT) when reviewing PRs in this repo.**
> Codex reads it via the GitHub integration. Keep this file at the repo root.

## About this repo

This is `imrohitagrawal/.github` itself — the source of the reusable PR
quality gate (`.github/workflows/reusable-pr-quality.yml`) and templates
(`templates/`) that every other `@imrohitagrawal` repo adopts. WP1
(dogfooding, F1/F25) made this repo consume its own product instead of only
shipping it: it has no `package.json`/`pyproject.toml` of its own — its
content IS GitHub Actions YAML and Markdown docs, not an npm/pip project — so
its quality gate is two first-party workflows, not the npm/Python native
paths this repo's reusable workflow runs for *consumer* repos (see "Review
principles" below for exactly what "gate" means today - it's not yet wired
into required branch protection):

- `.github/workflows/self-test.yml` — calls `reusable-pr-quality.yml` via
  `workflow_call` against real, checked-in fixture scenarios
  (`.github/self-test-fixtures/`), proving the reusable workflow's own
  detection/dispatch logic works, including a deliberately-failing fixture
  that proves the gate actually blocks rather than silently passing.
- `.github/workflows/self-lint.yml` — `actionlint` (with bundled
  `shellcheck` on every embedded `run:` block) on
  `reusable-pr-quality.yml`/`templates/caller-pr-quality.yml` and this
  repo's own two self-test/self-lint workflows, plus `markdownlint` on
  `docs/*.md`, `README.md`, `templates/AGENTS.md`, and this file
  (`AGENTS.md` at the repo root - round-2 review fix, real Codex finding:
  an earlier version of this list omitted this file even though
  self-lint.yml's own command already covers it).

A change to this repo is really a change to what every consumer repo trusts —
review it with that in mind, not as an isolated docs/CI tweak.

## Review principles

- **`self-test` and `self-lint` (GitHub Actions) are this repo's
  deterministic quality gate** - reusable-workflow fixture exercises,
  Actions-YAML lint, embedded-shell lint, and doc lint. Round-2 review
  fix (real Codex finding): calling this "the hard gate" without
  qualification overclaimed enforcement - as of this commit, neither
  workflow is yet a required branch-protection status check (see
  README.md's Dogfooding section), so a red run does not yet mechanically
  block a merge. Treat a red **`self-test`/`self-lint` job's own
  conclusion** (not the workflow run's overall conclusion) on a PR as a
  blocking finding anyway, the same as if it were already required -
  wiring that up is tracked as a follow-up, not a reason to relax the bar
  in the meantime.
- **The `Self-test` workflow's overall run conclusion is expected to be
  non-green on every run, by design** - real Codex finding on PR #15,
  fixed here rather than in the workflow file itself: two of its jobs
  (`node-lint-violation`, `python-test-failure`) deliberately call
  `reusable-pr-quality.yml` against fixtures crafted to fail it, and
  `continue-on-error` isn't available on a job that calls a reusable
  workflow via `uses:` (confirmed with `actionlint`), so those two jobs
  show red on every single run - that's correct, not a bug (see
  `self-test.yml`'s own header comment). The signal that actually matters
  is the final **`self-test` job** (and separately, `self-lint`'s job),
  which aggregate every scenario's `needs.<job>.result` - including the
  two negative fixtures' own assert jobs, not their raw pass/fail - and
  only fail if an assertion is actually violated. Read the specific job's
  conclusion in the PR checks list, not the workflow run's badge/summary
  conclusion, which will always show red because of the two jobs above.
- **Codex is the intelligent reviewer.** It reasons about correctness,
  design, security implications, and missing tests — especially whether a
  change to `reusable-pr-quality.yml` or `templates/caller-pr-quality.yml`
  changes behavior for `citevyn` or any other real consumer, since neither
  first-party gate above can detect that from inside this repo alone.
- **Do not approve code only because checks pass.** Checks passing is
  necessary, not sufficient — especially for a change to the one file every
  consumer's CI depends on.
- Review correctness, maintainability, testability, security, performance,
  reliability, observability, and rollback safety.
- Prefer small, focused pull requests — this repo's own history (WP0–WP9,
  each its own PR) is the model to follow, not a bundled diff.
- Call out assumptions explicitly.
- Prefer actionable findings over generic comments.

## Severity rules

### P0 — must block merge

- Secrets, tokens, passwords, private keys, or credentials committed to code.
- Authentication bypass.
- Authorization bypass.
- SQL injection.
- Command injection.
- SSRF.
- Unsafe deserialization.
- XSS.
- Path traversal.
- Unsafe file upload.
- Breaking production-critical behavior without migration / rollback notes.
- A CI/CD workflow change that weakens security **or that changes behavior
  for an existing consumer repo pinned to a released tag** (e.g. `citevyn`
  on `@v3`/`@v4`) without that being called out explicitly.
- Logging sensitive data.
- Removing or weakening security checks.
- Reintroducing a swallowed exit code (`continue-on-error: true`, `|| true`,
  `|| echo ...`) on a step this repo's own history already fixed once (see
  `reusable-pr-quality.yml`'s header comment on the pre-2026-08-11 fake
  gate) — this is the single most recurring real defect in this repo's own
  audit history and should be treated as a P0 on sight, not a style nit.

### P1 — should block until fixed or explicitly accepted

- Missing tests for changed business logic — for this repo, that means a
  change to `reusable-pr-quality.yml`'s detection/dispatch logic with no
  corresponding `.github/self-test-fixtures/` scenario (new or updated)
  exercising it.
- Breaking API / schema change without migration notes — for this repo,
  that means a `workflow_call` input/output change without a note on what
  happens to `v3`/`v4`-pinned consumers.
- Broad exception swallowing.
- Flaky or non-deterministic tests.
- Missing validation for user-controlled input.
- Missing observability for important failure paths.
- Risky dependency upgrade without test evidence (e.g. bumping a pinned
  action SHA or CLI tool version without checking its release notes).
- Performance regression risk in hot path.

### P2 — should improve

- Duplicated logic.
- Poor naming.
- Over-complex code.
- Weak comments.
- Missing edge-case documentation.
- Minor maintainability concerns.

## Codex review checklist

When reviewing a PR, check:

1. Does the PR solve the stated problem?
2. Are the self-test fixtures adequate for what changed?
3. Are edge cases covered?
4. Is the design simple enough?
5. Are there security risks?
6. Are secrets exposed?
7. Are logs safe?
8. Are errors handled correctly?
9. Is rollback possible? For a tagged reusable workflow, rollback means
   cutting a new tag, never force-moving an existing one (see this repo's
   own versioning policy).
10. Are docs updated if behavior changed — including `README.md`,
    `docs/repo-onboarding.md`, and this repo's own commit-message
    convention of documenting residuals honestly?

## Required review output style

Use this exact format:

### Summary

Briefly explain what changed.

### High-risk findings

List only P0 / P1 issues.

### Missing tests

List specific missing tests.

### Suggested fixes

Give actionable fixes.

### Final recommendation

Choose one:

- **Safe to merge after CI passes**
- **Do not merge until P0 / P1 issues are fixed**
- **Needs human design review**

## Operating constraints

- Codex review is **advisory**. It is not a substitute for the `self-test`
  / `self-lint` GitHub Actions workflows.
- Green `self-test` and `self-lint` checks are **necessary but not
  sufficient**. Human review and Codex review are still required.
- Do not recommend changes that would weaken CI/CD, remove tests, or remove
  security checks — even if the change "looks fine".
- If you find a real P0 issue, escalate in the review with the exact
  location, the impact, and the suggested fix.
