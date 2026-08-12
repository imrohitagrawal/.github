# imrohitagrawal/.github

Global GitHub defaults, reusable CI gates, and Codex review guidance for `@imrohitagrawal` repositories.

## What this repository provides

- **Default community files** — `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `SUPPORT.md`, `PULL_REQUEST_TEMPLATE.md`, `CODE_OF_CONDUCT.md`. These apply to a target repo **only when the target repo does not override them**.
- **Issue templates** — `.github/ISSUE_TEMPLATE/bug_report.yml`, `.github/ISSUE_TEMPLATE/feature_request.yml`.
- **Discussion category forms** — `.github/DISCUSSION_TEMPLATE/` guidance for General, Q&A, Ideas, and Show and tell categories.
- **Reusable GitHub Actions workflows** — see `.github/workflows/`.
- **Templates** that every target repo can copy: `AGENTS.md` (Codex review guidance), `CODEOWNERS`, dependabot config, language Makefiles.
- **Documentation** for onboarding, branch protection, and Codex review setup.

## What this repository does NOT do

- It does **not** automatically run in any target repo. GitHub Actions cannot be inherited across repos — every target repo must add a small caller workflow that references this repo's reusable workflow.
- It does **not** enforce anything in a *target* repo by itself. Enforcement happens in each target repo's branch protection / rulesets and in their own CI configuration.

## Dogfooding: this repo's own gate

This repo consumes its own product, not only ships it (WP1). It has no `package.json`/`pyproject.toml` — its content IS GitHub Actions YAML and docs — so it runs two first-party workflows on its own PRs:

- **`self-test`** — calls `reusable-pr-quality.yml` via `workflow_call` against real, checked-in fixture scenarios under `.github/self-test-fixtures/` (Node-only, Python-only, a monorepo using the `python-directory`/`node-directory` inputs, the no-manifest fallback, and a deliberately-failing fixture that proves the gate actually blocks rather than silently passing).
- **`self-lint`** — `actionlint` (with bundled `shellcheck`) on `reusable-pr-quality.yml`, `templates/caller-pr-quality.yml`, and this repo's own workflow files, plus `markdownlint` on the docs.

Making these required branch-protection status checks (alongside WP0's existing protection) is tracked as a follow-up, not yet done as of this commit.

## Review model

| Layer | Tool | Role |
| --- | --- | --- |
| **Hard gate** | GitHub Actions (`quality-gate` workflow) | Deterministic checks: tests, lint, type check, security scans (bandit, semgrep, gitleaks), dependency audit. |
| **Intelligent reviewer** | Codex (via ChatGPT UI / `@codex review` PR comment) | Correctness, security reasoning, design feedback, missing tests, review-worthy judgment calls. |
| **Soft guidance** | `AGENTS.md` in each repo | Severity rules, review checklist, output style for Codex. |

**Rule:** GitHub Actions is the hard merge gate. Codex review is advisory. A green CI is **necessary** but not **sufficient** — human review (and Codex review) is required on top of it.

## GitHub Free compatibility

- **Public repositories on GitHub Free:** branch protection / rulesets can require status checks. The hard gate works fully.
- **Private repositories on GitHub Free:** GitHub Actions still runs and fails visibly. However, **hard merge blocking through branch protection rulesets may require GitHub Pro / Team / Enterprise**. On the free plan, the gate is process-enforced: never merge red PRs, use the PR template checklist, use Codex review, use CODEOWNERS.
- **Codex review requires a paid ChatGPT Plus subscription (or higher).** It's bundled into that plan rather than billed separately, but it is not free on its own. Connecting GitHub repos to Codex is a one-time UI step per repo.

## Repo-onboarding

Onboarding a target repo is roughly 10 hand-run steps spanning local Git/repository file changes, GitHub itself (branch protection lives in repo Settings), and the ChatGPT UI for Codex — not a 5-minute task. See [`docs/repo-onboarding.md`](docs/repo-onboarding.md) for the exact steps. A future minimal template repo and retrofit script (a planned follow-up, not yet built or tracked anywhere in this repo) are intended to shrink this considerably; until then, budget real time for the manual steps.

## Layout

```text
.github/
  ISSUE_TEMPLATE/
    bug_report.yml
    feature_request.yml
  DISCUSSION_TEMPLATE/
    general.yml
    ideas.yml
    q-a.yml
    show-and-tell.yml
  workflows/
    reusable-pr-quality.yml      # The reusable quality-gate workflow
    self-test.yml                # WP1: exercises reusable-pr-quality.yml against real fixtures
    self-lint.yml                # WP1: actionlint/shellcheck/markdownlint on this repo's own content
  self-test-fixtures/            # WP1: real fixture scenarios self-test.yml calls the reusable workflow against
    node-only/
    python-only/
    monorepo/
      backend/
      frontend/
    node-lint-violation/         # deliberately fails — proves the gate actually blocks
  CODEOWNERS                     # WP1: this repo's own code owners (adapted from templates/CODEOWNERS)
  dependabot.yml                 # WP2: dependabot config for this repo's own github-actions ecosystem
templates/
  AGENTS.md                      # Codex review guidance
  CODEOWNERS
  caller-pr-quality.yml          # Caller workflow for each target repo
  Makefile.python
  Makefile.node
  dependabot.yml
docs/
  repo-onboarding.md
  codex-pr-review.md
  branch-protection.md
AGENTS.md                        # WP1: this repo's own Codex review guidance (adapted from templates/AGENTS.md)
README.md
CONTRIBUTING.md
SECURITY.md
SUPPORT.md
PULL_REQUEST_TEMPLATE.md
CODE_OF_CONDUCT.md
.markdownlint.jsonc               # WP1: config for the self-lint markdownlint step
```
