# imrohitagrawal/.github

Global GitHub defaults, reusable CI gates, and Codex review guidance for `@imrohitagrawal` repositories.

## What this repository provides

- **Default community files** — `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `PULL_REQUEST_TEMPLATE.md`, `CODE_OF_CONDUCT.md`. These apply to a target repo **only when the target repo does not override them**.
- **Issue templates** — `.github/ISSUE_TEMPLATE/bug_report.yml`, `.github/ISSUE_TEMPLATE/feature_request.yml`.
- **Reusable GitHub Actions workflows** — see `.github/workflows/`.
- **Templates** that every target repo can copy: `AGENTS.md` (Codex review guidance), `CODEOWNERS`, dependabot config, language Makefiles.
- **Documentation** for onboarding, branch protection, and Codex review setup.

## What this repository does NOT do

- It does **not** automatically run in any target repo. GitHub Actions cannot be inherited across repos — every target repo must add a small caller workflow that references this repo's reusable workflow.
- It does **not** enforce anything by itself. Enforcement happens in each target repo's branch protection / rulesets and in their own CI configuration.

## Review model

| Layer | Tool | Role |
|---|---|---|
| **Hard gate** | GitHub Actions (`quality-gate` workflow) | Deterministic checks: tests, lint, type check, security scans (bandit, semgrep, gitleaks), dependency audit. |
| **Intelligent reviewer** | Codex (via ChatGPT UI / `@codex review` PR comment) | Correctness, security reasoning, design feedback, missing tests, review-worthy judgment calls. |
| **Soft guidance** | `AGENTS.md` in each repo | Severity rules, review checklist, output style for Codex. |

**Rule:** GitHub Actions is the hard merge gate. Codex review is advisory. A green CI is **necessary** but not **sufficient** — human review (and Codex review) is required on top of it.

## GitHub Free compatibility

- **Public repositories on GitHub Free:** branch protection / rulesets can require status checks. The hard gate works fully.
- **Private repositories on GitHub Free:** GitHub Actions still runs and fails visibly. However, **hard merge blocking through branch protection rulesets may require GitHub Pro / Team / Enterprise**. On the free plan, the gate is process-enforced: never merge red PRs, use the PR template checklist, use Codex review, use CODEOWNERS.
- **Codex itself is free with ChatGPT Plus.** Connecting GitHub repos to Codex is a one-time UI step per repo.

## Repo-onboarding

Every target repo needs a 5-minute setup. See [`docs/repo-onboarding.md`](docs/repo-onboarding.md) for the exact steps.

## Layout

```
.github/
  ISSUE_TEMPLATE/
    bug_report.yml
    feature_request.yml
  workflows/
    reusable-pr-quality.yml      # The reusable quality-gate workflow
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
README.md
CONTRIBUTING.md
SECURITY.md
PULL_REQUEST_TEMPLATE.md
CODE_OF_CONDUCT.md
```