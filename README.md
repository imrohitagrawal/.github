# imrohitagrawal/.github

Reusable GitHub governance assets, opt-in CI workflows, and Codex review guidance for `@imrohitagrawal` repositories.

## What this repository provides

- **Eligible default community-health files** such as `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, issue templates, and pull-request templates. GitHub may use an eligible default only when the target repository does not provide its own version. This repository's root `README.md` is documentation for this repository and is not inherited by other repositories.
- **Issue templates** — `.github/ISSUE_TEMPLATE/bug_report.yml`, `.github/ISSUE_TEMPLATE/feature_request.yml`.
- **Reusable GitHub Actions workflows** — see `.github/workflows/`.
- **Templates** that target repositories can copy: `AGENTS.md`, `CODEOWNERS`, Dependabot configuration, caller workflows, and language-specific Makefiles.
- **Documentation** for repository onboarding, branch protection, and Codex review setup.

## What this repository does not do

- It does **not** automatically run workflows in target repositories. Each target repository must add a caller workflow that references the reusable workflow.
- It does **not** automatically enforce account-wide policy. Enforcement depends on each target repository's required checks, branch protection or rulesets, and local CI configuration.
- It does **not** make every configured check blocking. The current reusable workflow contains both blocking and advisory steps; consuming repositories must review the workflow and decide which failures should block merges.

## Review model

| Layer | Tool | Current role |
|---|---|---|
| **Deterministic CI** | GitHub Actions (`quality-gate` workflow) | Runs available tests, lint, type checks, security scans, and dependency audits. Some current steps are blocking and some are advisory. |
| **Intelligent reviewer** | Codex through the supported ChatGPT/GitHub workflow | Reviews correctness, security reasoning, design trade-offs, and missing tests. Advisory unless the target repository explicitly adds an enforcement mechanism. |
| **Repository guidance** | `AGENTS.md` in each repository | Defines severity rules, review expectations, and output conventions. |

**Rule:** A reusable workflow becomes a merge gate only when the consuming repository calls it and configures the resulting check as required. A green check is useful evidence, but human review remains required.

## Plan and repository compatibility

- GitHub Actions can run in public and private repositories subject to the repository owner's plan and usage limits.
- Availability of protected branches, rulesets, and required checks can depend on repository visibility and the current GitHub plan.
- Codex availability and usage limits are plan-dependent and should be verified against current official OpenAI documentation rather than treated as a permanent repository fact.

## Repository onboarding

Every target repository must opt in. See [`docs/repo-onboarding.md`](docs/repo-onboarding.md) for the setup steps.

## Layout

```text
.github/
  ISSUE_TEMPLATE/
    bug_report.yml
    feature_request.yml
  workflows/
    reusable-pr-quality.yml      # Opt-in reusable workflow
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

## Known current limitation

The reusable workflow currently mixes hard-failing and soft-failing checks. Workflow behaviour must be reconciled separately before this repository is described as providing a universal hard gate.
