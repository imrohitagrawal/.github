# Engineering Standards & AI Delivery System

> Reusable CI quality gates, security checks, AI-assisted review guidance, and community standards across the `@imrohitagrawal` engineering portfolio.

This repository is the shared delivery control plane for my public projects. It turns the principles behind my work—evidence over claims, deterministic validation, secure defaults, visible degradation, and human-reviewed AI—into reusable repository assets.

## Portfolio map

| Repository | Product / system | Engineering signal |
|---|---|---|
| [CiteVyn](https://github.com/imrohitagrawal/citevyn) | Citation-grounded Q&A over official AI documentation | RAG, pgvector, secure APIs, observability, refusal as a product capability |
| [Quorum-AI](https://github.com/imrohitagrawal/quorum-ai) | Multi-model LLM orchestration with critique and synthesis | Parallel execution, cost guardrails, source support, readiness and security controls |
| [SaafSaans](https://github.com/imrohitagrawal/saaf-saans) | Persona-aware Delhi/NCR air-quality companion | Grounded guidance, graceful fallback, privacy boundaries, accessibility, extensive testing |
| [NarraTwin AI](https://github.com/imrohitagrawal/narratwin-ai) | Grounded multilingual project-walkthrough platform | RAG, unsupported-claim evaluation, provider abstraction, responsible synthetic-media rules |
| [Project Documentation Skills](https://github.com/imrohitagrawal/project-doc-skills) | Eight reusable AI documentation and review skills | Diátaxis, independent critique, deterministic packaging, integrity manifests, release gates |

## What this repository provides

- **Default community files** — `CONTRIBUTING.md`, `SECURITY.md`, `PULL_REQUEST_TEMPLATE.md`, and `CODE_OF_CONDUCT.md`. These apply to a target repository only when that repository does not override them.
- **Issue templates** — `.github/ISSUE_TEMPLATE/bug_report.yml` and `.github/ISSUE_TEMPLATE/feature_request.yml`.
- **Reusable GitHub Actions workflows** — deterministic quality and security checks under `.github/workflows/`.
- **Repository templates** — `AGENTS.md`, `CODEOWNERS`, Dependabot configuration, caller workflows, and language-specific Makefiles.
- **Operating documentation** — onboarding, branch protection, and Codex review setup.
- **GitHub profile brand kit** — recruiter-facing profile copy, repository positioning, and publishing steps under [`docs/github-profile/`](docs/github-profile/).

## Review and delivery model

| Layer | Tool | Role |
|---|---|---|
| **Hard gate** | GitHub Actions `quality-gate` workflow | Tests, lint, type checks, security scans, secret detection, and dependency audit |
| **Intelligent reviewer** | Codex through ChatGPT / `@codex review` | Correctness, security reasoning, design feedback, and missing-test analysis |
| **Human judgment** | Pull-request review | Product intent, acceptable risk, architectural trade-offs, and final accountability |
| **Repository guidance** | `AGENTS.md` | Severity rules, review checklist, boundaries, and expected output style |

**Operating rule:** green CI is necessary, but not sufficient. AI review is advisory; accountable human review remains part of the merge decision.

## What this repository does not do

- It does **not** automatically run inside every repository. Each target repository adds a small caller workflow that references the reusable workflow here.
- It does **not** enforce branch protection by itself. Enforcement remains in each target repository's rulesets and CI configuration.
- It does **not** treat AI-generated review as an approval substitute.

## Repository onboarding

Every target repository needs a short setup pass. See [`docs/repo-onboarding.md`](docs/repo-onboarding.md) for the exact steps.

## GitHub Free compatibility

- **Public repositories on GitHub Free:** rulesets can require the quality-gate status check.
- **Private repositories on GitHub Free:** Actions still run and failures remain visible, while hard merge blocking may depend on plan capabilities. In that case, the gate is process-enforced through PR discipline, review checklists, and CODEOWNERS.

## Layout

```text
.github/
  ISSUE_TEMPLATE/
    bug_report.yml
    feature_request.yml
  workflows/
    reusable-pr-quality.yml

docs/
  repo-onboarding.md
  codex-pr-review.md
  branch-protection.md
  github-profile/
    PROFILE_README.md
    PUBLISH_CHECKLIST.md
    REPOSITORY_METADATA.md

templates/
  AGENTS.md
  CODEOWNERS
  caller-pr-quality.yml
  Makefile.python
  Makefile.node
  dependabot.yml

README.md
CONTRIBUTING.md
SECURITY.md
PULL_REQUEST_TEMPLATE.md
CODE_OF_CONDUCT.md
```
