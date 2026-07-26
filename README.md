# Engineering Standards

Shared repository standards for [`@imrohitagrawal`](https://github.com/imrohitagrawal).

This repository contains reusable CI workflows, security controls, contribution policies, and AI-assisted review guidance used across software and AI engineering projects.

## Operating principles

- **Evidence over claims** — important behavior should be supported by tests, telemetry, security checks, or reproducible artifacts.
- **Deterministic delivery gates** — linting, type checks, tests, dependency audits, and secret detection belong in the merge path.
- **Secure defaults** — credentials, dependencies, untrusted inputs, and release boundaries are handled explicitly.
- **Visible system state** — degraded, simulated, cached, and unavailable states should not be presented as normal operation.
- **Human accountability** — AI can accelerate implementation and review; maintainers remain responsible for engineering decisions.

## Repository assets

| Area | Purpose |
|---|---|
| Default community files | Shared contribution, security, conduct, and pull-request standards |
| Issue templates | Consistent bug reports and feature proposals |
| Reusable GitHub Actions | Portfolio-wide quality and security checks |
| Repository templates | `AGENTS.md`, `CODEOWNERS`, Dependabot, caller workflows, and language Makefiles |
| Operating guidance | Repository onboarding, branch protection, and Codex review setup |

## Review model

| Layer | Responsibility |
|---|---|
| **GitHub Actions** | Deterministic tests, linting, type checks, security scans, secret detection, and dependency audit |
| **AI-assisted review** | Advisory analysis of correctness, design, security reasoning, and missing tests |
| **Maintainer review** | Product intent, architectural trade-offs, acceptable risk, and final approval |

A green automated gate is necessary, but not sufficient. AI review does not replace accountable human judgment.

## Adoption

Reusable workflows and defaults do not execute automatically in every repository. Each target repository must add the appropriate caller workflow and configure its own rulesets or branch-protection policy.

Start with:

- [`docs/repo-onboarding.md`](docs/repo-onboarding.md)
- [`docs/branch-protection.md`](docs/branch-protection.md)
- [`docs/codex-pr-review.md`](docs/codex-pr-review.md)

## Scope

This repository is intentionally limited to shared engineering governance and delivery standards. Personal profile branding belongs in the dedicated public profile repository named [`imrohitagrawal`](https://github.com/imrohitagrawal/imrohitagrawal).