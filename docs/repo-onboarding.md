# Repo Onboarding — adding the PR quality gate to a target repo

This document describes the exact steps to add the quality-gate + Codex review setup to any repository under `@imrohitagrawal`.

The shared source of truth lives in [`imrohitagrawal/.github`](https://github.com/imrohitagrawal/.github). Files in `templates/` are copied into the target repo.

## Setup steps (~10 steps, two products)

This is not a 5-minute task. It's roughly 10 steps spanning local Git/repository file changes (copying the caller workflow, dependabot config, and other templates in, then opening a PR), GitHub itself (branch protection is configured in repo **Settings**), and the ChatGPT UI (for Codex, which requires a paid **ChatGPT Plus** subscription or higher — see [`docs/codex-pr-review.md`](codex-pr-review.md#prerequisites)). Budget real time for it, especially the first time through a given repo.

**Steps 1–6 below are automated for an existing repo** by [`scripts/retrofit-quality-gate.sh`](../scripts/retrofit-quality-gate.sh) — it copies in the same files, detects your stack, and opens a branch/commit (optionally a PR with `--push`) without clobbering anything already there. For a **brand-new** repo, create it from [`imrohitagrawal/repo-template`](https://github.com/imrohitagrawal/repo-template) instead — it starts with these files already in place, so steps 1–6 don't apply at all. Either way, **steps 7–10 stay manual** — they need human judgment and access to GitHub/ChatGPT UIs a script can't drive.

For every target repo, in order:

1. **Copy `templates/AGENTS.md`** to the target repo root.
   ```bash
   cp templates/AGENTS.md /path/to/target-repo/AGENTS.md
   git add AGENTS.md
   ```
   This is the file Codex reads when reviewing PRs.

2. **Copy `templates/CODEOWNERS`** to `.github/CODEOWNERS`.
   ```bash
   mkdir -p /path/to/target-repo/.github
   cp templates/CODEOWNERS /path/to/target-repo/.github/CODEOWNERS
   git add .github/CODEOWNERS
   ```

3. **Copy `templates/caller-pr-quality.yml`** to `.github/workflows/pr-quality.yml`.
   ```bash
   cp templates/caller-pr-quality.yml /path/to/target-repo/.github/workflows/pr-quality.yml
   git add .github/workflows/pr-quality.yml
   ```
   This is the small caller that triggers the reusable quality-gate workflow from `imrohitagrawal/.github`.

4. **Copy `templates/dependabot.yml`** to `.github/dependabot.yml`.
   ```bash
   cp templates/dependabot.yml /path/to/target-repo/.github/dependabot.yml
   git add .github/dependabot.yml
   ```

5. **Add a project Makefile** if the repo doesn't have one:
   - **Python project** (has `pyproject.toml`, `requirements.txt`, or `setup.py`):
     ```bash
     cp templates/Makefile.python /path/to/target-repo/Makefile
     git add Makefile
     ```
   - **Node project** (has `package.json`):
     ```bash
     cp templates/Makefile.node /path/to/target-repo/Makefile
     git add Makefile
     ```
   - **Other language:** write a `Makefile` with a `ci:` target that runs whatever checks the project already uses. The reusable workflow will pick it up.

6. **Open a PR** with all the above as one commit:
   ```bash
   git checkout -b setup/pr-quality-gate
   git commit -m "Add PR quality gate and Codex review guidance"
   git push origin setup/pr-quality-gate
   ```
   Then open a PR on GitHub.

7. **Let GitHub Actions run once.** The `quality-gate` check should appear and pass.

8. **Configure branch protection** to require the `quality-gate` check. See [`docs/branch-protection.md`](branch-protection.md) for the exact UI steps. This step is **mandatory for the hard gate to actually block** — without it, red checks are visible but don't block merge.

9. **Enable Codex review** for the repo (requires a paid ChatGPT Plus subscription or higher). See [`docs/codex-pr-review.md`](codex-pr-review.md) for the exact UI steps. One-time setup per repo.

10. **Open a test PR** to confirm:
    - `quality-gate` runs and shows a green check.
    - Codex posts a review comment (or responds to `@codex review`).
    - With branch protection enabled, the merge button is greyed out until the check passes.

## What if the repo already has CI?

Don't break it. The reusable workflow's `Makefile`-detection logic will run whatever `make ci` does. If your existing CI is in a different file:

- Add a thin `Makefile` with a `ci:` target that calls your existing CI:
  ```makefile
  ci:
      ./scripts/run-tests.sh
      ./scripts/run-lint.sh
  ```
- The reusable workflow will use that.

## What if the repo is private?

The reusable workflow runs on private repos too — GitHub Actions is free for private repos up to a usage limit. The only thing that breaks is **hard merge blocking via branch protection**, which may require GitHub Pro on private repos. See [`docs/branch-protection.md`](branch-protection.md) for the workaround.

## What if the repo is not a typical code project?

The reusable workflow has a fallback: if no `Makefile` ci target, `package.json`, or Python manifest is found, it runs only the secret scan and posts a notice. This is fine for repos that hold only documentation, schemas, or other non-executable content — Codex + manual review are the only quality layer for those.

## What about pnpm or yarn instead of npm?

Supported. The workflow detects the package manager via `package.json`'s `packageManager` field first (wins if present — this is Corepack's own field, so setting it also gets you a fully reproducible install, pinned to the exact version you declared), falling back to lockfile presence (`pnpm-lock.yaml` → pnpm, `yarn.lock` → yarn) if that field isn't set, and to plain `npm` if neither signal exists. Existing npm-only repos are unaffected either way.

One gap: the advisory `npm audit` step (the one that runs when the repo has *not* added an `audit-ci` config) is npm-only — a pnpm/yarn repo without an `audit-ci` config gets a notice instead, not silent advisory coverage. The **blocking** path (add an `audit-ci` config, see the main table above) works identically for all three package managers — `audit-ci` detects the manager from the lockfile itself.

## Why there's no "new workflow" picker entry for these templates

GitHub can surface starter workflows directly in a repo's **Actions → New workflow** picker when they live in `.github/workflow-templates/` of an *Organization*-owned `.github` repo. `imrohitagrawal` is a personal User account, not an Organization (`gh api orgs/imrohitagrawal` → `404`) — there is no verified evidence that mechanism works the same way for a user-owned `.github` repo, and GitHub's documented procedure for it is written for org-owned repos specifically. Rather than ship `.github/workflow-templates/` and hope it gets picked up, the actual path is [`imrohitagrawal/repo-template`](https://github.com/imrohitagrawal/repo-template) — a separate, minimal, real template repo (`is_template: true`) that a new repo can be created from directly via "Use this template" — that route doesn't depend on the unverified picker behavior.
