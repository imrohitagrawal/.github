# imrohitagrawal/.github

Shared GitHub config used across all of `@imrohitagrawal`'s repositories.

## What's here

- `.github/review-instructions.md` — Single source of truth for AI code review (Claude + Copilot). Edit here to change review behavior across every repo.
- `.github/workflows/ai-review.yml` — Reusable workflow. Call from any repo's workflow to trigger a Claude review on PRs.

## How to wire a new repo to this

1. In the new repo, create `.github/workflows/ai-review.yml`:
   ```yaml
   name: AI Review
   on:
     pull_request:
       types: [opened, synchronize, ready_for_review]
   permissions:
     contents: read
     pull-requests: write
     issues: write
     id-token: write
   jobs:
     review:
       uses: imrohitagrawal/.github/.github/workflows/ai-review.yml@main
       with:
         claude-model: claude-opus-4-8
         max-diff-lines: 600
       secrets:
         anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
   ```
2. Add `ANTHROPIC_API_KEY` as a repo secret (Settings → Secrets and variables → Actions).
3. For Copilot: also create `.github/copilot-instructions.md` in the new repo (one-line symlink or copy of the file above). Then enable Copilot Code Review in repo settings.

## Editing review behavior

Change `.github/review-instructions.md` here. Changes take effect on the next PR opened in any consuming repo.
