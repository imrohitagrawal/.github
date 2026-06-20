# Branch Protection & Hard Merge Gates

The `quality-gate` workflow is the **hard gate**. For it to actually block merges, the target repo needs branch protection (or rulesets) that **require the `quality-gate` status check to pass**.

## Public repositories on GitHub Free

Branch protection and rulesets work fully on public repos under GitHub Free. Setup steps:

1. Open the target repo on GitHub.
2. Go to **Settings** → **Branches** (for classic branch protection) **or** **Rules** → **Rulesets** (for the newer ruleset-based system; recommended).
3. Click **Add branch protection rule** or **New branch ruleset**.
4. **Target branch pattern:** `main` (or your default branch name).
5. Enable the following:
   - ☑ **Require a pull request before merging**
   - ☑ **Require status checks to pass**
   - ☑ **Require branches to be up to date before merging** (if available)
   - ☑ **Require conversation resolution before merging**
   - ☑ **Do not allow force pushes**
   - ☑ **Do not allow deletions**
6. In **Status checks that are required**, search for `quality-gate` and select it.
   - **Important:** `quality-gate` will only appear in the list **after** the workflow has run at least once on the repo. Open a test PR first if it isn't there.
7. Click **Create** / **Save changes**.

After this:
- The merge button on a PR with a red `quality-gate` will be disabled.
- The merge button is enabled only when `quality-gate` is green **and** any required reviews are in place.

## Private repositories on GitHub Free

GitHub Actions still runs and fails visibly on private repos under GitHub Free. However:

- **Branch protection rulesets** that require status checks may require GitHub Pro / Team / Enterprise for private repos.
- **Classic branch protection** is more limited on private repos.

If you see the option greyed out or the ruleset cannot be enforced, fall back to **process enforcement**:

1. **Never merge a red PR.** Make it a hard rule for yourself and any contributors.
2. **Use the PR template checklist** (`.github/PULL_REQUEST_TEMPLATE.md`) — it forces the author to acknowledge risk review.
3. **Use Codex review** — `@codex review` comments give a second opinion before merge.
4. **Use CODEOWNERS** — the owner is the only person who can approve.
5. **Use rulesets that don't require paid features.** Some rules (force-push prevention, deletion prevention, conversation resolution) are free even on private repos.

## Verification

To prove the gate works after setup:

1. Open a test PR that introduces a failing check (e.g. add a syntax error to a Python file).
2. Confirm `quality-gate` shows red.
3. Confirm the **Merge** button is disabled (public repo with branch protection) — or, on private repo free plan, that the red status is unmistakable.
4. Revert the failing change. Confirm `quality-gate` goes green. Confirm the **Merge** button becomes available.

## Limitations on GitHub Free

| Feature | Public repo | Private repo |
|---|---|---|
| GitHub Actions | ✅ Free (with monthly minute limits) | ✅ Free (with monthly minute limits) |
| Branch protection (classic) | ✅ Full | ⚠️ Limited |
| Rulesets (newer) | ✅ Full | ⚠️ May require Pro for some rule types |
| Required status checks | ✅ Yes | ⚠️ May require Pro for private repos |
| Required reviewers | ✅ Yes | ⚠️ May require Pro for private repos |
| Code scanning (CodeQL) | ✅ Free | ❌ Requires GitHub Advanced Security (paid) |

This is why `aegis-contracts` (private) has Codex review only and no CodeQL — the cost-benefit doesn't make sense for a small contracts repo. See [`docs/codex-pr-review.md`](codex-pr-review.md) for the alternative enforcement on private repos.