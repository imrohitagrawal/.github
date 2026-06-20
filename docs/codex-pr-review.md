# Codex PR Review

Codex (from OpenAI / ChatGPT) is the **intelligent reviewer** in this setup. It runs on top of the deterministic `quality-gate` workflow and provides reasoning that static analysis cannot — design feedback, security implications, missing tests, judgment calls.

This document covers how to set up Codex for a target repo and how to use it day-to-day.

## Prerequisites

- A ChatGPT **Plus** subscription (or higher). Codex is bundled with paid ChatGPT plans.
- Browser access to chatgpt.com / chat.openai.com.
- GitHub account: `imrohitagrawal`.
- An `AGENTS.md` file at the root of the target repo (provided by `templates/AGENTS.md` in the global `.github` repo).

## One-time UI setup per repo

1. Open ChatGPT at <https://chatgpt.com>.
2. Open Codex (sidebar, or via the dedicated Codex interface if available).
3. Go to **Settings** → **Connections** → **GitHub**.
4. Connect GitHub account `imrohitagrawal`.
5. Authorize only the repositories you want Codex to access. Grant the minimum scopes Codex needs (read repo contents, read PRs, post comments).
6. Open the Codex **Settings → Repositories** panel.
7. For each target repo:
   - Toggle **Code Review** on.
   - Toggle **Automatic Reviews** on (Codex will post a review on every new PR).
8. Confirm the target repo's `AGENTS.md` is present at the repo root — Codex reads it to calibrate its review style and severity rules.
9. Open a small test PR on the target repo. Confirm Codex posts a review comment within a few minutes.

## Day-to-day usage

### Automatic review (default)

With **Automatic Reviews** on, Codex posts a review on every PR. The review follows the output style defined in `AGENTS.md` (Summary / High-risk findings / Missing tests / Suggested fixes / Final recommendation).

### Manual trigger

If automatic review is off, or you want a fresh review after pushing new commits:

- Comment on the PR:
  ```
  @codex review
  ```

### Focused security review

For PRs that touch auth, payments, infra, secrets, or CI/CD:

```
@codex review this PR for security regressions, missing tests, risky behavior changes, secret exposure, CI/CD weakening, and rollback risks.
```

### Acting on a Codex review

Codex review is **advisory**. The author is responsible for deciding what to act on. The rule of thumb:

1. **Read the full review.** Don't skim.
2. **Validate every finding.** Codex can be wrong, especially around architectural or domain-specific decisions. Verify each P0/P1 by reading the code.
3. **For valid issues**, fix them in the same PR — or in a follow-up PR if the fix is large. If you want Codex to apply the fixes, comment:
   ```
   @codex fix the valid issues from your review while preserving existing behavior and tests.
   ```
4. **For invalid findings**, mark them resolved with a short comment explaining why.
5. **Do not blindly accept suggested fixes.** A correct-sounding fix can break invariants the AI doesn't know about. Always review the diff.

## What Codex is good at

- Catching missing edge cases in tests.
- Flagging security anti-patterns.
- Identifying over-complex code that should be split.
- Suggesting clearer names and tighter error messages.
- Calling out assumptions the author didn't make explicit.

## What Codex is NOT good at

- **Cross-file invariants** that depend on the whole codebase — Codex has limited whole-codebase context.
- **Performance reasoning** based on real measurements — Codex reasons about complexity but can't run a profiler.
- **Final merge decision** — only humans should approve merging.
- **Replacing tests** — Codex can suggest tests but doesn't run them. The `quality-gate` workflow runs them.

## Severity: how Codex prioritizes findings

Codex follows the rules in `AGENTS.md`:

- **P0** findings (secrets, authn/authz bypass, SQLi, etc.) must block merge.
- **P1** findings should block until fixed or explicitly accepted.
- **P2** findings should improve but don't block.

A P0 finding from Codex is treated the same as a P0 finding from a human reviewer: the PR does not merge until the issue is fixed or the risk is explicitly acknowledged.

## Operating constraints

- **Codex review is advisory.** It never *enforces* anything. The hard gate is GitHub Actions.
- **Codex is not a substitute for the PR template's risk review.** The author is still required to check the security/performance/rollback boxes in the PR description.
- **Codex does not have write access by default.** It posts review comments. If you want Codex to push commits, enable that explicitly in the Codex UI — and review every commit it pushes.
- **Cost is bounded by ChatGPT Plus.** Heavy review usage on many large PRs may hit ChatGPT Plus rate limits; that's an OpenAI-side constraint, not a setup issue.
