# Contributing

Thanks for contributing to `@imrohitagrawal` projects.

## How to contribute

- **Use pull requests for all changes.** No direct pushes to `main`.
- **Keep PRs small and focused.** One concern per PR. If a change touches more than ~400 lines, split it.
- **Include tests for changed logic.** No "I'll add tests later" — tests are part of the change.
- **Run local CI before opening the PR.** Use the project's `Makefile` (`make ci`) or the language-specific commands in the repo's `README`.
- **Never commit secrets, tokens, credentials, private keys, or confidential data.** If you find a leaked secret, see `SECURITY.md`.
- **Security-sensitive changes require extra review.** At minimum, a second pair of eyes and an explicit `Security impact checked` line in the PR template.
- **Breaking changes must include migration and rollback notes.** Even if the change is "obviously" the right direction, the PR template's `Risk review` section is mandatory for breaking changes.

## Review process

1. **GitHub Actions runs first** — the `quality-gate` workflow is the deterministic gate.
2. **Codex reviews second** — `@codex review` comments on the PR.
3. **Human review last** — owner approval via `CODEOWNERS`.

A PR is mergeable only when:
- `quality-gate` is green.
- Codex review has been read and any P0/P1 findings resolved.
- The CODEOWNER has approved.

## Local development

Most repos provide a `Makefile` with the targets:

```
make install   # set up environment
make lint      # static analysis
make typecheck # type / schema validation
make test      # unit + integration tests
make ci        # full CI locally
```

If a repo doesn't have a `Makefile`, see its `README.md`.

## Code style

Follow the project's existing conventions. If you want to introduce a new convention, propose it in the PR description and reference it explicitly.

## Reporting issues

Use the issue templates (`.github/ISSUE_TEMPLATE/bug_report.yml` or `feature_request.yml`).