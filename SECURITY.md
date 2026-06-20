# Security Policy

## Reporting a vulnerability

**Do not disclose security issues publicly.** Do not open a public issue, do not post in a public discussion, do not include details in a PR description.

Report privately by emailing the repository owner. Include:

- What the vulnerability is
- How to reproduce
- Impact / severity
- Suggested fix (if you have one)

You should receive an acknowledgment within a few days. Please do not share the vulnerability further until a fix is in place.

## Secrets policy

- **Never commit secrets** — API keys, tokens, passwords, private keys, certificates, OAuth client secrets, or any other credential.
- **Never paste secrets in issues, PRs, comments, or logs.**
- The `quality-gate` workflow runs `gitleaks` on every PR. If it flags your PR, fix it before requesting review.
- If a secret is committed (even briefly), assume it is compromised. Rotate it immediately, regardless of whether the commit was force-pushed away.

## Security-sensitive areas

The following areas require extra review and **must not be merged** without an explicit `Security impact checked` line in the PR template:

- Authentication and session management
- Authorization and access control
- Payments or financial flows
- Infrastructure (cloud resources, networking, IAM)
- Secrets management (vaults, env loading, key rotation)
- CI/CD workflow changes
- Data access (database, file system, external APIs)
- Logging (what is logged, what is not)
- Dependency upgrades that change runtime behavior
- Cryptographic operations

## Severity rules

- **P0 (must block merge):** secrets committed, authn/authz bypass, SQLi, command injection, SSRF, unsafe deserialization, XSS, path traversal, unsafe file upload, breaking production-critical behavior without rollback, CI/CD workflow change that weakens security, logging sensitive data, removing or weakening security checks.
- **P1 (should block until fixed):** missing tests for security-relevant logic, broad exception swallowing in security paths, missing input validation, missing observability for security events, risky dependency upgrades without test evidence.
- **P2 (should improve):** duplicated logic, weak comments, missing edge-case docs, minor maintainability concerns.

The `AGENTS.md` file in each repo provides the same severity rules for Codex to follow.

## P0 security issues MUST block merge

There are no exceptions. If a P0 is found after merge, the change should be reverted immediately and a follow-up PR opened with the fix.