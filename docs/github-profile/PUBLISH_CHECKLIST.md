# GitHub profile publishing checklist

This checklist converts the staged brand assets into the public profile visitors see at `github.com/imrohitagrawal`.

## 1. Create the special profile repository

Create a new **public** repository named exactly:

```text
imrohitagrawal
```

GitHub renders the root `README.md` from a public repository whose name matches the username as the profile README.

Do **not** rename the existing `.github` repository. It serves a different purpose: reusable workflows, community defaults, and engineering standards.

Copy [`PROFILE_README.md`](PROFILE_README.md) into the new repository as:

```text
README.md
```

## 2. Set the public profile fields

Use the following positioning consistently.

### Name

```text
Rohit Agrawal
```

### Bio

```text
Principal engineer building trustworthy AI systems, RAG/LLM evaluation, agentic workflows, cloud reliability & quality platforms | Ex-Oracle, Amazon
```

The bio is deliberately outcome- and domain-led. It avoids presenting a target role as a past employment title.

### Location

```text
Bengaluru, India
```

### Website / social link

Use LinkedIn until a dedicated portfolio is published:

```text
https://www.linkedin.com/in/rohitagrawal14/
```

When a portfolio site is ready, use the portfolio as the Website and retain LinkedIn as a social account.

### Private contribution visibility

Enable **Include private contributions on my profile** so the contribution graph reflects work in private repositories without exposing repository names or content.

## 3. Curate the six pinned repositories

Pin these repositories in this order:

1. `saaf-saans` — strongest product demonstration, live deployment, screenshots, security, observability, accessibility, and rigorous testing
2. `citevyn` — strongest production-style RAG and backend/platform proof
3. `quorum-ai` — strongest multi-model orchestration and cost/reliability proof
4. `narratwin-ai` — strongest product vision, agentic workflow, multilingual AI, and governance proof
5. `project-doc-skills` — strongest reusable-agent-tooling and deterministic-release proof
6. `.github` — strongest CI/CD, DevSecOps, quality-gate, and engineering-governance proof

This sequence tells a deliberate story: **product → trustworthy RAG → agentic orchestration → platform vision → reusable AI tooling → delivery standards**.

## 4. Complete repository About metadata

Apply the descriptions and topics in [`REPOSITORY_METADATA.md`](REPOSITORY_METADATA.md), especially for `narratwin-ai` and `project-doc-skills`, which currently do not communicate their value in GitHub's About panel.

Where a live application or documentation site exists, add it to the repository Website field.

## 5. Add recruiter-friendly social previews

Create one clean social-preview image per pinned repository. Each preview should contain only:

- project name
- one-line value proposition
- one visual or architecture motif
- three proof words, such as `Grounded · Evaluated · Observable`

Avoid dense technology-logo collages. The preview should still read clearly when GitHub, LinkedIn, or messaging applications render it as a small card.

Recommended proof words:

| Repository | Preview proof words |
|---|---|
| `saaf-saans` | Grounded · Accessible · Observable |
| `citevyn` | Cited · Secure · Production-minded |
| `quorum-ai` | Multi-model · Cost-aware · Verifiable |
| `narratwin-ai` | Multilingual · Grounded · Governed |
| `project-doc-skills` | Reusable · Deterministic · Reviewed |
| `.github` | Automated · Secure · Consistent |

## 6. Verify the public profile

Review the profile while signed out or in a private browser window.

Confirm that:

- the first screen explains who Rohit is, what he builds, and why the work is credible
- all six pinned repositories appear in the intended order
- every pinned card has a useful description and recognizable topic keywords
- the profile README works in light and dark mode
- all links open successfully
- no private employer information, secrets, personal phone number, or unsupported claim is exposed
- target roles are framed as direction or interest, not as employment history

## 7. Add automation only after the foundation is live

Recommended sequence:

1. GitHub-native profile fields and pinned repositories
2. profile README
3. repository descriptions, topics, social previews, releases, and live demos
4. GitHub Pages portfolio or documentation hub
5. restrained generated metrics, such as one `lowlighter/metrics` panel
6. optional n8n automation for release-to-LinkedIn draft generation

Do not add visitor counters, large badge walls, contribution animations, or unstable statistics cards before the profile story and repository substance are complete.

## 8. Monthly maintenance routine

Once per month:

- verify every live demo and README link
- update project status and remove stale claims
- publish meaningful releases rather than cosmetic commit bursts
- promote the strongest recent result into the profile README
- review pinned order against current career goals
- check repository traffic to learn which projects convert profile visits into deeper exploration
