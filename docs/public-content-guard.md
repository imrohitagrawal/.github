# Public-content guard

A Claude Code hook that checks what an AI agent is about to publish to a **public**
repository, and blocks it if it would leak something that should not be public.

## Why

AI coding agents publish all the time: they push commits, open pull requests, and write
issue comments. Secret scanners catch credentials, but most leaks from agent work are not
credentials. They are a home-folder path in a doc, a personal email address, a session
transcript, the name of a private project, or a remark about costs copied from a chat. In
a public repository each of these is permanent: git history keeps it after it is deleted.

## What it checks

It does not try to understand shell. If a publishing command appears **anywhere** in a
Bash call (on any line, inside `if`, after `timeout`, inside `bash -c`, with a heredoc or
piped body), the call counts as a publication and its **whole text** is scanned, plus
every file the call names. A body file that is named but cannot be read blocks the call.

| Channel | What is scanned |
| --- | --- |
| `git push` | What the push publishes: the commits on the pushed refs (or `HEAD`, `--all`, `--mirror`, `--tags`) that the destination does not have yet, their content (including content added and removed again), their commit messages and their file names. The destination is the remote or URL named, else git's own order: `branch.<b>.pushRemote`, `remote.pushDefault`, `branch.<b>.remote`, `origin` |
| `gh pr` / `gh issue` create, edit, comment, review, close; `gh release` create, edit; `gh gist` create, edit; `gh repo` create, edit; `gh api` writes (not `-X GET`) | The whole call text and every file it names |
| `gh repo edit --visibility public`, `gh repo create --push` | The whole history of the local repository |
| GitHub tools that write (`mcp__plugin_github_github__*`, `mcp__github__*`; not `get_*`, `list_*`, `search_*`, `*_read`) | Every string in the tool input |

Rules, in two gitleaks passes:

1. gitleaks' **default secret rules**, as shipped.
2. **Public-content rules**, [`public-content/gitleaks-public.toml`](../public-content/gitleaks-public.toml):
   home-folder paths, Claude Code's encoded home-folder names, personal email addresses
   (example, test and no-reply addresses are allowed), and session transcript file names.
   Plus a **`private-term`** rule built at run time from a private list (below). They run
   apart from the defaults because the defaults' global allowlist silently drops any
   match containing `/home/` (measured with gitleaks 8.30.1).

Inline `gitleaks:allow` comments are ignored, so a finding cannot be silenced from the
content itself. Common CI and container home folders (`/home/runner/`, `/home/node/`, ...)
and example, test and no-reply email domains are allowed. Private terms also match with
`-`, `_`, `.` or a space between their words, and are masked in file names in a reason.

Only repositories that are not known to be private are checked. Visibility comes from
`gh repo view`; an unknown answer counts as public, and only "public" answers are cached
(a day), so a repository that has just been made public is never treated as private.

## What it does not check

It protects against **mistakes**, not against an agent set on getting round it. An agent
can edit this hook or its settings, publish with `curl` or another HTTP client, drive a
browser, or use another tool. Release assets, wikis, Pages, packages, workflow logs, and
text produced at run time from files the call does not name are not scanned. Commit
author and committer identities are not scanned: they are public on every commit
already (use GitHub's private no-reply commit email to hide yours).
GitHub's own secret scanning and push protection stay on as the server-side net.

## When it blocks

The agent gets a denial naming each rule and place (file and line, and the commit for a
push), never the matched text. It is told to remove or rewrite the content (for a commit:
amend or rebase before pushing) and not to edit the guard. If the guard cannot complete a
check on a publication (gitleaks missing, a crash), it blocks that publication and says
why; every other tool call is unaffected.

## Install (per machine)

1. Install [gitleaks](https://github.com/gitleaks/gitleaks) and the GitHub CLI.
2. Clone this repository somewhere stable.
3. Optional, private: a list of terms that must never be published, one per line, in
   `$PRIVATE_NOTES_DIR/scanner/private-terms.txt` (lines starting with `#` are
   comments). Keep that file out of every public repository. Without it the guard says so
   on every check and still runs the public rules.
4. Add to your user-level `~/.claude/settings.json` (replace `<clone>` and `<notes>`):

   ```json
   {
     "hooks": {
       "PreToolUse": [
         {
           "matcher": "Bash|mcp__plugin_github_github__.*",
           "hooks": [
             {
               "type": "command",
               "command": "PRIVATE_NOTES_DIR=<notes> python3 <clone>/scripts/public_content_guard.py",
               "timeout": 180,
               "onFailure": "block"
             }
           ]
         }
       ]
     }
   }
   ```

   `onFailure: "block"` needs Claude Code 2.1.295 or later. The hook itself returns at
   once, with no output, for every call that is not a publication.

## Tests

`scripts/test-public-content-guard.sh` runs every channel in both directions against
throwaway repositories, with a fake `gh` for visibility. It runs in `self-lint.yml`.
