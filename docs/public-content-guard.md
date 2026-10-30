# Public-content guard

The public-content guard stops content that must not be public from being published to a
**public** GitHub repository by mistake. It is aimed at mistakes made by AI agents and by
people. It is not a defence against someone who wants to get round it: anyone can edit the
hook, call the API with curl, or push with `--no-verify`.

This version covers two ways of publishing:

- **pushes**, through a git pre-push hook installed for a user account. It runs for every
  client that uses that account's git: a terminal, Codex, Claude Code.
- **pull requests**, through a CI step in `reusable-pr-quality.yml` on public repositories.

It does not look at `gh` calls or GitHub MCP tool calls (comments, issues, releases, gists).

## What it blocks

- **Secrets**: gitleaks' default rules (keys, tokens, private keys and so on), plus OpenRouter
  API keys, which the default rules do not know. (gitleaks is an open-source secret scanner.)
- **Home-folder paths**: a path inside a person's home folder.
  - Caught: `/Users/<name>`, `/home/<name>` or `C:\Users\<name>` (the Windows form in any
    letter case, also with the doubled backslashes JSON writes), with or without a slash
    after the name, wherever it appears, also inside a `file://` URL. A name may start with
    a letter, a digit, `_` or any non-ASCII character.
  - Not caught: `/users/<name>` or `/HOME/<name>` in another letter case, `/root`, `~/...`
    and `~<name>`, environment forms such as `$HOME` or `%USERPROFILE%`, and placeholders
    such as `$USER` or `<name>`.
  - Passes, in any letter case: shared, CI and container home folders and common placeholder
    names. That is `/home/` followed by `runner`, `node`, `linuxbrew`, `vscode`, `codespace`,
    `ubuntu`, `ec2-user`, `user`, `app`, `appuser`, `nonroot`, `pwuser`, `jovyan`,
    `username`, `yourname`, `your-username` or `your_username`; `/Users/` followed by
    `Shared`, `runner`, `username`, `yourname`, `your-username` or `your_username`; and the
    Windows `Public` and `Default` folders.
  - Known false alarms, accepted: a URL or folder path that happens to hold a `home` or
    `Users` folder followed by another word. For example, a web page path whose folders are
    `site`, then `home`, then `about`; or an API route with a `Users` segment followed by an
    id.
  - Known miss: a shared folder name followed by a space and more words (for example the
    macOS `Shared` folder followed by a space and a second word) is read as the shared folder
    and passes.
- **Encoded home-folder names**: the folder names Claude Code builds from a macOS home path
  (`-Users-<name>-...`). Other systems' encoded forms are not matched.
- **Email addresses**. These pass: example and test domains (`example.com`, `.test` and the
  like), GitHub's no-reply domain (`users.noreply.github.com`), GitHub's service addresses
  (`support@`, `noreply@`, `no-reply@` and `actions@` at `github.com`),
  `noreply@anthropic.com`, `git@` at the big git hosts, and image names such as
  `logo@2x.png`. The user part of a URL (`https://key@host/...`) is not read as an address,
  but a URL with a user and a password (`https://user:secret@host/...`) is reported as one.
  The addresses in [`public-content/allowed-addresses.txt`](../public-content/allowed-addresses.txt)
  are public on purpose and pass the address rule in any letter case and any place; a private
  term inside one is still reported. A pull request to this repository that changes that file
  gets a CI warning.
- **Session transcript file names** (`<uuid>.jsonl`, lower-case hex).
- **Agent ids and links**: Claude tool-call ids (`toolu_` or `srvtoolu_` followed by a long
  id), a session or transcript id written next to the word `session` or `transcript` (an
  all-digit id too, so the word `session` followed by a date written as eight digits is a
  false alarm), and links to Claude Code
  sessions. The bare prefix, the bare word, `claude.ai` alone, and a short commit id with no
  such word pass.
- **Private terms**: a private list of words, such as private project names. The list is
  never committed (see [Private terms](#private-terms)). A term matches in any case, with one
  `-`, `_`, `.` or space, or nothing, between its words. It does not match inside a longer run
  of letters and digits; `_` and other marks count as breaks, so `term_client` matches.

The public rules live in [`public-content/gitleaks-public.toml`](../public-content/gitleaks-public.toml).
Secrets and the public rules run as two separate gitleaks passes. One layered config does not
work: gitleaks' default allowlist silently drops any match that contains `/home/`. Private
terms are matched by the scanner itself.

A report names the rule and the place (a file and line, a commit, a ref). A match inside an
archive names the archive's path followed by "(inside the archive)". It never repeats the
matched text. Every path shown in a place is checked first: a private term shows as
`<private>`, other matches as `<redacted>`, and a path that holds a secret, or that the masks
cannot clean, is withheld. A file the guard cannot read completely blocks the check on its
own; the other findings are listed once it is fixed.

### Warnings that never block

A line that looks like someone's words being quoted prints a `WARNING` with its place and
never blocks. That is "the owner" (a common way for an agent to name the person it works
for) followed by "said", "asked", "typed", "wrote", "told", "wants", "chose", "answered" or
"replied"; "owner's exact words" or "owner's own words"; and a Markdown quote line (starting
with `>`). The scanner's text mode checks every line. The CI step checks the PR title and
body. Pushes are not checked for this.

## What is checked

Everything a change publishes is checked whole, and **text that is already public is no reason
to pass**: the same text in a public repository, or earlier in this one, does not let it
through. What is not checked again is a commit the destination already has (or, for a push, a
public upstream remote has; see [The git pre-push hook](#the-git-pre-push-hook)):

- every file that a new commit adds or changes: its whole content and its path name, even
  when the same content already exists elsewhere in the repository. A merge commit counts as
  changing only the files that differ from every parent (a merge resolution), so a plain
  merge of published branches checks no old file again. A renamed or copied file counts as
  added at its new path.
- every new commit and annotated tag: the message, the author, committer and tagger names
  and addresses, a tag's name, and the tags a merge commit embeds (`mergetag`);
- the path of every embedded repository (a submodule's gitlink) that a new commit adds or
  changes; its content belongs to another repository and is not read;
- the name of every branch or tag the push creates or updates (pushes only: the CI step does
  not check branch or tag names);
- any other new file version, such as a file or tree pushed straight to a ref.

So editing a file that already holds an old match blocks until that match is cleaned out.
This is deliberate: a leak already in a public repository must not be copied, kept or
extended without a warning.

How content is read. The guard reads the formats below itself and hands gitleaks plain text.
It blocks a zip, tar, gzip, bzip2 or xz file it cannot read completely, and the archive
formats it cannot open when their signature starts a file (also inside an archive). Other
binaries are read only in part, as described below, and do not block.

- **Text** (no NUL byte) is read as it is.
- **A file with a UTF-16 or UTF-32 byte-order mark** is decoded as that encoding; a broken
  character does not hide the rest. Such a file usually holds NUL bytes, so it is also read
  as one of the other binaries below.
- **zip, tar, gzip, bzip2 and xz** are read completely, or the check blocks. Every file inside
  is checked, archives inside archives too, up to three deep. Every byte must be accounted
  for:
  - zip (a file that starts with a zip signature): one end record, whose comment ends the
    file; the central directory and the optional zip64 records just before it; and the
    entries back to back from byte 0 up to the central directory, each a local header that
    agrees with the directory, its data and, when the entry says so, a data descriptor that
    matches the directory. A local header agrees when its name, method and data-descriptor
    flag are the directory's, and so are its CRC and sizes; with a data descriptor, each local
    CRC and size is 0 or the directory's value. Every entry, folders included, is decoded by
    the guard (stored, deflate and bzip2 only), to its end, with the recorded size and CRC.
  - tar (found by a valid header checksum in its first block, after any blocks of NUL bytes,
    so a tar without the `ustar` mark is read and text with `ustar` at byte 257 is text):
    every header record back to back, each a header with a valid checksum, its data, then
    NUL bytes up to the next 512-byte block; after the last member only NUL bytes, or another
    tar. Besides each member's own header, this covers the extension headers that carry
    metadata (pax headers, global pax headers, GNU long names and long link targets): their
    data is read as content, and their padding must be NUL bytes too. A sparse member blocks.
  - gzip, bzip2 and xz: one stream after another, all of the same format, with only NUL
    bytes between and after them. The number of streams is bounded only by the unpack limit
    below (each stream also costs 4 KB of it).
  It also blocks on an encrypted file, nesting deeper than three, or more than 512 MB unpacked
  from one file. Every layer of nesting counts against that limit: a `.tar.gz` spends its bytes
  twice, so one whose files add up to more than about 256 MB blocks.
- **Archives the guard cannot open block**, clean or not: 7z, rar, zstd, lz4 (frame format),
  lzip, Unix compress (`.Z`), Microsoft cabinet (`.cab`) and xar files, found by their leading
  signature, at the top level and inside other archives. The block names the file and says
  what to do.
- **Other binaries** (any other file holding a NUL byte, such as images, PDFs and databases):
  their printable runs of 12 or more characters are checked, read as 7-bit text and as UTF-16
  and UTF-32 characters, the way the `strings` tool reads them; and the whole file as text
  when it is valid UTF-8. Lines that look like quoted words are not warned about in a
  binary.
- A zip glued after other data (for example after an image) is found by its end record and
  read when it opens, best effort.

Documented gaps, which do not block:

- a printable run shorter than 12 characters (a short private term between binary bytes);
- UTF-16 and UTF-32 text without a byte-order mark is read only through printable runs, and
  a non-ASCII character breaks a run;
- text inside the compressed parts of other binaries (PDF streams, image data), and
  compressed formats with no recognisable signature (brotli, raw zlib, lzma-alone);
- an archive of another format that does not start the file (for example a 7z or gzip glued
  after an image) is read only through its printable runs;
- a zip glued after other data that Python's `zipfile` cannot open, or whose end record is
  followed by more than about 64 KB of other data.
- compressed data deliberately placed inside a zip entry's extra field or the zip comment is
  not read (these are read only through their printable text); the guard is meant to catch
  mistakes, not a determined adversary.

gitleaks itself skips a file it takes for a binary format (it sniffs signatures at fixed
offsets, such as `ustar` at byte 257) and logs that only at debug level, and it reports
success when it cannot open a file. So every piece of content the guard hands it ends with a
line only that run knows, and gitleaks must report that line for the piece to count as read.
A piece that was skipped, or whose line is missing, is read once more behind 100 000 empty
lines (no signature can be sniffed there; line numbers are mapped back). If that fails too,
the check blocks. gitleaks' log is read at debug level: any warning or error other than its
count of findings, or a line that is not a log line, blocks.

What passes: the allowed addresses, the rules' own allowlists, and, on author, committer and
tagger lines only, an address that is the configured `user.email` (as git sees it for that
push or CI run) or is already used as an author or committer address on the destination's
history (in CI: the base side). The same address written in a commit message or a file is
reported like any other. GitHub also has an account setting that blocks command-line pushes
exposing your private email address; it backs up this check.

## The git pre-push hook

It is installed once per user account as a config-based hook (git 2.54 or newer): git runs it
for every repository, before the repository's own pre-push hook, which still runs. Setting
`core.hooksPath` does not switch it off.

For each push it works out where the push goes. That is every configured push URL of the
remote (`pushurl`, else `url`), plus the URL git passes (after any `insteadOf` rewrite). An
SSH host alias (`git@work:owner/repo`) is resolved with `ssh -G`, which reads the SSH config
and connects to nothing. The push is skipped only when every one of those is a local path or
a GitHub repository that `gh` reports as private or internal. Another host, a `gh` error or
no `gh` at all counts as public. When a push is blocked and `gh` could not answer for the
destination, the message says so and suggests `gh auth status`, so a private repository is not
"fixed" by deleting content. When gitleaks prints a warning the guard does not expect (usually
after a gitleaks upgrade), the block quotes that line and names the installed and the tested
gitleaks versions.

On a public destination it works out what the destination lacks: the commits and objects in
`git rev-list --objects <pushed> --not <destination tips>`, where a tip is the latest commit
of one of the destination's branches or tags. Then it checks them as described above. A delete
publishes nothing and is not checked. It reads objects the way `git push` sends them:
replacement objects (`git replace`) are ignored.

The destination tips come from a fresh `git ls-remote` of the destination's branches and tags,
plus the destination's current value of each pushed ref. Remote-tracking branches are never
used, because they can be stale. If a tip is missing locally (for example, another PR was
merged since the last fetch), the hook fetches it first. If that fetch fails, the push is
blocked and the report says to run `git fetch`. If `ls-remote` itself fails, fewer tips are
known and more is checked.

The branches and tags of every other configured remote that is a **public** GitHub repository
count as tips too, so a fork that is behind its public upstream does not re-check the
upstream's commits. Such a remote counts only when every URL configured for it and the URL git
really fetches from (after any `insteadOf` rewrite) name the same GitHub repository, and `gh`
reports it public at that moment (the cache is not used for this). Anything else, such as a
remote rewritten to another host or a local path, adds nothing. Those tips are fetched when
missing; if that fails, they are left out and more is checked.

## The CI step

On a `pull_request` event of a **public** repository that calls `reusable-pr-quality.yml`, it
checks the PR title, the PR body, and the commits reachable from the PR's head commit and not
from the base, as described above. Besides the base commit, the base branch's current tip
(`origin/<base branch>`) and every tag count as known, so a stale base commit does not make the
base branch's newer commits look new. Other branches do not: a PR whose branch starts from
another PR's branch (a stacked PR) is checked for the other PR's commits as well as its own. A
ref that contains the PR's head commit never counts. Branch and tag names are not checked in
CI.

In a repository that calls the workflow, the scanner is checked out from the workflow commit
the caller pins, never from the PR's own tree. A step before the checkout stops the job if
that repository or commit is empty, which would otherwise make the checkout fall back to the
PR's own tree. In this repository, `self-test.yml` calls the workflow by relative path, so a
PR here runs its own copy of the scanner: changes to the guard need a human review. The title
and body reach the scanner only as environment variables, so text such as `$(...)` in a PR body
is never run; if either variable is missing, the step fails. CI has no private term list.

## Private terms

The list is a file, `scanner/private-terms.txt`, inside a private notes folder: one term per
line, `#` for comments. A byte-order mark at the start is ignored. The scanner finds the folder
this way:

1. `PRIVATE_NOTES_DIR`, when it is set.
2. Otherwise the folder the installer recorded in global git config
   (`public-content.notesDir`).
3. Neither: the scanner warns on stderr and carries on with the public rules (CI, other
   machines).

When both are set and name different folders, the scanner blocks with the word `overridden`.
So a stray `PRIVATE_NOTES_DIR` cannot switch the private terms off. The same folder written
differently (a trailing slash, a symbolic link) counts as the same folder.

## Fail closed

The hook blocks the push, and the CI step fails, when a check cannot finish:

- gitleaks is missing, crashes, warns or errs, does not prove it read every piece of content
  (even after the one retry), or writes a report that cannot be read;
- an archive cannot be read completely, or is a format the guard cannot open (see
  [What is checked](#what-is-checked));
- the notes folder is set but its term list is missing, unreadable or empty;
- the allowed address list is missing, unreadable, or has a line that is not an address;
- `PRIVATE_NOTES_DIR` differs from the recorded notes folder;
- a destination tip is missing locally and cannot be fetched;
- git gives an answer the scanner does not expect, or anything else goes wrong.

The hook also blocks when it cannot start: no `python3`, or the hook file missing or not
executable. It cannot block when it does not run at all: on a machine where it is not
installed, with git older than 2.54, after its git config is removed, or with
`git push --no-verify`. Nothing in this version stops `--no-verify`.

gitleaks runs in a private temporary folder with every `GITLEAKS_*` variable removed and an
explicit config. A `.gitleaksignore` or `.gitleaks.toml` in a repository, and an inline
`gitleaks:allow`, change nothing. Its report holds the matched text, which the scanner needs
to check the allowed addresses and the masks; the report stays in that folder, which is deleted
when the check ends, and the text is never printed or passed on a command line.

The visibility cache (under `$XDG_CACHE_HOME`, else `~/.cache`) keeps only public answers, for
24 hours. A private answer is never cached, so a repository made public is checked again at
once. A cache entry that cannot be read, or whose time is not a finite moment in the past, is
ignored.

## What is not covered

- `gh` calls and GitHub MCP tool calls, from any client.
- Anything else that does not go through `git push` or a PR: `curl`, a web browser, another
  API client.
- A machine where the hook is not installed, and private terms in CI.
- Pushes made with `--no-verify`.
- A setting that replaces or switches off the hook for one repository or one command: git uses
  the last `hook.public-content.command` it reads, so a repository's own config or
  `git -c hook.public-content.command=...` replaces the guard, and
  `hook.public-content.enabled=false` switches it off.
- A push run with `HOME` or `GIT_CONFIG_GLOBAL` pointing somewhere else: git then does not
  read the global config that installs the hook, so the hook does not run.
- PR titles and bodies are public as soon as they are posted. The CI step finds a problem
  after publication; it can stop a merge, not the publication. A title or body edited after
  the check ran is not checked again, because the caller template does not run on `edited`.
- Content pushed while a repository was private is not checked again when the repository is
  made public.
- File names inside archives as names (their contents are checked; a name of 12 or more
  printable characters is also read from the archive's own bytes).
- Text in images (pixels) and the gaps listed under [What is checked](#what-is-checked).
- The content of embedded repositories (submodules): only their paths are checked.
- A pull request that edits the repository's own caller workflow: the check that runs is the
  one in the PR, so such a PR can change or remove it for itself. Review those edits.
- Git LFS objects. The LFS client uploads them on its own; only the small pointer files go
  through `git push`.
- Someone determined to get round it. The hook can be edited or removed by the same user.

## Install

Requirements: git 2.54 or newer, gitleaks, gh (logged in, or every GitHub push counts as
public and is checked) and python3 3.9 or newer. Run the installer from the root of a clone
you keep: the hook command runs this checkout's `hooks/pre-push`, so moving or deleting the
clone makes every push fail, and switching branches or pulling in it changes the guard.

```sh
PRIVATE_NOTES_DIR=<your private notes folder> scripts/install-public-content-guard.sh
```

The installer writes only global git settings:

- `hook.public-content.command`: this checkout's `hooks/pre-push`, with `PRIVATE_NOTES_DIR`
  in front when it is set;
- `hook.public-content.event`: `pre-push`, once;
- `public-content.notesDir`: the notes folder, when `PRIVATE_NOTES_DIR` is set.

It never sets `core.hooksPath` and never edits any other tool's settings. If
`hook.public-content.command` or `public-content.notesDir` already holds a different value,
it stops and changes nothing. Running it again changes nothing. To check it:

```sh
git hook list pre-push
```

## When it blocks you

- **A push**: amend or rebase the commits to remove the content, then push again. An old
  match in a file you edited blocks too: clean it out in the same change.
- **A file the guard cannot read completely** (an archive it cannot open, or one with bytes it
  cannot account for): remove it from the commits; or commit its contents unpacked; or repack
  it as zip, tar.gz or tar.xz, which the guard reads completely; or keep it in a private
  repository.
- **A push that says to fetch**: run `git fetch`, then push again.
- **A PR**: amend or rebase the commits and push. For the title or body, edit it, then push a
  new commit (or close and reopen the PR) so the check runs again.
- **A false positive**: open an issue in this repository. Do not edit the guard or its rules
  to get past it, and do not use `--no-verify`.

## Tests

These suites run the cases against throwaway files and repositories, with the real gitleaks
and a fake `gh`:

- `scripts/test-public-content-guard.sh`: the scanner, the hook, the CI step and the installer;
- `scripts/test-public-content-added-lines.sh` (its name is historical: it covers the rule
  that every added or changed file is checked whole);
- `scripts/test-public-content-formats.sh`: file formats, the gitleaks retry, gitlinks;
- `scripts/test-public-content-zip-headers.sh`: each zip entry's local header against its
  central directory;
- `scripts/test-public-content-real-tools.sh`: archives as common tools write them.

They run in `self-lint.yml` with gitleaks installed from the checksum-verified release. The
cases that need a config-based hook are skipped on git older than 2.54.
