#!/usr/bin/env bash
# shellcheck disable=SC2016
# (SC2016: some cases below pass shell text that must stay unexpanded, e.g. "$TOKEN".)
#
# test-public-content-guard.sh - the public-content guard's scanner, git pre-push hook, CI mode and
# installer. It shares the harness in lib-public-content-test.sh with
# test-public-content-added-lines.sh. The gh and GitHub MCP hook is not part of this version.
#
# The cases were written before the code they test, and each names the change that turns it
# red. Runs on bash 3.2 and 5, macOS and Linux, against throwaway repositories under
# mktemp, with the REAL gitleaks (8.30.1) from PATH and a fake `gh` that answers repository
# visibility from a table and logs every call. No case calls GitHub or touches this machine's
# git, gh or Claude Code configuration: HOME, GIT_CONFIG_GLOBAL and XDG_CACHE_HOME all point
# into the throwaway folder, and the system git config is off.
#
# Every leak below is ASSEMBLED AT RUN TIME (for example "/Us" + "ers/jane/"), so this file
# holds no home path, email address, key, private term or transcript name in a form a scanner
# would match. All names are fictional (acme, jane).
#
# =================================== INTERFACE CONTRACT ===================================
#
# 1. public-content/scan.py - Python 3.9+, standard library only, plus the `gitleaks` binary.
#    Library and CLI. CLI modes:
#      scan.py text --label LABEL              scan stdin
#      scan.py pre-push REMOTE URL             what hooks/pre-push runs (refs on stdin)
#      scan.py ci --repo DIR --base SHA --head SHA
#          CI mode. Scans the PR title and body, taken from the environment variables
#          PR_TITLE and PR_BODY (data only, never evaluated), and what the new commits publish
#          (`git rev-list HEAD --not BASE origin/<base branch> <tags>`; see 5): each file a new
#          commit adds or changes, the names of added or changed paths (gitlinks included),
#          and each new commit's and tag's text.
#    Exit status, every mode: 0 clean, 1 findings, 2 error (gitleaks missing or crashed, an
#    unparseable report, bad arguments, a private-term list that is set but unusable).
#    Report on STDERR, one finding per line, naming the rule id and the place, NEVER the
#    matched text; a private term inside a place (a file name) is shown as `<private>`.
#    text-mode place: `LABEL:LINE` (1-based line of the input).
#
# 2. hooks/pre-push - executable; git's pre-push protocol: args `<remote> <url>`, lines
#    `<local ref> <local sha> <remote ref> <remote sha>` on stdin. Exit 0 allows, non-zero
#    blocks; report on stderr. It must work as a config-based hook
#    (hook.public-content.command) AND when git finds it through core.hooksPath, which is how
#    most cases below deliver it so the suite runs on any git version.
#    - Destination candidates: the raw configured pushurl(s) of the remote named in $1 (else
#      its url), plus $2; when $1 is not a configured remote name, $1 itself. The push is NOT
#      scanned only when EVERY candidate is a local path / file:// URL or a GitHub repository
#      whose `gh api repos/OWNER/REPO --jq .visibility` answer is private or internal.
#      Anything else (another host, a gh error, no gh) counts as public.
#    - What is scanned (public destination): what the destination lacks,
#      `git rev-list --objects <pushed shas> --not <tips>`, where the tips come from a fresh
#      git ls-remote, the destination's current value of each pushed ref and the other public
#      remotes (see 6), never from remote-tracking refs: each file a new commit adds or
#      changes, the names of added or changed paths (gitlinks and trees pushed straight to a
#      ref included), each new commit's and annotated tag's text, and every destination ref
#      name (stdin field 3). A delete (local sha all zeros) publishes nothing.
#    - Places in the report: a blob's path; a commit message: the commit sha (at least its
#      first 7 hex characters); a tag message: the word `tag`; a destination ref name: the word
#      `ref` (never the ref text). The report says how to fix it (contains the word `amend`).
#
# 3. The gh and GitHub MCP hook is not part of this version; nothing here depends on it.
#
# 4. scripts/install-public-content-guard.sh - no arguments. Requires git >= 2.54 (from
#    `git --version`, compared numerically, tolerating suffixes such as " (Apple Git-160)"),
#    gitleaks, gh and python3 >= 3.9 on PATH; otherwise exits non-zero and changes nothing.
#    Writes ONLY through `git config --global` (so it honours GIT_CONFIG_GLOBAL):
#    hook.public-content.command = a command running THIS checkout's absolute hooks/pre-push,
#    prefixed with `PRIVATE_NOTES_DIR=<dir>` when that variable is set at install time; and
#    exactly one `hook.public-content.event = pre-push` (added with --add, never duplicated).
#    Running it again changes nothing. Refuses (non-zero, nothing changed) when hook.public-content.command already
#    holds a different value. When PRIVATE_NOTES_DIR is set it also records that folder as
#    `public-content.notesDir`, and refuses (non-zero, nothing changed) when that key already
#    names a different folder. It sets up the git hook only: it never sets core.hooksPath, never
#    writes ~/.claude/settings.json and prints no Claude Code settings (the gh and GitHub MCP
#    hook is not part of this version); it prints the keys it set. It asks git for
#    nothing beyond `--version` and `config`, so this suite can fake the version on any CI git.
#
# 5. Pre-push and CI, further rules:
#    - No exemption for text that is already public: every match in new content blocks.
#      New commits are those the destination lacks (`git rev-list` against its tips; CI: the
#      --base sha, refs/remotes/origin/$GITHUB_BASE_REF when that variable is set, and tags,
#      each only when it does not contain --head). Every file a new commit ADDS or CHANGES is
#      checked whole, content and path name: an edit checks the old matches too, a rename or
#      a copy is an add at the new path, a revert that restores a file checks it. For a merge,
#      only files that differ from EVERY parent count as changed, so a plain merge of
#      published branches checks nothing old. Also checked: every new commit and tag message
#      (a merged signed tag's mergetag header included), ref names, every name in a tree
#      pushed straight to a ref, any new blob not reached through a commit, PR title and body.
#      An unchanged path's name is not re-checked.
#    - Only exemptions: public-content/allowed-addresses.txt; the rules' own allowlists
#      (example and test domains, shared and CI homes, placeholders); and, ON AUTHOR,
#      COMMITTER AND TAGGER LINES ONLY, the configured user.email and addresses already used
#      as an author or committer on the destination's history. In a message or a file those
#      addresses block like any other.
#      Archives are unpacked by the scanner itself (see test-public-content-formats.sh); a
#      match inside one is reported as the archive's path followed by "(inside the archive)".
#    - A destination tip that is missing locally is fetched before exclusions are computed; when
#      that fetch fails, the push is blocked and the report contains the word `fetch`.
#    - Every place is masked: a place never repeats matched text (a path or ref holding an
#      address, a key or a transcript name included).
#    - Reported speech ("the owner said|asked|...", "owner's exact|own words", Markdown quote
#      lines; "the owner" is a common way for an agent to name the person it works for) never
#      blocks: text and CI modes exit 0 and print a line containing `WARNING` and
#      the place (`LABEL:LINE` in text mode, `body`/`title` in CI mode).
#    - The installer records the notes folder in global git config `public-content.notesDir`
#      when PRIVATE_NOTES_DIR is set at install time. The scanner reads it; when it is set and
#      PRIVATE_NOTES_DIR names a different folder (after normalising, so a trailing slash is the
#      same folder), every mode fails closed (exit 2 / blocked) with the word `overridden`; when
#      the variable is unset, the recorded folder is used.
#    - A corrupt visibility cache entry is a cache miss; no cache entry ever makes a repo private.
#
# 6. Pre-push and CI, more rules:
#    - A home folder path needs no trailing slash (`HOME=/Users/<name>` is caught); shared, CI and
#      container homes stay exempt (runner, node, linuxbrew, vscode, codespace, ubuntu,
#      ec2-user, user, app, nonroot, pwuser, /Users/Shared, /Users/runner). A Windows home path
#      written as JSON (`C:\\Users\\<name>\\`) is caught. An all-digit id next to the
#      word session_id or transcript is caught; a 7-character commit id is not.
#    - UTF-16 text (with a byte-order mark) is decoded before scanning.
#    - Pre-push exclusions also hold the tips of every other configured remote that is a public
#      GitHub repository AND whose real fetch URL (after any insteadOf) is that same repository;
#      a private remote's tips never, nor a remote that insteadOf sends elsewhere.
#    - The scanner reads the objects git really sends: local replace refs change nothing. A
#      merge commit's mergetag header (a merged signed tag) and every tagger, author and
#      committer line (name and address) are scanned.
#    - Content the guard cannot read completely (an archive it cannot open, one nested more
#      than three deep, an encrypted file) fails closed (exit 2); look-alike signatures in text
#      never make it skip the text. Cases in test-public-content-formats.sh:
#      zip, tar, gzip, bzip2 and xz are read completely or refused; a stream of another format
#      or other bytes after a compressed stream is refused; the number of streams is bounded
#      only by the unpack limit;
#      7z, rar, zstd, lz4 frame, lzip, Unix compress and cabinet files are refused (exit 2);
#      `ustar` at byte 257 without a valid tar checksum is plain text.
#    - CI mode needs PR_TITLE and PR_BODY in the environment (empty is fine; unset: exit 2).
#    - The author and committer addresses of every NEW commit are checked with the email rule
#      (place: `author` or `committer`). An address is allowed when it equals the configured
#      `user.email` (git config as the push sees it), already appears as an author or
#      committer address on commits the destination already has (in CI: on the base side), or
#      is listed in public-content/allowed-addresses.txt; any other address the email rule
#      flags blocks. Existing commits are not checked. Taggers are treated the same way.
#    - An SSH host alias is resolved with `ssh -G <alias>` (its `hostname` line).
#    - A cached visibility entry is a JSON object {"v": ..., "at": <epoch seconds>}; an `at` that
#      is not a finite number in the past is a miss.
#
# Environment the tools honour (and NO test-only switch in production code):
#    PRIVATE_NOTES_DIR  private terms in $PRIVATE_NOTES_DIR/scanner/private-terms.txt (one per
#                       line, `#` comments; matched case-insensitively with `-`, `_`, `.` or a
#                       space between words). Unset: warn on stderr (the words `private term`,
#                       lowercase) and continue with the public rules. Set but missing,
#                       unreadable or empty: fail closed (block / exit 2).
#    PATH               gitleaks, gh, git, python3.
#    XDG_CACHE_HOME     the visibility cache: public answers only; private/internal never.
#    GITLEAKS_* variables, .gitleaksignore / .gitleaks.toml in a repo or cwd, and inline
#    `gitleaks:allow` change NOTHING.
#
# The fake gh here: `gh api repos/O/R` prints the lowercase visibility when the call mentions
# `.visibility` (e.g. `--jq .visibility`), else {"full_name","visibility","private"}; an
# unknown repo exits 1 with "HTTP 404"; `gh alias list` prints `name: expansion` lines;
# `gh repo set-default --view` exits 1 (no default set); `gh --version` works; every other call
# exits 3. Destinations are https://github.com/acme/<name>.git, rewritten to a local bare repo
# by repo-local `url.<bare>.insteadOf`.
#
# Each case has a "RED WHEN:" line naming the change that turns it red. Allows carry evidence
# where it matters (`scanned`: gitleaks ran; `gh=O/R`: visibility was looked up; `noscan`,
# `noapi`) so an allow cannot pass by the guard not running.
# ===========================================================================================

# shellcheck source=scripts/lib-public-content-test.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-public-content-test.sh"

echo "test-public-content-guard.sh"

# ========================================================================= entry points
echo "== entry points"
# RED WHEN: an entry point named in the contract is missing.
for f in "$SCAN" "$INSTALLER"; do
  if [ -f "$f" ]; then ok "exists: ${f#"$ROOT"/}"; else bad "exists: ${f#"$ROOT"/}" "missing"; fi
done
# RED WHEN: hooks/pre-push is missing or not executable (git silently skips such a hook).
if [ -x "$PREPUSH" ]; then ok "executable: hooks/pre-push"; else bad "executable: hooks/pre-push" "missing or not executable"; fi

# ========================================================================= harness sanity
# These pass before the guard exists: they prove the cases below are not vacuous.
echo "== harness sanity"
printf '[extend]\nuseDefault = true\n' >"$SAN/default.toml"
{
  printf '[extend]\nuseDefault = true\n\n'
  grep -v '^title' "$RULES"
} >"$SAN/layered.toml"
# RED WHEN: gitleaks' default rules stop flagging the key used here (every secret case would be vacuous).
got="$(printf 'key %s\n' "$KEY" | gl_rules "$SAN/default.toml")"
if [ "$got" = aws-access-token ]; then ok "sanity: default rules flag the test key"; else bad "sanity: default rules flag the test key" "got '$got'"; fi
# RED WHEN: gitleaks drops the default global allowlist on /home/ (then two passes may no longer be needed).
got1="$(printf 'path %s\n' "$HOMEL" | gl_rules "$SAN/layered.toml")"
got2="$(printf 'path %s\n' "$HOMEL" | gl_rules "$RULES")"
if [ -z "$got1" ] && [ "$got2" = home-folder-path ]; then ok "sanity: layered config drops /home/ matches, a separate pass finds them"; else bad "sanity: two-pass finding" "layered='$got1' separate='$got2'"; fi
# RED WHEN: a .gitleaksignore in the cwd stops silencing a naive gitleaks run (the cases proving ignore files in the repo or cwd change nothing would be vacuous).
IGNDIR="$WORK/sanity/ign"
mkdir -p "$IGNDIR"
printf ':home-folder-path:1\n' >"$IGNDIR/.gitleaksignore"
got1="$(printf 'see %s\n' "$HOMEP" | gl_rules "$RULES" "$IGNDIR")"
got2="$(printf 'see %s\n' "$HOMEP" | gl_rules "$RULES")"
if [ -z "$got1" ] && [ "$got2" = home-folder-path ]; then ok "sanity: .gitleaksignore in the cwd silences a naive run"; else bad "sanity: .gitleaksignore" "with='$got1' without='$got2'"; fi
# RED WHEN: GITLEAKS_CONFIG_TOML stops replacing the default config of a run without --config.
got1="$(printf 'key %s\n' "$KEY" | GITLEAKS_CONFIG_TOML="$(cat "$SAN/nomatch.toml")" gl_rules -)"
got2="$(printf 'key %s\n' "$KEY" | gl_rules -)"
if [ -z "$got1" ] && [ "$got2" = aws-access-token ]; then ok "sanity: GITLEAKS_CONFIG_TOML silences a run without --config"; else bad "sanity: GITLEAKS_CONFIG_TOML" "with='$got1' without='$got2'"; fi
# RED WHEN: the fake gh stops answering visibility from the table.
if [ "$(gh api repos/acme/priv --jq .visibility 2>/dev/null)" = private ] && ! gh api repos/acme/nowhere --jq .visibility >/dev/null 2>&1; then
  ok "sanity: fake gh answers visibility and 404s an unknown repo"
else bad "sanity: fake gh" "wrong answers"; fi

# ========================================================================= scanner core
echo "== scanner core: scan.py text"
_text() {
  printf '%s\n' "$1" >"$WORK/text.in"
  _run python3 "$SCAN" text --label demo <"$WORK/text.in"
}
# RED WHEN: clean text is reported, or text mode stops running gitleaks.
_text "Adds a parser test."
expect_rc "text: clean text exits 0 after scanning" 0 @scanned
# RED WHEN: the home-folder-path rule is dropped, or the place stops being LABEL:LINE.
_text "see $HOMEP"
expect_rc "text: home path -> rule and label:line" 1 home-folder-path "demo:1"
# RED WHEN: line numbers are lost or off by one.
_text "one${NL}two${NL}see $HOMEP"
expect_rc "text: finding on line 3 says demo:3" 1 "demo:3"
# RED WHEN: the public rules are layered on the defaults (their allowlist drops /home/).
_text "path $HOMEL"
expect_rc "text: /home/ path found (passes not layered)" 1 home-folder-path
# RED WHEN: the default secret pass is dropped.
_text "key $KEY"
expect_rc "text: secret found by the default pass" 1 aws-access-token
# RED WHEN: the email rule is dropped.
_text "write to $MAIL"
expect_rc "text: email address" 1 personal-email
# RED WHEN: the transcript rule is dropped.
_text "log $TRANSCRIPT"
expect_rc "text: transcript file name" 1 agent-transcript
# RED WHEN: the encoded home-folder rule is dropped.
_text "folder $ENCHOME"
expect_rc "text: encoded home folder" 1 home-folder-path-encoded
# RED WHEN: the private-term rule is not built from PRIVATE_NOTES_DIR.
_text "we build $PTERM next"
expect_rc "text: private term" 1 private-term
# RED WHEN: private terms stop matching with _, space or . between words, or become case-sensitive.
for v in "${TERM_A}_labs" "Zebracorn Labs" "ZEBRACORN.LABS"; do
  _text "we build $v next"
  expect_rc "text: private term variant ($(printf '%s' "$v" | sed "s/[Zz][Ee][Bb][Rr][Aa][Cc][Oo][Rr][Nn]/T/"))" 1 private-term
done
# RED WHEN: --ignore-gitleaks-allow is dropped (content could silence itself).
_text "see $HOMEP gitleaks:allow"
expect_rc "text: inline gitleaks:allow is ignored" 1 home-folder-path
# RED WHEN: the email allowlist's anchoring breaks (a no-reply look-alike passes).
_text "mail $SPOOF"
expect_rc "text: no-reply look-alike address is caught" 1 personal-email
# RED WHEN: the shared/CI home folders, example domains or generic folder names start being flagged.
for t in "log $CIHOME" "write to you@Example.COM or db@evil.example" "transcripts live under ~/.claude/projects/<repo>/" "/Users/Shared/build"; do
  _text "$t"
  expect_rc "text: allowed: $t" 0 @scanned
done
# RED WHEN: a gitleaks crash is treated as clean (fail open).
PATH="$BROKEN:$PATH" _text "clean"
expect_rc "text: gitleaks crash -> exit 2" 2 gitleaks
if [ "$HAVE_NOGL" = yes ]; then
  # RED WHEN: a missing gitleaks is treated as clean.
  PATH="$NOGL_PATH" _text "clean"
  expect_rc "text: gitleaks missing -> exit 2" 2 gitleaks
else skip "text: gitleaks missing" "gitleaks is in /usr/bin or /bin here"; fi
# RED WHEN: GITLEAKS_* variables or a .gitleaksignore/.gitleaks.toml in the cwd reach gitleaks.
cp "$SAN/nomatch.toml" "$IGNDIR/.gitleaks.toml"
(cd "$IGNDIR" && GITLEAKS_CONFIG="$SAN/nomatch.toml" GITLEAKS_CONFIG_TOML="$(cat "$SAN/nomatch.toml")" _text "see $HOMEP")
expect_rc "text: GITLEAKS_* env and ignore files in the cwd change nothing" 1 home-folder-path
# Dropping every GITLEAKS_* variable is an equivalent change while --config is explicit:
# gitleaks 8.30.1 reads only GITLEAKS_CONFIG and GITLEAKS_CONFIG_TOML, and neither changes a run
# that passes --config (measured: same findings with each set). So no case can tell the
# filtering apart; the case above stays as the guard against the cwd and default-path routes.
# RED WHEN: a private-term list that is set but missing is treated as "no terms" (fail open).
PRIVATE_NOTES_DIR="$WORK/no-such-notes" _text "clean"
expect_rc "text: PRIVATE_NOTES_DIR set, list missing -> exit 2" 2 "private term"
# RED WHEN: an empty list (only comments) is accepted silently.
PRIVATE_NOTES_DIR="$WORK/empty-notes" _text "clean"
expect_rc "text: PRIVATE_NOTES_DIR set, list empty -> exit 2" 2 "private term"
# RED WHEN: an unset PRIVATE_NOTES_DIR blocks (CI and other machines have none), or the warning goes.
(unset PRIVATE_NOTES_DIR && _text "clean")
expect_rc "text: PRIVATE_NOTES_DIR unset -> warn, exit 0" 0 "private term" @scanned
# RED WHEN: an unset PRIVATE_NOTES_DIR also switches off the public rules.
(unset PRIVATE_NOTES_DIR && _text "see $HOMEP")
expect_rc "text: PRIVATE_NOTES_DIR unset still finds a home path" 1 home-folder-path
# RED WHEN: the generated private-term config is left behind (in TMPDIR or the cache).
mkdir -p "$WORK/iso-tmp" "$WORK/iso-cache"
TMPDIR="$WORK/iso-tmp" XDG_CACHE_HOME="$WORK/iso-cache" _text "we build $PTERM next"
if [ "$(rc)" = 1 ] && ! grep -r -q -i "$TERM_A" "$WORK/iso-tmp" "$WORK/iso-cache" 2>/dev/null; then
  ok "text: no copy of the private terms left behind"
else bad "text: no copy of the private terms left behind" "exit $(rc), or a file under TMPDIR/cache holds a term"; fi

# ========================================================================= scanner core: shared case set
# The shared case set: the same cases every scanner of this kind is measured against (private
# terms excluded; they belong to the private list). Every value is assembled from pieces.
echo "== scanner core: shared case set"
ALNUM24="$(printf '%s%s%s' A1b2C3d4 E5f6G7h8 I9j0K1l2)"
ALNUM36="${ALNUM24}$(printf '%s%s' Mn3Op4Qr 5St6)"
HEX8="$(printf '%s%s' 3f9a 0c1d)"
HEX64=""
for _ in 1 2 3 4; do HEX64="${HEX64}$(printf '%s%s' 01234567 89abcdef)"; done
UUID2="$(printf '%s-%s-%s-%s-%s' 7b1e4c2a 9d3f 4e6b 8a1c 2f5e7d9b0a13)"
# _noecho TEXT: true when stderr repeats no word of TEXT that is 12 characters or longer.
_noecho() {
  local w
  for w in $(printf '%s\n' "$1" | tr -cs 'A-Za-z0-9._@/:+_-' '\n'); do
    if [ "${#w}" -ge 12 ] && grep -q -F -e "$w" "$ERR"; then return 1; fi
  done
  return 0
}
# shared NAME block|pass TEXT
shared() {
  _text "$3"
  if [ "$2" = block ]; then
    if [ "$(rc)" != 1 ]; then bad "shared: $1 blocks" "expected exit 1, got $(rc)$(_hint)"
    elif ! _noecho "$3" || _leaks "$OUT" "$ERR"; then bad "shared: $1 blocks" "the report repeats the matched text"
    else ok "shared: $1 blocks"; fi
  else
    expect_rc "shared: $1 passes" 0 @scanned
  fi
}
# RED WHEN: a rule for that id, key, link or address is missing (block), or too broad (pass).
# Each block below has pass partners in the same list (bare prefix, column name, short commit
# id, plain claude.ai, example and no-reply addresses, URL userinfo, retina names).
shared "tool id" block "see tool""u_${ALNUM24} for the call"
shared "server tool id" block "srv""tool""u_${ALNUM24}"
shared "transcript file name" block "saved as ${UUID2}.js""onl"
shared "short transcript id next to 'transcript'" block "transcript \`${HEX8}\` says so"
shared "full session id next to 'session'" block "session ${UUID2} decided it"
shared "session link" block "https://claude"".ai/code/""session_${ALNUM24:0:20}"
shared "valued session_id" block "session_id=${HEX8}"
shared "email address (gmail)" block "mail jane.q@gm""ail.com today"
shared "email address (own domain)" block "write to jane.q@acme""corp.io"
shared "noreply local part at a private domain" block "no""reply@acme""corp.io"
shared "macOS home path" block "${U}ers/jane/Projects/x/file.py"
shared "Linux home path" block "/ho""me/jane/work/file.py"
shared "encoded home folder name" block "$(printf -- '-%s-%s-%s' Users jane Projects)-demo"
shared "OpenRouter key" block "sk-""or-v1-${HEX64}"
shared "GitHub token" block "gh""p_${ALNUM36}"
shared "AWS key id" block "AK""IA""QWERTYUIOPASDFGH"
shared "private key block" block "-----BEGIN ""RSA PRIVATE KEY-----${NL}${ALNUM24}${ALNUM24}${ALNUM24}${NL}-----END ""RSA PRIVATE KEY-----"
shared "email at a hyphenated domain" block "mail jane@acme""-corp.io"
shared "a person's address at github.com" block "ping jane.doe@github"".com"
shared "plain prose" pass "The deploy job ran and production reports the merged build."
shared "GitHub no-reply email" pass "12345+someone@users.""noreply.github.com"
shared "noreply at the GitHub no-reply domain" pass "no""reply@users.""noreply.github.com"
shared "noreply at anthropic.com" pass "Co-Authored-By: Claude <no""reply@anthropic"".com>"
shared "Dependabot sign-off address" pass "Signed-off-by: dependabot[bot] <support@github"".com>"
shared "GitHub service addresses" pass "from no""reply@github"".com and actions@github"".com"
shared "git@ in an SSH clone URL" pass "clone git@""github.com:acme/x.git"
shared "example.com email" pass "user@""example.com"
TILDE="~"
shared "tilde path" pass "${TILDE}/Projects/demo/scripts/x.py"
shared "CI runner home" pass "/ho""me/runner/work/repo/repo"
shared "macOS shared folder" pass "${U}ers/Shared/data"
shared "short commit id" pass "merged as \`88f618d\` on main"
shared "identifier name only" pass "the session_id column is indexed"
shared "short fake test key" pass 'api_key = "sk-not-a-real-key"'
shared "bare tool prefix" pass "ids start with tool""u_ and are opaque"
shared "claude.ai alone" pass "see claude"".ai for the product"
shared "Sentry placeholder 1" pass "fly secrets set SENTRY_DSN=\"https://...@""sentry.io/...\""
shared "Sentry placeholder 2" pass "a full URL like \`https://abc@""sentry.io/123\`"
shared "retina image names" pass "see assets/logo@""2x.png and icon@""3x.webp"

echo "== scanner core: reported speech is a warning, never a block"
# Contract: such a line exits 0 and prints a line containing WARNING and LABEL:LINE.
# RED WHEN: reported speech blocks, or is not reported, or the line number is wrong.
_text "Plan.${NL}the owner said we should ship it${NL}done"
expect_rc "speech: 'the owner said' warns with its line" 0 WARNING "demo:2"
_text "the owner's exact words were: ship it"
expect_rc "speech: 'owner's exact words' warns" 0 WARNING "demo:1"
_text "Intro.${NL}${NL}> quoted from a chat"
expect_rc "speech: a Markdown quote line warns" 0 WARNING "demo:3"
_text "The owner of this module is the parser team."
# RED WHEN: the warning fires on any mention of "owner" (partner of the cases above).
if [ "$(rc)" = 0 ] && ! grep -q WARNING "$ERR"; then ok "speech: 'the owner of this module' does not warn"; else bad "speech: 'the owner of this module' does not warn" "exit $(rc)$(_hint)"; fi
_text "the owner said see $HOMEP"
# RED WHEN: a warning hides a finding on the same line.
expect_rc "speech: a home path on a warned line still blocks" 1 home-folder-path

echo "== scanner core: paths without a trailing slash, escaped Windows paths, all-digit ids"
# tcase NAME block|pass TEXT: like `shared`, for the cases of this section.
tcase() {
  _text "$3"
  if [ "$2" = block ]; then
    if [ "$(rc)" != 1 ]; then bad "text: $1 blocks" "expected exit 1, got $(rc)$(_hint)"
    elif ! _noecho "$3" || _leaks "$OUT" "$ERR"; then bad "text: $1 blocks" "the report repeats the matched text"
    else ok "text: $1 blocks"; fi
  else
    expect_rc "text: $1 passes" 0 @scanned
  fi
}
# RED WHEN: the home-folder rule needs a slash after the user name.
tcase "HOME=/Users/<name> with no slash" block "export HOME=${U}ers/jane"
tcase "/home/<name> at the end of a line" block "cd /ho""me/jane"
tcase "/Users/<name> before a comma" block "see ${U}ers/jane, then"
# RED WHEN: the shared, CI and container home folders stop being exempt once the slash is optional.
for h in "/ho""me/app" "/ho""me/nonroot" "/ho""me/pwuser" "${U}ers/runner" "${U}ers/Shared" "/ho""me/runner/work/x" "/ho""me/node"; do
  tcase "shared or CI home $(printf '%s' "$h" | sed 's#^/[^/]*/##')" pass "HOME=$h"
done
# A "/home/<word>" inside a URL path or a relative path is reported too: an accepted, documented
# false alarm of the plain home-path rule, so no case asserts it either way.
# RED WHEN: the rule stops catching a real home path after a command, a = or at a line start.
tcase "/home/<name>/ path" block "/ho""me/jane/x"
tcase "cd /home/<name>" block "cd /ho""me/jane"
tcase "HOME=/home/<name>" block "HOME=/ho""me/jane"
# RED WHEN: a home path inside a file:// URL is missed (the slash before it is not a separator).
tcase "file:// URL to a macOS home path" block "open file://${U}ers/jane/x"
tcase "file:// URL to a Linux home path" block "open file:///ho""me/jane/x"
# RED WHEN: catching file:// URLs also catches shared homes or paths outside a home (partners).
tcase "file:// URL to the shared macOS folder" pass "open file://${U}ers/Shared/x"
tcase "file:// URL outside a home" pass "open file:///tmp/build/x"
# RED WHEN: a Windows home path written as JSON (doubled backslashes) is not caught.
BS2="\\\\"
tcase "JSON-escaped Windows home path" block "see C:${BS2}Users${BS2}jane${BS2}AppData"
tcase "JSON-escaped Windows path outside a home" pass "see C:${BS2}Program Files${BS2}Tool"
# RED WHEN: an all-digit id next to "session_id" or "transcript" is exempt.
tcase "session_id with an all-digit id" block "session_""id=1234""5678"
tcase "transcript with an all-digit id" block "transcript \`1234""5678\` says so"
# RED WHEN: a 7-hex commit id or a plain number is flagged (partners of the two cases above).
tcase "a 7-hex commit id" pass "merged as \`88f618d\` on main"
tcase "a 7-digit commit id" pass "merged as \`1234567\` on main"
tcase "an 8-digit number with no session word" pass "issue 12345678 is closed"

# ========================================================================= git pre-push hook
echo "== git pre-push hook"
# mkpush, addbare, commit_file, nohook_push, gpush, expect_blocked, expect_pushed, gh_url and
# sha7 live in lib-public-content-test.sh (the added-content file uses them too).

vis acme/p-clean public
mkpush clean "$(gh_url acme/p-clean)"
D="$P/clean"
commit_file "$D" docs/guide.md "How to run the tests." "docs: add a guide"
gpush "$D" "$D.git" origin main
# RED WHEN: a clean push to a public repo is refused, or allowed without being scanned.
expect_pushed "push: clean commit to a public repo is allowed and scanned" scanned
# RED WHEN: destination ref names stop being scanned, or a ref already-published commit is refused.
git -C "$D" tag light
gpush "$D" "$D.git" origin light
expect_pushed "push: lightweight tag on a published commit is allowed (ref name scanned)" scanned

vis acme/p-dirty public
mkpush dirty "$(gh_url acme/p-dirty)"
D="$P/dirty"
commit_file "$D" b.txt "see $HOMEP" "add b"
gpush "$D" "$D.git" origin main
# RED WHEN: blob contents stop being scanned, or the place stops naming the path, or the fix advice goes.
expect_blocked "push: home path in content is blocked, names path and rule" home-folder-path b.txt amend
commit_file "$D" k.txt "key $KEY" "add k"
gpush "$D" "$D.git" origin main
# RED WHEN: the default secret pass is dropped from pushes.
expect_blocked "push: secret in content is blocked" aws-access-token
git -C "$D" reset -q --hard origin/main
commit_file "$D" c.txt "see $HOMEP gitleaks:allow" "add c"
gpush "$D" "$D.git" origin main
# RED WHEN: inline gitleaks:allow silences a push finding.
expect_blocked "push: inline gitleaks:allow is ignored" home-folder-path

vis acme/p-gone public
mkpush gone "$(gh_url acme/p-gone)"
D="$P/gone"
commit_file "$D" b.txt "see $HOMEP" "add b"
git -C "$D" rm -q b.txt && git -C "$D" commit -q -m "drop b"
gpush "$D" "$D.git" origin main
# RED WHEN: only the final tree is scanned (history keeps a file added then removed).
expect_blocked "push: file added then removed in the range is blocked" home-folder-path b.txt

vis acme/p-msg public
mkpush msg "$(gh_url acme/p-msg)"
D="$P/msg"
git -C "$D" commit -q --allow-empty -m "thanks to $MAIL for the review"
gpush "$D" "$D.git" origin main
# RED WHEN: commit messages stop being scanned, or the place stops naming the commit.
expect_blocked "push: email in a commit message is blocked, names the commit" personal-email "$(sha7 "$D" HEAD)"

vis acme/p-name public
mkpush name "$(gh_url acme/p-name)"
D="$P/name"
commit_file "$D" "docs/${PTERM}-plan.md" "clean words" "add plan"
gpush "$D" "$D.git" origin main
# RED WHEN: path names stop being scanned, or a private term is shown in the place instead of <private>.
expect_blocked "push: private term in a file name is blocked and masked" private-term "<private>"
git -C "$D" reset -q --hard origin/main
commit_file "$D" "logs/$TRANSCRIPT" "{}" "add log"
gpush "$D" "$D.git" origin main
# RED WHEN: path names stop being scanned for the transcript rule.
expect_blocked "push: transcript file name is blocked" agent-transcript

vis acme/p-merge public
mkpush merge "$(gh_url acme/p-merge)"
D="$P/merge"
git -C "$D" checkout -q -b side
commit_file "$D" side.txt "side work" "side"
nohook_push "$D" origin side
git -C "$D" checkout -q main
commit_file "$D" main2.txt "main work" "main"
nohook_push "$D" origin main
git -C "$D" merge -q --no-ff --no-commit side >/dev/null 2>&1
printf 'see %s\n' "$HOMEP" >"$D/merged.txt"
git -C "$D" add merged.txt && git -C "$D" commit -q -m "Merge side"
# RED WHEN: the setup changes so `git log -p` would show the merge content (the case would be vacuous).
if [ "$(git -C "$D" log -p --format= -1 | grep -c merged.txt)" = 0 ]; then ok "sanity: merge-only content is invisible to git log -p"; else bad "sanity: merge-only content" "git log -p shows it"; fi
gpush "$D" "$D.git" origin main
# RED WHEN: pushes are scanned as patches (git log -p / gitleaks git mode) instead of new objects.
expect_blocked "push: content only in a merge resolution is blocked" home-folder-path merged.txt

vis acme/p-obj public
mkpush obj "$(gh_url acme/p-obj)"
D="$P/obj"
BLOB="$(printf 'see %s\n' "$HOMEP" | git -C "$D" hash-object -w --stdin)"
gpush "$D" "$D.git" origin "${BLOB}:refs/tags/blobtag"
# RED WHEN: a ref pointing at a blob is not scanned as its object.
expect_blocked "push: dirty blob pushed to a tag ref is blocked" home-folder-path
BLOB="$(printf 'release notes\n' | git -C "$D" hash-object -w --stdin)"
gpush "$D" "$D.git" origin "${BLOB}:refs/tags/cleanblob"
# RED WHEN: a blob push is refused or skipped instead of scanned.
expect_pushed "push: clean blob pushed to a tag ref is allowed and scanned" scanned
printf 'see %s\n' "$HOMEP" >"$D/t.txt"
git -C "$D" add t.txt
TREE="$(git -C "$D" write-tree)"
git -C "$D" reset -q
gpush "$D" "$D.git" origin "${TREE}:refs/tags/treetag"
# RED WHEN: a ref pointing at a tree is not scanned as its objects.
expect_blocked "push: dirty tree pushed to a tag ref is blocked" home-folder-path

vis acme/p-tag public
mkpush tag "$(gh_url acme/p-tag)"
D="$P/tag"
git -C "$D" tag -a v1 -m "release notes from $HOMEP"
gpush "$D" "$D.git" origin v1
# RED WHEN: annotated tag messages stop being scanned.
expect_blocked "push: home path in an annotated tag message is blocked" home-folder-path tag
git -C "$D" tag -a v2 -m "first release"
gpush "$D" "$D.git" origin v2
# RED WHEN: a clean annotated tag is refused or not scanned.
expect_pushed "push: clean annotated tag is allowed and scanned" scanned

vis acme/p-ref public
mkpush ref "$(gh_url acme/p-ref)"
D="$P/ref"
gpush "$D" "$D.git" origin "HEAD:refs/heads/$MAIL"
# RED WHEN: destination ref names stop being scanned (no new objects here: only the name).
expect_blocked "push: email in a destination ref name is blocked" personal-email ref
gpush "$D" "$D.git" origin "HEAD:refs/heads/feature/parser"
# RED WHEN: a clean ref name for an already-published commit is refused.
expect_pushed "push: clean ref name for a published commit is allowed" scanned

vis acme/p-hist public
mkpush hist "$(gh_url acme/p-hist)"
D="$P/hist"
commit_file "$D" old.txt "see $HOMEP" "old leak already public"
nohook_push "$D" origin main
git -C "$D" checkout -q -b scratch
commit_file "$D" s.txt "see $HOMEP" "local only"
git -C "$D" checkout -q main
commit_file "$D" new.txt "new clean work" "new"
gpush "$D" "$D.git" origin main
# RED WHEN: objects the destination already has (per ls-remote) are scanned again, or an unpushed branch is.
expect_pushed "push: history the destination already has is not rescanned" scanned

vis acme/p-stale public
git init -q --bare "$P/stale.git"
git init -q "$P/stale"
D="$P/stale"
git -C "$D" remote add origin "$(gh_url acme/p-stale)"
git -C "$D" config "url.$P/stale.git.insteadOf" "$(gh_url acme/p-stale)"
git -C "$D" config core.hooksPath "$ROOT/hooks"
commit_file "$D" b.txt "see $HOMEP" "fetched from another repo"
git -C "$D" update-ref refs/remotes/origin/main HEAD
commit_file "$D" c.txt "clean" "clean on top"
# RED WHEN: the setup changes so the destination really has the dirty commit (the case would be vacuous).
if [ -z "$(git --git-dir="$P/stale.git" for-each-ref)" ] && [ -n "$(git -C "$D" rev-parse -q --verify refs/remotes/origin/main)" ]; then
  ok "sanity: stale tracking ref points at a commit the destination lacks"
else bad "sanity: stale tracking ref" "setup wrong"; fi
gpush "$D" "$P/stale.git" origin main
# RED WHEN: remote-tracking refs are used as exclusions (they can be stale after `git remote set-url`).
expect_blocked "push: stale remote-tracking ref does not hide history" home-folder-path b.txt

vis acme/p-del public
mkpush del "$(gh_url acme/p-del)"
D="$P/del"
git -C "$D" checkout -q -b feature
commit_file "$D" f.txt "see $HOMEP" "feature leak"
nohook_push "$D" origin feature
git -C "$D" checkout -q main
gpush "$D" "$D.git" origin --delete feature
# RED WHEN: a delete is scanned (it publishes nothing) or refused.
expect_pushed "push: branch delete is allowed"
git -C "$D" checkout -q -b feature2
nohook_push "$D" origin feature2
git -C "$D" checkout -q main
commit_file "$D" m.txt "see $HOMEP" "leak on main"
gpush "$D" "$D.git" origin :feature2 main
# RED WHEN: a delete in the same push makes the guard skip the other refs.
expect_blocked "push: delete plus a dirty ref in one push is blocked" home-folder-path

vis acme/p-priv private
vis acme/p-pubr public
mkpush priv "$(gh_url acme/p-priv)"
D="$P/priv"
commit_file "$D" b.txt "see $HOMEP and $PTERM" "private notes"
gpush "$D" "$D.git" origin main
# RED WHEN: a private destination is scanned/blocked, or allowed without a visibility check.
expect_pushed "push: private content to a PRIVATE repo is allowed" gh=acme/p-priv
addbare "$D" pubr "$(gh_url acme/p-pubr)"
gpush "$D" "$P/pubr.git" pubr main
# RED WHEN: the destination is taken from origin instead of the remote being pushed to.
expect_blocked "push: same commit to a public remote is blocked" home-folder-path
gpush "$D" "$P/pubr.git" "$(gh_url acme/p-pubr)" main
# RED WHEN: a push to a URL (no remote name) is judged by the rewritten URL alone.
expect_blocked "push: push to a public URL given on the command line is blocked" home-folder-path
gpush "$D" "$D.git" "$(gh_url acme/p-priv)" HEAD:refs/heads/viaurl
# RED WHEN: a private URL given on the command line is treated as public.
expect_pushed "push: push to a private URL given on the command line is allowed" gh=acme/p-priv

vis acme/p-int internal
mkpush int "$(gh_url acme/p-int)"
D="$P/int"
commit_file "$D" b.txt "see $HOMEP" "internal notes"
gpush "$D" "$D.git" origin main
# RED WHEN: internal repositories are treated as public.
expect_pushed "push: internal repo is allowed" gh=acme/p-int

vis acme/p-loc private
vis acme/p-locpub public
mkpush loc "$(gh_url acme/p-loc)"
D="$P/loc"
commit_file "$D" b.txt "see $HOMEP" "notes"
git init -q --bare "$P/backup.git"
git -C "$D" remote add backup "$P/backup.git"
gpush "$D" "$P/backup.git" backup main
# RED WHEN: a local-path destination is scanned or refused.
expect_pushed "push: local path destination is allowed without a scan" noscan
git init -q --bare "$P/backup2.git"
git -C "$D" remote add backup2 "file://$P/backup2.git"
gpush "$D" "$P/backup2.git" backup2 main
# RED WHEN: a file:// destination is scanned or refused.
expect_pushed "push: file:// destination is allowed without a scan" noscan
addbare "$D" locpub "$(gh_url acme/p-locpub)"
gpush "$D" "$P/locpub.git" locpub main
# RED WHEN: once a local remote exists in the repo, every remote is skipped.
expect_blocked "push: same commit to a public GitHub remote is blocked" home-folder-path

vis acme/p-pu private
vis acme/p-pupub public
mkpush pu "$(gh_url acme/p-pu)"
D="$P/pu"
git init -q --bare "$P/pupub.git"
git -C "$D" config remote.origin.pushurl "$(gh_url acme/p-pupub)"
git -C "$D" config "url.$P/pupub.git.insteadOf" "$(gh_url acme/p-pupub)"
commit_file "$D" b.txt "see $HOMEP" "notes"
gpush "$D" "$P/pupub.git" origin main
# RED WHEN: the remote's url is consulted but its pushurl is not.
expect_blocked "push: public pushurl on a private-url remote is blocked" home-folder-path
# Direct invocation, as git would call it when the rewritten $2 is a public GitHub URL.
printf 'refs/heads/main %s refs/heads/main %s\n' "$(git -C "$P/priv" rev-parse HEAD)" "$ZERO" >"$WORK/refs.in"
printf '%s\n' "$P/pubr.git" >"$WORK/push.bare"
_refs "$P/pubr.git" >"$WORK/refs.before"
(cd "$P/priv" && _run "$PREPUSH" origin "$(gh_url acme/p-pubr)" <"$WORK/refs.in")
# RED WHEN: $2 is ignored when the named remote's own URL is private.
expect_blocked "push: direct call, private remote name but public \$2, is blocked" home-folder-path
(cd "$P/priv" && _run "$PREPUSH" origin "$P/priv.git" <"$WORK/refs.in")
# RED WHEN: a private remote whose URL git rewrote to a local path is scanned/refused.
expect_pushed "push: direct call, private remote and local \$2, is allowed" gh=acme/p-priv

mkpush other "https://git.example.org/acme/x.git"
D="$P/other"
commit_file "$D" b.txt "see $HOMEP" "notes"
gpush "$D" "$D.git" origin main
# RED WHEN: a host other than GitHub is treated as private.
expect_blocked "push: non-GitHub host counts as public" home-folder-path

vis acme/p-scp private
mkpush scp "git@github.com:acme/p-scp.git"
D="$P/scp"
commit_file "$D" b.txt "see $HOMEP" "notes"
gpush "$D" "$D.git" origin main
# RED WHEN: scp-style GitHub URLs are not parsed (the private repo would be treated as public).
expect_pushed "push: scp-style URL to a private repo is allowed" gh=acme/p-scp
vis acme/p-ssh public
mkpush ssh "ssh://git@github.com/acme/p-ssh.git"
D="$P/ssh"
commit_file "$D" b.txt "see $HOMEP" "notes"
gpush "$D" "$D.git" origin main
# RED WHEN: ssh:// GitHub URLs are mis-parsed into something private or skipped.
expect_blocked "push: ssh:// URL to a public repo is blocked" home-folder-path

mkpush unk "$(gh_url acme/p-nowhere)"
D="$P/unk"
commit_file "$D" b.txt "see $HOMEP" "notes"
gpush "$D" "$D.git" origin main
# RED WHEN: a gh error (404, no auth) is read as private.
expect_blocked "push: unknown visibility counts as public" home-folder-path

vis acme/p-nogh private
mkpush nogh "$(gh_url acme/p-nogh)"
D="$P/nogh"
commit_file "$D" b.txt "see $HOMEP" "notes"
if [ "$HAVE_NOGH" = yes ]; then
  PATH="$NOGH_PATH" gpush "$D" "$D.git" origin main
  # RED WHEN: a missing gh is read as private.
  expect_blocked "push: no gh on PATH counts as public" home-folder-path
else skip "push: no gh on PATH" "gh is in /usr/bin or /bin here"; fi
gpush "$D" "$D.git" origin main
# RED WHEN: the same private push is refused when gh is present (partner of the case above).
expect_pushed "push: ... and with gh present the private push is allowed" gh=acme/p-nogh

vis acme/p-flip private
mkpush flip "$(gh_url acme/p-flip)"
D="$P/flip"
commit_file "$D" b.txt "see $HOMEP" "notes"
gpush "$D" "$D.git" origin main
expect_pushed "push: repo private at first is allowed" gh=acme/p-flip
vis_set acme/p-flip public
commit_file "$D" c.txt "a clean follow-up" "follow-up"
gpush "$D" "$D.git" origin main
# RED WHEN: content the repo already held while private is scanned again after it is made public
# (it is published already; blocking the next push cannot unpublish it).
expect_pushed "push: after the repo is made public, a clean push is allowed" scanned
commit_file "$D" d.txt "new notes for $MAIL" "new leak"
gpush "$D" "$D.git" origin main
# RED WHEN: a PRIVATE answer is cached (a repo made public would keep being skipped).
expect_blocked "push: after the repo is made public, a push that adds dirty content is blocked" personal-email

vis acme/p-brk public
mkpush brk "$(gh_url acme/p-brk)"
D="$P/brk"
commit_file "$D" ok.txt "clean" "clean"
PATH="$BROKEN:$PATH" gpush "$D" "$D.git" origin main
# RED WHEN: a gitleaks crash lets a push through (fail open).
expect_blocked "push: gitleaks crash blocks the push" gitleaks
if [ "$HAVE_NOGL" = yes ]; then
  PATH="$NOGL_PATH" gpush "$D" "$D.git" origin main
  # RED WHEN: a missing gitleaks lets a push through.
  expect_blocked "push: gitleaks missing blocks the push" gitleaks
else skip "push: gitleaks missing" "gitleaks is in /usr/bin or /bin here"; fi
PRIVATE_NOTES_DIR="$WORK/no-such-notes" gpush "$D" "$D.git" origin main
# RED WHEN: a set-but-missing private-term list is treated as "no terms".
expect_blocked "push: PRIVATE_NOTES_DIR set, list missing -> blocked" "private term"
PRIVATE_NOTES_DIR="$WORK/empty-notes" gpush "$D" "$D.git" origin main
# RED WHEN: an empty private-term list is accepted.
expect_blocked "push: PRIVATE_NOTES_DIR set, list empty -> blocked" "private term"
(unset PRIVATE_NOTES_DIR && gpush "$D" "$D.git" origin HEAD:refs/heads/unset-notes)
# RED WHEN: an unset PRIVATE_NOTES_DIR blocks pushes or stops warning.
if [ "$(rc)" = 0 ] && grep -q "private term" "$ERR"; then ok "push: PRIVATE_NOTES_DIR unset -> warning, allowed"; else bad "push: PRIVATE_NOTES_DIR unset -> warning, allowed" "exit $(rc)$(_hint)"; fi
gpush "$D" "$D.git" origin main
# RED WHEN: the same clean push is refused with a working setup (partner of the fail-closed cases).
expect_pushed "push: ... and with gitleaks and the list in place it is allowed" scanned

vis acme/p-ignore public
mkpush ignore "$(gh_url acme/p-ignore)"
D="$P/ignore"
printf 'see %s\n' "$HOMEP" >"$D/b.txt"
BSHA="$(git -C "$D" hash-object b.txt)"
printf 'b.txt:home-folder-path:1\n%s:home-folder-path:1\n:home-folder-path:1\n' "$BSHA" >"$D/.gitleaksignore"
cp "$SAN/nomatch.toml" "$D/.gitleaks.toml"
git -C "$D" add b.txt .gitleaksignore .gitleaks.toml && git -C "$D" commit -q -m "with ignore files"
printf '%s:b.txt:home-folder-path:1\n' "$(git -C "$D" rev-parse HEAD)" >>"$D/.gitleaksignore"
GITLEAKS_CONFIG="$SAN/nomatch.toml" GITLEAKS_CONFIG_TOML="$(cat "$SAN/nomatch.toml")" gpush "$D" "$D.git" origin main
# RED WHEN: gitleaks runs with the caller's environment, cwd or default ignore path.
expect_blocked "push: .gitleaksignore, .gitleaks.toml and GITLEAKS_* change nothing" home-folder-path

# ========================================================================= pre-push: added content, names, tips, cache, notes folder
echo "== git pre-push hook: every file a new commit adds or changes is checked whole"
# Contract: header, item 5. Old matches in a changed, renamed or copied file block too: that is
# the intended cost of having no exemption for text that is already public.
vis acme/p-add public
mkpush add "$(gh_url acme/p-add)"
D="$P/add"
commit_file "$D" old.txt "line one${NL}see $HOMEP${NL}line three" "old leak, already public"
nohook_push "$D" origin main
printf 'line four\n' >>"$D/old.txt"
git -C "$D" commit -q -am "edit a file that already holds a match"
gpush "$D" "$D.git" origin main
# RED WHEN: a changed file is checked by its added lines, or its old match is excused because
# the destination already publishes it.
expect_blocked "added lines: editing a published file that holds a match is blocked (its old match)" home-folder-path old.txt
git -C "$D" reset -q --hard origin/main
printf 'line four\nmail %s\n' "$MAIL" >>"$D/old.txt"
git -C "$D" commit -q -am "add a dirty line to that file"
gpush "$D" "$D.git" origin main
# RED WHEN: lines added to a file that already holds a match are not scanned (partner of the case above).
expect_blocked "added lines: a new dirty line in that file is blocked" personal-email old.txt
git -C "$D" reset -q --hard origin/main
git -C "$D" mv old.txt moved.txt
git -C "$D" commit -q -m "rename the file"
gpush "$D" "$D.git" origin main
# RED WHEN: a rename is not checked as an add at the new path (content and name).
expect_blocked "added lines: renaming a published file that holds a match is blocked" home-folder-path moved.txt
git -C "$D" reset -q --hard origin/main
cp "$D/$(git -C "$D" ls-files | grep -E '^(old|moved)\.txt$' | head -1)" "$D/copy.txt"
git -C "$D" add copy.txt && git -C "$D" commit -q -m "copy the file"
gpush "$D" "$D.git" origin main
# RED WHEN: a copy of a published file at a new path is skipped because its content is not new.
expect_blocked "added lines: a copy of a published file that holds a match is blocked" home-folder-path copy.txt
git -C "$D" reset -q --hard origin/main
git -C "$D" mv "$(git -C "$D" ls-files | grep -E '^(old|moved|copy)\.txt$' | head -1)" "notes-for-$MAIL.txt"
git -C "$D" commit -q -m "rename to a dirty name"
gpush "$D" "$D.git" origin main
# RED WHEN: the new path name of a moved blob is not scanned, or the place repeats it unmasked.
expect_blocked "added lines: a move to a dirty path name is blocked, the name masked" personal-email

vis acme/p-mres public
mkpush mres "$(gh_url acme/p-mres)"
D="$P/mres"
commit_file "$D" f.txt "shared start" "f"
nohook_push "$D" origin main
git -C "$D" checkout -q -b side
commit_file "$D" s.txt "side work" "side"
nohook_push "$D" origin side
git -C "$D" checkout -q main
commit_file "$D" m.txt "main work" "main"
nohook_push "$D" origin main
git -C "$D" merge -q --no-ff --no-commit side >/dev/null 2>&1
printf 'see %s\n' "$HOMEP" >>"$D/f.txt"
git -C "$D" add f.txt && git -C "$D" commit -q -m "Merge side"
gpush "$D" "$D.git" origin main
# RED WHEN: a line that is in no parent (merge resolution) is treated as not new.
expect_blocked "added lines: a line only in a merge resolution is blocked" home-folder-path f.txt
vis acme/p-mpub public
mkpush mpub "$(gh_url acme/p-mpub)"
D="$P/mpub"
git -C "$D" checkout -q -b side
commit_file "$D" s.txt "see $HOMEP" "side leak, already public"
nohook_push "$D" origin side
git -C "$D" checkout -q main
commit_file "$D" m.txt "main work" "main"
nohook_push "$D" origin main
git -C "$D" merge -q --no-ff -m "Merge side" side >/dev/null 2>&1
gpush "$D" "$D.git" origin main
# RED WHEN: a plain merge of published branches is blocked by content one side already published.
expect_pushed "added lines: merging published branches is allowed" scanned

vis acme/p-bin public
mkpush bin "$(gh_url acme/p-bin)"
D="$P/bin"
L_H="$HOMEP" "$REAL_PY" -c 'import os,sys; open(sys.argv[1],"wb").write(b"\x00\x01 see " + os.environ["L_H"].encode() + b" \x00\xff")' "$D/blob.dat"
git -C "$D" add blob.dat && git -C "$D" commit -q -m "binary, already public"
nohook_push "$D" origin main
commit_file "$D" other.txt "unrelated" "unrelated"
gpush "$D" "$D.git" origin main
# RED WHEN: an untouched binary file is rescanned on a later push.
expect_pushed "binary: an unchanged published binary is not rescanned" scanned
"$REAL_PY" -c 'import sys; p=sys.argv[1]; b=bytearray(open(p,"rb").read()); b[1]=2; open(p,"wb").write(bytes(b))' "$D/blob.dat"
git -C "$D" commit -q -am "change one byte"
gpush "$D" "$D.git" origin main
# RED WHEN: a changed binary file is diffed or excused instead of scanned whole (its old match
# blocks, as in any changed file).
expect_blocked "binary: a changed binary blob is scanned whole (its old match blocks)" home-folder-path blob.dat

echo "== git pre-push hook: archives, odd names, sign-offs, masking"
vis acme/p-arc public
mkpush arc "$(gh_url acme/p-arc)"
D="$P/arc"
L_H="$HOMEP" "$REAL_PY" - "$D" <<'PY'
import gzip, os, sys, zipfile
d, h = sys.argv[1], os.environ["L_H"]
with zipfile.ZipFile(os.path.join(d, "notes.zip"), "w") as z:
    z.writestr("inner/notes.md", "see %s\n" % h)
open(os.path.join(d, "notes.txt.gz"), "wb").write(gzip.compress(("see %s\n" % h).encode()))
with zipfile.ZipFile(os.path.join(d, "clean.zip"), "w") as z:
    z.writestr("inner/readme.md", "All tests pass.\n")
PY
git -C "$D" add clean.zip && git -C "$D" commit -q -m "clean archive"
gpush "$D" "$D.git" origin main
# RED WHEN: archives cannot be pushed at all (partner of the two cases below).
expect_pushed "archive: a clean zip is allowed and scanned" scanned
git -C "$D" add notes.zip && git -C "$D" commit -q -m "zip"
gpush "$D" "$D.git" origin main
# RED WHEN: gitleaks runs with --max-archive-depth 0 (zip contents unread).
expect_blocked "archive: a home path inside a zip is blocked" home-folder-path notes.zip
git -C "$D" reset -q --hard origin/main
git -C "$D" add notes.txt.gz && git -C "$D" commit -q -m "gz"
gpush "$D" "$D.git" origin main
# RED WHEN: gzip contents are not opened.
expect_blocked "archive: a home path inside a .gz is blocked" home-folder-path notes.txt.gz

vis acme/p-colon public
mkpush colon "$(gh_url acme/p-colon)"
D="$P/colon"
GIT_LITERAL_PATHSPECS=1 commit_file "$D" ":notes" "plain notes" "a file named :notes"
gpush "$D" "$D.git" origin main
# RED WHEN: a path starting with ':' breaks the tree listing (every push fails).
expect_pushed "names: a file named ':notes' pushes cleanly" scanned
GIT_LITERAL_PATHSPECS=1 commit_file "$D" ":dirty" "see $HOMEP" "a dirty file named :dirty"
gpush "$D" "$D.git" origin main
# RED WHEN: a ':' name is skipped instead of scanned (partner of the case above).
expect_blocked "names: a dirty file named ':dirty' is blocked" home-folder-path ":dirty"
git -C "$D" reset -q --hard origin/main
commit_file "$D" "img/logo@""2x.png" "png bytes" "retina image"
gpush "$D" "$D.git" origin main
# RED WHEN: retina image names are read as email addresses.
expect_pushed "names: a retina image name (logo at 2x .png) is allowed" scanned
commit_file "$D" "contacts/$MAIL.vcf" "card" "a contact card"
gpush "$D" "$D.git" origin main
# RED WHEN: an email address in a path is not caught, or the place repeats it (masking every place).
expect_blocked "names: an email address as a file name is blocked, masked" personal-email
git -C "$D" reset -q --hard origin/main
git -C "$D" commit -q --allow-empty -m "Bump parser from 1.0 to 1.1${NL}${NL}Signed-off-by: dependabot[bot] <support@github"".com>"
gpush "$D" "$D.git" origin main
# RED WHEN: GitHub's service addresses are flagged (every Dependabot PR would fail).
expect_pushed "sign-off: a Dependabot sign-off passes" scanned
git -C "$D" commit -q --allow-empty -m "Fix${NL}${NL}Signed-off-by: Jane Doe <$MAIL>"
gpush "$D" "$D.git" origin main
# RED WHEN: the service-address exemption covers every address (partner of the case above).
expect_blocked "sign-off: a personal sign-off address is blocked" personal-email "$(sha7 "$D" HEAD)"
git -C "$D" reset -q --hard origin/main
git -C "$D" commit -q --allow-empty -m "clean"
gpush "$D" "$D.git" origin "HEAD:refs/heads/review/$TRANSCRIPT"
# RED WHEN: a ref name finding repeats the ref text.
expect_blocked "names: a transcript name in a ref is blocked, masked" agent-transcript ref

echo "== git pre-push hook: destination tips the clone does not have"
vis acme/p-tip public
mkpush tip "$(gh_url acme/p-tip)"
D="$P/tip"
commit_file "$D" old.txt "see $HOMEP" "old leak, already public"
nohook_push "$D" origin main
git clone -q "$D.git" "$P/tip-other" 2>/dev/null
commit_file "$P/tip-other" other.txt "merged elsewhere" "another PR"
git -C "$P/tip-other" push -q origin main 2>/dev/null
OTHER="$(git -C "$P/tip-other" rev-parse HEAD)"
# RED WHEN: the setup changes so this clone already has the destination's tip (the case would be vacuous).
if ! git -C "$D" cat-file -e "$OTHER" 2>/dev/null; then ok "sanity: the destination's tip is missing locally"; else bad "sanity: the destination's tip is missing locally" "it is present"; fi
git -C "$D" checkout -q -b feature
commit_file "$D" feature.txt "clean feature" "feature"
gpush "$D" "$D.git" origin feature
# RED WHEN: a destination tip missing locally is ignored (the whole history gets scanned).
expect_pushed "tips: a clean branch passes after the guard fetches the destination's tip" scanned
vis acme/p-tipf public
mkpush tipf "$(gh_url acme/p-tipf)"
D="$P/tipf"
commit_file "$D" old.txt "see $HOMEP" "old leak, already public"
nohook_push "$D" origin main
git clone -q "$D.git" "$P/tipf-other" 2>/dev/null
commit_file "$P/tipf-other" other.txt "merged elsewhere" "another PR"
git -C "$P/tipf-other" push -q origin main 2>/dev/null
OTHER="$(git -C "$P/tipf-other" rev-parse HEAD)"
OBJ="$D.git/objects/$(printf '%s' "$OTHER" | cut -c1-2)/$(printf '%s' "$OTHER" | cut -c3-)"
if [ -f "$OBJ" ]; then rm -f "$OBJ"; ok "sanity: the destination tip's object removed (fetch will fail)"; else bad "sanity: the destination tip's object removed" "no loose object at the expected place"; fi
git -C "$D" checkout -q -b feature
commit_file "$D" feature.txt "clean feature" "feature"
gpush "$D" "$D.git" origin feature
# RED WHEN: a failed fetch falls back to scanning everything, or to remote-tracking refs, without saying so.
expect_blocked "tips: a failed fetch blocks and says to fetch" fetch

echo "== git pre-push hook: a corrupt visibility cache"
# Contract: a cache entry the guard cannot read is a miss; a cached entry never makes a repo private.
CACHE_DIR="$WORK/cache-corrupt"
vis acme/p-cache public
mkpush cache "$(gh_url acme/p-cache)"
D="$P/cache"
commit_file "$D" ok.txt "clean" "clean"
XDG_CACHE_HOME="$CACHE_DIR" gpush "$D" "$D.git" origin main
expect_pushed "cache: a first push to a public repo is allowed" scanned
# corrupt_cache MODE: rewrite every cache file under $CACHE_DIR; false when there is none.
corrupt_cache() { # MODE: values-bad-time | values-string | values-private | not-json
  local list
  list="$(find "$CACHE_DIR" -type f 2>/dev/null)"
  [ -n "$list" ] || return 1
  printf '%s\n' "$list" | "$REAL_PY" -c '
import json, sys, time
mode = sys.argv[1]
bad = {"values-bad-time": {"v": "public", "at": "never"}, "values-string": "garbage",
       "values-private": {"v": "private", "at": time.time()}}
for path in sys.stdin.read().split("\n"):
    if not path:
        continue
    try:
        data = json.load(open(path))
    except Exception:
        data = None
    if mode == "not-json" or not isinstance(data, dict):
        open(path, "w").write("{{{ not json")
    else:
        open(path, "w").write(json.dumps({k: bad[mode] for k in data}))
' "$1"
}
i=0
for mode in values-bad-time values-string values-private not-json; do
  i=$((i + 1))
  if corrupt_cache "$mode"; then
    commit_file "$D" "leak$i.txt" "see $HOMEP number $i" "leak $i"
    XDG_CACHE_HOME="$CACHE_DIR" gpush "$D" "$D.git" origin main
    # RED WHEN: a corrupt cache entry crashes the guard or is believed (a cached "private" skips the scan).
    expect_blocked "cache: entry corrupted ($mode), a dirty push is still blocked" home-folder-path
    git -C "$D" reset -q --hard origin/main
  else bad "cache: entry corrupted ($mode)" "no cache file under XDG_CACHE_HOME to corrupt (public answers must be cached)"; fi
done
vis acme/p-cachepriv private
mkpush cachepriv "$(gh_url acme/p-cachepriv)"
D="$P/cachepriv"
mkdir -p "$CACHE_DIR"
printf '{{{ not json' >"$WORK/cache-garbage"
find "$CACHE_DIR" -type f -exec cp "$WORK/cache-garbage" {} \;
commit_file "$D" b.txt "see $HOMEP" "private notes"
XDG_CACHE_HOME="$CACHE_DIR" gpush "$D" "$D.git" origin main
# RED WHEN: a corrupt cache makes the guard block a private push (a miss must fall back to gh).
expect_pushed "cache: with a corrupt cache a private push is still allowed" gh=acme/p-cachepriv

echo "== git pre-push hook: a pinned private notes folder"
# Contract: the installer records the notes folder in the global git config key
# public-content.notesDir. When it is set, a PRIVATE_NOTES_DIR naming a different folder
# blocks (the report says "overridden"); with it unset the variable is used as before.
NOTESDIR_CFG="$WORK/notesdir-gitconfig"
cp "$GIT_CONFIG_GLOBAL" "$NOTESDIR_CFG"
git config --file "$NOTESDIR_CFG" public-content.notesDir "$NOTES"
mkdir -p "$WORK/dummy-notes/scanner"
printf 'zzzz-not-a-term\n' >"$WORK/dummy-notes/scanner/private-terms.txt"
vis acme/p-notesdir public
mkpush notesdir "$(gh_url acme/p-notesdir)"
D="$P/notesdir"
commit_file "$D" ok.txt "clean" "clean"
GIT_CONFIG_GLOBAL="$NOTESDIR_CFG" PRIVATE_NOTES_DIR="$WORK/dummy-notes" gpush "$D" "$D.git" origin main
# RED WHEN: PRIVATE_NOTES_DIR can silently replace the recorded notes folder on a push.
expect_blocked "notes: a different PRIVATE_NOTES_DIR blocks a push" overridden
(unset PRIVATE_NOTES_DIR && GIT_CONFIG_GLOBAL="$NOTESDIR_CFG" gpush "$D" "$D.git" origin main)
# RED WHEN: the recorded folder is not used when the variable is unset (partner of the case above).
expect_pushed "notes: with the folder recorded and no variable the push is allowed" scanned
commit_file "$D" plan.txt "we build $PTERM next" "plan"
(unset PRIVATE_NOTES_DIR && GIT_CONFIG_GLOBAL="$NOTESDIR_CFG" gpush "$D" "$D.git" origin main)
# RED WHEN: the recorded folder's terms are not loaded.
expect_blocked "notes: the recorded folder's private terms are applied" private-term

echo "== git pre-push hook: multi-line findings, CRLF, renames, reverts"
# Contract: a changed file is checked whole, so a key formed by reordering published lines, or by
# a body between published markers, blocks; so does an old key in a file edited elsewhere.
KB="-----BEGIN ""RSA PRIVATE KEY-----"
KE="-----END ""RSA PRIVATE KEY-----"
KEYBODY="${ALNUM24}${ALNUM24}${ALNUM24}"
vis acme/p-keybody public
mkpush keybody "$(gh_url acme/p-keybody)"
D="$P/keybody"
commit_file "$D" id.pem "$KB${NL}$KE" "an empty key block, already public"
nohook_push "$D" origin main
printf '%s\n%s\n%s\n' "$KB" "$KEYBODY" "$KE" >"$D/id.pem"
git -C "$D" commit -q -am "fill the key in"
gpush "$D" "$D.git" origin main
# RED WHEN: a multi-line finding is kept only when its own first line is new.
expect_blocked "multi-line: a key body added between published BEGIN/END lines is blocked" private-key id.pem
vis acme/p-keyold public
mkpush keyold "$(gh_url acme/p-keyold)"
D="$P/keyold"
commit_file "$D" id.pem "header${NL}$KB${NL}$KEYBODY${NL}$KE" "a key, already public"
nohook_push "$D" origin main
printf 'a trailing note\n' >>"$D/id.pem"
git -C "$D" commit -q -am "edit elsewhere in the file"
gpush "$D" "$D.git" origin main
# RED WHEN: a changed file is checked by its added lines only (the old key escapes).
expect_blocked "multi-line: an edit elsewhere in a file holding an old key is blocked" private-key id.pem
vis acme/p-keyorder public
mkpush keyorder "$(gh_url acme/p-keyorder)"
D="$P/keyorder"
commit_file "$D" id.pem "$KE${NL}$KEYBODY${NL}$KB" "the key lines, scrambled"
nohook_push "$D" origin main
_text "$KE${NL}$KEYBODY${NL}$KB"
# RED WHEN: the setup changes so the published scrambled version already holds a finding.
if [ "$(rc)" = 0 ]; then ok "sanity: the scrambled key lines hold no finding"; else bad "sanity: the scrambled key lines hold no finding" "exit $(rc)"; fi
printf '%s\n%s\n%s\n' "$KB" "$KEYBODY" "$KE" >"$D/id.pem"
git -C "$D" commit -q -am "put the lines in order"
gpush "$D" "$D.git" origin main
# RED WHEN: a file whose lines were only reordered is treated as unchanged.
expect_blocked "multi-line: reordering published lines into a complete key is blocked" private-key

vis acme/p-crlf public
mkpush crlf "$(gh_url acme/p-crlf)"
D="$P/crlf"
commit_file "$D" notes.txt "line one${NL}see $HOMEP${NL}line three" "an old match, already public"
nohook_push "$D" origin main
"$REAL_PY" -c 'import sys; p=sys.argv[1]; d=open(p,"rb").read(); open(p,"wb").write(d.replace(b"\n", b"\r\n"))' "$D/notes.txt"
git -C "$D" commit -q -am "convert to CRLF"
gpush "$D" "$D.git" origin main
# RED WHEN: a line-ending change is treated as no change (the file is changed: checked whole).
expect_blocked "crlf: converting a file with an old match to CRLF is blocked" home-folder-path notes.txt
printf 'mail %s\r\n' "$MAIL" >>"$D/notes.txt"
git -C "$D" commit -q -am "a new CRLF line"
gpush "$D" "$D.git" origin main
# RED WHEN: CRLF lines are skipped instead of compared (partner of the case above).
expect_blocked "crlf: a new dirty CRLF line is blocked" personal-email notes.txt

vis acme/p-mvedit public
mkpush mvedit "$(gh_url acme/p-mvedit)"
D="$P/mvedit"
TEN=""
for n in 1 2 3 4 5 6 7 8 9; do TEN="${TEN}line number $n of the notes${NL}"; done
commit_file "$D" notes.txt "${TEN}see $HOMEP" "an old match, already public"
nohook_push "$D" origin main
git -C "$D" mv notes.txt docs-notes.txt
printf 'line ten\n' >>"$D/docs-notes.txt"
git -C "$D" commit -q -am "rename and edit one line"
gpush "$D" "$D.git" origin main
# RED WHEN: a renamed and edited file is checked against its source instead of whole.
expect_blocked "rename: a rename with a one-line edit of a file holding an old match is blocked" home-folder-path docs-notes.txt
printf 'mail %s\n' "$MAIL" >>"$D/docs-notes.txt"
git -C "$D" mv docs-notes.txt notes-final.txt
git -C "$D" commit -q -am "rename again and add a dirty line"
gpush "$D" "$D.git" origin main
# RED WHEN: rename detection hides the lines added in the same commit (partner of the case above).
expect_blocked "rename: a rename with a new dirty line is blocked" personal-email

vis acme/p-revert public
mkpush revert "$(gh_url acme/p-revert)"
D="$P/revert"
commit_file "$D" f.txt "keep${NL}see $HOMEP" "an old match, already public"
nohook_push "$D" origin main
printf 'keep\n' >"$D/f.txt"
git -C "$D" commit -q -am "drop the line"
nohook_push "$D" origin main
git -C "$D" revert --no-edit HEAD >/dev/null
gpush "$D" "$D.git" origin main
# RED WHEN: a file the revert commit changes is skipped because the destination already holds
# that file version (in its history).
expect_blocked "revert: restoring a file that holds a match is blocked" home-folder-path f.txt
printf 'mail %s\n' "$MAIL" >>"$D/f.txt"
git -C "$D" commit -q -am "a new dirty line"
gpush "$D" "$D.git" origin main
# RED WHEN: the restored file is exempt from later scans (partner of the case above).
expect_blocked "revert: a new dirty line in the restored file is blocked" personal-email f.txt

echo "== git pre-push hook: UTF-16 text and escaped paths in files"
vis acme/p-utf16 public
mkpush utf16 "$(gh_url acme/p-utf16)"
D="$P/utf16"
"$REAL_PY" -c 'import sys; open(sys.argv[1],"wb").write("\ufeffAll tests pass.\n".encode("utf-16-le"))' "$D/clean16.txt"
git -C "$D" add clean16.txt && git -C "$D" commit -q -m "a clean UTF-16 file"
gpush "$D" "$D.git" origin main
# RED WHEN: UTF-16 files cannot be pushed at all (partner of the case below).
expect_pushed "utf-16: a clean UTF-16LE file passes" scanned
L_H="$HOMEP" "$REAL_PY" -c 'import os,sys; open(sys.argv[1],"wb").write(("\ufeffsee " + os.environ["L_H"] + "\n").encode("utf-16-le"))' "$D/notes16.txt"
git -C "$D" add notes16.txt && git -C "$D" commit -q -m "a dirty UTF-16 file"
gpush "$D" "$D.git" origin main
# RED WHEN: UTF-16 text is scanned as bytes (every other byte NUL, so nothing matches).
expect_blocked "utf-16: a home path in UTF-16LE text is blocked" home-folder-path notes16.txt
git -C "$D" reset -q --hard origin/main
printf '{"profile": "C:%sUsers%sjane%sAppData"}\n' "$BS2" "$BS2" "$BS2" >"$D/settings.json"
git -C "$D" add settings.json && git -C "$D" commit -q -m "settings"
gpush "$D" "$D.git" origin main
# RED WHEN: a Windows home path written as JSON is not caught in a pushed file.
expect_blocked "escaped: a JSON-escaped Windows home path in a file is blocked" home-folder-path settings.json

echo "== git pre-push hook: forks of a public upstream"
# Contract: the exclusions also hold the ls-remote tips of every OTHER configured remote that is
# a public GitHub repository (fetched when missing, as for the destination); a private remote's
# tips are never exclusions.
vis acme/p-fork public
vis acme/p-up public
mkpush fork "$(gh_url acme/p-fork)"
D="$P/fork"
addbare "$D" upfork "$(gh_url acme/p-up)"
commit_file "$D" old.txt "see $HOMEP" "upstream work, already public"
nohook_push "$D" upfork main
commit_file "$D" new.txt "clean fork work" "fork work"
gpush "$D" "$D.git" origin main
# The sibling's raw URL names a public repository, but insteadOf sends every fetch to a local bare
# that holds a commit nobody published. Its tips must not hide that commit.
# RED WHEN: a sibling remote is trusted by its RAW url when its real fetch URL goes elsewhere.
expect_blocked "fork: a sibling whose public URL insteadOf rewrites elsewhere hides nothing" home-folder-path old.txt
commit_file "$D" new2.txt "mail $MAIL" "dirty fork work"
gpush "$D" "$D.git" origin main
# RED WHEN: upstream tips hide content that is new everywhere (partner of the case above).
expect_blocked "fork: new dirty content still blocks" personal-email
vis acme/p-fork2 public
vis acme/p-up2 private
mkpush fork2 "$(gh_url acme/p-fork2)"
D="$P/fork2"
addbare "$D" upfork2 "$(gh_url acme/p-up2)"
commit_file "$D" old.txt "see $HOMEP" "upstream work, private"
nohook_push "$D" upfork2 main
commit_file "$D" new.txt "clean fork work" "fork work"
gpush "$D" "$D.git" origin main
# RED WHEN: a PRIVATE remote's tips are used as exclusions (its content is not public).
expect_blocked "fork: content only on a private upstream still blocks" home-folder-path

# A fork behind its public upstream, with NO rewrite: the upstream's real URL is
# git@github.com:acme/p-up3.git, reached through a fake ssh on PATH that serves
# $WORK/ssh-root/<owner>/<repo>.git with the local git (no network, no insteadOf).
SSHSRV="$WORK/bin-sshsrv"
SSHROOT="$WORK/ssh-root"
mkdir -p "$SSHSRV" "$SSHROOT/acme"
{
  printf '#!/bin/sh\nSSHROOT=%s\n' "'$SSHROOT'"
  cat <<'SSH'
if [ "$1" = -G ]; then printf 'user git\nhostname %s\nport 22\n' "$2"; exit 0; fi
while [ $# -gt 0 ]; do
  case "$1" in -o|-p|-i|-l|-F) shift 2 ;; -*) shift ;; *) break ;; esac
done
case "$1" in git@github.com|github.com) ;; *) echo "fake ssh: unknown host $1" >&2; exit 255 ;; esac
shift
cmd="$*"
prog=${cmd%% *}
repo=$(printf '%s' "${cmd#* }" | tr -d "'")
repo=${repo#/}
case "$prog" in
  git-upload-pack) exec git upload-pack "$SSHROOT/$repo" ;;
  git-receive-pack) exec git receive-pack "$SSHROOT/$repo" ;;
esac
echo "fake ssh: unexpected command" >&2
exit 255
SSH
} >"$SSHSRV/ssh"
chmod +x "$SSHSRV/ssh"
vis acme/p-fork3 public
vis acme/p-up3 public
git init -q --bare "$SSHROOT/acme/p-up3.git"
mkpush fork3 "$(gh_url acme/p-fork3)"
D="$P/fork3"
git -C "$D" remote add upssh "git@github.com:acme/p-up3.git"
commit_file "$D" old.txt "see $HOMEP" "upstream work, already public"
PATH="$SSHSRV:$PATH" nohook_push "$D" upssh main
# RED WHEN: the setup stops putting the commit on the ssh-served upstream (the case would be vacuous).
if [ "$(git --git-dir="$SSHROOT/acme/p-up3.git" rev-parse -q --verify refs/heads/main)" = "$(git -C "$D" rev-parse HEAD)" ]; then
  ok "sanity: the public upstream really holds the fork's base (served over the fake ssh)"
else bad "sanity: the public upstream really holds the fork's base" "setup wrong"; fi
commit_file "$D" new.txt "clean fork work" "fork work"
PATH="$SSHSRV:$PATH" gpush "$D" "$D.git" origin main
# RED WHEN: a sibling whose real URL IS the public GitHub repository stops counting as published
# (a fork behind its public upstream would block on the upstream's own content; partner of the rewritten-sibling case).
expect_pushed "fork: content already on a public upstream (no rewrite) does not block" scanned gh=acme/p-up3

# Unit level (the same partner without any transport): public_sibling_tips trusts a sibling
# whose fetch URL, after a PROTOCOL-only rewrite, is the same GitHub repository, asking gh
# afresh (fresh=True); a rewrite to a local path is not trusted. `git ls-remote --get-url`
# connects to nothing, and visibility and tips are stubbed.
SIBPY="$WORK/sibling.py"
cat >"$SIBPY" <<'EOF'
import sys
sys.path.insert(0, sys.argv[1])
import scan
calls = []
def known_visibility(slug, *a, **kw):
    calls.append((slug, kw.get("fresh", a[0] if a else None)))
    return "public"
scan.known_visibility = known_visibility
scan.remote_tips = lambda *a, **kw: ["MARKER"]
tips = scan.public_sibling_tips("origin")
fresh = any(s == "acme/x" and f is True for s, f in calls)
print("tips=%s fresh=%s" % (",".join(tips) or "none", fresh))
EOF
sibling_case() { # NAME REWRITE-BASE REWRITTEN-PREFIX
  local r="$WORK/sib-$1"
  if ! { git init -q "$r" && git -C "$r" remote add upstream "$(gh_url acme/x)" &&
    git -C "$r" config "url.$2.insteadOf" "$3"; }; then
    die "sibling repo $1"
  fi
  (cd "$r" && _run "$REAL_PY" -I -B "$SIBPY" "$ROOT/public-content") # -B: no __pycache__ in the repo
}
sibling_case proto "ssh://git@github.com/" "https://github.com/"
# RED WHEN: a protocol-only rewrite (same GitHub repository) makes the sibling untrusted, or its
# visibility is taken from the cache instead of asked afresh.
if [ "$(rc)" = 0 ] && grep -q -x "tips=MARKER fresh=True" "$OUT"; then
  ok "fork (unit): a protocol-only rewrite of a public sibling is trusted, visibility asked afresh"
else bad "fork (unit): a protocol-only rewrite of a public sibling is trusted, visibility asked afresh" "exit $(rc), got '$(head -c 200 "$OUT")'$(_hint)"; fi
sibling_case local "$P/elsewhere.git" "$(gh_url acme/x)"
# RED WHEN: a sibling is trusted by its raw URL when insteadOf sends it to a local path.
if [ "$(rc)" = 0 ] && grep -q "^tips=none " "$OUT"; then
  ok "fork (unit): a public sibling rewritten to a local path adds no tips"
else bad "fork (unit): a public sibling rewritten to a local path adds no tips" "exit $(rc), got '$(head -c 200 "$OUT")'$(_hint)"; fi

echo "== git pre-push hook: author and committer addresses"
# Contract: see item 6 of the header (the configured identity and addresses already on the
# destination's history pass; any other flagged address on a new commit blocks).
MAIL2="$(printf '%s@%s' sam.roe corp-mail.io)"
vis acme/p-author public
mkpush author "$(gh_url acme/p-author)"
D="$P/author"
git -C "$D" -c user.email="12345+jane@users.""noreply.github.com" commit -q --allow-empty -m "work"
gpush "$D" "$D.git" origin main
# RED WHEN: GitHub's no-reply author addresses are flagged.
expect_pushed "author: a GitHub no-reply author passes" scanned
git -C "$D" -c user.email="$MAIL" commit -q --allow-empty -m "work"
gpush "$D" "$D.git" origin main
# RED WHEN: a flagged author address that is neither configured nor already published passes.
expect_blocked "author: a new personal author address (not configured, not on the destination) is blocked" personal-email author
git -C "$D" reset -q --hard origin/main
GIT_COMMITTER_EMAIL="$MAIL" git -C "$D" commit -q --allow-empty -m "work"
gpush "$D" "$D.git" origin main
# RED WHEN: committer addresses of new commits are not checked.
expect_blocked "author: a new personal committer address (not configured, not on the destination) is blocked" personal-email committer
git -C "$D" reset -q --hard origin/main
git -C "$D" config user.email "$MAIL"
git -C "$D" commit -q --allow-empty -m "work by the configured identity"
gpush "$D" "$D.git" origin main
# RED WHEN: the configured user.email is blocked (every push by a person using a real address would fail).
expect_pushed "author: the configured user.email passes" scanned
git -C "$D" config --unset user.email

vis acme/p-author2 public
mkpush author2 "$(gh_url acme/p-author2)"
D="$P/author2"
git -C "$D" -c user.email="$MAIL2" commit -q --allow-empty -m "old work, already public"
nohook_push "$D" origin main
git -C "$D" commit -q --allow-empty -m "new work by someone else"
gpush "$D" "$D.git" origin main
# RED WHEN: commits the destination already has are checked again.
expect_pushed "author: an existing commit's address is not rechecked" scanned
git -C "$D" -c user.email="$MAIL2" commit -q --allow-empty -m "more work by the same person"
gpush "$D" "$D.git" origin main
# RED WHEN: an address already on the destination's history is blocked on a new commit.
expect_pushed "author: an address already on the destination's history passes" scanned
git -C "$D" -c user.email="$MAIL" commit -q --allow-empty -m "work by a new person"
gpush "$D" "$D.git" origin main
# RED WHEN: one published address exempts every address (partner of the case above).
expect_blocked "author: in the same repo, a new address not on its history is blocked" personal-email author

echo "== git pre-push hook: SSH host aliases"
# A fake ssh: `ssh -G work` resolves to github.com, `ssh -G lab` to another host.
SSHBIN="$WORK/bin-ssh"
mkdir -p "$SSHBIN"
cat >"$SSHBIN/ssh" <<'SSH'
#!/bin/sh
[ "$1" = -G ] || { echo "fake ssh: only -G is answered" >&2; exit 255; }
case "$2" in
  work) h=github.com ;;
  lab) h=git.example.org ;;
  *) h="$2" ;;
esac
printf 'user git\nhostname %s\nport 22\n' "$h"
SSH
chmod +x "$SSHBIN/ssh"
vis acme/p-alias private
mkpush alias "git@work:acme/p-alias.git"
D="$P/alias"
commit_file "$D" b.txt "see $HOMEP" "private notes"
PATH="$SSHBIN:$PATH" gpush "$D" "$D.git" origin main
# RED WHEN: SSH host aliases are not resolved with `ssh -G` (the private repo counts as public).
expect_pushed "alias: an alias that resolves to github.com, private repo, passes" gh=acme/p-alias
mkpush alias2 "git@lab:acme/p-alias.git"
D="$P/alias2"
commit_file "$D" b.txt "see $HOMEP" "notes"
PATH="$SSHBIN:$PATH" gpush "$D" "$D.git" origin main
# RED WHEN: any alias is taken for GitHub (partner of the case above).
expect_blocked "alias: an alias that resolves elsewhere counts as public" home-folder-path

echo "== git pre-push hook: names, cache values"
vis acme/p-keyname public
mkpush keyname "$(gh_url acme/p-keyname)"
D="$P/keyname"
commit_file "$D" "keys/$KEY.txt" "line one" "a file named like a key, already public"
nohook_push "$D" origin main
printf 'line two\n' >>"$D/keys/$KEY.txt"
git -C "$D" commit -q -am "a clean edit"
gpush "$D" "$D.git" origin main
# RED WHEN: the name of a path a new commit changes is not checked.
expect_blocked "names: a clean edit of a file whose name holds a key is blocked" aws-access-token
printf 'see %s\n' "$HOMEP" >>"$D/keys/$KEY.txt"
git -C "$D" commit -q -am "a dirty edit"
gpush "$D" "$D.git" origin main
# RED WHEN: a place is masked only when its name was scanned in this push.
expect_blocked "names: a finding in that file never prints its name" home-folder-path

# Contract: a cache file is a JSON object whose entries are {"v": ..., "at": <epoch seconds>};
# an `at` that is not a finite number in the past is a miss.
vis acme/p-cacheat public
mkpush cacheat "$(gh_url acme/p-cacheat)"
D="$P/cacheat"
CACHE_AT="$WORK/cache-at"
commit_file "$D" ok.txt "clean" "clean"
XDG_CACHE_HOME="$CACHE_AT" gpush "$D" "$D.git" origin main
expect_pushed "cache: a public answer is looked up and cached" scanned
rm -rf "$WORK/cache-at.saved"
cp -R "$CACHE_AT" "$WORK/cache-at.saved" 2>/dev/null
vis_set acme/p-cacheat private
set_cache_at() { # VALUE: now | huge | inf ; restore the saved cache, then set every entry's at
  rm -rf "$CACHE_AT"
  cp -R "$WORK/cache-at.saved" "$CACHE_AT" 2>/dev/null || return 1
  find "$CACHE_AT" -type f | "$REAL_PY" -c '
import json, sys, time
v = {"now": time.time(), "huge": 10 ** 400, "inf": float("inf")}[sys.argv[1]]
n = 0
for path in sys.stdin.read().split():
    try:
        data = json.load(open(path))
    except Exception:
        continue
    if not isinstance(data, dict):
        continue
    for entry in data.values():
        if isinstance(entry, dict) and "at" in entry:
            entry["at"] = v
            n += 1
    open(path, "w").write(json.dumps(data))
sys.exit(0 if n else 1)
' "$1"
}
i=0
for at in now huge inf; do
  i=$((i + 1))
  commit_file "$D" "leak$i.txt" "see $HOMEP, case $i" "leak $i"
  if set_cache_at "$at"; then
    XDG_CACHE_HOME="$CACHE_AT" gpush "$D" "$D.git" origin main
    if [ "$at" = now ]; then
      # RED WHEN: a fresh cached public answer is ignored (partner: the cases below are decided by the bad value).
      expect_blocked "cache: a fresh cached 'public' is used (repo since made private)" home-folder-path
    else
      # RED WHEN: an overflowing or infinite `at` is read as fresh (or crashes) instead of a miss.
      expect_pushed "cache: at=$at is a miss, so gh is asked again" gh=acme/p-cacheat
    fi
  else bad "cache: at=$at" "no cache entry with an 'at' field to change"; fi
done

# ========================================================================= CI mode
echo "== CI mode: scan.py ci"
CIR="$WORK/ci"
git init -q "$CIR"
commit_file "$CIR" a.txt "start" "init"
CIBASE="$(git -C "$CIR" rev-parse HEAD)"
CI_TITLE="Fix the parser"
CI_BODY="Adds a test."
_ci() { # BASE HEAD
  (unset PRIVATE_NOTES_DIR && PR_TITLE="$CI_TITLE" PR_BODY="$CI_BODY" _run python3 "$SCAN" ci --repo "$CIR" --base "$1" --head "$2")
}
ci_branch() { git -C "$CIR" checkout -q -B "$1" "$CIBASE" || die "ci branch"; }
ci_branch c-clean
commit_file "$CIR" docs.md "How to run the tests." "docs"
_ci "$CIBASE" "$(git -C "$CIR" rev-parse HEAD)"
# RED WHEN: a clean PR fails CI, or CI stops scanning.
expect_rc "ci: clean title, body and commits pass" 0 @scanned
CLEANHEAD="$(git -C "$CIR" rev-parse HEAD)"
CI_BODY="see $HOMEP"
_ci "$CIBASE" "$CLEANHEAD"
# RED WHEN: the PR body is not scanned.
expect_rc "ci: home path in the PR body" 1 home-folder-path body
CI_BODY="Adds a test."
CI_TITLE="ask $MAIL"
_ci "$CIBASE" "$CLEANHEAD"
# RED WHEN: the PR title is not scanned.
expect_rc "ci: email in the PR title" 1 personal-email title
CI_TITLE="Fix the parser"
# The marker is a bare name, run from $WORK: a full temp path could itself hold an encoded
# home folder (macOS temp folders under a session folder do), which is a real finding.
MARK="$WORK/ci-injected"
CI_BODY="run \$(touch ci-injected) and \`touch ci-injected\` now"
(cd "$WORK" && _ci "$CIBASE" "$CLEANHEAD")
# RED WHEN: the body is evaluated by a shell or $(...) text is flagged.
if [ "$(rc)" = 0 ] && [ ! -e "$MARK" ]; then ok "ci: \$(...) in the body is data, not code"; else bad "ci: \$(...) in the body is data, not code" "exit $(rc), marker exists: $([ -e "$MARK" ] && echo yes || echo no)"; fi
CI_BODY="run \$(touch ci-injected) see $HOMEP"
(cd "$WORK" && _ci "$CIBASE" "$CLEANHEAD")
expect_rc "ci: ... and a home path next to it is still found" 1 home-folder-path
if [ "$(rc)" = 1 ] && [ ! -e "$MARK" ]; then ok "ci: no code ran from the body"; else bad "ci: no code ran from the body" "exit $(rc), marker exists: $([ -e "$MARK" ] && echo yes || echo no)"; fi
CI_BODY="Adds a test."
ci_branch c-content
commit_file "$CIR" b.txt "see $HOMEP" "add b"
_ci "$CIBASE" "$(git -C "$CIR" rev-parse HEAD)"
# RED WHEN: the commit range's content is not scanned.
expect_rc "ci: home path in a commit's content" 1 home-folder-path b.txt
ci_branch c-msg
git -C "$CIR" commit -q --allow-empty -m "thanks $MAIL"
_ci "$CIBASE" "$(git -C "$CIR" rev-parse HEAD)"
# RED WHEN: commit messages in the range are not scanned.
expect_rc "ci: email in a commit message" 1 personal-email "$(sha7 "$CIR" HEAD)"
ci_branch c-name
commit_file "$CIR" "logs/$TRANSCRIPT" "{}" "add log"
_ci "$CIBASE" "$(git -C "$CIR" rev-parse HEAD)"
# RED WHEN: path names in the range are not scanned.
expect_rc "ci: transcript file name" 1 agent-transcript
ci_branch c-gone
commit_file "$CIR" g.txt "see $HOMEP" "add g"
git -C "$CIR" rm -q g.txt && git -C "$CIR" commit -q -m "drop g"
_ci "$CIBASE" "$(git -C "$CIR" rev-parse HEAD)"
# RED WHEN: only the head tree is scanned.
expect_rc "ci: file added then removed in the range" 1 home-folder-path
ci_branch c-old
commit_file "$CIR" old.txt "see $HOMEP" "old leak already on the base"
OLDBASE="$(git -C "$CIR" rev-parse HEAD)"
commit_file "$CIR" new.txt "clean work" "new"
_ci "$OLDBASE" "$(git -C "$CIR" rev-parse HEAD)"
# RED WHEN: CI rescans what the base already has (blocking for NEW content only).
expect_rc "ci: content already on the base is not rescanned" 0 @scanned
(unset PRIVATE_NOTES_DIR && PATH="$BROKEN:$PATH" PR_TITLE="$CI_TITLE" PR_BODY="$CI_BODY" _run python3 "$SCAN" ci --repo "$CIR" --base "$CIBASE" --head "$CLEANHEAD")
# RED WHEN: a gitleaks crash passes CI.
expect_rc "ci: gitleaks crash -> exit 2" 2 gitleaks

# ========================================================================= CI mode: added content, sign-offs, archives, warnings
echo "== CI mode: only added content, sign-offs, archives, masking, warnings"
ci_branch c-base-old
commit_file "$CIR" old.txt "line one${NL}see $HOMEP" "old leak already on the base"
OLDB="$(git -C "$CIR" rev-parse HEAD)"
printf 'line three\n' >>"$CIR/old.txt"
git -C "$CIR" commit -q -am "edit the file"
_ci "$OLDB" "$(git -C "$CIR" rev-parse HEAD)"
# RED WHEN: CI checks a changed file by its added lines, or excuses an old match.
expect_rc "ci: editing a base file that holds a match fails (its old match)" 1 home-folder-path old.txt
printf 'mail %s\n' "$MAIL" >>"$CIR/old.txt"
git -C "$CIR" commit -q -am "add a dirty line"
_ci "$OLDB" "$(git -C "$CIR" rev-parse HEAD)"
# RED WHEN: added lines in a changed file are not scanned in CI (partner of the case above).
expect_rc "ci: a new dirty line in that file fails" 1 personal-email old.txt
ci_branch c-dependabot
git -C "$CIR" commit -q --allow-empty -m "Bump parser from 1.0 to 1.1${NL}${NL}Signed-off-by: dependabot[bot] <support@github"".com>"
_ci "$CIBASE" "$(git -C "$CIR" rev-parse HEAD)"
# RED WHEN: the Dependabot sign-off address fails CI.
expect_rc "ci: a Dependabot sign-off passes" 0 @scanned
git -C "$CIR" commit -q --allow-empty -m "Fix${NL}${NL}Signed-off-by: Jane Doe <$MAIL>"
_ci "$CIBASE" "$(git -C "$CIR" rev-parse HEAD)"
# RED WHEN: every sign-off address is exempt (partner of the case above).
expect_rc "ci: a personal sign-off address fails" 1 personal-email
ci_branch c-zip
L_H="$HOMEP" "$REAL_PY" -c 'import os,sys,zipfile; z=zipfile.ZipFile(sys.argv[1],"w"); z.writestr("inner/notes.md","see "+os.environ["L_H"]+"\n"); z.close()' "$CIR/notes.zip"
git -C "$CIR" add notes.zip && git -C "$CIR" commit -q -m "zip"
_ci "$CIBASE" "$(git -C "$CIR" rev-parse HEAD)"
# RED WHEN: CI does not open archives.
expect_rc "ci: a home path inside a zip fails" 1 home-folder-path notes.zip
ci_branch c-name-mail
commit_file "$CIR" "contacts/$MAIL.vcf" "card" "a contact card"
_ci "$CIBASE" "$(git -C "$CIR" rev-parse HEAD)"
# RED WHEN: a path place repeats the address it matched.
expect_rc "ci: an email address as a file name fails, masked" 1 personal-email
CI_BODY="Context.${NL}the owner asked for this change"
_ci "$CIBASE" "$CLEANHEAD"
# RED WHEN: reported speech in a PR body fails CI, or is not reported.
expect_rc "ci: reported speech in the body warns and passes" 0 WARNING "body"
CI_BODY="Adds a test."
_ci "$CIBASE" "$CLEANHEAD"
if [ "$(rc)" = 0 ] && ! grep -q WARNING "$ERR"; then ok "ci: a plain body does not warn"; else bad "ci: a plain body does not warn" "exit $(rc)$(_hint)"; fi

echo "== CI mode: multi-line findings, stale bases, authors, UTF-16, key-shaped names"
_ci_in() { # REPO BASE HEAD
  (unset PRIVATE_NOTES_DIR && PR_TITLE="$CI_TITLE" PR_BODY="$CI_BODY" _run python3 "$SCAN" ci --repo "$1" --base "$2" --head "$3")
}
ci_branch c-keybody
commit_file "$CIR" id.pem "$KB${NL}$KE" "an empty key block on the base"
KBASE="$(git -C "$CIR" rev-parse HEAD)"
printf '%s\n%s\n%s\n' "$KB" "$KEYBODY" "$KE" >"$CIR/id.pem"
git -C "$CIR" commit -q -am "fill the key in"
_ci "$KBASE" "$(git -C "$CIR" rev-parse HEAD)"
# RED WHEN: CI keeps a multi-line finding only when its first line is new.
expect_rc "ci: a key body added between base BEGIN/END lines fails" 1 private-key id.pem
ci_branch c-keyold
commit_file "$CIR" id.pem "header${NL}$KB${NL}$KEYBODY${NL}$KE" "a key on the base"
KBASE="$(git -C "$CIR" rev-parse HEAD)"
printf 'a trailing note\n' >>"$CIR/id.pem"
git -C "$CIR" commit -q -am "edit elsewhere"
_ci "$KBASE" "$(git -C "$CIR" rev-parse HEAD)"
# RED WHEN: CI checks a changed file by its added lines only (the old key escapes).
expect_rc "ci: an edit elsewhere in a file holding an old key fails" 1 private-key id.pem
CI_BODY="HOME=${U}ers/jane"
_ci "$CIBASE" "$CLEANHEAD"
# RED WHEN: a home path with no trailing slash passes in a PR body.
expect_rc "ci: HOME=/Users/<name> in the PR body fails" 1 home-folder-path body
CI_BODY="Adds a test."

# Contract: CI treats as already on the destination the --base sha, the base branch's remote ref
# (refs/remotes/origin/$GITHUB_BASE_REF) and every tag, when they do NOT contain the head; a ref
# that contains the head (the PR's own branch) never is, and other origin branches are not. So a
# PR that merges in newer base-branch content UNCHANGED checks nothing of it.
CIS="$WORK/ci-stale"
git init -q "$CIS"
commit_file "$CIS" a.txt "start" "init"
M0="$(git -C "$CIS" rev-parse HEAD)"
commit_file "$CIS" old.txt "see $HOMEP" "main moved on, already public"
M1="$(git -C "$CIS" rev-parse HEAD)"
git -C "$CIS" checkout -q -b feature "$M0"
commit_file "$CIS" f.txt "feature work" "feature"
git -C "$CIS" merge -q --no-edit "$M1" >/dev/null 2>&1
H="$(git -C "$CIS" rev-parse HEAD)"
git -C "$CIS" update-ref refs/remotes/origin/main "$M1"
GITHUB_BASE_REF=main _ci_in "$CIS" "$M0" "$H"
# RED WHEN: a stale base sha makes the base branch's newer, public content count as new.
expect_rc "ci: stale base, newer content on the base branch (GITHUB_BASE_REF) passes" 0 @scanned
_ci_in "$CIS" "$M0" "$H"
# RED WHEN: with GITHUB_BASE_REF unset, an origin branch still counts as on the destination (only
# the base commit and tags may; partner of the case above).
expect_rc "ci: without GITHUB_BASE_REF an origin branch does not count as on the destination" 1 home-folder-path old.txt
git -C "$CIS" update-ref -d refs/remotes/origin/main
git -C "$CIS" tag v1 "$M1"
_ci_in "$CIS" "$M0" "$H"
# RED WHEN: tags are not exclusions in CI.
expect_rc "ci: stale base, newer main content under a tag passes" 0 @scanned
commit_file "$CIS" g.txt "mail $MAIL" "new dirty work"
H2="$(git -C "$CIS" rev-parse HEAD)"
_ci_in "$CIS" "$M0" "$H2"
# RED WHEN: the exclusions hide content that is new (partner of the cases above).
expect_rc "ci: new dirty content on a stale base still fails" 1 personal-email
git -C "$CIS" update-ref refs/remotes/origin/feature "$H2"
GITHUB_BASE_REF=feature _ci_in "$CIS" "$M0" "$H2"
# RED WHEN: the PR's own branch (a ref that contains the head) is used as an exclusion.
expect_rc "ci: the PR's own origin branch is not an exclusion" 1 personal-email

ci_branch c-author
git -C "$CIR" -c user.email="$MAIL" commit -q --allow-empty -m "work"
_ci "$CIBASE" "$(git -C "$CIR" rev-parse HEAD)"
# RED WHEN: CI does not check the author addresses of the PR's commits.
expect_rc "ci: a new personal author address not on the base side fails" 1 personal-email author
ci_branch c-author-base
git -C "$CIR" -c user.email="$MAIL2" commit -q --allow-empty -m "work already on the base"
ABASE="$(git -C "$CIR" rev-parse HEAD)"
git -C "$CIR" -c user.email="$MAIL2" commit -q --allow-empty -m "more work by the same person"
_ci "$ABASE" "$(git -C "$CIR" rev-parse HEAD)"
# RED WHEN: an address already on the base side fails CI (partner of the case above).
expect_rc "ci: an author address already on the base side passes" 0 @scanned
ci_branch c-author-ok
git -C "$CIR" -c user.email="12345+jane@users.""noreply.github.com" commit -q --allow-empty -m "work"
_ci "$CIBASE" "$(git -C "$CIR" rev-parse HEAD)"
# RED WHEN: no-reply author addresses fail CI (partner of the case above).
expect_rc "ci: a GitHub no-reply author passes" 0 @scanned
ci_branch c-utf16
L_H="$HOMEP" "$REAL_PY" -c 'import os,sys; open(sys.argv[1],"wb").write(("\ufeffsee " + os.environ["L_H"] + "\n").encode("utf-16-le"))' "$CIR/notes16.txt"
git -C "$CIR" add notes16.txt && git -C "$CIR" commit -q -m "a dirty UTF-16 file"
_ci "$CIBASE" "$(git -C "$CIR" rev-parse HEAD)"
# RED WHEN: CI scans UTF-16 text as bytes.
expect_rc "ci: a home path in UTF-16LE text fails" 1 home-folder-path notes16.txt
ci_branch c-keyname
commit_file "$CIR" "keys/$KEY.txt" "line one" "a file named like a key, on the base"
KNB="$(git -C "$CIR" rev-parse HEAD)"
printf 'see %s\n' "$HOMEP" >>"$CIR/keys/$KEY.txt"
git -C "$CIR" commit -q -am "a dirty edit"
_ci "$KNB" "$(git -C "$CIR" rev-parse HEAD)"
# RED WHEN: CI prints the name of a file it did not scan the name of.
expect_rc "ci: a finding in a key-named file never prints its name" 1 home-folder-path

# ========================================================================= allowed addresses
echo "== allowed addresses: public-content/allowed-addresses.txt"
# Contract: public-content/allowed-addresses.txt lists the addresses that are deliberately
# public, one per line (`#` comment lines and blank lines allowed). The owner chose exactly the
# two below; they are public on purpose, so this file may name them literally. A listed address
# passes in any case (compared lowercased) wherever the email rule looks: file content, messages,
# author and committer addresses. Any other address still blocks, even one a character away.
# The list missing or holding a malformed line: exit 2 (fail closed). In CI, a range that
# changes the list prints a `::warning` line (and does not fail for that alone).
ALLOW1="rohit.ra.agrawal@gmail.com"
ALLOW2="rohit@stackclimb.com"
ALLOWF="$ROOT/public-content/allowed-addresses.txt"
ADDR_RE='^[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$'
# _allow_lines FILE: the non-comment, non-blank lines, trimmed.
_allow_lines() { grep -v -E -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$1" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }
if [ -f "$ALLOWF" ]; then
  got="$(_allow_lines "$ALLOWF" | tr '[:upper:]' '[:lower:]' | sort -u | tr '\n' ' ')"
  want="$(printf '%s\n%s\n' "$ALLOW1" "$ALLOW2" | sort | tr '\n' ' ')"
  # RED WHEN: the list loses one of the owner's two addresses or gains another one.
  if [ "$got" = "$want" ]; then ok "allowed list: holds exactly the owner's two addresses"; else bad "allowed list: holds exactly the owner's two addresses" "got '$got'"; fi
  # RED WHEN: a line that is not an address (or a comment, or blank) is added to the list.
  odd="$(_allow_lines "$ALLOWF" | grep -c -v -E "$ADDR_RE")"
  if [ "$odd" = 0 ] && [ -n "$got" ]; then ok "allowed list: every other line is a comment or blank"; else bad "allowed list: every other line is a comment or blank" "$odd line(s) are not an address"; fi
else
  bad "allowed list: holds exactly the owner's two addresses" "public-content/allowed-addresses.txt is missing"
  bad "allowed list: every other line is a comment or blank" "public-content/allowed-addresses.txt is missing"
fi

# RED WHEN: a listed address is reported in text, or matched case-sensitively.
for t in "contact $ALLOW1 for the demo" "contact $ALLOW2 for the demo" "contact Rohit.Ra.Agrawal@Gmail.com" "contact ROHIT@StackClimb.COM"; do
  _text "$t"
  expect_rc "allowed: '$t' passes" 0 @scanned
done
# RED WHEN: the list is matched as a prefix, suffix or substring, or loosely, instead of exactly
# (each address below is one character, or one domain part, away from a listed one).
tcase "an address with one extra leading character" block "contact x$ALLOW2"
tcase "a listed address with its last character dropped" block "contact ${ALLOW1%m}"
tcase "a listed address with one character changed" block "contact r0${ALLOW2#ro}"
tcase "a listed address followed by more domain" block "contact ${ALLOW2}.evil.io"
# RED WHEN: the allow list exempts every address (partner: an unlisted personal address blocks).
tcase "an unlisted personal address" block "contact $MAIL"

# File content, messages and authors in CI mode.
ci_branch c-allowed
commit_file "$CIR" CONTACT.md "Write to $ALLOW1 or $ALLOW2 (also Rohit@StackClimb.com)." "contact: the public addresses"
git -C "$CIR" -c user.email="$ALLOW1" commit -q --allow-empty -m "work by the owner"
GIT_COMMITTER_EMAIL="Rohit@StackClimb.com" git -C "$CIR" -c user.email="$ALLOW2" commit -q --allow-empty -m "more work, mail $ALLOW1"
_ci "$CIBASE" "$(git -C "$CIR" rev-parse HEAD)"
# RED WHEN: a listed address blocks in a new file, a message, or as an author or committer
# address (the configured user.email here is a different one, so only the list can allow it).
expect_rc "allowed (ci): listed addresses in a file, a message and as author/committer pass" 0 @scanned
git -C "$CIR" -c user.email="x$ALLOW2" commit -q --allow-empty -m "work"
_ci "$CIBASE" "$(git -C "$CIR" rev-parse HEAD)"
# RED WHEN: an author address one character away from a listed one passes (partner of the above).
expect_rc "allowed (ci): an author one character away from a listed address fails" 1 personal-email author

vis acme/p-allow public
mkpush allow "$(gh_url acme/p-allow)"
D="$P/allow"
GIT_COMMITTER_EMAIL="$ALLOW2" git -C "$D" -c user.email="$ALLOW1" commit -q --allow-empty -m "work by the owner"
gpush "$D" "$D.git" origin main
# RED WHEN: a listed author or committer address blocks a push.
expect_pushed "allowed (push): listed author and committer addresses pass" scanned
git -C "$D" -c user.email="$MAIL" commit -q --allow-empty -m "work by someone else"
gpush "$D" "$D.git" origin main
# RED WHEN: the list exempts unlisted authors on a push (partner of the case above).
expect_blocked "allowed (push): an unlisted author address still blocks" personal-email author

# The list missing or malformed: run copies of the scanner folder.
PCOK="$WORK/pc-ok"
PCNO="$WORK/pc-nolist"
PCBAD="$WORK/pc-badlist"
for d in "$PCOK" "$PCNO" "$PCBAD"; do
  rm -rf "$d"
  cp -R "$ROOT/public-content" "$d" || die "copy public-content"
done
rm -f "$PCNO/allowed-addresses.txt"
_text_with() { # SCANNER TEXT
  printf '%s\n' "$2" >"$WORK/text.in"
  _run python3 "$1" text --label demo <"$WORK/text.in"
}
_text_with "$PCOK/scan.py" "contact $ALLOW1"
# RED WHEN: a copy of the scanner folder cannot run (the fail-closed cases below would be vacuous).
expect_rc "allowed list: a full copy of the scanner folder runs and allows a listed address" 0 @scanned
_text_with "$PCNO/scan.py" "contact $ALLOW1"
# RED WHEN: a missing list is read as empty or ignored (fail open, or every listed address blocks).
expect_rc "allowed list: missing -> exit 2 (text with a listed address)" 2
_text_with "$PCNO/scan.py" "Adds a parser test."
# RED WHEN: the list is only read when an address is found (a missing list must never pass).
expect_rc "allowed list: missing -> exit 2 (clean text)" 2
for line in "not-an-address" "@stackclimb.com"; do
  printf '# allowed addresses\n%s\n%s\n' "$ALLOW1" "$line" >"$PCBAD/allowed-addresses.txt"
  _text_with "$PCBAD/scan.py" "contact $ALLOW1"
  # RED WHEN: a malformed line is skipped (a typo would silently drop an address or allow junk).
  expect_rc "allowed list: a malformed line ('$line') -> exit 2" 2
done

# CI: a range that changes the list warns.
CIA="$WORK/ci-allow"
git init -q "$CIA"
commit_file "$CIA" public-content/allowed-addresses.txt "# deliberately public${NL}$ALLOW1${NL}$ALLOW2" "the list"
commit_file "$CIA" README.md "readme" "readme"
ABASE2="$(git -C "$CIA" rev-parse HEAD)"
commit_file "$CIA" docs.md "How to run the tests." "docs only"
_ci_in "$CIA" "$ABASE2" "$(git -C "$CIA" rev-parse HEAD)"
# RED WHEN: every range warns (partner of the case below).
if [ "$(rc)" = 0 ] && ! grep -q -F "::warning" "$ERR"; then ok "allowed list (ci): a range that does not touch the list does not warn"; else bad "allowed list (ci): a range that does not touch the list does not warn" "exit $(rc)$(_hint)"; fi
printf '# reviewed\n' >>"$CIA/public-content/allowed-addresses.txt"
git -C "$CIA" commit -q -am "touch the list"
_ci_in "$CIA" "$ABASE2" "$(git -C "$CIA" rev-parse HEAD)"
# RED WHEN: a change to the allowed-address list goes by without a warning to the reviewer.
expect_rc "allowed list (ci): a range that changes the list prints ::warning and passes" 0 "::warning" @scanned

# ========================================================================= harder names, idents, unreadable content
echo "== scanner core: home folder names with underscores, accents and other case"
# Contract: a home folder name may start with any character a user name can (an underscore, an
# accented letter); a Windows home path matches in any case. Placeholders ($USER, ${USER},
# <name>) and shared or CI homes are not a person's home.
BS="\\"
# RED WHEN: the home-folder rule needs an ASCII letter or digit first, or is case-sensitive on Windows.
tcase "a macOS home folder starting with an underscore" block "see ${U}ers/_alice/x"
tcase "a Linux home folder starting with an underscore" block "see /ho""me/_alice/x"
tcase "a macOS home folder with an accented first letter" block "see ${U}ers/Élodie/x"
tcase "a lowercase Windows home path" block "see c:${BS}users${BS}jane${BS}x"
tcase "an uppercase Windows home path" block "see C:${BS}USERS${BS}jane${BS}x"
# RED WHEN: widening the rule catches CI and shared homes or placeholders (partners of the above).
tcase "the CI runner home" pass "see /ho""me/runner/x"
tcase "the shared macOS folder" pass "see ${U}ers/Shared/x"
tcase "the public Windows profile" pass "see C:${BS}Users${BS}Public${BS}x"
tcase "a \$USER placeholder" pass "see /ho""me/"'$USER'"/x"
tcase "a \${USER} placeholder" pass "see ${U}ers/"'${USER}'"/x"
tcase "a <name> placeholder" pass "see /ho""me/<name>"

echo "== scanner core: a private term list saved with a byte-order mark"
mkdir -p "$WORK/bom-notes/scanner"
printf '\357\273\277%s\n' "$PTERM" >"$WORK/bom-notes/scanner/private-terms.txt"
PRIVATE_NOTES_DIR="$WORK/bom-notes" _text "we build $PTERM next"
# RED WHEN: a UTF-8 byte-order mark becomes part of the first term (it never matches).
expect_rc "terms: the first term of a list saved with a byte-order mark still matches" 1 private-term

echo "== CI mode: PR title and body must be given"
(unset PRIVATE_NOTES_DIR PR_TITLE && PR_BODY="$CI_BODY" _run python3 "$SCAN" ci --repo "$CIR" --base "$CIBASE" --head "$CLEANHEAD")
# RED WHEN: a missing PR_TITLE is read as an empty title (a broken workflow would pass unchecked).
expect_rc "ci: PR_TITLE unset -> exit 2" 2
(unset PRIVATE_NOTES_DIR PR_BODY && PR_TITLE="$CI_TITLE" _run python3 "$SCAN" ci --repo "$CIR" --base "$CIBASE" --head "$CLEANHEAD")
# RED WHEN: a missing PR_BODY is read as an empty body.
expect_rc "ci: PR_BODY unset -> exit 2" 2
(unset PRIVATE_NOTES_DIR && PR_TITLE="$CI_TITLE" PR_BODY="" _run python3 "$SCAN" ci --repo "$CIR" --base "$CIBASE" --head "$CLEANHEAD")
# RED WHEN: an EMPTY body (a PR with no description) is refused (partner of the two cases above).
expect_rc "ci: PR_BODY set but empty passes" 0 @scanned

echo "== masking: accented home folder names in paths"
ci_branch c-mask
commit_file "$CIR" "docs${U}ers/José/notes.txt" "notes" "notes in an accented home folder"
_ci "$CIBASE" "$(git -C "$CIR" rev-parse HEAD)"
# RED WHEN: a home path in a path name is missed, or the place prints it because the masking
# regex stops at an accented letter (the leak check looks for its start).
expect_rc "ci: an accented home folder in a path is found and never printed" 1 home-folder-path
vis acme/p-mask public
mkpush mask "$(gh_url acme/p-mask)"
D="$P/mask"
commit_file "$D" "x/ho""me/zoë/y.txt" "y" "a file in an accented home folder"
gpush "$D" "$D.git" origin main
# RED WHEN: a push misses the home path in a path name, or prints it unmasked.
expect_blocked "push: an accented home folder in a path is blocked and never printed" home-folder-path

echo "== git pre-push hook: taggers and author names"
vis acme/p-tagger public
mkpush tagger "$(gh_url acme/p-tagger)"
D="$P/tagger"
GIT_COMMITTER_EMAIL="$MAIL" git -C "$D" tag -a t-mail -m "release notes"
gpush "$D" "$D.git" origin t-mail
# RED WHEN: the tagger address of a new annotated tag is not checked (a tag on a published
# commit, pushed alone, publishes only the tag object).
expect_blocked "tag: a tagger address that is personal is blocked" personal-email
git -C "$D" config user.email "$MAIL2"
git -C "$D" tag -a t-own -m "release notes"
gpush "$D" "$D.git" origin t-own
# RED WHEN: the configured user.email is blocked as a tagger (partner of the case above).
expect_pushed "tag: the configured user.email as tagger passes" scanned
git -C "$D" config --unset user.email
git -C "$D" -c user.name="Jane $HOMEP" commit -q --allow-empty -m "work"
gpush "$D" "$D.git" origin main
# RED WHEN: only the address of an author line is checked, not its name.
expect_blocked "author: a home path in an author name is blocked" home-folder-path

echo "== content that gitleaks cannot read by itself"
# Contract: content that looks like an archive or a binary format is opened or scanned as text;
# what cannot be read (encrypted, nested deeper than three archives, an archive not read
# completely) fails closed with exit 2. Never exit 0 with a leak inside. Each fixture holds a home
# path. A contract change altered some cases below (marked); the rest of its cases are in
# test-public-content-formats.sh.
FX="$WORK/fx"
mkdir -p "$FX"
L_H="$HOMEP" "$REAL_PY" - "$FX" <<'PY'
import bz2, gzip, io, lzma, os, random, sys, tarfile, zipfile
out, h = sys.argv[1], os.environ["L_H"].encode()
leak = b"see " + h + b"\n"
def w(name, data):
    with open(os.path.join(out, name), "wb") as f:
        f.write(data)
def zbytes(members):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for n, d in members:
            z.writestr(n, d)
    return b.getvalue()
def tarbytes(members):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w", format=tarfile.USTAR_FORMAT) as t:
        for n, d in members:
            ti = tarfile.TarInfo(n)
            ti.size, ti.mtime = len(d), 0
            t.addfile(ti, io.BytesIO(d))
    return b.getvalue()
w("bzh.bin", b"BZh " + leak)
w("pk.bin", b"PK\x03\x04 " + leak)
w("gzmagic.bin", b"\x1f\x8b " + leak)
w("ustar.bin", b"A" * 257 + b"ustar " + leak)
w("sqlite.bin", b"SQLite format 3\x00\x00\x01 " + leak)
w("pdf.txt", b"%PDF-1.4 " + leak)
w("rtf.txt", b"{\\rtf1 " + leak)
w("utf16odd.txt", ("﻿see " + h.decode() + "\n").encode("utf-16-le") + b"x")
z = zbytes([("notes.md", leak)])
for depth in (2, 3, 4):
    z = zbytes([("inner%d.zip" % (depth - 1), z)])
    w("nest%d.zip" % depth, z)
rnd = random.Random(7)
w("big.tar.bz2", bz2.compress(tarbytes([("pad.bin", rnd.randbytes(310000)), ("notes.md", leak)])))
small = tarbytes([("notes.md", leak)])
w("t.tar.gz", gzip.compress(small, mtime=0))
w("t.tar.xz", lzma.compress(small))
w("clean.zip", zbytes([("readme.md", b"All tests pass.\n")]))
w("clean.bin", rnd.randbytes(4096))
w("leak.txt", leak)
def zdefl(members):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for n, d in members:
            z.writestr(n, d)
    return b.getvalue()
gz = lambda d: gzip.compress(d, mtime=0)
clean = b"All tests pass.\n"
w("gz-two.gz", gz(clean) + gz(leak))
w("bz-two.bz2", bz2.compress(clean) + bz2.compress(leak))
t = gz(leak + rnd.randbytes(2048))
w("gz-cut.gz", t[: len(t) // 2])
t = zdefl([("notes.md", leak + rnd.randbytes(2048))])
w("zip-corrupt.zip", t[: len(t) // 2])
w("bom-ascii.txt", b"\xff\xfe" + leak)
w("utf32.txt", ("\ufeffsee " + h.decode() + "\n").encode("utf-32-le"))
w("glued.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 64 + zdefl([("notes.md", leak)]))
w("gz-zip.gz", gz(clean) + zdefl([("notes.md", leak)]))
w("gz-bz2.gz", gz(clean) + bz2.compress(leak))
w("gz-1001.gz", gz(b"x\n") * 1001)
w("gz-999.gz", gz(b"x\n") * 999)
w("gz-pad.gz", gz(clean) + b"\x00" * 512)
w("bzh-clean.txt", b"BZh is how a bzip2 file starts.\n")
w("clean.txt", clean)
PY
HAVE_ZIP=no
if command -v zip >/dev/null 2>&1 && (cd "$FX" && zip -q -P not-a-secret enc.zip leak.txt); then HAVE_ZIP=yes; fi
HAVE_ZSTD=no
if command -v zstd >/dev/null 2>&1 && zstd -q "$FX/leak.txt" -o "$FX/leak.txt.zst"; then HAVE_ZSTD=yes; fi
# RED WHEN: the fixtures change so a case below holds no leak (the "never 0" cases would be vacuous).
if [ "$(wc -c <"$FX/big.tar.bz2")" -gt 300000 ] && grep -q -F -e "$HOMEP" "$FX/pdf.txt"; then ok "sanity: the archive and binary fixtures hold the leak"; else bad "sanity: the archive and binary fixtures hold the leak" "fixtures wrong"; fi
_bin() { _run python3 "$SCAN" text --label demo <"$1"; }
# expect_not0 NAME: exit 1 or 2, and nothing printed repeats the leak.
expect_not0() {
  case "$(rc)" in
    1 | 2) if _leaks "$OUT" "$ERR"; then bad "$1" "the output repeats the matched text"; else ok "$1"; fi ;;
    *) bad "$1" "expected exit 1 or 2 (a leak inside), got $(rc)$(_hint)" ;;
  esac
}
# fx_case NAME FILE WANT: WANT is 0, 1, 2 or "not0"; run in text mode.
fx_case() {
  _bin "$FX/$2"
  case "$3" in
    not0) expect_not0 "$1" ;;
    0) expect_rc "$1" 0 @scanned ;;
    1) expect_rc "$1" 1 home-folder-path ;;
    *) expect_rc "$1" "$3" ;;
  esac
}
# RED WHEN: content gitleaks skips or fails to open silently (by magic bytes, as binary, or as a
# broken archive) is treated as clean.
fx_case "unreadable (text): text starting with BZh" bzh.bin not0
fx_case "unreadable (text): text starting with a zip header" pk.bin not0
fx_case "unreadable (text): text starting with the gzip magic" gzmagic.bin not0
# Contract changed: a tar is now found by its header checksum, so this is text (was 1 or 2).
# RED WHEN: text with 'ustar' at byte 257 is read as a broken tar (exit 2) or its leak is missed.
fx_case "unreadable (text): text with 'ustar' at offset 257 -> found" ustar.bin 1
fx_case "unreadable (text): an SQLite-headed file" sqlite.bin not0
fx_case "unreadable (text): a PDF-headed text" pdf.txt not0
fx_case "unreadable (text): an RTF-headed text" rtf.txt not0
fx_case "unreadable (text): UTF-16LE with a BOM and an odd trailing byte" utf16odd.txt not0
# RED WHEN: an archive gitleaks cannot open, or one nested past the depth limit, passes as clean.
if [ "$HAVE_ZIP" = yes ]; then fx_case "archive (text): an encrypted zip -> exit 2" enc.zip 2; else skip "archive (text): an encrypted zip" "no zip tool"; fi
fx_case "archive (text): a zip nested 4 deep -> exit 2" nest4.zip 2
# RED WHEN: the depth limit is set below three (partner of the case above).
fx_case "archive (text): a zip nested 3 deep -> found" nest3.zip 1
# RED WHEN: a compressed tarball is only recognised from its first 64 KB.
fx_case "archive (text): a 300 KB+ .tar.bz2 -> found" big.tar.bz2 1
fx_case "archive (text): a .tar.gz -> found" t.tar.gz 1
fx_case "archive (text): a .tar.xz -> found" t.tar.xz 1
# Contract tightened: archives the guard cannot open, zstd among them, are refused (was 1 or 2).
# RED WHEN: a zstd file is read as text or passed instead of refused.
if [ "$HAVE_ZSTD" = yes ]; then fx_case "archive (text): a .zst file -> exit 2" leak.txt.zst 2; else skip "archive (text): a .zst file" "no zstd tool"; fi
# RED WHEN: failing closed also refuses clean archives and binaries (partners of all the above).
fx_case "archive (text): a clean zip passes" clean.zip 0
fx_case "binary (text): a clean binary passes" clean.bin 0
# RED WHEN: only the first stream of a multi-stream file is read (the leak is in the second).
fx_case "streams (text): a gzip of two streams, leak in the second -> found" gz-two.gz 1
fx_case "streams (text): a bzip2 of two streams, leak in the second -> found" bz-two.bz2 1
# RED WHEN: a stream after a gzip stream is ignored or read as the wrong format.
# Contract changed: the guard now reads gzip, bzip2 and xz completely or blocks; after a stream
# only NUL padding or a stream of the SAME format may follow (these were found, exit 1).
# RED WHEN: bytes after a gzip stream that are not another gzip stream are accepted.
fx_case "streams (text): a gzip stream then a glued zip -> exit 2" gz-zip.gz 2
fx_case "streams (text): a gzip stream then a bzip2 stream -> exit 2" gz-bz2.gz 2
# RED WHEN: a truncated or corrupt archive is read as far as it goes and passed as clean.
fx_case "corrupt (text): a gzip cut in half -> exit 2" gz-cut.gz 2
fx_case "corrupt (text): a zip signature on a corrupt zip -> exit 2" zip-corrupt.zip 2
# RED WHEN: a byte-order mark is trusted when the text after it is not that encoding, or UTF-32 is
# read as UTF-16 (the leak hides either way).
fx_case "encoding (text): an FF FE mark before plain ASCII -> found" bom-ascii.txt 1
fx_case "encoding (text): UTF-32LE with its mark -> found" utf32.txt 1
# RED WHEN: an archive glued after other bytes (an image header and padding) is not found.
fx_case "glued (text): a zip after a PNG signature and NUL padding -> found" glued.png 1
# Contract changed: no stream count limit (the unpack budget bounds the work; this was exit 2).
# RED WHEN: a stream count limit comes back (BGZF files hold thousands of streams).
fx_case "streams (text): 1001 tiny clean gzip streams pass" gz-1001.gz 0
fx_case "streams (text): 999 clean gzip streams pass" gz-999.gz 0
fx_case "streams (text): a clean gzip followed by NUL padding passes" gz-pad.gz 0
# RED WHEN: text that merely starts like a bzip2 file, or plain clean text, is refused.
fx_case "partner (text): clean text starting with 'BZh' passes" bzh-clean.txt 0
fx_case "partner (text): clean text passes" clean.txt 0

# The same files committed, in CI mode.
# fx_ci NAME FILE WANT
fx_ci() {
  ci_branch c-fx
  mkdir -p "$CIR/fx"
  cp "$FX/$2" "$CIR/fx/$2"
  if ! { git -C "$CIR" add "fx/$2" && git -C "$CIR" commit -q -m "add $2"; }; then die "commit fx/$2"; fi
  _ci "$CIBASE" "$(git -C "$CIR" rev-parse HEAD)"
  case "$3" in
    not0) expect_not0 "$1" ;;
    0) expect_rc "$1" 0 @scanned ;;
    1) expect_rc "$1" 1 home-folder-path ;;
    *) expect_rc "$1" "$3" ;;
  esac
}
# RED WHEN: a committed file that gitleaks skips or cannot open passes CI as clean.
fx_ci "unreadable (ci): a file starting with BZh" bzh.bin not0
fx_ci "unreadable (ci): a file starting with a zip header" pk.bin not0
fx_ci "unreadable (ci): a file starting with the gzip magic" gzmagic.bin not0
# Contract changed: the guard now reads zip, tar, gzip, bzip2 and xz completely or blocks,
# and reads other binaries by their plain text (was 1 or 2).
# RED WHEN: a committed text with 'ustar' at byte 257 is read as a broken tar or its leak is missed.
fx_ci "unreadable (ci): a file with 'ustar' at offset 257 -> found" ustar.bin 1
fx_ci "unreadable (ci): an SQLite-headed file" sqlite.bin not0
fx_ci "unreadable (ci): a PDF-headed text" pdf.txt not0
fx_ci "unreadable (ci): an RTF-headed text" rtf.txt not0
fx_ci "unreadable (ci): UTF-16LE with a BOM and an odd trailing byte" utf16odd.txt not0
if [ "$HAVE_ZIP" = yes ]; then fx_ci "archive (ci): an encrypted zip -> exit 2" enc.zip 2; else skip "archive (ci): an encrypted zip" "no zip tool"; fi
fx_ci "archive (ci): a zip nested 4 deep -> exit 2" nest4.zip 2
fx_ci "archive (ci): a zip nested 3 deep -> found" nest3.zip 1
fx_ci "archive (ci): a 300 KB+ .tar.bz2 -> found" big.tar.bz2 1
fx_ci "archive (ci): a .tar.gz -> found" t.tar.gz 1
fx_ci "archive (ci): a .tar.xz -> found" t.tar.xz 1
# Contract tightened: archives the guard cannot open, zstd among them, are refused (was 1 or 2).
# RED WHEN: a committed zstd file is read as text or passed instead of refused.
if [ "$HAVE_ZSTD" = yes ]; then fx_ci "archive (ci): a .zst file -> exit 2" leak.txt.zst 2; else skip "archive (ci): a .zst file" "no zstd tool"; fi
fx_ci "archive (ci): a clean zip passes" clean.zip 0
fx_ci "binary (ci): a clean binary passes" clean.bin 0
# RED WHEN: a committed file hides its leak in a later stream, a glued archive, a wrong byte-order
# mark, or behind a stream count CI does not limit (the cases above, as committed files).
fx_ci "streams (ci): a gzip of two streams, leak in the second -> found" gz-two.gz 1
# Contract changed: the guard now reads gzip completely or blocks (these were found, exit 1).
# RED WHEN: CI accepts bytes after a gzip stream that are not another gzip stream.
fx_ci "streams (ci): a gzip stream then a glued zip -> exit 2" gz-zip.gz 2
fx_ci "streams (ci): a gzip stream then a bzip2 stream -> exit 2" gz-bz2.gz 2
fx_ci "corrupt (ci): a gzip cut in half -> exit 2" gz-cut.gz 2
fx_ci "encoding (ci): an FF FE mark before plain ASCII -> found" bom-ascii.txt 1
fx_ci "encoding (ci): UTF-32LE with its mark -> found" utf32.txt 1
fx_ci "glued (ci): a zip after a PNG signature and NUL padding -> found" glued.png 1
# Contract changed: no stream count limit (this was exit 2).
# RED WHEN: CI refuses a clean file for its stream count.
fx_ci "streams (ci): 1001 tiny clean gzip streams pass" gz-1001.gz 0
fx_ci "partner (ci): clean text starting with 'BZh' passes" bzh-clean.txt 0

echo "== git pre-push hook: replace refs, merged tags, squash and cherry-pick messages"
# Contract: the scanner reads the objects git really sends, never a local `git replace` view.
vis acme/p-repl public
mkpush repl "$(gh_url acme/p-repl)"
D="$P/repl"
commit_file "$D" x.txt "x" "work from $HOMEP"
GIT_EDITOR="sed -i.bak -e 's#from .*#from my laptop#'" git -C "$D" replace --edit HEAD
# RED WHEN: the setup changes so the local view still shows the home path (the case would be vacuous).
if git -C "$D" log -1 --format=%s | grep -q -F "my laptop"; then ok "sanity: git replace hides the message locally"; else bad "sanity: git replace hides the message locally" "replace --edit did not apply"; fi
gpush "$D" "$D.git" origin main
# RED WHEN: the scanner honours replace refs (it scans the clean replacement; git pushes the original).
expect_blocked "replace: a message cleaned only by a local replace ref is blocked" home-folder-path
vis acme/p-graft public
git init -q --bare "$P/graft.git"
D="$P/graft"
git init -q "$D"
git -C "$D" remote add origin "$(gh_url acme/p-graft)"
git -C "$D" config "url.$P/graft.git.insteadOf" "$(gh_url acme/p-graft)"
git -C "$D" config core.hooksPath "$ROOT/hooks"
commit_file "$D" old.txt "see $HOMEP" "old private history"
git -C "$D" rm -q old.txt && git -C "$D" commit -q -m "remove"
commit_file "$D" a.txt "public start" "public start"
git -C "$D" replace --graft HEAD
# RED WHEN: the setup changes so the graft does not hide the history locally (vacuous case).
if [ "$(git -C "$D" rev-list --count HEAD)" = 1 ]; then ok "sanity: git replace --graft hides the old history locally"; else bad "sanity: git replace --graft hides the old history locally" "graft did not apply"; fi
gpush "$D" "$P/graft.git" origin main
# RED WHEN: a graft hides history that the first push to an empty destination really sends.
expect_blocked "replace: history hidden by a local graft is still scanned on a first push" home-folder-path old.txt

if command -v ssh-keygen >/dev/null 2>&1 && ssh-keygen -q -t ed25519 -N '' -f "$WORK/signkey" >/dev/null 2>&1; then
  vis acme/p-mtag public
  mkpush mtag "$(gh_url acme/p-mtag)"
  D="$P/mtag"
  git -C "$D" config gpg.format ssh
  git -C "$D" config user.signingkey "$WORK/signkey.pub"
  git -C "$D" checkout -q -b side
  commit_file "$D" s.txt "side" "side"
  GIT_COMMITTER_EMAIL="$MAIL" git -C "$D" tag -s v-side -m "release notes: see $HOMEP"
  git -C "$D" checkout -q main
  commit_file "$D" m.txt "main" "main"
  git -C "$D" merge -q --no-ff -m "Merge side" v-side >/dev/null 2>&1
  # RED WHEN: the setup changes so the merge records no mergetag header (the case would be vacuous).
  if git -C "$D" cat-file commit HEAD | grep -q '^mergetag '; then ok "sanity: the merge commit carries the tag in a mergetag header"; else bad "sanity: the merge commit carries the tag in a mergetag header" "no mergetag header"; fi
  gpush "$D" "$D.git" origin main
  # RED WHEN: a merge commit's mergetag header (the merged tag's tagger and message) is not scanned.
  expect_blocked "mergetag: a merged tag's home path and tagger address are blocked with the branch" home-folder-path personal-email
else
  skip "mergetag: a merged tag's home path and tagger address" "ssh-keygen cannot make a signing key here"
fi

ME="$(printf '%s@%s' pat.lee corp-mail.io)"
vis acme/p-squash public
mkpush squash "$(gh_url acme/p-squash)"
D="$P/squash"
git -C "$D" config user.email "$ME"
commit_file "$D" plain.txt "plain" "plain work by the configured identity"
gpush "$D" "$D.git" origin main
# RED WHEN: the configured user.email is blocked on its own author and committer lines.
expect_pushed "squash (partner): the configured address on identity lines passes" scanned
git -C "$D" checkout -q -b feat
commit_file "$D" f.txt "feature" "feature work"
git -C "$D" checkout -q main
git -C "$D" merge -q --squash feat >/dev/null
git -C "$D" commit -q --no-edit
# RED WHEN: the setup changes so the default squash message no longer names the author (vacuous).
if git -C "$D" log -1 --format=%B | grep -q -F "$ME"; then ok "sanity: the squash message names the configured address"; else bad "sanity: the squash message names the configured address" "it does not"; fi
gpush "$D" "$D.git" origin main
# RED WHEN: the identity exemption reaches into messages (it covers identity lines only).
expect_blocked "squash: git's default squash message naming the configured address is blocked" personal-email
git -C "$D" config --unset user.email

vis acme/p-pick public
mkpush pick "$(gh_url acme/p-pick)"
D="$P/pick"
git -C "$D" branch release
printf 'fix\n' >"$D/fix.txt"
git -C "$D" add fix.txt
GIT_AUTHOR_EMAIL="$MAIL2" git -C "$D" commit -q -m "fix bug" -m "Co-authored-by: Sam Roe <$MAIL2>"
nohook_push "$D" origin main release
git -C "$D" checkout -q release
GIT_AUTHOR_EMAIL="$MAIL2" git -C "$D" commit -q --allow-empty -m "more work by the same author"
gpush "$D" "$D.git" origin release
# RED WHEN: an author address already on the destination's history is blocked on an author line.
expect_pushed "cherry-pick (partner): an author already on the destination passes as author" scanned
git -C "$D" cherry-pick -x main >/dev/null
gpush "$D" "$D.git" origin release
# RED WHEN: the history exemption reaches into messages (a cherry-pick -x carries the published
# commit's Co-authored-by line; identity lines only are exempt).
expect_blocked "cherry-pick: a message naming an author already on the destination is blocked" personal-email
git -C "$D" reset -q --hard origin/release
git -C "$D" commit -q --allow-empty -m "thanks" -m "Co-authored-by: Jane Doe <$MAIL>"
gpush "$D" "$D.git" origin release
# RED WHEN: the history exemption covers every address in a message (partner of the case above).
expect_blocked "cherry-pick: a message naming any other personal address is blocked" personal-email

echo "== CI mode: stacked pull requests and the base branch"
# Contract: in CI, commits already on the destination are those reachable from --base, from
# tags that do not contain --head, and from refs/remotes/origin/$GITHUB_BASE_REF when that
# variable is set. Other origin branches do NOT count (a stacked PR's parent is not merged yet).
CST="$WORK/ci-stack"
git init -q "$CST"
commit_file "$CST" a.txt "start" "init"
SM="$(git -C "$CST" rev-parse HEAD)"
git -C "$CST" checkout -q -b a
commit_file "$CST" leak.txt "see $HOMEP" "part 1"
SA="$(git -C "$CST" rev-parse HEAD)"
git -C "$CST" checkout -q -b b
commit_file "$CST" more.txt "clean" "part 2"
SB="$(git -C "$CST" rev-parse HEAD)"
git -C "$CST" update-ref refs/remotes/origin/main "$SM"
git -C "$CST" update-ref refs/remotes/origin/a "$SA"
git -C "$CST" update-ref refs/remotes/origin/b "$SB"
GITHUB_BASE_REF=main _ci_in "$CST" "$SM" "$SB"
# RED WHEN: any origin branch counts as published (the parent PR's unmerged branch hides its leak).
expect_rc "ci: a PR stacked on an unmerged branch that adds a home path fails" 1 home-folder-path leak.txt

# ========================================================================= installer
echo "== installer"
fakegit "$WORK/git-254" "git version 2.54.0"
fakegit "$WORK/git-253" "git version 2.53.0"
fakegit "$WORK/git-2100" "git version 2.100.0"
fakegit "$WORK/git-apple" "git version 2.54.1 (Apple Git-160)"
INST="$WORK/inst"
mkdir -p "$INST" "$HOME/.claude"
printf '{"hooks": {}}\n' >"$HOME/.claude/settings.json"
cp "$HOME/.claude/settings.json" "$INST/settings.before"
: >"$INST/g1"
(unset PRIVATE_NOTES_DIR && _install "$WORK/git-254" "$INST/g1")
# RED WHEN: the installer fails on a good machine, or does not set the command to this checkout's hook.
if [ "$(rc)" = 0 ] && cfg "$INST/g1" --get hook.public-content.command | grep -q -F -e "$ROOT/hooks/pre-push"; then
  ok "install: sets hook.public-content.command to this checkout's hooks/pre-push"
else bad "install: sets hook.public-content.command" "exit $(rc), command '$(cfg "$INST/g1" --get hook.public-content.command)'$(_hint)"; fi
# RED WHEN: the event is not set, or set more than once.
if [ "$(events "$INST/g1")" = 1 ]; then ok "install: exactly one pre-push event"; else bad "install: exactly one pre-push event" "count $(events "$INST/g1")"; fi
# RED WHEN: the installer writes the Claude settings itself (the operator does that).
if [ "$(rc)" = 0 ] && cmp -s "$HOME/.claude/settings.json" "$INST/settings.before"; then ok "install: leaves ~/.claude/settings.json untouched"; else bad "install: leaves ~/.claude/settings.json untouched" "install exit $(rc), or the file changed"; fi
# RED WHEN: the installer sets core.hooksPath (it would disable every repo's own hooks).
if [ "$(rc)" = 0 ] && [ -z "$(cfg "$INST/g1" --get core.hooksPath)" ]; then ok "install: does not set core.hooksPath"; else bad "install: does not set core.hooksPath" "install exit $(rc), or it set it"; fi
CMD1="$(cfg "$INST/g1" --get hook.public-content.command)"
(unset PRIVATE_NOTES_DIR && _install "$WORK/git-254" "$INST/g1")
# RED WHEN: a second run fails, duplicates the event or changes the command.
if [ "$(rc)" = 0 ] && [ "$(events "$INST/g1")" = 1 ] && [ "$(cfg "$INST/g1" --get hook.public-content.command)" = "$CMD1" ]; then
  ok "install: running it twice changes nothing"
else bad "install: running it twice changes nothing" "exit $(rc), events $(events "$INST/g1")"; fi
: >"$INST/g2"
_install "$WORK/git-254" "$INST/g2"
# RED WHEN: PRIVATE_NOTES_DIR set at install time is not passed to the git hook.
if [ "$(rc)" = 0 ] && cfg "$INST/g2" --get hook.public-content.command | grep -q -F -e "PRIVATE_NOTES_DIR=" &&
  cfg "$INST/g2" --get hook.public-content.command | grep -q -F -e "$NOTES"; then
  ok "install: passes PRIVATE_NOTES_DIR to the git hook"
else bad "install: passes PRIVATE_NOTES_DIR to the git hook" "exit $(rc), command '$(cfg "$INST/g2" --get hook.public-content.command)'"; fi
printf '[hook "public-content"]\n\tcommand = /opt/other/guard\n' >"$INST/g3"
_install "$WORK/git-254" "$INST/g3"
# RED WHEN: the installer overwrites someone else's hook command, adds the event anyway, or does not name what it found.
if [ "$(rc)" != 0 ] && [ "$(cfg "$INST/g3" --get hook.public-content.command)" = /opt/other/guard ] && [ "$(events "$INST/g3")" = 0 ] && grep -q -F -e "/opt/other/guard" "$ERR"; then
  ok "install: refuses to overwrite a different command"
else bad "install: refuses to overwrite a different command" "exit $(rc), command '$(cfg "$INST/g3" --get hook.public-content.command)'"; fi
: >"$INST/g4"
_install "$WORK/git-253" "$INST/g4"
# RED WHEN: git older than 2.54 (which ignores hook.* config) is accepted.
if [ "$(rc)" != 0 ] && [ -z "$(cfg "$INST/g4" --get hook.public-content.command)" ] && grep -q -F -e "2.54" "$ERR"; then
  ok "install: refuses git 2.53 and changes nothing"
else bad "install: refuses git 2.53 and changes nothing" "exit $(rc)$(_hint)"; fi
for gd in git-2100 git-apple; do
  : >"$INST/g-$gd"
  _install "$WORK/$gd" "$INST/g-$gd"
  # RED WHEN: the version check compares strings, or chokes on a vendor suffix.
  if [ "$(rc)" = 0 ] && [ -n "$(cfg "$INST/g-$gd" --get hook.public-content.command)" ]; then ok "install: accepts $("$WORK/$gd/git" --version)"; else bad "install: accepts $("$WORK/$gd/git" --version)" "exit $(rc)$(_hint)"; fi
done
if [ "$HAVE_NOGL" = yes ]; then
  : >"$INST/g5"
  GIT_CONFIG_GLOBAL="$INST/g5" PATH="$WORK/git-254:$NOGL_PATH" _run bash "$INSTALLER"
  # RED WHEN: the installer installs a hook that can only fail (no gitleaks).
  if [ "$(rc)" != 0 ] && [ -z "$(cfg "$INST/g5" --get hook.public-content.command)" ] && grep -q -F -e gitleaks "$ERR"; then ok "install: refuses without gitleaks, saying so"; else bad "install: refuses without gitleaks, saying so" "exit $(rc)$(_hint)"; fi
else skip "install: refuses without gitleaks" "gitleaks is in /usr/bin or /bin here"; fi

# ---- the pinned notes folder (installer side)
: >"$INST/notesdir"
_install "$WORK/git-254" "$INST/notesdir"
# RED WHEN: the installer does not record the notes folder (then PRIVATE_NOTES_DIR alone decides).
if [ "$(rc)" = 0 ] && [ "$(cfg "$INST/notesdir" --get public-content.notesDir)" = "$NOTES" ]; then ok "install: records public-content.notesDir"; else bad "install: records public-content.notesDir" "exit $(rc), value '$(cfg "$INST/notesdir" --get public-content.notesDir)'"; fi
: >"$INST/notesdir-unset"
(unset PRIVATE_NOTES_DIR && _install "$WORK/git-254" "$INST/notesdir-unset")
# RED WHEN: an install without a notes folder records an empty or invented one.
if [ "$(rc)" = 0 ] && [ -z "$(cfg "$INST/notesdir-unset" --get public-content.notesDir)" ]; then ok "install: without PRIVATE_NOTES_DIR records no notes folder"; else bad "install: without PRIVATE_NOTES_DIR records no notes folder" "exit $(rc), value '$(cfg "$INST/notesdir-unset" --get public-content.notesDir)'"; fi

echo "== scanner core: a pinned private notes folder"
NOTESDIR_TEXT_CFG="$WORK/notesdir-text-gitconfig"
cp "$GIT_CONFIG_GLOBAL" "$NOTESDIR_TEXT_CFG"
git config --file "$NOTESDIR_TEXT_CFG" public-content.notesDir "$NOTES"
mkdir -p "$WORK/dummy-notes/scanner"
printf 'zzzz-not-a-term\n' >"$WORK/dummy-notes/scanner/private-terms.txt"
GIT_CONFIG_GLOBAL="$NOTESDIR_TEXT_CFG" PRIVATE_NOTES_DIR="$WORK/dummy-notes" _text "we build $PTERM next"
# RED WHEN: a PRIVATE_NOTES_DIR that differs from the recorded folder is obeyed (terms silently off).
expect_rc "notes: a different PRIVATE_NOTES_DIR is refused" 2 overridden
GIT_CONFIG_GLOBAL="$NOTESDIR_TEXT_CFG" PRIVATE_NOTES_DIR="$WORK/dummy-notes" _text "clean"
expect_rc "notes: ... even for clean text" 2 overridden
GIT_CONFIG_GLOBAL="$NOTESDIR_TEXT_CFG" PRIVATE_NOTES_DIR="$NOTES" _text "we build $PTERM next"
# RED WHEN: the same folder given in the variable is refused (partner of the cases above).
expect_rc "notes: the same folder in the variable is accepted" 1 private-term
GIT_CONFIG_GLOBAL="$NOTESDIR_TEXT_CFG" PRIVATE_NOTES_DIR="$NOTES/" _text "we build $PTERM next"
# RED WHEN: folders are compared as raw strings (a trailing slash is the same folder).
expect_rc "notes: the same folder with a trailing slash is accepted" 1 private-term
(unset PRIVATE_NOTES_DIR && GIT_CONFIG_GLOBAL="$NOTESDIR_TEXT_CFG" _text "we build $PTERM next")
# RED WHEN: the recorded folder is not used when the variable is unset.
expect_rc "notes: the recorded folder is used when the variable is unset" 1 private-term
(unset PRIVATE_NOTES_DIR && _text "we build $PTERM next")
# RED WHEN: with no recorded folder and no variable, terms are invented or the run fails.
expect_rc "notes: no folder recorded and no variable -> public rules only" 0 "private term"
NOTESDIR_MISSING_CFG="$WORK/notesdir-missing-gitconfig"
cp "$GIT_CONFIG_GLOBAL" "$NOTESDIR_MISSING_CFG"
git config --file "$NOTESDIR_MISSING_CFG" public-content.notesDir "$WORK/no-such-notes"
(unset PRIVATE_NOTES_DIR && GIT_CONFIG_GLOBAL="$NOTESDIR_MISSING_CFG" _text "clean")
# RED WHEN: a recorded folder whose list is missing is treated as "no terms" (fail open).
expect_rc "notes: a recorded folder with no list fails closed" 2 "private term"

# End to end with the real git: the config-based hook (needs git >= 2.54).
GV="$("$REAL_GIT" --version | awk '{print $3}')"
GMAJ="${GV%%.*}"
GREST="${GV#*.}"
GMIN="${GREST%%.*}"
if [ "$GMAJ" -gt 2 ] || { [ "$GMAJ" -eq 2 ] && [ "$GMIN" -ge 54 ]; }; then
  E="$INST/e2e-gitconfig"
  cp "$GIT_CONFIG_GLOBAL" "$E"
  GIT_CONFIG_GLOBAL="$E" _run bash "$INSTALLER"
  if [ "$(rc)" = 0 ]; then ok "e2e: installer succeeds with the real git $GV"; else bad "e2e: installer succeeds with the real git $GV" "exit $(rc)$(_hint)"; fi
  vis acme/p-e2e public
  mkpush e2e "$(gh_url acme/p-e2e)"
  D="$P/e2e"
  git -C "$D" config --unset core.hooksPath
  printf '#!/bin/sh\ntouch "%s"\nexit 0\n' "$WORK/own-hook-ran" >"$D/.git/hooks/pre-push"
  chmod +x "$D/.git/hooks/pre-push"
  commit_file "$D" b.txt "see $HOMEP" "leak"
  GIT_CONFIG_GLOBAL="$E" gpush "$D" "$D.git" origin main
  # RED WHEN: the installed config-based hook does not run on a push.
  expect_blocked "e2e: installed hook blocks a dirty push" home-folder-path
  printf '%s\n' "$D.git" >"$WORK/push.bare"
  _refs "$D.git" >"$WORK/refs.before"
  GIT_CONFIG_GLOBAL="$E" _run git -C "$D" -c core.hooksPath=/dev/null push origin main
  # RED WHEN: core.hooksPath can switch the config-based hook off.
  expect_blocked "e2e: core.hooksPath=/dev/null does not bypass it" home-folder-path
  git -C "$D" reset -q --hard HEAD~1
  rm -f "$WORK/own-hook-ran"
  commit_file "$D" c.txt "clean" "clean"
  GIT_CONFIG_GLOBAL="$E" gpush "$D" "$D.git" origin HEAD:refs/heads/clean-work
  # RED WHEN: a clean push is refused, or the repo's own pre-push hook stops running.
  if [ "$(rc)" = 0 ] && [ -e "$WORK/own-hook-ran" ]; then ok "e2e: clean push passes and the repo's own hook still runs"; else bad "e2e: clean push passes and the repo's own hook still runs" "exit $(rc), own hook ran: $([ -e "$WORK/own-hook-ran" ] && echo yes || echo no)$(_hint)"; fi
  # A config hook whose file is missing or not executable makes git refuse the push.
  NXD="$WORK/hook-nx"
  mkdir -p "$NXD"
  printf '#!/bin/sh\nexec "%s" "$@"\n' "$PREPUSH" >"$NXD/pre-push"
  chmod 644 "$NXD/pre-push"
  EX="$INST/e2e-broken-gitconfig"
  cp "$GIT_CONFIG_GLOBAL" "$EX"
  git config --file "$EX" --add hook.public-content.event pre-push
  commit_file "$D" c2.txt "clean again" "clean again"
  git config --file "$EX" hook.public-content.command "$WORK/no-such-hook/pre-push"
  GIT_CONFIG_GLOBAL="$EX" gpush "$D" "$D.git" origin HEAD:refs/heads/hook-missing
  # RED WHEN: git (or the guard's install) lets a push through when the hook file is gone.
  expect_blocked "e2e: a configured hook file that is missing makes the push fail"
  git config --file "$EX" hook.public-content.command "$NXD/pre-push"
  GIT_CONFIG_GLOBAL="$EX" gpush "$D" "$D.git" origin HEAD:refs/heads/hook-not-exec
  # RED WHEN: a hook file that is not executable is skipped and the push goes through.
  expect_blocked "e2e: a configured hook file that is not executable makes the push fail"
  chmod 755 "$NXD/pre-push"
  GIT_CONFIG_GLOBAL="$EX" gpush "$D" "$D.git" origin HEAD:refs/heads/hook-exec
  # RED WHEN: the wrapper itself is wrong (partner: the same file, executable, lets a clean push through).
  expect_pushed "e2e: the same hook file, executable, lets a clean push through" scanned
else
  skip "e2e: config-based hook" "git $GV is older than 2.54"
fi

# ========================================================================= CI step: the scanner's own ref
echo "== CI step: the scanner checkout refuses empty refs"
# Contract: reusable-pr-quality.yml has a step BEFORE the scanner checkout whose run block holds
#   # BEGIN public-content-ref-check
#   check_public_content_ref() { ... }   # $1 = repository, $2 = commit sha
#   # END public-content-ref-check
# and then calls check_public_content_ref with job.workflow_repository and job.workflow_sha
# (through env vars). The function fails (non-zero, naming workflow_repository or
# workflow_sha) when the repository is empty or the sha is not 40 hex characters; empty
# values would make actions/checkout fall back to the PR's own tree.
WF="$ROOT/.github/workflows/reusable-pr-quality.yml"
REFCHK="$WORK/ref-check.sh"
sed -n '/# BEGIN public-content-ref-check/,/# END public-content-ref-check/p' "$WF" >"$REFCHK"
if [ -s "$REFCHK" ] && grep -q '# END public-content-ref-check' "$REFCHK" && grep -q 'check_public_content_ref() {' "$REFCHK"; then
  ok "ref check: the marked function is in the workflow"
  refcheck() { _run bash -c '. "$1" && check_public_content_ref "$2" "$3"' refcheck "$REFCHK" "$1" "$2"; }
  SHA40="$(printf '%s%s%s%s%s' 0123456789 abcdef0123 456789abcd ef01234567 89abcdef)"
  SHA40="${SHA40:0:40}"
  refcheck "" "$SHA40"
  # RED WHEN: an empty repository is accepted.
  if [ "$(rc)" != 0 ] && grep -q workflow_repository "$ERR"; then ok "ref check: empty repository fails"; else bad "ref check: empty repository fails" "exit $(rc)$(_hint)"; fi
  refcheck "acme/.github" ""
  # RED WHEN: an empty sha is accepted.
  if [ "$(rc)" != 0 ] && grep -q workflow_sha "$ERR"; then ok "ref check: empty sha fails"; else bad "ref check: empty sha fails" "exit $(rc)$(_hint)"; fi
  refcheck "acme/.github" "main"
  # RED WHEN: a branch name is accepted in place of the workflow's own commit.
  if [ "$(rc)" != 0 ]; then ok "ref check: a branch name instead of a sha fails"; else bad "ref check: a branch name instead of a sha fails" "accepted"; fi
  refcheck "acme/.github" "$SHA40"
  # RED WHEN: a real repository and sha are refused (partner of the cases above).
  if [ "$(rc)" = 0 ]; then ok "ref check: a repository and a 40-hex sha pass"; else bad "ref check: a repository and a 40-hex sha pass" "exit $(rc)$(_hint)"; fi
  CALL_LINE="$(grep -n 'check_public_content_ref "' "$WF" | grep -v '() {' | head -1 | cut -d: -f1)"
  CO_LINE="$(grep -n 'path: .public-content-scanner' "$WF" | head -1 | cut -d: -f1)"
  # RED WHEN: the check is defined but never called, or called after the checkout.
  if [ -n "$CALL_LINE" ] && [ -n "$CO_LINE" ] && [ "$CALL_LINE" -lt "$CO_LINE" ]; then ok "ref check: called before the scanner checkout"; else bad "ref check: called before the scanner checkout" "call line '${CALL_LINE}', checkout line '${CO_LINE}'"; fi
else
  bad "ref check: the marked function is in the workflow" "no BEGIN/END public-content-ref-check block defining check_public_content_ref"
fi

echo
echo "${PASS} passed, ${FAIL} failed, ${SKIPPED} skipped"
[ "$FAIL" -eq 0 ]
