#!/usr/bin/env bash
# test-public-content-added-lines.sh - the scanner's rule for what content is NEW, in CI mode and
# through real pushes with the hook. test-public-content-guard.sh holds the rest of the guard.
#
# The rule: there is NO exemption for text that is already public; every match in new content
# blocks. New commits are those the destination lacks (`git rev-list` against its branch and tag
# tips; CI: the --base sha, refs/remotes/origin/$GITHUB_BASE_REF when that variable is set, and
# tags, each only when it does not contain --head; other origin branches do not count). Every
# file a new commit ADDS or CHANGES is checked whole, content and path name: an edit checks the
# file's old matches too, a rename or a copy is an add at the new path, a restore is an add. For
# a merge commit only files that differ from EVERY parent count as changed, so a merge that takes
# a file unchanged from one parent checks nothing of it. Commit messages and ref names are
# checked too. An unchanged path's name is not re-checked.
#
# Uses the shared harness, so it runs against throwaway repositories with the real gitleaks.
# All leaks and keys are assembled at run time.

# shellcheck source=scripts/lib-public-content-test.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-public-content-test.sh"

echo "test-public-content-added-lines.sh"

# Key material, assembled at run time: three distinct body lines, and three others.
ALN="$(printf '%s%s%s' A1b2C3d4 E5f6G7h8 I9j0K1l2)"
KB="-----BEGIN ""RSA PRIVATE KEY-----"
KE="-----END ""RSA PRIVATE KEY-----"
K1="${ALN}Aa${ALN}"
K2="${ALN}Bb${ALN}"
K3="${ALN}Cc${ALN}"
J1="${ALN}Dd${ALN}"
J2="${ALN}Ee${ALN}"
J3="${ALN}Ff${ALN}"
KEYTEXT="$KB${NL}$K1${NL}$K2${NL}$K3${NL}$KE"
MAIL3="$(printf '%s@%s' sam.roe corp-mail.io)"

# ========================================================================= CI mode
echo "== CI mode"
R="$WORK/added"
git init -q "$R"
commit_all() { # MESSAGE
  if ! { git -C "$R" add -A && git -C "$R" commit -q -m "$1"; }; then die "commit $1"; fi
}
printf 'line one\nsee %s\n' "$HOMEP" >"$R/old.txt"
commit_all "base, with an old match"
BASE="$(git -C "$R" rev-parse HEAD)"
_ci() { # [BASE]: scan BASE..HEAD of $R (default base: $BASE)
  (unset PRIVATE_NOTES_DIR && cd "$R" && PR_TITLE="t" PR_BODY="b" _run python3 "$SCAN" ci --base "${1:-$BASE}" --head HEAD)
}
reset_to() { git -C "$R" checkout -q -B work "${1:-$BASE}" || die "reset"; }
reset_base() { reset_to "$BASE"; }
reset_base

printf 'line three\n' >>"$R/old.txt"
commit_all "edit the file"
cp "$R/old.txt" "$R/copy.txt"
commit_all "copy the edited file"
_ci
# RED WHEN: a changed file is checked by its added lines, or its old match is excused because
# the base already holds it (the edit and the copy both carry it).
expect_rc "added: editing a file that holds an old match, then copying it, fails" 1 home-folder-path old.txt

reset_base
git -C "$R" mv old.txt moved.txt
commit_all "rename the file"
_ci
# RED WHEN: a rename is not checked as an add at the new path (content and name).
expect_rc "added: renaming a file that holds an old match fails" 1 home-folder-path moved.txt

reset_base
printf 'mail %s\n' "$MAIL" >"$R/new.txt"
commit_all "add a dirty file"
git -C "$R" mv new.txt renamed.txt
commit_all "rename it"
_ci
# RED WHEN: a dirty file added in the range escapes because a later commit renamed it.
expect_rc "added: a dirty file added then renamed in the range fails" 1 personal-email

reset_base
git -C "$R" rm -q old.txt
commit_all "delete the file"
git -C "$R" checkout -q "$BASE" -- old.txt
commit_all "restore it"
_ci
# RED WHEN: a file a commit adds is skipped because the base already holds that file version.
expect_rc "added: restoring a deleted file that holds a match fails" 1 home-folder-path old.txt

reset_base
printf 'see %s\n' "$HOMEP" >"$R/again.txt"
commit_all "a new path holding the base's match"
_ci
# Changed: this once asserted that repeating published text passes; there is no such exemption.
# RED WHEN: a match in a new file is excused because a base file holds the same text.
expect_rc "added: a new path holding the same match text as a base file fails" 1 home-folder-path again.txt
reset_base
printf 'see %s\n' "$HOMEQ" >"$R/again.txt"
commit_all "a new path holding a different home path"
_ci
# RED WHEN: new files stop being scanned (partner of the case above).
expect_rc "added: a new path holding a different home path fails" 1 home-folder-path again.txt

# ---- a substring of a published match is not the published match
SUBP="$(printf 'see %sers/janet/x and mail %s@%s' "$U" jane.doe corp-mail.io)"
SUBN="$(printf 'see %sers/jane and mail %s@%s' "$U" doe corp-mail.io)"
RS="$WORK/substr"
git init -q "$RS"
commit_file "$RS" a.txt "$SUBP" "publish a home path and an address"
SUBBASE="$(git -C "$RS" rev-parse HEAD)"
commit_file "$RS" b.txt "$SUBN" "a shorter home path and address"
_ci_sub() { (unset PRIVATE_NOTES_DIR && cd "$RS" && PR_TITLE="t" PR_BODY="b" _run python3 "$SCAN" ci --base "$SUBBASE" --head HEAD); }
_ci_sub
# RED WHEN: a new match is excused because its text is a substring of a published match
# (".../jane" inside ".../janet/x", "doe@..." inside "jane.doe@...").
expect_rc "added: a new match that is only a substring of a published match fails" 1 home-folder-path personal-email b.txt
git -C "$RS" reset -q --hard "$SUBBASE"
cp "$RS/a.txt" "$RS/b.txt"
if ! { git -C "$RS" add b.txt && git -C "$RS" commit -q -m "an identical copy at a new path"; }; then die "copy"; fi
_ci_sub
# RED WHEN: a copy is skipped because its content (the same blob) is already published.
expect_rc "added: an identical copy of a published file at a new path fails" 1 home-folder-path personal-email b.txt

reset_base
printf 'line one\nwe now see %s here\n' "$HOMEP" >"$R/old.txt"
commit_all "reword the line that holds the match"
_ci
# RED WHEN: a changed line is excused because its match text is unchanged and already public.
expect_rc "added: rewording the line around an old match fails" 1 home-folder-path old.txt

reset_base
printf 'side\nsee %s\n' "$HOMEQ" >"$R/side.txt"
commit_all "add a line"
printf 'side\n' >"$R/side.txt"
commit_all "drop it again"
_ci
# RED WHEN: only the head version is scanned (the earlier commit still publishes the line).
expect_rc "added: a match added in one commit and removed in a later one fails" 1 home-folder-path side.txt

reset_base
git -C "$R" commit -q --allow-empty -m "notes from $HOMEQ"
_ci
# RED WHEN: commit messages stop being scanned.
expect_rc "added: a new home path in a commit message fails" 1 home-folder-path "$(git -C "$R" rev-parse --short=7 HEAD)"
reset_base
git -C "$R" commit -q --allow-empty -m "fix the note that says see $HOMEP"
_ci
# RED WHEN: a message is excused because a base file holds the same text.
expect_rc "added: a commit message repeating a base file's match fails" 1 home-folder-path "$(git -C "$R" rev-parse --short=7 HEAD)"

reset_base
printf 'see %s\n' "$HOMEQ" >"$R/hist.txt"
commit_all "a match, published once"
git -C "$R" rm -q hist.txt
commit_all "removed again"
OLDHIST="$(git -C "$R" rev-parse HEAD)"
printf 'see %s\n' "$HOMEQ" >"$R/hist.txt"
commit_all "re-add the same file"
_ci "$OLDHIST"
# RED WHEN: a file a commit adds is skipped because the base's history already holds that version.
expect_rc "added: re-adding a file that only old history holds fails" 1 home-folder-path hist.txt

# ---- the base branch: newer base-branch content merged in UNCHANGED checks nothing of it
reset_base
printf 'see %s\n' "$HOMEQ" >"$R/other.txt"
commit_all "work that reached the base branch"
TIPSHA="$(git -C "$R" rev-parse HEAD)"
reset_base
printf 'clean\n' >"$R/mine.txt"
commit_all "the PR's own work"
git -C "$R" merge -q --no-edit "$TIPSHA" >/dev/null 2>&1 || die "merge base branch"
git -C "$R" update-ref refs/remotes/origin/main "$TIPSHA"
GITHUB_BASE_REF=main _ci
# RED WHEN: the base branch's origin ref (GITHUB_BASE_REF) is not treated as on the destination,
# or a merge rechecks a file it takes unchanged from one parent.
expect_rc "added: a PR merging newer base-branch content unchanged passes (stale base)" 0 @scanned
git -C "$R" update-ref -d refs/remotes/origin/main
git -C "$R" update-ref refs/remotes/origin/other "$TIPSHA"
GITHUB_BASE_REF=main _ci
# RED WHEN: any origin branch counts as on the destination, not just the base branch (partner).
expect_rc "added: ... but fails when only another origin branch holds that content" 1 home-folder-path other.txt
git -C "$R" update-ref -d refs/remotes/origin/other
_ci
# RED WHEN: the case above fails for another reason than the branch (partner: no origin ref at all).
expect_rc "added: ... and fails when no origin ref holds it" 1 home-folder-path other.txt

# ---- merges: only files that differ from every parent are changed
git -C "$R" checkout -q -B mmain "$BASE"
printf 'line one\nsee %s\n' "$HOMEP" >"$R/A.txt"
commit_all "main adds A with a match"
MBASE="$(git -C "$R" rev-parse HEAD)"
git -C "$R" checkout -q -B mfeat "$BASE"
printf 'other\n' >"$R/other-work.txt"
commit_all "feature work"
git -C "$R" merge -q --no-edit "$MBASE" >/dev/null 2>&1 || die "merge"
_ci "$MBASE"
# RED WHEN: a merge rechecks a file it takes unchanged from one parent (every merge of a branch
# holding an old match would fail).
expect_rc "merge: taking a file with a match unchanged from one parent passes" 0 @scanned
git -C "$R" checkout -q -B mfeat2 "$BASE"
printf 'other\n' >"$R/other-work.txt"
commit_all "feature work"
git -C "$R" merge -q --no-commit "$MBASE" >/dev/null 2>&1
printf 'clean line\n' >>"$R/A.txt"
commit_all "merge main, with an edit"
_ci "$MBASE"
# RED WHEN: a merge resolution (a file that differs from every parent) is checked by its added
# lines only, or not at all; its old match blocks like any changed file's.
expect_rc "merge: a merge that edits such a file (a resolution) fails" 1 home-folder-path A.txt

# ---- private keys
git -C "$R" checkout -q -B keybase "$BASE"
printf '%s\n' "$KEYTEXT" >"$R/id.pem"
commit_all "a key, already public"
KEYBASE="$(git -C "$R" rev-parse HEAD)"
reset_to "$KEYBASE"
printf '%s\n%s\n%s\n%s\n%s\n' "$KB" "$J1" "$J2" "$J3" "$KE" >"$R/id.pem"
commit_all "replace the key body"
_ci "$KEYBASE"
# RED WHEN: a changed file holding a key is not checked whole.
expect_rc "key: replacing only the body between published BEGIN/END lines fails" 1 private-key id.pem
reset_to "$KEYBASE"
printf '%s\n%s\n%s\n%s\n%s\n' "$KB" "$K3" "$K1" "$K2" "$KE" >"$R/id.pem"
commit_all "reorder the key body"
_ci "$KEYBASE"
# RED WHEN: a file whose lines were only reordered is treated as unchanged.
expect_rc "key: reordering the body lines of a published key fails" 1 private-key id.pem
reset_to "$KEYBASE"
printf '%s\n' "$KEYTEXT" >"$R/copy.pem"
commit_all "the same key at a new path"
_ci "$KEYBASE"
# RED WHEN: a copy of a published key at a new path is skipped because its blob is not new.
expect_rc "key: the identical published key at a new path fails" 1 private-key copy.pem
reset_base
printf '%s\n%s\n' "$KB" "$K1" >"$R/split.pem"
commit_all "half a key"
printf '%s\n%s\n%s\n%s\n%s\n' "$KB" "$K1" "$K2" "$K3" "$KE" >"$R/split.pem"
commit_all "the rest of the key"
_ci
# RED WHEN: a changed file is checked by its added lines (the key exists only once both commits
# of the range are applied).
expect_rc "key: a key split across two commits of the range fails" 1 private-key split.pem

# ---- path names
git -C "$R" checkout -q -B namebase "$BASE"
mkdir -p "$R/people/$MAIL"
printf 'card\n' >"$R/people/$MAIL/card.txt"
commit_all "a folder named by an address, already public"
NAMEBASE="$(git -C "$R" rev-parse HEAD)"
reset_to "$NAMEBASE"
printf 'clean\n' >"$R/elsewhere.txt"
commit_all "work elsewhere"
_ci "$NAMEBASE"
# RED WHEN: the names of paths a commit leaves unchanged are checked again.
expect_rc "names: a commit leaving a path with a dirty name unchanged passes" 0 @scanned
reset_to "$NAMEBASE"
printf 'more\n' >>"$R/people/$MAIL/card.txt"
commit_all "edit inside the folder"
_ci "$NAMEBASE"
# RED WHEN: the name of a path a commit changes is not checked (it includes its folders).
expect_rc "names: an edit inside a folder whose name holds an address fails" 1 personal-email
reset_to "$NAMEBASE"
printf 'second\n' >"$R/people/$MAIL/second.txt"
commit_all "a new file in that folder"
_ci "$NAMEBASE"
# RED WHEN: a new path's name is excused because a published path name holds the same text.
expect_rc "names: a new file in a folder whose name holds an address fails" 1 personal-email
reset_to "$NAMEBASE"
printf 'clean\n' >"$R/notes-for-$MAIL3.txt"
commit_all "a clean file under a name holding an address"
_ci "$NAMEBASE"
# RED WHEN: a new path name is not checked.
expect_rc "names: a clean file under a name holding an address fails" 1 personal-email

# ---- private terms: two terms side by side
NAB="$WORK/notes-ab"
mkdir -p "$NAB/scanner"
printf '# two terms\n%s\n%s\n' "$TERM_A" "$TERM_B" >"$NAB/scanner/private-terms.txt"
RT="$WORK/terms"
git init -q "$RT"
commit_file "$RT" a.txt "x $TERM_A public" "one term"
TBASE="$(git -C "$RT" rev-parse HEAD)"
_ci_terms() { (cd "$RT" && PRIVATE_NOTES_DIR="$NAB" PR_TITLE="t" PR_BODY="b" _run python3 "$SCAN" ci --base "$TBASE" --head HEAD); }
commit_file "$RT" b.txt "y $TERM_A $TERM_B" "both terms on one line"
_ci_terms
# RED WHEN: private terms stop being checked in CI.
expect_rc "terms: two terms side by side fail" 1 private-term b.txt
git -C "$RT" reset -q --hard "$TBASE"
commit_file "$RT" b.txt "y $TERM_A again" "the same term again at a new path"
_ci_terms
# RED WHEN: a term is excused at a new path because the base already holds it.
expect_rc "terms: a term the base already holds fails at a new path" 1 private-term b.txt

# ---- revisions
reset_base
(unset PRIVATE_NOTES_DIR && cd "$R" && PR_TITLE="t" PR_BODY="b" _run python3 "$SCAN" ci --base "$BASE" --head=-x)
# RED WHEN: an option-like revision reaches git as an option.
expect_rc "ci: a revision that starts with '-' is refused" 2 "not a commit"
(unset PRIVATE_NOTES_DIR && cd "$R" && PR_TITLE="t" PR_BODY="b" _run python3 "$SCAN" ci --base "$BASE" --head no-such-branch)
# RED WHEN: an unknown revision is treated as an empty range.
expect_rc "ci: an unknown revision is refused" 2 "not a commit"

# ========================================================================= pre-push hook
echo "== pre-push hook"
vis acme/p-pt public
mkpush pt "$(gh_url acme/p-pt)"
D="$P/pt"
PTINIT="$(git -C "$D" rev-parse HEAD)"
commit_file "$D" old.txt "line one${NL}see $HOMEP" "an old match, already public"
printf '%s\n' "$KEYTEXT" >"$D/id.pem"
git -C "$D" add id.pem && git -C "$D" commit -q -m "a key, already public"
nohook_push "$D" origin main
back() { if ! { git -C "$D" checkout -q main && git -C "$D" reset -q --hard origin/main; }; then die "back"; fi; }

gpush "$D" "$D.git" origin "$(git -C "$D" rev-parse origin/main):refs/heads${U}ers/jane/topic"
# RED WHEN: a ref name is excused because a destination file holds the same home path.
expect_blocked "push: a new ref named with a home path a destination file holds is blocked" home-folder-path ref
gpush "$D" "$D.git" origin "$(git -C "$D" rev-parse origin/main):refs/heads/topic/clean"
# RED WHEN: a clean ref for a published commit is refused, or its old files rechecked (partner).
expect_pushed "push: a new clean ref for a published commit passes" scanned

commit_file "$D" again.txt "see $HOMEP" "a new path holding the destination's match"
gpush "$D" "$D.git" origin main
# RED WHEN: a match in a new file is excused because a destination file holds the same text.
expect_blocked "push: a new path holding the same match text as a destination file is blocked" home-folder-path again.txt
back
printf '%s\n%s\n%s\n%s\n%s\n' "$KB" "$J1" "$J2" "$J3" "$KE" >"$D/id.pem"
git -C "$D" commit -q -am "replace the key body"
gpush "$D" "$D.git" origin main
# RED WHEN: a changed file holding a key is not checked whole on a push.
expect_blocked "push: replacing only the body of a published key is blocked" private-key id.pem
back
commit_file "$D" split.pem "$KB${NL}$J1" "half of a new key"
commit_file "$D" split.pem "$KB${NL}$J1${NL}$J2${NL}$J3${NL}$KE" "the rest of the key"
gpush "$D" "$D.git" origin main
# RED WHEN: a push checks a changed file by its added lines (the key is whole only at the end).
expect_blocked "push: a key split across two pushed commits is blocked" private-key split.pem
back
commit_file "$D" side.txt "side${NL}see $HOMEQ" "add a line"
commit_file "$D" side.txt "side" "drop it again"
gpush "$D" "$D.git" origin main
# RED WHEN: a push scans only its final tree (the earlier commit still publishes the line).
expect_blocked "push: a match added then removed in the pushed range is blocked" home-folder-path side.txt
back
git -C "$D" commit -q --allow-empty -m "notes from $HOMEQ"
gpush "$D" "$D.git" origin main
# RED WHEN: commit messages stop being scanned on a push.
expect_blocked "push: a new home path in a commit message is blocked" home-folder-path "$(sha7 "$D" HEAD)"
back

# Merges through a push: the destination's main holds old.txt with a match.
git -C "$D" checkout -q -b mplain "$PTINIT"
commit_file "$D" other-work.txt "other" "feature work"
git -C "$D" merge -q --no-edit main >/dev/null 2>&1 || die "merge"
gpush "$D" "$D.git" origin HEAD:refs/heads/mplain
# RED WHEN: a pushed merge rechecks a file it takes unchanged from one parent.
expect_pushed "push: a merge taking a file with a match unchanged from one parent passes" scanned
back
git -C "$D" checkout -q -b medit "$PTINIT"
commit_file "$D" other-work.txt "other" "feature work"
git -C "$D" merge -q --no-commit main >/dev/null 2>&1
printf 'clean line\n' >>"$D/old.txt"
git -C "$D" add old.txt && git -C "$D" commit -q -m "merge main, with an edit"
gpush "$D" "$D.git" origin HEAD:refs/heads/medit
# RED WHEN: a merge resolution is not checked whole (its old match blocks like any changed file's).
expect_blocked "push: a merge that edits a file holding a match is blocked" home-folder-path old.txt
back

# A branch already on the destination, merged in unchanged.
vis acme/p-ptb public
mkpush ptb "$(gh_url acme/p-ptb)"
D="$P/ptb"
git -C "$D" checkout -q -b other
commit_file "$D" other.txt "see $HOMEQ" "a match on another branch"
git -C "$D" checkout -q main
commit_file "$D" mine.txt "clean" "main's own work"
git -C "$D" merge -q --no-edit other >/dev/null 2>&1 || die "merge other"
gpush "$D" "$D.git" origin main
# RED WHEN: commits on no destination tip are skipped (partner: the case below differs only in
# the other branch being on the destination).
expect_blocked "push: merging a branch the destination lacks is blocked" home-folder-path other.txt
nohook_push "$D" origin other
gpush "$D" "$D.git" origin main
# RED WHEN: another destination branch's commits are scanned again when merged in unchanged.
expect_pushed "push: merging a branch the destination already has, unchanged, passes" scanned

# The substring case through a push.
vis acme/p-sub public
mkpush sub "$(gh_url acme/p-sub)"
D="$P/sub"
commit_file "$D" a.txt "$SUBP" "publish a home path and an address"
nohook_push "$D" origin main
commit_file "$D" b.txt "$SUBN" "a shorter home path and address"
gpush "$D" "$D.git" origin main
# RED WHEN: a push excuses a new match whose text is only a substring of a published one.
expect_blocked "push: a new match that is only a substring of a published match is blocked" home-folder-path personal-email b.txt

echo
echo "${PASS} passed, ${FAIL} failed, ${SKIPPED} skipped"
[ "$FAIL" -eq 0 ]
