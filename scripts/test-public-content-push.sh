#!/usr/bin/env bash
# test-public-content-push.sh - `scan.py push`, the mode the public-content workflow runs on a
# `push` event: the push already happened (detection, not prevention), so it scans what the
# push introduced, in a full-history checkout of the repository.
#
# CLI under test (the values come from the event file: `before`, `after`, `ref`, and the tip of
# `repository.default_branch` in the checkout):
#
#   scan.py push --repo DIR --before SHA --after SHA --ref REFNAME [--default-tip SHA]
#
# --default-tip is required only when --before is all zeros (a new ref).
#
# The rule (history that existed BEFORE the push, never "every other current ref": two refs
# pushed at once to one new commit would hide each other):
# - after all zeros: a delete; the ref must be gone from the checkout; pass, "ref deleted:
#   nothing to scan".
# - before non-zero: scan the commits in `after ^before`.
# - before all zeros: scan the commits in `after ^default-tip`; all of `after`'s history when
#   `after` IS the default tip.
# - always: the ref name; for a tag, the tag object (message, tagger) even when no commit is new.
# - refuse (exit 2): a shallow repository, or a before/after/default-tip object that is missing.
#
# The checkout is made the way the workflow makes it: an empty repository that fetches
# '+refs/heads/*:refs/remotes/origin/*' '+refs/tags/*:refs/tags/*' from the remote after the push.
#
# Runs on bash 3.2 and 5, macOS and Linux, against throwaway repositories under mktemp (a bare
# "remote" and a work clone per case), with the REAL gitleaks from PATH. Leaks are ASSEMBLED AT
# RUN TIME. Exit 0 clean, 1 findings, 2 could not check; output never repeats the match.

# shellcheck source=scripts/lib-public-content-test.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-public-content-test.sh"

echo "test-public-content-push.sh"

R="$WORK/repos"
# CI has no private-term list: run every case as CI does.
unset PRIVATE_NOTES_DIR

# newrepo NAME: bare $R/NAME.git and work clone $R/NAME with one clean commit on main, pushed.
newrepo() {
  local d="$R/$1" b="$R/$1.git"
  if ! { git init -q --bare "$b" && git init -q "$d" && git -C "$d" remote add origin "$b" &&
    echo start >"$d/a.txt" && git -C "$d" add a.txt && git -C "$d" commit -q -m init &&
    git -C "$d" push -q origin main 2>/dev/null; }; then
    die "newrepo $1"
  fi
}
# co NAME: (re)make the workflow-style checkout $R/NAME.co of the bare remote.
co() {
  local c="$R/$1.co"
  rm -rf "$c"
  if ! { git init -q "$c" && git -C "$c" remote add origin "$R/$1.git" &&
    git -C "$c" fetch -q origin '+refs/heads/*:refs/remotes/origin/*' '+refs/tags/*:refs/tags/*'; }; then
    die "checkout $1"
  fi
}
tip() { git --git-dir="$R/$1.git" rev-parse --verify --quiet "$2" || echo "$ZERO"; } # NAME REF
cf() { commit_file "$R/$1" "$2" "$3" "$4"; }                                          # NAME PATH CONTENT MSG
push() { git -C "$R/$1" push -q "${@:2}" 2>/dev/null || die "push $*"; }               # NAME ARGS...
# scan NAME BEFORE AFTER REF [DEFAULT_TIP]: run push mode in NAME's checkout.
scan() {
  local c="$R/$1.co"
  if [ $# -ge 5 ]; then
    (_run python3 "$SCAN" push --repo "$c" --before "$2" --after "$3" --ref "$4" --default-tip "$5" </dev/null)
  else
    (_run python3 "$SCAN" push --repo "$c" --before "$2" --after "$3" --ref "$4" </dev/null)
  fi
}
# expect_red NAME [NEEDLE...]: exit 1, gitleaks ran, needles on stderr, no leak.
expect_red() { local n="$1"; shift; expect_rc "$n" 1 @scanned "$@"; }
# expect_clean NAME: exit 0 and gitleaks really ran.
expect_clean() {
  if [ "$(rc)" != 0 ]; then bad "$1" "expected exit 0, got $(rc)$(_hint)"; return; fi
  _evidence "$1" scanned || return
  ok "$1"
}
# expect_said NAME WANT NEEDLE...: exit WANT, every needle on stdout or stderr, no leak.
expect_said() {
  local name="$1" want="$2" n
  shift 2
  if [ "$(rc)" != "$want" ]; then bad "$name" "expected exit $want, got $(rc)$(_hint)"; return; fi
  for n in "$@"; do
    cat "$OUT" "$ERR" | grep -q -F -e "$n" || { bad "$name" "the output lacks '$n'$(_hint)"; return; }
  done
  if _leaks "$OUT" "$ERR"; then bad "$name" "the output repeats the matched text"; return; fi
  ok "$name"
}

echo "== an existing ref, fast-forward"
newrepo ff
B="$(tip ff refs/heads/main)"
cf ff notes.md "see $HOMEP" "add notes"
cf ff notes.md "nothing here" "remove the path again"
push ff origin main
co ff
scan ff "$B" "$(tip ff refs/heads/main)" refs/heads/main
# Red when: only the final tree or only the tip commit is scanned (the intermediate commit published the match).
expect_red "push: a match added then removed inside a fast-forward is red" home-folder-path
newrepo ffok
B="$(tip ffok refs/heads/main)"
cf ffok b.txt "fine" "a clean change"
push ffok origin main
co ffok
scan ffok "$B" "$(tip ffok refs/heads/main)" refs/heads/main
# Red when: a clean fast-forward is blocked, or passes without gitleaks running.
expect_clean "push: a clean fast-forward passes (scanned)"
newrepo ffmsg
B="$(tip ffmsg refs/heads/main)"
cf ffmsg b.txt "fine" "notes are in $HOMEP"
push ffmsg origin main
co ffmsg
scan ffmsg "$B" "$(tip ffmsg refs/heads/main)" refs/heads/main
# Red when: commit messages are not scanned in push mode.
expect_red "push: a match in a new commit message is red" home-folder-path

echo "== a force push"
newrepo force
cf force b.txt "first" "first version"
push force origin main
B="$(tip force refs/heads/main)"
git -C "$R/force" reset -q --hard HEAD~1
cf force notes.md "see $HOMEP" "second version"
push force --force origin main
co force
# The old tip is unreachable after a force push, so the checkout's ref fetch does not bring it;
# the workflow must fetch `before` by sha (GitHub serves it; a local bare needs allowAnySHA1InWant).
git --git-dir="$R/force.git" config uploadpack.allowAnySHA1InWant true
git -C "$R/force.co" fetch -q origin "$B" || die "fetch before"
scan force "$B" "$(tip force refs/heads/main)" refs/heads/main
# Red when: a force push (before not an ancestor of after) scans nothing or only `before..after` by ancestry.
expect_red "push: a force push's new commits are scanned" home-folder-path

echo "== a new branch"
newrepo nb
cf nb x.txt "fine" "main moves on"
push nb origin main
DEF="$(tip nb refs/heads/main)"
git -C "$R/nb" checkout -q -b feature
cf nb notes.md "see $HOMEP" "a leaking commit"
cf nb more.txt "fine" "a clean commit on top"
push nb origin feature
co nb
scan nb "$ZERO" "$(tip nb refs/heads/feature)" refs/heads/feature "$DEF"
# Red when: a new ref (before all zeros) is not scanned against the default tip.
expect_red "push: a new branch's new commits are scanned" home-folder-path
newrepo nbok
DEF="$(tip nbok refs/heads/main)"
git -C "$R/nbok" checkout -q -b feature
cf nbok y.txt "fine" "a clean commit"
push nbok origin feature
co nbok
scan nbok "$ZERO" "$(tip nbok refs/heads/feature)" refs/heads/feature "$DEF"
# Red when: a clean new branch is blocked, or passes without gitleaks running.
expect_clean "push: a clean new branch passes (scanned)"
scan nbok "$ZERO" "$DEF" refs/heads/"$TRANSCRIPT" "$DEF"
# Red when: the ref name is not scanned when the ref points at a commit the remote already had.
expect_red "push: a new branch at an existing commit with a leaking name is red" agent-transcript
scan nbok "$ZERO" "$(tip nbok refs/heads/feature)" refs/heads/feature
# Red when: a new ref without --default-tip is scanned against nothing or everything silently.
expect_said "push: a new ref without --default-tip exits 2" 2 "could not check this"

echo "== two new branches at the same new leaking commit"
newrepo two
DEF="$(tip two refs/heads/main)"
git -C "$R/two" checkout -q -b one
cf two notes.md "see $HOMEP" "a leaking commit"
git -C "$R/two" branch other
push two origin one other
co two
LEAK="$(tip two refs/heads/one)"
scan two "$ZERO" "$LEAK" refs/heads/one "$DEF"
# Red when: the scan subtracts every other current ref (the sibling branch hides the commit).
expect_red "push: the first of two new branches at one new commit is red" home-folder-path
scan two "$ZERO" "$LEAK" refs/heads/other "$DEF"
# Red when: the scan subtracts every other current ref (the sibling branch hides the commit).
expect_red "push: the second of two new branches at one new commit is red" home-folder-path

echo "== the first push of a repository (after is the default tip)"
R1="$R/first"
{ git init -q --bare "$R1.git" && git init -q "$R1" && git -C "$R1" remote add origin "$R1.git"; } || die "first"
cf first notes.md "see $HOMEP" "an early leaking commit"
cf first notes.md "nothing here" "removed later"
push first origin main
co first
T="$(tip first refs/heads/main)"
scan first "$ZERO" "$T" refs/heads/main "$T"
# Red when: `after ^default-tip` is used even when after IS the default tip (scans nothing).
expect_red "push: the first push of a repository scans all its history" home-folder-path

echo "== tags"
newrepo tags
OLD="$(tip tags refs/heads/main)"
git -C "$R/tags" tag "$TRANSCRIPT" "$OLD"
push tags origin "refs/tags/$TRANSCRIPT"
co tags
scan tags "$ZERO" "$OLD" "refs/tags/$TRANSCRIPT" "$OLD"
# Red when: a lightweight tag on an existing commit is not scanned because no commit is new.
expect_red "push: a new lightweight tag with a leaking name is red" agent-transcript
git -C "$R/tags" tag -a v1 -m "release notes are in $HOMEP" "$OLD"
push tags origin refs/tags/v1
co tags
scan tags "$ZERO" "$(tip tags refs/tags/v1)" refs/tags/v1 "$OLD"
# Red when: an annotated tag's own object (its message) is not scanned when it points at an old commit.
expect_red "push: a new annotated tag with a leaking message is red" home-folder-path
git -C "$R/tags" tag -a v2 -m "a clean release" "$OLD"
push tags origin refs/tags/v2
co tags
scan tags "$ZERO" "$(tip tags refs/tags/v2)" refs/tags/v2 "$OLD"
# Red when: a clean annotated tag is blocked, or passes without gitleaks running.
expect_clean "push: a clean annotated tag passes (scanned)"

echo "== a merge commit"
newrepo merge
B="$(tip merge refs/heads/main)"
git -C "$R/merge" checkout -q -b side
cf merge s.txt "fine" "a clean side commit"
push merge origin side
git -C "$R/merge" checkout -q main
cf merge m.txt "fine" "a clean main commit"
push merge origin main
B="$(tip merge refs/heads/main)"
git -C "$R/merge" merge -q --no-ff side -m "Merge side; notes in $HOMEP" || die "merge"
push merge origin main
co merge
scan merge "$B" "$(tip merge refs/heads/main)" refs/heads/main
# Red when: a merge commit's own message is not scanned (its parents are both already on the remote).
expect_red "push: a match only in a merge commit's message is red" home-folder-path

echo "== deletes"
newrepo del
git -C "$R/del" checkout -q -b gone
cf del g.txt "fine" "a branch to delete"
push del origin gone
GONE="$(tip del refs/heads/gone)"
co del
STALE="$R/del.stale.co"
rm -rf "$STALE" && cp -R "$R/del.co" "$STALE"
push del origin --delete gone
co del
git -C "$R/del.co" cat-file -e "$GONE" 2>/dev/null && die "the deleted branch's commit is still in the checkout"
scan del "$GONE" "$ZERO" refs/heads/gone
# Red when: a delete is blocked or scanned instead of passing with its own notice, or is refused
# because `before` (the deleted branch's old, now unreachable tip) is not in the checkout.
expect_said "push: a branch delete passes" 0 "ref deleted: nothing to scan"
_evidence "push: a delete runs no gitleaks" noscan && ok "push: a delete runs no gitleaks"
(_run python3 "$SCAN" push --repo "$STALE" --before "$GONE" --after "$ZERO" --ref refs/heads/gone </dev/null)
# Red when: a "delete" is believed while the ref still exists in the checkout (an unvalidated delete).
expect_said "push: a delete whose ref still exists exits 2" 2 "could not check this"

echo "== refusals"
newrepo shallow
B="$(tip shallow refs/heads/main)"
cf shallow b.txt "fine" "one"
cf shallow c.txt "fine" "two"
push shallow origin main
A="$(tip shallow refs/heads/main)"
rm -rf "$R/shallow.co"
git clone -q --depth 1 "file://$R/shallow.git" "$R/shallow.co" 2>/dev/null || die "shallow clone"
[ "$(git -C "$R/shallow.co" rev-parse --is-shallow-repository)" = true ] || die "not shallow"
scan shallow "$B" "$A" refs/heads/main
# Red when: a shallow checkout is scanned (it lacks history, so new commits cannot be told apart).
expect_said "push: a shallow repository is refused" 2 "could not check this" "shallow"
co ffok
scan ffok "$(tip ffok refs/heads/main~1)" 1234567890abcdef1234567890abcdef12345678 refs/heads/main
# Red when: an `after` object missing from the checkout passes (nothing to scan is not clean).
expect_said "push: a missing after object is refused" 2 "could not check this"
scan ffok 1234567890abcdef1234567890abcdef12345678 "$(tip ffok refs/heads/main)" refs/heads/main
# Red when: a missing `before` object makes the scan fall back to all history or to nothing.
expect_said "push: a missing before object is refused" 2 "could not check this"
scan ffok "$ZERO" "$(tip ffok refs/heads/main)" refs/heads/x 1234567890abcdef1234567890abcdef12345678
# Red when: a missing default tip is ignored.
expect_said "push: a missing default tip is refused" 2 "could not check this"
scan ffok "$(tip ffok refs/heads/main~1)" "not-a-sha" refs/heads/main
# Red when: a malformed `after` value is passed to git as a revision.
expect_said "push: a malformed after value is refused" 2 "could not check this"
scan ffok "$(tip ffok refs/heads/main~1)" "$(tip ffok refs/heads/main)" ""
# Red when: an empty ref name skips the ref-name scan silently.
expect_said "push: an empty ref is refused" 2 "could not check this"

echo "== a place never prints a ref name or file path that holds a match"
newrepo places
DEF="$(tip places refs/heads/main)"
co places
scan places "$ZERO" "$DEF" "refs/heads/x${U}ers/jane/y" "$DEF"
# Red when: the ref name is not scanned, or a finding prints it.
expect_red "push: a home path in a ref name is red and not printed" home-folder-path "the ref name"
B="$(tip places refs/heads/main)"
cf places "x${U}ers/jane/a.txt" "fine" "a file at a leaking path"
cf places "x${U}ers/jane/b.txt" "see $HOMEQ" "a leaking file at a leaking path"
push places origin main
co places
scan places "$B" "$(tip places refs/heads/main)" refs/heads/main
# Red when: a file path is not scanned, or a finding prints a path that holds a match.
expect_red "push: a home path in a file path is red and the path is withheld" home-folder-path "withheld"

echo "== a new default branch is scanned in full, even after a later push moved its tip"
newrepo newdef
# Rebuild main from nothing: C (a leak), then D (clean, C's child), each pushed on its own.
git -C "$R/newdef" checkout -q --orphan fresh || die "orphan"
git -C "$R/newdef" rm -q -rf . || die "rm"
cf newdef notes.md "see $HOMEP" "C: a leaking commit"
C="$(git -C "$R/newdef" rev-parse HEAD)"
cf newdef notes.md "nothing here" "D: clean it up"
D="$(git -C "$R/newdef" rev-parse HEAD)"
git --git-dir="$R/newdef.git" update-ref -d refs/heads/main
push newdef origin "$D:refs/heads/main"
co newdef
[ "$(git -C "$R/newdef.co" rev-parse refs/remotes/origin/main)" = "$D" ] || die "origin/main is not D"
mkevent() { # FILE BEFORE AFTER: a push event of refs/heads/main in a public repository whose default branch is main
  "$REAL_PY" -I -c 'import json,sys
p,b,a=sys.argv[1:4]
json.dump({"ref":"refs/heads/main","before":b,"after":a,
  "repository":{"full_name":"acme/pub","private":False,"default_branch":"main"}},open(p,"w"))' "$@" || die "event $1"
}
mkevent "$WORK/newdef-1.json" "$ZERO" "$C"
mkevent "$WORK/newdef-2.json" "$C" "$D"
(_run python3 "$SCAN" push --repo "$R/newdef.co" --event-path "$WORK/newdef-1.json" </dev/null)
# Red when: a new default branch is scanned against the checkout's later default tip (D hides C).
expect_red "push: the first event of a new default branch (C, a leak) is red although origin/main is D" home-folder-path
(_run python3 "$SCAN" push --repo "$R/newdef.co" --event-path "$WORK/newdef-2.json" </dev/null)
# Red when: the clean cleanup push (C..D) is blocked, or passes without gitleaks running.
expect_clean "push: the cleanup event (C to D, clean) passes (scanned)"
(_run python3 "$SCAN" push --repo "$R/newdef.co" --before "$ZERO" --after "$C" --ref refs/heads/main \
  --default-branch main </dev/null)
# Red when: --default-branch does not mark the ref as the default branch the way the event does.
expect_red "push: --default-branch main with before all zeros scans all of after's history" home-folder-path

echo "== two existing branches pushed at once: each is judged by its own before..after"
newrepo twoold
{ git -C "$R/twoold" branch A && git -C "$R/twoold" branch B; } || die "branches"
push twoold origin A B
OLDTIP="$(tip twoold refs/heads/A)"
cf twoold s.txt "key $KEY" "L: a leaking commit"
L2="$(git -C "$R/twoold" rev-parse HEAD)"
cf twoold c.txt "fine" "C: a clean child of L"
C2="$(git -C "$R/twoold" rev-parse HEAD)"
push twoold origin "$C2:refs/heads/A" "$L2:refs/heads/B"
co twoold
scan twoold "$OLDTIP" "$C2" refs/heads/A
# Red when: the scan subtracts every other current ref (B already holds L, so A's push looks clean).
expect_red "push: branch A (fast-forward to C, a child of the leak) is red" aws-access-token
scan twoold "$OLDTIP" "$L2" refs/heads/B
# Red when: the scan subtracts every other current ref (A's tip C contains L, so B's push looks clean).
expect_red "push: branch B (fast-forward to the leak L) is red" aws-access-token

echo "== a finding is also a workflow error line under GitHub Actions"
(export GITHUB_ACTIONS=true && _run python3 "$SCAN" push --repo "$R/places.co" --before "$ZERO" \
  --after "$DEF" --ref "refs/heads/x${U}ers/jane/y" --default-tip "$DEF" </dev/null)
# Red when: push mode prints no ::error line per finding under GitHub Actions, or it names the ref.
if [ "$(rc)" = 1 ] && grep -q -x -F -e "::error title=public-content guard::home-folder-path in the ref name" "$OUT" &&
  ! _leaks "$OUT" "$ERR"; then
  ok "push: GITHUB_ACTIONS=true prints one ::error line per finding"
else
  bad "push: GITHUB_ACTIONS=true prints one ::error line per finding" "exit $(rc), stdout '$(head -c 300 "$OUT")'"
fi

echo
echo "${PASS} passed, ${FAIL} failed, ${SKIPPED} skipped"
[ "$FAIL" -eq 0 ]
