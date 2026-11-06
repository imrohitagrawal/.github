#!/usr/bin/env bash
# test-public-content-events.sh - `scan.py event`, the mode the public-content workflow runs on
# every text-bearing GitHub event (issues, comments, reviews, discussions, releases, pull
# request title and body). It reads the event file itself (never env: a step's env block is
# printed in the public log) and scans a FIXED field map:
#
#   pull_request: title, body          issues: title, body           issue_comment: comment.body
#   pull_request_review: review.body   pull_request_review_comment: comment.body
#   commit_comment: comment.body       discussion: title, body       discussion_comment: comment.body
#   release: name, body, tag_name
#
# CLI under test:
#
#   scan.py event --name EVENT_NAME --path EVENT_JSON
#
# Exit 0 clean (or not a public repository: a notice, nothing scanned), 1 findings, 2 could not
# check (including an event or action the guard does not handle). A finding names the event,
# the field and the object's fixed label and number (issue #7, comment 1001), never the
# object's html_url or any other payload string, and never the matched text.
#
# The fixtures in public-content/tests/events/ are TEMPLATES: each mapped field holds a
# placeholder `@@FIELD@@`. This suite renders them at run time with the planted value in one
# field and clean text in the others, so no committed file holds a match (the guard scans this
# repository's own pushes and pull requests). Leaks are ASSEMBLED AT RUN TIME, as in the other
# suites.
#
# Also here: `scan.py ci --event-path EVENT_JSON` (the pull request step reads the title and
# body from the event file instead of PR_TITLE/PR_BODY), including the regression that an
# `edited` event with a clean body never turns red commits green.
#
# Runs on bash 3.2 and 5, macOS and Linux, with the REAL gitleaks from PATH (the harness fails
# when it is missing, so this suite cannot pass by not running).

# shellcheck source=scripts/lib-public-content-test.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-public-content-test.sh"

echo "test-public-content-events.sh"

EVENTS="$ROOT/public-content/tests/events"
EV="$WORK/events"
mkdir -p "$EV"
# CI has no private-term list: run every case as CI does.
unset PRIVATE_NOTES_DIR

# render TEMPLATE OUT FIELD VALUE: copy TEMPLATE to OUT with @@FIELD@@ replaced by VALUE and
# every other @@X@@ by clean text. FIELD "-" plants nothing. JSON-escaped by json.dump.
RENDER="$WORK/render.py"
cat >"$RENDER" <<'EOF'
import json, re, sys
src, out, field, value = sys.argv[1:5]
clean = {"tag_name": "v1.2.3", "name": "Release 1.2.3"}
def fill(m):
    f = m.group(1)
    return value if f == field else clean.get(f, "Clean text for %s." % f)
def walk(x):
    if isinstance(x, dict):
        return {k: walk(v) for k, v in x.items()}
    if isinstance(x, list):
        return [walk(v) for v in x]
    if isinstance(x, str):
        return re.sub(r"@@([a-z_.]+)@@", fill, x)
    return x
with open(src, encoding="utf-8") as f:
    data = walk(json.load(f))
with open(out, "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False, indent=1)
EOF
render() { "$REAL_PY" -I "$RENDER" "$@" || die "render $*"; }

# edit_json FILE PYTHON-EXPR-ON-d: change a rendered payload in place (d is the parsed JSON).
edit_json() {
  "$REAL_PY" -I -c 'import json,sys
p=sys.argv[1]
d=json.load(open(p,encoding="utf-8"))
exec(sys.argv[2])
json.dump(d,open(p,"w",encoding="utf-8"),ensure_ascii=False)' "$1" "$2" || die "edit_json $1"
}

ev() { (_run python3 "$SCAN" event --name "$1" --path "$2" </dev/null); }

# expect_finding NAME EVENT FIELD URL OTHER_FIELDS: exit 1; a finding line ("  - ...") names
# EVENT, FIELD and URL (URL "-": not required); no finding names another of the event's fields;
# no output repeats the planted text.
expect_finding() {
  local name="$1" event="$2" field="$3" url="$4" others="$5" lines
  if [ "$(rc)" != 1 ]; then bad "$name" "expected exit 1, got $(rc)$(_hint)"; return; fi
  if _leaks "$OUT" "$ERR"; then bad "$name" "the output repeats the matched text"; return; fi
  lines="$(grep -e '^  - ' "$ERR")"
  [ -n "$lines" ] || { bad "$name" "no finding line$(_hint)"; return; }
  printf '%s\n' "$lines" | grep -q -F -e "$event" || { bad "$name" "the finding does not name the event $event$(_hint)"; return; }
  if [ "$url" != - ]; then
    printf '%s\n' "$lines" | grep -q -F -e "$url" || { bad "$name" "the finding does not name $url$(_hint)"; return; }
  fi
  if ! printf '%s\n' "$lines" | "$REAL_PY" -I -c '
import re, sys
want, others = sys.argv[1], sys.argv[2].split()
text = sys.stdin.read()
tok = lambda f: re.search(r"(?<![\w.])" + re.escape(f) + r"(?![\w.])", text)
sys.exit(0 if tok(want) and not any(tok(o) for o in others if o != want) else 1)' "$field" "$others"; then
    bad "$name" "the finding does not name the field $field (alone)$(_hint)"
    return
  fi
  ok "$name"
}

# expect_clean NAME: exit 0 and gitleaks really ran (a pass that scanned nothing is no pass).
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

echo "== every mapped field of every handled event"
# event | fields (space separated) | label and number of the object the fields belong to
CASES="pull_request|title body|pull request #12
issues|title body|issue #7
issue_comment|comment.body|comment 1001
pull_request_review|review.body|review 2002
pull_request_review_comment|comment.body|comment 3003
commit_comment|comment.body|comment 4004
discussion|title body|discussion #5
discussion_comment|comment.body|comment 6006
release|name body tag_name|release 8008"
while IFS='|' read -r event fields url; do
  [ -f "$EVENTS/$event.json" ] || { bad "events: fixture $event.json exists" "missing"; continue; }
  for field in $fields; do
    out="$EV/$event-$field.json"
    if [ "$event/$field" = release/tag_name ]; then
      # A tag name cannot hold a path; a transcript name is a valid tag. The release's html_url
      # carries the tag name, so here the url holds the match and must not be printed either.
      render "$EVENTS/$event.json" "$out" "$field" "$TRANSCRIPT"
      ev "$event" "$out"
      # Red when: tag_name is not scanned, or the report prints the html_url that holds the match.
      expect_finding "events: $event $field with a match is red" "$event" "$field" - "$fields"
      continue
    fi
    render "$EVENTS/$event.json" "$out" "$field" "see $HOMEP for details"
    ev "$event" "$out"
    # Red when: this field is dropped from the event map, or the finding stops naming event, field and object.
    expect_finding "events: $event $field with a match is red" "$event" "$field" "$url" "$fields"
  done
  render "$EVENTS/$event.json" "$EV/$event-clean.json" - -
  ev "$event" "$EV/$event-clean.json"
  # Red when: a clean payload of this event is blocked, or passes without gitleaks running.
  expect_clean "events: $event clean payload passes (scanned)"
done <<EOF
$CASES
EOF

echo "== an address and a secret-shaped value are found too (not only home paths)"
render "$EVENTS/issues.json" "$EV/issues-mail.json" body "write to $MAIL"
ev issues "$EV/issues-mail.json"
# Red when: the event mode runs only some of the public rules (personal-email missing).
expect_finding "events: issues body with an email address is red" issues body "issue #7" "title body"
render "$EVENTS/issue_comment.json" "$EV/comment-key.json" comment.body "key $KEY"
ev issue_comment "$EV/comment-key.json"
# Red when: the event mode skips gitleaks' default (secret) rules.
expect_finding "events: comment body with an access key is red" issue_comment comment.body \
  "comment 1001" comment.body

echo "== a draft pull request is scanned"
render "$EVENTS/pull_request.json" "$EV/pr-draft.json" body "see $HOMEP"
edit_json "$EV/pr-draft.json" 'd["pull_request"]["draft"]=True'
ev pull_request "$EV/pr-draft.json"
# Red when: a draft pull request's text is skipped.
expect_finding "events: a draft pull request body is scanned" pull_request body "pull request #12" "title body"

echo "== unknown events and actions fail closed"
ev watch "$EVENTS/unhandled-watch.json"
# Red when: an event outside the map passes (exit 0) or fails without saying nothing was scanned.
expect_said "events: an unknown event exits 2 with its own message" 2 \
  "is not handled by the public-content guard" "nothing was scanned" "nothing is known to have leaked"
render "$EVENTS/issues.json" "$EV/issues-labeled.json" - -
edit_json "$EV/issues-labeled.json" 'd["action"]="labeled"'
ev issues "$EV/issues-labeled.json"
# Red when: an action the caller template does not list is scanned or passed instead of refused.
expect_said "events: an unhandled action (issues labeled) exits 2" 2 "is not handled by the public-content guard"
render "$EVENTS/issues.json" "$EV/issues-noaction.json" - -
edit_json "$EV/issues-noaction.json" 'del d["action"]'
ev issues "$EV/issues-noaction.json"
# Red when: a payload without an action is treated as a handled one.
expect_said "events: a payload without an action exits 2" 2 "is not handled by the public-content guard"

echo "== a private repository is not scanned"
render "$EVENTS/issues.json" "$EV/issues-private.json" body "see $HOMEP"
edit_json "$EV/issues-private.json" 'd["repository"]["private"]=True'
ev issues "$EV/issues-private.json"
# Red when: a private repository's event is blocked, or passes silently with no notice.
expect_said "events: a private repository passes with a notice" 0 "not a public repository"
_evidence "events: a private repository runs no gitleaks" noscan && ok "events: a private repository runs no gitleaks"
render "$EVENTS/issues.json" "$EV/issues-norepo.json" body "see $HOMEP"
edit_json "$EV/issues-norepo.json" 'del d["repository"]'
ev issues "$EV/issues-norepo.json"
# Red when: a payload whose visibility is unknown is treated as private (it must not pass).
if [ "$(rc)" = 0 ]; then
  bad "events: a payload without repository does not pass" "exit 0"
elif _leaks "$OUT" "$ERR"; then
  bad "events: a payload without repository does not pass" "the output repeats the matched text"
else
  ok "events: a payload without repository does not pass"
fi

echo "== a missing or null mapped field is empty, not a crash"
render "$EVENTS/issues.json" "$EV/issues-nullbody.json" - -
edit_json "$EV/issues-nullbody.json" 'd["issue"]["body"]=None'
ev issues "$EV/issues-nullbody.json"
# Red when: a null body (GitHub sends null for an empty body) crashes the scan.
expect_clean "events: a null body is empty (exit 0, scanned)"
render "$EVENTS/issues.json" "$EV/issues-nobody.json" - -
edit_json "$EV/issues-nobody.json" 'del d["issue"]["body"]'
ev issues "$EV/issues-nobody.json"
# Red when: an absent body key crashes the scan.
expect_clean "events: an absent body is empty (exit 0, scanned)"
render "$EVENTS/issues.json" "$EV/issues-title-nullbody.json" title "see $HOMEP"
edit_json "$EV/issues-title-nullbody.json" 'd["issue"]["body"]=None'
ev issues "$EV/issues-title-nullbody.json"
# Red when: a null field stops the other fields from being scanned (partner of the two above).
expect_finding "events: the title is still scanned when the body is null" issues title "issue #7" "title body"

echo "== input that cannot be read fails closed"
ev issues "$EV/does-not-exist.json"
# Red when: a missing event file passes or crashes without the guard's could-not-check message.
expect_said "events: a missing event file exits 2" 2 "could not check this"
printf '{"action": "opened", "issue": ' >"$EV/broken.json"
ev issues "$EV/broken.json"
# Red when: a truncated event file passes.
expect_said "events: a malformed event file exits 2" 2 "could not check this"

echo "== a large multiline non-ASCII body"
"$REAL_PY" -I - "$EVENTS/issue_comment.json" "$EV/comment-large.json" "$HOMEP" <<'EOF' || die "large body"
import json, sys
src, out, leak = sys.argv[1:4]
d = json.load(open(src, encoding="utf-8"))
line = "Naïve café, 日本語のテキスト, ✓ emoji 🚀, Ελληνικά, עברית, done.\n"
body = line * 800 + "the notes are at " + leak + "\n" + line * 20
d["comment"]["body"] = body
json.dump(d, open(out, "w", encoding="utf-8"), ensure_ascii=False)
EOF
ev issue_comment "$EV/comment-large.json"
# Red when: a long non-ASCII body is truncated, mis-decoded, or its match is printed.
expect_finding "events: a large non-ASCII comment with a match near the end is red" issue_comment \
  comment.body "comment 1001" comment.body
if [ "$(cat "$OUT" "$ERR" | wc -c)" -gt 4000 ]; then
  bad "events: the large body is not echoed" "output is $(cat "$OUT" "$ERR" | wc -c) bytes"
else
  ok "events: the large body is not echoed"
fi

echo "== scan.py ci --event-path (the pull request step reads the event file, not env)"
CIR="$WORK/repos/ci"
mkrepo "$CIR" acme/pub
CIBASE="$(git -C "$CIR" rev-parse HEAD)"
printf 'clean\n' >"$CIR/ok.txt"
git -C "$CIR" add ok.txt && git -C "$CIR" commit -q -m "a clean change"
CICLEAN="$(git -C "$CIR" rev-parse HEAD)"
git -C "$CIR" checkout -q -b red "$CIBASE"
printf 'see %s\n' "$HOMEP" >"$CIR/notes.md"
git -C "$CIR" add notes.md && git -C "$CIR" commit -q -m "notes"
CIRED="$(git -C "$CIR" rev-parse HEAD)"
render "$EVENTS/pull_request.json" "$EV/pr-clean.json" - -
render "$EVENTS/pull_request.json" "$EV/pr-body.json" body "see $HOMEP"
cie() { (unset PR_TITLE PR_BODY && _run python3 "$SCAN" ci --repo "$CIR" --base "$CIBASE" --head "$1" --event-path "$2"); }
cie "$CICLEAN" "$EV/pr-clean.json"
# Red when: ci still requires PR_TITLE/PR_BODY in env when --event-path is given.
expect_clean "ci --event-path: clean commits and a clean event pass without PR_TITLE/PR_BODY"
cie "$CICLEAN" "$EV/pr-body.json"
# Red when: ci --event-path does not scan the body read from the event file.
expect_rc "ci --event-path: a match in the event file's body is red" 1 "the PR body"
cie "$CIRED" "$EV/pr-clean.json"
# Red when: an `edited` event with a clean body runs a text-only scan and turns red commits green.
expect_rc "ci --event-path: red commits stay red on an edited event with a clean body" 1 home-folder-path

echo "== a place prints only fixed labels and numbers, never a payload string"
# set_url FILE KEY URL: set the html_url of the payload object KEY (the value never goes
# through a Python expression).
set_url() {
  "$REAL_PY" -I -c 'import json,sys
p,k,u=sys.argv[1:4]
d=json.load(open(p,encoding="utf-8"))
d[k]["html_url"]=u
json.dump(d,open(p,"w",encoding="utf-8"))' "$@" || die "set_url $1"
}
render "$EVENTS/issues.json" "$EV/issues-urltoken.json" body "token $GHPAT"
set_url "$EV/issues-urltoken.json" issue "https://github.com/acme/$GHPAT/issues/7"
ev issues "$EV/issues-urltoken.json"
# Red when: a finding's place prints the object's html_url (here it holds the matched token).
expect_finding "events: a token in html_url is never printed (the place is the issue number)" issues body "issue #7" "title body"
render "$EVENTS/issues.json" "$EV/issues-urlquote.json" body "> a quoted line"
set_url "$EV/issues-urlquote.json" issue "https://github.com/acme/$GHPAT/issues/7"
ev issues "$EV/issues-urlquote.json"
# Red when: the quote-line warning names the object by its html_url (which holds a token).
expect_said "events: a quote-line warning never prints html_url" 0 "may quote someone's words" "issue #7"
render "$EVENTS/release.json" "$EV/release-tagtoken.json" tag_name "$GHPAT"
ev release "$EV/release-tagtoken.json"
# Red when: a release whose tag_name holds a secret prints the tag name or the html_url built from it.
expect_finding "events: a token in a release tag_name is never printed" release tag_name "release 8008" "name body tag_name"
render "$EVENTS/release.json" "$EV/release-tagkey.json" tag_name "$KEY"
ev release "$EV/release-tagkey.json"
# Red when: a release whose tag_name is a secret prints any part of the tag (the tag or its release link).
expect_finding "events: an access key as a release tag_name is red" release tag_name "release 8008" "name body tag_name"
for f in "$EV/release-tagtoken.json:$GHPAT" "$EV/release-tagkey.json:$KEY"; do
  file="${f%%:*}" tag="${f#*:}"
  ev release "$file"
  # Red when: any 8 characters of the tag in a row appear in the output (a link, a tag name, a fragment).
  if "$REAL_PY" -I -c 'import sys
tag, text = sys.argv[1], open(sys.argv[2], encoding="utf-8", errors="replace").read() + open(sys.argv[3], encoding="utf-8", errors="replace").read()
sys.exit(1 if any(tag[i:i + 8] in text for i in range(len(tag) - 7)) else 0)' "$tag" "$OUT" "$ERR"; then
    ok "events: no part of a secret release tag ($(basename "$file")) is printed"
  else
    bad "events: no part of a secret release tag ($(basename "$file")) is printed" "a piece of the tag is in the output"
  fi
done

echo "== a finding is also a workflow error line under GitHub Actions"
render "$EVENTS/issues.json" "$EV/issues-annot.json" body "see $HOMEP"
(export GITHUB_ACTIONS=true && ev issues "$EV/issues-annot.json")
# Red when: no ::error line is printed per finding under GitHub Actions, or it prints the match.
if [ "$(rc)" = 1 ] && grep -q -x -F -e "::error title=public-content guard::home-folder-path in issues issue #7 body:1" "$OUT" &&
  ! _leaks "$OUT" "$ERR"; then
  ok "events: GITHUB_ACTIONS=true prints one ::error line per finding"
else
  bad "events: GITHUB_ACTIONS=true prints one ::error line per finding" "exit $(rc), stdout '$(head -c 300 "$OUT")'"
fi
ev issues "$EV/issues-annot.json"
# Red when: ::error lines are printed outside GitHub Actions (partner of the case above).
if [ "$(rc)" = 1 ] && ! grep -q -F -e "::error" "$OUT" "$ERR"; then
  ok "events: no ::error line outside GitHub Actions"
else
  bad "events: no ::error line outside GitHub Actions" "exit $(rc)"
fi

echo "== the pull request clean line comes from a real scan only"
CLEANLINE="public-content guard: scanned this pull request: clean for the public rules (private terms are not checked in CI)"
cie "$CICLEAN" "$EV/pr-clean.json"
# Red when: ci prints no clean line after a real clean scan (the workflow no longer echoes it).
if [ "$(rc)" = 0 ] && grep -q -x -F -e "$CLEANLINE" "$OUT"; then
  ok "ci --event-path: a clean scan prints the clean line"
else
  bad "ci --event-path: a clean scan prints the clean line" "exit $(rc), stdout '$(head -c 300 "$OUT")'"
fi
render "$EVENTS/pull_request.json" "$EV/pr-private.json" - -
edit_json "$EV/pr-private.json" 'd["repository"]["private"]=True'
cie "$CICLEAN" "$EV/pr-private.json"
# Red when: a private repository's pull request says "clean" after the "not a public repository" notice.
if [ "$(rc)" = 0 ] && grep -q -F -e "not a public repository" "$ERR" && ! grep -q -F -e "clean" "$OUT" "$ERR"; then
  ok "ci --event-path: a private repository prints no clean line"
else
  bad "ci --event-path: a private repository prints no clean line" "exit $(rc)$(_hint)"
fi

echo
echo "${PASS} passed, ${FAIL} failed, ${SKIPPED} skipped"
[ "$FAIL" -eq 0 ]
