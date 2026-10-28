#!/usr/bin/env bash
# test-public-content-guard.sh - cases for scripts/public_content_guard.py, the Claude Code
# PreToolUse hook that scans what an agent is about to publish to a public repo.
#
# Every case runs against throwaway repositories under mktemp, with a fake `gh` that answers
# repository visibility from a table, so no case calls GitHub. Every leak below is ASSEMBLED
# AT RUN TIME, so this file holds no home path, email, key or transcript name itself (the
# guard would otherwise block pushes of this very file). Needs gitleaks; without it the
# suite SKIPS, except on CI, where it FAILS so it cannot pass by never running.
#
# Which change turns each case red:
#   allow-*          - the guard denying more than it should (a rule or allowlist broken)
#   deny-*           - that rule removed from public-content/gitleaks-public.toml, that channel
#                      no longer detected, or a deny turned into an allow
#   shape-*          - detection made to depend on parsing the command shape again (multi-line
#                      calls, heredoc and piped bodies, `timeout`, `if` blocks, `bash -lc`)
#   push-meta-*      - commit messages or file names no longer scanned on a push
#   push-dest-*      - the destination taken from origin, or the range excluding every remote
#                      instead of only the destination's refs
#   push-scope-unrelated-branch - the push range widened to every local branch again
#   flip-*           - `gh repo edit --visibility public` / `repo create --push` not scanning history
#   body-*           - an unreadable named body file allowed, `--flag=value` or `$VAR` not resolved
#   redacted / masked-* - the reason built from the match, or private terms not masked in paths
#   default-*        - the secret pass dropped, or the content rules layered on the defaults
#                      again (their global allowlist drops /home/ matches)
#   override-cannot-disable - PUBLIC_CONTENT_GUARD_VISIBILITY honoured for PRIVATE
#   cache-*          - a PRIVATE answer cached
#   fail-closed*     - a publication allowed when gitleaks is missing, or other calls blocked
#   dest-*           - one destination deciding for a call with several, -R read from inside a
#                      quoted body, graphql or an MCP call without owner falling back to origin
#   deny-push-alias / -option-with-value / -unresolvable-ref - aliases ignored, a push option's
#                      value taken as the remote, or an unresolvable source passed to git log
#   flip-api-* / flip-no-local-clone - API visibility flips missed, or a flip allowed with no clone

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="${HERE}/public_content_guard.py"
PASS=0
FAIL=0

if ! command -v gitleaks >/dev/null 2>&1; then
  if [ "${CI:-}" = "true" ]; then echo "FAIL - gitleaks is not installed on CI"; exit 1; fi
  echo "SKIP - gitleaks not installed"; exit 0
fi

# ---- leaks, assembled at run time
U="/Us"; HOMEP="${U}ers/jane/notes.txt"
MAIL="$(printf '%s@%s' jane.doe corp-mail.io)"
KEY="AKIA""IOSFODNN7EXAMPLA"
TERM_A="zebracorn"; PTERM="${TERM_A}-labs"
TRANSCRIPT="$(printf '%s-%s-%s-%s-%s.%s' 0f1e2d3c 1a2b 4c5d 8e9f 0123456789ab jsonl)"
CIHOME="/home/runner/work/x"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
NOTES="${WORK}/notes"
mkdir -p "${NOTES}/scanner" "${WORK}/bin"
printf '# private terms\n%s\n' "$PTERM" > "${NOTES}/scanner/private-terms.txt"
cat > "${WORK}/bin/gh" <<'FAKE'
#!/usr/bin/env bash
[ "$1 $2" = "repo view" ] || exit 1
grep -E "^$3 " "${FAKE_VIS_TABLE}" | awk '{print $2}'
FAKE
chmod +x "${WORK}/bin/gh"
VIS="${WORK}/vis.txt"
printf 'o/private PRIVATE\no/public PUBLIC\n' > "$VIS"

g() { git -c user.email=t@example.com -c user.name=t "$@"; }
new_repo() {  # new_repo <dir> <origin slug>: a repo whose main is already on origin
  g init -q --bare -b main "$1.remote.git"
  g init -q -b main "$1"
  g -C "$1" remote add origin "https://github.com/$2.git"
  echo start > "$1/a.txt"; g -C "$1" add a.txt; g -C "$1" commit -q -m init
  g -C "$1" push -q "$1.remote.git" main 2>/dev/null
  g -C "$1" update-ref refs/remotes/origin/main HEAD
}
new_repo "${WORK}/pub" o/public
new_repo "${WORK}/priv" o/private

# _run <dir> <tool> <tool_input json> -> allow | deny | warn ; output kept in last.json
_run() {
  local out
  out="$(python3 -c '
import json, sys
print(json.dumps({"hook_event_name": "PreToolUse", "tool_name": sys.argv[1],
                  "tool_input": json.loads(sys.argv[2]), "cwd": sys.argv[3]}))
' "$2" "$3" "$1" | PATH="${WORK}/bin:${PATH}" FAKE_VIS_TABLE="$VIS" PRIVATE_NOTES_DIR="${NOTES_DIR-$NOTES}" XDG_CACHE_HOME="${WORK}/cache" python3 "$GUARD")"
  printf '%s' "$out" > "${WORK}/last.json"
  if [ -z "$out" ]; then echo allow
  elif printf '%s' "$out" | grep -q '"permissionDecision": "deny"'; then echo deny
  else echo warn; fi
}
# _obj k v k v ... -> a JSON object of strings
_obj() { python3 -c 'import json,sys; a=sys.argv[1:]; print(json.dumps(dict(zip(a[::2], a[1::2]))))' "$@"; }
_bash() { python3 -c 'import json,sys; print(json.dumps({"command": sys.argv[1]}))' "$1"; }
B() { _run "${WORK}/pub" Bash "$(_bash "$1")"; }       # a Bash call in the public repo
BP() { _run "${WORK}/priv" Bash "$(_bash "$1")"; }     # ... in the private repo
_check() {
  if [ "$2" = "$3" ]; then printf '  ok   %s\n' "$1"; PASS=$((PASS + 1))
  else printf '  FAIL %s - expected %s, got %s\n' "$1" "$2" "$3"; FAIL=$((FAIL + 1)); fi
}

echo "test-public-content-guard.sh"

# ---- text channels
_check "allow-not-a-publication" allow "$(B 'ls -la && git status')"
_check "allow-clean-pr" allow "$(B 'gh pr create --title "Fix the parser" --body "Adds a test."')"
_check "deny-home-path" deny "$(B "gh pr create --title x --body \"see ${HOMEP}\"")"
_check "deny-email" deny "$(B "gh issue comment 3 --body \"mail ${MAIL}\"")"
_check "deny-transcript" deny "$(B "gh issue comment 3 --body \"log ${TRANSCRIPT}\"")"
_check "default-secret-pass" deny "$(B "gh pr create --title x --body \"key ${KEY}\"")"
HOMEL="/ho""me/jane/x"
_check "default-not-layered" deny "$(B "gh api repos/o/public/issues -f body=\"path ${HOMEL}\"")"
_check "allow-ci-home" allow "$(B "gh issue comment 3 --body \"log ${CIHOME}\"")"
_check "allow-example-mail-any-case" allow "$(B 'gh issue comment 3 --body "write to you@Example.COM or db@evil.example"')"
_check "allow-generic-claude-folder" allow "$(B 'gh pr create --title x --body "transcripts live under ~/.claude/projects/<repo>/"')"
_check "allow-gh-api-get" allow "$(B "gh api -X GET search/issues -f q=\"${HOMEP}\"")"
_check "allow-read-command" allow "$(B "gh pr view 3 --json body ${HOMEP}")"
_check "deny-private-term" deny "$(B "gh pr create --title x --body \"we build ${PTERM} next\"")"
_check "redacted-names-rule" yes "$(grep -q 'private-term at' "${WORK}/last.json" && echo yes || echo no)"
_check "redacted" no "$(grep -qi "${TERM_A}" "${WORK}/last.json" && echo yes || echo no)"
_check "deny-private-term-variant" deny "$(B "gh pr create --title x --body \"we build ${TERM_A}_labs next\"")"
_check "deny-gitleaks-allow-ignored" deny "$(B "gh pr create --title x --body \"see ${HOMEP} gitleaks:allow\"")"
_check "deny-mcp-write" deny "$(_run "${WORK}/pub" mcp__plugin_github_github__create_pull_request "$(_obj owner o repo public title x body "see ${HOMEP}")")"
_check "deny-mcp-standalone-server" deny "$(_run "${WORK}/pub" mcp__github__add_issue_comment "$(_obj owner o repo public body "see ${HOMEP}")")"
_check "allow-mcp-read" allow "$(_run "${WORK}/pub" mcp__plugin_github_github__get_file_contents "$(_obj owner o repo public path "${HOMEP}")")"
_check "allow-private-repo-text" allow "$(BP "gh pr create --title x --body \"see ${HOMEP}\"")"

# ---- destinations
_check "dest-any-public-in-call" deny "$(BP "gh pr comment 1 -R o/private --body ok; gh pr comment 2 -R o/public --body \"${HOMEP}\"")"
_check "dest-repo-flag-inside-body-ignored" deny "$(B "gh pr create --title x --body \"use -R o/private here; ${HOMEP}\"")"
_check "dest-api-graphql-unknown" deny "$(BP "gh api graphql -f query=\"mutation { addComment(input: {body: \\\"${HOMEP}\\\"}) }\"")"
_check "dest-api-attached-flags" deny "$(BP "gh api repos/o/private/issues -XPOST -fbody=\"${HOMEP}\" --hostname x; gh api repos/o/public/issues -fbody=\"${HOMEP}\"")"
_check "dest-api-endpoint-token-only" deny "$(B "gh api -X POST repos/o/public/issues -f body=\"see repos/o/private/x ${HOMEP}\"")"
_check "dest-unbalanced-quotes-unknown" deny "$(BP "gh pr comment 1 -R o/private --body \"${HOMEP}")"
_check "dest-mcp-no-owner-unknown" deny "$(_run "${WORK}/priv" mcp__plugin_github_github__create_gist "$(_obj description x content "see ${HOMEP}")")"
_check "allow-email-spoof-caught" deny "$(B "gh issue comment 3 --body \"$(printf '%s@%s' b users.noreply.github.com.evil.io)\"")"

# ---- shapes an agent really uses
NL=$'\n'
_check "shape-multiline" deny "$(B "git add -A${NL}git commit -m docs${NL}gh pr create --title docs --body \"see ${HOMEP}\"")"
_check "shape-heredoc-body" deny "$(B "gh pr create --title x --body-file - <<'EOF'${NL}## Summary${NL}- It doesn't crash (was at ${HOMEP})${NL}EOF")"
_check "shape-piped-body" deny "$(B "echo 'see ${HOMEP}' | gh issue comment 3 --body-file -")"
_check "shape-timeout" deny "$(B "timeout 60 gh pr create --title x --body \"${HOMEP}\"")"
_check "shape-if-block" deny "$(B "if true; then gh pr create --title x --body \"${HOMEP}\"; fi")"
_check "shape-bash-lc" deny "$(B "bash -lc \"gh pr create --title x --body ${HOMEP}\"")"

# ---- body files
printf 'notes for %s\n' "$HOMEP" > "${WORK}/body.md"
_check "body-file" deny "$(B "gh pr create --title x --body-file ${WORK}/body.md")"
_check "body-file-equals" deny "$(B "gh pr create --title x --body-file=${WORK}/body.md")"
_check "body-file-variable" deny "$(B "F=${WORK}/body.md; gh pr create --title x --body-file \"\$F\"")"
_check "body-file-unreadable" deny "$(B 'gh pr create --title x --body-file /nonexistent/body.md')"
head -c 2200000 /dev/zero | tr '\0' 'a' > "${WORK}/big.txt"
_check "body-gist-file-too-large" deny "$(B "gh gist create -d clean ${WORK}/big.txt")"
_check "body-gist-file" deny "$(B "gh gist create -d clean ${WORK}/body.md")"

# ---- pushes
_check "allow-clean-push" allow "$(B 'git push origin main')"
printf '%s\n' "$HOMEP" > "${WORK}/pub/b.txt"
g -C "${WORK}/pub" add b.txt && g -C "${WORK}/pub" commit -q -m "add b"
g -C "${WORK}/pub" rm -q b.txt && g -C "${WORK}/pub" commit -q -m "drop b"
_check "deny-push-history" deny "$(B 'git push origin main')"
_check "shape-push-second-line" deny "$(B "git status${NL}git push origin main")"
_check "shape-push-timeout" deny "$(B 'timeout 120 git push origin main')"
_check "deny-push-option-value" deny "$(B 'git -c core.x=y push origin main')"
_check "deny-push-option-with-value" deny "$(B 'git push -o ci.skip origin main')"
g -C "${WORK}/pub" config alias.shipit push
_check "deny-push-alias" deny "$(B 'git shipit origin main')"
_check "deny-push-unresolvable-ref" deny "$(B 'git push origin no-such-branch')"
g -C "${WORK}/pub" reset -q --hard origin/main
g -C "${WORK}/pub" commit -q --allow-empty -m "thanks ${PTERM} team, path ${HOMEP}"
_check "push-meta-message" deny "$(B 'git push origin main')"
g -C "${WORK}/pub" reset -q --hard origin/main
mkdir -p "${WORK}/pub/docs"; echo clean > "${WORK}/pub/docs/${PTERM}-plan.md"
g -C "${WORK}/pub" add docs && g -C "${WORK}/pub" commit -q -m "add plan"
_check "push-meta-file-name" deny "$(B 'git push origin main')"
_check "masked-private-term-in-path" no "$(grep -qi "${TERM_A}" "${WORK}/last.json" && echo yes || echo no)"
g -C "${WORK}/pub" reset -q --hard origin/main
g -C "${WORK}/pub" checkout -q -b old-scratch; printf '%s\n' "$HOMEP" > "${WORK}/pub/o.txt"
g -C "${WORK}/pub" add o.txt && g -C "${WORK}/pub" commit -q -m scratch
g -C "${WORK}/pub" checkout -q main; g -C "${WORK}/pub" commit -q --allow-empty -m clean
_check "push-scope-unrelated-branch" allow "$(B 'git push origin main')"
# Private repo: history with a leak is already on its PRIVATE origin.
printf '%s\n' "$HOMEP" > "${WORK}/priv/c.txt"; g -C "${WORK}/priv" add c.txt; g -C "${WORK}/priv" commit -q -m leak
g -C "${WORK}/priv" update-ref refs/remotes/origin/main HEAD
g -C "${WORK}/priv" remote add pubr https://github.com/o/public.git
_check "allow-push-to-private-origin" allow "$(BP 'git push origin main')"
_check "push-dest-other-remote" deny "$(BP 'git push pubr main')"
_check "push-dest-url" deny "$(BP 'git push https://github.com/o/public.git main')"
g -C "${WORK}/priv" branch -q --set-upstream-to=origin/main main
g -C "${WORK}/priv" config branch.main.pushRemote pubr
_check "push-dest-configured-push-remote" deny "$(BP 'git push')"
g -C "${WORK}/priv" config --unset branch.main.pushRemote
_check "flip-visibility-public" deny "$(BP 'gh repo edit o/private --visibility public --accept-visibility-change-consequences')"
_check "flip-api-visibility" deny "$(BP 'gh api -X PATCH repos/o/private -f visibility=public')"
_check "flip-no-local-clone" deny "$(BP 'gh repo edit o/elsewhere --visibility public --accept-visibility-change-consequences')"
_check "flip-repo-create-push" deny "$(BP "gh repo create o/newpub --public --source ${WORK}/priv --push")"

# ---- visibility and failure
_check "override-cannot-disable" deny "$(PUBLIC_CONTENT_GUARD_VISIBILITY=PRIVATE B "gh pr create --title x --body \"${HOMEP}\"")"
_check "cache-private-first" allow "$(BP "gh pr create --title x --body \"${HOMEP}\"")"
printf 'o/private PUBLIC\no/public PUBLIC\n' > "$VIS"
_check "cache-does-not-keep-private" deny "$(BP "gh pr create --title x --body \"${HOMEP}\"")"
_check "no-term-list-warns" warn "$(NOTES_DIR="" B 'gh pr create --title x --body "clean"')"
_check "no-term-list-still-denies" deny "$(NOTES_DIR="" B "gh pr create --title x --body \"${HOMEP}\"")"
_check "fail-closed" deny "$(PATH="${WORK}/bin:/usr/bin:/bin" B 'gh pr create --title x --body "clean"')"
_check "fail-closed-other-calls-pass" allow "$(PATH="${WORK}/bin:/usr/bin:/bin" B 'echo hello')"

echo "${PASS} passed, ${FAIL} failed"
[ "${FAIL}" -eq 0 ]
