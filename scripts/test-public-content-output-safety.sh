#!/usr/bin/env bash
# test-public-content-output-safety.sh - a name the scanner did not write (a file path, a ref, an
# archive member, a --label, any event payload field) reaches its output only through one
# renderer. The renderer scans the RAW name with every rule before anything is escaped, and
# prints it only when it matches no rule and every character is in [A-Za-z0-9._/-]; anything
# else is replaced by a fixed placeholder. So a hostile name can neither leak a token (escaping
# a newline first moved the token's boundary, so the token passed the scan and was printed) nor
# forge a workflow command (a raw newline in a name put `::notice::` at the start of a line).
#
# Two parts:
# - behaviour: hostile names (a leading newline and a token, `safe\n::notice::FORGED`, `%0A`, a
#   CR, U+2028, a colon pair, a token split by a newline) through a finding, an unreadable
#   archive and a warning, in push, ci, pre-push and text modes. The output holds no token and
#   no piece of the name, no line starting with `::` other than the scanner's own ::error and
#   ::warning lines, no CR and no Unicode line separator; the exit code is 1 or 2 as before.
#   Partners: a safe name is still printed, so "withheld" is not vacuous.
# - source: every output call in scan.py (print, the ScanError family, _report, _finding,
#   speech_warnings) formats only constants, renderer output, or a fixed allowlist of safe
#   values (see the checker below; it is itself shown to flag a planted `print(path)`).
#
# Runs on bash 3.2 and 5, macOS and Linux, with the REAL gitleaks from PATH. Leaks are
# ASSEMBLED AT RUN TIME. Each check's "Red when:" line names the change that turns it red.

# shellcheck source=scripts/lib-public-content-test.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-public-content-test.sh"

echo "test-public-content-output-safety.sh"

R="$WORK/repos"
unset PRIVATE_NOTES_DIR

# The hostile names, each with a marker that must never reach the output.
K1="${KEY:0:8}"  # the token's first half
K2="${KEY:8}"    # its second half
LS="$(printf '\342\200\250')"  # U+2028 LINE SEPARATOR, as UTF-8
NAMES_ID="lead cmd pct cr ls colon split"
hostile() { # ID -> the name
  case "$1" in
    lead) printf '\n%s.txt' "$KEY" ;;
    cmd) printf 'safe\n::notice::FORGED' ;;
    pct) printf 'safe%%0A::notice::FORGED' ;;
    cr) printf 'safe\r::notice::FORGED' ;;
    ls) printf 'safe%s::notice::FORGED' "$LS" ;;
    colon) printf 'safe::notice::FORGED' ;;
    split) printf '%s\n%s.txt' "$K1" "$K2" ;;
  esac
}

# write_file PATH KIND: KIND home (a home-folder path), 7z (an archive the guard cannot open),
# clean (no match). Python, so a name with any byte is written exactly.
write_file() {
  "$REAL_PY" -I -c '
import os, sys
path, kind, home = sys.argv[1], sys.argv[2], sys.argv[3]
data = {"home": ("see " + home + "\n").encode(), "7z": b"7z\xbc\xaf\x27\x1c" + b"\x00" * 32,
        "clean": b"All tests pass.\n"}[kind]
open(path, "wb").write(data)' "$1" "$2" "$HOMEP" || die "write $2"
}

# safe_output NAME WANT_RC [NEEDLE...]: exit WANT_RC; each needle on stderr; no token, no
# marker of a hostile name, no forged workflow command, no CR or line separator anywhere.
safe_output() {
  local name="$1" want="$2" n
  shift 2
  if [ "$(rc)" != "$want" ]; then bad "$name" "expected exit $want, got $(rc)$(_hint)"; return; fi
  for n in "$@"; do
    grep -q -F -e "$n" "$ERR" || { bad "$name" "stderr lacks '$n'$(_hint)"; return; }
  done
  if _leaks "$OUT" "$ERR"; then bad "$name" "the output repeats the matched text"; return; fi
  if grep -q -F -e FORGED -e "$K1" -e "$K2" "$OUT" "$ERR"; then
    bad "$name" "the output repeats a piece of a hostile name"
    return
  fi
  if "$REAL_PY" -I -c '
import re, sys
for f in sys.argv[1:]:
    data = open(f, "rb").read()
    if b"\r" in data or " ".encode() in data or " ".encode() in data or "\x85".encode() in data:
        sys.exit(0)
    for ln in data.split(b"\n"):
        s = ln.lstrip()
        if s.startswith(b"::") and not re.match(rb"::(error|warning) title=public-content guard::", s):
            sys.exit(0)
sys.exit(1)' "$OUT" "$ERR"; then
    bad "$name" "the output holds a forged workflow command, a CR or a line separator$(_hint)"
    return
  fi
  ok "$name"
}

# newrepo / co / tip / scan_push: a bare remote, a work clone, and the workflow-style checkout.
newrepo() {
  local d="$R/$1" b="$R/$1.git"
  if ! { git init -q --bare "$b" && git init -q "$d" && git -C "$d" remote add origin "$b" &&
    echo start >"$d/a.txt" && git -C "$d" add a.txt && git -C "$d" commit -q -m init &&
    git -C "$d" push -q origin main 2>/dev/null; }; then
    die "newrepo $1"
  fi
}
co() {
  local c="$R/$1.co"
  rm -rf "$c"
  if ! { git init -q "$c" && git -C "$c" remote add origin "$R/$1.git" &&
    git -C "$c" fetch -q origin '+refs/heads/*:refs/remotes/origin/*' '+refs/tags/*:refs/tags/*'; }; then
    die "checkout $1"
  fi
}
tip() { git --git-dir="$R/$1.git" rev-parse --verify --quiet "$2" || echo "$ZERO"; }
# add_named REPO ID KIND: commit one file named by hostile ID (or a literal name) holding KIND.
add_named() {
  local d="$R/$1" f
  case "$2" in lit:*) f="${2#lit:}" ;; *) f="$(hostile "$2")" ;; esac
  rm -f "$d"/* 2>/dev/null
  git -C "$d" rm -q -r --cached . >/dev/null 2>&1
  echo start >"$d/a.txt"
  write_file "$d/$f" "$3"
  { git -C "$d" add -A && git -C "$d" commit -q -m "a fixture" && git -C "$d" push -q origin main 2>/dev/null; } ||
    die "add_named $2"
}
scan_push() { # NAME BEFORE AFTER
  (GITHUB_ACTIONS=true _run python3 "$SCAN" push --repo "$R/$1.co" --before "$2" --after "$3" \
    --ref refs/heads/main </dev/null)
}

echo "== push mode: hostile names through a finding and an unreadable archive"
for id in $NAMES_ID; do
  newrepo "h-$id"
  B="$(tip "h-$id" refs/heads/main)"
  add_named "h-$id" "$id" home
  C="$(tip "h-$id" refs/heads/main)"
  co "h-$id"
  scan_push "h-$id" "$B" "$C"
  # Red when: a finding's place prints a name that is not plain [A-Za-z0-9._/-], or escapes it
  # before the scan (a token or a forged command line then reaches the output).
  safe_output "push: finding in a file named '$id' prints no piece of the name" 1 home-folder-path withheld
  add_named "h-$id" "$id" 7z
  D="$(tip "h-$id" refs/heads/main)"
  co "h-$id"
  scan_push "h-$id" "$C" "$D"
  # Red when: the unreadable-archive error names the file by its raw (or escaped) name.
  safe_output "push: unreadable archive named '$id' prints no piece of the name" 2 "could not check" withheld
done

echo "== push mode: a token in a name is found on the raw name"
newrepo h-tok
B="$(tip h-tok refs/heads/main)"
add_named h-tok lead clean
C="$(tip h-tok refs/heads/main)"
co h-tok
scan_push h-tok "$B" "$C"
# Red when: the name is escaped (\n -> \\n) before the scan, so the token after the newline
# no longer starts a word and the name passes.
safe_output "push: a token after a newline in a file name is a finding" 1 aws-access-token withheld
newrepo h-tok2
B="$(tip h-tok2 refs/heads/main)"
add_named h-tok2 "lit:${KEY}.txt" clean
C="$(tip h-tok2 refs/heads/main)"
co h-tok2
scan_push h-tok2 "$B" "$C"
# Red when: a token in a plain file name stops being found (control for the case above).
safe_output "push: a token in a plain file name is a finding" 1 aws-access-token withheld

echo "== push mode: partners (a safe name is still printed; a space is withheld)"
newrepo h-safe
B="$(tip h-safe refs/heads/main)"
add_named h-safe lit:plain-notes.txt home
C="$(tip h-safe refs/heads/main)"
co h-safe
scan_push h-safe "$B" "$C"
# Red when: the renderer withholds every name (the hostile cases would then pass vacuously).
safe_output "push: a finding in a plain file name names the file" 1 home-folder-path plain-notes.txt
newrepo h-sp
B="$(tip h-sp refs/heads/main)"
add_named h-sp "lit:my notes.txt" home
C="$(tip h-sp refs/heads/main)"
co h-sp
scan_push h-sp "$B" "$C"
# Red when: a name with a space (outside [A-Za-z0-9._/-]) is printed.
safe_output "push: a file name with a space is withheld" 1 home-folder-path withheld
if grep -q -F "my notes" "$ERR" "$OUT"; then bad "push: the spaced name is not printed" "printed"; else
  ok "push: the spaced name is not printed"; fi

echo "== ci mode"
for id in cmd lead; do
  newrepo "c-$id"
  B="$(tip "c-$id" refs/heads/main)"
  add_named "c-$id" "$id" home
  C="$(tip "c-$id" refs/heads/main)"
  (cd "$R/c-$id" && GITHUB_ACTIONS=true PR_TITLE="a title" PR_BODY="a body" \
    _run python3 "$SCAN" ci --repo "$R/c-$id" --base "$B" --head "$C" </dev/null)
  # Red when: ci mode prints a hostile file name in a finding or an ::error line.
  safe_output "ci: finding in a file named '$id' prints no piece of the name" 1 home-folder-path withheld
done

echo "== pre-push mode"
vis acme/hp public
mkpush hp "$(gh_url acme/hp)"
write_file "$P/hp/$(hostile cmd)" home
{ git -C "$P/hp" add -A && git -C "$P/hp" commit -q -m "a fixture"; } || die "hp commit"
gpush "$P/hp" "$P/hp.git" origin main
# Red when: the pre-push report prints a hostile file name.
safe_output "pre-push: finding in a file named 'cmd' prints no piece of the name" 1 home-folder-path withheld
git -C "$P/hp" reset -q --hard origin/main
write_file "$P/hp/$(hostile split)" 7z
{ git -C "$P/hp" add -A && git -C "$P/hp" commit -q -m "a fixture"; } || die "hp commit"
gpush "$P/hp" "$P/hp.git" origin main
# git push exits 1 whatever the hook's own status, so the block is told apart by its message.
# Red when: the pre-push unreadable-archive error prints a hostile file name.
safe_output "pre-push: unreadable archive named 'split' prints no piece of the name" 1 "could not check" withheld

echo "== text mode: a hostile --label through a finding, an unreadable file and a warning"
for id in cmd lead cr ls; do
  lab="$(hostile "$id")"
  write_file "$WORK/t.in" home
  (GITHUB_ACTIONS=true _run python3 "$SCAN" text --label "$lab" <"$WORK/t.in")
  # Red when: text mode prints its --label raw in a finding.
  safe_output "text: finding under label '$id' prints no piece of the label" 1 home-folder-path withheld
  write_file "$WORK/t.in" 7z
  (GITHUB_ACTIONS=true _run python3 "$SCAN" text --label "$lab" <"$WORK/t.in")
  # Red when: text mode prints its --label raw in the unreadable-file error.
  safe_output "text: unreadable input under label '$id' prints no piece of the label" 2 "could not check" withheld
  printf 'the owner said it is fine\n' >"$WORK/t.in"
  (GITHUB_ACTIONS=true _run python3 "$SCAN" text --label "$lab" <"$WORK/t.in")
  # Red when: the reported-speech warning prints the --label raw.
  safe_output "text: warning under label '$id' prints no piece of the label" 0 WARNING withheld
done
printf 'the owner said it is fine\n' >"$WORK/t.in"
(_run python3 "$SCAN" text --label demo <"$WORK/t.in")
# Red when: a plain label is withheld too (partner: the label cases above are not vacuous).
safe_output "text: warning under a plain label names it" 0 "WARNING: demo:1"

echo "== source: every output call formats only renderer output or allowlisted values"
cat >"$WORK/outcheck.py" <<'PYEOF'
"""Static check of scan.py's output calls. A SINK is a call that prints or builds printed text:
print, sys.stdout/stderr.write, ScanError, UnreadableFile, NotHandled, _zip_bad, _report,
_finding and speech_warnings. Each argument must be built only from: string or number
constants; module constants (UPPER_CASE names bound to constants); calls to the renderer
(`render`, whose templates must be constants); a local name every one of whose assignments is
itself safe; a parameter of a sink function (checked at its call sites); or an expression on
ALLOW, the fixed list of values known safe, each with its reason. The place of Scanner.add and
Scanner.add_names and the label of _add_object_text count as sinks: they become the place a
report prints."""
import ast, sys

SINKS = {"print", "ScanError", "UnreadableFile", "NotHandled", "_zip_bad", "_report", "_finding",
         "speech_warnings", "add", "add_names", "_add_object_text"}
# Sinks whose other arguments are not printed: the argument positions (and keywords) checked.
SINK_ARGS = {"speech_warnings": ([0], ()), "add": ([0], ("place",)), "add_names": ([0], ("place",)),
             "_add_object_text": ([1], ("what",))}
# Calls that return a safe value whatever their argument (they validate it or raise).
SAFE_CALLS = {"_short"}
# (function, expression source): why it is safe to print. "*" is any function.
ALLOW = {
    ("*", "type(exc).__name__"): "an exception class name",
    ("*", "r.returncode"): "an integer exit code",
    ("*", "terms.warning"): "the fixed warning text of load_terms",
    ("*", "sc.run()"): "Scanner.run returns only _finding results (a sink)",
    ("*", "w"): "a line built by speech_warnings (a sink)",
    ("main", "exc"): "a ScanError or NotHandled, whose every construction is a sink checked here",
    ("allowed_addresses", "n"): "a line number (int)",
    ("speech_warnings", "n"): "a line number (int)",
    ("_add_object_text", "n"): "a tag number (int)",
    ("_add_object_text", "role"): "a loop over the fixed words author, committer, tagger",
    ("_spend", "UNPACK_LIMIT >> 20"): "a constant",
    ("unpack", "what"): "a fixed format name from _CANNOT_OPEN",
    ("Scanner._log", "self._unexpected(ln)"): "a gitleaks log line: masked, cut to 100 characters, printed with %r",
    ("Scanner._log", "self._unexpected(level + ' ' + message)"): "as above",
    ("Scanner._unexpected", "shown"): "the masked, cut log line, printed with %r (escapes every line break)",
    ("Scanner._unexpected", "have"): "the installed gitleaks' version string",
    ("Scanner.run", "rule"): "a rule id, checked as [A-Za-z0-9_.-]+ when read from gitleaks",
    ("Scanner.run", "line"): "an integer line number",
    ("Scanner.run", "fixed"): "the fixed place a file was added with (a sink argument)",
    ("Scanner.run", "reason"): "a ScanError message from unpack, whose every construction is checked",
    ("Scanner.run", "str(chunk['place'])"): "the fixed place a chunk was added with (a sink argument)",
    ("cmd_ci", "listed"): "a constant path inside this repository",
    ("cmd_ci", "' and '.join(missing)"): "names of fixed environment variables",
    ("cmd_ci", "place"): "a loop over the fixed labels the PR title and the PR body",
    ("cmd_event", "name"): "an EVENT_MAP key: checked against the map before it is printed",
    ("cmd_event", "key"): "an EVENT_MAP value (a fixed object key)",
    ("cmd_event", "label"): "a loop over EVENT_MAP's fixed field labels",
    ("cmd_event", "_object_label(key, obj)"): "a fixed label and an integer (see _object_label)",
    ("cmd_event", "_word(action)"): "a lower-case word, else (unreadable)",
    ("cmd_event", "_word(name)"): "a lower-case word, else (unreadable)",
    ("cmd_push", "flag"): "a loop over the fixed words before and after",
    ("_pr_sha", "side"): "the fixed words base or head",
    ("_field_text", "label"): "a fixed label from the callers",
    ("_commit", "name"): "the fixed words base or head",
    ("_git", "args[0]"): "a git subcommand name fixed by the callers",
    ("_recorded_notes_dir", "NOTES_KEY"): "a constant",
    ("load_terms", "where"): "a fixed folder description",
    ("_report", "item"): "an element of found: each built by _finding",
    ("_report", "item.replace(' at ', ' in ', 1)"): "the same element, reworded for the ::error line",
}


class Checker:
    def __init__(self, tree):
        self.errors = []
        self.sinks = 0
        self.renders = 0
        self.consts = set()
        for node in tree.body:
            if isinstance(node, ast.Assign) and all(isinstance(t, ast.Name) and t.id.isupper() for t in node.targets):
                if self.constant(node.value):
                    self.consts.update(t.id for t in node.targets)
        self.walk(tree, [], None)

    def constant(self, e):
        if isinstance(e, ast.Constant):
            return True
        if isinstance(e, ast.BinOp):
            return self.constant(e.left) and self.constant(e.right)
        if isinstance(e, ast.Tuple):
            return all(self.constant(x) for x in e.elts)
        return False

    def walk(self, node, stack, fn):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                self.walk(child, stack + [child.name], fn)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.walk(child, stack + [child.name], child)
            else:
                if isinstance(child, ast.Call) and self.sink_name(child):
                    self.check_call(child, stack, fn)
                self.walk(child, stack, fn)

    @staticmethod
    def callee(call):
        f = call.func
        return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None

    def sink_name(self, call):
        name = self.callee(call)
        f = call.func
        if name in ("add", "add_names"):  # Scanner.add, not set.add
            return isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in ("sc", "self")
        if name in SINKS:
            return True
        return (name == "write" and isinstance(f, ast.Attribute) and isinstance(f.value, ast.Attribute)
                and f.value.attr in ("stdout", "stderr"))

    def check_call(self, call, stack, fn):
        self.sinks += 1
        args = list(call.args) + [k.value for k in call.keywords if k.arg not in ("file", "flush")]
        name = self.callee(call)
        if name in SINK_ARGS:
            pos, kws = SINK_ARGS[name]
            args = [call.args[i] for i in pos if i < len(call.args)] + [k.value for k in call.keywords if k.arg in kws]
        for a in args:
            self.check(a, stack, fn, call.lineno, set())

    def allowed(self, e, stack):
        src = ast.unparse(e)
        here = ".".join(stack)
        return ("*", src) in ALLOW or (here, src) in ALLOW or (stack[-1] if stack else "", src) in ALLOW

    def check(self, e, stack, fn, line, seen):
        if isinstance(e, ast.Constant):
            return
        if self.allowed(e, stack):
            return
        if isinstance(e, ast.JoinedStr):
            for v in e.values:
                if isinstance(v, ast.FormattedValue):
                    self.check(v.value, stack, fn, line, seen)
            return
        if isinstance(e, ast.BinOp) and isinstance(e.op, (ast.Add, ast.Mod)):
            self.check(e.left, stack, fn, line, seen)
            right = e.right.elts if isinstance(e.op, ast.Mod) and isinstance(e.right, ast.Tuple) else [e.right]
            for r in right:
                self.check(r, stack, fn, line, seen)
            return
        if isinstance(e, ast.IfExp):
            self.check(e.body, stack, fn, line, seen)
            self.check(e.orelse, stack, fn, line, seen)
            return
        if isinstance(e, ast.Call) and self.callee(e) == "render":
            self.renders += 1
            for t in e.args[1:]:  # the templates; the first argument is the raw name it checks
                self.check(t, stack, fn, line, seen)
            return
        if isinstance(e, ast.Call) and self.callee(e) in SAFE_CALLS:
            return
        if isinstance(e, ast.Call) and self.callee(e) in ("_annotation", "_finding") and len(e.args) >= 1:
            for a in e.args:
                self.check(a, stack, fn, line, seen)
            return
        if isinstance(e, ast.Call) and isinstance(e.func, ast.Attribute) and e.func.attr == "join" \
                and isinstance(e.func.value, ast.Constant) and len(e.args) == 1:
            arg = e.args[0]
            if isinstance(arg, ast.Call) and self.callee(arg) == "fromkeys" and arg.args:
                arg = arg.args[0]
            self.check(arg, stack, fn, line, seen)
            return
        if isinstance(e, ast.Name):
            if e.id in self.consts:
                return
            if fn is not None and self.local_ok(e.id, stack, fn, line, seen):
                return
        self.fail(line, stack, e, "a value not produced by the renderer or the allowlist")

    def local_ok(self, name, stack, fn, line, seen):
        if name in seen:
            return True
        seen = seen | {name}
        params = {a.arg for a in fn.args.args + fn.args.kwonlyargs}
        if name in params:
            return fn.name in SINKS
        found = False
        for node in ast.walk(fn):
            values = []
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
                values.append(node.value)
            elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and isinstance(node.target, ast.Name) \
                    and node.target.id == name and node.value is not None:
                values.append(node.value)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr == "append" and isinstance(node.func.value, ast.Name) \
                    and node.func.value.id == name:
                values += node.args
            elif isinstance(node, (ast.For, ast.comprehension)):
                targets = [t.id for t in ast.walk(node.target) if isinstance(t, ast.Name)]
                if name in targets:
                    return False  # a loop variable: only through ALLOW
            elif isinstance(node, (ast.Tuple, ast.List)) and isinstance(getattr(node, "ctx", None), ast.Store):
                if any(isinstance(t, ast.Name) and t.id == name for t in node.elts):
                    return False  # tuple unpacking: only through ALLOW
            for v in values:
                found = True
                if isinstance(v, (ast.List, ast.Tuple)) and not v.elts:
                    continue  # an empty list, filled by appends checked above
                before = len(self.errors)
                self.check(v, stack, fn, line, seen)
                if len(self.errors) != before:
                    return True  # the failure is already recorded at its source
        return found

    def fail(self, line, stack, e, why):
        self.errors.append("scan.py:%d in %s formats `%s`: %s" % (line, ".".join(stack) or "<module>",
                                                                  ast.unparse(e), why))


def check_source(text):
    return Checker(ast.parse(text))


if __name__ == "__main__":
    path = sys.argv[1]
    c = check_source(open(path, encoding="utf-8").read())
    for err in c.errors:
        print("  " + err)
    print("SINKS %d RENDERS %d ERRORS %d" % (c.sinks, c.renders, len(c.errors)))
    # The checker itself bites: a planted raw print and a raw ScanError are flagged.
    planted = check_source("def f(path):\n    print('at ' + path)\n    raise ScanError(f'bad {path}')\n")
    print("PLANTED %d" % len(planted.errors))
PYEOF
"$REAL_PY" -I "$WORK/outcheck.py" "$SCAN" >"$WORK/outcheck.txt" 2>&1 || true
sed -n '/^  scan.py/p' "$WORK/outcheck.txt"
summary="$(grep '^SINKS ' "$WORK/outcheck.txt")"
planted="$(grep '^PLANTED ' "$WORK/outcheck.txt")"
sinks=0 renders=0 errors=x
read -r _ sinks _ renders _ errors <<<"$summary"
# Red when: any print, error or report call in scan.py formats a value that is neither renderer
# output nor on the allowlist (for example a file path or a payload field put in a message raw).
if [ "$errors" = 0 ]; then ok "source: every output call formats only safe values"; else
  bad "source: every output call formats only safe values" "$errors violation(s), listed above"; fi
# Red when: the checker stops finding the output calls (it would then pass by checking nothing).
if [ "$sinks" -ge 60 ]; then ok "source: the checker sees the output calls ($sinks)"; else
  bad "source: the checker sees the output calls" "only $sinks sinks found $(tail -2 "$WORK/outcheck.txt" | tr '\n' ' ')"; fi
# Red when: no output goes through the renderer (names would then be printed some other way).
if [ "$renders" -ge 3 ]; then ok "source: names reach output through the renderer ($renders calls)"; else
  bad "source: names reach output through the renderer" "$renders render calls"; fi
# Red when: the checker no longer flags a raw path in print or in a ScanError.
if [ "$planted" = "PLANTED 2" ]; then ok "source: the checker flags a planted raw print and raw error"; else
  bad "source: the checker flags a planted raw print and raw error" "$planted"; fi

echo
echo "${PASS} passed, ${FAIL} failed, ${SKIPPED} skipped"
[ "$FAIL" -eq 0 ]
