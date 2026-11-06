#!/usr/bin/env bash
# test-public-content-workflow-shape.sh - static checks on the public-content workflow, its
# caller template and the pull request step of reusable-pr-quality.yml. A required check that
# can be skipped reports success, and a step's env block is printed in the public log, so the
# shape of these files is part of what the guard promises:
#
# - .github/workflows/reusable-public-content.yml exists, is called by workflow_call only (no
#   pull_request_target), and has exactly the jobs `public-content` and `public-content-text`;
# - neither job has a job-level `if:`, `needs:` or `continue-on-error`, and no step up to the last
#   one that runs scan.py has an `if:` or `continue-on-error`;
# - no `concurrency` with cancel-in-progress; every `permissions` value is read or none;
# - no env value (workflow, job or step) carries an expression other than a fixed allowlist, and
#   no `run:` interpolates `${{ }}`: event text reaches the scanner only through
#   GITHUB_EVENT_PATH;
# - it holds the same BEGIN/END public-content-ref-check block as reusable-pr-quality.yml;
# - templates/caller-public-content.yml triggers on exactly the events and action types the
#   event map handles that GitHub can trigger a workflow on (commit_comment is not one), lists
#   no event outside GitHub's documented workflow triggers, has no filters, and calls the
#   reusable workflow;
# - reusable-pr-quality.yml's public-content scan step no longer puts PR_TITLE/PR_BODY in env
#   and passes --event-path "$GITHUB_EVENT_PATH" to scan.py ci.
#
# Bash and `python3 -I` only (standard library: a small reader for the block-style YAML these
# files use, which refuses anything it does not understand); no network. Exit 0 all pass,
# 1 a check failed, 2 the harness could not run. Each check's "Red when:" line names the change
# that turns it red.

set -u -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/pcg-shape.XXXXXX")" || { echo "harness error: mktemp" >&2; exit 2; }
trap 'rm -rf "$WORK"' EXIT

echo "test-public-content-workflow-shape.sh"

cat >"$WORK/shape.py" <<'PYEOF'
import json, re, sys
from pathlib import Path

ROOT = Path(sys.argv[1])
REUSABLE = ROOT / ".github/workflows/reusable-public-content.yml"
TEMPLATE = ROOT / "templates/caller-public-content.yml"
PRQ = ROOT / ".github/workflows/reusable-pr-quality.yml"

# The events and action types the event map handles (scan.py event) that are workflow triggers,
# plus push and the pull_request actions the `public-content` job runs on (every one runs the
# full scan). commit_comment is not here: GitHub has no workflow trigger for it.
EXPECTED_ON = {
    "pull_request": ["opened", "synchronize", "reopened", "edited", "ready_for_review"],
    "push": None,
    "issues": ["opened", "edited"],
    "issue_comment": ["created", "edited"],
    "pull_request_review": ["submitted", "edited"],
    "pull_request_review_comment": ["created", "edited"],
    "discussion": ["created", "edited"],
    "discussion_comment": ["created", "edited"],
    "release": ["published", "edited"],
}
# GitHub's documented workflow triggers ("Events that trigger workflows") that carry public
# content this guard scans. A name outside it either is no workflow trigger at all (actionlint
# rejects commit_comment as an unknown webhook event, and the caller would never start) or is
# not this guard's job.
DOCUMENTED_TRIGGERS = {"pull_request", "push", "issues", "issue_comment", "pull_request_review",
                       "pull_request_review_comment", "discussion", "discussion_comment", "release"}
JOBS = ["public-content", "public-content-text"]
# The only expressions an env value may hold: none of them is text a person wrote.
ENV_OK = {"job.workflow_repository", "job.workflow_sha", "github.event_name", "github.event_path",
          "github.workspace", "github.repository", "runner.temp"}

PASS = FAIL = 0
def ok(name):
    global PASS
    PASS += 1
    print("  ok   " + name)
def bad(name, why):
    global FAIL
    FAIL += 1
    print("  FAIL %s - %s" % (name, why))

class YamlError(Exception):
    pass

# ------------------------------------------------------------------ a small block-YAML reader
def _strip_comment(s):
    q = None
    for i, ch in enumerate(s):
        if q:
            if ch == q:
                q = None
        elif ch in "'\"" and (i == 0 or s[i - 1] in " :[{,"):
            q = ch
        elif ch == "#" and (i == 0 or s[i - 1] in " \t"):
            return s[:i].rstrip()
    return s.rstrip()

def _unquote(s):
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] == "'":
        return s[1:-1].replace("''", "'")
    if len(s) >= 2 and s[0] == s[-1] == '"':
        return json.loads(s)
    return s

def _flow(s):
    s = s.strip()
    pos = [0]
    def ws():
        while pos[0] < len(s) and s[pos[0]] in " \t":
            pos[0] += 1
    def scalar(stops):
        ws()
        if pos[0] < len(s) and s[pos[0]] in "'\"":
            q = s[pos[0]]
            j = pos[0] + 1
            while j < len(s) and not (s[j] == q and not (q == "'" and s[j + 1:j + 2] == "'")):
                j += 2 if (q == "'" and s[j:j + 2] == "''") or (q == '"' and s[j] == "\\") else 1
            out = _unquote(s[pos[0]:j + 1])
            pos[0] = j + 1
            return out
        j = pos[0]
        while j < len(s) and s[j] not in stops:
            j += 1
        out = s[pos[0]:j].strip()
        pos[0] = j
        return out
    def value():
        ws()
        if s[pos[0]] == "[":
            pos[0] += 1
            out = []
            ws()
            if s[pos[0]] == "]":
                pos[0] += 1
                return out
            while True:
                out.append(value())
                ws()
                if s[pos[0]] == ",":
                    pos[0] += 1
                    continue
                if s[pos[0]] == "]":
                    pos[0] += 1
                    return out
                raise YamlError("bad flow sequence: " + s)
        if s[pos[0]] == "{":
            pos[0] += 1
            out = {}
            ws()
            if s[pos[0]] == "}":
                pos[0] += 1
                return out
            while True:
                k = scalar(":,}")
                ws()
                if s[pos[0]] != ":":
                    raise YamlError("bad flow mapping: " + s)
                pos[0] += 1
                out[k] = value()
                ws()
                if s[pos[0]] == ",":
                    pos[0] += 1
                    continue
                if s[pos[0]] == "}":
                    pos[0] += 1
                    return out
                raise YamlError("bad flow mapping: " + s)
        return scalar(",]}")
    try:
        out = value()
    except IndexError:
        raise YamlError("unterminated flow value: " + s)
    ws()
    if pos[0] != len(s):
        raise YamlError("trailing text after a flow value: " + s)
    return out

_KEY = re.compile(r"""^(?:"(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s'"#\[\]{}&*!|>%@`-][^:#]*?|-[^\s:#][^:#]*?)\s*:(?:\s|$)""")

class Reader:
    def __init__(self, text):
        if "\t" in "".join(l[:len(l) - len(l.lstrip())] for l in text.split("\n")):
            raise YamlError("a tab in indentation")
        self.L = text.split("\n")
        self.i = 0
    def skip(self):
        while self.i < len(self.L):
            t = self.L[self.i].strip()
            if t == "" or t.startswith("#") or t == "---":
                self.i += 1
            else:
                break
    @staticmethod
    def ind(line):
        return len(line) - len(line.lstrip(" "))
    def doc(self):
        out = self.node(0)
        self.skip()
        if self.i < len(self.L):
            raise YamlError("unexpected text at line %d" % (self.i + 1))
        return out
    def node(self, indent):
        self.skip()
        if self.i >= len(self.L):
            return None
        line = self.L[self.i]
        n = self.ind(line)
        if n < indent:
            return None
        body = line[n:]
        if body.startswith("- ") or body.rstrip() == "-":
            return self.seq(n)
        return self.map(n)
    def seq(self, n):
        out = []
        while True:
            self.skip()
            if self.i >= len(self.L):
                return out
            line = self.L[self.i]
            m = self.ind(line)
            body = line[m:]
            if m != n or not (body.startswith("- ") or body.rstrip() == "-"):
                if m > n:
                    raise YamlError("bad indentation at line %d" % (self.i + 1))
                return out
            rest = body[1:]
            stripped = rest.lstrip(" ")
            if _strip_comment(stripped) == "":
                self.i += 1
                out.append(self.node(n + 1))
                continue
            col = n + 1 + len(rest) - len(stripped)
            self.L[self.i] = " " * col + stripped
            if stripped.startswith("- "):
                out.append(self.seq(col))
            elif _KEY.match(stripped):
                out.append(self.map(col))
            else:
                self.i += 1
                out.append(self.value(_strip_comment(stripped), n))
    def map(self, n):
        out = {}
        while True:
            self.skip()
            if self.i >= len(self.L):
                return out
            line = self.L[self.i]
            m = self.ind(line)
            if m < n:
                return out
            if m > n:
                raise YamlError("bad indentation at line %d" % (self.i + 1))
            body = line[m:]
            if body.startswith("- "):
                return out
            km = _KEY.match(body)
            if not km:
                raise YamlError("not a mapping entry at line %d: %r" % (self.i + 1, body[:60]))
            key = _unquote(body[:km.end()].rstrip().rstrip(":").rstrip())
            rest = _strip_comment(body[km.end():]).strip()
            if key in out:
                raise YamlError("duplicate key %r at line %d" % (key, self.i + 1))
            self.i += 1
            if rest == "":
                self.skip()
                if self.i < len(self.L):
                    nl = self.L[self.i]
                    nm = self.ind(nl)
                    if nm == n and (nl[nm:].startswith("- ") or nl[nm:].rstrip() == "-"):
                        out[key] = self.seq(n)
                        continue
                out[key] = self.node(n + 1)
            else:
                out[key] = self.value(rest, n)
    def value(self, rest, parent):
        if rest[0] in "&*!":
            raise YamlError("anchors, aliases and tags are not supported (line %d)" % self.i)
        if rest[0] in "|>":
            if not re.fullmatch(r"[|>][+-]?", rest):
                raise YamlError("unsupported block scalar header %r" % rest)
            lines = []
            block = None
            while self.i < len(self.L):
                line = self.L[self.i]
                if line.strip() == "":
                    lines.append("")
                    self.i += 1
                    continue
                m = self.ind(line)
                if m <= parent:
                    break
                if block is None:
                    block = m
                if m < block:
                    break
                lines.append(line[block:])
                self.i += 1
            while lines and lines[-1] == "":
                lines.pop()
            return "\n".join(lines) + "\n"
        if rest[0] in "[{":
            buf = rest
            while buf.count("[") + buf.count("{") > buf.count("]") + buf.count("}") and self.i < len(self.L):
                buf += " " + _strip_comment(self.L[self.i]).strip()
                self.i += 1
            return _flow(buf)
        if rest[0] in "'\"":
            return _unquote(rest)
        # A plain scalar may continue on more-indented lines.
        parts = [rest]
        while self.i < len(self.L):
            line = self.L[self.i]
            if line.strip() == "" or self.ind(line) <= parent or line.strip().startswith("#"):
                break
            parts.append(_strip_comment(line).strip())
            self.i += 1
        return " ".join(parts)

def load(path):
    return Reader(path.read_text(encoding="utf-8")).doc()

def on_of(doc):
    # A YAML 1.1 reader would read the key `on` as true; this reader keeps it as "on".
    return doc.get("on") if isinstance(doc, dict) else None

def steps_of(job):
    s = job.get("steps") if isinstance(job, dict) else None
    return s if isinstance(s, list) else []

def is_scan(step):
    return isinstance(step, dict) and "scan.py" in str(step.get("run", ""))

def block(path, name):
    text = path.read_text(encoding="utf-8").split("\n")
    out, inside = [], False
    for ln in text:
        if ln.strip() == "# BEGIN " + name:
            inside = True
            continue
        if ln.strip() == "# END " + name:
            inside = False
            continue
        if inside:
            out.append(ln)
    if not out:
        return None
    cut = min(len(l) - len(l.lstrip()) for l in out if l.strip())
    return "\n".join(l[cut:] for l in out)

# ------------------------------------------------------------------ the reader reads the real files
print("== the YAML reader reads this repository's own workflows")
try:
    prq = load(PRQ)
    gate = prq["jobs"]["quality-gate"]
    # Red when: the reader mis-reads block scalars, sequences or nested mappings.
    if (isinstance(on_of(prq), dict) and "workflow_call" in on_of(prq)
            and any(is_scan(s) for s in steps_of(gate))
            and any(s.get("name") == "Check the public-content scanner's repository and commit" for s in steps_of(gate))):
        ok("reader: reusable-pr-quality.yml has workflow_call, the scan step and the ref check step")
    else:
        bad("reader: reusable-pr-quality.yml has workflow_call, the scan step and the ref check step", "not found")
    lint = load(ROOT / ".github/workflows/self-lint.yml")
    conc = lint.get("concurrency", {})
    # Red when: the reader drops a nested mapping value (partner of the concurrency check below).
    if str(conc.get("cancel-in-progress")).lower() == "true" and lint["permissions"] == {"contents": "read"}:
        ok("reader: self-lint.yml's concurrency and permissions are read")
    else:
        bad("reader: self-lint.yml's concurrency and permissions are read", repr(conc))
    tpl = load(ROOT / "templates/caller-pr-quality.yml")
    # Red when: the reader mis-reads a flow sequence of action types.
    if on_of(tpl) == {"pull_request": {"types": ["opened", "synchronize", "reopened", "ready_for_review"]}}:
        ok("reader: caller-pr-quality.yml's trigger types are read")
    else:
        bad("reader: caller-pr-quality.yml's trigger types are read", repr(on_of(tpl)))
except (YamlError, KeyError, TypeError, OSError) as exc:
    print("harness error: the YAML reader could not read this repository's own workflows: %s" % exc)
    sys.exit(2)

# ------------------------------------------------------------------ the reusable workflow
print("== .github/workflows/reusable-public-content.yml")
wf = None
if not REUSABLE.is_file():
    # Red when: the reusable workflow is missing or renamed.
    bad("shape: reusable-public-content.yml exists", "missing")
else:
    ok("shape: reusable-public-content.yml exists")
    try:
        wf = load(REUSABLE)
    except YamlError as exc:
        bad("shape: reusable-public-content.yml is readable", str(exc))

if isinstance(wf, dict):
    on = on_of(wf)
    # Red when: the workflow can be triggered by anything but workflow_call (pull_request_target included).
    if isinstance(on, dict) and list(on) == ["workflow_call"]:
        ok("shape: triggered by workflow_call only")
    else:
        bad("shape: triggered by workflow_call only", "on = %r" % (on,))
    raw = REUSABLE.read_text(encoding="utf-8")
    # Red when: pull_request_target appears anywhere outside a comment.
    if any("pull_request_target" in _strip_comment(l) for l in raw.split("\n")):
        bad("shape: no pull_request_target", "found")
    else:
        ok("shape: no pull_request_target")
    jobs = wf.get("jobs") if isinstance(wf.get("jobs"), dict) else {}
    # Red when: a job is added, removed or renamed (a ruleset requires the name `public-content`).
    if sorted(jobs) == sorted(JOBS) and all(str(jobs[j].get("name", j)) == j for j in jobs):
        ok("shape: jobs are exactly public-content and public-content-text, named as their ids")
    else:
        bad("shape: jobs are exactly public-content and public-content-text, named as their ids",
            "jobs = %r" % {j: (v or {}).get("name") for j, v in jobs.items()})
    for j in JOBS:
        job = jobs.get(j)
        if not isinstance(job, dict):
            bad("shape: job %s exists" % j, "missing")
            continue
        for key in ("if", "needs", "continue-on-error"):
            # Red when: the job gets this key (a skipped or tolerated required job reports success).
            if key in job:
                bad("shape: job %s has no %s" % (j, key), repr(job[key]))
            else:
                ok("shape: job %s has no %s" % (j, key))
        steps = steps_of(job)
        last = max([n for n, s in enumerate(steps) if is_scan(s)], default=-1)
        # Red when: the job no longer runs scan.py.
        if last < 0:
            bad("shape: job %s runs scan.py" % j, "no step runs scan.py")
            continue
        ok("shape: job %s runs scan.py" % j)
        guarded = [str(s.get("name", n)) for n, s in enumerate(steps[:last + 1])
                   if isinstance(s, dict) and ("if" in s or "continue-on-error" in s)]
        # Red when: a step up to the scan gets `if:` or `continue-on-error` (it could skip or excuse the scan).
        if guarded:
            bad("shape: job %s has no if/continue-on-error up to its scan" % j, ", ".join(guarded))
        else:
            ok("shape: job %s has no if/continue-on-error up to its scan" % j)

    # concurrency, permissions, env, run
    concs = [("workflow", wf.get("concurrency"))] + [(j, (jobs.get(j) or {}).get("concurrency")) for j in jobs]
    cancel = [w for w, c in concs if c is not None and (not isinstance(c, dict) or str(c.get("cancel-in-progress", "false")).lower() != "false")]
    # Red when: a concurrency group can cancel a running scan (a cancelled required run is not red).
    if cancel:
        bad("shape: no concurrency with cancel-in-progress", ", ".join(cancel))
    else:
        ok("shape: no concurrency with cancel-in-progress")
    perms = [("workflow", wf.get("permissions"))] + [(j, (jobs.get(j) or {}).get("permissions")) for j in jobs]
    def read_only(p):
        if p in ("read-all", {}):
            return True
        return isinstance(p, dict) and all(str(v) in ("read", "none") for v in p.values())
    wrong = [w for w, p in perms if p is not None and not read_only(p)]
    unset = [j for j in jobs if wf.get("permissions") is None and (jobs.get(j) or {}).get("permissions") is None]
    # Red when: any permission is write, or a job runs with the caller's default token permissions.
    if wrong or unset:
        bad("shape: permissions are read-only and set for every job", "write: %r, unset: %r" % (wrong, unset))
    else:
        ok("shape: permissions are read-only and set for every job")
    envs = [("workflow", wf.get("env"))]
    runs = []
    for j, job in jobs.items():
        envs.append((j, (job or {}).get("env")))
        for n, s in enumerate(steps_of(job)):
            if isinstance(s, dict):
                envs.append(("%s step %s" % (j, s.get("name", n)), s.get("env")))
                if "run" in s:
                    runs.append(("%s step %s" % (j, s.get("name", n)), str(s["run"])))
    leaky = []
    for where, env in envs:
        if env is None:
            continue
        if not isinstance(env, dict):
            leaky.append("%s (env is not a mapping)" % where)
            continue
        for k, v in env.items():
            for expr in re.findall(r"\$\{\{(.*?)\}\}", str(v), re.S):
                if expr.strip() not in ENV_OK:
                    leaky.append("%s %s" % (where, k))
    # Red when: an env value carries event text (title, body, comment) or any expression outside the allowlist.
    if leaky:
        bad("shape: no env value carries event text", ", ".join(leaky))
    else:
        ok("shape: no env value carries event text")
    interp = [w for w, r in runs if "${{" in r]
    # Red when: a run block interpolates an expression (event text would become shell code).
    if interp:
        bad("shape: no run block interpolates ${{ }}", ", ".join(interp))
    else:
        ok("shape: no run block interpolates ${{ }}")
    # Red when: no step reads the event file (the scan would have no event text to read).
    if any("GITHUB_EVENT_PATH" in r for _w, r in runs):
        ok("shape: a step reads GITHUB_EVENT_PATH")
    else:
        bad("shape: a step reads GITHUB_EVENT_PATH", "not found")
    mine, theirs = block(REUSABLE, "public-content-ref-check"), block(PRQ, "public-content-ref-check")
    # Red when: the scanner ref check is missing or differs from reusable-pr-quality.yml's copy.
    if theirs is None:
        print("harness error: reusable-pr-quality.yml has no public-content-ref-check block")
        sys.exit(2)
    if mine == theirs:
        ok("shape: the public-content-ref-check block matches reusable-pr-quality.yml")
    else:
        bad("shape: the public-content-ref-check block matches reusable-pr-quality.yml",
            "missing" if mine is None else "differs")

# ------------------------------------------------------------------ the caller template
print("== templates/caller-public-content.yml")
if not TEMPLATE.is_file():
    # Red when: the caller template is missing or renamed.
    bad("template: caller-public-content.yml exists", "missing")
else:
    ok("template: caller-public-content.yml exists")
    try:
        tpl = load(TEMPLATE)
        on = on_of(tpl)
        got = {}
        problems = []
        for ev, spec in (on or {}).items():
            if spec in (None, {}):
                got[ev] = None
            elif isinstance(spec, dict) and list(spec) == ["types"] and isinstance(spec["types"], list):
                got[ev] = spec["types"]
            else:
                problems.append("%s has filters or an odd shape: %r" % (ev, spec))
        missing = sorted(set(EXPECTED_ON) - set(got))
        extra = sorted(set(got) - set(EXPECTED_ON))
        diff = [ev for ev in EXPECTED_ON if ev in got and sorted(got[ev] or []) != sorted(EXPECTED_ON[ev] or [])]
        # Red when: the template drops or adds an event or action type, or filters one (branches, paths, tags).
        if isinstance(on, dict) and not (missing or extra or diff or problems):
            ok("template: triggers on exactly the handled events and action types")
        else:
            bad("template: triggers on exactly the handled events and action types",
                "missing %r, extra %r, different types %r, %s" % (missing, extra, diff, "; ".join(problems)))
        undocumented = sorted(set(on or {}) - DOCUMENTED_TRIGGERS)
        # Red when: the template lists an event that is not a documented workflow trigger for this
        # guard (commit_comment included: GitHub has no such workflow trigger).
        if isinstance(on, dict) and on and not undocumented:
            ok("template: lists only documented workflow triggers")
        else:
            bad("template: lists only documented workflow triggers", "not documented %r" % undocumented)
        uses = [str(j.get("uses", "")) for j in (tpl.get("jobs") or {}).values() if isinstance(j, dict)]
        conds = [k for k, j in (tpl.get("jobs") or {}).items() if isinstance(j, dict) and "if" in j]
        # Red when: the template does not call the reusable workflow, or skips it with a job `if:` (drafts included).
        if any(re.match(r"imrohitagrawal/\.github/\.github/workflows/reusable-public-content\.yml@[0-9a-f]{40}( |$)", u) for u in uses) and not conds:
            ok("template: calls reusable-public-content.yml by commit sha, with no job if:")
        else:
            bad("template: calls reusable-public-content.yml by commit sha, with no job if:", "uses %r, if on %r" % (uses, conds))
    except YamlError as exc:
        bad("template: caller-public-content.yml is readable", str(exc))

# ------------------------------------------------------------------ reusable-pr-quality.yml's PR step
print("== reusable-pr-quality.yml's public-content scan step")
scan_steps = [s for s in steps_of(prq["jobs"]["quality-gate"]) if is_scan(s)]
if len(scan_steps) != 1:
    bad("pr-quality: exactly one step runs scan.py", "found %d" % len(scan_steps))
else:
    s = scan_steps[0]
    env = s.get("env") or {}
    # Red when: PR_TITLE or PR_BODY is still passed through env (their values are printed in the public log).
    if "PR_TITLE" in env or "PR_BODY" in env:
        bad("pr-quality: the scan step has no PR_TITLE/PR_BODY in env", "still there")
    else:
        ok("pr-quality: the scan step has no PR_TITLE/PR_BODY in env")
    leaky = [k for k, v in env.items() if any(e.strip() not in ENV_OK | {"github.event.pull_request.base.sha", "github.event.pull_request.head.sha"}
                                                for e in re.findall(r"\$\{\{(.*?)\}\}", str(v), re.S))]
    # Red when: other event text (not the base and head shas) is passed through env instead.
    if leaky:
        bad("pr-quality: the scan step's env holds no other event text", ", ".join(leaky))
    else:
        ok("pr-quality: the scan step's env holds no other event text")
    # Red when: scan.py ci is not given the event file.
    if re.search(r"""--event-path\s+"?\$GITHUB_EVENT_PATH"?""", str(s.get("run", ""))):
        ok("pr-quality: the scan step passes --event-path \"$GITHUB_EVENT_PATH\"")
    else:
        bad("pr-quality: the scan step passes --event-path \"$GITHUB_EVENT_PATH\"", "not found")

# The scanner is checked out from the workflow's own repository and commit, and only after the
# step that refuses an empty one: if either context were empty, actions/checkout would fall back
# to the caller's own tree, which would then supply its own scanner.
TOLERATE = re.compile(r"\|\|\s*(?:true|:)(?![\w-])|;\s*(?:true|:)\s*$|\bset\s+[-+]?\w*\+e|\bset\s+\+\w*e|\|\|\s*exit\s+0\b")
if isinstance(wf, dict):
    for j in JOBS:
        steps = steps_of(jobs.get(j))
        scanner = [n for n, st in enumerate(steps) if isinstance(st, dict)
                   and str(st.get("uses", "")).startswith("actions/checkout@")
                   and isinstance(st.get("with"), dict) and st["with"].get("path") == ".public-content-scanner"]
        checks = [n for n, st in enumerate(steps) if isinstance(st, dict)
                  and re.search(r'(?m)^\s*check_public_content_ref "\$WORKFLOW_REPOSITORY" "\$WORKFLOW_SHA"\s*$', str(st.get("run", "")))
                  and (st.get("env") or {}).get("WORKFLOW_REPOSITORY") == "${{ job.workflow_repository }}"
                  and (st.get("env") or {}).get("WORKFLOW_SHA") == "${{ job.workflow_sha }}"]
        # Red when: the ref check is removed, stops being called, or moves after the scanner checkout.
        if len(scanner) == 1 and checks and min(checks) < scanner[0]:
            ok("shape: job %s runs the ref check before the scanner checkout" % j)
        else:
            bad("shape: job %s runs the ref check before the scanner checkout" % j,
                "scanner checkouts at %r, ref checks at %r" % (scanner, checks))
        w = steps[scanner[0]]["with"] if len(scanner) == 1 else {}
        # Red when: the scanner checkout's repository or ref is changed (or dropped, which falls back to the caller's tree).
        if w.get("repository") == "${{ job.workflow_repository }}" and w.get("ref") == "${{ job.workflow_sha }}":
            ok("shape: job %s checks the scanner out from job.workflow_repository at job.workflow_sha" % j)
        else:
            bad("shape: job %s checks the scanner out from job.workflow_repository at job.workflow_sha" % j,
                "repository=%r ref=%r" % (w.get("repository"), w.get("ref")))
        tolerant = [ln.strip() for st in steps if is_scan(st)
                    for ln in str(st.get("run", "")).split("\n") if TOLERATE.search(_strip_comment(ln))]
        # Red when: a scan step tolerates a failure (`|| true`, `|| :`, `; true`, `set +e`, `|| exit 0`).
        if tolerant:
            bad("shape: job %s's scan step never tolerates a failure" % j, tolerant[0])
        else:
            ok("shape: job %s's scan step never tolerates a failure" % j)

# The clean line is printed by scan.py after a real scan only: a workflow that echoes it would
# print "clean" after a private repository's "not a public repository" notice too.
for label, path in (("reusable", REUSABLE), ("pr-quality", PRQ)):
    echoed = [ln for ln in path.read_text(encoding="utf-8").splitlines()
              if re.search(r"\becho\b.*scanned this pull request", ln)]
    # Red when: a workflow echoes the pull request clean line itself instead of leaving it to scan.py.
    if echoed:
        bad("%s: no step echoes the pull request clean line" % label, echoed[0].strip())
    else:
        ok("%s: no step echoes the pull request clean line" % label)

print()
print("%d passed, %d failed, 0 skipped" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
PYEOF

python3 -I "$WORK/shape.py" "$ROOT"
