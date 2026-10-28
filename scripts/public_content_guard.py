#!/usr/bin/env python3
"""Claude Code PreToolUse hook: scan what an agent is about to publish to a PUBLIC repo.

WHAT IT GUARDS. Accidental leaks by an AI agent: secrets (gitleaks' default rules), plus
content that is not a credential but must not be public (home-folder paths, personal email
addresses, session transcripts, private terms such as private project names). See
docs/public-content-guard.md for the channels, the rules and what is NOT covered.

HOW IT DECIDES WHAT TO SCAN. It does not try to parse shell. If a publishing command
(`git ... push`, or a `gh` command that writes) appears ANYWHERE in a Bash call, the call
is a publication and its WHOLE text is scanned, together with every file it names. A body
file that is named but cannot be read blocks the call. Parsing is used only to find where
something is published (which remote, which repository), never to decide whether to scan;
a destination it cannot work out counts as public.

A push is scanned as what it publishes: the commits on the pushed refs that the
destination does not have yet, their content, their commit messages and their file names.
Commit author and committer identities are not scanned (they are public on every commit
already). Making a repository public (`gh repo edit --visibility public`) scans its whole
history.

Any finding, or any failure while checking a publication, DENIES the call; the reason names
rules and places, never the matched text, and masks private terms in file names. Calls that
publish nothing exit at once with no output.

Standard library only; needs `gitleaks` and, to learn a repo's visibility, `gh`.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PUBLIC_CONFIG = HERE.parent / "public-content" / "gitleaks-public.toml"
CACHE = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "public-content-guard"
VISIBILITY_TTL = 24 * 3600
MAX_FILE = 2 * 1024 * 1024

#: `git [global options] push` on one line.
_PUSH = re.compile(r"(?m)\bgit\b(?:[ \t]+(?:-C|-c|--git-dir|--work-tree)[ \t]+\S+|[ \t]+-\S+)*[ \t]+push\b(?P<rest>[^\n;&|]*)")
#: `gh [global options] <group> <sub>` on one line.
_GH = re.compile(r"(?m)\bgh\b(?:[ \t]+-\S+(?:[ \t]+[^\s-]\S*)?)*[ \t]+(?P<group>pr|issue|release|gist|repo|api)\b(?P<rest>[^\n]*)")
_GH_WRITE = {
    "pr": {"create", "edit", "comment", "review", "merge", "close", "reopen"},
    "issue": {"create", "edit", "comment", "close", "reopen", "transfer"},
    "release": {"create", "edit", "upload"},
    "gist": {"create", "edit"},
    "repo": {"create", "edit"},
}
_BODY_FLAGS = ("--body-file", "-F", "--notes-file", "--input")
_TOKEN = re.compile(r'"((?:[^"\\]|\\.)*)"|\'([^\']*)\'|(\S+)')

_GITHUB_TOOL = re.compile(r"^mcp__(?:plugin_[^_]*_)?github[^_]*__(?P<tool>.+)$")
_MCP_READ = re.compile(r"^(get_|list_|search_|issue_read$|pull_request_read$|run_secret_scanning$)")


# --------------------------------------------------------------------------- helpers


def _git(directory: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(directory), *args], capture_output=True, text=True, check=False
    ).stdout.strip()


def _tokens(text: str) -> list[str]:
    return [a or b or c for a, b, c in _TOKEN.findall(text)]


def _command_tokens(rest: str) -> list[str] | None:
    """The words of ONE command, by shell quoting rules, up to the first `;`, `&` or `|`
    outside quotes. None when the quoting cannot be read (the caller then assumes the
    worst: an unknown, so public, destination)."""
    try:
        lexer = shlex.shlex(rest, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        out = []
        for tok in lexer:
            if tok and set(tok) <= set(";&|"):
                break
            out.append(tok)
        return out
    except ValueError:
        return None


def _assignments(text: str) -> dict[str, str]:
    """`NAME=value` assignments written in the command itself (so `B=x; ... "$B"` works)."""
    env = dict(os.environ)
    for name, value in re.findall(r"(?:^|[\s;&|(])([A-Za-z_][A-Za-z0-9_]*)=(\"[^\"]*\"|'[^']*'|\S+)", text):
        env[name] = value.strip("\"'")
    return env


def _expand(word: str, env: dict[str, str]) -> str:
    def sub(m: re.Match[str]) -> str:
        return env.get(m.group(1) or m.group(2), m.group(0))

    return os.path.expanduser(re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)", sub, word))


def _dirs(text: str, cwd: Path, env: dict[str, str]) -> list[Path]:
    """The folders a command may run in: the cwd, every `cd X`, every `git -C X`."""
    found = [cwd]
    for m in re.finditer(r"(?:\bcd|\bpushd|\bgit[ \t]+-C)[ \t]+(\"[^\"]*\"|'[^']*'|[^\s;&|)]+)", text):
        p = Path(_expand(m.group(1).strip("\"'"), env))
        found.append(p if p.is_absolute() else cwd / p)
    return [d for d in dict.fromkeys(found)]


def _slug(url: str) -> str | None:
    m = re.search(r"github\.com[:/]([^/\s]+/[^/\s]+?)(?:\.git)?/?$", url.strip())
    return m.group(1) if m else None


def _flag_value(toks: list[str], *names: str) -> str | None:
    """The value of the LAST `--name value` / `--name=value` among parsed tokens (a
    quoted body is one token, so a flag written inside it is never read)."""
    value = None
    for i, tok in enumerate(toks):
        for name in names:
            if tok == name and i + 1 < len(toks):
                value = toks[i + 1]
            elif tok.startswith(name + "="):
                value = tok.split("=", 1)[1]
    return value


def _named_file(word: str, dirs: list[Path], env: dict[str, str]) -> tuple[Path | None, bool]:
    """(file, too_big) for a word that names an existing file."""
    w = _expand(word, env)
    for d in dirs:
        q = Path(w) if Path(w).is_absolute() else d / w
        try:
            if q.is_file():
                return q, q.stat().st_size > MAX_FILE
        except OSError:
            continue
    return None, False


def _push_aliases(dirs: list[Path]) -> set[str]:
    """git aliases (in the repos the call runs in) that run `push`."""
    names: set[str] = set()
    for d in dirs:
        if not d.is_dir():
            continue
        for line in _git(d, "config", "--get-regexp", r"^alias\.").splitlines():
            key, _, value = line.partition(" ")
            if re.search(r"\bpush\b", value):
                names.add(key.split(".", 1)[1])
    return names


def _local_clone(dirs: list[Path], repo: str | None) -> Path | None:
    """The local clone of `repo` among dirs (or, with no repo named, the nearest)."""
    for d in reversed(dirs):
        top = _git(d, "rev-parse", "--show-toplevel") if d.is_dir() else ""
        if top and (repo is None or _slug(_git(Path(top), "remote", "get-url", "origin")) == repo):
            return Path(top)
    return None


def classify_bash(text: str, cwd: Path) -> list[dict[str, object]]:
    pubs: list[dict[str, object]] = []
    env = _assignments(text)
    all_dirs = _dirs(text, cwd, env)

    repos: list[str | None] = []
    unreadable: list[str] = []
    files: list[Path] = []
    pos, matches = 0, []
    while (found := _GH.search(text, pos)) is not None:
        matches.append(found)
        pos = found.end("group")  # keep looking INSIDE the rest of the line: two gh calls can share one
    for m in matches:
        group, rest = m.group("group"), m.group("rest")
        dirs = _dirs(text[: m.start()], cwd, env)  # where THIS command runs
        parsed = _command_tokens(rest)
        toks = parsed if parsed is not None else _tokens(rest)
        words = [w for w in toks if not w.startswith("-")]
        sub = words[0] if words else ""
        flip = False
        if group == "api":
            # gh's own rule: an explicit GET (any spelling, including -XGET) is a read even
            # with fields (they become query parameters); with no method, fields mean POST;
            # no method and no fields is a GET. Any other method is a write.
            methods = [
                (toks[i + 1] if tk in {"-X", "--method"} and i + 1 < len(toks) else tk[2:] if tk.startswith("-X") else tk.split("=", 1)[1] if tk.startswith("--method=") else "")
                for i, tk in enumerate(toks)
            ]
            method = next((x.upper() for x in reversed(methods) if x), "")
            fields = any(tk in {"-f", "-F", "--field", "--raw-field", "--input"} or re.match(r"^(-[fF].|--(?:field|raw-field|input)=)", tk) for tk in toks)
            if method == "GET" or (not method and not fields):
                continue
            endpoint = next((tk for tk in toks[0:1] if not tk.startswith("-")), "")
            r = re.match(r"^/?repos/([^/\s]+/[^/\s?]+)", endpoint)
            repo = r.group(1) if (r and parsed is not None) else "unknown"  # never origin
            flip = bool(re.search(r"(?:visibility=public|private=false)\b", " ".join(toks)))
        elif sub not in _GH_WRITE.get(group, set()):
            continue
        else:
            repo = _flag_value(toks, "-R", "--repo") if parsed is not None else "unknown"
            if group == "gist":
                repo = "gist"
            if group == "repo" and len(words) > 1 and "/" in words[1]:
                repo = words[1]
            if group == "repo" and sub == "edit":
                flip = (_flag_value(toks, "--visibility") or "").lower() == "public"
        if repo is None:  # gh's default: the repository of the folder this command runs in
            repo = _slug(_git(dirs[-1], "remote", "get-url", "origin")) or "unknown"
        repos.append(repo)
        body_words = [v for v in (_flag_value(toks, f) for f in _BODY_FLAGS) if v]
        body_words += [tk.split("=@", 1)[1] for tk in toks if "=@" in tk]
        if group == "gist":
            body_words += words[1:]  # the gist's files
        for w in body_words:
            if w == "-":
                continue
            found, too_big = _named_file(w, dirs, env)
            if found is None or too_big:
                unreadable.append(w if found is None else f"{w} (too large to check)")
        if flip:
            pubs.append({"kind": "history", "dir": _local_clone(dirs, repo if repo not in {None, "unknown"} else None), "repo": repo or "unknown"})
        if group == "repo" and sub == "create" and "--push" in toks:
            src = _flag_value(toks, "--source") or "."
            sdir = Path(_expand(src, env))
            pubs.append({"kind": "history", "dir": sdir if sdir.is_absolute() else dirs[-1] / sdir, "repo": repo or "unknown"})

    if repos:
        for w in _tokens(text):
            found, too_big = _named_file(w.split("=", 1)[-1].lstrip("@"), all_dirs, env)
            if found is not None and not too_big:
                files.append(found)
        body = "\n".join([text] + [f.read_text(encoding="utf-8", errors="replace") for f in dict.fromkeys(files)])
        pubs.append({"kind": "text", "dirs": all_dirs, "repos": repos, "text": body, "unreadable": unreadable})

    aliases = _push_aliases(all_dirs)
    push_re = _PUSH if not aliases else re.compile(
        _PUSH.pattern.replace(r"push\b", "(?:push|" + "|".join(map(re.escape, sorted(aliases))) + r")\b")
    )
    for m in push_re.finditer(text):
        dirs = _dirs(text[: m.start()], cwd, env)  # the cd / -C BEFORE this push
        line_start = text.rfind("\n", 0, m.start()) + 1
        head = text[line_start : m.start("rest")]
        cdir = re.search(r"-C[ \t]+(\S+)", head)
        pdir = Path(_expand(cdir.group(1).strip("\"'"), env)) if cdir else None
        if pdir is not None and not pdir.is_absolute():
            pdir = dirs[-1] / pdir
        pubs.append({"kind": "push", "dir": pdir or dirs[-1], "rest": m.group("rest"), "env": env})
    return pubs


def classify(payload: dict[str, object]) -> list[dict[str, object]]:
    tool = str(payload.get("tool_name") or "")
    tool_input = payload.get("tool_input") or {}
    cwd = Path(str(payload.get("cwd") or os.getcwd()))
    if not isinstance(tool_input, dict):
        return []
    if tool == "Bash":
        return classify_bash(str(tool_input.get("command") or ""), cwd)
    m = _GITHUB_TOOL.match(tool)
    if m and not _MCP_READ.match(m.group("tool")):
        owner, name = tool_input.get("owner"), tool_input.get("repo") or tool_input.get("name")
        repo = f"{owner}/{name}" if owner and name else None
        if tool_input.get("private") is False or m.group("tool") == "create_gist":
            repo = "unknown"
        return [{"kind": "text", "dirs": [cwd], "repos": [repo or "unknown"], "text": "\n".join(_strings(tool_input)), "unreadable": []}]
    return []


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


# --------------------------------------------------------------------------- push range


def push_target(pub: dict[str, object]) -> tuple[str | None, str | None, list[str]]:
    """(remote name or None, destination owner/name or None, log-opts for the commits
    this push publishes)."""
    directory = Path(str(pub["dir"]))
    env = pub["env"] if isinstance(pub["env"], dict) else {}
    words = [_expand(w, env) for w in _tokens(str(pub["rest"]))]
    flags = {w for w in words if w.startswith("-")}
    positional: list[str] = []
    skip = False
    for i, w in enumerate(words):
        if skip:
            skip = False
        elif w in {"-o", "--push-option", "--receive-pack", "--exec", "--repo"}:
            skip = True
            if w == "--repo" and i + 1 < len(words):
                positional.insert(0, words[i + 1])
        elif w.startswith("--repo="):
            positional.insert(0, w.split("=", 1)[1])
        elif not w.startswith("-"):
            positional.append(w)
    remote = positional[0] if positional else None
    refspecs = positional[1:]
    if remote is None:
        # git's own order for a bare `git push` (@{push} is empty until the push remote
        # has a tracking branch, so it cannot be relied on).
        branch = _git(directory, "symbolic-ref", "--short", "-q", "HEAD")
        remote = (
            (branch and _git(directory, "config", f"branch.{branch}.pushRemote"))
            or _git(directory, "config", "remote.pushDefault")
            or (branch and _git(directory, "config", f"branch.{branch}.remote"))
            or "origin"
        )
    is_url = bool(re.search(r"[:/]", remote))
    url = remote if is_url else _git(directory, "remote", "get-url", "--push", remote)
    slug = _slug(url)
    if "--mirror" in flags or "--all" in flags:
        sources = ["--all"] if "--mirror" in flags else ["--branches"]
    else:
        wanted = [s.lstrip("+").split(":", 1)[0] for s in refspecs] or ["HEAD"]
        sources = []
        for src in (w for w in wanted if w):  # an empty source deletes a ref: nothing published
            sha = _git(directory, "rev-parse", "--verify", "-q", "--end-of-options", f"{src}^{{commit}}")
            if not re.fullmatch(r"[0-9a-f]{40,64}", sha):
                raise ValueError(f"cannot resolve the pushed ref {src!r}")
            sources.append(sha)  # only hashes reach git log: no option can be smuggled in
    if "--tags" in flags or "--follow-tags" in flags:
        sources.append("--tags")
    has_tracking = not is_url and bool(_git(directory, "for-each-ref", "--count=1", f"refs/remotes/{remote}"))
    exclude = ["--not", f"--remotes={remote}"] if has_tracking else []
    return (None if is_url else remote), slug, sources + exclude


# --------------------------------------------------------------------------- visibility


def visibility(repo: str | None) -> str:
    """PUBLIC, PRIVATE or INTERNAL; anything unknown counts as PUBLIC. The test override
    can only make things stricter (PUBLIC), never switch the guard off."""
    if os.environ.get("PUBLIC_CONTENT_GUARD_VISIBILITY", "").upper() == "PUBLIC":
        return "PUBLIC"
    if not repo or repo in {"gist", "unknown"} or "/" not in repo:
        return "PUBLIC"
    CACHE.mkdir(parents=True, exist_ok=True)
    cache_file = CACHE / "visibility.json"
    try:
        cache = json.loads(cache_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        cache = {}
    hit = cache.get(repo)
    # Only PUBLIC is cached: a cached "private" would hide a repo made public since.
    if hit and hit.get("v") == "PUBLIC" and time.time() - hit.get("at", 0) < VISIBILITY_TTL:
        return "PUBLIC"
    try:
        r = subprocess.run(
            ["gh", "repo", "view", repo, "--json", "visibility", "--jq", ".visibility"],
            capture_output=True, text=True, check=False, timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "PUBLIC"
    seen = r.stdout.strip().upper()
    if r.returncode != 0 or seen not in {"PUBLIC", "PRIVATE", "INTERNAL"}:
        return "PUBLIC"
    if seen == "PUBLIC":
        cache[repo] = {"v": seen, "at": time.time()}
        cache_file.write_text(json.dumps(cache), encoding="utf-8")
    return seen


# --------------------------------------------------------------------------- scan


def private_terms() -> tuple[list[str], str | None]:
    base = os.environ.get("PRIVATE_NOTES_DIR")
    if not base:
        return [], "PRIVATE_NOTES_DIR is not set, so private terms were NOT checked"
    path = Path(os.path.expanduser(base)) / "scanner" / "private-terms.txt"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return [], "the private term list could not be read, so private terms were NOT checked"
    terms = [t.strip() for t in lines if t.strip() and not t.lstrip().startswith("#")]
    if not terms:
        return [], "the private term list is empty, so private terms were NOT checked"
    return terms, None


def _term_pattern(terms: list[str]) -> str:
    """Each term, with `-`, `_`, `.` or a space allowed between its words."""
    parts = ["[-_. ]?".join(re.escape(w) for w in re.split(r"[-_. ]+", t) if w) for t in terms]
    return "(?i)(?:^|[^A-Za-z0-9])(?:" + "|".join(p for p in parts if p) + ")(?:[^A-Za-z0-9]|$)"


def _configs(work: Path, terms: list[str]) -> list[Path]:
    """Two configs, run as two passes: gitleaks' default secret rules, and the public
    content rules plus the private term. Not one layered config: the defaults' global
    allowlist silently drops matches containing /home/ (measured, gitleaks 8.30.1)."""
    secrets = work / "secrets.toml"
    secrets.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
    lines = [f'[extend]\npath = "{PUBLIC_CONFIG}"\n']
    if terms:
        lines.append(
            '[[rules]]\nid = "private-term"\ndescription = "a private term"\n'
            f"regex = '''{_term_pattern(terms)}'''\n"
        )
    content = work / "content.toml"
    content.write_text("\n".join(lines), encoding="utf-8")
    return [secrets, content]


def _gitleaks(args: list[str], cfg: Path, stdin: str | None, cwd: Path) -> list[dict[str, object]]:
    r = subprocess.run(
        ["gitleaks", *args, "--config", str(cfg), "--redact", "--no-banner",
         "--ignore-gitleaks-allow", "--report-format", "json", "--report-path", "-",
         "--exit-code", "0"],
        input=stdin, capture_output=True, text=True, check=False, cwd=str(cwd), timeout=150,
    )
    if r.returncode != 0:
        raise RuntimeError(f"gitleaks exited {r.returncode}")
    return json.loads(r.stdout or "[]")


def _where(f: dict[str, object], terms: list[str], label: str) -> str:
    place = f"{f.get('File') or label}:{f.get('StartLine', '?')}"
    if f.get("Commit"):
        place += f" (commit {str(f['Commit'])[:10]})"
    if terms:
        place = re.sub(_term_pattern(terms), "<private>", place)
    return f"{f.get('RuleID')} at {place}"


def scan_text(text: str, cwd: Path, terms: list[str], label: str) -> list[str]:
    CACHE.mkdir(parents=True, exist_ok=True)
    os.chmod(CACHE, 0o700)
    with tempfile.TemporaryDirectory(dir=CACHE) as tmp:
        found = [f for cfg in _configs(Path(tmp), terms) for f in _gitleaks(["stdin"], cfg, text, cwd)]
    return [_where(f, terms, label) for f in found]


def scan_commits(directory: Path, log_opts: list[str], terms: list[str]) -> list[str]:
    """Content of the commits, then their messages and file names (gitleaks' git mode
    reads neither)."""
    if not log_opts:
        return []
    CACHE.mkdir(parents=True, exist_ok=True)
    os.chmod(CACHE, 0o700)
    with tempfile.TemporaryDirectory(dir=CACHE) as tmp:
        found = []
        for cfg in _configs(Path(tmp), terms):
            found += _gitleaks(["git", "--log-opts=" + " ".join(log_opts), "."], cfg, None, directory)
    meta = subprocess.run(
        ["git", "-C", str(directory), "log", "--format=%n%B", "--name-only", *log_opts],
        capture_output=True, text=True, check=False,
    ).stdout
    out = [_where(f, terms, "commit") for f in found]
    if meta.strip():
        out += [x.replace(" at text:", " at commit message or file name, line ") for x in scan_text(meta, directory, terms, "text")]
    return out


# --------------------------------------------------------------------------- hook


def _deny(reason: str) -> dict[str, object]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def decide(payload: dict[str, object]) -> dict[str, object] | None:
    pubs = classify(payload)
    if not pubs:
        return None
    terms, warn = private_terms()
    findings: list[str] = []
    blocked: list[str] = []
    checked_public = False
    for pub in pubs:
        if pub["kind"] == "text":
            dirs = pub["dirs"] if isinstance(pub["dirs"], list) else []
            targets = pub["repos"] if isinstance(pub["repos"], list) else [None]
            # Scan if ANY destination in the call is public or unknown.
            if all(visibility(str(r) if r else None) != "PUBLIC" for r in targets):
                continue
            checked_public = True
            for path in pub["unreadable"] if isinstance(pub["unreadable"], list) else []:
                blocked.append(f"the body file {path!r} could not be read, so it could not be checked")
            findings += scan_text(str(pub["text"]), Path(str(dirs[-1] if dirs else ".")), terms, "text")
        elif pub["kind"] == "push":
            _, slug, log_opts = push_target(pub)
            if visibility(slug) != "PUBLIC":
                continue
            checked_public = True
            findings += scan_commits(Path(str(pub["dir"])), log_opts, terms)
        elif pub["kind"] == "history":
            # Making a repository public: scan its whole history whatever it is now.
            checked_public = True
            if not pub["dir"]:
                blocked.append(
                    "making a repository public needs a full-history scan, and no local clone of "
                    f"{pub['repo']} was found in the folders this call runs in"
                )
            else:
                findings += scan_commits(Path(str(pub["dir"])), ["--all"], terms)
    message = f"public-content guard: {warn}" if warn and checked_public else None
    if not findings and not blocked:
        return {"systemMessage": message} if message else None
    items = sorted(set(findings)) + blocked
    out = _deny(
        "public-content guard: this would publish content that must not be public "
        "(matches are hidden):\n  - " + "\n  - ".join(items) + "\nRemove or rewrite it (for a "
        "commit: amend or rebase before pushing), then try again. Do not edit the guard or "
        "its rules to get past it; if this is a false positive, tell the owner."
    )
    if message:
        out["systemMessage"] = message
    return out


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:  # noqa: BLE001 — nothing to judge
        return 0
    if not isinstance(payload, dict):
        return 0
    try:
        out = decide(payload)
    except Exception as exc:  # noqa: BLE001 — fail CLOSED, but only for a publication
        ti = payload.get("tool_input")
        # The real command text: in JSON, a newline is the two characters \\n, which hides
        # the word boundary before `gh` or `git` (measured: it let a multi-line call through).
        raw = ti.get("command") if isinstance(ti, dict) and isinstance(ti.get("command"), str) else json.dumps(ti)
        if not (_PUSH.search(raw) or _GH.search(raw) or _GITHUB_TOOL.match(str(payload.get("tool_name")))):
            return 0
        out = _deny(
            f"public-content guard could not check this publication ({type(exc).__name__}), "
            "so it is blocked. Fix the cause (is gitleaks installed?) or ask the owner."
        )
    if out:
        print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
