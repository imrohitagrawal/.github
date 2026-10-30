# shellcheck shell=bash
# shellcheck disable=SC2034
# (SC2034: the variables here are used by the test files that source this one.)
#
# lib-public-content-test.sh - the shared harness of the scripts/test-public-content-*.sh
# suites. Sourced, not run. It builds the throwaway world (HOME,
# GIT_CONFIG_GLOBAL, XDG_CACHE_HOME, a fake gh, a gitleaks spy, PATHs without gh or gitleaks),
# the leaks (assembled at run time), the runner and assertion helpers, and the push helpers
# (a work repo whose public GitHub origin is rewritten to a local bare). See the contract at
# the top of each test file.

set -u -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCAN="$ROOT/public-content/scan.py"
PREPUSH="$ROOT/hooks/pre-push"
INSTALLER="$ROOT/scripts/install-public-content-guard.sh"
RULES="$ROOT/public-content/gitleaks-public.toml"

PASS=0
FAIL=0
SKIPPED=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL %s - %s\n' "$1" "$2"; }
skip() { SKIPPED=$((SKIPPED + 1)); printf '  SKIP %s - %s\n' "$1" "$2"; }
die() { echo "harness error: $*" >&2; exit 2; }

command -v gitleaks >/dev/null 2>&1 || {
  echo "FAIL - gitleaks is not on PATH; this suite must not pass by not running"
  exit 1
}
REAL_GITLEAKS="$(command -v gitleaks)"
REAL_GIT="$(command -v git)" || die "git missing"
REAL_PY="$(command -v python3)" || die "python3 missing"
GL_VERSION="$("$REAL_GITLEAKS" version 2>/dev/null)"
[ "$GL_VERSION" = "8.30.1" ] || echo "note: gitleaks ${GL_VERSION} on PATH; the rules were measured on 8.30.1"

# ---------------------------------------------------------------- leaks, assembled at run time
U="/Us"
HOMEP="${U}ers/jane/notes.txt"
HOMEL="/ho""me/jane/x"
# A DIFFERENT home folder: its matched text never occurs inside HOMEP's (".../janet/" vs ".../jane/").
HOMEQ="${U}ers/janet/plan.txt"
MAIL="$(printf '%s@%s' jane.doe corp-mail.io)"
KEY="AKIA""IOSFODNN7EXAMPLA"
TERM_A="zebracorn"
PTERM="${TERM_A}-labs"
TERM_B="quokkaship"
TRANSCRIPT="$(printf '%s-%s-%s-%s-%s.%s' 0f1e2d3c 1a2b 4c5d 8e9f 0123456789ab jsonl)"
ENCHOME="$(printf -- '-%s-%s-%s' Users jane proj)"
CIHOME="/home/runner/work/x"
SPOOF="$(printf '%s@%s' b users.noreply.github.com.evil.io)"
NL=$'\n'
ZERO=0000000000000000000000000000000000000000

# Pieces of home folder names whose full form a report must never print (accented, underscored,
# backslashed): ".../Jos" of José, ".../zo" of zoë.
LEAK_JOS="${U}ers/Jos"
LEAK_ZO="/ho""me/zo"
# _leaks FILE...: true when any file repeats matched text.
_leaks() {
  grep -i -q -F -e "/jane" -e "-jane-" -e '\jane' -e "corp-mail" -e "IOSFODNN7" -e "$TERM_A" \
    -e "$TERM_B" -e "0f1e2d3c" -e "evil.io" -e "_alice" -e "lodie" -e "$LEAK_JOS" -e "$LEAK_ZO" \
    "$@" 2>/dev/null
}

# ---------------------------------------------------------------- throwaway world
WORK="$(mktemp -d "${TMPDIR:-/tmp}/pcg-test.XXXXXX")" || die "mktemp"
cleanup() { chmod -R u+rwx "$WORK" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
mkdir -p "$WORK/home" "$WORK/cache" "$WORK/repos" "$WORK/push" "$WORK/files" "$WORK/sanity"
export HOME="$WORK/home"
export GIT_CONFIG_GLOBAL="$WORK/gitconfig" GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0
export XDG_CACHE_HOME="$WORK/cache"
unset GITLEAKS_CONFIG GITLEAKS_CONFIG_TOML GH_REPO GH_HOST GH_TOKEN GITHUB_TOKEN \
  GH_ENTERPRISE_TOKEN GIT_DIR GIT_WORK_TREE PR_TITLE PR_BODY GITHUB_BASE_REF GITHUB_HEAD_REF \
  GIT_NO_REPLACE_OBJECTS GIT_REPLACE_REF_BASE 2>/dev/null || true
git config --global user.name "Test Person"
git config --global user.email test@example.com
git config --global init.defaultBranch main
git config --global advice.detachedHead false

NOTES="$WORK/notes"
mkdir -p "$NOTES/scanner"
printf '# private terms (test)\n%s\n' "$PTERM" >"$NOTES/scanner/private-terms.txt"
export PRIVATE_NOTES_DIR="$NOTES"

# fake gh, gitleaks spy, broken gitleaks; logs live at fixed paths baked into the scripts
FAKEBIN="$WORK/bin-gh"
SPYBIN="$WORK/bin-spy"
BROKEN="$WORK/bin-broken"
GHLOG="$WORK/gh.log"
GLLOG="$WORK/gitleaks.log"
VIS="$WORK/visibility.txt"
ALIASES="$WORK/aliases.txt"
mkdir -p "$FAKEBIN" "$SPYBIN" "$BROKEN"
: >"$GHLOG"
: >"$GLLOG"
: >"$VIS"
: >"$ALIASES"
{
  printf '#!/bin/sh\nGHLOG=%s\nVIS=%s\nALIASES=%s\n' "'$GHLOG'" "'$VIS'" "'$ALIASES'"
  cat <<'EOF'
printf '%s\n' "$*" >> "$GHLOG"
case "$1" in
  api)
    case "$2" in
      repos/*/*)
        slug=${2#repos/}
        case "$slug" in */*/*) echo "fake gh: only repos/OWNER/REPO is answered" >&2; exit 3 ;; esac
        vis=$(awk -v s="$slug" 'tolower($1) == tolower(s) { print $2; exit }' "$VIS")
        if [ -z "$vis" ]; then echo "gh: Not Found (HTTP 404)" >&2; exit 1; fi
        case "$*" in
          *visibility*) echo "$vis" ;;
          *) if [ "$vis" = public ]; then priv=false; else priv=true; fi
             printf '{"full_name":"%s","visibility":"%s","private":%s}\n' "$slug" "$vis" "$priv" ;;
        esac
        exit 0 ;;
    esac ;;
  alias) if [ "$2" = list ]; then cat "$ALIASES"; exit 0; fi ;;
  repo) if [ "$2" = set-default ]; then echo "no default repository has been set" >&2; exit 1; fi ;;
  --version|version) echo "gh version 2.99.0 (fake)"; exit 0 ;;
esac
echo "fake gh: unexpected call: $*" >&2
exit 3
EOF
} >"$FAKEBIN/gh"
{
  printf '#!/bin/sh\nGLLOG=%s\nREAL=%s\n' "'$GLLOG'" "'$REAL_GITLEAKS'"
  cat <<'EOF'
printf '%s\n' "$*" >> "$GLLOG"
exec "$REAL" "$@"
EOF
} >"$SPYBIN/gitleaks"
printf '#!/bin/sh\necho "fake gitleaks: simulated crash" >&2\nexit 2\n' >"$BROKEN/gitleaks"
chmod +x "$FAKEBIN/gh" "$SPYBIN/gitleaks" "$BROKEN/gitleaks"

export PATH="$FAKEBIN:$SPYBIN:$PATH"

# PATHs without gitleaks / without gh
NOGL="$WORK/bin-nogl"
NOGH="$WORK/bin-nogh"
mkdir -p "$NOGL" "$NOGH"
ln -s "$REAL_GIT" "$NOGL/git"
ln -s "$REAL_PY" "$NOGL/python3"
ln -s "$FAKEBIN/gh" "$NOGL/gh"
ln -s "$REAL_GIT" "$NOGH/git"
ln -s "$REAL_PY" "$NOGH/python3"
ln -s "$SPYBIN/gitleaks" "$NOGH/gitleaks"
NOGL_PATH="$NOGL:/usr/bin:/bin"
NOGH_PATH="$NOGH:/usr/bin:/bin"
HAVE_NOGL=yes
HAVE_NOGH=yes
[ -z "$(env PATH="$NOGL_PATH" sh -c 'command -v gitleaks' 2>/dev/null)" ] || HAVE_NOGL=no
[ -z "$(env PATH="$NOGH_PATH" sh -c 'command -v gh' 2>/dev/null)" ] || HAVE_NOGH=no

vis() { printf '%s %s\n' "$1" "$2" >>"$VIS"; }
vis_set() {
  grep -v "^$1 " "$VIS" >"$VIS.tmp"
  mv "$VIS.tmp" "$VIS"
  vis "$1" "$2"
}
vis acme/pub public
vis acme/priv private
vis acme/int internal
vis acme/flip private
vis acme/x public

# ---------------------------------------------------------------- runner and verdicts
RUNPY="$WORK/run.py"
cat >"$RUNPY" <<'EOF'
import subprocess, sys
out, err, rcfile = sys.argv[1:4]
cmd = sys.argv[4:]
try:
    with open(out, "wb") as o, open(err, "wb") as e:
        rc = subprocess.run(cmd, stdout=o, stderr=e, timeout=180).returncode
except subprocess.TimeoutExpired:
    rc = 124
except OSError as exc:
    with open(err, "ab") as e:
        e.write(("runner: %s\n" % exc).encode())
    rc = 127
with open(rcfile, "w") as f:
    f.write(str(rc))
EOF
OUT="$WORK/last.out"
ERR="$WORK/last.err"
RCF="$WORK/last.rc"
# _run CMD...: run with logs reset; stdout/stderr/exit to OUT/ERR/RCF. Inherits stdin and cwd.
_run() {
  : >"$GHLOG"
  : >"$GLLOG"
  "$REAL_PY" "$RUNPY" "$OUT" "$ERR" "$RCF" "$@"
}
rc() { cat "$RCF"; }
_hint() { printf ' [stderr: %s]' "$(head -c 300 "$ERR" | tr '\n' ' ')"; }

# _evidence NAME TOKEN...: scanned | noscan | noapi | gh=OWNER/REPO
_evidence() {
  local name="$1" e
  shift
  for e in "$@"; do
    case "$e" in
      scanned) [ -s "$GLLOG" ] || { bad "$name" "allowed without running gitleaks (nothing was scanned)"; return 1; } ;;
      noscan) if [ -s "$GLLOG" ]; then bad "$name" "ran gitleaks for a call that needs no scan"; return 1; fi ;;
      noapi) if grep -q '^api repos/' "$GHLOG"; then bad "$name" "looked up visibility for a call that needs none"; return 1; fi ;;
      gh=*) grep -E -q "repos/${e#gh=}( |\$)" "$GHLOG" || { bad "$name" "no visibility lookup for ${e#gh=}"; return 1; } ;;
      *) die "unknown evidence $e" ;;
    esac
  done
  return 0
}

# expect_rc NAME WANT [NEEDLE|@scanned...]: exit status WANT; stderr has every needle; no leak.
expect_rc() {
  local name="$1" want="$2" n
  shift 2
  if [ "$(rc)" != "$want" ]; then
    bad "$name" "expected exit $want, got $(rc)$(_hint)"
    return
  fi
  for n in "$@"; do
    case "$n" in
      @scanned) [ -s "$GLLOG" ] || { bad "$name" "gitleaks never ran"; return; } ;;
      *) grep -q -F -e "$n" "$ERR" || { bad "$name" "stderr lacks '$n'$(_hint)"; return; } ;;
    esac
  done
  if _leaks "$OUT" "$ERR"; then
    bad "$name" "the output repeats the matched text"
    return
  fi
  ok "$name"
}

mkrepo() { # DIR SLUG: a repo whose origin is https://github.com/SLUG.git (no rewrite)
  if ! { git init -q "$1" && git -C "$1" remote add origin "https://github.com/$2.git" &&
    echo hello >"$1/README.md" && git -C "$1" add README.md && git -C "$1" commit -q -m init; }; then
    die "mkrepo $1"
  fi
}

# ---------------------------------------------------------------- push helpers
P="$WORK/push"
# mkpush NAME URL: work repo $P/NAME and bare $P/NAME.git; origin = URL, rewritten to the bare
# by insteadOf; one clean commit already on the bare; the hook enabled through core.hooksPath.
mkpush() {
  local d="$P/$1" bare="$P/$1.git"
  if ! { git init -q --bare "$bare" && git init -q "$d" &&
    git -C "$d" remote add origin "$2" &&
    git -C "$d" config "url.$bare.insteadOf" "$2" &&
    echo start >"$d/a.txt" && git -C "$d" add a.txt && git -C "$d" commit -q -m init &&
    git -C "$d" -c core.hooksPath=/dev/null push -q origin main 2>/dev/null &&
    git -C "$d" config core.hooksPath "$ROOT/hooks"; }; then
    die "mkpush $1"
  fi
}
addbare() { # DIR REMOTE URL: a second remote whose URL is rewritten to its own bare
  local bare="$P/$2.git"
  if ! { git init -q --bare "$bare" && git -C "$1" remote add "$2" "$3" &&
    git -C "$1" config "url.$bare.insteadOf" "$3"; }; then
    die "addbare $2"
  fi
}
commit_file() { # DIR PATH CONTENT MESSAGE
  if ! { mkdir -p "$(dirname "$1/$2")" && printf '%s\n' "$3" >"$1/$2" &&
    git -C "$1" add -- "$2" && git -C "$1" commit -q -m "$4"; }; then
    die "commit $2"
  fi
}
nohook_push() { git -C "$1" -c core.hooksPath=/dev/null push -q "${@:2}" 2>/dev/null || die "nohook push $*"; }
_refs() { git --git-dir="$1" for-each-ref --format='%(objectname) %(refname)' | sort; }
# gpush DIR BARE ARGS...: snapshot BARE's refs, then `git push ARGS` from DIR with the hook on.
gpush() {
  local d="$1" b="$2"
  shift 2
  printf '%s\n' "$b" >"$WORK/push.bare"
  _refs "$b" >"$WORK/refs.before"
  _run git -C "$d" push "$@"
}
# expect_blocked NAME [NEEDLE...]: push refused, destination unchanged, needles on stderr, no leak.
expect_blocked() {
  local name="$1" n
  shift
  if [ "$(rc)" = 0 ]; then bad "$name" "push was allowed"; return; fi
  if ! _refs "$(cat "$WORK/push.bare")" | cmp -s - "$WORK/refs.before"; then
    bad "$name" "the destination's refs changed"
    return
  fi
  for n in "$@"; do
    grep -q -F -e "$n" "$ERR" || { bad "$name" "stderr lacks '$n'$(_hint)"; return; }
  done
  if _leaks "$OUT" "$ERR"; then bad "$name" "the output repeats the matched text"; return; fi
  ok "$name"
}
# expect_pushed NAME [EVIDENCE...]
expect_pushed() {
  local name="$1"
  shift
  if [ "$(rc)" != 0 ]; then bad "$name" "push was refused (exit $(rc))$(_hint)"; return; fi
  _evidence "$name" "$@" || return
  ok "$name"
}
gh_url() { printf 'https://github.com/%s.git' "$1"; }
sha7() { git -C "$1" rev-parse --short=7 "$2"; }

# shared fixtures
SAN="$WORK/sanity"
printf 'title = "nothing"\n\n[[rules]]\nid = "never"\nregex = %s\n' "'''zq9zq9zq9'''" >"$SAN/nomatch.toml"
mkdir -p "$WORK/empty-notes/scanner"
printf '# nothing here\n\n' >"$WORK/empty-notes/scanner/private-terms.txt"

gl_rules() { # CONFIG [CWD] ; stdin -> rule ids, one per line (no --config when CONFIG is "-")
  local cfg="$1" dir="${2:-$SAN}"
  if [ "$cfg" = - ]; then
    (cd "$dir" && "$REAL_GITLEAKS" stdin --no-banner --redact --report-format json --report-path - --exit-code 0 2>/dev/null)
  else
    (cd "$dir" && "$REAL_GITLEAKS" stdin --config "$cfg" --no-banner --redact --report-format json --report-path - --exit-code 0 2>/dev/null)
  fi | "$REAL_PY" -c 'import json,sys; [print(f["RuleID"]) for f in json.load(sys.stdin)]'
}

# installer helpers: a git that reports a chosen version and passes everything else through
fakegit() { # DIR "git version X"
  mkdir -p "$1"
  {
    printf '#!/bin/sh\nREAL=%s\nVER=%s\n' "'$REAL_GIT'" "'$2'"
    cat <<'EOF'
case "$1" in --version|version) echo "$VER"; exit 0 ;; esac
exec "$REAL" "$@"
EOF
  } >"$1/git"
  chmod +x "$1/git"
}
cfg() { "$REAL_GIT" config --file "$@"; }
events() { cfg "$1" --get-all hook.public-content.event 2>/dev/null | grep -c '^pre-push$'; }
_install() { # GITDIR GLOBALCONFIG
  GIT_CONFIG_GLOBAL="$2" PATH="$1:$PATH" _run bash "$INSTALLER"
}
