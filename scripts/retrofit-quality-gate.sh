#!/usr/bin/env bash
#
# retrofit-quality-gate.sh -- mechanically automate docs/repo-onboarding.md
# steps 1-6 (copying AGENTS.md, .github/CODEOWNERS, .github/workflows/
# pr-quality.yml, .github/dependabot.yml, and a stack-appropriate Makefile
# into an EXISTING repo, then branching + committing) so an already-existing
# repo doesn't have to do it by hand.
#
# Deliberately does NOT automate onboarding steps 7-10 (branch protection,
# enabling Codex review, opening a test PR) -- those are cross-product UI
# steps (GitHub Settings, the ChatGPT UI) that this script cannot perform.
# It also does not push or open a PR unless --push is passed explicitly.
#
# Usage:
#   scripts/retrofit-quality-gate.sh [--repo PATH] [--branch NAME]
#                                     [--force] [--push] [--no-commit] [-h]
#
#   --repo PATH     Path to the target repo (default: current directory).
#   --branch NAME   Branch to create/reuse (default: setup/pr-quality-gate).
#   --force         Overwrite a target file even if it already exists with
#                    different content (a .bak backup is written first).
#                    Without this flag, differing files are left untouched
#                    and reported at the end for manual review.
#   --push          After committing, push the branch and open a PR with
#                    `gh pr create`. Without this flag, the script stops
#                    after the local commit and prints the remaining manual
#                    steps.
#   --no-commit     Copy files into the working tree but don't create a
#                    branch or commit. Useful for reviewing the diff first.
#   -h, --help      Show this help and exit.
#
# Exit codes: 0 success (including "nothing to do, already onboarded"),
# 1 usage error, 2 target repo is not a usable git repo / has a dirty tree /
# is on an unsafe branch (detached HEAD, or --branch names the repo's
# current branch when that looks like a default branch), 3 monorepo (both
# Python and Node manifests at repo root) detected with no Makefile applied
# automatically -- files were still copied, see the printed notes.
#
# Safety notes (found in review, fixed here -- not just documented):
#   - A destination path that already exists as a symlink is never followed
#     or written through; it's treated as a conflicting file (same as
#     content that differs), never silently overwritten even with --force.
#   - --push refuses to run if the caller workflow (.github/workflows/
#     pr-quality.yml) itself was left SKIPPED (conflicting content, no
#     --force) or if the repo is an unresolved monorepo -- otherwise the
#     opened PR could claim to add the quality gate without actually adding
#     the one file that matters most.
#   - --push is idempotent: it re-attempts on every run with unpushed local
#     commits, not just the run that created the commit, and checks for an
#     existing PR before creating a new one.

set -euo pipefail

# --- imrohitagrawal/.github's current pinned tag, per its versioning policy
# (SHA + human-readable tag comment, not the mutable tag alone). Bump both
# together when a new tag ships.
PINNED_SHA="6bd9eec68b0fa7db8b60de89ee541666893febaa"
PINNED_TAG="v6"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATES_DIR="$SCRIPT_DIR/../templates"

TARGET_REPO="."
BRANCH="setup/pr-quality-gate"
FORCE=0
PUSH=0
DO_COMMIT=1

usage() {
	cat <<'EOF'
retrofit-quality-gate.sh -- mechanically automate docs/repo-onboarding.md
steps 1-6 (copying AGENTS.md, .github/CODEOWNERS, .github/workflows/
pr-quality.yml, .github/dependabot.yml, and a stack-appropriate Makefile
into an EXISTING repo, then branching + committing) so an already-existing
repo doesn't have to do it by hand.

Deliberately does NOT automate onboarding steps 7-10 (branch protection,
enabling Codex review, opening a test PR) -- those are cross-product UI
steps (GitHub Settings, the ChatGPT UI) that this script cannot perform.
It also does not push or open a PR unless --push is passed explicitly.

Usage:
  scripts/retrofit-quality-gate.sh [--repo PATH] [--branch NAME]
                                    [--force] [--push] [--no-commit] [-h]

  --repo PATH     Path to the target repo (default: current directory).
  --branch NAME   Branch to create/reuse (default: setup/pr-quality-gate).
  --force         Overwrite a target file even if it already exists with
                   different content (a .bak backup is written first).
                   Without this flag, differing files are left untouched
                   and reported at the end for manual review.
  --push          After committing, push the branch and open a PR with
                   `gh pr create`. Without this flag, the script stops
                   after the local commit and prints the remaining manual
                   steps.
  --no-commit     Copy files into the working tree but don't create a
                   branch or commit. Useful for reviewing the diff first.
  -h, --help      Show this help and exit.

Exit codes: 0 success (including "nothing to do, already onboarded"),
1 usage error, 2 target repo is not a usable git repo / has a dirty tree,
3 monorepo (both Python and Node manifests) detected with no Makefile
  applied automatically -- files were still copied, see the printed notes.
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--repo)
		TARGET_REPO="$2"
		shift 2
		;;
	--branch)
		BRANCH="$2"
		shift 2
		;;
	--force)
		FORCE=1
		shift
		;;
	--push)
		PUSH=1
		shift
		;;
	--no-commit)
		DO_COMMIT=0
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "error: unrecognized argument: $1" >&2
		usage >&2
		exit 1
		;;
	esac
done

if [ ! -d "$TEMPLATES_DIR" ]; then
	echo "error: expected templates dir at $TEMPLATES_DIR (is this script still inside dot-github/scripts/?)" >&2
	exit 1
fi

# --- Resolve and validate the target repo -----------------------------------

if ! git -C "$TARGET_REPO" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	echo "error: $TARGET_REPO is not inside a git working tree -- aborting before touching anything" >&2
	exit 2
fi

TARGET_ROOT="$(git -C "$TARGET_REPO" rev-parse --show-toplevel)"

# Captured separately from the `[ -n ... ]` test so a failing/corrupt `git
# status` itself (e.g. an unreadable index) is a hard error, not silently
# treated as "clean" -- `if [ -n "$(cmd)" ]` alone would let a failed `cmd`
# (empty stdout) pass the dirty check by accident (found in review).
# `--untracked-files=all` also overrides a local `status.showUntrackedFiles
# =no` config that would otherwise hide real untracked files from this check.
if ! STATUS_OUTPUT="$(git -C "$TARGET_ROOT" status --porcelain --untracked-files=all)"; then
	echo "error: 'git status' failed in $TARGET_ROOT -- repo may be corrupt; refusing to proceed" >&2
	exit 2
fi
if [ -n "$STATUS_OUTPUT" ]; then
	echo "error: $TARGET_ROOT has uncommitted changes -- commit or stash first, or the copied files will mix with unrelated dirty state" >&2
	echo "       (pass nothing to override -- there is no override; clean tree is required)" >&2
	exit 2
fi

# Refuse a detached HEAD -- there's no branch to safely commit onto, and a
# PR opened from a detached-HEAD commit would have the wrong base.
if ! git -C "$TARGET_ROOT" symbolic-ref -q HEAD >/dev/null; then
	echo "error: $TARGET_ROOT is in a detached HEAD state -- check out a real branch first" >&2
	exit 2
fi

# Refuse targeting what looks like the repo's default branch. This is a
# name-based guard, not a full check against origin/HEAD (no network call
# here), but it catches the concrete, documented failure mode: `--branch
# main --push` committing and pushing straight to main (found in review).
case "$BRANCH" in
main | master)
	echo "error: --branch '$BRANCH' looks like a default branch -- refusing to commit/push directly onto it. Use a feature branch (the default, 'setup/pr-quality-gate', is fine)." >&2
	exit 2
	;;
esac

echo "Target repo: $TARGET_ROOT"

# --- Detect stack -------------------------------------------------------

HAS_NODE=0
[ -f "$TARGET_ROOT/package.json" ] && HAS_NODE=1

HAS_PYTHON=0
if [ -f "$TARGET_ROOT/pyproject.toml" ] || [ -f "$TARGET_ROOT/requirements.txt" ] || [ -f "$TARGET_ROOT/setup.py" ]; then
	HAS_PYTHON=1
fi

echo "Detected: package.json=$([ "$HAS_NODE" = 1 ] && echo yes || echo no), python manifest=$([ "$HAS_PYTHON" = 1 ] && echo yes || echo no)"

# --- Branch (create or reuse) -----------------------------------------------

if [ "$DO_COMMIT" = 1 ]; then
	CURRENT_BRANCH="$(git -C "$TARGET_ROOT" rev-parse --abbrev-ref HEAD)"
	if git -C "$TARGET_ROOT" show-ref --verify --quiet "refs/heads/$BRANCH"; then
		if [ "$CURRENT_BRANCH" != "$BRANCH" ]; then
			echo "Branch '$BRANCH' already exists -- reusing it (re-run of a previous retrofit)."
			git -C "$TARGET_ROOT" checkout "$BRANCH"
		fi
	else
		git -C "$TARGET_ROOT" checkout -b "$BRANCH"
	fi
fi

# --- Copy-with-clobber-check helper -----------------------------------------
#
# copy_file SRC DEST DESCRIPTION
#   - DEST absent            -> copy, report "added"
#   - DEST present, identical -> skip silently (already onboarded), report "up to date"
#   - DEST present, differs   -> without --force: leave untouched, record for
#                                  the end-of-run summary; with --force: back
#                                  up the existing file to DEST.bak, then
#                                  overwrite.

SKIPPED_FILES=()
ADDED_OR_UPDATED=()

# Round-2 Codex review: checking only the IMMEDIATE parent (as the first
# version of copy_file did) misses a symlinked GRANDPARENT -- e.g. a tracked
# `.github -> /elsewhere` symlink. `.github/workflows` (dest's immediate
# parent) is not itself a symlink, so that check passed, but `mkdir -p`/`cp`
# still traverse through `.github` to get there, escaping the repo.
# Reproduced by the reviewer: `--no-commit` created a real file in the
# external symlink target. Fixed by walking every existing ancestor between
# TARGET_ROOT and dest's parent, not just the nearest one - all `dest`
# arguments passed to copy_file are always "$TARGET_ROOT/..." (absolute,
# anchored at TARGET_ROOT), so this walk is guaranteed to terminate exactly
# at TARGET_ROOT rather than needing to guess a stopping point.
ancestor_is_symlinked() {
	check="$(dirname "$1")"
	while [ "$check" != "$TARGET_ROOT" ]; do
		if [ -L "$check" ]; then
			echo "$check"
			return 0
		fi
		next="$(dirname "$check")"
		# Safety valve, should be unreachable given the "$TARGET_ROOT/..."
		# invariant above: stop if dirname stops making progress (hit "/"
		# or a loop) rather than spinning forever.
		[ "$next" = "$check" ] && return 1
		check="$next"
	done
	return 1
}

copy_file() {
	src="$1"
	dest="$2"
	desc="$3"

	dest_parent="$(dirname "$dest")"
	# Refuse to create-into or write-through ANY symlinked ancestor
	# directory between TARGET_ROOT and dest (e.g. a tracked
	# `.github -> /somewhere-else` symlink, not just dest's immediate
	# parent) -- `mkdir -p` and `cp` would otherwise follow it outside the
	# repo (found in review, real P0: a tracked symlink can redirect a copy
	# anywhere on disk; round-2 review found the immediate-parent-only
	# version of this check still missed a symlinked grandparent).
	if bad_ancestor="$(ancestor_is_symlinked "$dest")"; then
		echo "  SKIPPED:   $desc -- ancestor directory '$bad_ancestor' is a symlink, refusing to write through it" >&2
		SKIPPED_FILES+=("$dest (symlinked ancestor: $bad_ancestor)")
		return
	fi
	mkdir -p "$dest_parent"

	# Refuse a destination that is itself a symlink -- `cp` would overwrite
	# whatever it points at (possibly outside the repo) rather than the
	# tracked path itself. Treated like conflicting content: never touched,
	# even with --force, since there's no safe "original" to back up.
	if [ -L "$dest" ]; then
		echo "  SKIPPED:   $desc -- exists as a symlink, refusing to overwrite through it (remove it and rerun if this is expected)" >&2
		SKIPPED_FILES+=("$dest (symlink)")
		return
	fi

	if [ ! -e "$dest" ]; then
		cp "$src" "$dest"
		echo "  added:     $desc"
		ADDED_OR_UPDATED+=("$dest")
		return
	fi

	if [ ! -f "$dest" ]; then
		echo "  SKIPPED:   $desc -- exists but is not a regular file, refusing to overwrite" >&2
		SKIPPED_FILES+=("$dest (not a regular file)")
		return
	fi

	if diff -q "$src" "$dest" >/dev/null 2>&1; then
		echo "  unchanged: $desc (already matches template)"
		return
	fi

	if [ "$FORCE" = 1 ]; then
		bak="$dest.bak"
		if [ -e "$bak" ]; then
			echo "  SKIPPED:   $desc -- would overwrite, but '$bak' already exists from a previous run; move or remove it first so nothing is silently lost" >&2
			SKIPPED_FILES+=("$dest (stale .bak present)")
			return
		fi
		cp "$dest" "$bak"
		cp "$src" "$dest"
		echo "  OVERWRITTEN: $desc (previous content backed up to $(basename "$dest").bak)"
		# The .bak is committed alongside the overwrite, not left untracked --
		# an untracked .bak would otherwise trip this same script's own
		# clean-working-tree gate on the very next run (found in review).
		ADDED_OR_UPDATED+=("$dest" "$bak")
	else
		echo "  SKIPPED:   $desc -- exists with different content (rerun with --force to overwrite; a .bak backup will be made)"
		SKIPPED_FILES+=("$dest")
	fi
}

echo ""
echo "Copying files..."

copy_file "$TEMPLATES_DIR/AGENTS.md" "$TARGET_ROOT/AGENTS.md" "AGENTS.md"
copy_file "$TEMPLATES_DIR/CODEOWNERS" "$TARGET_ROOT/.github/CODEOWNERS" ".github/CODEOWNERS"
copy_file "$TEMPLATES_DIR/dependabot.yml" "$TARGET_ROOT/.github/dependabot.yml" ".github/dependabot.yml"

# The caller workflow needs the SHA pin substituted in, so it's staged into a
# temp file rather than copied byte-for-byte from templates/caller-pr-quality.yml.
CALLER_TMP="$(mktemp)"
trap 'rm -f "$CALLER_TMP"' EXIT
EXPECTED_PIN="uses: imrohitagrawal/.github/.github/workflows/reusable-pr-quality.yml@${PINNED_SHA} # ${PINNED_TAG}"
sed -E "s|uses: imrohitagrawal/\.github/\.github/workflows/reusable-pr-quality\.yml@[^[:space:]]+|${EXPECTED_PIN}|" \
	"$TEMPLATES_DIR/caller-pr-quality.yml" >"$CALLER_TMP"
# Verify the substitution actually happened rather than trusting sed's exit
# code -- sed exits 0 even on zero matches, which would otherwise silently
# ship a caller file still pinned to whatever templates/caller-pr-quality.yml
# had (a mutable tag), while this script reports it as SHA-pinned (found in
# review).
if ! grep -qF "$EXPECTED_PIN" "$CALLER_TMP"; then
	echo "error: failed to substitute the SHA pin into caller-pr-quality.yml -- templates/caller-pr-quality.yml's 'uses:' line may have changed format. Not writing an unpinned caller workflow." >&2
	exit 1
fi
CALLER_DEST="$TARGET_ROOT/.github/workflows/pr-quality.yml"
copy_file "$CALLER_TMP" "$CALLER_DEST" ".github/workflows/pr-quality.yml (pinned @${PINNED_SHA} # ${PINNED_TAG})"
# Tracked separately from SKIPPED_FILES (used only for the end-of-run
# summary) so the push gate below can check the ONE file that actually
# matters -- the caller workflow -- rather than parsing summary strings.
CALLER_INSTALLED=0
if [ -f "$CALLER_DEST" ] && diff -q "$CALLER_TMP" "$CALLER_DEST" >/dev/null 2>&1; then
	CALLER_INSTALLED=1
fi

# --- Makefile: pick by detected stack, never guess for a monorepo ----------

MONOREPO_NOTE=0
if [ "$HAS_PYTHON" = 1 ] && [ "$HAS_NODE" = 1 ]; then
	echo "  monorepo detected (both a Python and a Node manifest at repo root):"
	echo "    both Makefile.python and Makefile.node will be copied under those names,"
	echo "    NOT as 'Makefile' -- picking one silently would suppress the other"
	echo "    stack's checks while the gate still reports green. Merge them into a"
	echo "    single Makefile with lint/typecheck/test targets that dispatch into the"
	echo "    right subdirectory (e.g. 'make -C backend lint') by hand."
	copy_file "$TEMPLATES_DIR/Makefile.python" "$TARGET_ROOT/Makefile.python" "Makefile.python (monorepo -- merge by hand, see note above)"
	copy_file "$TEMPLATES_DIR/Makefile.node" "$TARGET_ROOT/Makefile.node" "Makefile.node (monorepo -- merge by hand, see note above)"
	MONOREPO_NOTE=1
elif [ "$HAS_PYTHON" = 1 ]; then
	copy_file "$TEMPLATES_DIR/Makefile.python" "$TARGET_ROOT/Makefile" "Makefile (Python)"
elif [ "$HAS_NODE" = 1 ]; then
	copy_file "$TEMPLATES_DIR/Makefile.node" "$TARGET_ROOT/Makefile" "Makefile (Node)"
else
	echo "  no Makefile copied: no package.json or Python manifest (pyproject.toml/requirements.txt/setup.py) found at repo root."
	echo "    Per docs/repo-onboarding.md's 'Other language' guidance: write a Makefile"
	echo "    with a 'ci:' target that runs whatever checks this repo already uses --"
	echo "    the reusable workflow will pick it up. Not done automatically here."
fi

# --- Commit ------------------------------------------------------------

COMMIT_MADE=0
if [ "$DO_COMMIT" = 1 ]; then
	if [ "${#ADDED_OR_UPDATED[@]}" -gt 0 ]; then
		git -C "$TARGET_ROOT" add "${ADDED_OR_UPDATED[@]}"
		if ! git -C "$TARGET_ROOT" diff --cached --quiet; then
			git -C "$TARGET_ROOT" commit -m "Add PR quality gate (imrohitagrawal/.github @${PINNED_TAG})"
			COMMIT_MADE=1
			echo ""
			echo "Committed on branch '$BRANCH'."
		fi
	else
		echo ""
		echo "Nothing new to commit -- all applicable files already matched the templates."
	fi
fi

# --- Push / PR, or print manual next steps ----------------------------------

echo ""
if [ "${#SKIPPED_FILES[@]}" -gt 0 ]; then
	echo "Files left untouched because they exist with different content (review manually, or rerun with --force):"
	for f in "${SKIPPED_FILES[@]}"; do
		echo "  - $f"
	done
	echo ""
fi

if [ "$DO_COMMIT" = 0 ]; then
	echo "Files copied into the working tree, --no-commit set: no branch/commit made. Review with 'git diff' and commit yourself."
elif [ "$COMMIT_MADE" = 1 ]; then
	echo "Local commit made on branch '$BRANCH'."
else
	echo "No new commit this run (already up to date on branch '$BRANCH')."
fi

if [ "$DO_COMMIT" = 1 ] && [ "$PUSH" = 1 ]; then
	# Refuse to push/open a PR that would claim to add the quality gate
	# without actually adding the one file that matters most, or while a
	# monorepo is left with two unmerged, non-operative Makefiles (found in
	# review) -- push based on unpushed commits existing, not on whether
	# THIS run made one, so a first run without --push followed by a second
	# run with --push still pushes (also found in review).
	if [ "$CALLER_INSTALLED" != 1 ]; then
		echo "error: refusing to push -- .github/workflows/pr-quality.yml was not installed (see SKIPPED files above). Resolve the conflict (or rerun with --force) before pushing, so the PR doesn't claim to add a gate it didn't add." >&2
		exit 2
	fi
	if [ "$MONOREPO_NOTE" = 1 ]; then
		echo "error: refusing to push -- monorepo detected with Makefile.python/Makefile.node left unmerged. Merge them into a single Makefile by hand, commit that, then rerun with --push." >&2
		exit 3
	fi
	UNPUSHED="$(git -C "$TARGET_ROOT" log "origin/$BRANCH..HEAD" --oneline 2>/dev/null || true)"
	if [ -z "$UNPUSHED" ] && git -C "$TARGET_ROOT" rev-parse --verify -q "refs/remotes/origin/$BRANCH" >/dev/null && [ "$COMMIT_MADE" != 1 ]; then
		echo "Nothing unpushed on '$BRANCH' -- skipping push."
	else
		git -C "$TARGET_ROOT" push -u origin "$BRANCH"
		if command -v gh >/dev/null 2>&1; then
			if (cd "$TARGET_ROOT" && gh pr view "$BRANCH" >/dev/null 2>&1); then
				echo "PR for branch '$BRANCH' already exists -- not creating a duplicate."
			else
				(cd "$TARGET_ROOT" && gh pr create --fill --head "$BRANCH" --title "Add PR quality gate" \
					--body "Automated by imrohitagrawal/.github's retrofit-quality-gate.sh. Adds the pinned caller workflow, AGENTS.md, CODEOWNERS, dependabot.yml, and a stack-appropriate Makefile. Remaining manual steps per docs/repo-onboarding.md: enable branch protection requiring the quality-gate check, enable Codex review, and open a test PR to confirm both fire.")
			fi
		else
			echo "Pushed branch '$BRANCH'. 'gh' CLI not found -- open the PR manually."
		fi
	fi
elif [ "$DO_COMMIT" = 1 ]; then
	echo "Not pushed (pass --push to push + open a PR automatically)."
fi

echo ""
echo "Remaining manual steps (docs/repo-onboarding.md steps 7-10, not automated by this script):"
echo "  7. Let GitHub Actions run once on the PR; confirm the quality-gate check passes."
echo "  8. Configure branch protection to require the quality-gate check (docs/branch-protection.md)."
echo "  9. Enable Codex review for the repo (requires ChatGPT Plus or higher; docs/codex-pr-review.md)."
echo "  10. Open a test PR to confirm quality-gate is green and Codex posts a review."
if [ "$MONOREPO_NOTE" = 1 ]; then
	echo ""
	echo "Also: merge Makefile.python and Makefile.node into a single Makefile by hand (see note above)."
	exit 3
fi
