#!/bin/sh
set -eu

# Safely update the macOS development branch while keeping upstream zapret2 core
# easy to refresh.
#
# The workflow is intentionally merge-based:
# - origin/master brings in the original developer repository updates
# - fork/<branch> brings in our macOS integration work
# - no reset/rebase is performed by this script

UPSTREAM_URL=${UPSTREAM_URL:-https://github.com/bol-van/zapret2.git}
FORK_URL=${FORK_URL:-https://github.com/pitk150-alt/zapret2.git}
BRANCH=${BRANCH:-feature/macos-menu-controller}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

die() {
  echo "error: $*" >&2
  exit 1
}

git_repo() {
  git -C "$REPO_DIR" "$@"
}

require_clean_tree() {
  git_repo diff --quiet || die "working tree has unstaged changes"
  git_repo diff --cached --quiet || die "working tree has staged changes"
  [ -z "$(git_repo ls-files --others --exclude-standard)" ] || die "working tree has untracked files"
}

[ -d "$REPO_DIR/.git" ] || die "not a git repository: $REPO_DIR"
require_clean_tree

git_repo remote set-url origin "$UPSTREAM_URL"
if git_repo remote get-url fork >/dev/null 2>&1; then
  git_repo remote set-url fork "$FORK_URL"
else
  git_repo remote add fork "$FORK_URL"
fi

git_repo fetch origin
git_repo fetch fork "$BRANCH:refs/remotes/fork/$BRANCH"

current_branch=$(git_repo branch --show-current)
if [ "$current_branch" != "$BRANCH" ]; then
  if git_repo rev-parse --verify "$BRANCH" >/dev/null 2>&1; then
    git_repo checkout "$BRANCH"
  else
    git_repo checkout -b "$BRANCH" "fork/$BRANCH"
  fi
fi

git_repo merge --no-edit origin/master
git_repo merge --no-edit "fork/$BRANCH"

cat <<EOF
Sync completed.

Branch:
  $BRANCH

Upstream:
  $UPSTREAM_URL

Fork:
  $FORK_URL
EOF
