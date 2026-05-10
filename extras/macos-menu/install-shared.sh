#!/bin/sh
set -eu

# Shareable bootstrap installer for Zapret2 Menu on macOS.
#
# Defaults keep the checkout based on the original upstream repository while
# applying the macOS menu branch from the fork:
#   origin -> https://github.com/bol-van/zapret2.git
#   fork   -> https://github.com/pitk150-alt/zapret2.git
#
# Override when needed:
#   BRANCH=feature/macos-menu-controller ./install-shared.sh
#   CHECKOUT_DIR="$HOME/src/zapret2" ./install-shared.sh

UPSTREAM_URL=${UPSTREAM_URL:-https://github.com/bol-van/zapret2.git}
FORK_URL=${FORK_URL:-https://github.com/pitk150-alt/zapret2.git}
BRANCH=${BRANCH:-feature/macos-menu-controller}
CHECKOUT_DIR=${CHECKOUT_DIR:-"$HOME/src/zapret2-macos-menu"}
ZAPRET_BASE=${ZAPRET_BASE:-/opt/zapret2}
INSTALL_DIR=${INSTALL_DIR:-"$HOME/Applications/Zapret2 Control"}

die() {
  echo "error: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

run_git() {
  git -C "$CHECKOUT_DIR" "$@"
}

ensure_clean_checkout() {
  run_git diff --quiet || die "checkout has unstaged changes: $CHECKOUT_DIR"
  run_git diff --cached --quiet || die "checkout has staged changes: $CHECKOUT_DIR"
  [ -z "$(run_git ls-files --others --exclude-standard)" ] || die "checkout has untracked files: $CHECKOUT_DIR"
}

[ "$(uname)" = "Darwin" ] || die "this installer is macOS-only"
need_cmd git
need_cmd swiftc

if [ ! -d "$CHECKOUT_DIR/.git" ]; then
  mkdir -p "$(dirname "$CHECKOUT_DIR")"
  git clone "$UPSTREAM_URL" "$CHECKOUT_DIR"
fi

ensure_clean_checkout

run_git remote set-url origin "$UPSTREAM_URL"
if run_git remote get-url fork >/dev/null 2>&1; then
  run_git remote set-url fork "$FORK_URL"
else
  run_git remote add fork "$FORK_URL"
fi

run_git fetch origin
run_git fetch fork "$BRANCH:refs/remotes/fork/$BRANCH"

if run_git rev-parse --verify "$BRANCH" >/dev/null 2>&1; then
  run_git checkout "$BRANCH"
else
  run_git checkout -b "$BRANCH" "fork/$BRANCH"
fi

run_git merge --no-edit origin/master
run_git merge --no-edit "fork/$BRANCH"

ZAPRET_BASE="$ZAPRET_BASE" \
INSTALL_DIR="$INSTALL_DIR" \
  "$CHECKOUT_DIR/extras/macos-menu/install.sh"

cat <<EOF

Zapret2 Menu installation finished.

Installed app:
  $INSTALL_DIR/Zapret2 Menu.app

Source checkout:
  $CHECKOUT_DIR

EOF
