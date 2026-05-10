#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
LUA_ENV="$SCRIPT_DIR/.deps/lua-env.sh"

[ "$(uname)" = "Darwin" ] || {
  echo "error: this helper is macOS-only" >&2
  exit 1
}

if [ ! -f "$LUA_ENV" ]; then
  echo "Local Lua dependency is missing. Building it now..."
  "$SCRIPT_DIR/build-core-deps.sh"
fi

# shellcheck disable=SC1090
. "$LUA_ENV"

make -C "$REPO_DIR/nfq2" darwin-engine-check libzapret2core-darwin.a darwin LUA_JIT=0 LUA_CFLAGS="$LUA_CFLAGS" LUA_LIB="$LUA_LIB"

echo
echo "Built zapret2 Darwin core binary:"
echo "  $REPO_DIR/nfq2/dvtws2"
echo "Built zapret2 Darwin core library:"
echo "  $REPO_DIR/nfq2/libzapret2core-darwin.a"
