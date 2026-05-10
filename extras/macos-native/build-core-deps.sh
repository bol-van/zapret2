#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DEPS_DIR="$SCRIPT_DIR/.deps"
BUILD_DIR="$DEPS_DIR/build"
PREFIX="$DEPS_DIR/prefix"
LUA_VERSION=${LUA_VERSION:-5.4.8}
LUA_ARCHIVE="lua-$LUA_VERSION.tar.gz"
LUA_URL="https://www.lua.org/ftp/$LUA_ARCHIVE"
LUA_SRC="$BUILD_DIR/lua-$LUA_VERSION"
ENV_FILE="$DEPS_DIR/lua-env.sh"

[ "$(uname)" = "Darwin" ] || {
  echo "error: this helper is macOS-only" >&2
  exit 1
}

command -v curl >/dev/null 2>&1 || {
  echo "error: curl is required" >&2
  exit 1
}
command -v make >/dev/null 2>&1 || {
  echo "error: make is required" >&2
  exit 1
}
command -v cc >/dev/null 2>&1 || {
  echo "error: cc is required" >&2
  exit 1
}

mkdir -p "$BUILD_DIR" "$PREFIX"

if [ ! -f "$BUILD_DIR/$LUA_ARCHIVE" ]; then
  echo "Downloading Lua $LUA_VERSION..."
  curl -fL "$LUA_URL" -o "$BUILD_DIR/$LUA_ARCHIVE"
fi

if [ ! -d "$LUA_SRC" ]; then
  tar -xzf "$BUILD_DIR/$LUA_ARCHIVE" -C "$BUILD_DIR"
fi

echo "Building Lua $LUA_VERSION locally..."
make -C "$LUA_SRC" macosx
make -C "$LUA_SRC" INSTALL_TOP="$PREFIX" install

cat >"$ENV_FILE" <<EOF
LUA_CFLAGS='-I$PREFIX/include'
LUA_LIB='$PREFIX/lib/liblua.a -lm'
EOF

cat <<EOF

Local Lua dependency is ready.

Environment file:
  $ENV_FILE

Use it with:
  . "$ENV_FILE"
  make -C nfq2 bsd LUA_CFLAGS="\$LUA_CFLAGS" LUA_LIB="\$LUA_LIB"

EOF
