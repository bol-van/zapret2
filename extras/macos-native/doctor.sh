#!/bin/sh
set -eu

failures=0
HOMEBREW_PREFIXES="/opt/homebrew /usr/local"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LOCAL_LUA_ENV="$SCRIPT_DIR/.deps/lua-env.sh"

add_homebrew_path() {
  for prefix in $HOMEBREW_PREFIXES; do
    if [ -x "$prefix/bin/brew" ]; then
      PATH="$prefix/bin:$PATH"
      export PATH
      return 0
    fi
  done
  return 1
}

check_cmd() {
  if command -v "$1" >/dev/null 2>&1; then
    echo "ok: $1"
  else
    echo "missing: $1"
    failures=$((failures + 1))
  fi
}

check_optional_cmd() {
  if command -v "$1" >/dev/null 2>&1; then
    echo "ok: $1"
  else
    echo "warning: optional command is missing: $1"
  fi
}

echo "Zapret2 native macOS doctor"
echo

[ "$(uname)" = "Darwin" ] || {
  echo "error: this backend targets macOS/Darwin"
  exit 1
}

add_homebrew_path || true

check_cmd swiftc
check_cmd git
if command -v xcodebuild >/dev/null 2>&1; then
  if xcodebuild -version >/dev/null 2>&1; then
    echo "ok: xcodebuild"
  else
    echo "warning: xcodebuild is present, but full Xcode is not selected"
  fi
else
  echo "warning: optional command is missing: xcodebuild"
fi
if [ -f "$LOCAL_LUA_ENV" ]; then
  check_optional_cmd pkg-config
  check_optional_cmd brew
else
  check_cmd pkg-config
  check_cmd brew
fi

echo
if [ -f "$LOCAL_LUA_ENV" ]; then
  echo "ok: local Lua dependency"
elif command -v pkg-config >/dev/null 2>&1; then
  if pkg-config --exists luajit 2>/dev/null; then
    echo "ok: luajit development package"
  elif pkg-config --exists lua54 2>/dev/null; then
    echo "ok: lua54 development package"
  elif pkg-config --exists lua 2>/dev/null; then
    echo "ok: lua development package"
  else
    echo "missing: Lua/LuaJIT development package"
    failures=$((failures + 1))
  fi
elif ! command -v pkg-config >/dev/null 2>&1; then
  echo "missing: pkg-config, cannot detect Lua/LuaJIT development package"
fi

echo
echo "Production backend requirements:"
echo "- Apple Network Extension entitlement"
echo "- signed app and extension bundle"
echo "- packet tunnel implementation feeding zapret2 core"

echo
if [ "$failures" -eq 0 ]; then
  echo "doctor: passed"
else
  echo "doctor: $failures required item(s) missing"
  if [ ! -f "$LOCAL_LUA_ENV" ] && ! command -v brew >/dev/null 2>&1; then
    cat <<'EOF'

To install Homebrew, run this in a regular Terminal window:
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

Then install native dependencies:
  extras/macos-native/install-dev-deps.sh

Alternative without Homebrew or sudo:
  extras/macos-native/build-core-deps.sh
EOF
  fi
fi

exit "$failures"
