#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
BUILD_DIR=${BUILD_DIR:-"$SCRIPT_DIR/build"}
BACKEND="$BUILD_DIR/zapret2-mac-backend"
BRIDGE_LIB="$BUILD_DIR/libzapret2-mac-bridge.a"
BRIDGE_OBJ="$BUILD_DIR/Zapret2CoreBridge.o"
BRIDGE_CHECK="$BUILD_DIR/zapret2-core-bridge-check"
UTUN_CHECK="$BUILD_DIR/zapret2-utun-check"
UTUN_RUNTIME="$BUILD_DIR/zapret2-utun-runtime"
PACKET_TUNNEL_APPEX="$BUILD_DIR/Zapret2PacketTunnel.appex"
LUA_ENV="$SCRIPT_DIR/.deps/lua-env.sh"

[ "$(uname)" = "Darwin" ] || {
  echo "error: native macOS backend can only be built on Darwin" >&2
  exit 1
}

command -v swiftc >/dev/null 2>&1 || {
  echo "error: swiftc is required. Install Xcode Command Line Tools first." >&2
  exit 1
}

command -v cc >/dev/null 2>&1 || {
  echo "error: cc is required. Install Xcode Command Line Tools first." >&2
  exit 1
}

mkdir -p "$BUILD_DIR"

if [ ! -f "$REPO_DIR/nfq2/libzapret2core-darwin.a" ]; then
  echo "Darwin core library is missing. Building it now..."
  "$SCRIPT_DIR/build-core.sh"
fi

if [ -f "$LUA_ENV" ]; then
  # shellcheck disable=SC1090
  . "$LUA_ENV"
fi

cc -c "$SCRIPT_DIR/Sources/Zapret2CoreBridge.c" \
  -I"$REPO_DIR/nfq2" \
  ${LUA_CFLAGS:-} \
  -o "$BRIDGE_OBJ"
ar rcs "$BRIDGE_LIB" "$BRIDGE_OBJ"
cc "$SCRIPT_DIR/Sources/Zapret2CoreBridgeCheck.c" \
  "$BRIDGE_OBJ" \
  "$REPO_DIR/nfq2/libzapret2core-darwin.a" \
  -I"$REPO_DIR/nfq2" \
  ${LUA_CFLAGS:-} \
  ${LUA_LIB:-} \
  -lz \
  -o "$BRIDGE_CHECK"

cc "$SCRIPT_DIR/Sources/UtunCheck.c" \
  -o "$UTUN_CHECK"

cc "$SCRIPT_DIR/Sources/UtunRuntime.c" \
  -o "$UTUN_RUNTIME"

swiftc "$SCRIPT_DIR/zapret2-mac-backend.swift" \
  "$SCRIPT_DIR/Sources/NetworkExtensionController.swift" \
  -o "$BACKEND" \
  -framework NetworkExtension \
  -framework Foundation

swiftc -typecheck \
  "$SCRIPT_DIR/Sources/PacketTunnelProvider.swift" \
  "$SCRIPT_DIR/Sources/PacketMetadata.swift" \
  "$SCRIPT_DIR/Sources/Zapret2CoreBindings.swift" \
  "$SCRIPT_DIR/Sources/Zapret2PacketProcessor.swift" \
  "$SCRIPT_DIR/Sources/PacketRelay.swift" \
  -framework NetworkExtension \
  -framework Network \
  -framework Foundation

"$SCRIPT_DIR/build-extension.sh" >/dev/null

echo "Built backend scaffold: $BACKEND"
echo "Built core bridge library: $BRIDGE_LIB"
echo "Built core bridge check: $BRIDGE_CHECK"
echo "Built utun check: $UTUN_CHECK"
echo "Built utun runtime: $UTUN_RUNTIME"
echo "Built packet tunnel extension scaffold: $PACKET_TUNNEL_APPEX"
echo "Network Extension source scaffold: $SCRIPT_DIR/Sources/PacketTunnelProvider.swift"

if [ -f "$SCRIPT_DIR/.deps/lua-env.sh" ]; then
  echo "Lua dependency: found locally"
elif command -v pkg-config >/dev/null 2>&1 && { pkg-config --exists luajit 2>/dev/null || pkg-config --exists lua54 2>/dev/null || pkg-config --exists lua 2>/dev/null; }; then
  echo "Lua dependency: found"
else
  echo "Lua dependency: missing"
  echo "Run extras/macos-native/build-core-deps.sh before building the native zapret2 core." >&2
fi

echo
echo "Core audit:"
echo "  zapret2 packet engine entry point: nfq2/desync.c:dpi_desync_packet(...)"
echo "  reusable engine init: available through bridge check"
echo "  open-source packet boundary: utun check available"
echo "  current macOS packet boundary: IPv4 UDP relay available, TCP remains on tpws fallback"
echo "  production target: utun/root runtime; Network Extension remains prepared for future signing"
echo
echo "This build initializes zapret2 core presets and includes the utun/root Discord UDP relay."
echo "Next step: validate Discord RTC counters with a live voice/video session."
