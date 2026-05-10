#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
BUILD_DIR=${BUILD_DIR:-"$SCRIPT_DIR/build"}
PROVIDER_BUNDLE_ID=${ZAPRET_TUNNEL_PROVIDER_BUNDLE_ID:-org.zapret2.PacketTunnel}
PRODUCT_NAME="Zapret2PacketTunnel"
APPEX="$BUILD_DIR/$PRODUCT_NAME.appex"
EXECUTABLE="$APPEX/Contents/MacOS/$PRODUCT_NAME"
INFO_PLIST="$APPEX/Contents/Info.plist"
BRIDGE_OBJ="$BUILD_DIR/Zapret2CoreBridge-extension.o"
LUA_ENV="$SCRIPT_DIR/.deps/lua-env.sh"
CODESIGN_IDENTITY=${CODESIGN_IDENTITY:--}

[ "$(uname)" = "Darwin" ] || {
  echo "error: Packet Tunnel extension can only be built on Darwin" >&2
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

if [ ! -f "$REPO_DIR/nfq2/libzapret2core-darwin.a" ]; then
  "$SCRIPT_DIR/build-core.sh"
fi

if [ -f "$LUA_ENV" ]; then
  # shellcheck disable=SC1090
  . "$LUA_ENV"
fi

rm -rf "$APPEX"
mkdir -p "$APPEX/Contents/MacOS"

cc -c "$SCRIPT_DIR/Sources/Zapret2CoreBridge.c" \
  -I"$REPO_DIR/nfq2" \
  ${LUA_CFLAGS:-} \
  -o "$BRIDGE_OBJ"

swiftc -emit-library -parse-as-library \
  -module-name Zapret2PacketTunnel \
  "$SCRIPT_DIR/Sources/PacketTunnelProvider.swift" \
  "$SCRIPT_DIR/Sources/PacketMetadata.swift" \
  "$SCRIPT_DIR/Sources/Zapret2CoreBindings.swift" \
  "$SCRIPT_DIR/Sources/Zapret2PacketProcessor.swift" \
  "$SCRIPT_DIR/Sources/PacketRelay.swift" \
  "$BRIDGE_OBJ" \
  "$REPO_DIR/nfq2/libzapret2core-darwin.a" \
  ${LUA_LIB:-} \
  -lz \
  -framework NetworkExtension \
  -framework Network \
  -framework Foundation \
  -o "$EXECUTABLE"

cat >"$INFO_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleDisplayName</key>
  <string>Zapret2 Packet Tunnel</string>
  <key>CFBundleExecutable</key>
  <string>$PRODUCT_NAME</string>
  <key>CFBundleIdentifier</key>
  <string>$PROVIDER_BUNDLE_ID</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>$PRODUCT_NAME</string>
  <key>CFBundlePackageType</key>
  <string>XPC!</string>
  <key>CFBundleShortVersionString</key>
  <string>02.00.000</string>
  <key>CFBundleVersion</key>
  <string>02.00.000</string>
  <key>NSExtension</key>
  <dict>
    <key>NSExtensionPointIdentifier</key>
    <string>com.apple.networkextension.packet-tunnel</string>
    <key>NSExtensionPrincipalClass</key>
    <string>PacketTunnelProvider</string>
  </dict>
</dict>
</plist>
EOF

if command -v codesign >/dev/null 2>&1; then
  codesign --force --sign "$CODESIGN_IDENTITY" \
    --entitlements "$SCRIPT_DIR/PacketTunnel.entitlements" \
    "$APPEX" >/dev/null 2>&1 || {
      echo "warning: codesign failed. Set CODESIGN_IDENTITY to a valid identity with Network Extension entitlement." >&2
    }
fi

echo "$APPEX"
echo "Provider bundle id: $PROVIDER_BUNDLE_ID"
