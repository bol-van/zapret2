#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
APP_NAME="Zapret2 Menu.app"
EXECUTABLE_NAME="Zapret2 Menu"
BUILD_DIR="${SCRIPT_DIR}/build"
APP_DIR="${BUILD_DIR}/${APP_NAME}"
MACOS_DIR="${APP_DIR}/Contents/MacOS"
RESOURCES_DIR="${APP_DIR}/Contents/Resources"
ICONSET_DIR="${BUILD_DIR}/ZapretIcon.iconset"

command -v swiftc >/dev/null 2>&1 || {
  echo "swiftc is required. Install Xcode Command Line Tools first." >&2
  exit 1
}

rm -rf "$APP_DIR" "$ICONSET_DIR"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR" "$ICONSET_DIR"

cp "$SCRIPT_DIR/Info.plist" "$APP_DIR/Contents/Info.plist"

swift "$SCRIPT_DIR/make-icon.swift" "$ICONSET_DIR"
if command -v iconutil >/dev/null 2>&1; then
  iconutil -c icns "$ICONSET_DIR" -o "$RESOURCES_DIR/ZapretIcon.icns"
fi

swiftc "$SCRIPT_DIR/Sources/ZapretMenu.swift" \
  -o "$MACOS_DIR/$EXECUTABLE_NAME" \
  -framework Cocoa \
  -framework UserNotifications

chmod +x "$MACOS_DIR/$EXECUTABLE_NAME"
touch "$APP_DIR"

echo "$APP_DIR"
