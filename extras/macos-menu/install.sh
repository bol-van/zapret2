#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
APP_NAME="Zapret2 Menu.app"
EXECUTABLE_NAME="Zapret2 Menu"
ZAPRET_BASE=${ZAPRET_BASE:-/opt/zapret2}
INSTALL_USER=${INSTALL_USER:-$(id -un)}
INSTALL_UID=$(id -u "$INSTALL_USER")
INSTALL_HOME=$(dscl . -read "/Users/$INSTALL_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
[ -n "$INSTALL_HOME" ] || INSTALL_HOME=$(eval echo "~$INSTALL_USER")
INSTALL_DIR=${INSTALL_DIR:-"$INSTALL_HOME/Applications/Zapret2 Control"}
APP_PATH="$INSTALL_DIR/$APP_NAME"
LAUNCH_AGENT="$INSTALL_HOME/Library/LaunchAgents/org.zapret2.menu.plist"
SUDOERS_FILE="/etc/sudoers.d/zapret2-menu"
HELPER_SRC="$SCRIPT_DIR/zapret2-menu-helper"
HELPER_DST="$ZAPRET_BASE/zapret2-menu-helper"
METADATA_DST="$ZAPRET_BASE/zapret2-menu.env"
NATIVE_BACKEND_SRC="$SOURCE_DIR/extras/macos-native/build/zapret2-mac-backend"
NATIVE_BACKEND_DST="$ZAPRET_BASE/bin/zapret2-mac-backend"
NATIVE_BRIDGE_CHECK_SRC="$SOURCE_DIR/extras/macos-native/build/zapret2-core-bridge-check"
NATIVE_BRIDGE_CHECK_DST="$ZAPRET_BASE/bin/zapret2-core-bridge-check"
NATIVE_UTUN_CHECK_SRC="$SOURCE_DIR/extras/macos-native/build/zapret2-utun-check"
NATIVE_UTUN_CHECK_DST="$ZAPRET_BASE/bin/zapret2-utun-check"
NATIVE_UTUN_RUNTIME_SRC="$SOURCE_DIR/extras/macos-native/build/zapret2-utun-runtime"
NATIVE_UTUN_RUNTIME_DST="$ZAPRET_BASE/bin/zapret2-utun-runtime"
PACKET_TUNNEL_SRC="$SOURCE_DIR/extras/macos-native/build/Zapret2PacketTunnel.appex"
PACKET_TUNNEL_DST="$ZAPRET_BASE/PlugIns/Zapret2PacketTunnel.appex"
TUNNEL_PROVIDER_BUNDLE_ID=${ZAPRET_TUNNEL_PROVIDER_BUNDLE_ID:-org.zapret2.PacketTunnel}
UPSTREAM_URL=${UPSTREAM_URL:-https://github.com/bol-van/zapret2.git}
FORK_URL=${FORK_URL:-https://github.com/pitk150-alt/zapret2.git}
BRANCH=${BRANCH:-$(git -C "$SOURCE_DIR" branch --show-current 2>/dev/null || true)}
[ -n "$BRANCH" ] || BRANCH=feature/macos-menu-controller

[ "$(uname)" = "Darwin" ] || {
  echo "This menu app is macOS-only." >&2
  exit 1
}

shell_quote() {
  printf "'%s'" "$(printf "%s" "$1" | sed "s/'/'\\\\''/g")"
}

stop_legacy_tpws_processes() {
  legacy_init="$ZAPRET_BASE/init.d/macos/zapret"
  legacy_config="$ZAPRET_BASE/config.legacy-tpws"
  if [ -x "$legacy_init" ]; then
    echo "Stopping legacy pf anchors before replacing runtime..."
    sudo ZAPRET_CONFIG="$legacy_config" "$legacy_init" stop-fw 2>/dev/null || true
    sudo ZAPRET_CONFIG="$legacy_config" "$legacy_init" stop 2>/dev/null || true
  fi
  sudo /sbin/pfctl -qa zapret2-v4 -F all 2>/dev/null || true
  sudo /sbin/pfctl -qa zapret2-v6 -F all 2>/dev/null || true
  sudo /sbin/pfctl -qa zapret2 -F all 2>/dev/null || true

  pids=$(/usr/bin/pgrep -f "^$ZAPRET_BASE/tpws/tpws" 2>/dev/null || true)
  if [ -n "$pids" ]; then
    echo "Stopping remaining legacy tpws processes from previous compatibility runtime..."
    sudo /bin/kill $pids 2>/dev/null || true
    /bin/sleep 1
    pids=$(/usr/bin/pgrep -f "^$ZAPRET_BASE/tpws/tpws" 2>/dev/null || true)
    [ -z "$pids" ] || sudo /bin/kill -9 $pids 2>/dev/null || true
  fi
}

sudo chown -R "$INSTALL_USER":staff "$SOURCE_DIR/extras/macos-native/build" "$SCRIPT_DIR/build" 2>/dev/null || true
"$SOURCE_DIR/extras/macos-native/build.sh"
APP_BUILT=$("$SCRIPT_DIR/build.sh")
sudo chown -R "$INSTALL_USER":staff "$SOURCE_DIR/extras/macos-native/build" 2>/dev/null || true
sudo chown -R "$INSTALL_USER":staff "$SCRIPT_DIR/build" 2>/dev/null || true
mkdir -p "$INSTALL_DIR"
sudo chown "$INSTALL_USER":staff "$INSTALL_DIR" 2>/dev/null || true
rm -rf "$APP_PATH" 2>/dev/null || sudo rm -rf "$APP_PATH"
cp -R "$APP_BUILT" "$APP_PATH"
sudo chown -R "$INSTALL_USER":staff "$APP_PATH" 2>/dev/null || true
xattr -dr com.apple.quarantine "$APP_PATH" 2>/dev/null || true

cat <<EOF
Installing zapret2 native macOS runtime scaffold.
Target runtime: $ZAPRET_BASE

This installer does not copy or depend on zapret v1.
The default open-source backend path is utun/root; Network Extension is prepared for future signing.
EOF

stop_legacy_tpws_processes

if [ -f "$ZAPRET_BASE/config" ]; then
  sudo mv "$ZAPRET_BASE/config" "$ZAPRET_BASE/config.legacy-tpws"
fi
sudo mkdir -p "$ZAPRET_BASE/bin" "$ZAPRET_BASE/extras/macos-native" "$ZAPRET_BASE/config" "$ZAPRET_BASE/PlugIns"
sudo install -m 0755 -o root -g wheel "$NATIVE_BACKEND_SRC" "$NATIVE_BACKEND_DST"
sudo install -m 0755 -o root -g wheel "$NATIVE_BRIDGE_CHECK_SRC" "$NATIVE_BRIDGE_CHECK_DST"
sudo install -m 0755 -o root -g wheel "$NATIVE_UTUN_CHECK_SRC" "$NATIVE_UTUN_CHECK_DST"
sudo install -m 0755 -o root -g wheel "$NATIVE_UTUN_RUNTIME_SRC" "$NATIVE_UTUN_RUNTIME_DST"
sudo install -m 0755 -o root -g wheel "$HELPER_SRC" "$HELPER_DST"
sudo rm -rf "$PACKET_TUNNEL_DST"
sudo cp -R "$PACKET_TUNNEL_SRC" "$PACKET_TUNNEL_DST"
sudo chown -R root:wheel "$PACKET_TUNNEL_DST"
sudo rm -rf "$ZAPRET_BASE/lua" "$ZAPRET_BASE/extras/macos-native/configs"
sudo cp -R "$SOURCE_DIR/lua" "$ZAPRET_BASE/lua"
sudo cp -R "$SOURCE_DIR/extras/macos-native/configs" "$ZAPRET_BASE/extras/macos-native/configs"
sudo chown -R root:wheel "$ZAPRET_BASE/lua" "$ZAPRET_BASE/extras/macos-native/configs"
sudo chmod -R a+rX "$ZAPRET_BASE/lua" "$ZAPRET_BASE/extras/macos-native/configs"

TMP_SUDOERS=$(mktemp)
cat >"$TMP_SUDOERS" <<EOF
$INSTALL_USER ALL=(root) NOPASSWD: $HELPER_DST start, $HELPER_DST stop, $HELPER_DST restart, $HELPER_DST update, $HELPER_DST update-all, $HELPER_DST reinstall, $HELPER_DST status, $HELPER_DST profiles, $HELPER_DST profile, $HELPER_DST check-profile, $HELPER_DST check-profile *, $HELPER_DST check-utun, $HELPER_DST reset-network, $HELPER_DST discover-discord-media, $HELPER_DST enable-discord-media-routes, $HELPER_DST disable-discord-media-routes, $HELPER_DST fix-discord-startup, $HELPER_DST reset-discord-cache, $HELPER_DST set-profile *
EOF
sudo visudo -cf "$TMP_SUDOERS"
sudo install -m 0440 -o root -g wheel "$TMP_SUDOERS" "$SUDOERS_FILE"
rm -f "$TMP_SUDOERS"

TMP_METADATA=$(mktemp)
cat >"$TMP_METADATA" <<EOF
ZAPRET_MENU_SOURCE_DIR=$(shell_quote "$SOURCE_DIR")
ZAPRET_MENU_INSTALL_USER=$(shell_quote "$INSTALL_USER")
ZAPRET_MENU_INSTALL_HOME=$(shell_quote "$INSTALL_HOME")
ZAPRET_MENU_INSTALL_DIR=$(shell_quote "$INSTALL_DIR")
ZAPRET_MENU_ZAPRET_BASE=$(shell_quote "$ZAPRET_BASE")
ZAPRET_MENU_UPSTREAM_URL=$(shell_quote "$UPSTREAM_URL")
ZAPRET_MENU_FORK_URL=$(shell_quote "$FORK_URL")
ZAPRET_MENU_BRANCH=$(shell_quote "$BRANCH")
ZAPRET_BACKEND_MODE='utun'
ZAPRET_TUNNEL_PROVIDER_BUNDLE_ID=$(shell_quote "$TUNNEL_PROVIDER_BUNDLE_ID")
EOF
sudo install -m 0644 -o root -g wheel "$TMP_METADATA" "$METADATA_DST"
rm -f "$TMP_METADATA"

mkdir -p "$INSTALL_HOME/Library/LaunchAgents"
cat >"$LAUNCH_AGENT" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>org.zapret2.menu</string>
  <key>ProgramArguments</key>
  <array>
    <string>$APP_PATH/Contents/MacOS/$EXECUTABLE_NAME</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <false/>
  <key>LimitLoadToSessionType</key>
  <string>Aqua</string>
  <key>StandardOutPath</key>
  <string>/tmp/zapret2-menu.out.log</string>
  <key>StandardErrorPath</key>
  <string>/tmp/zapret2-menu.err.log</string>
</dict>
</plist>
EOF
sudo chown "$INSTALL_USER":staff "$LAUNCH_AGENT" 2>/dev/null || true

launchctl bootout "gui/$INSTALL_UID" "$LAUNCH_AGENT" 2>/dev/null || true
pkill -x "$EXECUTABLE_NAME" 2>/dev/null || true
launchctl bootstrap "gui/$INSTALL_UID" "$LAUNCH_AGENT"

cat <<EOF
Installed: $APP_PATH
LaunchAgent: $LAUNCH_AGENT
Helper: $HELPER_DST
sudoers: $SUDOERS_FILE
EOF
