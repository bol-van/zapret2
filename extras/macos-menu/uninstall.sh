#!/bin/sh
set -eu

ZAPRET_BASE=${ZAPRET_BASE:-/opt/zapret2}
INSTALL_DIR=${INSTALL_DIR:-"$HOME/Applications/Zapret2 Control"}
INSTALL_USER=${INSTALL_USER:-$(id -un)}
INSTALL_UID=$(id -u "$INSTALL_USER")
APP_PATH="$INSTALL_DIR/Zapret2 Menu.app"
LAUNCH_AGENT="$HOME/Library/LaunchAgents/org.zapret2.menu.plist"
SUDOERS_FILE="/etc/sudoers.d/zapret2-menu"
HELPER_DST="$ZAPRET_BASE/zapret2-menu-helper"

[ "$(uname)" = "Darwin" ] || {
  echo "This menu app is macOS-only." >&2
  exit 1
}

launchctl bootout "gui/$INSTALL_UID" "$LAUNCH_AGENT" 2>/dev/null || true
pkill -x "Zapret2 Menu" 2>/dev/null || true

rm -f "$LAUNCH_AGENT"
rm -rf "$APP_PATH"

echo "Removing privileged helper and sudoers rule. You may be asked for your macOS password."
sudo "$HELPER_DST" stop 2>/dev/null || true
sudo rm -f "$HELPER_DST" "$SUDOERS_FILE"

if [ "${REMOVE_ZAPRET2_RUNTIME:-0}" = "1" ]; then
  sudo rm -rf "$ZAPRET_BASE"
  echo "Removed compatibility runtime: $ZAPRET_BASE"
else
  echo "Left compatibility runtime in place: $ZAPRET_BASE"
fi

echo "Zapret2 Menu removed."
