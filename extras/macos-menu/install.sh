#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
APP_NAME="Zapret2 Menu.app"
EXECUTABLE_NAME="Zapret2 Menu"
ZAPRET_BASE=${ZAPRET_BASE:-/opt/zapret2}
ZAPRET1_BASE=${ZAPRET1_BASE:-/opt/zapret}
INSTALL_DIR=${INSTALL_DIR:-"$HOME/Applications/Zapret2 Control"}
INSTALL_USER=${INSTALL_USER:-$(id -un)}
INSTALL_UID=$(id -u "$INSTALL_USER")
APP_PATH="$INSTALL_DIR/$APP_NAME"
LAUNCH_AGENT="$HOME/Library/LaunchAgents/org.zapret2.menu.plist"
SUDOERS_FILE="/etc/sudoers.d/zapret2-menu"
HELPER_SRC="$SCRIPT_DIR/zapret2-menu-helper"
HELPER_DST="$ZAPRET_BASE/zapret2-menu-helper"

[ "$(uname)" = "Darwin" ] || {
  echo "This menu app is macOS-only." >&2
  exit 1
}

[ -d "$ZAPRET1_BASE" ] || {
  echo "Existing zapret macOS runtime was not found at $ZAPRET1_BASE." >&2
  echo "Install and verify zapret v1 on macOS first, or set ZAPRET1_BASE." >&2
  exit 1
}

[ -x "$ZAPRET1_BASE/tpws/tpws" ] || {
  echo "tpws binary was not found at $ZAPRET1_BASE/tpws/tpws." >&2
  exit 1
}

APP_BUILT=$("$SCRIPT_DIR/build.sh")
sudo chown -R "$INSTALL_USER":staff "$SCRIPT_DIR/build" 2>/dev/null || true
mkdir -p "$INSTALL_DIR"
rm -rf "$APP_PATH"
cp -R "$APP_BUILT" "$APP_PATH"
sudo chown -R "$INSTALL_USER":staff "$APP_PATH" 2>/dev/null || true
xattr -dr com.apple.quarantine "$APP_PATH" 2>/dev/null || true

cat <<EOF
Installing zapret2 macOS compatibility runtime.
Source runtime: $ZAPRET1_BASE
Target runtime: $ZAPRET_BASE

This copies the working zapret v1 macOS runtime into a separate /opt/zapret2 tree.
The existing $ZAPRET1_BASE installation is not modified.
EOF

sudo mkdir -p "$ZAPRET_BASE"
for item in binaries common ipset init.d/macos tpws ip2net mdig config config.default; do
  if [ -e "$ZAPRET1_BASE/$item" ]; then
    sudo rm -rf "$ZAPRET_BASE/$item"
    sudo /usr/bin/ditto "$ZAPRET1_BASE/$item" "$ZAPRET_BASE/$item"
  fi
done

# Isolate PF anchors from the v1 install so stopping zapret2 does not clear zapret v1 anchors.
if [ -f "$ZAPRET_BASE/common/pf.sh" ]; then
  sudo /usr/bin/perl -0pi -e 's/zapret-v4/zapret2-v4/g; s/zapret-v6/zapret2-v6/g; s/"zapret"/"zapret2"/g; s/\/zapret-v4/\/zapret2-v4/g; s/\/zapret-v6/\/zapret2-v6/g; s/-qa zapret /-qa zapret2 /g; s/-a zapret /-a zapret2 /g; s#PF_ANCHOR_ZAPRET="\$PF_ANCHOR_DIR/zapret"#PF_ANCHOR_ZAPRET="\$PF_ANCHOR_DIR/zapret2"#g; s/zapret anchors/zapret2 anchors/g; s/zapret anchor/zapret2 anchor/g; s/rdr-anchor \\"zapret\\"/rdr-anchor \\"zapret2\\"/g; s/anchor \\"zapret\\"/anchor \\"zapret2\\"/g' "$ZAPRET_BASE/common/pf.sh"
fi

# Keep pid files separate from a regular /opt/zapret installation.
if [ -f "$ZAPRET_BASE/init.d/macos/functions" ]; then
  sudo /usr/bin/perl -0pi -e 's#^PIDDIR=/var/run$#PIDDIR=/var/run/zapret2#m' "$ZAPRET_BASE/init.d/macos/functions"
fi

# Restrict hostlist reload notifications to this runtime's tpws process.
if [ -f "$ZAPRET_BASE/ipset/def.sh" ]; then
  sudo /bin/sh -c "cat >>\"\$1\"" sh "$ZAPRET_BASE/ipset/def.sh" <<'EOF'

# macOS compatibility layer override: reload only this runtime's tpws.
hup_zapret_daemons()
{
 echo forcing zapret2 compatibility daemons to reload their hostlist
 pgrep -f "^$ZAPRET_BASE/tpws/tpws" 2>/dev/null | while read pid; do
  [ -n "$pid" ] && kill -HUP "$pid" 2>/dev/null || true
 done
}
EOF
fi

sudo install -m 0755 -o root -g wheel "$HELPER_SRC" "$HELPER_DST"

TMP_SUDOERS=$(mktemp)
cat >"$TMP_SUDOERS" <<EOF
$INSTALL_USER ALL=(root) NOPASSWD: $HELPER_DST start, $HELPER_DST stop, $HELPER_DST restart, $HELPER_DST update
EOF
sudo visudo -cf "$TMP_SUDOERS"
sudo install -m 0440 -o root -g wheel "$TMP_SUDOERS" "$SUDOERS_FILE"
rm -f "$TMP_SUDOERS"

mkdir -p "$HOME/Library/LaunchAgents"
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
