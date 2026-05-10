# Zapret2 Menu for macOS

Optional macOS menu bar controller for `zapret2`.

> **Native backend status**
>
> This menu is being moved to a real macOS backend for the new zapret2 packet engine.
>
> The old zapret v1 `tpws + pf` compatibility runtime is no longer the target architecture. The production target is a Network Extension packet boundary feeding packets into zapret2 core. See `extras/macos-native`.

## What You Get

The app lives in the macOS menu bar and provides:

- start, stop, and restart controls;
- hostlist update wiring;
- connection check for internet, Apple, YouTube, Discord Web, and Discord Gateway;
- human-readable status;
- Russian/English interface switch;
- launch at user login while keeping the native backend off after reboot.

## Requirements

- macOS;
- Xcode Command Line Tools (`swiftc`);
- administrator account for installing `/opt/zapret2`, the helper, and sudoers rule.

Install Command Line Tools if needed:

```sh
xcode-select --install
```

## Install

From the repository root:

```sh
extras/macos-menu/install.sh
```

Custom target runtime:

```sh
ZAPRET_BASE=/opt/zapret2 extras/macos-menu/install.sh
```

Custom app install directory:

```sh
INSTALL_DIR="$HOME/Applications/Zapret2 Control" extras/macos-menu/install.sh
```

The installer:

1. Builds `Zapret2 Menu.app`.
2. Copies it to `$HOME/Applications/Zapret2 Control`.
3. Builds the native backend scaffold from `extras/macos-native`.
4. Installs `/opt/zapret2/bin/zapret2-mac-backend`.
5. Installs `/opt/zapret2/bin/zapret2-core-bridge-check`, Lua scripts, and native presets.
6. Installs the dev Packet Tunnel extension scaffold to `/opt/zapret2/PlugIns`.
7. Installs `/opt/zapret2/zapret2-menu-helper`.
8. Adds a limited sudoers rule in `/etc/sudoers.d/zapret2-menu`.
9. Adds a user LaunchAgent so the menu app starts at login.

## Security Note

The menu app needs elevated privileges because the native backend will control packet interception and root-owned daemons.

The installer does **not** grant broad passwordless sudo. It grants passwordless access only to:

```text
/opt/zapret2/zapret2-menu-helper start
/opt/zapret2/zapret2-menu-helper stop
/opt/zapret2/zapret2-menu-helper restart
/opt/zapret2/zapret2-menu-helper update
/opt/zapret2/zapret2-menu-helper update-all
/opt/zapret2/zapret2-menu-helper status
/opt/zapret2/zapret2-menu-helper profiles
/opt/zapret2/zapret2-menu-helper profile
/opt/zapret2/zapret2-menu-helper check-profile
/opt/zapret2/zapret2-menu-helper set-profile *
```

The sudoers file is validated with `visudo -cf` before installation.

## Use

Menu bar icons:

- `📳` native backend is running;
- `📴` native backend is stopped;
- `🔀` native backend is restarting.

Menu actions:

- `📳 Start` starts the `/opt/zapret2` native backend.
- `📴 Stop` stops the native backend.
- `🔀 Restart` refreshes the backend only when it is already running and internet check passes.
- `🎛 Native Profile` selects `base`, `youtube`, `discord-media`, or `aggressive` after validating the preset through the core bridge.
- `🔂 Update Hostlist` downloads the domain list.
- `📶 Check Connection` shows statuses for internet, `apple.com`, `youtube.com`, Discord Web, Discord Gateway, and Discord Voice/Media readiness.
- `▶ Show Status` shows runtime, last stop, list update date, and list sizes.
- `ℹ️ About` shows app dates and a short usage guide.
- `✖ Quit` stops the `/opt/zapret2` backend first, verifies it stopped, then closes the menu app.

## Uninstall

```sh
extras/macos-menu/uninstall.sh
```

The uninstaller removes:

- user LaunchAgent;
- menu app bundle;
- privileged helper;
- sudoers rule.

It leaves `/opt/zapret2` in place by default. Remove it too with:

```sh
REMOVE_ZAPRET2_RUNTIME=1 extras/macos-menu/uninstall.sh
```

The installer does not use or remove `/opt/zapret`.

## Build Only

```sh
extras/macos-menu/build.sh
```

The built app is written to:

```text
extras/macos-menu/build/Zapret2 Menu.app
```

## Native zapret2 Backend

The native backend scaffold lives in `extras/macos-native`. It is not a working packet bypass backend yet; the missing piece is the Network Extension packet boundary and adapter into zapret2 core.
