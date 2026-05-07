# Zapret2 Menu for macOS

Optional macOS menu bar controller for `zapret2`.

> **Compatibility status**
>
> `zapret2` does not currently provide a native macOS packet backend. The upstream manual states that macOS is unsupported because Apple removed the BSD `ipdivert` mechanism needed by the `dvtws2` path.
>
> This module is a practical macOS compatibility layer. It reuses the proven `zapret` v1 macOS runtime (`tpws + pf`) and installs it into a separate `/opt/zapret2` tree, then controls it with a `Zapret2 Menu.app` menu bar UI.

## What You Get

The app lives in the macOS menu bar and provides:

- start, stop, and restart controls;
- hostlist update;
- connection check for internet, Apple, YouTube, and Discord;
- human-readable status;
- Russian/English interface switch;
- launch at user login while keeping the compatibility backend off after reboot.

## Requirements

- macOS;
- Xcode Command Line Tools (`swiftc`);
- a working zapret v1 macOS runtime at `/opt/zapret` by default;
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

Custom source zapret v1 runtime:

```sh
ZAPRET1_BASE=/opt/zapret extras/macos-menu/install.sh
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
3. Copies the working v1 macOS runtime into `/opt/zapret2`.
4. Rewrites PF anchor names to `zapret2`, `zapret2-v4`, and `zapret2-v6` so they do not collide with `/opt/zapret`.
5. Installs `/opt/zapret2/zapret2-menu-helper`.
6. Adds a limited sudoers rule in `/etc/sudoers.d/zapret2-menu`.
7. Adds a user LaunchAgent so the menu app starts at login.

## Security Note

The menu app needs elevated privileges because the compatibility backend controls PF rules and root-owned daemons.

The installer does **not** grant broad passwordless sudo. It grants passwordless access only to:

```text
/opt/zapret2/zapret2-menu-helper start
/opt/zapret2/zapret2-menu-helper stop
/opt/zapret2/zapret2-menu-helper restart
/opt/zapret2/zapret2-menu-helper update
```

The sudoers file is validated with `visudo -cf` before installation.

## Use

Menu bar icons:

- `📳` compatibility backend is running;
- `📴` compatibility backend is stopped;
- `🔀` compatibility backend is restarting.

Menu actions:

- `📳 Start` starts the `/opt/zapret2` compatibility backend.
- `📴 Stop` stops `/opt/zapret2` and clears only `zapret2` PF anchors.
- `🔀 Restart` refreshes the backend only when it is already running and internet check passes.
- `🔂 Update Hostlist` downloads the domain list.
- `📶 Check Connection` shows statuses for internet, `apple.com`, `youtube.com`, and `discord.com`.
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

The original `/opt/zapret` runtime is never removed by this module.

## Build Only

```sh
extras/macos-menu/build.sh
```

The built app is written to:

```text
extras/macos-menu/build/Zapret2 Menu.app
```

## Native zapret2 Backend

This module is not a native `nfqws2` macOS backend. See `docs/macos-native-backend.md` for the design notes and missing kernel boundary needed for true native support.
