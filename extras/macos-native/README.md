# Native zapret2 Backend for macOS

This directory is the start of the real macOS port of the zapret2 packet
engine. It intentionally does not depend on the old zapret v1 `tpws + pf`
runtime.

## Goal

The current open-source target architecture is:

1. A root-owned macOS packet boundary implemented with `utun`.
2. A small adapter that feeds raw IP packets into the zapret2 packet engine.
3. Existing zapret2 Lua strategies for TCP, QUIC, STUN, and Discord media.
4. The existing menu bar app as the user-facing controller.

The menu app remains a macOS UX layer only. Network traffic handling must live in
the native zapret2 backend.

## Why utun first

macOS does not provide Linux NFQUEUE, Windows WinDivert, or a compatible BSD
divert path. Apple removed the classic `ipdivert` mechanism, and macOS `pf`
cannot transparently pass packets to `dvtws2` the way OpenBSD can.

Network Extension is the best Apple-native production API, but Packet Tunnel
providers require a paid Apple Developer Program membership and the Network
Extension entitlement. Until signing is available, this project keeps Network
Extension as a prepared future path and uses `utun/root` as the default
open-source path.

## Current State

This is a native backend scaffold with a reusable Darwin core library, C bridge
init check, and `utun` availability check. Presets under `configs/` can now
initialize zapret2 reusable state through `zapret2_engine_init_from_config(...)`,
including profile defaults, Lua scripts, hostlists/ipsets, and conntrack.

The repository still does not contain a production Darwin packet boundary that
can feed packets into `dpi_desync_packet(...)` and reinject the result.
`start`/`stop` already maintain requested backend state. In default `utun` mode,
`start` validates the selected profile and checks whether macOS allows opening an
`utun` interface; the packet read/write loop and routing setup are still pending.
The Network Extension skeleton contains a first-pass UDP relay path. Unsupported
packets are counted without cancelling the tunnel, but TCP relay and loop
prevention are still missing.
`zapret2-mac-backend` can manage a `NETunnelProviderManager` when
`ZAPRET_TUNNEL_PROVIDER_BUNDLE_ID` points to a signed Packet Tunnel provider,
and `build-extension.sh` creates a dev `.appex` scaffold. Real startup still
requires a valid signing identity with the Packet Tunnel Network Extension
entitlement.
Use `ZAPRET_BACKEND_MODE=network-extension` only after a valid signing identity
with Network Extension entitlement is available. The default mode is `utun`.

See `MIGRATION_PLAN.md` for the phased work plan.

Run:

```sh
extras/macos-native/build.sh
```

The script validates the local build environment and reports the current native
backend readiness.

Build only the Packet Tunnel extension scaffold with:

```sh
ZAPRET_TUNNEL_PROVIDER_BUNDLE_ID=org.zapret2.PacketTunnel extras/macos-native/build-extension.sh
```

Set `CODESIGN_IDENTITY` to a valid identity with Network Extension entitlement
for a system-loadable provider. The default ad-hoc signature is useful only for
local build validation.

Run:

```sh
extras/macos-native/doctor.sh
```

to check local development prerequisites.

If `doctor.sh` reports missing Lua/pkg-config dependencies and Homebrew is
available, install the development dependencies with:

```sh
extras/macos-native/install-dev-deps.sh
```

If Homebrew is not available or sudo is not possible, build Lua locally inside
the workspace instead:

```sh
extras/macos-native/build-core-deps.sh
```

Then build the Darwin core binary and reusable static library:

```sh
extras/macos-native/build-core.sh
```

After `build.sh`, profile commands can be checked from the checkout:

```sh
extras/macos-native/build/zapret2-mac-backend profiles
extras/macos-native/build/zapret2-mac-backend check-profile discord-media
extras/macos-native/build/zapret2-mac-backend check-utun
extras/macos-native/build/zapret2-mac-backend set-profile discord-media
```

Installed systems use the same commands through `/opt/zapret2/zapret2-menu-helper`.
The selected profile is stored in `/opt/zapret2/config/macos-native-profile`.

## Source Layout

- `zapret2-mac-backend.swift` is the privileged helper-facing CLI scaffold.
- `Sources/UtunCheck.c` is a minimal `utun` smoke test used by diagnose/status.
- `Sources/NetworkExtensionController.swift` owns `NETunnelProviderManager`
  start/stop/status wiring.
- `build-extension.sh` builds `Zapret2PacketTunnel.appex` for dev validation.
- `Sources/PacketTunnelProvider.swift` is the Network Extension packet boundary skeleton.
- `Sources/PacketMetadata.swift` extracts IPv4/IPv6 and TCP/UDP/ICMP metadata
  before packets enter the relay layer.
- `Sources/Zapret2CoreBindings.swift` declares the Swift calls into the C bridge.
- `Sources/Zapret2PacketProcessor.swift` defines the Swift packet processing interface.
- `Sources/PacketRelay.swift` marks the still-missing network relay layer.
- `Sources/PacketRelay.swift` contains the first-pass UDP relay and explicit
  unsupported-protocol errors for traffic that still needs a relay implementation.
- `Sources/Zapret2CoreBridge.h` and `Sources/Zapret2CoreBridge.c` define the C bridge into zapret2 core.
- `Sources/Zapret2CoreBridgeCheck.c` is a small bridge init smoke test for presets.

`build.sh` builds the bridge object/archive and links `zapret2-core-bridge-check`
against `nfq2/libzapret2core-darwin.a`.

See `nfq2/zapret2_engine.md` for the extraction plan.

## Keeping Upstream Updateable

The macOS port must stay easy to refresh from the original zapret2 repository.
See `extras/macos-native/UPSTREAM-SAFE.md` for the development rules and use:

```sh
extras/macos-native/sync-upstream.sh
```

## Discord Strategy

Discord must be diagnosed as several paths, not as one `discord.com` check:

- Discord Web: HTTPS availability of `discord.com`.
- Discord Gateway: HTTPS/WebSocket gateway reachability.
- Discord Voice/Media: `discord-media` preset validation plus UDP/STUN/media
  readiness, including Discord IP discovery.

The last category is the reason the old TCP-only macOS compatibility layer can
show working YouTube while Discord voice/media still fails.

The menu currently reports Discord Voice/Media readiness by validating the
`discord-media` preset through the core bridge and running a basic STUN/UDP
probe. Real traffic handling now depends on completing the default `utun/root`
packet loop, or later enabling the signed Network Extension path.
