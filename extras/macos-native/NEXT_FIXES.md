# Next Approved Fixes

These fixes are approved for implementation under the upstream-safe rules.

## 1. Core Init Extraction

Scope:

- Add reusable init helpers behind `nfq2/zapret2_engine.*`.
- Do not rewrite existing Linux/BSD/Windows loops.
- Keep behavior of `nfqws2`, `dvtws2`, and `winws2` unchanged.

First target:

- `zapret2_engine_init_from_config(...)` validates that a preset exists,
  initializes reusable state, and reports a structured reason when the engine is
  not ready.

Current unblocked state:

- Local Lua builds without Homebrew.
- `make -C nfq2 darwin` is available through `build-core.sh`.
- Default blobs, profile defaults, `.args` file loading, macOS preset option
  parsing, hostlist/ipset loading, Lua init, and conntrack init are available
  through `zapret2_engine_init_from_config(...)`.
- `build-core.sh` builds both `dvtws2` and `libzapret2core-darwin.a`.
- `build.sh` builds the C bridge archive and `zapret2-core-bridge-check`.
- Swift bindings are present in `Sources/Zapret2CoreBindings.swift`, and the
  Packet Tunnel skeleton initializes a preset before applying tunnel settings.
- Runtime profile commands are available through `zapret2-mac-backend` and
  `zapret2-menu-helper`.
- The next blocker is the default `utun/root` packet loop and routing setup.

## 2. Backend Status

Scope:

- Extend `zapret2-mac-backend status` and `diagnose`.
- Report:
  - backend scaffold state;
  - engine init state;
  - Lua/pkg-config dependency state;
- backend mode: default `utun`, optional future `network-extension`;
- `utun` availability state;
- Network Extension availability state for signed future builds.
- `start`/`stop` now maintain requested state and expose whether the selected
  profile and `utun` smoke check are ready.

## 3. Menu Status

Scope:

- Show MacBook version `02.00.000`.
- Show native backend readiness clearly.
- Keep Discord Web/Gateway/Voice diagnostics separated.
- Discord Voice/Media readiness validates `discord-media` through the bridge and
  runs a basic STUN/UDP probe.

## 4. Profile Presets

Scope:

- Keep presets under `extras/macos-native/configs`.
- Presets now load through the C bridge smoke test.
- Runtime profile selection is implemented without modifying upstream core.
- Profile switching is exposed as a menu submenu.

## 6. Network Extension Relay

Scope:

- `PacketRelay` now fails explicitly with `missingNetworkPath` instead of
  silently dropping the missing relay problem.
- `PacketTunnelProvider` cancels the tunnel when relay is missing.
- `PacketMetadata` extracts IPv4/IPv6, transport protocol, addresses, and
  TCP/UDP ports before relay.
- `UdpPacketRelay` sends UDP payloads with `NWConnection` and writes UDP/IP
  response packets back to `NEPacketTunnelFlow`.
- Unsupported non-UDP packets are counted as unsupported instead of cancelling
  the tunnel.
- The default route mode is `udp-development`; `full-tunnel` is opt-in through
  `ZAPRET_TUNNEL_ROUTE_MODE=full-tunnel`.
- `NetworkExtensionController` can create/start/stop a `NETunnelProviderManager`
  when `ZAPRET_TUNNEL_PROVIDER_BUNDLE_ID` points to a signed Packet Tunnel
  provider.
- `build-extension.sh` builds a dev `Zapret2PacketTunnel.appex` scaffold with
  Packet Tunnel metadata and entitlements template.
- Next implementation step: use a real signing identity with Network Extension
  entitlement, then add TCP relay and loop-prevention strategy.

This path is intentionally parked as a prepared future target until signing and
Network Extension entitlement are available.

## 7. utun/root Runtime

Scope:

- `Sources/UtunCheck.c` opens `com.apple.net.utun_control` and reports the
  allocated interface name.
- `build.sh` builds `zapret2-utun-check`.
- `install.sh` installs `zapret2-utun-check` into `/opt/zapret2/bin`.
- `zapret2-mac-backend diagnose/status/check-utun/start` report `utun`
  readiness.
- Default backend mode is `utun`; set `ZAPRET_BACKEND_MODE=network-extension`
  only for signed Packet Tunnel builds.

Next implementation step: create the root packet loop that configures routes,
reads raw packets from the `utun` fd, feeds them into the zapret2 bridge, and
reinjects/passes traffic without self-capture.

## 5. Update Safety

Scope:

- Use `sync-upstream.sh` for update flow.
- Do not run destructive git commands.
- Keep `origin/master` merge-based updates reviewable.
