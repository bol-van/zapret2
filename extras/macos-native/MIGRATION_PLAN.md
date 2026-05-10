# macOS Native Migration Work Plan

Goal: deliver a stable MacBook version that uses the new zapret2 packet engine,
keeps the original upstream repository updateable, and preserves the macOS menu
as the user-facing shell only.

Current MacBook version: `02.00.000`.

## Guardrails

- Keep `origin` as the original upstream repository.
- Keep macOS development on the fork branch.
- Prefer additive files over edits to upstream core files.
- Keep macOS-specific code in `extras/macos-native` and `extras/macos-menu`.
- Touch `nfq2` only through narrow shared APIs needed by all backends.
- Do not reintroduce zapret v1 `tpws + pf` runtime.

## Phase 1: Core API Extraction

Purpose: make the zapret2 engine usable without Linux NFQUEUE, BSD divert, or
Windows WinDivert loops.

Status:

- Local Lua dependency can be built without Homebrew or sudo.
- Darwin core binary can be built with `extras/macos-native/build-core.sh`.
- `nfq2/dvtws2 --version` runs on macOS.
- Default blob initialization has been extracted from `nfqws.c` into
  `nfq2/zapret2_defaults.*`.
- Initial/no-action profile creation and profile defaults have been extracted
  into `nfq2/zapret2_profiles.*`.
- `zapret2_engine_init_from_config(...)` still needs real config/profile init.

Work items:

1. Keep `nfq2/zapret2_engine.*` as the stable shared API.
2. Extract config/argument parsing from `nfqws.c` into reusable functions.
3. Extract default blob initialization.
4. Extract profile/template initialization.
5. Extract hostlist/ipset registration and loading.
6. Extract Lua initialization and shutdown.
7. Extract conntrack initialization.
8. Make `zapret2_engine_init_from_config(...)` return `OK` only after all
   required state is initialized.

Done when:

- `zapret2_engine_init_from_config(...)` can load a preset file.
- `zapret2_engine_is_ready()` returns true after successful init.
- `zapret2_engine_process_packet(...)` can be called safely by an external
  backend.
- Existing Linux/BSD/Windows targets still build after the extraction.

Status: the macOS preset subset now reaches `OK` through the bridge smoke test;
full CLI option parity remains intentionally outside the current macOS subset.

## Phase 2: macOS Core Bridge

Purpose: connect Swift/Network Extension code to the C engine without leaking
upstream internals into macOS UI code.

Work items:

1. Build `Zapret2CoreBridge.c` into a native library.
2. Add Swift bindings for init/process/shutdown.
3. Load one preset from `extras/macos-native/configs`.
4. Add structured errors for missing Lua, bad preset, or unready engine.

Done when:

- `zapret2-mac-backend diagnose` can report bridge/core readiness.
- A packet can pass through Swift -> C bridge -> `zapret2_engine`.
- Failures are visible in menu status, not hidden in logs.

Status: the C bridge archive, Swift bindings, and preset init smoke test are in
place. The Packet Tunnel skeleton now parses packet metadata before relay.
The backend also has `NETunnelProviderManager` control wiring for a future signed
extension target. End-to-end packet processing still depends on Phase 3 relay and
extension packaging work.

## Phase 3: utun/root Packet Boundary

Purpose: replace the missing macOS packet interception layer with an
open-source-friendly root runtime that does not require Apple Developer Program
payment or Network Extension entitlement.

Work items:

1. Keep `zapret2-utun-check` as the minimal smoke test for `utun` availability.
2. Open and configure a root-owned `utun` interface.
3. Implement route/DNS/MTU handling.
4. Implement packet read/write loop through the C bridge.
5. Prevent loops and self-capture.
6. Handle sleep/wake and network changes.
7. Add start/stop/status integration with the menu helper.

Done when:

- The `utun` runtime starts and stops reliably.
- Non-target traffic remains usable.
- Packet relay survives Wi-Fi changes and sleep/wake.
- The menu can show meaningful backend status.

Network Extension remains as a prepared future path under
`Sources/PacketTunnelProvider.swift`, `NetworkExtensionController.swift`, and
`build-extension.sh`. Enable it with `ZAPRET_BACKEND_MODE=network-extension`
only after a valid signing identity with Packet Tunnel entitlement is available.

## Phase 4: Discord and Operator Profiles

Purpose: fix Discord by treating Web, Gateway, and Voice/Media as different
paths with separate diagnostics and strategies.

Work items:

1. Keep presets outside upstream core under `extras/macos-native/configs`.
2. Implement `base`, `youtube`, `discord-media`, and `aggressive` profile
   selection in the backend.
3. Add Discord Web check.
4. Add Discord Gateway check.
5. Add Discord UDP/STUN/media readiness check.
6. Add operator-specific preset override files.
7. Show selected profile and last failure reason in the menu.

Done when:

- YouTube still works.
- Discord Web and Gateway are diagnosed separately.
- Discord Voice/Media uses UDP/STUN/discord media strategy.
- Users can switch profiles without editing config files manually.

## Phase 5: Packaging and Updates

Purpose: make the solution installable and updateable for another MacBook user.

Work items:

1. Keep `install-shared.sh` based on `origin` plus `fork`.
2. Keep `sync-upstream.sh` as the safe update workflow.
3. Add version reporting for app/backend/core.
4. Add signing and entitlements documentation.
5. Add installer checks for Network Extension requirements.
6. Add rollback/uninstall flow.

Done when:

- A clean machine can install from the fork branch.
- The app can update from upstream without losing macOS work.
- The menu shows MacBook version, backend version, and core readiness.

## Immediate Next Fixes

1. Extract the first reusable init function from `nfqws.c` into `zapret2_engine`.
2. Wire `zapret2_engine_init_from_config(...)` to validate preset files.
3. Implement the `utun` packet loop and route setup.
4. Add backend/menu status output for `engine not initialized`, `Lua missing`,
   and `utun` unavailable.
5. Keep all Discord tuning in `extras/macos-native/configs`.
