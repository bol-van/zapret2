# Native macOS zapret2 Presets

These files are planned input profiles for `zapret2_engine_init_from_config(...)`.
They are intentionally stored outside `nfq2` so upstream core can be updated with
minimal conflicts.

The files use the nfqws2-style argument-file format. The native macOS engine
currently supports the subset used by these presets through
`zapret2_engine_init_from_config(...)`.

## Presets

- `base.args`: conservative TCP/HTTPS and QUIC profile skeleton.
- `youtube.args`: YouTube-focused TLS/QUIC profile skeleton.
- `discord-media.args`: UDP/STUN/Discord media profile skeleton.
- `aggressive.args`: fallback profile for stricter DPI cases.

Operator-specific tuning should add new preset files here instead of changing
the zapret2 core.

Runtime selection:

```sh
extras/macos-native/build/zapret2-mac-backend profiles
extras/macos-native/build/zapret2-mac-backend check-profile <name>
extras/macos-native/build/zapret2-mac-backend set-profile <name>
```

After installation, use `/opt/zapret2/zapret2-menu-helper` with the same
`profiles`, `check-profile`, and `set-profile` commands.
