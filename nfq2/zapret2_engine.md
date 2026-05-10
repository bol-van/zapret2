# zapret2 Engine Extraction Notes

`zapret2_engine` is the shared packet-processing API for OS backends that do not
own an existing Linux/BSD/Windows packet interception loop.

## Current API

- `zapret2_engine_init_from_config(...)`
- `zapret2_engine_is_ready()`
- `zapret2_engine_process_packet(...)`
- `zapret2_engine_shutdown()`

`zapret2_engine_process_packet(...)` wraps `dpi_desync_packet(...)`, but refuses
to process packets until the engine is initialized. This prevents native macOS
code from accidentally invoking zapret2 packet processing without Lua profiles,
hostlists, ipsets, conntrack, and default blobs being prepared.

## Extracted So Far

- Default blob initialization is available through `zapret2_apply_default_blobs`
  in `zapret2_defaults.*`.
- Initial/no-action profile creation and profile defaults are available through
  `zapret2_profiles.*`.
- Argument-file loading is available through `zapret2_config_load_args` in
  `zapret2_config.*`. It preserves the existing `@file`/`$file` splitting
  behavior while returning structured errors for non-CLI backends.
- The macOS preset option subset is available through `zapret2_engine_apply_args`
  in `zapret2_options.*`. It currently supports the options used by
  `extras/macos-native/configs`.
- `zapret2_engine_init_from_config(...)` now loads preset args, applies profile
  defaults, loads hostlists/ipsets, validates and initializes Lua, initializes
  conntrack, and marks the engine ready.

## Remaining Extraction Work

The following CLI-only or broad compatibility logic still lives inside
`nfqws.c` `main(...)` and can be extracted later if native backends need it:

1. Full command-line option coverage beyond the macOS preset subset.
2. Template import and advanced profile option parsing.
3. Auto-hostlist tuning and writable-directory handling.
4. Dry-run validation that does not depend on OS packet capture.

The existing OS loops should keep their capture/reinject logic. The shared
engine should own only config, profiles, Lua, conntrack, and packet decisions.
