# Upstream-Safe Development Rules

The macOS native backend must remain easy to update from the original zapret2
repository.

## Repository Roles

- `origin` is the original upstream repository: `bol-van/zapret2`.
- `fork` is the macOS development fork.
- macOS work lives on `feature/macos-menu-controller` unless explicitly changed.

## Core Preservation Rules

1. Keep upstream files unchanged whenever possible.
2. Prefer additive files over invasive edits.
3. Keep macOS-specific code under `extras/macos-native` and
   `extras/macos-menu`.
4. If the zapret2 core needs a new API, add a small wrapper such as
   `nfq2/zapret2_engine.*` instead of rewriting existing packet loops.
5. Do not move Linux/BSD/Windows capture logic into macOS code.
6. Do not vendor old zapret v1 runtime files.

## Sync Workflow

Use:

```sh
extras/macos-native/sync-upstream.sh
```

The script:

- requires a clean working tree;
- fetches `origin/master`;
- fetches `fork/feature/macos-menu-controller`;
- merges upstream first;
- merges the fork branch second;
- never runs `reset` or `rebase`.

This preserves a clear history and keeps upstream updates reviewable.
