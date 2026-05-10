# Upstream-Safe Development Policy

This macOS port must stay easy to update from the original zapret2 repository.

## Repository Roles

- `origin`: original upstream repository, currently `bol-van/zapret2`.
- `fork`: development fork that carries the macOS native work.

## Rules

1. Keep upstream core changes additive whenever possible.
2. Prefer new files over invasive edits to existing `nfq2` files.
3. Do not rewrite `nfqws.c` wholesale. Extract reusable API in small, reviewable
   steps.
4. Keep macOS-specific code under `extras/macos-native` and `extras/macos-menu`.
5. If a core change is required, isolate it behind a narrow API such as
   `nfq2/zapret2_engine.h`.
6. Before updating from upstream, require a clean working tree.
7. Merge `origin/master` into the fork branch rather than editing upstream
   history.

## Current Core Surface

The only intended core addition for macOS is the additive engine API:

- `nfq2/zapret2_engine.h`
- `nfq2/zapret2_engine.c`
- `nfq2/zapret2_engine.md`

Everything else should remain in macOS-specific directories until a small shared
core extraction is unavoidable.

## Update Flow

Run:

```sh
extras/macos-native/update-from-upstream.sh
```

The script fetches `origin` and `fork`, checks the working tree, merges
`origin/master` into the current development branch, and then runs lightweight
macOS validation.
