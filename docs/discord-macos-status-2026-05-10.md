# Discord macOS Status - 2026-05-10

This note freezes the current state of the macOS Discord investigation so the next session can continue from a known point.

## Current State

- YouTube bypass works through the legacy `tpws + pf` compatibility fallback.
- The macOS menu app can start the native scaffold and reports version `02.00.000`.
- The open-source macOS path is still `utun/root`; Network Extension Packet Tunnel remains a prepared future path that requires signing entitlements.
- Discord Desktop can get past the updater window after forcing `settings.json`:
  - `USE_NEW_UPDATER=false`
  - `SKIP_HOST_UPDATE=true`
  - `SKIP_MODULE_UPDATE=true`
- Discord gateway startup is still not solved reliably. The app reaches `GatewaySocket CONNECT`, then often times out waiting for `OP_HELLO`.
- Discord voice/media is not stable yet. We reached voice once, but RTT jumped from about 40 ms to about 5000 ms and audio stopped flowing.

## Implemented Changes

- Added native macOS backend scaffolding under `extras/macos-native`.
- Added a `utun` runtime for UDP relay experiments.
- Added Discord media route discovery/enable/disable commands.
- Added status counters for the `utun` relay:
  - packets read
  - outbound UDP
  - inbound UDP
  - malformed packets
  - relay errors
  - packet drops
  - active sessions
  - relay mode
- Added Discord startup helper actions:
  - `fix-discord-startup`
  - `reset-discord-cache`
- Added a volatile Discord cache reset that moves cache/session folders aside without intentionally deleting login tokens.
- Updated `tpws` fallback generation to treat Discord gateway separately from the broader Discord hostlist.

## Findings

- Direct TLS to `gateway.discord.gg` does not complete on this network.
- Stopping zapret entirely does not fix direct gateway TLS, so this is not only a local `pf`/routing issue.
- Standard `tpws` gateway tests with `--hostlist-domains=gateway.discord.gg` did not apply the working tamper reliably in SOCKS testing.
- Forcing `tpws` without a hostlist filter proved that `--tlsrec=sniext+1` can make `https://gateway.discord.gg` complete TLS and return an HTTP response.
- The latest code therefore switches gateway matching from `--hostlist-domains` to a generated gateway IP set:
  - `/opt/zapret2/ipset/discord-gateway-ipset.txt`
  - strategy: `--filter-tcp=443 --tlsrec=sniext+1 --ipset=<gateway ipset> --new`
- Gateway IPs should not be placed in the generic `zapret-ip-exclude.txt`, because direct gateway traffic is blocked by the provider.

## Remaining Problems

- The latest gateway IP-set strategy still needs to be installed and tested after a fresh Discord restart.
- `pf` table inspection is blocked when `sudo -n` cannot run without a password.
- Discord Desktop may rewrite or regenerate some updater/session state, so `fix-discord-startup` and `reset-discord-cache` may need to be run together during testing.
- The UDP media relay needs another real voice-call verification after gateway startup is fixed.
- `raw-ipfrag` mode was added for UDP, but earlier runtime counters showed relay errors in some runs; the fallback behavior and packet return path still need careful validation.
- `blockcheck2.sh` cannot run on macOS (`Darwin not supported`), so strategy discovery currently requires manual test harnesses.

## Next Session Checklist

1. Install the latest helper:
   `sudo install -m 0755 -o root -g wheel extras/macos-menu/zapret2-menu-helper /opt/zapret2/zapret2-menu-helper`
2. Apply Discord startup config:
   `sudo /opt/zapret2/zapret2-menu-helper fix-discord-startup`
3. Confirm `/opt/zapret2/ipset/discord-gateway-ipset.txt` exists and contains `162.159.*.234` gateway IPs.
4. Confirm `tpws` command line contains `--tlsrec=sniext+1 --ipset=/opt/zapret2/ipset/discord-gateway-ipset.txt`.
5. Restart Discord and check `renderer_js.log` for `GatewaySocket READY` or `CONNECTION_OPEN`.
6. If gateway opens, join voice and watch `zapret2-menu-helper status` for UDP counter growth and relay errors.

## Known Good Test Result

The following manual test succeeded when `tpws` was forced by IP-set instead of hostlist matching:

```sh
/opt/zapret2/tpws/tpws \
  --socks \
  --bind-addr=127.0.0.1 \
  --port=12399 \
  --filter-tcp=443 \
  --tlsrec=sniext+1 \
  --ipset-ip=162.159.130.234,162.159.133.234,162.159.134.234,162.159.135.234,162.159.136.234

curl -I --socks5-hostname 127.0.0.1:12399 https://gateway.discord.gg
```

Observed result: TLS completed and Cloudflare returned `HTTP/2 404`, which is expected for a plain request to the gateway host.
