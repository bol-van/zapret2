#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

echo "update-from-upstream.sh is kept for compatibility."
echo "Delegating to sync-upstream.sh."
echo

"$SCRIPT_DIR/sync-upstream.sh"
