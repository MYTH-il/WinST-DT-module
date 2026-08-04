#!/usr/bin/env bash
set -euo pipefail
ROOT="${WINSTDT_ROOT:-/srv/winstdt}"
LOCK="${LOCK_FILE:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/config/cape.lock.json}"
MIN="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["policy"]["memory_min_free_bytes"])' "$LOCK")"
AVAILABLE="$(df -PB1 "$ROOT" | awk 'NR==2 {print $4}')"
[ "$AVAILABLE" -ge "$MIN" ] || { echo "skipped_insufficient_storage: need=$MIN available=$AVAILABLE" >&2; exit 3; }
LOCK_PATH="$ROOT/locks/full-memory.lock"
install -d -m 0750 "$(dirname "$LOCK_PATH")"
exec 9>"$LOCK_PATH"
flock -n 9 || { echo 'full-memory task already active' >&2; exit 4; }
test -d "${VOLATILITY_SYMBOL_ROOT:-$ROOT/symbols/volatility}" || { echo 'Volatility symbols unavailable' >&2; exit 5; }
printf 'full-memory preflight passed; free_bytes=%s\n' "$AVAILABLE"
