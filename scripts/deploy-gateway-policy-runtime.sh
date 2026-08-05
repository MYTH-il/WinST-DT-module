#!/usr/bin/env bash
set -euo pipefail
EXECUTE=0; [ "${1:-}" != --execute ] || EXECUTE=1
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATEWAY_IP="${GATEWAY_IP:-10.66.0.254}"; GATEWAY_USER="${GATEWAY_USER:-winstdt-gateway}"
GATEWAY_KEY="${GATEWAY_KEY:-/srv/winstdt/gateway/keys/id_ed25519}"
KNOWN="${GATEWAY_KNOWN_HOSTS:-/srv/winstdt/gateway/known_hosts}"
echo "Gateway policy runtime target: $GATEWAY_USER@$GATEWAY_IP"
[ "$EXECUTE" -eq 1 ] || { echo 'Dry run only. Re-run with --execute.'; exit; }
scp -q -i "$GATEWAY_KEY" -o UserKnownHostsFile="$KNOWN" -o StrictHostKeyChecking=accept-new \
  "$PROJECT_ROOT/gateway/winstdt-egress-activate" "$GATEWAY_USER@$GATEWAY_IP:/tmp/winstdt-egress-activate"
ssh -i "$GATEWAY_KEY" -o UserKnownHostsFile="$KNOWN" -o StrictHostKeyChecking=accept-new \
  "$GATEWAY_USER@$GATEWAY_IP" 'sudo sh -eu' <<'REMOTE'
install -d -m 0755 /usr/local/libexec
if [ ! -f /usr/local/libexec/winstdt-egress-activate-legacy ]; then
  mv /usr/local/sbin/winstdt-egress-activate /usr/local/libexec/winstdt-egress-activate-legacy
fi
install -m 0755 /tmp/winstdt-egress-activate /usr/local/sbin/winstdt-egress-activate
rm -f /tmp/winstdt-egress-activate
/usr/local/sbin/winstdt-egress-revoke runtime-update
REMOTE
