#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATEWAY_IP="${GATEWAY_IP:-10.66.0.254}"
GATEWAY_USER="${GATEWAY_USER:-winstdt-gateway}"
GATEWAY_KEY="${GATEWAY_KEY:-/srv/winstdt/gateway/keys/id_ed25519}"
GATEWAY_KNOWN_HOSTS="${GATEWAY_KNOWN_HOSTS:-/srv/winstdt/gateway/known_hosts}"
GATEWAY_ALLOWED_SIGNERS="${GATEWAY_ALLOWED_SIGNERS:-/srv/winstdt/gateway/approval_allowed_signers}"
VM_NAME="${GATEWAY_VM_NAME:-winstdt-egress-gateway}"
SSH=(ssh -i "$GATEWAY_KEY" -o UserKnownHostsFile="$GATEWAY_KNOWN_HOSTS" -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$GATEWAY_USER@$GATEWAY_IP")

usage() {
  echo "Usage: $0 activate CONFIG.json | revoke [REASON] | status | collect RUN_ID DEST | emergency-stop" >&2
}

case "${1:-}" in
  activate)
    config="${2:?configuration path required}"
    work="$(mktemp -d)"
    trap 'rm -rf -- "$work"' EXIT
    python3 "$PROJECT_ROOT/scripts/configure-egress-gateway.py" "$config" \
      --allowed-signers "$GATEWAY_ALLOWED_SIGNERS" \
      --output "$work/rules.nft" --metadata-output "$work/metadata.json"
    run_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["run_id"])' "$work/metadata.json")"
    expires="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["expires_epoch"])' "$work/metadata.json")"
    dns_name="$(python3 -c 'import json,sys; print((json.load(open(sys.argv[1])).get("dns") or {}).get("name", ""))' "$work/metadata.json")"
    dns_ip="$(python3 -c 'import json,sys; print((json.load(open(sys.argv[1])).get("dns") or {}).get("pinned_ip", ""))' "$work/metadata.json")"
    scp -q -i "$GATEWAY_KEY" -o UserKnownHostsFile="$GATEWAY_KNOWN_HOSTS" -o StrictHostKeyChecking=accept-new \
      "$work/rules.nft" "$work/metadata.json" "$GATEWAY_USER@$GATEWAY_IP:/tmp/"
    "${SSH[@]}" sudo /usr/local/sbin/winstdt-egress-activate \
      "$run_id" "$expires" "$dns_name" "$dns_ip" /tmp/rules.nft /tmp/metadata.json
    ;;
  revoke)
    "${SSH[@]}" sudo /usr/local/sbin/winstdt-egress-revoke "${2:-operator-request}"
    ;;
  status)
    "${SSH[@]}" sudo /usr/local/sbin/winstdt-egress-status
    ;;
  collect)
    run_id="${2:?run id required}"; destination="${3:?destination required}"
    [[ "$run_id" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || { echo 'invalid run id' >&2; exit 2; }
    mkdir -p "$destination/gateway"
    "${SSH[@]}" sudo tar -C "/var/lib/winstdt-egress/runs/$run_id" -cf - . | \
      tar -C "$destination/gateway" -xf -
    curl --fail --silent --show-error --max-time 10 \
      http://192.168.125.10:8080/receipts >"$destination/responder-receipts.jsonl"
    (cd "$destination" && find gateway -type f -print0 | sort -z | xargs -0 sha256sum >gateway-hashes.sha256)
    (cd "$destination" && sha256sum responder-receipts.jsonl >responder-hashes.sha256)
    ;;
  emergency-stop)
    "${SSH[@]}" sudo /usr/local/sbin/winstdt-egress-revoke emergency-stop || true
    external_mac="52:54:00:67:00:02"
    device="$(virsh domiflist "$VM_NAME" | awk -v mac="$external_mac" '$5 == mac {print $1}')"
    test -n "$device" || { echo "external interface not found" >&2; exit 1; }
    virsh domif-setlink "$VM_NAME" "$device" down
    echo "Emergency stop complete: $VM_NAME external interface $device is down."
    ;;
  *) usage; exit 2 ;;
esac
