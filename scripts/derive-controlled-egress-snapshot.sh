#!/usr/bin/env bash
set -euo pipefail

EXECUTE=0
VM="${CAPE_VM_NAME:-winstdt-win10-22h2}"
SOURCE="${CAPE_SOURCE_SNAPSHOT:-hardened-baseline-antievasion-v1}"
TARGET="${CAPE_CONTROLLED_SNAPSHOT:-hardened-baseline-controlled-egress-v2}"
GUEST_IP="${CAPE_GUEST_IP:-10.66.0.101}"
CAPE_DIR="${CAPE_DIR:-/opt/CAPEv2}"
SNAPSHOT_ROOT="${WINSTDT_SNAPSHOT_ROOT:-/var/lib/libvirt/images/winstdt/snapshots}"
while [ "$#" -gt 0 ]; do
  case "$1" in --execute) EXECUTE=1 ;; *) echo "Usage: $0 [--execute]" >&2; exit 2 ;; esac
  shift
done
virsh snapshot-info "$VM" "$SOURCE" >/dev/null
virsh net-dumpxml winstdt-isolated | grep -q '<hostname>validation.winstdt.test</hostname>'
echo "Controlled snapshot: $SOURCE -> $TARGET (DNS and gateway 10.66.0.254)"
if [ "$EXECUTE" -eq 0 ]; then echo 'Dry run only. Re-run with --execute.'; exit 0; fi

if ! virsh snapshot-info "$VM" "$TARGET" >/dev/null 2>&1; then
  virsh snapshot-revert "$VM" "$SOURCE" --running >/dev/null
  cleanup() { virsh destroy "$VM" >/dev/null 2>&1 || true; }
  trap cleanup EXIT INT TERM
  for _attempt in $(seq 1 60); do
    curl -fsS --max-time 2 "http://$GUEST_IP:8000/" >/dev/null && break
    sleep 1
  done
  curl -fsS --max-time 2 "http://$GUEST_IP:8000/" >/dev/null
  command='powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$a=Get-NetAdapter | Where-Object Status -eq Up | Select-Object -First 1; Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses 10.66.0.254; Get-NetRoute -InterfaceIndex $a.ifIndex -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false; New-NetRoute -InterfaceIndex $a.ifIndex -DestinationPrefix 0.0.0.0/0 -NextHop 10.66.0.254 -RouteMetric 10 | Out-Null; Clear-DnsClientCache"'
  response="$(curl -fsS --max-time 60 -X POST --data-urlencode "command=$command" "http://$GUEST_IP:8000/execute")"
  RESPONSE="$response" python3 - <<'PY'
import json,os
value=json.loads(os.environ['RESPONSE'])
if value.get('stderr') or value.get('error'):
    raise SystemExit(value)
PY
  network_config="$(curl -fsS --max-time 30 -X POST --data-urlencode \
    'command=powershell.exe -NoProfile -Command "$a=Get-NetAdapter | Where-Object Status -eq Up | Select-Object -First 1; [pscustomobject]@{Dns=(Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4).ServerAddresses; Gateway=(Get-NetRoute -InterfaceIndex $a.ifIndex -DestinationPrefix 0.0.0.0/0 | Sort-Object RouteMetric | Select-Object -First 1).NextHop} | ConvertTo-Json -Compress"' \
    "http://$GUEST_IP:8000/execute")"
  printf '%s' "$network_config" | grep -q '10.66.0.254' || { echo 'controlled network configuration validation failed' >&2; exit 1; }
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  sudo install -d -m 0755 -o libvirt-qemu -g kvm "$SNAPSHOT_ROOT"
  virsh snapshot-create-as "$VM" "$TARGET" \
    --description 'Reviewed baseline with private controlled responder DNS and gateway only' \
    --live --atomic \
    --memspec "$SNAPSHOT_ROOT/${VM}-${TARGET}-${stamp}.mem,snapshot=external" \
    --diskspec "sda,file=$SNAPSHOT_ROOT/${VM}-${TARGET}-${stamp}.qcow2,snapshot=external" >/dev/null
  virsh destroy "$VM" >/dev/null
  trap - EXIT INT TERM
fi
virsh snapshot-info "$VM" "$TARGET" | awk '$1=="State:" && $2=="running" {ok=1} END {exit ok ? 0 : 1}'
sudo sed -i "s/^snapshot = .*/snapshot = $TARGET/" "$CAPE_DIR/conf/kvm.conf"
sudo chown cape:cape "$CAPE_DIR/conf/kvm.conf"
sudo systemctl restart cape.service
systemctl is-active --quiet cape.service
echo "Controlled snapshot active in CAPE: $TARGET"
