#!/usr/bin/env bash
set -euo pipefail
EXECUTE=0
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VM="${GATEWAY_VM_NAME:-winstdt-egress-gateway}"
OLD_NETWORK="${OLD_GATEWAY_NETWORK:-winstdt-external}"
NEW_NETWORK="winstdt-controlled-services"
MAC="52:54:00:67:00:02"
[ "${1:-}" != --execute ] || EXECUTE=1
xml="$PROJECT_ROOT/config/libvirt/winstdt-controlled-services.xml"
grep -q '<forward' "$xml" && { echo 'controlled-services network contains forwarding' >&2; exit 1; }
virsh dominfo "$VM" >/dev/null
current="$(virsh domiflist "$VM" | awk -v mac="$MAC" '$5==mac {print $3}')"
echo "Gateway outside interface: ${current:-missing} -> $NEW_NETWORK ($MAC)"
[ "$EXECUTE" -eq 1 ] || { echo 'Dry run only. Re-run with --execute.'; exit; }
virsh net-info "$NEW_NETWORK" >/dev/null 2>&1 || virsh net-define "$xml"
virsh net-autostart "$NEW_NETWORK"
[ "$(virsh net-info "$NEW_NETWORK" | awk '/^Active:/ {print $2}')" = yes ] || virsh net-start "$NEW_NETWORK"
if [ "$current" != "$NEW_NETWORK" ]; then
  [ "$current" = "$OLD_NETWORK" ] || { echo "unexpected gateway outside network: $current" >&2; exit 1; }
  active=(); [ "$(virsh domstate "$VM")" != running ] || active=(--live)
  virsh detach-interface "$VM" network --mac "$MAC" --config "${active[@]}"
  virsh attach-interface "$VM" network "$NEW_NETWORK" --model virtio --mac "$MAC" --config "${active[@]}"
fi
virsh dumpxml "$VM" | grep -A8 "mac address='$MAC'" | grep -q "source network='$NEW_NETWORK'"
virsh net-dumpxml "$NEW_NETWORK" | grep -qv '<forward'
old_used=0
while IFS= read -r domain; do
  [ -z "$domain" ] || ! virsh domiflist "$domain" | awk '{print $3}' | grep -qx "$OLD_NETWORK" || old_used=1
done < <(virsh list --all --name)
if [ "$old_used" -eq 0 ]; then
  virsh net-destroy "$OLD_NETWORK" 2>/dev/null || true
  virsh net-undefine "$OLD_NETWORK" 2>/dev/null || true
fi
echo 'Gateway now has no libvirt public forwarding network.'
