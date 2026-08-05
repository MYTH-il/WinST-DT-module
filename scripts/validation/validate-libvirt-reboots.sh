#!/usr/bin/env bash
set -euo pipefail

PHASE="${1:-}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATE_ROOT="${WINSTDT_REBOOT_STATE_ROOT:-/srv/winstdt/validation/libvirt-reboots}"
STATE_FILE="$STATE_ROOT/state.json"

usage() { echo "Usage: $0 prepare | after-reboot-1 | after-reboot-2" >&2; }
case "$PHASE" in prepare|after-reboot-1|after-reboot-2) ;; *) usage; exit 2 ;; esac

sudo install -d -m 0750 "$STATE_ROOT"
"$PROJECT_ROOT/scripts/repair-libvirt-runtime.sh" --validate-only
for service in libvirtd.service cape.service cape-processor.service cape-rooter.service; do
  systemctl is-active --quiet "$service" || { echo "inactive service: $service" >&2; exit 1; }
done

boot_id="$(cat /proc/sys/kernel/random/boot_id)"
now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sudo python3 - "$STATE_FILE" "$PHASE" "$boot_id" "$now" <<'PY'
import json, os, sys, tempfile
path, phase, boot_id, now = sys.argv[1:]
state = {"schema_version": "1.0", "cycles": []}
if os.path.exists(path):
    state = json.load(open(path, encoding="utf-8"))
cycles = state.setdefault("cycles", [])
expected = {"prepare": 0, "after-reboot-1": 1, "after-reboot-2": 2}[phase]
if len(cycles) != expected:
    raise SystemExit(f"unexpected phase {phase}: recorded cycles={len(cycles)} expected={expected}")
if cycles and cycles[-1]["boot_id"] == boot_id:
    raise SystemExit("a new host boot was not observed")
cycles.append({"phase": phase, "boot_id": boot_id, "validated_at_utc": now, "passed": True})
state["complete"] = phase == "after-reboot-2"
directory = os.path.dirname(path)
fd, tmp = tempfile.mkstemp(prefix=".state.", dir=directory, text=True)
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    json.dump(state, handle, indent=2)
    handle.write("\n")
os.replace(tmp, path)
PY
sudo chmod 0640 "$STATE_FILE"
echo "recorded $PHASE in $STATE_FILE"
if [ "$PHASE" != after-reboot-2 ]; then
  echo "operator action required: reboot the host, then run the next phase"
fi
