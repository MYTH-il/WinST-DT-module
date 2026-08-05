#!/usr/bin/env bash
set -euo pipefail

EXECUTE=0
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CAPE_DIR="${CAPE_DIR:-/opt/CAPEv2}"
CAPE_USER="${CAPE_USER:-cape}"
WINSTDT_ROOT="${WINSTDT_ROOT:-/srv/winstdt}"
VM_NAME="${VM_NAME:-winstdt-win10-22h2}"
CAPE_API="${CAPE_API:-http://127.0.0.1:8000}"
ROUTE="${WINSTDT_VALIDATION_ROUTE:-inetsim}"
ANALYSIS_TIMEOUT="${WINSTDT_VALIDATION_TIMEOUT:-45}"
WAIT_SECONDS="${WINSTDT_VALIDATION_WAIT_SECONDS:-300}"

usage() {
  cat <<EOF
Usage: scripts/validate-deployment.sh [--execute]

Submit the controlled benign payload and require a completed WinST/DT handoff
containing non-empty PCAP and ETL artifacts. No task is submitted without
--execute.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --execute) EXECUTE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

log() { printf '[winstdt-validation] %s\n' "$*"; }

"$PROJECT_ROOT/scripts/repair-libvirt-runtime.sh" --validate-only
network_xml="$(virsh net-dumpxml winstdt-isolated)"
grep -q '<hostname>validation.winstdt.test</hostname>' <<<"$network_xml" || {
  echo 'isolated network is missing the controlled responder DNS pin' >&2; exit 1;
}
grep -q "<host ip='192.168.125.10'>" <<<"$network_xml" || {
  echo 'controlled responder DNS pin has the wrong address' >&2; exit 1;
}

restart_limit="${WINSTDT_CAPE_MAX_RESTARTS:-3}"
for service in cape cape-processor cape-rooter; do
  restarts="$(systemctl show -p NRestarts --value "$service" 2>/dev/null || echo 0)"
  [[ "$restarts" =~ ^[0-9]+$ ]] || restarts=0
  [ "$restarts" -le "$restart_limit" ] || {
    echo "CAPE restart-loop threshold exceeded: $service restarts=$restarts limit=$restart_limit" >&2
    exit 1
  }
done

for service in cape cape-processor cape-rooter cape-web inetsim libvirtd; do
  systemctl is-active --quiet "$service" || { echo "inactive service: $service" >&2; exit 1; }
done
systemctl is-active --quiet mongodb.service || systemctl is-active --quiet mongod.service || {
  echo 'neither supported MongoDB service unit is active' >&2; exit 1;
}
test -x "$WINSTDT_ROOT/bin/winstdt"
test -f "$PROJECT_ROOT/scripts/validation/Invoke-BenignDetonation.ps1"
curl --max-time 10 -fsS "$CAPE_API/" >/dev/null
python3 - "$CAPE_DIR/conf/routing.conf" <<'PY'
import configparser,sys
config=configparser.ConfigParser(); config.read(sys.argv[1])
if not config.getboolean('routing','enable_pcap',fallback=False):
    raise SystemExit('CAPE routing.enable_pcap must be yes for controlled route-none capture')
PY
sudo -u "$CAPE_USER" sudo --list --non-interactive /usr/bin/tcpdump >/dev/null || {
  echo 'CAPE processor account cannot invoke the configured tcpdump capture command' >&2; exit 1;
}
log "preflight passed; route=$ROUTE machine=$VM_NAME"

if [ "$EXECUTE" -eq 0 ]; then
  log "dry-run complete; rerun with --execute"
  exit 0
fi

staged="$WINSTDT_ROOT/validation/Invoke-BenignDetonation.ps1"
sudo install -d -m 0755 -o "$CAPE_USER" -g "$CAPE_USER" "$WINSTDT_ROOT/validation"
sudo install -m 0644 -o "$CAPE_USER" -g "$CAPE_USER" \
  "$PROJECT_ROOT/scripts/validation/Invoke-BenignDetonation.ps1" "$staged"

submit_output="$(sudo -u "$CAPE_USER" bash -lc "cd '$CAPE_DIR' && /etc/poetry/bin/poetry run python utils/submit.py --machine '$VM_NAME' --platform windows --timeout '$ANALYSIS_TIMEOUT' --enforce-timeout --route '$ROUTE' '$staged'")"
task_id="$(printf '%s\n' "$submit_output" | sed -n 's/.*task with ID \([0-9][0-9]*\).*/\1/p' | tail -n1)"
[ -n "$task_id" ] || { echo "could not parse task ID: $submit_output" >&2; exit 1; }
log "submitted benign task $task_id"

deadline=$((SECONDS + WAIT_SECONDS))
last_status=""
while [ "$SECONDS" -lt "$deadline" ]; do
  status="$(curl --max-time 10 -fsS "$CAPE_API/apiv2/tasks/view/$task_id/" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["status"])')"
  if [ "$status" != "$last_status" ]; then
    log "task $task_id status=$status"
    last_status="$status"
  fi
  bundle="$WINSTDT_ROOT/handoff/$task_id"
  if [ -f "$bundle/manifest.json" ]; then
    "$WINSTDT_ROOT/bin/winstdt" validate-bundle "$bundle"
    BUNDLE="$bundle" python3 - <<'PY'
import json, os
from pathlib import Path

bundle = Path(os.environ['BUNDLE'])
manifest = json.loads((bundle / 'manifest.json').read_text(encoding='utf-8'))
if manifest.get('status') != 'completed':
    raise SystemExit('handoff status is not completed: ' + str(manifest.get('status')))
if manifest.get('network_mode') != 'simulated_inetsim':
    raise SystemExit('unexpected network mode: ' + str(manifest.get('network_mode')))
for relative in ('network/capture.pcapng', 'behavior/trace.etl'):
    path = bundle / relative
    if not path.is_file() or path.stat().st_size <= 0:
        raise SystemExit('required artifact missing or empty: ' + relative)
telemetry = manifest.get('telemetry', {})
if not telemetry.get('capture_started') or not telemetry.get('capture_completed'):
    raise SystemExit('ETW capture did not complete')
print('deployment validation passed')
print('pcap_bytes=' + str((bundle / 'network/capture.pcapng').stat().st_size))
print('etl_bytes=' + str((bundle / 'behavior/trace.etl').stat().st_size))
PY
    log "accepted handoff: $bundle"
    exit 0
  fi
  case "$status" in
    failed_analysis|failed_processing|failed_reporting|recovered)
      echo "CAPE task entered terminal failure state: $status" >&2
      exit 1
      ;;
  esac
  sleep 5
done

echo "timed out waiting for handoff for task $task_id (last status: $last_status)" >&2
exit 1
