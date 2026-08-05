#!/usr/bin/env bash
set -euo pipefail

EXECUTE=0; CONFIG=""; FIXTURE=""
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WINSTDT_ROOT="${WINSTDT_ROOT:-/srv/winstdt}"; CAPE_DIR="${CAPE_DIR:-/opt/CAPEv2}"
CAPE_USER="${CAPE_USER:-cape}"; CAPE_API="${CAPE_API:-http://127.0.0.1:8000}"
VM="${CAPE_VM_NAME:-winstdt-win10-22h2}"; SNAPSHOT="${CAPE_SNAPSHOT:-hardened-baseline-controlled-egress-v2}"
WAIT_SECONDS="${CAPE_WAIT_SECONDS:-900}"
while [ "$#" -gt 0 ]; do case "$1" in --execute) EXECUTE=1;; --config) CONFIG="${2:?}"; shift;; --fixture) FIXTURE="${2:?}"; shift;; *) echo "Usage: $0 --config APPROVED.json --fixture FILE.exe [--execute]" >&2; exit 2;; esac; shift; done
test -s "$CONFIG" && test -s "$FIXTURE" || { echo 'approved config and compiled fixture are required' >&2; exit 2; }
run_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["run_id"])' "$CONFIG")"
fixture_sha="$(sha256sum "$FIXTURE" | awk '{print $1}')"
test "$(diec "$FIXTURE" | head -n1)" != "" || { echo 'DIE did not identify fixture' >&2; exit 1; }
virsh snapshot-info "$VM" "$SNAPSHOT" >/dev/null
virsh net-dumpxml winstdt-controlled-services | grep -q '<forward' && { echo 'public forwarding is present' >&2; exit 1; }
test ! -e "$WINSTDT_ROOT/c2-results"/"$run_id"
curl --fail --silent --max-time 3 http://192.168.125.10:8080/receipts >/dev/null
echo "Validated plan: run=$run_id fixture_sha256=$fixture_sha VM=$VM snapshot=$SNAPSHOT"
[ "$EXECUTE" -eq 1 ] || { echo 'Dry run only. Re-run with --execute.'; exit; }
evidence="$WINSTDT_ROOT/validation/end-to-end/$run_id"
sudo install -d -m 0750 -o "$(id -u)" -g "$(id -g)" "$evidence"
task_id=""; revoked=0; reverted=0
revert_and_stop() {
  virsh snapshot-revert "$VM" "$SNAPSHOT" --running >/dev/null || return 1
  virsh destroy "$VM" >/dev/null || return 1
}
cleanup() {
  set +e
  "$PROJECT_ROOT/scripts/manage-egress-run.sh" revoke end-to-end-cleanup
  revoked=1
  if [ -n "$task_id" ]; then "$PROJECT_ROOT/scripts/manage-egress-run.sh" collect "$run_id" "$evidence"; fi
  revert_and_stop && reverted=1
}
trap cleanup EXIT INT TERM
if [ "$(virsh domstate "$VM")" != 'shut off' ]; then
  virsh destroy "$VM" >/dev/null
fi
sudo systemctl restart cape.service
for _attempt in $(seq 1 20); do
  systemctl is-active --quiet cape.service && break
  sleep 1
done
systemctl is-active --quiet cape.service || { echo 'CAPE scheduler did not restart cleanly' >&2; exit 1; }
"$PROJECT_ROOT/scripts/manage-egress-run.sh" activate "$CONFIG"
staged="$WINSTDT_ROOT/validation/$(basename "$FIXTURE")"
sudo install -m 0644 -o "$CAPE_USER" -g "$CAPE_USER" "$FIXTURE" "$staged"
submit="$(sudo -u "$CAPE_USER" bash -lc "cd '$CAPE_DIR' && /etc/poetry/bin/poetry run python utils/submit.py --machine '$VM' --platform windows --timeout 180 --enforce-timeout --route none --options arguments='$run_id' '$staged'")"
task_id="$(printf '%s\n' "$submit" | sed -n 's/.*task with ID \([0-9][0-9]*\).*/\1/p' | tail -n1)"
test -n "$task_id" || { echo "could not parse CAPE task: $submit" >&2; exit 1; }
deadline=$((SECONDS + WAIT_SECONDS)); bundle="$WINSTDT_ROOT/handoff/$task_id"
while [ "$SECONDS" -lt "$deadline" ]; do
  test ! -f "$bundle/manifest.json" || break
  status="$(curl --max-time 10 -fsS "$CAPE_API/apiv2/tasks/view/$task_id/" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["status"])')"
  case "$status" in failed_analysis|failed_processing|failed_reporting|recovered) echo "CAPE failed: $status" >&2; exit 1;; esac
  sleep 5
done
test -f "$bundle/manifest.json" || { echo 'timed out waiting for immutable handoff' >&2; exit 1; }
"$WINSTDT_ROOT/bin/winstdt" validate-bundle "$bundle"
test -s "$bundle/network/capture.pcapng"; test -s "$bundle/behavior/trace.etl"
"$PROJECT_ROOT/scripts/manage-egress-run.sh" revoke cape-task-complete; revoked=1
"$PROJECT_ROOT/scripts/manage-egress-run.sh" collect "$run_id" "$evidence"
receipts="$(python3 - "$evidence/responder-receipts.jsonl" "$run_id" <<'PY'
import json,sys
print(sum(1 for line in open(sys.argv[1]) if json.loads(line).get('run_id') == sys.argv[2]))
PY
)"; test "$receipts" -eq 3
access_status="$bundle/behavior/access_events.status.json"
python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); assert s["correlation_eligible"] and s["source"]=="cape_capemon"' "$access_status"
WINSTDT_POSTGRES_ENABLED=1 "$PROJECT_ROOT/scripts/run-c2-analyzer.sh" "$bundle"
result="$WINSTDT_ROOT/c2-results/$task_id"
"$WINSTDT_ROOT/bin/winstdt" validate-c2-result "$result" --handoff "$bundle"
grep -qs 'WINSTDT controlled validation canary' "$bundle/analysis/suricata.json"
revert_and_stop; reverted=1
status_output="$("$PROJECT_ROOT/scripts/manage-egress-run.sh" status)"
printf '%s' "$status_output" | grep -q '"active_run":null'
printf '%s' "$status_output" | grep -A5 'chain forward' | grep -q 'policy drop'
virsh net-dumpxml winstdt-controlled-services | grep -q '<forward' && exit 1
TASK="$task_id" RUN="$run_id" SHA="$fixture_sha" RECEIPTS="$receipts" REVOKED="$revoked" REVERTED="$reverted" OUT="$evidence/acceptance.json" python3 - <<'PY'
import json,os
value={'schema_version':'1.0','run_id':os.environ['RUN'],'task_id':int(os.environ['TASK']),
'fixture_sha256':os.environ['SHA'],'sample_identity_consistent':True,'real_correlation':True,
'receipt_count':int(os.environ['RECEIPTS']),'pcap_preserved':True,'etl_preserved':True,
'suricata_marker_observed':True,'postgresql_round_trip':True,'snapshot_reverted':os.environ['REVERTED']=='1',
'gateway_revoked':os.environ['REVOKED']=='1','public_route_absent':True,'status':'passed'}
open(os.environ['OUT'],'w').write(json.dumps(value,indent=2)+'\n')
PY
trap - EXIT INT TERM
echo "End-to-end validation passed: task=$task_id evidence=$evidence"
