#!/usr/bin/env bash
set -euo pipefail

EXECUTE=0
QUALIFICATION_ONLY=0
SEAL_APPROVED=0
ALLOW_REJECTED=0
AL_KHASER_PATH=""
PAFISH_PATH=""
ACCEPTANCE_REPORT=""
VC_REDIST_PATH="${VC_REDIST_PATH:-/srv/winstdt/tools/anti-evasion/vc_redist.x64.exe}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CAPE_DIR="${CAPE_DIR:-/opt/CAPEv2}"
WINSTDT_ROOT="${WINSTDT_ROOT:-/srv/winstdt}"
VM_NAME="${VM_NAME:-winstdt-win10-22h2}"
SNAPSHOT_NAME="${SNAPSHOT_NAME:-hardened-baseline-antievasion-v1}"
GUEST_IP="${GUEST_IP:-10.66.0.101}"
AGENT_PORT="${GUEST_AGENT_PORT:-8000}"
LIBVIRT_URI="${LIBVIRT_URI:-qemu+unix:///system?socket=/run/libvirt/libvirt-sock}"
SYSTEM_LIB_PATH="${SYSTEM_LIB_PATH:-/usr/lib/x86_64-linux-gnu}"
SNAPSHOT_DIR="${SNAPSHOT_DIR:-/var/lib/libvirt/images/winstdt/snapshots}"
WAIT_ATTEMPTS="${WAIT_ATTEMPTS:-60}"
QUALIFICATION_ROOT="${QUALIFICATION_ROOT:-/srv/winstdt/qualification}"
QUALIFICATION_MARKER="${QUALIFICATION_ROOT}/${VM_NAME}.awaiting-review"

usage() {
  cat <<EOF
Usage: scripts/finalize-windows-guest.sh --qualification-only --al-khaser FILE --pafish FILE --execute
       scripts/finalize-windows-guest.sh --seal-approved --acceptance-report FILE --execute
       scripts/finalize-windows-guest.sh --seal-approved --allow-rejected --acceptance-report FILE --execute

Provision and seal the WinST/DT Windows guest after configure-cape-runtime.sh
has registered the libvirt domain. Without --execute, only preflight checks run.

Qualification installs and hardens the guest, runs both anti-evasion suites,
retrieves evidence, and stops without sealing. After manual strict-subset review,
the seal phase requires an Accepted report, sanitizes validation residue,
cold-boots the guest, performs non-invasive checks, and seals the snapshot.
The explicit testing-only override permits a rejected anti-evasion report but
does not bypass qualification, sanitization, cold-boot, or telemetry controls.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --execute) EXECUTE=1 ;;
    --qualification-only) QUALIFICATION_ONLY=1 ;;
    --seal-approved) SEAL_APPROVED=1 ;;
    --allow-rejected) ALLOW_REJECTED=1 ;;
    --al-khaser) AL_KHASER_PATH="${2:-}"; shift ;;
    --pafish) PAFISH_PATH="${2:-}"; shift ;;
    --acceptance-report) ACCEPTANCE_REPORT="${2:-}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

log() { printf '[winstdt-guest] %s\n' "$*"; }
virsh_cmd() { sudo env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" "$@"; }
agent_url() { printf 'http://%s:%s' "$GUEST_IP" "$AGENT_PORT"; }

agent_get() { curl --max-time 10 -fsS "$(agent_url)/"; }

agent_execute() {
  curl --max-time 300 -fsS -X POST \
    --data-urlencode "command=$1" "$(agent_url)/execute"
}

agent_mkdir() {
  curl --max-time 30 -fsS -X POST \
    --data-urlencode "dirpath=$1" "$(agent_url)/mkdir" >/dev/null
}

agent_upload() {
  curl --max-time 120 -fsS -X POST \
    -F "filepath=$2" -F "file=@$1" "$(agent_url)/store" >/dev/null
}

agent_retrieve() {
  curl --max-time 30 -fsS -X POST -d "filepath=$1" "$(agent_url)/retrieve"
}

wait_agent() {
  local attempt
  for attempt in $(seq 1 "$WAIT_ATTEMPTS"); do
    if agent_get >/tmp/winstdt-guest-agent.json 2>/dev/null; then
      log "guest agent ready on attempt $attempt"
      return 0
    fi
    sleep 2
  done
  echo "guest agent did not become ready at ${GUEST_IP}:${AGENT_PORT}" >&2
  return 1
}

wait_shut_off() {
  local attempt state
  for attempt in $(seq 1 "$WAIT_ATTEMPTS"); do
    state="$(virsh_cmd domstate "$VM_NAME")"
    [ "$state" = "shut off" ] && return 0
    sleep 2
  done
  echo "guest did not shut down: $VM_NAME" >&2
  return 1
}

start_guest() {
  if virsh_cmd snapshot-info "$VM_NAME" "$SNAPSHOT_NAME" >/dev/null 2>&1; then
    virsh_cmd snapshot-revert "$VM_NAME" "$SNAPSHOT_NAME" --running >/dev/null
  else
    virsh_cmd start "$VM_NAME" >/dev/null
  fi
  wait_agent
}

shutdown_guest() {
  agent_execute 'shutdown.exe /s /t 0 /f' >/dev/null || true
  wait_shut_off
}

modern_agent_ready() {
  agent_get | python3 -c '
import json, sys
features = set(json.load(sys.stdin).get("features", []))
required = {"execpy", "logs", "subdir_upload"}
raise SystemExit(0 if required <= features else 1)
'
}

install_payloads() {
  log "creating guest payload directories"
  agent_mkdir 'C:\ProgramData\WinSTDT\bin'
  agent_mkdir 'C:\ProgramData\WinSTDT\behavior'
  agent_mkdir 'C:\Windows\Temp\winstdt-cape-agent'
  agent_mkdir 'C:\ProgramData\WinSTDT\agent'

  log "uploading CAPE agent, ETW collector, and hardening inputs"
  agent_upload "$CAPE_DIR/agent/agent.py" 'C:\ProgramData\WinSTDT\agent\agent.py'
  agent_upload "$WINSTDT_ROOT/bin/winstdt.exe" 'C:\ProgramData\WinSTDT\bin\winstdt.exe'
  agent_upload "$PROJECT_ROOT/scripts/etw_agent/etw-agent.config.json" 'C:\ProgramData\WinSTDT\etw-agent.config.json'
  agent_upload "$PROJECT_ROOT/scripts/guest_hardening/Invoke-GuestHardening.ps1" 'C:\ProgramData\WinSTDT\Invoke-GuestHardening.ps1'
  agent_upload "$PROJECT_ROOT/scripts/guest_hardening/Install-CapeAgent.ps1" 'C:\ProgramData\WinSTDT\Install-CapeAgent.ps1'
  agent_upload "$PROJECT_ROOT/scripts/guest_hardening/Sanitize-GoldenImage.ps1" 'C:\ProgramData\WinSTDT\Sanitize-GoldenImage.ps1'
  agent_upload "$PROJECT_ROOT/scripts/guest_hardening/example.config.json" 'C:\ProgramData\WinSTDT\guest-hardening.config.json'
  test -s "$VC_REDIST_PATH" || { echo "VC++ runtime installer missing: $VC_REDIST_PATH" >&2; exit 1; }
  agent_upload "$VC_REDIST_PATH" 'C:\ProgramData\WinSTDT\vc_redist.x64.exe'
  log "installing Microsoft VC++ runtime required by al-khaser"
  agent_execute '"C:\ProgramData\WinSTDT\vc_redist.x64.exe" /install /quiet /norestart' >/dev/null

  log "configuring current CAPE agent as the persistent primary agent"
  agent_execute 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\WinSTDT\Install-CapeAgent.ps1" -AgentPath "C:\ProgramData\WinSTDT\agent\agent.py"' >/dev/null
}

run_qualification() {
  test -s "$AL_KHASER_PATH" || { echo "--al-khaser must name a non-empty executable" >&2; exit 2; }
  test -s "$PAFISH_PATH" || { echo "--pafish must name a non-empty executable" >&2; exit 2; }
  log "running mandatory al-khaser and Pafish qualification"
  GUEST_AGENT_HOST="$GUEST_IP" GUEST_AGENT_PORT="$AGENT_PORT" \
    "$PROJECT_ROOT/scripts/validation/run-anti-evasion-validation.sh" \
    --al-khaser "$AL_KHASER_PATH" --pafish "$PAFISH_PATH" --execute
  sudo install -d -m 0755 "$QUALIFICATION_ROOT"
  sudo touch "$QUALIFICATION_MARKER"
  log "qualification marker created: $QUALIFICATION_MARKER"
}

validate_acceptance_report() {
  test -s "$ACCEPTANCE_REPORT" || { echo "--acceptance-report must name a reviewed report" >&2; exit 2; }
  test -f "$QUALIFICATION_MARKER" || { echo "no unsealed qualification run exists for $VM_NAME" >&2; exit 1; }
  test "$ACCEPTANCE_REPORT" -nt "$QUALIFICATION_MARKER" || {
    echo "acceptance report must be reviewed after the latest qualification run" >&2
    exit 1
  }
  python3 - "$ACCEPTANCE_REPORT" "$ALLOW_REJECTED" <<'PY'
from pathlib import Path
import sys

lines = Path(sys.argv[1]).read_text(encoding='utf-8').splitlines()
allow_rejected = sys.argv[2] == '1'
decision = next((line for line in lines if line.startswith('| MVP gate decision |')), '')
if not decision:
    raise SystemExit('anti-evasion report has no MVP gate decision')
if not allow_rejected and decision.split('|')[2].strip() != 'Accepted':
    raise SystemExit('anti-evasion report decision is not exactly Accepted')
start = lines.index('## Required Gate Results')
end = lines.index('## Non-Blocking Findings')
rows = []
for line in lines[start:end]:
    cells = [cell.strip() for cell in line.strip().strip('|').split('|')]
    if len(cells) == 4 and cells[0] not in ('Category', '') and not set(cells[0]) <= {'-'}:
        rows.append(cells)
if not rows:
    raise SystemExit('reviewed report contains no required gate rows')
allowed = {'Pass', 'N/A'}
bad = [(row[0], row[1], row[2]) for row in rows if row[1] not in allowed or row[2] not in allowed]
if bad and not allow_rejected:
    raise SystemExit('required gate rows are not strictly Pass/N/A: ' + repr(bad))
if allow_rejected:
    print('WARNING: sealing testing-only image with rejected/pending anti-evasion findings')
else:
    print('reviewed anti-evasion report accepted with {} required rows'.format(len(rows)))
PY
}

sanitize_guest() {
  log "sanitizing setup and validation residue before sealing"
  agent_execute 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\WinSTDT\Sanitize-GoldenImage.ps1"' >/dev/null
}

validate_etw() {
  log "validating ETW start/stop and required artifacts"
  agent_execute '"C:\ProgramData\WinSTDT\bin\winstdt.exe" etw-agent --config "C:\ProgramData\WinSTDT\etw-agent.config.json" start' >/dev/null
  sleep 3
  agent_execute '"C:\ProgramData\WinSTDT\bin\winstdt.exe" etw-agent --config "C:\ProgramData\WinSTDT\etw-agent.config.json" stop' >/dev/null
  agent_retrieve 'C:\ProgramData\WinSTDT\behavior\telemetry.json' >/tmp/winstdt-telemetry.json
  agent_retrieve 'C:\ProgramData\WinSTDT\behavior\trace.etl' >/tmp/winstdt-trace.etl
  python3 - <<'PY'
import json
from pathlib import Path

metadata = json.loads(Path('/tmp/winstdt-telemetry.json').read_text(encoding='utf-8-sig'))
required = {
    'Microsoft-Windows-Kernel-Process',
    'Microsoft-Windows-Kernel-File',
    'Microsoft-Windows-Kernel-Registry',
    'Microsoft-Windows-Kernel-Network',
}
enabled = set(metadata.get('providers_enabled', []))
missing = sorted(required - enabled)
if missing:
    raise SystemExit('missing baseline ETW providers: ' + ', '.join(missing))
if not metadata.get('capture_started') or not metadata.get('capture_completed'):
    raise SystemExit('ETW capture did not complete')
if Path('/tmp/winstdt-trace.etl').stat().st_size <= 0:
    raise SystemExit('ETW trace is empty')
print('ETW validation passed; degraded=' + str(metadata.get('telemetry_degraded', False)).lower())
PY
}

apply_hardening() {
  log "applying guest hardening and interaction warm-up"
  local response
  response="$(agent_execute 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\WinSTDT\Invoke-GuestHardening.ps1" -ConfigPath "C:\ProgramData\WinSTDT\guest-hardening.config.json" -Apply')"
  RESPONSE="$response" python3 - <<'PY'
import json, os
data = json.loads(os.environ['RESPONSE'])
code = data.get('exit_code', data.get('returncode', 0))
if code not in (0, None):
    raise SystemExit(data)
output = data.get('stdout', '')
if 'Guest hardening checks completed.' not in output:
    raise SystemExit('guest hardening completion marker missing: ' + repr(output))
print(output.strip())
PY
}

reseal_snapshot() {
  local stamp mem disk description
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  mem="${SNAPSHOT_DIR}/${VM_NAME}-${SNAPSHOT_NAME}-${stamp}.mem"
  disk="${SNAPSHOT_DIR}/${VM_NAME}-${SNAPSHOT_NAME}-${stamp}.qcow2"
  description='WinST/DT automated modern-agent ETW hardened accepted baseline'
  if [ "$ALLOW_REJECTED" -eq 1 ]; then
    description='WinST/DT TESTING ONLY; anti-evasion residual risks accepted for ST/DT'
  fi

  if virsh_cmd snapshot-info "$VM_NAME" "$SNAPSHOT_NAME" >/dev/null 2>&1; then
    virsh_cmd snapshot-delete "$VM_NAME" "$SNAPSHOT_NAME" --metadata >/dev/null
  fi
  virsh_cmd snapshot-create-as "$VM_NAME" "$SNAPSHOT_NAME" \
    --description "$description" \
    --live --atomic --memspec "${mem},snapshot=external" \
    --diskspec "sda,file=${disk},snapshot=external" >/dev/null
  virsh_cmd snapshot-info "$VM_NAME" "$SNAPSHOT_NAME" | awk '$1 == "State:" && $2 == "running" {ok=1} END {exit ok ? 0 : 1}'
  virsh_cmd destroy "$VM_NAME" >/dev/null
  log "snapshot sealed and guest returned to idle: $SNAPSHOT_NAME"
}

preflight() {
  sudo -n true >/dev/null
  command -v curl >/dev/null
  command -v python3 >/dev/null
  test -f "$CAPE_DIR/agent/agent.py"
  test -x "$WINSTDT_ROOT/bin/winstdt.exe"
  virsh_cmd dominfo "$VM_NAME" >/dev/null
  log "preflight passed for $VM_NAME"
}

preflight
if [ "$EXECUTE" -eq 0 ]; then
  log "dry-run complete; rerun with --execute"
  exit 0
fi

if [ "$QUALIFICATION_ONLY" -eq "$SEAL_APPROVED" ]; then
  echo "select exactly one of --qualification-only or --seal-approved" >&2
  exit 2
fi

if [ "$SEAL_APPROVED" -eq 1 ]; then
  validate_acceptance_report
  virsh_cmd start "$VM_NAME" >/dev/null
  wait_agent
  sanitize_guest
  shutdown_guest
  virsh_cmd start "$VM_NAME" >/dev/null
  wait_agent
  modern_agent_ready || { echo "modern CAPE agent failed non-invasive cold-boot readiness" >&2; exit 1; }
  reseal_snapshot
  sudo mv "$QUALIFICATION_MARKER" "${QUALIFICATION_ROOT}/${VM_NAME}.sealed.$(date -u +%Y%m%dT%H%M%SZ)"
  exit 0
fi

start_guest
install_payloads
validate_etw
apply_hardening
run_qualification
shutdown_guest
log "qualification evidence collected; review it and rerun with --seal-approved --acceptance-report FILE"
