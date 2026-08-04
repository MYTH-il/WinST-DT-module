#!/usr/bin/env bash
set -euo pipefail

EXECUTE=0
AL_KHASER_PATH=""
PAFISH_PATH=""
SKIP_AL_KHASER=0
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-300}"
GUEST_AGENT_HOST="${GUEST_AGENT_HOST:-10.66.0.101}"
GUEST_AGENT_PORT="${GUEST_AGENT_PORT:-8000}"
GUEST_STAGE_DIR="${GUEST_STAGE_DIR:-C:\\Windows\\Temp\\winstdt-anti-evasion}"
GUEST_OUTPUT_ROOT="${GUEST_OUTPUT_ROOT:-C:\\ProgramData\\WinSTDT\\validation\\anti-evasion}"
LOCAL_OUTPUT_ROOT="${LOCAL_OUTPUT_ROOT:-docs/validation/evidence}"

usage() {
  cat <<EOF
Usage: scripts/validation/run-anti-evasion-validation.sh --al-khaser PATH --pafish PATH [--execute]
       scripts/validation/run-anti-evasion-validation.sh --skip-al-khaser --pafish PATH [--execute]

Stages al-khaser, Pafish, and the WinST/DT collection helper into the running
Windows guest through the CAPE agent, runs the tools, zips the evidence, and
retrieves it to \$LOCAL_OUTPUT_ROOT.

Default is a dry run. Use --execute to mutate the guest and run the tools.

Environment overrides:
  GUEST_AGENT_HOST    default: 10.66.0.101
  GUEST_AGENT_PORT    default: 8000
  GUEST_STAGE_DIR     default: C:\\Windows\\Temp\\winstdt-anti-evasion
  GUEST_OUTPUT_ROOT   default: C:\\ProgramData\\WinSTDT\\validation\\anti-evasion
  LOCAL_OUTPUT_ROOT   default: docs/validation/evidence
  TIMEOUT_SECONDS     default: 300
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --execute) EXECUTE=1 ;;
    --skip-al-khaser) SKIP_AL_KHASER=1 ;;
    --al-khaser) AL_KHASER_PATH="${2:-}"; shift ;;
    --pafish) PAFISH_PATH="${2:-}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

base_url() {
  printf 'http://%s:%s' "$GUEST_AGENT_HOST" "$GUEST_AGENT_PORT"
}

log() {
  printf '[winstdt-anti-evasion] %s\n' "$*"
}

require_file() {
  local path="$1"
  local label="$2"
  if [ -z "$path" ]; then
    echo "missing $label path" >&2
    usage >&2
    exit 2
  fi
  if [ ! -s "$path" ]; then
    echo "$label path missing or empty: $path" >&2
    exit 1
  fi
}

agent_post() {
  curl --max-time 60 -fsS "$@"
}

agent_execute() {
  local command="$1"
  local max_time=$((TIMEOUT_SECONDS * 2 + 180))
  curl --max-time "$max_time" -fsS -X POST \
    --data-urlencode "command=$command" \
    "$(base_url)/execute"
}

agent_mkdir() {
  agent_post -X POST --data-urlencode "dirpath=$1" "$(base_url)/mkdir" >/dev/null
}

agent_upload() {
  local source="$1"
  local target="$2"
  agent_post -X POST \
    -F "filepath=$target" \
    -F "file=@$source" \
    "$(base_url)/store" >/dev/null
}

agent_retrieve() {
  local guest_path="$1"
  local local_path="$2"
  agent_post -X POST \
    --data-urlencode "filepath=$guest_path" \
    "$(base_url)/retrieve" \
    -o "$local_path"
}

powershell_quote() {
  printf "'%s'" "${1//\'/\'\'}"
}

guest_join() {
  local left="${1%\\}"
  local right="${2#\\}"
  printf '%s\\%s' "$left" "$right"
}

main() {
  if [ "$SKIP_AL_KHASER" -eq 0 ]; then
    require_file "$AL_KHASER_PATH" "al-khaser"
  fi
  require_file "$PAFISH_PATH" "Pafish"
  require_file "scripts/validation/Invoke-AntiEvasionCollection.ps1" "collector"

  log "probing CAPE agent at $(base_url)"
  agent_post "$(base_url)/" >/tmp/winstdt-anti-evasion-agent.json
  log "agent response: $(tr -d '\n' </tmp/winstdt-anti-evasion-agent.json)"

  if [ "$SKIP_AL_KHASER" -eq 0 ]; then
    log "al-khaser sha256=$(sha256sum "$AL_KHASER_PATH" | awk '{print $1}')"
  else
    log "al-khaser skipped; final MVP gate remains incomplete"
  fi
  log "pafish sha256=$(sha256sum "$PAFISH_PATH" | awk '{print $1}')"

  if [ "$EXECUTE" -eq 0 ]; then
    log "dry run complete; rerun with --execute to stage and run validation"
    return
  fi

  local guest_tools_dir al_guest pafish_guest collector_guest runner_guest marker_guest zip_guest
  guest_tools_dir="$(guest_join "$GUEST_STAGE_DIR" "tools")"
  al_guest="$(guest_join "$guest_tools_dir" "al-khaser.exe")"
  pafish_guest="$(guest_join "$guest_tools_dir" "pafish.exe")"
  collector_guest="$(guest_join "$GUEST_STAGE_DIR" "Invoke-AntiEvasionCollection.ps1")"
  runner_guest="$(guest_join "$GUEST_STAGE_DIR" "Run-AntiEvasionCollection.ps1")"
  marker_guest="$(guest_join "$GUEST_STAGE_DIR" "last-run.txt")"
  zip_guest="$(guest_join "$GUEST_STAGE_DIR" "anti-evasion-evidence.zip")"

  log "creating guest stage directory"
  agent_mkdir "$guest_tools_dir"

  log "uploading tools and collector"
  if [ "$SKIP_AL_KHASER" -eq 0 ]; then
    agent_upload "$AL_KHASER_PATH" "$al_guest"
  fi
  agent_upload "$PAFISH_PATH" "$pafish_guest"
  agent_upload "scripts/validation/Invoke-AntiEvasionCollection.ps1" "$collector_guest"

  local runner_local
  runner_local="$(mktemp)"
  local collector_args
  collector_args="-PafishPath $(powershell_quote "$pafish_guest")"
  if [ "$SKIP_AL_KHASER" -eq 0 ]; then
    collector_args="-AlKhaserPath $(powershell_quote "$al_guest") ${collector_args}"
  fi
  {
    printf '$ErrorActionPreference = "Stop"\n'
    printf 'Set-ExecutionPolicy -Scope Process Bypass -Force\n'
    printf '& %s %s -OutputRoot %s -TimeoutSeconds %s\n' \
      "$(powershell_quote "$collector_guest")" \
      "$collector_args" \
      "$(powershell_quote "$GUEST_OUTPUT_ROOT")" \
      "$TIMEOUT_SECONDS"
    printf '$latest = Get-ChildItem -LiteralPath %s -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1\n' \
      "$(powershell_quote "$GUEST_OUTPUT_ROOT")"
    printf '$latest.FullName | Set-Content -LiteralPath %s -Encoding ASCII\n' \
      "$(powershell_quote "$marker_guest")"
    printf 'if (Test-Path -LiteralPath %s) { Remove-Item -LiteralPath %s -Force }\n' \
      "$(powershell_quote "$zip_guest")" \
      "$(powershell_quote "$zip_guest")"
    printf 'Compress-Archive -LiteralPath $latest.FullName -DestinationPath %s -Force\n' \
      "$(powershell_quote "$zip_guest")"
  } >"$runner_local"
  agent_upload "$runner_local" "$runner_guest"
  rm -f "$runner_local"

  log "running anti-evasion tools inside guest; timeout per tool=${TIMEOUT_SECONDS}s"
  agent_execute "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"${runner_guest}\"" >/tmp/winstdt-anti-evasion-execute.json
  log "guest execution response saved to /tmp/winstdt-anti-evasion-execute.json"

  mkdir -p "$LOCAL_OUTPUT_ROOT"
  local run_marker local_zip run_id local_run_dir
  run_marker="$(mktemp)"
  agent_retrieve "$marker_guest" "$run_marker"
  run_id="$(tr -d '\r\n' <"$run_marker" | awk -F '\\\\' '{print $NF}')"
  if [ -z "$run_id" ]; then
    echo "guest did not report anti-evasion run id" >&2
    exit 1
  fi

  local_zip="${LOCAL_OUTPUT_ROOT}/${run_id}.zip"
  local_run_dir="${LOCAL_OUTPUT_ROOT}/${run_id}"
  log "retrieving evidence archive to ${local_zip}"
  agent_retrieve "$zip_guest" "$local_zip"
  mkdir -p "$local_run_dir"
  python3 - "$local_zip" "$local_run_dir" <<'PY'
from pathlib import Path
from zipfile import ZipFile
import sys

archive = Path(sys.argv[1])
destination = Path(sys.argv[2])
with ZipFile(archive) as zf:
    for member in zf.infolist():
        normalized = member.filename.replace("\\", "/").lstrip("/")
        if not normalized or normalized.endswith("/"):
            continue
        target = destination / normalized
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(zf.read(member))
PY

  log "evidence extracted to ${local_run_dir}"
  find "$local_run_dir" -maxdepth 3 -type f -printf '%P %s bytes\n' | sort
  python3 - "$local_run_dir" <<'PY'
from pathlib import Path
import json, sys

root = Path(sys.argv[1])
for name in ('al-khaser', 'pafish'):
    result_path = next(root.rglob(name + '.result.json'), None)
    if result_path is None:
        raise SystemExit(name + ' result metadata is missing')
    result = json.loads(result_path.read_text(encoding='utf-8-sig'))
    if not result.get('completed') or result.get('timed_out'):
        raise SystemExit(name + ' did not complete successfully')
    stdout = next(root.rglob(name + '.stdout.txt'), None)
    sidecars = [path for path in (result_path.parent / name).rglob('*') if path.is_file() and path.suffix.lower() != '.exe' and path.stat().st_size]
    if not ((stdout and stdout.stat().st_size) or sidecars):
        raise SystemExit(name + ' produced no reviewable stdout or sidecar output')
print('both anti-evasion tools produced reviewable evidence')
PY
}

main
