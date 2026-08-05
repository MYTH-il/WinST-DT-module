#!/usr/bin/env bash
set -euo pipefail

EXECUTE=0

CAPE_DIR="${CAPE_DIR:-/opt/CAPEv2}"
GUEST_AGENT_HOST="${GUEST_AGENT_HOST:-10.66.0.101}"
GUEST_AGENT_PORT="${GUEST_AGENT_PORT:-8000}"
MODERN_AGENT_PORT="${MODERN_AGENT_PORT:-8001}"
STAGE_DIR="${STAGE_DIR:-C:\\Windows\\Temp\\winstdt-cape-agent}"
REQUIRED_FEATURES=(execpy logs subdir_upload)

usage() {
  cat <<EOF
Usage: scripts/stage-cape-guest-agent.sh [--execute]

Stage and validate the current CAPEv2 agent.py inside the Windows guest.

Default behavior validates the currently reachable guest agent and, with
--execute, uploads CAPE's current agent.py and starts it on alternate port
\$MODERN_AGENT_PORT. Replacing the primary CAPE control channel on port 8000 is
disabled unless WINSTDT_REPLACE_CAPE_AGENT=1 is set.

Environment overrides:
  CAPE_DIR                    default: /opt/CAPEv2
  GUEST_AGENT_HOST            default: 10.66.0.101
  GUEST_AGENT_PORT            default: 8000
  MODERN_AGENT_PORT           default: 8001
  STAGE_DIR                   default: C:\\Windows\\Temp\\winstdt-cape-agent
  WINSTDT_REPLACE_CAPE_AGENT  default: 0
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

base_url() {
  local port="$1"
  printf 'http://%s:%s' "$GUEST_AGENT_HOST" "$port"
}

log() {
  printf '[winstdt-guest-agent] %s\n' "$*"
}

curl_json() {
  curl --max-time 20 -fsS "$@"
}

agent_json() {
  local port="$1"
  curl_json "$(base_url "$port")/"
}

agent_field() {
  local json="$1"
  local expr="$2"
  JSON_PAYLOAD="$json" python3 - "$expr" <<'PY'
import json
import os
import sys

payload = json.loads(os.environ["JSON_PAYLOAD"])
expr = sys.argv[1]
if expr == "version":
    print(payload.get("version", "unknown"))
elif expr == "features":
    print(" ".join(payload.get("features", [])))
else:
    raise SystemExit(f"unsupported expression: {expr}")
PY
}

has_required_features() {
  local features="$1"
  local feature
  for feature in "${REQUIRED_FEATURES[@]}"; do
    [[ " $features " == *" $feature "* ]] || return 1
  done
}

execute_guest() {
  local command="$1"
  curl_json -X POST \
    --data-urlencode "command=$command" \
    -d 'shell=1' \
    "$(base_url "$GUEST_AGENT_PORT")/execute"
}

execute_guest_async() {
  local command="$1"
  curl_json -X POST \
    --data-urlencode "command=$command" \
    -d 'shell=1' \
    -d 'async=1' \
    "$(base_url "$GUEST_AGENT_PORT")/execute"
}

upload_guest() {
  local source="$1"
  local target="$2"
  curl_json -X POST \
    -F "filepath=$target" \
    -F "file=@$source" \
    "$(base_url "$GUEST_AGENT_PORT")/store"
}

choose_python_command() {
  local probe_file="${STAGE_DIR}\\python-probe.txt"
  execute_guest "cmd.exe /c mkdir \"${STAGE_DIR}\" 2>nul & if exist C:\\Python3\\python.exe (C:\\Python3\\python.exe --version > \"${probe_file}\" 2>&1 & echo C:\\Python3\\python.exe>>\"${probe_file}\") else if exist C:\\Python39\\python.exe (C:\\Python39\\python.exe --version > \"${probe_file}\" 2>&1 & echo C:\\Python39\\python.exe>>\"${probe_file}\") else if exist C:\\Python38\\python.exe (C:\\Python38\\python.exe --version > \"${probe_file}\" 2>&1 & echo C:\\Python38\\python.exe>>\"${probe_file}\") else if exist C:\\Python36\\python.exe (C:\\Python36\\python.exe --version > \"${probe_file}\" 2>&1 & echo C:\\Python36\\python.exe>>\"${probe_file}\") else (py -3 --version > \"${probe_file}\" 2>&1 && echo py -3>>\"${probe_file}\") || (python --version > \"${probe_file}\" 2>&1 && echo python>>\"${probe_file}\")" >/dev/null
  local probe
  probe="$(curl_json -X POST -d "filepath=${probe_file}" "$(base_url "$GUEST_AGENT_PORT")/retrieve" || true)"
  printf '%s\n' "$probe" | tail -n1 | tr -d '\r'
}

stage_alternate_agent() {
  local source_agent="${CAPE_DIR}/agent/agent.py"
  local target_agent="${STAGE_DIR}\\agent.py"
  test -f "$source_agent" || {
    echo "missing CAPE agent source: $source_agent" >&2
    exit 1
  }

  if validate_modern_agent_port; then
    return
  fi

  local python_cmd
  python_cmd="$(choose_python_command)"
  case "$python_cmd" in
    py\ -3|python|C:\\Python*.exe) ;;
    *)
      echo "could not find Python 3 in guest; cannot stage modern agent.py" >&2
      exit 1
      ;;
  esac

  upload_guest "$source_agent" "$target_agent" >/dev/null
  execute_guest_async "cmd.exe /c ${python_cmd} \"${target_agent}\" 0.0.0.0 ${MODERN_AGENT_PORT} > \"${STAGE_DIR}\\agent-${MODERN_AGENT_PORT}.log\" 2>&1" >/dev/null

  validate_modern_agent_port || {
    echo "modern agent did not answer on port ${MODERN_AGENT_PORT}" >&2
    exit 1
  }
}

validate_modern_agent_port() {
  local _attempt
  for _attempt in $(seq 1 30); do
    if agent_json "$MODERN_AGENT_PORT" >/tmp/winstdt-modern-agent.json 2>/dev/null; then
      local json version features
      json="$(cat /tmp/winstdt-modern-agent.json)"
      version="$(agent_field "$json" version)"
      features="$(agent_field "$json" features)"
      if has_required_features "$features"; then
        log "modern agent validated on port ${MODERN_AGENT_PORT}: version=${version} features=${features}"
        return 0
      fi
      echo "modern agent lacks required features: $features" >&2
      exit 1
    fi
    sleep 2
  done
  return 1
}

replace_primary_agent() {
  if [ "${WINSTDT_REPLACE_CAPE_AGENT:-0}" != "1" ]; then
    log "primary port replacement skipped; set WINSTDT_REPLACE_CAPE_AGENT=1 to enable"
    return
  fi
  echo "primary agent replacement is intentionally not automated yet; validate port ${MODERN_AGENT_PORT} first and reseal the guest image through the golden-image workflow" >&2
  exit 1
}

main() {
  local current version features
  current="$(agent_json "$GUEST_AGENT_PORT")"
  version="$(agent_field "$current" version)"
  features="$(agent_field "$current" features)"
  log "current agent on port ${GUEST_AGENT_PORT}: version=${version} features=${features}"
  if has_required_features "$features"; then
    log "current agent already satisfies required CAPE features"
    return
  fi
  log "current agent is missing one or more required features: ${REQUIRED_FEATURES[*]}"
  if [ "$EXECUTE" -eq 0 ]; then
    log "dry-run only; rerun with --execute to stage modern agent on port ${MODERN_AGENT_PORT}"
    return
  fi
  stage_alternate_agent
  replace_primary_agent
}

main
