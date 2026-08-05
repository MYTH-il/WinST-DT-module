#!/usr/bin/env bash
set -euo pipefail

EXECUTE=0
VALIDATE_ONLY=0
CAPE_DIR="${CAPE_DIR:-/opt/CAPEv2}"
WINSTDT_ROOT="${WINSTDT_ROOT:-/srv/winstdt}"
LIBVIRT_URI="${LIBVIRT_URI:-qemu:///system}"
ANALYSIS_NETWORK="${NETWORK_NAME:-winstdt-isolated}"
GATEWAY_NETWORK="${GATEWAY_NETWORK_NAME:-winstdt-controlled-services}"
ANALYSIS_DOMAIN="${VM_NAME:-winstdt-win10-22h2}"
GATEWAY_DOMAIN="${GATEWAY_VM_NAME:-winstdt-egress-gateway}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_ROOT="$WINSTDT_ROOT/backups/libvirt/$STAMP"

usage() {
  cat <<'EOF'
Usage: scripts/repair-libvirt-runtime.sh [--execute | --validate-only]

Dry-run is the default. --execute quarantines unowned modular libvirt files,
restores packaged monolithic libvirtd, validates networks/domains, and only then
restarts CAPE. --validate-only performs the final read-only health checks.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --execute) EXECUTE=1 ;;
    --validate-only) VALIDATE_ONLY=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done
if [ "$EXECUTE" -eq 1 ] && [ "$VALIDATE_ONLY" -eq 1 ]; then
  echo '--execute and --validate-only are mutually exclusive' >&2
  exit 2
fi

log() { printf '[libvirt-repair] %s\n' "$*"; }
run() {
  log "+ $*"
  [ "$EXECUTE" -eq 0 ] || sudo "$@"
}
run_shell() {
  log "+ $1"
  [ "$EXECUTE" -eq 0 ] || sudo bash -o pipefail -c "$1"
}
cape_stop() {
  sudo systemctl stop cape-web.service cape-processor.service cape.service cape-rooter.service 2>/dev/null || true
}
hard_fail() {
  echo "[libvirt-repair] HARD FAILURE: $*" >&2
  if [ "$EXECUTE" -eq 1 ]; then
    echo '[libvirt-repair] leaving CAPE stopped because libvirt is unhealthy' >&2
    cape_stop
  fi
  exit 1
}

test -r /etc/os-release || hard_fail 'cannot read /etc/os-release'
# shellcheck disable=SC1091
. /etc/os-release
[ "${ID:-}" = ubuntu ] && [ "${VERSION_ID:-}" = 24.04 ] || hard_fail 'Ubuntu 24.04 is required'
dpkg-query -W -f='${Status}\n' libvirt-daemon-system 2>/dev/null | grep -qx 'install ok installed' \
  || hard_fail 'libvirt-daemon-system is not installed'

STALE_UNITS=(
  virtstoraged.service
  virtstoraged.socket
  virtstoraged-ro.socket
  virtstoraged-admin.socket
)

declare -a UNOWNED=()
package_owns() {
  local path="$1" legacy
  dpkg-query -S "$path" >/dev/null 2>&1 && return 0
  if [[ "$path" = /usr/lib/* ]]; then
    legacy="/lib/${path#/usr/lib/}"
    dpkg-query -S "$legacy" >/dev/null 2>&1 && return 0
  fi
  return 1
}
discover_unowned() {
  local path
  UNOWNED=()
  shopt -s nullglob
  for path in \
    /usr/sbin/virtqemud /usr/sbin/virtnetworkd /usr/sbin/virtproxyd \
    /usr/sbin/virtinterfaced /usr/sbin/virtnodedevd /usr/sbin/virtnwfilterd \
    /usr/sbin/virtsecretd /usr/sbin/virtstoraged /usr/sbin/virtchd \
    /usr/sbin/virtlxcd /usr/sbin/virtvboxd /usr/sbin/virtxend \
    /usr/lib/systemd/system/virt*.service /usr/lib/systemd/system/virt*.socket; do
    [ -e "$path" ] || [ -L "$path" ] || continue
    if ! package_owns "$path"; then
      UNOWNED+=("$path")
    fi
  done
  shopt -u nullglob
}

enabled_unit_execstart_errors() {
  local unit fragment command
  while read -r unit _; do
    [ -n "$unit" ] || continue
    fragment="$(systemctl show -p FragmentPath --value "$unit" 2>/dev/null || true)"
    [ -n "$fragment" ] && [ -r "$fragment" ] || continue
    while IFS= read -r command; do
      command="${command#-}"
      command="${command%% *}"
      case "$command" in ''|@*|/bin/true) continue ;; esac
      if [[ "$command" = /* ]] && [ ! -x "$command" ]; then
        printf '%s: ExecStart target missing: %s\n' "$unit" "$command"
      fi
    done < <(sed -n 's/^[[:space:]]*ExecStart=//p' "$fragment")
  done < <(systemctl list-unit-files --no-legend --no-pager 'libvirt*' 'virt*' 2>/dev/null | awk '$2 == "enabled" || $2 == "enabled-runtime"')
}

validate_runtime() {
  local errors=0 uri_configured
  if [ ! -S /run/libvirt/libvirt-sock ]; then
    echo 'libvirt socket is absent: /run/libvirt/libvirt-sock' >&2
    errors=1
  fi
  if ! virsh -c "$LIBVIRT_URI" list --all >/dev/null 2>&1; then
    echo "virsh connection failed: $LIBVIRT_URI" >&2
    errors=1
  fi
  for network in "$ANALYSIS_NETWORK" "$GATEWAY_NETWORK"; do
    if ! virsh -c "$LIBVIRT_URI" net-info "$network" 2>/dev/null | awk '$1 == "Active:" && $2 == "yes" {ok=1} END {exit !ok}'; then
      echo "required libvirt network is unavailable: $network" >&2
      errors=1
    fi
  done
  for domain in "$ANALYSIS_DOMAIN" "$GATEWAY_DOMAIN"; do
    if ! virsh -c "$LIBVIRT_URI" dominfo "$domain" >/dev/null 2>&1; then
      echo "required libvirt domain cannot be queried: $domain" >&2
      errors=1
    fi
  done
  if [ -r "$CAPE_DIR/conf/kvm.conf" ]; then
    uri_configured="$(sed -n 's/^[[:space:]]*dsn[[:space:]]*=[[:space:]]*//p; s/^[[:space:]]*uri[[:space:]]*=[[:space:]]*//p' "$CAPE_DIR/conf/kvm.conf" | tail -n1)"
    if [ -n "$uri_configured" ] && ! virsh -c "$uri_configured" list --all >/dev/null 2>&1; then
      echo "CAPE libvirt URI is unavailable: $uri_configured" >&2
      errors=1
    fi
  fi
  if enabled_unit_execstart_errors | tee /tmp/winstdt-libvirt-execstart-errors.$$ | grep -q .; then
    cat /tmp/winstdt-libvirt-execstart-errors.$$ >&2
    errors=1
  fi
  rm -f /tmp/winstdt-libvirt-execstart-errors.$$
  discover_unowned
  if [ "${#UNOWNED[@]}" -gt 0 ]; then
    printf 'unowned modular libvirt files remain:\n' >&2
    printf '  %s\n' "${UNOWNED[@]}" >&2
    errors=1
  fi
  [ "$errors" -eq 0 ]
}

if [ "$VALIDATE_ONLY" -eq 1 ]; then
  validate_runtime || hard_fail 'read-only validation failed'
  log 'libvirt runtime validation passed'
  exit 0
fi

discover_unowned
log "found ${#UNOWNED[@]} unowned modular libvirt file(s)"
printf '[libvirt-repair] quarantine candidate: %s\n' "${UNOWNED[@]}"

run systemctl disable --now "${STALE_UNITS[@]}" || true
if [ "${#UNOWNED[@]}" -gt 0 ]; then
  run install -d -m 0750 "$BACKUP_ROOT"
  for path in "${UNOWNED[@]}"; do
    relative="${path#/}"
    run install -d -m 0750 "$BACKUP_ROOT/$(dirname "$relative")"
    run mv "$path" "$BACKUP_ROOT/$relative"
  done
fi
run systemctl daemon-reload
run systemctl reset-failed libvirtd.service virtlogd.service virtlockd.service
run systemctl enable libvirtd.service libvirtd.socket libvirtd-ro.socket virtlogd.socket virtlockd.socket
run systemctl start virtlogd.socket virtlockd.socket libvirtd.socket libvirtd-ro.socket libvirtd.service

if [ "$EXECUTE" -eq 0 ]; then
  log 'dry-run complete; no changes made and post-repair validation was not attempted'
  exit 0
fi

validate_runtime || hard_fail 'post-repair libvirt validation failed'
sudo systemctl restart cape-rooter.service cape.service cape-processor.service
if systemctl cat cape-web.service >/dev/null 2>&1; then
  sudo systemctl restart cape-web.service
fi
for service in cape-rooter.service cape.service cape-processor.service; do
  sudo systemctl is-active --quiet "$service" || hard_fail "CAPE service failed after repair: $service"
done
log "repair completed; quarantined files are under $BACKUP_ROOT"
