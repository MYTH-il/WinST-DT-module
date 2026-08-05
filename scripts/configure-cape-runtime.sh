#!/usr/bin/env bash
set -euo pipefail

EXECUTE=0
SKIP_DOMAIN=0
SKIP_SERVICE_RESTART=0

SCRIPT_VERSION="v0.1"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK_FILE="${LOCK_FILE:-$PROJECT_ROOT/config/cape.lock.json}"

CAPE_DIR="${CAPE_DIR:-/opt/CAPEv2}"
CAPE_USER="${CAPE_USER:-cape}"
WINSTDT_ROOT="${WINSTDT_ROOT:-/srv/winstdt}"
VM_NAME="${VM_NAME:-winstdt-win10-22h2}"
SNAPSHOT_NAME="${SNAPSHOT_NAME:-hardened-baseline-antievasion-v1}"
NETWORK_NAME="${NETWORK_NAME:-winstdt-isolated}"
BRIDGE_NAME="${BRIDGE_NAME:-virbr-winstdt}"
HOST_IP="${HOST_IP:-10.66.0.1}"
GUEST_IP="${GUEST_IP:-10.66.0.101}"
WINSTDT_VM_COUNT="${WINSTDT_VM_COUNT:-1}"
VM_CPUS="${VM_CPUS:-4}"
VM_RAM_MB="${VM_RAM_MB:-8192}"
VM_DISK_GB="${VM_DISK_GB:-160}"
LIBVIRT_URI="${LIBVIRT_URI:-qemu+unix:///system?socket=/run/libvirt/libvirt-sock}"
SYSTEM_LIB_PATH="${SYSTEM_LIB_PATH:-/usr/lib/x86_64-linux-gnu}"
SYSTEM_PKG_CONFIG_PATH="${SYSTEM_PKG_CONFIG_PATH:-/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/lib64/pkgconfig:/usr/share/pkgconfig}"
MONGODB_KERNEL_COMPAT_VERSION="${MONGODB_KERNEL_COMPAT_VERSION:-8.0.4}"
MONGODB_HELD_PACKAGES=(
  mongodb-org
  mongodb-org-database
  mongodb-org-server
  mongodb-org-mongos
  mongodb-org-shell
  mongodb-org-database-tools-extra
  mongodb-org-tools
)
VMCLOAK_IMAGE_PATH="${VMCLOAK_IMAGE_PATH:-${HOME}/.vmcloak/image/${VM_NAME}.qcow2}"
LIBVIRT_IMAGE_DIR="${LIBVIRT_IMAGE_DIR:-/var/lib/libvirt/images/winstdt}"
GOLDEN_DISK_PATH="${GOLDEN_DISK_PATH:-${LIBVIRT_IMAGE_DIR}/${VM_NAME}-golden.qcow2}"
CLONE_DISK_PATH="${CLONE_DISK_PATH:-${LIBVIRT_IMAGE_DIR}/${VM_NAME}.qcow2}"
SNAPSHOT_DIR="${SNAPSHOT_DIR:-${LIBVIRT_IMAGE_DIR}/snapshots}"

usage() {
  cat <<EOF
Usage: scripts/configure-cape-runtime.sh [--execute] [options]

Close the post-bootstrap CAPE runtime gap for WinST/DT.

Options:
  --execute              Apply changes. Without this, only planned checks run.
  --skip-domain          Do not create/check the libvirt domain and snapshot.
  --skip-service-restart Do not restart CAPE/MongoDB services.
  -h, --help             Show this help.

Environment overrides:
  CAPE_DIR               default: /opt/CAPEv2
  CAPE_USER              default: cape
  VM_NAME                default: winstdt-win10-22h2
  SNAPSHOT_NAME          default: hardened-baseline-antievasion-v1
  NETWORK_NAME           default: winstdt-isolated
  BRIDGE_NAME            default: virbr-winstdt
  HOST_IP                default: 10.66.0.1
  GUEST_IP               default: 10.66.0.101
  WINSTDT_VM_COUNT       default: 1
  VM_CPUS                default: 4
  VM_RAM_MB              default: 8192
  VM_DISK_GB             default: 160
  WINSTDT_SMBIOS_*       optional OEM identity overrides for hardened libvirt XML
  WINSTDT_HYPERV_VENDOR_ID default: DellInc2023
  SYSTEM_PKG_CONFIG_PATH default: multiarch, /usr/lib64, and shared pkgconfig paths
  MONGODB_KERNEL_COMPAT_VERSION default: 8.0.4 on kernel 6.19+
  VMCLOAK_IMAGE_PATH     default: ~/.vmcloak/image/\$VM_NAME.qcow2
  LIBVIRT_IMAGE_DIR      default: /var/lib/libvirt/images/winstdt
  GOLDEN_DISK_PATH       default: \$LIBVIRT_IMAGE_DIR/\$VM_NAME-golden.qcow2
  CLONE_DISK_PATH        default: \$LIBVIRT_IMAGE_DIR/\$VM_NAME.qcow2
  SNAPSHOT_DIR           default: \$LIBVIRT_IMAGE_DIR/snapshots
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --execute) EXECUTE=1 ;;
    --skip-domain) SKIP_DOMAIN=1 ;;
    --skip-service-restart) SKIP_SERVICE_RESTART=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

log() {
  printf '[winstdt-runtime] %s\n' "$*"
}

run_root() {
  log "+ sudo $*"
  if [ "$EXECUTE" -eq 1 ]; then
    sudo "$@"
  fi
}

run_root_shell() {
  log "+ sudo bash -lc $1"
  if [ "$EXECUTE" -eq 1 ]; then
    sudo bash -lc "$1"
  fi
}

run_cape_shell() {
  log "+ sudo -u ${CAPE_USER} bash -lc $1"
  if [ "$EXECUTE" -eq 1 ]; then
    sudo -u "$CAPE_USER" bash -lc "$1"
  fi
}

require_execute_sudo() {
  if [ "$EXECUTE" -eq 0 ]; then
    log "dry-run mode; no system changes will be made"
    return
  fi
  sudo -n true 2>/dev/null || {
    echo "passwordless/cached sudo is required. Run 'sudo -v' in a terminal, then retry." >&2
    exit 1
  }
}

validate_gates() {
  case "$WINSTDT_VM_COUNT" in
    ''|*[!0-9]*)
      echo "WINSTDT_VM_COUNT must be a positive integer" >&2
      exit 1
      ;;
  esac
  if [ "$WINSTDT_VM_COUNT" -lt 1 ]; then
    echo "WINSTDT_VM_COUNT must be at least 1" >&2
    exit 1
  fi
  if [ "${WINSTDT_LIVE_EGRESS_ENABLED:-0}" = "1" ]; then
    local missing=0
    for name in WINSTDT_LIVE_EGRESS_APPROVAL_ID WINSTDT_LIVE_EGRESS_OWNER WINSTDT_LIVE_EGRESS_DATE WINSTDT_LIVE_EGRESS_ALLOWED_NETWORKS WINSTDT_LIVE_EGRESS_RATE_LIMIT; do
      if [ -z "${!name:-}" ]; then
        echo "live egress requires $name" >&2
        missing=1
      fi
    done
    if [ "$missing" -ne 0 ]; then
      exit 1
    fi
    log "live egress approval metadata present; route profile remains operator-controlled"
  fi
}

vm_name_for_index() {
  local index="$1"
  if [ "$WINSTDT_VM_COUNT" -eq 1 ]; then
    printf '%s\n' "$VM_NAME"
  else
    printf '%s-%02d\n' "$VM_NAME" "$index"
  fi
}

guest_ip_for_index() {
  local index="$1"
  printf '10.66.0.%d\n' $((100 + index))
}

ensure_dhcp_reservation() {
  local name="$1"
  local ip="$2"
  local mac old_mac
  mac="$(env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" dumpxml "$name" | sed -n "s/.*<mac address='\([^']*\)'.*/\1/p" | head -n1)"
  if [ -z "$mac" ]; then
    echo "could not discover MAC for $name" >&2
    exit 1
  fi
  old_mac="$(env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" net-dumpxml "$NETWORK_NAME" | sed -n "s/.*<host mac='\([^']*\)' name='$name' ip='$ip'.*/\1/p" | head -n1)"
  if [ -n "$old_mac" ] && [ "$old_mac" != "$mac" ]; then
    run_root_shell "env LD_LIBRARY_PATH='$SYSTEM_LIB_PATH' virsh -c '$LIBVIRT_URI' net-update '$NETWORK_NAME' delete ip-dhcp-host \"<host mac='$old_mac' name='$name' ip='$ip'/>\" --live --config"
  fi
  if ! env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" net-dumpxml "$NETWORK_NAME" | grep -q "$mac"; then
    run_root_shell "env LD_LIBRARY_PATH='$SYSTEM_LIB_PATH' virsh -c '$LIBVIRT_URI' net-update '$NETWORK_NAME' add ip-dhcp-host \"<host mac='$mac' name='$name' ip='$ip'/>\" --live --config || env LD_LIBRARY_PATH='$SYSTEM_LIB_PATH' virsh -c '$LIBVIRT_URI' net-dumpxml '$NETWORK_NAME' | grep -q '$mac'"
  fi
}

ensure_qcow2_min_size() {
  local image="$1"
  local min_gb="$2"
  local current_bytes
  local required_bytes
  current_bytes="$(qemu-img info --output=json "$image" | python3 -c 'import json,sys; print(json.load(sys.stdin)["virtual-size"])')"
  required_bytes=$((min_gb * 1024 * 1024 * 1024))
  if [ "$current_bytes" -lt "$required_bytes" ]; then
    qemu-img resize "$image" "${min_gb}G"
  fi
}

harden_libvirt_domain_definition() {
  local name="$1"
  local tmp_in
  local tmp_out
  tmp_in="$(mktemp)"
  tmp_out="$(mktemp)"
  env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" dumpxml --inactive "$name" >"$tmp_in"
  python3 "$PROJECT_ROOT/scripts/harden-libvirt-domain.py" --input "$tmp_in" --output "$tmp_out" --cpus "$VM_CPUS"
  run_root_shell "env LD_LIBRARY_PATH='$SYSTEM_LIB_PATH' virsh -c '$LIBVIRT_URI' define '$tmp_out'"
  rm -f "$tmp_in" "$tmp_out"
}

backup_file() {
  local path="$1"
  if [ -f "$path" ]; then
    local relative="${path#"${CAPE_DIR}"/}"
    local destination
    destination="$WINSTDT_ROOT/backups/cape/$(date -u +%Y%m%dT%H%M%SZ)/$relative"
    run_root install -d -m 0750 -o "$CAPE_USER" -g "$CAPE_USER" "$(dirname "$destination")"
    run_root cp -a "$path" "$destination"
  fi
}

verify_cape_revision() {
  local expected actual
  expected="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["cape"]["commit"])' "$LOCK_FILE")"
  actual="$(git -c safe.directory="$CAPE_DIR" -C "$CAPE_DIR" rev-parse HEAD 2>/dev/null || true)"
  if [ "$actual" != "$expected" ]; then
    echo "CAPE revision mismatch: expected=$expected actual=${actual:-missing}; refusing configuration" >&2
    exit 1
  fi
  if ! git -c safe.directory="$CAPE_DIR" -C "$CAPE_DIR" diff --quiet || ! git -c safe.directory="$CAPE_DIR" -C "$CAPE_DIR" diff --cached --quiet || [ -n "$(git -c safe.directory="$CAPE_DIR" -C "$CAPE_DIR" ls-files --others --exclude-standard)" ]; then
    log "CAPE revision matches but worktree has local divergence; no reset or overwrite will be attempted"
    git -c safe.directory="$CAPE_DIR" -C "$CAPE_DIR" status --short >&2
  fi
}

ensure_runtime_packages() {
  if ! PKG_CONFIG_PATH="$SYSTEM_PKG_CONFIG_PATH" pkg-config --exists libvirt || [ ! -e "${SYSTEM_LIB_PATH}/libvirt.so" ]; then
    run_root apt-get update
    run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y libvirt-dev pkg-config
  fi
}

kernel_requires_mongodb_compat() {
  local release
  release="$(uname -r | cut -d- -f1)"
  local major minor
  major="$(printf '%s' "$release" | cut -d. -f1)"
  minor="$(printf '%s' "$release" | cut -d. -f2)"
  case "$major" in ''|*[!0-9]*) return 1 ;; esac
  case "$minor" in ''|*[!0-9]*) minor=0 ;; esac
  [ "$major" -gt 6 ] || { [ "$major" -eq 6 ] && [ "$minor" -ge 19 ]; }
}

ensure_mongodb_kernel_compat() {
  if ! kernel_requires_mongodb_compat; then
    return
  fi
  if ! command -v mongod >/dev/null 2>&1; then
    return
  fi
  local current
  current="$(mongod --version | awk '/db version/ { sub(/^v/, "", $3); print $3; exit }')"
  if [ "$current" = "$MONGODB_KERNEL_COMPAT_VERSION" ]; then
    return
  fi
  log "MongoDB $current is incompatible with kernel $(uname -r); downgrading to $MONGODB_KERNEL_COMPAT_VERSION"
  run_root apt-mark unhold "${MONGODB_HELD_PACKAGES[@]}" || true
  run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades \
    "mongodb-org=${MONGODB_KERNEL_COMPAT_VERSION}" \
    "mongodb-org-database=${MONGODB_KERNEL_COMPAT_VERSION}" \
    "mongodb-org-server=${MONGODB_KERNEL_COMPAT_VERSION}" \
    "mongodb-org-mongos=${MONGODB_KERNEL_COMPAT_VERSION}" \
    "mongodb-org-shell=${MONGODB_KERNEL_COMPAT_VERSION}" \
    "mongodb-org-database-tools-extra=${MONGODB_KERNEL_COMPAT_VERSION}" \
    "mongodb-org-tools=${MONGODB_KERNEL_COMPAT_VERSION}"
  run_root apt-mark hold "${MONGODB_HELD_PACKAGES[@]}"
}

ensure_mongodb_local_bind() {
  if [ ! -f /etc/mongod.conf ]; then
    return
  fi
  run_root_shell "python3 - <<'PY'
from pathlib import Path

path = Path('/etc/mongod.conf')
lines = path.read_text(encoding='utf-8').splitlines()
out = []
in_net = False
seen_net = False
seen_bind = False
for line in lines:
    stripped = line.strip()
    if line and not line.startswith((' ', '\t')) and stripped.endswith(':'):
        if in_net and not seen_bind:
            out.append('  bindIp: 127.0.0.1')
            seen_bind = True
        in_net = stripped == 'net:'
        seen_net = seen_net or in_net
        out.append(line)
        continue
    if in_net and stripped.startswith('bindIp:'):
        out.append('  bindIp: 127.0.0.1')
        seen_bind = True
    else:
        out.append(line)
if in_net and not seen_bind:
    out.append('  bindIp: 127.0.0.1')
if not seen_net:
    out.extend(['', 'net:', '  port: 27017', '  bindIp: 127.0.0.1'])
path.write_text('\\n'.join(out) + '\\n', encoding='utf-8')
PY"
}

set_ini_value() {
  local path="$1"
  local section="$2"
  local key="$3"
  local value="$4"
  run_root_shell "python3 - <<'PY'
from pathlib import Path
path = Path('$path')
section = '$section'
key = '$key'
value = '$value'
lines = path.read_text(encoding='utf-8').splitlines()
out = []
in_section = False
seen_section = False
changed = False
for line in lines:
    stripped = line.strip()
    if stripped.startswith('[') and stripped.endswith(']'):
        if in_section and not changed:
            out.append(f'{key} = {value}')
            changed = True
        in_section = stripped == f'[{section}]'
        seen_section = seen_section or in_section
        out.append(line)
        continue
    if in_section and stripped.startswith(f'{key} ='):
        out.append(f'{key} = {value}')
        changed = True
    else:
        out.append(line)
if not seen_section:
    out.extend(['', f'[{section}]', f'{key} = {value}'])
elif in_section and not changed:
    out.append(f'{key} = {value}')
path.write_text('\\n'.join(out) + '\\n', encoding='utf-8')
PY"
}

write_kvm_conf() {
  local path="$CAPE_DIR/conf/kvm.conf"
  backup_file "$path"
  local machines=""
  local body=""
  local index
  for index in $(seq 1 "$WINSTDT_VM_COUNT"); do
    local name
    local ip
    name="$(vm_name_for_index "$index")"
    ip="$(guest_ip_for_index "$index")"
    if [ -z "$machines" ]; then
      machines="$name"
    else
      machines="${machines},${name}"
    fi
    body="${body}
[${name}]
label = ${name}
platform = windows
ip = ${ip}
tags = win10
snapshot = ${SNAPSHOT_NAME}
interface = ${BRIDGE_NAME}
resultserver_ip = ${HOST_IP}
arch = x64
reserved = no
"
  done
  run_root_shell "cat > '$path' <<'EOF'
[kvm]
machines = ${machines}
interface = ${BRIDGE_NAME}
dsn = ${LIBVIRT_URI}
${body}
EOF
chown '${CAPE_USER}:${CAPE_USER}' '$path'"
}

install_reporting_overlay() {
  run_root install -d -m 0755 -o "$CAPE_USER" -g "$CAPE_USER" "$WINSTDT_ROOT/handoff"
  run_root install -d -m 0755 "$CAPE_DIR/winstdt"
  run_root install -m 0644 "$PROJECT_ROOT/winstdt/__init__.py" "$CAPE_DIR/winstdt/__init__.py"
  run_root install -m 0644 "$PROJECT_ROOT/winstdt/access_events.py" "$CAPE_DIR/winstdt/access_events.py"
  run_root install -m 0644 "$PROJECT_ROOT/cape/modules/reporting/winstdt_handoff_export.py" "$CAPE_DIR/modules/reporting/winstdt_handoff_export.py"
  run_root install -d -m 0755 "$CAPE_DIR/analyzer/windows/modules/auxiliary"
  run_root install -m 0644 "$PROJECT_ROOT/cape/analyzer/windows/modules/auxiliary/winstdt_etw_pickup.py" "$CAPE_DIR/analyzer/windows/modules/auxiliary/winstdt_etw_pickup.py"
  run_root install -d -m 0755 "$CAPE_DIR/custom/conf/reporting.conf.d"
  run_root install -m 0644 "$PROJECT_ROOT/cape/custom/conf/reporting.conf.d/winstdt_handoff_export.conf" "$CAPE_DIR/custom/conf/reporting.conf.d/winstdt_handoff_export.conf"
  run_root_shell "python3 - <<'PY'
from pathlib import Path
base = Path('$CAPE_DIR/conf/reporting.conf')
overlay = Path('$PROJECT_ROOT/cape/custom/conf/reporting.conf.d/winstdt_handoff_export.conf').read_text(encoding='utf-8').strip()
text = base.read_text(encoding='utf-8')
section = '[winstdt_handoff_export]'
lines = text.splitlines()
out = []
skip = False
for line in lines:
    stripped = line.strip()
    if stripped.startswith('[') and stripped.endswith(']'):
        skip = stripped == section
        if skip:
            continue
    if not skip:
        out.append(line)
base.write_text('\\n'.join(out).rstrip() + '\\n\\n' + overlay + '\\n', encoding='utf-8')
PY
chown '${CAPE_USER}:${CAPE_USER}' '$CAPE_DIR/conf/reporting.conf'"
}

repair_python_libvirt() {
  local py_site="/usr/local/lib/python3.12/dist-packages"
  local backup
  backup="/usr/local/lib/python3.12/winstdt-disabled-libvirt-$(date -u +%Y%m%dT%H%M%SZ)"
  run_root_shell "if compgen -G '${py_site}/libvirt*' >/dev/null || compgen -G '${py_site}/cygvirt*' >/dev/null; then
  install -d -m 0755 '${backup}'
  mv '${py_site}'/libvirt* '${backup}'/ 2>/dev/null || true
  mv '${py_site}'/cygvirt* '${backup}'/ 2>/dev/null || true
fi"
  local libvirt_version
  libvirt_version="$(dpkg-query -W -f='${Version}' python3-libvirt 2>/dev/null | sed 's/-.*//')"
  if [ -z "$libvirt_version" ]; then
    echo "python3-libvirt is not installed; rerun scripts/setup-ubuntu24-host.sh --execute first" >&2
    exit 1
  fi
  run_cape_shell "cd '$CAPE_DIR' && /etc/poetry/bin/poetry run pip uninstall -y libvirt-python >/dev/null 2>&1 || true"
  run_cape_shell "cd '$CAPE_DIR' && PKG_CONFIG_PATH='${SYSTEM_PKG_CONFIG_PATH}' /etc/poetry/bin/poetry run pip install --no-binary libvirt-python 'libvirt-python==${libvirt_version}'"
}

configure_live_cape_files() {
  write_kvm_conf
  backup_file "$CAPE_DIR/conf/cuckoo.conf"
  backup_file "$CAPE_DIR/conf/auxiliary.conf"
  backup_file "$CAPE_DIR/conf/routing.conf"
  set_ini_value "$CAPE_DIR/conf/cuckoo.conf" resultserver ip "$HOST_IP"
  set_ini_value "$CAPE_DIR/conf/auxiliary.conf" sniffer interface "$BRIDGE_NAME"
  set_ini_value "$CAPE_DIR/conf/auxiliary.conf" auxiliary_modules winstdt_etw_pickup yes
  set_ini_value "$CAPE_DIR/conf/routing.conf" inetsim enabled yes
  set_ini_value "$CAPE_DIR/conf/routing.conf" inetsim server "$HOST_IP"
  set_ini_value "$CAPE_DIR/conf/routing.conf" inetsim interface "$BRIDGE_NAME"
  install_reporting_overlay
}

create_domain_and_snapshot() {
  if [ "$SKIP_DOMAIN" -eq 1 ]; then
    log "domain/snapshot creation skipped by flag"
    return
  fi
  local source_image="$VMCLOAK_IMAGE_PATH"
  if [ "$WINSTDT_VM_COUNT" -gt 1 ] && [ ! -f "$source_image" ]; then
    source_image="${HOME}/.vmcloak/image/${VM_NAME}.qcow2"
  fi
  if [ ! -f "$source_image" ]; then
    echo "VMCloak image not found: $source_image" >&2
    exit 1
  fi
  run_root install -d -m 0755 -o libvirt-qemu -g kvm "$LIBVIRT_IMAGE_DIR" "$SNAPSHOT_DIR"
  local index
  for index in $(seq 1 "$WINSTDT_VM_COUNT"); do
    local name
    name="$(vm_name_for_index "$index")"
    local ip
    ip="$(guest_ip_for_index "$index")"
    local golden="${LIBVIRT_IMAGE_DIR}/${name}-golden.qcow2"
    local clone="${LIBVIRT_IMAGE_DIR}/${name}.qcow2"
    run_root_shell "if [ ! -f '$golden' ]; then
  install -m 0644 '$source_image' '$golden'
  chown libvirt-qemu:kvm '$golden'
fi"
    run_root_shell "ensure_size() {
  image=\"\$1\"
  min_gb=\"\$2\"
  current_bytes=\$(qemu-img info --output=json \"\$image\" | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"virtual-size\"])')
  required_bytes=\$((min_gb * 1024 * 1024 * 1024))
  if [ \"\$current_bytes\" -lt \"\$required_bytes\" ]; then
    qemu-img resize \"\$image\" \"\${min_gb}G\"
  fi
}
ensure_size '$golden' '$VM_DISK_GB'"
    run_root_shell "if ! env LD_LIBRARY_PATH='$SYSTEM_LIB_PATH' virsh -c '$LIBVIRT_URI' dominfo '$name' >/dev/null 2>&1; then
  if [ ! -f '$clone' ]; then
    qemu-img convert -O qcow2 '$golden' '$clone'
    chown libvirt-qemu:kvm '$clone'
    chmod 0644 '$clone'
  fi
  current_bytes=\$(qemu-img info --output=json '$clone' | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"virtual-size\"])')
  required_bytes=\$(($VM_DISK_GB * 1024 * 1024 * 1024))
  if [ \"\$current_bytes\" -lt \"\$required_bytes\" ]; then
    qemu-img resize '$clone' '${VM_DISK_GB}G'
  fi
  virt-install --connect '$LIBVIRT_URI' \
    --name '$name' \
    --vcpus '$VM_CPUS' \
    --memory '$VM_RAM_MB' \
    --disk path='$clone',format=qcow2,bus=sata \
    --os-variant win10 \
    --network network='$NETWORK_NAME',model=e1000e \
    --graphics vnc,listen=127.0.0.1 \
    --import \
    --noautoconsole
fi"
    harden_libvirt_domain_definition "$name"
    ensure_dhcp_reservation "$name" "$ip"
    if env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" domstate "$name" | grep -q running; then
      log "persistent XML for $name is hardened; shut down/start the guest and recreate $SNAPSHOT_NAME before final anti-evasion acceptance"
    fi
    run_root_shell "env LD_LIBRARY_PATH='$SYSTEM_LIB_PATH' virsh -c '$LIBVIRT_URI' domstate '$name' | grep -q running || env LD_LIBRARY_PATH='$SYSTEM_LIB_PATH' virsh -c '$LIBVIRT_URI' start '$name'"
    local snapshot_mem="${SNAPSHOT_DIR}/${name}-${SNAPSHOT_NAME}.mem"
    local snapshot_disk="${SNAPSHOT_DIR}/${name}-${SNAPSHOT_NAME}.qcow2"
    run_root_shell "snapshot_state=\$(env LD_LIBRARY_PATH='$SYSTEM_LIB_PATH' virsh -c '$LIBVIRT_URI' snapshot-info '$name' '$SNAPSHOT_NAME' 2>/dev/null | awk -F: '\$1 == \"State\" { gsub(/^[ \t]+|[ \t]+$/, \"\", \$2); print \$2 }' || true)
if [ \"\$snapshot_state\" != \"running\" ]; then
  if [ -n \"\$snapshot_state\" ]; then
    env LD_LIBRARY_PATH='$SYSTEM_LIB_PATH' virsh -c '$LIBVIRT_URI' snapshot-delete '$name' '$SNAPSHOT_NAME' --metadata || env LD_LIBRARY_PATH='$SYSTEM_LIB_PATH' virsh -c '$LIBVIRT_URI' snapshot-delete '$name' '$SNAPSHOT_NAME'
  fi
  ts=\$(date -u +%Y%m%dT%H%M%SZ)
  [ -e '$snapshot_mem' ] && mv '$snapshot_mem' '$snapshot_mem'.bak.\$ts
  [ -e '$snapshot_disk' ] && mv '$snapshot_disk' '$snapshot_disk'.bak.\$ts
  env LD_LIBRARY_PATH='$SYSTEM_LIB_PATH' virsh -c '$LIBVIRT_URI' domstate '$name' | grep -q running || env LD_LIBRARY_PATH='$SYSTEM_LIB_PATH' virsh -c '$LIBVIRT_URI' start '$name'
  env LD_LIBRARY_PATH='$SYSTEM_LIB_PATH' virsh -c '$LIBVIRT_URI' snapshot-create-as '$name' '$SNAPSHOT_NAME' --description 'WinST/DT hardened baseline running full-system snapshot' --live --atomic --memspec '$snapshot_mem',snapshot=external --diskspec sda,file='$snapshot_disk',snapshot=external
fi"
  done
}

restart_runtime_services() {
  if [ "$SKIP_SERVICE_RESTART" -eq 1 ]; then
    log "service restart skipped by flag"
    return
  fi
  run_root install -d -m 0755 /data/db /data/configdb
  run_root_shell "id mongodb >/dev/null 2>&1 && chown -R mongodb:mongodb /data || true"
  ensure_mongodb_local_bind
  run_root systemctl reset-failed mongodb.service mongod.service cape.service cape-processor.service
  run_root_shell "systemctl start mongodb.service 2>/dev/null || systemctl start mongod.service"
  run_root systemctl restart cape-rooter.service
  run_root systemctl restart cape.service cape-processor.service
}

wait_active_service() {
  local service="$1"
  local attempts="${2:-30}"
  local index
  for index in $(seq 1 "$attempts"); do
    if systemctl is-active --quiet "$service"; then
      sleep 2
      systemctl is-active --quiet "$service" && return 0
    fi
    sleep 2
  done
  systemctl status "$service" --no-pager -l || true
  return 1
}

postcheck() {
  log "postcheck: CAPE_DIR=$CAPE_DIR"
  test -d "$CAPE_DIR" || { echo "missing CAPE_DIR: $CAPE_DIR" >&2; exit 1; }
  test -f "$CAPE_DIR/conf/kvm.conf" || { echo "missing $CAPE_DIR/conf/kvm.conf" >&2; exit 1; }
  test -f "$CAPE_DIR/modules/reporting/winstdt_handoff_export.py" || { echo "missing WinST/DT reporting module in CAPE" >&2; exit 1; }
  test -f "$CAPE_DIR/analyzer/windows/modules/auxiliary/winstdt_etw_pickup.py" || { echo "missing WinST/DT ETW pickup analyzer module in CAPE" >&2; exit 1; }
  awk '
    /^\[auxiliary_modules\]/ { in_section = 1; next }
    /^\[/ { in_section = 0 }
    in_section && $1 == "winstdt_etw_pickup" && $3 == "yes" { found = 1 }
    END { exit found ? 0 : 1 }
  ' "$CAPE_DIR/conf/auxiliary.conf" || { echo "WinST/DT ETW pickup auxiliary module is not enabled" >&2; exit 1; }
  env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" net-info "$NETWORK_NAME" | awk '$1 == "Active:" && $2 == "yes" { found = 1 } END { exit found ? 0 : 1 }'
  if [ "$SKIP_DOMAIN" -eq 0 ]; then
    for index in $(seq 1 "$WINSTDT_VM_COUNT"); do
      name="$(vm_name_for_index "$index")"
      env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" dominfo "$name" >/dev/null
      env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" dumpxml --inactive "$name" | awk '
        /<sysinfo type=.smbios./ { sysinfo = 1 }
        /<smbios mode=.sysinfo./ { smbios = 1 }
        /<hidden state=.on./ { kvm_hidden = 1 }
        /<vendor_id state=.on./ { vendor_id = 1 }
        /<topology / && /cores=./ { topology = 1 }
        /x-oem-id=/ && /x-oem-table-id=/ { acpi_oem = 1 }
        /<serial>/ { disk_serial = 1 }
        /ua-winst-disk1/ { disk_alias = 1 }
        /<qemu:property name=.model./ && /WDC WD5000LPCX-75VHAT0/ { disk_model = 1 }
        /<memballoon model=.none./ { no_balloon = 1 }
        END { exit (sysinfo && smbios && kvm_hidden && vendor_id && topology && acpi_oem && disk_serial && disk_alias && disk_model && no_balloon) ? 0 : 1 }
      ' || {
        echo "libvirt domain is missing WinST/DT hardened SMBIOS/KVM/disk markers: $name" >&2
        exit 1
      }
      env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" snapshot-info "$name" "$SNAPSHOT_NAME" >/dev/null
      env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" snapshot-info "$name" "$SNAPSHOT_NAME" | awk '$1 == "State:" && $2 == "running" { found = 1 } END { exit found ? 0 : 1 }'
    done
  fi
  python3 - <<'PY'
import libvirt
print("system python libvirt import ok")
PY
  if [ "$EXECUTE" -eq 1 ]; then
    sudo -u "$CAPE_USER" bash -lc "cd '$CAPE_DIR' && /etc/poetry/bin/poetry run python - <<'PY'
import libvirt
print('CAPE poetry libvirt import ok')
PY"
  fi
  wait_active_service mongodb.service 15 || wait_active_service mongod.service 15 || {
    echo "MongoDB service is not active" >&2
    exit 1
  }
  if command -v ss >/dev/null 2>&1; then
    ss -ltnp 2>/dev/null | awk '
      /:27017/ {
        if ($4 != "127.0.0.1:27017" && $4 != "[::1]:27017") {
          print "MongoDB is exposed beyond localhost: " $4 > "/dev/stderr"
          exposed = 1
        }
        seen = 1
      }
      END {
        if (!seen) {
          print "MongoDB is not listening on 27017" > "/dev/stderr"
          exit 1
        }
        exit exposed ? 1 : 0
      }'
  fi
  if command -v apt-mark >/dev/null 2>&1 && kernel_requires_mongodb_compat; then
    for package in "${MONGODB_HELD_PACKAGES[@]}"; do
      apt-mark showhold | grep -qx "$package" || {
        echo "MongoDB compatibility package is not held: $package" >&2
        exit 1
      }
    done
  fi
  wait_active_service cape.service 30 || { echo "cape.service is not active" >&2; exit 1; }
  wait_active_service cape-processor.service 30 || { echo "cape-processor.service is not active" >&2; exit 1; }
  log "postcheck passed"
}

require_execute_sudo
validate_gates
verify_cape_revision
log "runtime closure script $SCRIPT_VERSION"
ensure_runtime_packages
ensure_mongodb_kernel_compat
ensure_mongodb_local_bind
repair_python_libvirt
configure_live_cape_files
create_domain_and_snapshot
restart_runtime_services
postcheck
