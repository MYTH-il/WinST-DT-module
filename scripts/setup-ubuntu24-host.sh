#!/usr/bin/env bash
set -uo pipefail

EXECUTE=0
RUN_CAPE_INSTALLERS=1
RERUN_CAPE_INSTALLERS=0
BUILD_GUEST=0
WINDOWS_ISO=""
FAIL_PHASE="${WINSTDT_DASHBOARD_FAIL_PHASE:-}"
SETUP_SCRIPT_VERSION="v0.22"

CAPE_REPO_URL="${CAPE_REPO_URL:-https://github.com/kevoreilly/CAPEv2.git}"
CAPE_DIR="${CAPE_DIR:-/opt/CAPEv2}"
CAPE_USER="${CAPE_USER:-cape}"
WINSTDT_ROOT="${WINSTDT_ROOT:-/srv/winstdt}"
NETWORK_NAME="${NETWORK_NAME:-winstdt-isolated}"
BRIDGE_NAME="${BRIDGE_NAME:-virbr-winstdt}"
HOST_IP="${HOST_IP:-10.66.0.1}"
NETMASK="${NETMASK:-255.255.255.0}"
DHCP_START="${DHCP_START:-10.66.0.100}"
DHCP_END="${DHCP_END:-10.66.0.200}"
GUEST_NETWORK_CIDR="${GUEST_NETWORK_CIDR:-10.66.0.0/24}"
GUEST_IP="${GUEST_IP:-10.66.0.101}"
WINDOWS_ISO_MOUNT="${WINDOWS_ISO_MOUNT:-/mnt/winstdt-win10-iso}"
VM_NAME="${VM_NAME:-winstdt-win10-22h2}"
VM_CPUS="${VM_CPUS:-4}"
VM_RAM_MB="${VM_RAM_MB:-8192}"
VM_DISK_GB="${VM_DISK_GB:-80}"
VMCLOAK_BASELINE_DEPS="${VMCLOAK_BASELINE_DEPS:-}"
VMCLOAK_REPO_URL="${VMCLOAK_REPO_URL:-https://github.com/cert-ee/vmcloak.git}"
VMCLOAK_DIR="${VMCLOAK_DIR:-$WINSTDT_ROOT/tools/vmcloak}"
SYSTEM_LIB_PATH="/usr/lib/x86_64-linux-gnu"
LOCAL_LIB_PATH="/usr/local/lib/x86_64-linux-gnu"
LIBVIRT_URI="${LIBVIRT_URI:-qemu+unix:///system?socket=/run/libvirt/libvirt-sock}"
COMMAND_TIMEOUT_SECONDS="${COMMAND_TIMEOUT_SECONDS:-7200}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="$WINSTDT_ROOT/setup-state"
LOG_ROOT="${LOG_ROOT:-$WINSTDT_ROOT/logs/setup}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="$LOG_ROOT/$RUN_ID"
ERROR_LOG="$LOG_DIR/errors.log"

PHASE_KEYS=(
  ubuntu
  apt
  rust
  layout
  network
  cape
  vmcloak
  build
  overlay
  guest
)

PHASE_NAMES=(
  "Ubuntu 24.04 preflight"
  "APT packages"
  "Rust toolchain"
  "Users and directories"
  "Libvirt isolated network"
  "CAPEv2 rolling release"
  "VMCloak"
  "WinST/DT binaries"
  "CAPE reporting overlay"
  "Windows guest build"
)

declare -A STATUS
declare -A DETAIL
declare -A PHASE_LOG

for key in "${PHASE_KEYS[@]}"; do
  STATUS["$key"]="pending"
  DETAIL["$key"]=""
  PHASE_LOG["$key"]=""
done

usage() {
  cat <<'EOF'
Usage: scripts/setup-ubuntu24-host.sh [--execute] [options]

Stable dashboard setup runner for a fresh/resumable Ubuntu 24.04 WinST/DT host.
It keeps one checklist on screen and writes stdout/stderr for every phase to:

  /srv/winstdt/logs/setup/<run-id>/

Options:
  --execute                 Actually run system-changing commands.
  --skip-cape-installers    Clone/update CAPE but do not run kvm-qemu.sh/cape2.sh.
  --rerun-cape-installers   Ignore CAPE installer marker files and rerun them.
  --windows-iso PATH        Licensed Windows 10 22H2 x64 ISO for VMCloak.
  --log-dir PATH            Override log directory for this run.
  --fail-phase KEY          Test-only: force one phase to fail after opening its log.
  -h, --help                Show this help.

Environment overrides:
  CAPE_REPO_URL             default: https://github.com/kevoreilly/CAPEv2.git
  CAPE_DIR                  default: /opt/CAPEv2
  CAPE_USER                 default: cape
  WINSTDT_ROOT              default: /srv/winstdt
  NETWORK_NAME              default: winstdt-isolated
  BRIDGE_NAME               default: virbr-winstdt
  GUEST_NETWORK_CIDR        default: 10.66.0.0/24
  VM_NAME                   default: winstdt-win10-22h2
  LOG_ROOT                  default: /srv/winstdt/logs/setup
  VMCLOAK_REPO_URL          default: https://github.com/cert-ee/vmcloak.git
  VMCLOAK_DIR               default: /srv/winstdt/tools/vmcloak
  COMMAND_TIMEOUT_SECONDS   default: 7200
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --execute) EXECUTE=1 ;;
    --skip-cape-installers) RUN_CAPE_INSTALLERS=0 ;;
    --rerun-cape-installers) RERUN_CAPE_INSTALLERS=1 ;;
    --windows-iso)
      WINDOWS_ISO="${2:-}"
      BUILD_GUEST=1
      shift
      ;;
    --log-dir)
      LOG_DIR="${2:-}"
      ERROR_LOG="$LOG_DIR/errors.log"
      shift
      ;;
    --fail-phase)
      FAIL_PHASE="${2:-}"
      shift
      ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

ensure_log_dir() {
  if [ "$EXECUTE" -eq 1 ]; then
    # Validate non-interactive command execution directly. `sudo -n -v` may
    # still request authentication for a timestamp refresh even when the user
    # has a matching NOPASSWD rule, producing a false negative.
    if ! sudo -n true 2>/dev/null; then
      printf 'sudo credentials are required before setup can run unattended.\n' >&2
      printf 'Run this in your terminal first, then rerun setup:\n\n' >&2
      printf '  sudo -v\n\n' >&2
      exit 1
    fi
    mkdir -p "$LOG_DIR" 2>/dev/null || sudo mkdir -p "$LOG_DIR"
    touch "$ERROR_LOG" 2>/dev/null || sudo touch "$ERROR_LOG"
    sudo chown -R "$USER:$USER" "$LOG_DIR" 2>/dev/null || true
  else
    if ! mkdir -p "$LOG_DIR" 2>/dev/null; then
      LOG_DIR="/tmp/winstdt-setup-$RUN_ID"
      ERROR_LOG="$LOG_DIR/errors.log"
      mkdir -p "$LOG_DIR"
    fi
    : >"$ERROR_LOG"
  fi
}

status_icon() {
  case "$1" in
    done) printf '[✓]' ;;
    working) printf '[~]' ;;
    skipped) printf '[-]' ;;
    failed) printf '[!]' ;;
    pending) printf '[ ]' ;;
    *) printf '[?]' ;;
  esac
}

redraw() {
  local index key icon
  tput civis 2>/dev/null || true
  tput clear 2>/dev/null || printf '\033[2J'
  printf 'WinST/DT Ubuntu 24.04 Setup Dashboard\n'
  printf '=====================================\n'
  printf 'Setup script: %s\n' "$SETUP_SCRIPT_VERSION"
  printf 'Mode: %s\n' "$([ "$EXECUTE" -eq 1 ] && printf execute || printf dry-run)"
  printf 'Logs: %s\n' "$LOG_DIR"
  printf 'Errors: %s\n\n' "$ERROR_LOG"

  for index in "${!PHASE_KEYS[@]}"; do
    key="${PHASE_KEYS[$index]}"
    icon="$(status_icon "${STATUS[$key]}")"
    printf '%s %-28s %s\n' "$icon" "${PHASE_NAMES[$index]}" "${DETAIL[$key]}"
    if [ -n "${PHASE_LOG[$key]}" ]; then
      printf '    log: %s\n' "${PHASE_LOG[$key]}"
    fi
    if [ "${STATUS[$key]}" = "failed" ]; then
      printf '    failed component: %s\n' "${PHASE_NAMES[$index]}"
      printf '    check this log: %s\n' "${PHASE_LOG[$key]}"
      printf '    aggregate errors: %s\n' "$ERROR_LOG"
    fi
  done

  printf '\nLegend: [ ] pending  [~] working  [✓] done  [-] skipped  [!] failed\n'
  printf 'Installer output is kept out of this screen. Tail logs from another terminal if needed.\n'
}

finish_screen() {
  redraw
  tput cnorm 2>/dev/null || true
}

trap finish_screen EXIT

log_for_phase() {
  local key="$1"
  printf '%s/%s-%s.log' "$LOG_DIR" "$(phase_number "$key")" "$key"
}

phase_number() {
  local needle="$1"
  local index
  for index in "${!PHASE_KEYS[@]}"; do
    if [ "${PHASE_KEYS[$index]}" = "$needle" ]; then
      printf '%02d' "$((index + 1))"
      return
    fi
  done
  printf '99'
}

run_logged() {
  local key="$1"
  shift
  local log="${PHASE_LOG[$key]}"
  printf '+ ' >>"$log"
  printf '%q ' "$@" >>"$log"
  printf '\n' >>"$log"
  if [ "$EXECUTE" -eq 0 ]; then
    return 0
  fi
  timeout --foreground "$COMMAND_TIMEOUT_SECONDS" "$@" >>"$log" 2>&1
  local rc=$?
  if [ "$rc" -eq 124 ]; then
    echo "command timed out after ${COMMAND_TIMEOUT_SECONDS}s" >>"$log"
  fi
  return "$rc"
}

run_shell_logged() {
  local key="$1"
  local command="$2"
  local log="${PHASE_LOG[$key]}"
  printf '+ bash -lc %q\n' "$command" >>"$log"
  if [ "$EXECUTE" -eq 0 ]; then
    return 0
  fi
  timeout --foreground "$COMMAND_TIMEOUT_SECONDS" bash -lc "$command" >>"$log" 2>&1
  local rc=$?
  if [ "$rc" -eq 124 ]; then
    echo "command timed out after ${COMMAND_TIMEOUT_SECONDS}s" >>"$log"
  fi
  return "$rc"
}

run_root_logged() {
  local key="$1"
  shift
  local log="${PHASE_LOG[$key]}"
  printf '+ sudo ' >>"$log"
  printf '%q ' "$@" >>"$log"
  printf '\n' >>"$log"
  if [ "$EXECUTE" -eq 0 ]; then
    return 0
  fi
  timeout --foreground "$COMMAND_TIMEOUT_SECONDS" sudo "$@" >>"$log" 2>&1
  local rc=$?
  if [ "$rc" -eq 124 ]; then
    echo "command timed out after ${COMMAND_TIMEOUT_SECONDS}s" >>"$log"
  fi
  return "$rc"
}

run_root_shell_logged() {
  local key="$1"
  local command="$2"
  local log="${PHASE_LOG[$key]}"
  printf '+ sudo bash -lc %q\n' "$command" >>"$log"
  if [ "$EXECUTE" -eq 0 ]; then
    return 0
  fi
  timeout --foreground "$COMMAND_TIMEOUT_SECONDS" sudo bash -lc "$command" >>"$log" 2>&1
  local rc=$?
  if [ "$rc" -eq 124 ]; then
    echo "command timed out after ${COMMAND_TIMEOUT_SECONDS}s" >>"$log"
  fi
  return "$rc"
}

append_error_log() {
  local key="$1"
  local log="${PHASE_LOG[$key]}"
  {
    printf '\n===== %s failed: %s =====\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$key"
    printf 'phase log: %s\n' "$log"
    tail -n 80 "$log" 2>/dev/null || true
  } >>"$ERROR_LOG"
}

run_phase() {
  local key="$1"
  local function_name="$2"
  PHASE_LOG["$key"]="$(log_for_phase "$key")"
  : >"${PHASE_LOG[$key]}"
  STATUS["$key"]="working"
  DETAIL["$key"]="running"
  redraw
  if [ "$FAIL_PHASE" = "$key" ]; then
    echo "Forced failure for dashboard smoke test." >>"${PHASE_LOG[$key]}"
    STATUS["$key"]="failed"
    DETAIL["$key"]="FAILED - check ${PHASE_LOG[$key]}"
    append_error_log "$key"
    redraw
    return 0
  fi
  if "$function_name" "$key"; then
    if [ "${STATUS[$key]}" = "working" ]; then
      STATUS["$key"]="done"
      DETAIL["$key"]="complete"
    fi
  else
    STATUS["$key"]="failed"
    DETAIL["$key"]="FAILED - check ${PHASE_LOG[$key]}"
    append_error_log "$key"
  fi
  redraw
}

package_installed() {
  dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'
}

package_version() {
  dpkg-query -W -f='${Version}' "$1" 2>/dev/null || true
}

vmcloak_image_exists() {
  command -v vmcloak >/dev/null 2>&1 && vmcloak list images 2>/dev/null | grep -qE "(^|[[:space:]])${VM_NAME}([[:space:]]|\\|)"
}

quarantine_if_unowned() {
  local key="$1"
  local backup_dir="$2"
  local path="$3"
  if [ ! -e "$path" ]; then
    return 0
  fi
  if dpkg -S "$path" >/dev/null 2>&1; then
    echo "keep packaged file: $path" >>"${PHASE_LOG[$key]}"
    return 0
  fi
  run_root_logged "$key" install -d -m 0755 "$backup_dir" || return 1
  echo "quarantine unowned libvirt source-install file: $path -> $backup_dir" >>"${PHASE_LOG[$key]}"
  run_root_logged "$key" mv "$path" "$backup_dir/"
}

marker_path() {
  printf '%s/%s.done' "$STATE_DIR" "$1"
}

have_marker() {
  [ "$RERUN_CAPE_INSTALLERS" -eq 0 ] && [ -f "$(marker_path "$1")" ]
}

libvirt_network_active() {
  local info
  if ! command -v virsh >/dev/null 2>&1; then
    return 1
  fi
  if [ "$EXECUTE" -eq 1 ]; then
    info="$(sudo env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" net-info "$NETWORK_NAME" 2>/dev/null \
      || env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" net-info "$NETWORK_NAME" 2>/dev/null)" || return 1
  else
    info="$(env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" net-info "$NETWORK_NAME" 2>/dev/null)" || return 1
  fi
  printf '%s\n' "$info" | awk '$1 == "Active:" && $2 == "yes" { found = 1 } END { exit found ? 0 : 1 }'
}

libvirt_network_defined() {
  local info
  if ! command -v virsh >/dev/null 2>&1; then
    return 1
  fi
  if [ "$EXECUTE" -eq 1 ]; then
    info="$(sudo env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" net-info "$NETWORK_NAME" 2>/dev/null \
      || env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" net-info "$NETWORK_NAME" 2>/dev/null)" || return 1
  else
    info="$(env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" net-info "$NETWORK_NAME" 2>/dev/null)" || return 1
  fi
  [ -n "$info" ]
}

configure_qemu_bridge_helper() {
  local key="$1"
  run_root_logged "$key" install -d -m 0755 /etc/qemu || return 1
  run_root_shell_logged "$key" "grep -qxF 'allow $BRIDGE_NAME' /etc/qemu/bridge.conf 2>/dev/null || printf '%s\n' 'allow $BRIDGE_NAME' >> /etc/qemu/bridge.conf" || return 1
  run_root_logged "$key" chmod 0644 /etc/qemu/bridge.conf || return 1
  if [ -x /usr/lib/qemu/qemu-bridge-helper ]; then
    run_root_logged "$key" chmod u+s /usr/lib/qemu/qemu-bridge-helper || return 1
  else
    echo "qemu-bridge-helper not found at /usr/lib/qemu/qemu-bridge-helper" >>"${PHASE_LOG[$key]}"
    return 1
  fi
}

patch_vmcloak_large_wim_iso() {
  local key="$1"
  local target
  for target in \
    "$VMCLOAK_DIR/vmcloak/abstract.py" \
    "$VMCLOAK_DIR/venv/lib/python3.12/site-packages/vmcloak/abstract.py"; do
    if [ -f "$target" ]; then
      run_root_shell_logged "$key" "grep -q -- '-allow-limited-size' \"$target\" || sed -i '/\"-no-emul-boot\",/a\\        \"-allow-limited-size\",' \"$target\"" || return 1
    fi
  done
}

patch_vmcloak_win10_22h2_unattend() {
  local key="$1"
  local target
  for target in \
    "$VMCLOAK_DIR/vmcloak/data/win10/autounattend.xml" \
    "$VMCLOAK_DIR/venv/lib/python3.12/site-packages/vmcloak/data/win10/autounattend.xml"; do
    if [ -f "$target" ]; then
      run_root_shell_logged "$key" "sed -i '/<ShowWindowsLive>false<\\/ShowWindowsLive>/d' \"$target\"" || return 1
      run_root_shell_logged "$key" "sed -i '/<component name=\"Security-Malware-Windows-Defender\"/,/<\\/component>/d' \"$target\"" || return 1
    fi
  done
}

cape_already_setup() {
  [ "$RERUN_CAPE_INSTALLERS" -eq 0 ] \
    && [ -d "$CAPE_DIR/.git" ] \
    && [ -x "$CAPE_DIR/installer/kvm-qemu.sh" ] \
    && [ -x "$CAPE_DIR/installer/cape2.sh" ] \
    && [ -f "$(marker_path kvm-qemu)" ] \
    && [ -f "$(marker_path cape2-base)" ]
}

write_marker() {
  local key="$1"
  local marker="$2"
  run_root_logged "$key" install -d -m 0755 "$STATE_DIR" || return 1
  run_root_shell_logged "$key" "date -u +%Y-%m-%dT%H:%M:%SZ > \"$(marker_path "$marker")\""
}

phase_ubuntu() {
  local key="$1"
  if [ ! -r /etc/os-release ]; then
    echo "Cannot read /etc/os-release." >>"${PHASE_LOG[$key]}"
    return 1
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  echo "Detected: ${NAME:-unknown} ${VERSION_ID:-unknown}" >>"${PHASE_LOG[$key]}"
  if [ "${ID:-}" != "ubuntu" ] || [ "${VERSION_ID:-}" != "24.04" ]; then
    echo "Expected Ubuntu 24.04." >>"${PHASE_LOG[$key]}"
    return 1
  fi
  DETAIL["$key"]="${NAME:-Ubuntu} ${VERSION_ID:-24.04}"
}

phase_apt() {
  local key="$1"
  local apt_env=(env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a APT_LISTCHANGES_FRONTEND=none UCF_FORCE_CONFFOLD=1)
  local apt_dpkg_opts=(-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
  local qemu_version
  local packages=(
    apparmor apparmor-utils bridge-utils build-essential ca-certificates clamav clamav-daemon
    curl dnsmasq-base genisoimage git gnupg inetsim jq libvirt-clients libvirt-daemon-system
    mingw-w64 pkg-config python3 python3-full python3-pip python3-venv
    rsync tshark virtinst virt-manager wget whiptail wireshark-common yara
  )
  local missing=()
  local package

  qemu_version="$(package_version qemu)"
  if [ -n "$qemu_version" ]; then
    echo "foreign qemu package detected: qemu $qemu_version" >>"${PHASE_LOG[$key]}"
    echo "removing qemu package so Ubuntu qemu-system/qemu-utils packages can own their files" >>"${PHASE_LOG[$key]}"
    run_root_logged "$key" apt-mark unhold qemu || true
    run_root_logged "$key" "${apt_env[@]}" apt-get "${apt_dpkg_opts[@]}" purge -y qemu \
      || run_root_logged "$key" dpkg --remove qemu \
      || return 1
  fi

  if ls "$LOCAL_LIB_PATH"/libvirt* >/dev/null 2>&1; then
    local backup_dir="$LOCAL_LIB_PATH/winstdt-disabled-libvirt-$RUN_ID"
    echo "local libvirt libraries shadow Ubuntu libvirt; moving them to $backup_dir" >>"${PHASE_LOG[$key]}"
    run_root_logged "$key" install -d -m 0755 "$backup_dir" || return 1
    run_root_shell_logged "$key" "mv \"$LOCAL_LIB_PATH\"/libvirt* \"$backup_dir\"/" || return 1
    run_root_logged "$key" ldconfig || return 1
  fi

  local source_libvirt_backup="$WINSTDT_ROOT/setup-state/disabled-source-libvirt-$RUN_ID"
  local source_libvirt_path
  for source_libvirt_path in \
    /usr/sbin/virtqemud \
    /usr/sbin/virtnetworkd \
    /usr/sbin/virtproxyd \
    /usr/sbin/virtinterfaced \
    /usr/sbin/virtnodedevd \
    /usr/sbin/virtnwfilterd \
    /usr/sbin/virtsecretd \
    /usr/sbin/virtstoraged \
    /usr/sbin/virtchd \
    /usr/sbin/virtlxcd \
    /usr/sbin/virtvboxd \
    /usr/sbin/virtxend \
    /usr/libexec/libvirt_leaseshelper \
    /usr/libexec/libvirt_iohelper \
    /usr/libexec/libvirt_lxc \
    /usr/lib/systemd/system/virtqemud.service \
    /usr/lib/systemd/system/virtqemud.socket \
    /usr/lib/systemd/system/virtqemud-ro.socket \
    /usr/lib/systemd/system/virtqemud-admin.socket \
    /usr/lib/systemd/system/virtnetworkd.service \
    /usr/lib/systemd/system/virtnetworkd.socket \
    /usr/lib/systemd/system/virtnetworkd-ro.socket \
    /usr/lib/systemd/system/virtnetworkd-admin.socket \
    /usr/lib/systemd/system/virtproxyd.service \
    /usr/lib/systemd/system/virtproxyd.socket \
    /usr/lib/systemd/system/virtproxyd-ro.socket \
    /usr/lib/systemd/system/virtproxyd-admin.socket; do
    quarantine_if_unowned "$key" "$source_libvirt_backup" "$source_libvirt_path" || return 1
  done
  run_root_logged "$key" systemctl daemon-reload || true

  if command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "skip qemu-system-x86 package: qemu-system-x86_64 already present at $(command -v qemu-system-x86_64)" >>"${PHASE_LOG[$key]}"
  else
    packages+=(qemu-system-x86)
  fi

  if command -v qemu-img >/dev/null 2>&1; then
    echo "skip qemu-utils package: qemu-img already present at $(command -v qemu-img)" >>"${PHASE_LOG[$key]}"
  else
    packages+=(qemu-utils)
  fi

  for package in "${packages[@]}"; do
    if package_installed "$package"; then
      echo "skip installed package: $package" >>"${PHASE_LOG[$key]}"
    else
      missing+=("$package")
      echo "need package: $package" >>"${PHASE_LOG[$key]}"
    fi
  done
  if [ "${#missing[@]}" -eq 0 ]; then
    DETAIL["$key"]="repairing package state"
  else
    DETAIL["$key"]="installing ${#missing[@]} missing packages"
  fi
  redraw
  if command -v debconf-set-selections >/dev/null 2>&1; then
    run_root_shell_logged "$key" "printf '%s\n' 'wireshark-common wireshark-common/install-setuid boolean false' | debconf-set-selections" || return 1
  fi
  run_root_logged "$key" "${apt_env[@]}" dpkg --force-confdef --force-confold --configure -a \
    || echo "dpkg configuration is incomplete; continuing with apt --fix-broken recovery." >>"${PHASE_LOG[$key]}"
  run_root_logged "$key" "${apt_env[@]}" apt-get "${apt_dpkg_opts[@]}" --fix-broken install -y || return 1
  run_root_logged "$key" "${apt_env[@]}" dpkg --force-confdef --force-confold --configure -a || return 1
  run_root_logged "$key" "${apt_env[@]}" apt-get update || return 1
  if ! package_installed software-properties-common; then
    run_root_logged "$key" "${apt_env[@]}" apt-get "${apt_dpkg_opts[@]}" install -y software-properties-common || return 1
  fi
  run_root_logged "$key" add-apt-repository -y universe || true
  run_root_logged "$key" "${apt_env[@]}" apt-get update || return 1
  if [ "${#missing[@]}" -eq 0 ]; then
    STATUS["$key"]="skipped"
    DETAIL["$key"]="all packages already installed"
    return 0
  fi
  run_root_logged "$key" "${apt_env[@]}" apt-get "${apt_dpkg_opts[@]}" install -y "${missing[@]}"
}

phase_rust() {
  local key="$1"
  if command -v rustup >/dev/null 2>&1; then
    echo "rustup present: $(command -v rustup)" >>"${PHASE_LOG[$key]}"
  else
    DETAIL["$key"]="installing rustup"
    redraw
    run_shell_logged "$key" 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y' || return 1
  fi
  if command -v rustup >/dev/null 2>&1 && rustup target list --installed | grep -qx 'x86_64-pc-windows-gnu'; then
    STATUS["$key"]="skipped"
    DETAIL["$key"]="rustup and Windows target already installed"
    return 0
  fi
  DETAIL["$key"]="adding Windows Rust target"
  redraw
  run_shell_logged "$key" 'source "$HOME/.cargo/env" 2>/dev/null || true; rustup target add x86_64-pc-windows-gnu'
}

phase_layout() {
  local key="$1"
  if id "$CAPE_USER" >/dev/null 2>&1; then
    echo "user exists: $CAPE_USER" >>"${PHASE_LOG[$key]}"
  else
    run_root_logged "$key" useradd -r -m -G libvirt,kvm "$CAPE_USER" || return 1
  fi
  if id -nG "$USER" | tr ' ' '\n' | grep -qx libvirt && id -nG "$USER" | tr ' ' '\n' | grep -qx kvm; then
    echo "current user already in libvirt,kvm groups" >>"${PHASE_LOG[$key]}"
  else
    run_root_logged "$key" usermod -aG libvirt,kvm "$USER" || return 1
  fi
  local dirs=(
    "$WINSTDT_ROOT" "$WINSTDT_ROOT/bin" "$WINSTDT_ROOT/images/golden"
    "$WINSTDT_ROOT/images/clones" "$WINSTDT_ROOT/handoff"
    "$WINSTDT_ROOT/captures/tmp" "$WINSTDT_ROOT/rules/yara" "$STATE_DIR" "$LOG_ROOT"
  )
  local dir
  for dir in "${dirs[@]}"; do
    if [ -d "$dir" ]; then
      echo "directory exists: $dir" >>"${PHASE_LOG[$key]}"
    else
      run_root_logged "$key" install -d -m 0755 "$dir" || return 1
    fi
  done
  run_root_logged "$key" chown -R "$USER:$USER" "$WINSTDT_ROOT"
}

phase_network() {
  local key="$1"
  if libvirt_network_active; then
    echo "Network already defined and active: $NETWORK_NAME" >>"${PHASE_LOG[$key]}"
    configure_qemu_bridge_helper "$key" || return 1
    STATUS["$key"]="skipped"
    DETAIL["$key"]="network already defined and active"
    return 0
  fi
  if [ "$EXECUTE" -eq 1 ]; then
    run_root_logged "$key" systemctl reset-failed libvirtd.service virtlogd.service virtlockd.service virtnetworkd.service virtqemud.service || true
    run_root_logged "$key" systemctl start virtlogd.socket virtlogd.service || return 1
    run_root_logged "$key" systemctl start virtlockd.socket virtlockd.service || true
    run_root_logged "$key" systemctl start libvirtd.socket libvirtd-ro.socket libvirtd.service || return 1
  fi
  if libvirt_network_active; then
    echo "Network already defined and active: $NETWORK_NAME" >>"${PHASE_LOG[$key]}"
    configure_qemu_bridge_helper "$key" || return 1
    STATUS["$key"]="skipped"
    DETAIL["$key"]="network already defined and active"
    return 0
  fi

  local xml_path="/tmp/${NETWORK_NAME}.xml"
  cat >"$xml_path" <<EOF
<network>
  <name>${NETWORK_NAME}</name>
  <bridge name="${BRIDGE_NAME}" stp="on" delay="0"/>
  <ip address="${HOST_IP}" netmask="${NETMASK}">
    <dhcp>
      <range start="${DHCP_START}" end="${DHCP_END}"/>
    </dhcp>
  </ip>
</network>
EOF
  {
    echo "Generated libvirt network XML: $xml_path"
    sed 's/^/  /' "$xml_path"
  } >>"${PHASE_LOG[$key]}"

  if [ "$EXECUTE" -eq 0 ]; then
    run_root_logged "$key" env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" net-define "$xml_path" || return 1
    run_root_logged "$key" env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" net-autostart "$NETWORK_NAME" || return 1
    run_root_logged "$key" env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" net-start "$NETWORK_NAME" || return 1
    return 0
  fi

  if libvirt_network_defined; then
    echo "Network already exists: $NETWORK_NAME" >>"${PHASE_LOG[$key]}"
  else
    run_root_logged "$key" env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" net-define "$xml_path" || return 1
  fi

  if sudo env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" net-info "$NETWORK_NAME" 2>/dev/null | awk '$1 == "Autostart:" && $2 == "yes" { found = 1 } END { exit found ? 0 : 1 }'; then
    echo "Network already autostarts: $NETWORK_NAME" >>"${PHASE_LOG[$key]}"
  else
    run_root_logged "$key" env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" net-autostart "$NETWORK_NAME" || return 1
  fi

  if sudo env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" net-info "$NETWORK_NAME" 2>/dev/null | awk '$1 == "Active:" && $2 == "yes" { found = 1 } END { exit found ? 0 : 1 }'; then
    echo "Network already active: $NETWORK_NAME" >>"${PHASE_LOG[$key]}"
  else
    if ! run_root_logged "$key" env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" net-start "$NETWORK_NAME"; then
      if sudo env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" net-info "$NETWORK_NAME" 2>/dev/null | awk '$1 == "Active:" && $2 == "yes" { found = 1 } END { exit found ? 0 : 1 }'; then
        echo "Network became active during start attempt: $NETWORK_NAME" >>"${PHASE_LOG[$key]}"
      else
        return 1
      fi
    fi
  fi

  configure_qemu_bridge_helper "$key" || return 1
}

phase_cape() {
  local key="$1"
  if cape_already_setup; then
    echo "CAPEv2 checkout already present: $CAPE_DIR" >>"${PHASE_LOG[$key]}"
    echo "Installer marker present: $(marker_path kvm-qemu)" >>"${PHASE_LOG[$key]}"
    echo "Installer marker present: $(marker_path cape2-base)" >>"${PHASE_LOG[$key]}"
    if [ -r "$CAPE_DIR/.git/HEAD" ]; then
      git --git-dir="$CAPE_DIR/.git" --work-tree="$CAPE_DIR" rev-parse HEAD >>"${PHASE_LOG[$key]}" 2>&1 || true
    fi
    STATUS["$key"]="skipped"
    DETAIL["$key"]="CAPEv2 already set up"
    return 0
  fi

  if [ -d "$CAPE_DIR/.git" ]; then
    DETAIL["$key"]="updating CAPEv2 checkout"
    redraw
    run_root_logged "$key" chown -R "$CAPE_USER:$CAPE_USER" "$CAPE_DIR" || return 1
    run_root_logged "$key" -u "$CAPE_USER" git -C "$CAPE_DIR" pull --ff-only || return 1
  elif [ -e "$CAPE_DIR" ]; then
    echo "$CAPE_DIR exists but is not a git checkout." >>"${PHASE_LOG[$key]}"
    return 1
  else
    DETAIL["$key"]="cloning CAPEv2"
    redraw
    run_root_logged "$key" git clone "$CAPE_REPO_URL" "$CAPE_DIR" || return 1
  fi
  run_root_logged "$key" chown -R "$CAPE_USER:$CAPE_USER" "$CAPE_DIR" || return 1
  run_root_logged "$key" chmod a+x "$CAPE_DIR/installer/kvm-qemu.sh" "$CAPE_DIR/installer/cape2.sh" || return 1

  if [ "$RUN_CAPE_INSTALLERS" -eq 0 ]; then
    echo "CAPE installers skipped by flag." >>"${PHASE_LOG[$key]}"
  else
    if have_marker kvm-qemu; then
      echo "skip marked CAPE phase: kvm-qemu" >>"${PHASE_LOG[$key]}"
    else
      DETAIL["$key"]="running CAPE kvm-qemu.sh"
      redraw
      if run_root_shell_logged "$key" "\"$CAPE_DIR/installer/kvm-qemu.sh\" all \"$CAPE_USER\""; then
        write_marker "$key" kvm-qemu || return 1
      else
        echo "kvm-qemu.sh failed; continuing to summary." >>"${PHASE_LOG[$key]}"
        return 1
      fi
    fi
    if have_marker cape2-base; then
      echo "skip marked CAPE phase: cape2-base" >>"${PHASE_LOG[$key]}"
    else
      DETAIL["$key"]="running CAPE cape2.sh"
      redraw
      if run_root_shell_logged "$key" "\"$CAPE_DIR/installer/cape2.sh\" base \"$CAPE_USER\""; then
        write_marker "$key" cape2-base || return 1
      else
        echo "cape2.sh failed; continuing to summary." >>"${PHASE_LOG[$key]}"
        return 1
      fi
    fi
  fi
  run_root_shell_logged "$key" "sudo -u \"$CAPE_USER\" git -C \"$CAPE_DIR\" rev-parse HEAD > \"$CAPE_DIR/WINSTDT_CAPE_GIT_REF\""
}

phase_vmcloak() {
  local key="$1"
  if command -v vmcloak >/dev/null 2>&1; then
    if [ -x "$VMCLOAK_DIR/venv/bin/python" ]; then
      run_logged "$key" "$VMCLOAK_DIR/venv/bin/python" -c "import pkg_resources" \
        || run_logged "$key" "$VMCLOAK_DIR/venv/bin/python" -m pip install --force-reinstall "setuptools<81" \
        || return 1
      run_logged "$key" "$VMCLOAK_DIR/venv/bin/python" -c "import pkg_resources" \
        || return 1
    fi
    patch_vmcloak_large_wim_iso "$key" || return 1
    patch_vmcloak_win10_22h2_unattend "$key" || return 1
    STATUS["$key"]="skipped"
    DETAIL["$key"]="vmcloak already installed"
    return 0
  fi
  if [ -x "$VMCLOAK_DIR/venv/bin/vmcloak" ]; then
    run_root_logged "$key" ln -sf "$VMCLOAK_DIR/venv/bin/vmcloak" /usr/local/bin/vmcloak
    DETAIL["$key"]="linked existing VMCloak venv"
    return 0
  fi

  run_root_logged "$key" install -d -m 0755 "$(dirname "$VMCLOAK_DIR")" || return 1
  if [ -d "$VMCLOAK_DIR/.git" ]; then
    run_root_logged "$key" git -C "$VMCLOAK_DIR" pull --ff-only || return 1
  elif [ -e "$VMCLOAK_DIR" ]; then
    echo "$VMCLOAK_DIR exists but is not a git checkout." >>"${PHASE_LOG[$key]}"
    return 1
  else
    run_root_logged "$key" git clone "$VMCLOAK_REPO_URL" "$VMCLOAK_DIR" || return 1
  fi
  run_root_logged "$key" python3 -m venv "$VMCLOAK_DIR/venv" || return 1
  run_root_logged "$key" "$VMCLOAK_DIR/venv/bin/python" -m pip install --upgrade pip wheel || return 1
  run_root_logged "$key" "$VMCLOAK_DIR/venv/bin/python" -m pip install --force-reinstall "setuptools<81" || return 1
  run_root_logged "$key" "$VMCLOAK_DIR/venv/bin/python" -m pip install "$VMCLOAK_DIR" || return 1
  run_root_logged "$key" ln -sf "$VMCLOAK_DIR/venv/bin/vmcloak" /usr/local/bin/vmcloak
  patch_vmcloak_large_wim_iso "$key" || return 1
  patch_vmcloak_win10_22h2_unattend "$key"
}

phase_build() {
  local key="$1"
  run_shell_logged "$key" 'source "$HOME/.cargo/env" 2>/dev/null || true; cargo build --release' || return 1
  run_shell_logged "$key" 'source "$HOME/.cargo/env" 2>/dev/null || true; cargo build --release --target x86_64-pc-windows-gnu' || return 1
  run_root_logged "$key" install -m 0755 "$PROJECT_ROOT/target/release/WinST-DT-module" "$WINSTDT_ROOT/bin/winstdt" || return 1
  run_root_logged "$key" install -m 0755 "$PROJECT_ROOT/target/x86_64-pc-windows-gnu/release/WinST-DT-module.exe" "$WINSTDT_ROOT/bin/winstdt.exe" || return 1
  run_root_logged "$key" install -d -m 0755 "$WINSTDT_ROOT/scripts/etw_agent" || return 1
  run_root_logged "$key" install -m 0644 "$PROJECT_ROOT/scripts/etw_agent/etw-agent.config.json" "$WINSTDT_ROOT/scripts/etw_agent/etw-agent.config.json" || return 1
  run_root_logged "$key" install -m 0644 "$PROJECT_ROOT/scripts/etw_agent/Invoke-EtwAgentValidation.ps1" "$WINSTDT_ROOT/scripts/etw_agent/Invoke-EtwAgentValidation.ps1" || return 1
  run_root_logged "$key" install -d -m 0755 "$WINSTDT_ROOT/scripts/guest_hardening" || return 1
  run_root_logged "$key" install -m 0644 "$PROJECT_ROOT/scripts/guest_hardening/Invoke-GuestHardening.ps1" "$WINSTDT_ROOT/scripts/guest_hardening/Invoke-GuestHardening.ps1" || return 1
  run_root_logged "$key" install -m 0644 "$PROJECT_ROOT/scripts/guest_hardening/example.config.json" "$WINSTDT_ROOT/scripts/guest_hardening/example.config.json" || return 1
  run_root_logged "$key" install -d -m 0755 "$WINSTDT_ROOT/scripts/validation" || return 1
  run_root_logged "$key" install -m 0644 "$PROJECT_ROOT/scripts/validation/Invoke-BenignDetonation.ps1" "$WINSTDT_ROOT/scripts/validation/Invoke-BenignDetonation.ps1" || return 1
  run_root_logged "$key" install -m 0644 "$PROJECT_ROOT/scripts/validation/Invoke-AntiEvasionCollection.ps1" "$WINSTDT_ROOT/scripts/validation/Invoke-AntiEvasionCollection.ps1"
}

phase_overlay() {
  local key="$1"
  if [ "$EXECUTE" -eq 1 ] && [ ! -d "$CAPE_DIR/modules/reporting" ]; then
    echo "CAPE reporting directory not present: $CAPE_DIR/modules/reporting" >>"${PHASE_LOG[$key]}"
    return 1
  fi
  run_root_logged "$key" install -m 0644 "$PROJECT_ROOT/cape/modules/reporting/winstdt_handoff_export.py" "$CAPE_DIR/modules/reporting/winstdt_handoff_export.py" || return 1
  run_root_logged "$key" install -d -m 0755 "$CAPE_DIR/custom/conf/reporting.conf.d" || return 1
  run_root_logged "$key" install -m 0644 "$PROJECT_ROOT/cape/custom/conf/reporting.conf.d/winstdt_handoff_export.conf" "$CAPE_DIR/custom/conf/reporting.conf.d/winstdt_handoff_export.conf"
}

phase_guest() {
  local key="$1"
  local detected_iso="$PROJECT_ROOT/Win10_22H2_x64.iso"
  if [ "$BUILD_GUEST" -eq 0 ]; then
    STATUS["$key"]="skipped"
    DETAIL["$key"]="no --windows-iso supplied"
    return 0
  fi
  if [ ! -f "$WINDOWS_ISO" ]; then
    if [ -f "$detected_iso" ]; then
      echo "Provided Windows ISO path does not exist: $WINDOWS_ISO" >>"${PHASE_LOG[$key]}"
      echo "Using detected local ISO: $detected_iso" >>"${PHASE_LOG[$key]}"
      WINDOWS_ISO="$detected_iso"
    else
      echo "Windows ISO does not exist: $WINDOWS_ISO" >>"${PHASE_LOG[$key]}"
      echo "No fallback ISO found at: $detected_iso" >>"${PHASE_LOG[$key]}"
      return 1
    fi
  fi
  if ! command -v vmcloak >/dev/null 2>&1; then
    echo "vmcloak is not installed." >>"${PHASE_LOG[$key]}"
    return 1
  fi
  if vmcloak_image_exists; then
    echo "VMCloak image already exists: $VM_NAME" >>"${PHASE_LOG[$key]}"
  elif command -v virsh >/dev/null 2>&1 && env LD_LIBRARY_PATH="$SYSTEM_LIB_PATH" virsh -c "$LIBVIRT_URI" dominfo "$VM_NAME" >/dev/null 2>&1; then
    echo "Libvirt domain already exists: $VM_NAME" >>"${PHASE_LOG[$key]}"
  fi
  if [ -f "$HOME/.vmcloak/image/$VM_NAME.qcow2" ] && ! vmcloak_image_exists; then
    echo "removing stale VMCloak image file from previous failed init: $HOME/.vmcloak/image/$VM_NAME.qcow2" >>"${PHASE_LOG[$key]}"
    run_logged "$key" rm -f "$HOME/.vmcloak/image/$VM_NAME.qcow2" || return 1
  fi
  if [ -f "$HOME/.vmcloak/iso/$VM_NAME.iso" ] && ! vmcloak_image_exists; then
    echo "removing stale VMCloak ISO from previous failed init: $HOME/.vmcloak/iso/$VM_NAME.iso" >>"${PHASE_LOG[$key]}"
    run_logged "$key" rm -f "$HOME/.vmcloak/iso/$VM_NAME.iso" || return 1
  fi
  if mountpoint -q "$WINDOWS_ISO_MOUNT"; then
    echo "Windows ISO already mounted at: $WINDOWS_ISO_MOUNT" >>"${PHASE_LOG[$key]}"
  else
    run_root_logged "$key" install -d -m 0755 "$WINDOWS_ISO_MOUNT" || return 1
    run_root_logged "$key" mount -o loop,ro "$WINDOWS_ISO" "$WINDOWS_ISO_MOUNT" || return 1
  fi

  if ! vmcloak_image_exists; then
    DETAIL["$key"]="running VMCloak init"
    redraw
    run_logged "$key" vmcloak init \
      --win10x64 \
      --iso-mount "$WINDOWS_ISO_MOUNT" \
      --ip "$GUEST_IP" \
      --network "$GUEST_NETWORK_CIDR" \
      --gateway "$HOST_IP" \
      --vrde \
      --vrde-port 1 \
      --cpus "$VM_CPUS" \
      --ramsize "$VM_RAM_MB" \
      --hddsize "$VM_DISK_GB" \
      "$VM_NAME" "$BRIDGE_NAME" || return 1
    if ! vmcloak_image_exists; then
      echo "VMCloak init did not register image: $VM_NAME" >>"${PHASE_LOG[$key]}"
      return 1
    fi
  fi

  if [ -n "$VMCLOAK_BASELINE_DEPS" ]; then
    DETAIL["$key"]="installing baseline guest software"
    redraw
    # shellcheck disable=SC2086
    if ! run_logged "$key" vmcloak install "$VM_NAME" $VMCLOAK_BASELINE_DEPS; then
      echo "baseline VMCloak dependency install failed; image exists and can be retried separately" >>"${PHASE_LOG[$key]}"
      echo "continuing because baseline guest software is non-blocking for MVP setup" >>"${PHASE_LOG[$key]}"
      DETAIL["$key"]="complete; baseline app install failed, see log"
      return 0
    fi
  else
    echo "baseline guest software install skipped by VMCLOAK_BASELINE_DEPS=''" >>"${PHASE_LOG[$key]}"
  fi
}

print_summary() {
  local failed=0
  local key
  local index
  for key in "${PHASE_KEYS[@]}"; do
    if [ "${STATUS[$key]}" = "failed" ]; then
      failed=$((failed + 1))
    fi
  done
  printf '\nSummary\n'
  printf '%s\n' '-------'
  if [ "$failed" -eq 0 ]; then
    printf 'No failed phases.\n'
  else
    printf 'Failed phases: %s\n' "$failed"
    printf 'Aggregated errors: %s\n' "$ERROR_LOG"
    printf '\nFailed components and logs:\n'
    for index in "${!PHASE_KEYS[@]}"; do
      key="${PHASE_KEYS[$index]}"
      if [ "${STATUS[$key]}" = "failed" ]; then
        printf '  - %s\n' "${PHASE_NAMES[$index]}"
        printf '    log: %s\n' "${PHASE_LOG[$key]}"
      fi
    done
  fi
  printf 'Detailed logs: %s\n' "$LOG_DIR"
}

ensure_log_dir
{
  printf 'setup_script_version=%s\n' "$SETUP_SCRIPT_VERSION"
  printf 'script_path=%s\n' "$PROJECT_ROOT/scripts/setup-ubuntu24-host.sh"
  printf 'run_id=%s\n' "$RUN_ID"
  printf 'mode=%s\n' "$([ "$EXECUTE" -eq 1 ] && printf execute || printf dry-run)"
  printf 'started_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$LOG_DIR/run.meta"
redraw
run_phase ubuntu phase_ubuntu
run_phase apt phase_apt
run_phase rust phase_rust
run_phase layout phase_layout
run_phase network phase_network
run_phase cape phase_cape
run_phase vmcloak phase_vmcloak
run_phase build phase_build
run_phase overlay phase_overlay
run_phase guest phase_guest
finish_screen
trap - EXIT
print_summary
