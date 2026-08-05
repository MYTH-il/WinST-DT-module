#!/usr/bin/env bash
set -euo pipefail

EXECUTE=0
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK_FILE="${GATEWAY_LOCK_FILE:-$PROJECT_ROOT/config/gateway.lock.json}"
ROOT="${RESPONDER_ROOT:-/srv/winstdt/responder}"
IMAGE_ROOT="${GATEWAY_IMAGE_ROOT:-/var/lib/libvirt/images/winstdt}"
while [ "$#" -gt 0 ]; do case "$1" in --execute) EXECUTE=1;; -h|--help) echo "Usage: $0 [--execute]"; exit;; *) exit 2;; esac; shift; done
read_json() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2],{"d":d}))' "$LOCK_FILE" "$1"; }
name="$(read_json 'd["responder"]["name"]')"; network="$(read_json 'd["responder"]["network"]')"
ip="$(read_json 'd["responder"]["ipv4"]')"; mac="$(read_json 'd["responder"]["mac"]')"
memory="$(read_json 'd["responder"]["memory_mib"]')"; vcpus="$(read_json 'd["responder"]["vcpus"]')"
disk_gib="$(read_json 'd["responder"]["disk_gib"]')"; image="$(read_json 'd["guest"]["image"]')"
echo "Responder plan: $name ${vcpus} vCPU ${memory} MiB ${disk_gib} GiB, $network $ip"
[ "$EXECUTE" -eq 1 ] || { echo 'Dry run only. Re-run with --execute.'; exit; }
for command in virsh virt-install qemu-img genisoimage ssh-keygen openssl; do command -v "$command" >/dev/null || { echo "missing $command" >&2; exit 1; }; done
virsh dominfo "$name" >/dev/null 2>&1 && { echo "refusing to overwrite domain $name" >&2; exit 1; }
network_xml="$PROJECT_ROOT/config/libvirt/winstdt-controlled-services.xml"
grep -q '<forward' "$network_xml" && { echo 'controlled network unexpectedly forwards' >&2; exit 1; }
virsh net-info "$network" >/dev/null 2>&1 || virsh net-define "$network_xml"
virsh net-autostart "$network"
[ "$(virsh net-info "$network" | awk '/^Active:/ {print $2}')" = yes ] || virsh net-start "$network"
sudo install -d -m 0750 "$ROOT/keys"
sudo install -d -m 0755 "$IMAGE_ROOT/seed"
if ! sudo test -f "$ROOT/keys/id_ed25519"; then sudo ssh-keygen -q -t ed25519 -N '' -f "$ROOT/keys/id_ed25519"; fi
if ! sudo test -f "$ROOT/keys/receipt_ed25519"; then
  sudo ssh-keygen -q -t ed25519 -N '' -f "$ROOT/keys/receipt_ed25519"
fi
if ! sudo test -f "$ROOT/keys/tls.key"; then
  sudo openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=validation.winstdt.test \
    -keyout "$ROOT/keys/tls.key" -out "$ROOT/keys/tls.crt" >/dev/null 2>&1
fi
ssh_public="$(sudo cat "$ROOT/keys/id_ed25519.pub")"
receipt_private="$(sudo sed 's/^/      /' "$ROOT/keys/receipt_ed25519")"
tls_private="$(sudo sed 's/^/      /' "$ROOT/keys/tls.key")"
tls_cert="$(sudo sed 's/^/      /' "$ROOT/keys/tls.crt")"
server_source="$(base64 -w0 "$PROJECT_ROOT/responder/controlled_responder.py")"
seed="$(mktemp -d)"; trap 'rm -rf -- "$seed"' EXIT
cat >"$seed/meta-data" <<EOF
instance-id: $name-v1
local-hostname: $name
EOF
cat >"$seed/network-config" <<EOF
version: 2
ethernets:
  responder:
    match: {macaddress: "$mac"}
    set-name: eth0
    addresses: [$ip]
EOF
cat >"$seed/user-data" <<EOF
#cloud-config
users:
  - name: winstdt-responder
    groups: [wheel]
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    shell: /bin/ash
    lock_passwd: false
    hashed_passwd: '\$6\$W9wlBbGHRTBU9/wT\$a9Vds/4ojJBqeP91s2WC5JcB0rvkdeFSQ8DKfKGoAag2.UqGGsgIdYs92DYrWmSXIUwt2DkzfpUfrunnIhJH/.'
    ssh_authorized_keys:
      - $ssh_public
ssh_pwauth: false
write_files:
  - path: /etc/winstdt-responder/receipt_ed25519
    permissions: '0600'
    content: |
$receipt_private
  - path: /etc/winstdt-responder/tls.key
    permissions: '0600'
    content: |
$tls_private
  - path: /etc/winstdt-responder/tls.crt
    permissions: '0644'
    content: |
$tls_cert
  - path: /etc/init.d/winstdt-responder
    permissions: '0755'
    content: |
      #!/sbin/openrc-run
      command=/usr/local/bin/controlled_responder.py
      command_background=true
      pidfile=/run/winstdt-responder.pid
      output_log=/var/log/winstdt-responder/service.log
      error_log=/var/log/winstdt-responder/service.log
runcmd:
  - [mkdir, -p, /etc/winstdt-responder, /var/log/winstdt-responder]
  - [sh, -c, "echo '$server_source' | base64 -d > /usr/local/bin/controlled_responder.py && chmod 0755 /usr/local/bin/controlled_responder.py"]
  - [sysctl, -w, net.ipv4.ip_forward=0]
  - [rc-update, add, winstdt-responder, default]
  - [rc-service, winstdt-responder, start]
  - [rc-service, sshd, stop]
  - [rc-update, del, sshd, default]
EOF
seed_iso="$IMAGE_ROOT/seed/$name-seed.iso"; sudo genisoimage -quiet -output "$seed_iso" -volid cidata -joliet -rock "$seed/user-data" "$seed/meta-data" "$seed/network-config"
base="$IMAGE_ROOT/base/$image"; sudo test -s "$base" || { echo "missing verified Alpine base: $base" >&2; exit 1; }
disk="$IMAGE_ROOT/$name.qcow2"
if sudo test -e "$disk"; then
  sudo qemu-img info --output=json "$disk" | python3 -c 'import json,sys; d=json.load(sys.stdin); raise SystemExit(0 if d.get("format")=="qcow2" else 1)' || {
    echo "existing responder overlay failed validation: $disk" >&2; exit 1;
  }
else
  sudo qemu-img create -f qcow2 -F qcow2 -b "$base" "$disk" "${disk_gib}G"
fi
storage_owner="$(stat -c %U "$IMAGE_ROOT")"; storage_group="$(stat -c %G "$IMAGE_ROOT")"
sudo chown "$storage_owner:$storage_group" "$disk" "$seed_iso"
sudo chmod 0640 "$disk"; sudo chmod 0644 "$seed_iso"
virt-install --connect qemu:///system --name "$name" --memory "$memory" --vcpus "$vcpus" --cpu host-passthrough --os-variant generic --import --noautoconsole \
  --disk "path=$disk,format=qcow2,bus=virtio" --disk "path=$seed_iso,device=cdrom" \
  --channel unix,target.type=virtio,target.name=org.qemu.guest_agent.0 --network "network=$network,model=virtio,mac=$mac"
virsh autostart "$name"
