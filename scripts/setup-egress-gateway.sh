#!/usr/bin/env bash
set -euo pipefail

EXECUTE=0
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK_FILE="${GATEWAY_LOCK_FILE:-$PROJECT_ROOT/config/gateway.lock.json}"
GATEWAY_ROOT="${GATEWAY_ROOT:-/srv/winstdt/gateway}"
IMAGE_ROOT="${GATEWAY_IMAGE_ROOT:-/var/lib/libvirt/images/winstdt}"

usage() { echo "Usage: $0 [--execute] [--lock FILE]"; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --execute) EXECUTE=1 ;;
    --lock) LOCK_FILE="${2:?missing lock path}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
  shift
done

json() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2], {"d":d}))' "$LOCK_FILE" "$1"; }
vm_name="$(json 'd["vm"]["name"]')"
vcpus="$(json 'd["vm"]["vcpus"]')"
memory="$(json 'd["vm"]["memory_mib"]')"
disk_gib="$(json 'd["vm"]["disk_gib"]')"
internal_network="$(json 'd["vm"]["internal_network"]')"
internal_ip="$(json 'd["vm"]["internal_ipv4"]')"
internal_mac="$(json 'd["vm"]["internal_mac"]')"
external_network="$(json 'd["vm"]["external_network"]')"
external_mac="$(json 'd["vm"]["external_mac"]')"
base_url="$(json 'd["guest"]["base_url"]')"
image_name="$(json 'd["guest"]["image"]')"
image_sha="$(json 'd["guest"]["sha512"]')"

echo "Gateway plan: $vm_name, ${vcpus} vCPU, ${memory} MiB, ${disk_gib} GiB"
echo "  inside:  $internal_network $internal_ip ($internal_mac)"
echo "  outside: $external_network DHCP ($external_mac)"
if [ "$EXECUTE" -ne 1 ]; then
  echo "Dry run only. Re-run with --execute to install packages, create networks and boot the VM."
  exit 0
fi

if virsh dominfo "$vm_name" >/dev/null 2>&1; then
  echo "Refusing to overwrite existing libvirt domain: $vm_name" >&2
  exit 1
fi

for command in genisoimage ssh-keygen qemu-img virsh virt-install; do
  command -v "$command" >/dev/null || { echo "missing required host command: $command" >&2; exit 1; }
done
sudo install -d -m 0750 "$GATEWAY_ROOT" "$GATEWAY_ROOT/keys"
sudo chown "$(id -un):$(id -gn)" "$GATEWAY_ROOT"
sudo install -d -m 0755 "$IMAGE_ROOT" "$IMAGE_ROOT/base" "$IMAGE_ROOT/seed"
if ! sudo test -f "$GATEWAY_ROOT/keys/id_ed25519"; then
  sudo ssh-keygen -q -t ed25519 -N '' -C winstdt-egress-gateway -f "$GATEWAY_ROOT/keys/id_ed25519"
fi
sudo chmod 0600 "$GATEWAY_ROOT/keys/id_ed25519"
sudo chown "$(id -un):$(id -gn)" "$GATEWAY_ROOT/keys" "$GATEWAY_ROOT/keys/id_ed25519" "$GATEWAY_ROOT/keys/id_ed25519.pub"
sudo chmod 0700 "$GATEWAY_ROOT/keys"
public_key="$(sudo cat "$GATEWAY_ROOT/keys/id_ed25519.pub")"

base_image="$IMAGE_ROOT/base/$image_name"
if ! sudo test -f "$base_image"; then
  if [ -f "$PROJECT_ROOT/$image_name" ]; then
    echo "$image_sha  $PROJECT_ROOT/$image_name" | sha512sum -c -
    sudo install -m 0640 "$PROJECT_ROOT/$image_name" "$base_image"
  else
    sudo curl -fL "$base_url/$image_name" -o "$base_image.part"
    test "$(sudo sha512sum "$base_image.part" | awk '{print $1}')" = "$image_sha"
    sudo mv "$base_image.part" "$base_image"
  fi
fi
test "$(sudo sha512sum "$base_image" | awk '{print $1}')" = "$image_sha" || {
  echo "base image checksum mismatch: $base_image" >&2
  exit 1
}

network_xml="$(mktemp)"
seed_dir="$(mktemp -d)"
trap 'rm -f -- "$network_xml"; rm -rf -- "$seed_dir"' EXIT
cat >"$network_xml" <<EOF
<network>
  <name>$external_network</name>
  <forward mode='nat'/>
  <bridge name='virbr-wext' stp='on' delay='0'/>
  <ip address='192.168.124.1' netmask='255.255.255.0'>
    <dhcp><range start='192.168.124.100' end='192.168.124.200'/></dhcp>
  </ip>
</network>
EOF
if ! virsh net-info "$external_network" >/dev/null 2>&1; then
  virsh net-define "$network_xml"
fi
virsh net-autostart "$external_network"
if [ "$(virsh net-info "$external_network" | awk '/^Active:/ {print $2}')" != yes ]; then
  virsh net-start "$external_network"
fi
virsh net-info "$internal_network" >/dev/null

cat >"$seed_dir/meta-data" <<EOF
instance-id: $vm_name-v1
local-hostname: $vm_name
EOF
cat >"$seed_dir/network-config" <<EOF
version: 2
ethernets:
  internal:
    match: {macaddress: "$internal_mac"}
    set-name: eth0
    addresses: [$internal_ip]
  external:
    match: {macaddress: "$external_mac"}
    set-name: eth1
    dhcp4: true
EOF
cat >"$seed_dir/user-data" <<EOF
#cloud-config
growpart:
  mode: auto
  devices: ['/']
resize_rootfs: true
users:
  - name: winstdt-gateway
    groups: [wheel]
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    shell: /bin/ash
    lock_passwd: false
    hashed_passwd: '\$6\$W9wlBbGHRTBU9/wT\$a9Vds/4ojJBqeP91s2WC5JcB0rvkdeFSQ8DKfKGoAag2.UqGGsgIdYs92DYrWmSXIUwt2DkzfpUfrunnIhJH/.'
    ssh_authorized_keys:
      - $public_key
ssh_pwauth: false
disable_root: true
package_update: true
package_upgrade: true
packages: [nftables, nftables-openrc, tcpdump, conntrack-tools, dnsmasq, jq, qemu-guest-agent, qemu-guest-agent-openrc, sudo, openssh]
write_files:
  - path: /etc/modules
    append: true
    permissions: '0644'
    content: |
      nf_conntrack
      nf_tables
      nft_nat
  - path: /etc/sysctl.d/90-winstdt-gateway.conf
    permissions: '0644'
    content: |
      net.ipv4.ip_forward=1
      net.ipv6.conf.all.forwarding=0
      net.ipv4.conf.all.send_redirects=0
  - path: /etc/nftables.nft
    permissions: '0644'
    content: |
      flush ruleset
      table inet winstdt_run {
        chain input { type filter hook input priority 0; policy drop;
          iifname "lo" accept
          ct state established,related accept
          iifname "eth0" ip saddr 10.66.0.1 tcp dport 22 accept
          iifname "eth0" ip protocol icmp accept
          iifname "eth1" udp sport 67 udp dport 68 accept
        }
        chain forward { type filter hook forward priority 0; policy drop; }
      }
  - path: /usr/local/sbin/winstdt-egress-revoke
    permissions: '0755'
    content: |
      #!/bin/ash
      set -euo pipefail
      reason="\${1:-expiry}"
      state=/var/lib/winstdt-egress/current
      stop_pidfile() {
        file="\$1"
        [ -f "\$file" ] || return 0
        pid="\$(cat "\$file" 2>/dev/null || true)"
        case "\$pid" in ''|*[!0-9]*) return 0 ;; esac
        kill "\$pid" 2>/dev/null || true
      }
      if [ -f "\$state/metadata.json" ]; then
        jq --arg reason "\$reason" --arg ended "\$(date -u +%FT%TZ)" '. + {ended_at_utc:\$ended,revocation_reason:\$reason}' "\$state/metadata.json" >"\$state/final.json"
      fi
      stop_pidfile "\$state/internal.pid"
      stop_pidfile "\$state/external.pid"
      stop_pidfile "\$state/dnsmasq.pid"
      if [ "\$reason" != automatic-expiry ]; then stop_pidfile "\$state/expiry.pid"; fi
      nft delete table inet winstdt_run 2>/dev/null || true
      nft -f /etc/nftables.nft
      conntrack -D -s 10.66.0.101 2>/dev/null || true
      if [ -d "\$state" ]; then
        run="\$(basename "\$(readlink -f "\$state")")"
        rm -f /var/lib/winstdt-egress/current
        logger -t winstdt-egress "revoked \$run: \$reason"
      fi
  - path: /usr/local/sbin/winstdt-egress-activate
    permissions: '0755'
    content: |
      #!/bin/ash
      set -euo pipefail
      run="\$1"; expires="\$2"; dns_name="\$3"; dns_ip="\$4"; rules="\$5"; metadata="\$6"
      now="\$(date +%s)"; duration="\$((expires-now))"
      test "\$duration" -gt 0 && test "\$duration" -le 86400
      /usr/local/sbin/winstdt-egress-revoke replacement
      dest="/var/lib/winstdt-egress/runs/\$run"
      install -d -m 0750 "\$dest"
      install -m 0640 "\$metadata" "\$dest/metadata.json"
      install -m 0640 "\$rules" "\$dest/rules.nft"
      ln -sfn "\$dest" /var/lib/winstdt-egress/current
      tcpdump -i eth0 -U -w "\$dest/internal.pcap" >"\$dest/internal.capture.log" 2>&1 & echo \$! >"\$dest/internal.pid"
      tcpdump -i eth1 -U -w "\$dest/external.pcap" >"\$dest/external.capture.log" 2>&1 & echo \$! >"\$dest/external.pid"
      if [ -n "\$dns_name" ]; then
        dnsmasq --no-resolv --no-hosts --bind-interfaces --interface=eth0 --listen-address=10.66.0.254 \
          --address="/\$dns_name/\$dns_ip" --pid-file="\$dest/dnsmasq.pid" --log-facility="\$dest/dnsmasq.log"
      fi
      nft -f "\$dest/rules.nft"
      nohup sh -c "sleep \$duration; exec /usr/local/sbin/winstdt-egress-revoke automatic-expiry" \
        >"\$dest/expiry.log" 2>&1 & echo \$! >"\$dest/expiry.pid"
      logger -t winstdt-egress "activated \$run for \$duration seconds"
  - path: /usr/local/sbin/winstdt-egress-status
    permissions: '0755'
    content: |
      #!/bin/ash
      set -euo pipefail
      if [ -f /var/lib/winstdt-egress/current/metadata.json ]; then
        jq '{run_id,approval_id,expires_at_utc,destinations,dns}' /var/lib/winstdt-egress/current/metadata.json
      else
        echo '{"status":"default_deny","active_run":null}'
      fi
      nft list table inet winstdt_run
runcmd:
  - [modprobe, nf_conntrack]
  - [modprobe, nf_tables]
  - [modprobe, nft_nat]
  - [sysctl, -p, /etc/sysctl.d/90-winstdt-gateway.conf]
  - [install, -d, -m, '0750', /var/lib/winstdt-egress/runs]
  - [rc-update, add, nftables, boot]
  - [rc-service, nftables, restart]
  - [rc-update, add, qemu-guest-agent, default]
  - [rc-service, qemu-guest-agent, start]
  - [rc-update, add, sshd, default]
  - [rc-service, sshd, restart]
  - [nft, -f, /etc/nftables.nft]
  - [cloud-init-per, once, ready, touch, /var/lib/winstdt-egress/ready]
power_state:
  delay: now
  mode: reboot
  message: Rebooting into the updated Alpine kernel for gateway activation
  condition: true
EOF

seed_iso="$IMAGE_ROOT/seed/$vm_name-seed.iso"
sudo genisoimage -quiet -output "$seed_iso" -volid cidata -joliet -rock \
  "$seed_dir/user-data" "$seed_dir/meta-data" "$seed_dir/network-config"
disk="$IMAGE_ROOT/$vm_name.qcow2"
if [ -e "$disk" ]; then
  echo "Refusing to overwrite existing disk: $disk" >&2
  exit 1
fi
sudo qemu-img create -f qcow2 -F qcow2 -b "$base_image" "$disk" "${disk_gib}G"
storage_owner="$(stat -c %U "$IMAGE_ROOT")"
storage_group="$(stat -c %G "$IMAGE_ROOT")"
sudo chown "$storage_owner:$storage_group" "$base_image" "$disk" "$seed_iso"
sudo chmod 0644 "$base_image" "$seed_iso"
sudo chmod 0640 "$disk"

virt-install --connect qemu:///system --name "$vm_name" --memory "$memory" --vcpus "$vcpus" \
  --cpu host-passthrough --os-variant generic --import --noautoconsole \
  --disk "path=$disk,format=qcow2,bus=virtio" --disk "path=$seed_iso,device=cdrom" \
  --channel unix,target.type=virtio,target.name=org.qemu.guest_agent.0 \
  --network "network=$internal_network,model=virtio,mac=$internal_mac" \
  --network "network=$external_network,model=virtio,mac=$external_mac"
virsh autostart "$vm_name"

echo "Gateway booted fail-closed. Wait for cloud-init, then verify with:"
echo "  GATEWAY_KEY=$GATEWAY_ROOT/keys/id_ed25519 scripts/manage-egress-run.sh status"
