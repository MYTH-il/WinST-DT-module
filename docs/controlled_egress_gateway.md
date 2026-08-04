# Controlled-egress gateway

## Current status

The gateway appliance is deployed and fail-closed. It is **not** an approved
analysis route yet. Do not set the Windows analysis guest's default route to the
gateway until the controlled-responder and CAPE lifecycle acceptance tests pass.

Deployed configuration:

- Alpine Linux 3.24.1 x86_64 BIOS cloud-init image;
- image SHA-512 pinned in `config/gateway.lock.json`;
- VM `winstdt-egress-gateway`: one vCPU, 512 MiB RAM, 4 GiB thin disk;
- internal NIC `10.66.0.254/24` on `winstdt-isolated`;
- external NIC on the dedicated `winstdt-external` libvirt NAT network;
- IPv4 forwarding enabled, IPv6 forwarding disabled;
- nftables forwarding policy `drop` with no default allow rules;
- SSH key authentication accepted only from host address `10.66.0.1`;
- QEMU guest agent enabled.

The copied qcow2 in the project root is an installation input and is ignored by
Git. Provisioning verifies its SHA-512 before copying the public base image into
the libvirt storage pool. The private controller key remains outside Git under
`/srv/winstdt/gateway/keys/`.

## Provisioning and inspection

Provisioning is dry-run by default:

```text
scripts/setup-egress-gateway.sh
scripts/setup-egress-gateway.sh --execute
scripts/manage-egress-run.sh status
```

Provisioning refuses to overwrite an existing domain or overlay. A new Alpine
kernel installed during first boot triggers one cloud-init reboot so its
Netfilter modules match the running kernel.

## Per-run policy

Copy `config/gateway-run.example.json`, provide a literal destination IP,
protocol, port, UTC expiry no more than 24 hours ahead, byte ceiling,
new-connection rate, pinned DNS record, and approval identifier. Then use:

```text
scripts/manage-egress-run.sh activate /approved/path/run.json
scripts/manage-egress-run.sh status
scripts/manage-egress-run.sh revoke operator-revocation
```

Activation atomically replaces the complete gateway ruleset. Only the declared
Windows guest, destination, protocol and port are accepted. DNS answers are
served only for the pinned name. The gateway records `internal.pcap` and
`external.pcap` under `/var/lib/winstdt-egress/runs/<run_id>/`.

Expiry or revocation restores the base default-drop ruleset, deletes matching
conntrack state, stops DNS and both packet captures, removes the `current`
symlink, and writes `final.json` with its reason and time.

The host-side emergency stop also lowers the gateway's external virtual NIC:

```text
scripts/manage-egress-run.sh emergency-stop
```

Restore that link only as an explicit maintenance operation after reviewing the
incident and confirming the default-drop policy.

## Validation completed

The no-traffic lifecycle smoke test on 2026-08-04 used reserved documentation
address `192.0.2.10` for 30 seconds. It confirmed:

- the allowlist, quota, connection-rate limit and pinned-DNS rules loaded;
- both tcpdump processes and dnsmasq started;
- the allow rule observed zero packets;
- automatic expiry restored the empty default-drop forwarding chain;
- tcpdump and dnsmasq terminated;
- both PCAPs and an `automatic-expiry` final record remained in the run store.
- the host emergency stop lowered the external virtual NIC, which was restored
  only after confirming that no run was active and forwarding remained
  default-drop.

This test did not route the Windows guest or contact an endpoint.

## Remaining acceptance gates

1. Add an isolated virtual controlled responder and verify positive and negative
   destination/port cases.
2. Export and hash both PCAPs into the evidence workflow.
3. Connect activation and unconditional revocation to the CAPE task lifecycle.
4. Verify the Windows gateway route exists only in the selected egress profile.
5. Test connection, byte and duration ceilings with real controlled traffic.
6. Confirm controlled-traffic teardown leaves no continuing forward or proxy
   path.
7. Obtain approval before testing a team-owned public endpoint.

Individually approved public endpoints come only after those gates. Arbitrary
unknown-malware public egress remains outside the single-host milestone.
