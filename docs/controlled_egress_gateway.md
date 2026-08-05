# Single-host controlled-egress gateway

This is a resource-conscious research workaround, not an independent security boundary. The Alpine gateway uses one vCPU, 512 MiB RAM, a 4 GiB thin disk, two virtual NICs, default-drop nftables, and no graphical environment.

Its inside interface is `10.66.0.254` on `winstdt-isolated`. Its outside interface is `192.168.125.254` on `winstdt-controlled-services`. The responder is `192.168.125.10`. The controlled-services libvirt network has no `<forward>` element; the former NAT network is not part of the design.

Policies are canonical JSON with an Ed25519 signature, policy hash, signer identity, run ID, single-use approval ID, exact destinations/ports/protocols, expiry, DNS pin, connection rate, and byte quota. Production activation verifies the signature locally, and the gateway refuses a consumed approval. Revocation restores the default-drop table and deletes analysis-guest conntrack state.

```bash
scripts/manage-egress-run.sh activate approved-run.json
scripts/manage-egress-run.sh status
scripts/manage-egress-run.sh revoke operator-request
scripts/manage-egress-run.sh collect RUN_ID /srv/winstdt/validation/RUN_ID
scripts/manage-egress-run.sh emergency-stop
```

Collection retrieves both gateway captures, DNS/policy logs and metadata, responder receipts, and hashes. Activation is always paired with an unconditional trap in the end-to-end runner.

Limitations:

- Host or hypervisor compromise can cross every virtual boundary.
- A virtual switch is not a physical firewall or passive TAP.
- Host resource exhaustion can affect enforcement and evidence collection.
- The host, hypervisor, CAPE, analysis guest, gateway, responder, and evidence control plane share hardware.
- The design is suitable only for controlled research validation.
- Public egress remains disabled until every acceptance gate passes; arbitrary public egress remains unsupported.
