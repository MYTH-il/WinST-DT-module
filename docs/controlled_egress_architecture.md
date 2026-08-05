# Recommended controlled-egress architecture

```text
Management network
        │
Policy controller / evidence collector
        │ out-of-band control
        ▼
Detonation hypervisor ── analysis VLAN ── physical gateway
                                             │
                       ┌─────────────────────┴────────────────────┐
                       ▼                                          ▼
             Controlled-services DMZ                    Governed WAN uplink
```

The recommended laboratory separates the detonation hypervisor and gateway onto different hardware. Analysis guests cannot reach the dedicated management interfaces. Forwarding is default-deny and every run is bounded by signed, single-use approval for destination, port, protocol, duration, connections, and bytes.

DNS answers are pinned and checked against the approved destination to resist rebinding. Capture occurs on both gateway sides, with passive TAP/SPAN evidence where practical. CAPE lifecycle events activate policy immediately before execution and revoke it unconditionally afterward; expiry also deletes conntrack state. A host-independent emergency stop removes the forwarding path.

Controlled responders live on a separate DMZ and never forward. Evidence is exported immutably out of band. TLS interception is optional only through a separately trusted guest profile and must record pinning or protocol limitations. None of these controls protects against compromise of the hypervisor or physical gateway itself.

Rollout order is fixed:

1. isolated controlled responder;
2. team-owned public endpoint;
3. individually approved public endpoint;
4. arbitrary public egress remains unsupported.
