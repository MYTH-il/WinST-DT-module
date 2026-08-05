# Current Stack and Capability Status

Status date: 2026-08-05. `Working` means a current acceptance record exists; software installation alone is not sufficient.

| Capability | Status | Evidence or remaining gate |
|---|---|---|
| Ubuntu 24.04 monolithic libvirt runtime | Working on demand | Packaged `libvirtd`, socket, networks, and both original domains validated after stale modular units were quarantined |
| Two-reboot libvirt persistence | Degraded | Run `validate-libvirt-reboots.sh` after two distinct operator-initiated boots |
| CAPE service stability | Working on demand | Services are active after live repair; reboot persistence remains coupled to the two-reboot gate |
| Windows guest and snapshot | Working on demand | The reviewed `hardened-baseline-antievasion-v1` parent and controlled-network derivative `hardened-baseline-controlled-egress-v1` are queryable |
| CAPE/capemon and PCAP/ETL handoff | Working on demand | Existing completed controlled validation evidence; every new task remains independently validated |
| Detect It Easy 3.10 | Working | [acceptance:die_3_10] Official package hash, exact version, database access, PE positive, and text negative validated live |
| CAPA/FLOSS/TRiD/Volatility | Degraded | Installed or profile-gated; completed-task positives remain required where indicated in `analysis_capabilities.md` |
| Suricata | Degraded | Pinned passive processing is configured; the controlled canary rule exists, but the full CAPE run gate is pending |
| C2 upstream subtree | Working on demand | Pristine `c417276196586c676d3f0b63d23100d2cd20fce9`; 233 collected, 222 passed, 11 upstream-declared corpus skips |
| C2 compatibility runtime | Degraded | Patch, feed, schema, identity, migration, Zeek, and bundle tests pass; live versioned promotion/full task acceptance is pending |
| PostgreSQL contract | Working on demand | Clean schema and repeated migration passed locally; full CAPE JSON/SQL round trip is pending |
| Access-event adapter | Working on demand | Interpolation, bounds, uncertainty, ETW conflict, malformed input, and fixture prevention are tested |
| Controlled-services network | Working on demand | Isolated `192.168.125.0/24`, no libvirt forward element, old NAT network removed |
| Controlled responder | Working on demand | Private DNS, HTTP, HTTPS, signed receipt, strict payload fields, and no public route validated live |
| Gateway negative-policy matrix | Degraded | Default-drop is live; wrong destination/port, expiry, quota, ceiling, pin mismatch, and outage evidence must all pass in one acceptance set |
| Harmless Windows fixture | Working on demand | Separate pinned Rust crate cross-compiles to PE and DIE detects it |
| Full harmless CAPE detonation | Degraded | Operator-approved signed policy, real correlation, Suricata, SQL round trip, snapshot revert, and final route proof remain required |
| Public egress | Unavailable | Arbitrary public egress is unsupported |

## Deployed boundaries

The current host runs KVM/libvirt, CAPE, the Windows analysis guest, and the Alpine gateway. The responder is a separate small guest, but all virtual components still share one physical host. This is suitable for controlled validation only and is not an independent security boundary.

The analysis network is `winstdt-isolated`. The gateway outside interface and responder attach to `winstdt-controlled-services`, which has no `<forward>` element. The responder is `192.168.125.10`; the gateway outside address is `192.168.125.254`. No public endpoint is permitted.

## Evidence contracts

Immutable CAPE input lives at `/srv/winstdt/handoff/{task_id}`. Derived analyzer output lives at `/srv/winstdt/c2-results/{task_id}` and is atomically promoted read-only only after schema, identity, provenance, handoff-integrity, and complete-hash validation.

The submitted file SHA-256 is the canonical sample identity. The capture SHA-256 is separate evidence identity. Raw ETL remains authoritative; classified access events are eligible for 15-second correlation only with complete start/end clock measurements, uncertainty below 7.5 seconds, analysis-window validity, and no material ETW conflict.

## Interpretation

- A valid capture with failed attempts does not prove successful transfer.
- Allowlisting remains visible and ranks below all threat tiers.
- Compiler, packer, or weak heuristic evidence cannot establish a family.
- Native Zeek is preferred. The streamed fallback is degraded and lacks at least `x509.log` and `files.log`.
- A screenshot or gateway-stage failure must not delete already collected PCAP or ETL evidence.
- Sealed results and handoffs are never rewritten.
