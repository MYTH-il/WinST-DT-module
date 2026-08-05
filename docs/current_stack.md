# Current Stack and Capability Status

Status date: 2026-08-05. `Working` means a current acceptance record exists; software installation alone is not sufficient.

| Capability | Status | Evidence or remaining gate |
|---|---|---|
| Ubuntu 24.04 monolithic libvirt runtime | Working | [acceptance:libvirt_live_recovery] Packaged `libvirtd`, socket, networks, and both original domains passed live validation |
| Two-reboot libvirt persistence | Working | [acceptance:libvirt_two_reboots] Prepare and two consecutive post-reboot validations passed with three distinct boot IDs |
| CAPE service stability | Working | [acceptance:libvirt_two_reboots] CAPE remained healthy through both reboot validation cycles |
| Windows guest and snapshot | Working | [acceptance:full_end_to_end] The reviewed parent and gateway-DNS derivative `hardened-baseline-controlled-egress-v2` passed detonation and rollback |
| CAPE/capemon and PCAP/ETL handoff | Working | [acceptance:full_end_to_end] Task 17 preserved and validated immutable PCAP, ETL, clock, access-event, and reporting evidence |
| Detect It Easy 3.10 | Working | [acceptance:die_3_10] Official package hash, exact version, database access, PE positive, and text negative validated live |
| CAPA/FLOSS/TRiD/Volatility | Degraded | Installed or profile-gated; completed-task positives remain required where indicated in `analysis_capabilities.md` |
| Suricata | Working | [acceptance:full_end_to_end] Pinned passive processing emitted three controlled-canary alerts from the CAPE capture |
| C2 upstream subtree | Working | [acceptance:c2_compatibility] Pristine `c417276196586c676d3f0b63d23100d2cd20fce9`; 233 collected, 222 passed, 11 upstream-declared corpus skips |
| C2 compatibility runtime | Working | [acceptance:full_end_to_end] Versioned runtime completed real correlation, attribution, IOC, provenance, and immutable result validation |
| PostgreSQL contract | Working | [acceptance:full_end_to_end] Schema v2 migration and JSON/SQL sample, PCAP, task, and row-count round trip passed |
| Access-event adapter | Working | [acceptance:full_end_to_end] Real CAPE/capemon events passed clock interpolation and correlation eligibility checks |
| Controlled-services network | Working | [acceptance:controlled_services_network] Isolated `192.168.125.0/24` has no libvirt forwarding element |
| Controlled responder | Working | [acceptance:full_end_to_end] Private DNS and three deterministic signed receipts passed with no public route |
| Gateway negative-policy matrix | Working | [acceptance:gateway_negative_matrix] Destination, port, expiry, byte, connection, DNS, outage, and emergency-stop cases passed together |
| Harmless Windows fixture | Working | [acceptance:full_end_to_end] The Rust/Win32 PE completed its controlled activity and transmitted only generated canary data |
| Full harmless CAPE detonation | Working | [acceptance:full_end_to_end] Task 17 passed correlation, Suricata, PostgreSQL, snapshot reversion, and final no-route proof |
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
