# Current Stack and Capability Status

Status date: 2026-08-04

Repository capability-completion scaffolding is implemented, but no additional
capability below is promoted to Working until its live acceptance test passes.
See `analysis_capabilities.md` for the pinned installer, profiles, evidence
contract, and acceptance procedure.

This document describes what the deployed WinST/DT stack currently does. It is
an operational inventory, not a roadmap and not a list of every feature CAPEv2
can theoretically support. A component is marked working only where the local
configuration and completed task artifacts demonstrate it.

## Executive status

The platform currently supports meaningful Windows static triage and isolated
dynamic detonation. CAPE task execution, behavioral API monitoring, PCAP
capture, raw ETW capture, reporting, and atomic evidence handoff have been
demonstrated end to end.

It does **not** yet provide the full analysis breadth of a mature commercial or
multi-engine laboratory. CAPA, FLOSS, Suricata processing, full-memory
forensics, TLS interception, and several supplemental static engines are not
active. Some features are installed but disabled; installation alone must not
be reported as analytical coverage.

**No live or controlled-live-egress analysis route is currently implemented or
available. Controlled live egress is under development.** The repository has a
disabled example profile and approval-metadata gate, but these do not implement
routing, containment, or safe external connectivity. Current analysis is
limited to drop/isolated and simulated-service behavior.

The complete Malware Analysis Platform also requires a new unified UI/web
interface capable of operating and coordinating both the Windows and Android
analysis modules. That cross-platform interface is not currently implemented
and is under development. CAPE's existing website remains a Windows-side
operator surface, not the final platform UI.

The authorized C2/Exfiltration analyzer is embedded as a pinned subtree.
WinST/DT owns host-event conversion, clock-quality enforcement, immutable
derived-result storage, and end-to-end acceptance; installation alone does not
make host/network correlation Working.

## Deployed architecture

| Layer | Current implementation |
|---|---|
| Host | Ubuntu 24.04 analysis host |
| Hypervisor | KVM/QEMU managed through libvirt |
| Guest | Hardened Windows 10 22H2 x64 golden image |
| Sandbox | CAPEv2 rolling-release checkout under `/opt/CAPEv2` |
| Dynamic monitor | CAPE/capemon user-mode behavioral monitoring |
| Additional telemetry | In-guest ETW trace-session agent |
| Required ETW classes | Kernel Process, File, Registry, and Network |
| Optional ETW classes | Kernel Image and Microsoft Windows Threat Intelligence; currently degraded/unavailable on the validated guest |
| Network capture | CAPE host-side sniffer |
| Network behavior | Isolated/drop or simulated services; no operational live-egress route |
| Evidence export | CAPE reporting overlay plus Rust schema validator |
| Handoff root | `/srv/winstdt/handoff/{task_id}` |
| Unified Windows/Android UI | Not implemented; under development |

The golden image is qualified with Pafish and al-khaser after hardening. The
strict gate can reject an image; `--allow-rejected` permits sealing for isolated
ST/DT testing while retaining the rejection and residual-risk record. It does
not make failed checks pass and does not improve resistance to VM detection.

## Static-analysis coverage

| Capability | Status | Current behavior or limitation |
|---|---|---|
| Cryptographic hashes | Working | MD5, SHA-1, SHA-256 and additional hashes are recorded |
| Similarity hashes | Working | ssdeep and TLSH are available in CAPE results |
| File typing | Working | File type and architecture are identified |
| PE structure | Working | Entry point, sections, imports, exports, resources, checksums, version data, signatures and related PE metadata |
| Plain strings | Working | CAPE strings processing is enabled |
| Digital signature inspection | Working | DigiSig result sidecar is produced |
| Extractor/unpacker attempts | Working framework | CAPE invokes configured format, archive, packer and deobfuscation integrations; success remains sample-dependent |
| YARA | Enabled | Local CAPE corpus is present and scans run; a zero-hit result means only that the installed rules did not match |
| CAPE YARA/config extraction | Enabled framework | Payload/config recovery is sample- and execution-dependent |
| Static IOC extraction | Partial | Available through CAPE results and project pre-triage; downstream normalization is still required |
| VirusTotal | Degraded | Configured lookup returned HTTP 429 during the audited malware runs; it is a soft dependency |
| ClamAV | Not active in audited CAPE run | No result was produced |
| FLARE CAPA | Degraded | Version 9.3.1 and pinned rules are installed and enabled; known-positive completed-task acceptance remains pending |
| FLOSS | Degraded, on demand | Version 3.1.1 and pinned signatures are installed; `deep_static` completed-task acceptance remains pending |
| Detect It Easy | Disabled | No DIE compiler/packer result |
| TRiD | Disabled | No TRiD identification result |
| Interactive disassembly/decompilation | Outside automated pipeline | Analyst tooling such as Ghidra is not part of the automatic CAPE handoff |

The project CLI also contains a pre-triage path that can use configured local
YARA rule sets, ClamAV when installed, and VirusTotal when an API key and service
capacity are available. That path must not be conflated with what an individual
CAPE task actually executed; the task report is authoritative for per-run
coverage.

## Dynamic-analysis coverage

| Capability | Status | Current behavior or limitation |
|---|---|---|
| Guest lifecycle and snapshot reversion | Working | CAPE/libvirt controls the disposable analysis guest |
| API-call telemetry | Working | capemon behavioral logs are processed into the CAPE report |
| Process tree | Working | Process lineage is reported when observed |
| File and registry behavior | Working | CAPE behavior plus raw ETW coverage |
| Network behavior | Working with routing limitation | Connections and supported protocols are reported from the PCAP |
| Behavioral signatures | Working | CAPE signatures score observed behavior |
| ATT&CK/TTP mapping | Partial | Mappings are signature-dependent, sparse, and require analyst quality review |
| Dropped-file collection | Working framework | Only produces artifacts when the sample drops or exposes them |
| CAPE payload/config recovery | Working framework | No payload/config was recovered in the audited StealBit runs |
| Process-memory analysis | Enabled framework, not demonstrated | Audited tasks contained no process-memory results |
| Full VM memory dump | Disabled | Default `memory_dump` is off and audited tasks did not request it |
| Volatility memory forensics | Degraded, on demand | Volatility 3 2.11.0, offline Windows symbols, and baseline plugins are configured; full-memory task acceptance remains pending |
| PCAP | Working | Non-empty captures are exported and hashed |
| Raw ETL | Working with optional-provider degradation | Non-empty ETL is exported and hashed |
| Screenshots | Disabled | QEMU screenshots are not currently collected |
| Suricata IDS | Degraded | Passive CAPE processing is enabled with a pinned 52,174-rule snapshot; positive/negative PCAP task acceptance remains pending |
| TLS interception/decryption | Disabled | Mitmdump, PolarProxy and PCAP decryption are off |
| Simulated Internet | Partial | Generic simulation may not satisfy malware-specific C2 protocols |
| Controlled live egress | Not implemented | Under development; no current testing or analysis may rely on it |

### Validated runtime evidence

CAPE benign task 11 demonstrated analyzer execution, PCAP capture, ETW capture
and retrieval, reporting-module export, schema validation, and mock-consumer
acceptance in one CAPE-controlled run.

Malware tasks 6 and 7 demonstrated repeatable capemon, PCAP, ETW, report, and
handoff generation for SHA-256
`6b795d9faa48ce3ae31f0bde3dcb61a6d738e8cc0e29b5949d93a5c8ee74786a`.
The sample made repeated unsuccessful connections to `5.149.249.242:80`. These
runs demonstrate attempted C2 behavior, not completed C2 or exfiltration.

The sample is an older StealBit component associated with the LockBit ecosystem,
not evidence that the LockBit file-encryption payload was exercised. The
simulated route did not provide the expected remote protocol, so the process
remained in a retry loop until the analysis timeout.

## Evidence handoff

A completed bundle normally contains:

```text
/srv/winstdt/handoff/{task_id}/
    manifest.json
    sample.meta.json
    network/capture.pcapng
    behavior/trace.etl
    behavior/clock-sync.json    # conditional on a valid measurement
    report.json
    report.html
    hashes.sha256
```

The exporter writes bundles atomically and the validator checks their schema,
required artifacts, and hashes. Missing required capture artifacts produce a
`capture_error`; unavailable optional ETW providers produce a degraded bundle
rather than silently claiming full telemetry.

Raw ETL is retained as the authoritative Windows trace. The C2/Exfiltration
module currently expects classified access events in JSON. Integration therefore
requires an adapter that:

1. Parses relevant ETW process, file, registry, and network records.
2. Adds user-mode access evidence from CAPE where kernel ETW cannot observe the
   required API semantics.
3. Converts events to the downstream `data_type`, `api_call`, process, and UTC
   timestamp contract.
4. Applies a valid per-task clock measurement and preserves its uncertainty.
5. Rejects or downgrades correlation when timing cannot satisfy the consumer's
   correlation window.

Tasks 6 and 7 do not have a trustworthy per-task start/end clock measurement.
Their PCAP and ETL are valid standalone artifacts, but precise cross-timeline
correlation must not be claimed for those runs.

The pinned C2/Exfiltration subtree was exercised against task 7's original
PCAP. It produced one weak network beacon finding for `5.149.249.242:80` in
`/srv/winstdt/c2-results/7/`. Provenance records that fixture events were not
used and host/network correlation was disabled. This validates network-only
integration, not the pending clock-corrected host/network acceptance case.

The host has approximately 400 GiB free on the filesystem containing
`/srv/winstdt` and `/var/lib/libvirt/images`; existing libvirt images occupy
about 28 GiB. This is sufficient for a small gateway disk. A 20–32 GiB
thin-provisioned gateway disk is recommended. The host has 15 GiB RAM and about
8.5 GiB presently available, so assign the gateway 1–2 GiB and prevent it from
overlapping a Windows full-memory workload through the task scheduler.

## Network modes and interpretation

### Available now

- Drop/isolated routing: safest; captures connection attempts but provides no
  server response.
- Simulated services: can provide DNS and common application responses while
  remaining isolated. Results depend on protocol compatibility.

### Not available now

- Controlled live egress.
- Unrestricted Internet access.
- A production-ready malware-specific C2 emulation library.

The presence of `WINSTDT_LIVE_EGRESS_ENABLED` and approval variables in setup
logic is fail-closed scaffolding only. It validates that metadata was supplied;
it does not establish an egress gateway or prove containment. Controlled egress
remains under development and requires, at minimum:

- a dedicated gateway separate from the CAPE host control plane;
- destination, port, protocol, and DNS allowlisting;
- bandwidth, connection, and upload-volume ceilings;
- complete capture on both sides of translation;
- automatic expiry and emergency termination;
- prevention of access to private, local, metadata, management, and researcher
  networks;
- documented legal/operational approval; and
- repeatable negative and escape-path validation.

Until all of those controls are implemented and accepted, analyses must remain
isolated or simulated.

## Interpretation rules

- YARA no-hit is not a clean verdict.
- A PCAP containing failed connection attempts is evidence of attempted network
  behavior, not successful C2.
- Successful TCP establishment alone is not proof of exfiltration.
- Exfiltration requires evidence of outbound content or a sufficiently specific
  protocol action, with confidence and limitations recorded.
- An empty dropped-file, payload, or process-memory section is not proof that a
  capability is absent; it may not have executed or been exposed.
- ATT&CK mappings are hypotheses derived from observed evidence and signatures,
  not automatic attribution.
- A valid ETL proves trace capture, not complete provider or API-semantic
  coverage.
- A sealed image using `--allow-rejected` remains detectably virtual according
  to its recorded Pafish/al-khaser failures.

## Priority gaps

The highest-value work required to broaden analysis coverage is:

1. Enable and validate CAPA against originals, recovered payloads, and process
   dumps.
2. Enable and validate FLOSS decoded-string recovery.
3. Maintain versioned YARA rules and known-positive/negative validation cases.
4. Enable Suricata with a maintained offline ruleset.
5. Add opt-in full-memory acquisition and Volatility 3 processing with storage
   controls.
6. Improve safe simulated-service and sample-specific protocol emulation.
7. Automate start/end clock measurement inside every CAPE task lifecycle.
8. Produce the ETW/CAPE-to-access-event adapter required by the C2 module.
9. Validate TLS interception in an isolated mode where malware behavior permits
   it.
10. Implement and independently test controlled egress before making that route
    selectable.
11. Build the unified Windows/Android web interface described below.

## Required unified Windows/Android interface

The new web interface should coordinate the overall platform without replacing
CAPE, the Android analysis engine, or the C2/Exfiltration module. Its backend
should submit work through module APIs or queues and consume versioned result
and evidence contracts.

Minimum required responsibilities are:

- one authenticated sample-intake workflow with hashes, case identity, handling
  markings, and duplicate detection;
- explicit Windows, Android, or approved multi-platform target selection;
- static-only, dynamic-only, and combined-analysis profiles;
- safe route-policy selection that exposes only implemented and approved modes;
- task state, queue, timeout, VM/device allocation, and failure visibility;
- coordinated submission to CAPE for Windows and the Android analysis backend;
- normalized summaries while retaining each engine's complete native report;
- PCAP, ETL, Android telemetry, memory artifacts, dropped files, screenshots,
  reports, and integrity-manifest download where produced;
- timeline alignment and handoff to the C2/Exfiltration correlation module;
- side-by-side Windows/Android IOC, behavior, and ATT&CK/TTP comparison;
- evidence hashes, provenance, parser/tool versions, degradation warnings, and
  chain-of-custody visibility;
- role-based authorization, audit logging, retention controls, and destructive
  action confirmation; and
- clear separation between requested, running, completed, degraded, rejected,
  timed-out, and capture-error states.

The UI must not silently upgrade weak evidence into a stronger conclusion. For
example, a failed connection attempt remains attempted C2, and a missing
artifact remains missing even if another module inferred related behavior. It
must also prevent selection of controlled live egress until that route is
implemented, independently validated, and administratively enabled.

The Windows and Android execution environments should remain isolated from each
other and from the UI control plane. Cross-platform coordination belongs in the
orchestration and evidence layers, not through direct guest-to-guest access.

## Related documents

- [Host and Windows guest bootstrap](host_guest_bootstrap.md)
- [CAPE handoff export](cape_handoff_export.md)
- [Anti-evasion qualification](validation/anti_evasion_gate.md)
- [Golden-image status](validation/golden_image_report_current.md)
- [Implementation plan](../WinST-DT-Implementation-Plan.md)
- [Evaluation report](../WinST-DT-Evaluation-Report.md)
