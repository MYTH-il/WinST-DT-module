# WinST/DT Malware Analysis Module

WinST/DT is a Windows static- and dynamic-malware-analysis platform built around
CAPEv2, KVM/libvirt, a hardened Windows 10 22H2 guest, CAPE's user-mode monitor,
and an additional ETW capture agent. Each completed analysis is exported as a
validated, hash-manifested handoff bundle containing the CAPE report, network
capture, and raw Windows telemetry.

The project is suitable for isolated malware-research and ST/DT evaluation. It
is not a claim of parity with every commercial malware-analysis platform. See
[Current stack and capability status](docs/current_stack.md) for the precise
deployed coverage and known gaps.

## C2/Exfiltration module acknowledgment

WinST/DT embeds the **C2-Exfil-E-Rakshak** network analysis module from
[demistifying/C2-Exfil-E-Rakshak](https://github.com/demistifying/C2-Exfil-E-Rakshak)
as a pinned Git subtree. The upstream project was created and is maintained by
[Raghav Shrivastav (`demistifying`)](https://github.com/demistifying). We are
grateful for his C2/exfiltration detection, correlation, provenance, and IOC
export work; WinST/DT does not claim authorship of that module.

Questions, doubts, bug reports, or design discussions about the upstream module
should be checked against its [actual repository and documentation](https://github.com/demistifying/C2-Exfil-E-Rakshak)
first. WinST/DT-specific questions—CAPE handoff generation, clock correction,
adapter behavior, deployment, and derived-result storage—belong to this
repository. The embedded copy is pinned and may lag upstream.

## Important network limitation

**Controlled live-egress testing is not currently implemented or available.**
Analyses must use an isolated/drop route or simulated services. The live-egress
configuration examples and approval environment variables are design gates
only: setting them does not create a working live-egress route.

Controlled live egress is under development. It must not be advertised or used
until routing enforcement, destination allowlisting, DNS controls, rate and
volume limits, complete capture, automatic expiry, emergency shutdown, and an
end-to-end isolation test have been implemented and approved.

Simulated networking can reveal attempted C2 destinations, connection cadence,
DNS queries, and supported application traffic. It cannot prove successful C2
or exfiltration when the simulator does not provide the protocol response the
sample expects.

## Unified web interface requirement

The platform needs a new unified UI/web interface to operate and coordinate both
the Windows and Android malware-analysis modules. The existing CAPE website is
useful for Windows task submission and report viewing, but it is not the final
cross-platform operator interface.

The new interface is under development. It should provide one controlled entry
point for sample intake, target-platform selection, static and dynamic task
submission, route-policy selection, progress and VM/device-state monitoring,
report comparison, artifact download, and cross-module C2/exfiltration
correlation. It must preserve the Windows and Android modules as separate
execution and trust boundaries and consume their versioned evidence contracts
instead of coupling the UI directly to guest internals.

Until that interface exists, Windows analysis is operated through CAPE and the
WinST/DT command-line tooling; Android analysis remains separately operated.

## Current outputs

A successful CAPE task can produce:

```text
/srv/winstdt/handoff/{task_id}/
    manifest.json
    sample.meta.json
    network/capture.pcapng
    behavior/trace.etl
    behavior/clock-sync.json    # only when a valid per-task measurement exists
    behavior/access_events.json # classified, clock-corrected C2 input
    report.json
    report.html
    hashes.sha256
```

The raw ETL remains authoritative. CAPE/capemon calls are normalized into the
analyzer's classified `access_events.json` contract when clock quality permits;
raw `.etl` is not interchangeable with that interface. ETL corroboration and a
clock-valid end-to-end host/network acceptance run remain pending.

## Setup

The scripts are resumable and default to dry-run mode. A licensed Windows 10
22H2 x64 ISO is required for guest construction.

```bash
scripts/setup-ubuntu24-host.sh \
  --windows-iso /absolute/path/to/Win10_22H2_x64.iso \
  --execute

scripts/configure-cape-runtime.sh --execute

scripts/finalize-windows-guest.sh \
  --qualification-only \
  --al-khaser /path/to/al-khaser.exe \
  --pafish /path/to/pafish.exe \
  --execute
```

Review the generated anti-evasion evidence before sealing. For isolated ST/DT
testing where documented anti-evasion failures are knowingly accepted, use the
short override while still retaining qualification and telemetry checks:

```bash
scripts/finalize-windows-guest.sh \
  --seal-approved \
  --allow-rejected \
  --acceptance-report docs/validation/golden_image_report_current.md \
  --execute
```

Then apply the runtime configuration and run the benign end-to-end acceptance
test:

```bash
scripts/configure-cape-runtime.sh --execute
scripts/validate-deployment.sh --execute
```

Full setup and recovery details are in
[Host and guest bootstrap](docs/host_guest_bootstrap.md).

## Analysis and evidence

Submit samples through the locally hosted CAPE interface or API and select an
isolated/simulated route. Do not enable real Internet access for a malware VM.
After processing, validate the exported evidence:

```bash
winstdt validate-bundle /srv/winstdt/handoff/{task_id}
winstdt report-bundle /srv/winstdt/handoff/{task_id} \
  --json report.json --html report.html
winstdt compare-telemetry /srv/winstdt/handoff/{task_id}
```

Whether an artifact exists and whether it contains useful behavior are separate
questions. For example, a valid PCAP containing only failed TCP attempts does
not demonstrate exfiltration, and an empty process-memory result is not proof
that no unpacked payload existed.

## Documentation

- [Current stack and capability status](docs/current_stack.md)
- [Host and Windows guest bootstrap](docs/host_guest_bootstrap.md)
- [CAPE handoff export](docs/cape_handoff_export.md)
- [C2/Exfiltration integration](docs/c2_exfil_integration.md)
- [Anti-evasion qualification gate](docs/validation/anti_evasion_gate.md)
- [Implementation plan](WinST-DT-Implementation-Plan.md)
- [Evaluation report](WinST-DT-Evaluation-Report.md)

## Safety boundary

Run malware only in disposable guests attached to the isolated analysis
network. Preserve the golden image, revert after every task, keep CAPE services
and MongoDB locally bound, and treat every sample and generated artifact as
hostile. Never copy analysis artifacts to ordinary user systems without the
appropriate containment controls.
