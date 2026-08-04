# WinST/DT Host and Windows Guest Bootstrap

There is one setup entry point:

```bash
scripts/setup-ubuntu24-host.sh
```

The script is a stable dashboard runner. It keeps one checklist on screen,
records per-component logs, and reports the exact log file for any failed
component.

Default logs:

```text
/srv/winstdt/logs/setup/<run-id>/
    01-ubuntu.log
    02-apt.log
    03-rust.log
    04-layout.log
    05-network.log
    06-cape.log
    07-vmcloak.log
    08-build.log
    09-overlay.log
    10-guest.log
    errors.log
```

Close the CAPE runtime gap after host bootstrap:

```bash
scripts/configure-cape-runtime.sh --execute
```

Finalize the Windows guest after the runtime script has registered its libvirt
domain. This step installs the current CAPE agent and ETW collector, applies the
guest hardening profile, validates ETW across a cold boot, and replaces the
hardened running-state snapshot:

```bash
scripts/finalize-windows-guest.sh \
  --qualification-only \
  --al-khaser /path/to/al-khaser.exe \
  --pafish /path/to/pafish.exe \
  --execute
# Review the new evidence into golden_image_report_current.md. Sealing is
# deliberately blocked until every required row is Pass/N/A and the decision is Accepted.
scripts/finalize-windows-guest.sh \
  --seal-approved \
  --acceptance-report docs/validation/golden_image_report_current.md \
  --execute
```

Finally, run the automated deployment acceptance gate. It submits only the
repository's controlled benign PowerShell payload through the isolated INetSim
route and fails unless CAPE exports both non-empty PCAP and ETL artifacts in a
schema-valid completed handoff:

```bash
scripts/validate-deployment.sh --execute
```

The complete automated order for a new host is therefore:

```bash
scripts/setup-ubuntu24-host.sh --windows-iso /absolute/path/to/Win10_22H2_x64.iso --execute
scripts/configure-cape-runtime.sh --execute
scripts/finalize-windows-guest.sh --qualification-only \
  --al-khaser /path/to/al-khaser.exe --pafish /path/to/pafish.exe --execute
# After evidence review and an Accepted report:
scripts/finalize-windows-guest.sh --seal-approved \
  --acceptance-report docs/validation/golden_image_report_current.md --execute

For isolated ST/DT testing where documented anti-evasion failures are accepted,
add `--allow-rejected`. This does not bypass qualification, guest sanitization,
cold-boot readiness, or telemetry requirements.
scripts/configure-cape-runtime.sh --execute
scripts/validate-deployment.sh --execute
```

This configures the live CAPE checkout under `/opt/CAPEv2`, repairs the
Python `libvirt` binding mismatch when a stale `/usr/local` binding shadows the
Ubuntu package, writes the WinST/DT KVM machine config, installs the reporting
overlay, creates/checks the libvirt domain and `hardened-baseline` running
snapshot, restarts MongoDB/CAPE services, and fails if the post-check cannot
prove runtime readiness.

On hosts running Linux kernel `6.19+`/`7.x`, the runtime script intentionally
pins MongoDB packages to `8.0.4` with `apt-mark hold`. This is a compatibility
exception for CAPE on the current host kernel, not the preferred security
baseline. The compensating control is strict local-only binding:

```yaml
net:
  port: 27017
  bindIp: 127.0.0.1
```

The runtime post-check fails if MongoDB listens on `0.0.0.0`, a LAN address, or
the guest bridge. Revisit the pin when MongoDB publishes a fixed secure build for
kernel `6.19+`, the host moves below kernel `6.19`, MongoDB moves into a
dedicated compatible-kernel VM, or this host becomes network-exposed.

For a disabled-by-default multi-VM pool, set `WINSTDT_VM_COUNT` before running
the runtime closure script. VM definitions use addresses beginning at
`10.66.0.101`; count `1` preserves the MVP domain name
`winstdt-win10-22h2`.

Live egress remains disabled. **No controlled live-egress route is currently
implemented or available for testing or analysis; it is under development.**
Setting `WINSTDT_LIVE_EGRESS_ENABLED=1` only passes a fail-closed metadata gate
when approval metadata is also supplied:
`WINSTDT_LIVE_EGRESS_APPROVAL_ID`, `WINSTDT_LIVE_EGRESS_OWNER`,
`WINSTDT_LIVE_EGRESS_DATE`, `WINSTDT_LIVE_EGRESS_ALLOWED_NETWORKS`, and
`WINSTDT_LIVE_EGRESS_RATE_LIMIT`.

Passing this gate does not create a gateway, apply network containment, or make
live egress safe or operational. Use only isolated/drop or simulated-service
routes until the controls listed in `docs/current_stack.md` are implemented and
accepted.

Disabled extension profiles live under `config/`:

```text
config/runtime.gates.example.json
config/windows11.profile.json
config/live_egress.route.example.json
```

The Windows 11 profile documents TPM, Secure Boot, and VBS requirements and must
not block the Windows 10 22H2 MVP path.

Dry-run:

```bash
scripts/setup-ubuntu24-host.sh
```

Execute setup:

```bash
scripts/setup-ubuntu24-host.sh --execute
```

Execute setup and build the Windows guest when a licensed Windows 10 22H2 x64
ISO is available:

```bash
scripts/setup-ubuntu24-host.sh \
  --windows-iso ./Win10_22H2_x64.iso \
  --execute
```

Force CAPE installer phases to rerun:

```bash
scripts/setup-ubuntu24-host.sh \
  --rerun-cape-installers \
  --execute
```

The setup flow is resumable. It skips installed apt packages, existing users,
existing directories, an already active libvirt network, an existing VMCloak
install, and CAPE installer phases with marker files under:

```text
/srv/winstdt/setup-state/
```

After VMCloak creates the Windows guest, copy the installed guest payload into
the guest and run the ETW validation script as Administrator:

```text
/srv/winstdt/bin/winstdt.exe
/srv/winstdt/scripts/etw_agent/etw-agent.config.json
/srv/winstdt/scripts/etw_agent/Invoke-EtwAgentValidation.ps1
/srv/winstdt/scripts/guest_hardening/Invoke-GuestHardening.ps1
/srv/winstdt/scripts/guest_hardening/example.config.json
/srv/winstdt/scripts/validation/Invoke-AntiEvasionCollection.ps1
```

Inside the Windows guest:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\Invoke-EtwAgentValidation.ps1 -SourceBinary .\winstdt.exe -SourceConfig .\etw-agent.config.json
```

If CAPE task processing reports missing analyzer logs, validate the guest's CAPE
agent version from the host:

```bash
scripts/stage-cape-guest-agent.sh
scripts/stage-cape-guest-agent.sh --execute
```

The script probes the current port `8000` agent and, when needed, stages the
current `/opt/CAPEv2/agent/agent.py` on alternate port `8001`. CAPE itself uses
guest port `8000`, so any durable primary-agent replacement must be captured in
the runtime snapshot. The current anti-evasion remediation snapshot is
`hardened-baseline-antievasion-v1`.

The CAPE runtime script applies the host-side anti-evasion profile before
snapshot validation. That profile sets libvirt SMBIOS/sysinfo fields, masks the
KVM CPUID leaf where supported, sets a Hyper-V vendor override, configures ACPI
OEM ID/table ID through QEMU machine options, removes the virtio balloon device,
assigns a stable disk serial, and uses libvirt `qemu:override` to present a
non-QEMU disk model. These are standard libvirt/QEMU configuration changes; they
are not custom QEMU or kernel patches.

After host-side VM identity changes, power the guest off and start it again
before collecting evidence. Inside the guest, run
`scripts/guest_hardening/Invoke-GuestHardening.ps1 -Apply` to expand C: to the
new virtual disk size, seed profile directories, and perform the desktop
warm-up.

The benign detonation validation payload is
`scripts/validation/Invoke-BenignDetonation.ps1`. Submit it through CAPE after
ETW validation; it exercises child process, file, registry, DNS, and simulated
HTTP egress behavior.

The current benign runtime proof is CAPE task `11`. It produced analyzer logs,
`dump.pcap`, `aux/trace.etl`, `aux/telemetry.json`, and `aux/etw_state.json`;
the reporting module exported `/srv/winstdt/handoff/11` with
`behavior/trace.etl` and `network/capture.pcapng`, and the Rust validator plus
mock C2 consumer accepted the bundle.

For al-khaser/Pafish evidence collection, provide local compiled tool binaries
and run the host wrapper:

```bash
scripts/validation/run-anti-evasion-validation.sh \
  --al-khaser /path/to/al-khaser.exe \
  --pafish /path/to/pafish.exe \
  --execute
```

The wrapper stages both tools and `Invoke-AntiEvasionCollection.ps1` through the
CAPE guest agent, runs them in the guest, zips the evidence, and retrieves it
under `docs/validation/evidence/`. The guest-side collector records tool hashes,
stdout, stderr, timeout status, and system context under
`C:\ProgramData\WinSTDT\validation\anti-evasion\`.

Draft a current report from the retrieved evidence:

```bash
scripts/validation/draft-golden-image-report.py \
  docs/validation/evidence/<anti-evasion-run-id> \
  --cape-git-ref "$(git -C /opt/CAPEv2 rev-parse --short HEAD)"
```

The draft keeps every strict-subset category as `Pending review`. Fill each row
from the raw al-khaser/Pafish output and accept the image only if no required
category fails.

Static pre-triage uses local scanners when configured:

```bash
WINSTDT_YARA_FAST_RULES=/srv/winstdt/rules/yara/fast \
WINSTDT_YARA_DEEP_RULES=/srv/winstdt/rules/yara/deep \
VIRUSTOTAL_API_KEY=... \
winstdt pretriage ./sample.exe
```

`clamscan` is used automatically when present. Set
`WINSTDT_DISABLE_CLAMAV=1` to skip it. VirusTotal is a soft dependency and is
not queried unless `VIRUSTOTAL_API_KEY` or `VT_API_KEY` is set.
