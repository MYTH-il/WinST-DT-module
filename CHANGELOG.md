# Changelog

All notable project changes since the implementation plan was finalized are recorded here.

## Unreleased

Baseline: finalized WinST/DT implementation plan with CAPEv2 rolling release, VMCloak-built Windows 10 22H2 x64 guest, CAPE-native orchestration, raw ETW `.etl` handoff, graceful provider degradation, and `capemon` retained during MVP validation.

### Planning and Scope

- Updated the implementation plan to lock behavioral telemetry handoff to raw ETW `.etl`:
  - MVP artifact is `behavior/trace.etl`.
  - EVTX handoff, EVTX conversion, and JSONL conversion are out of the MVP contract.
  - Future structured export remains `behavior/events.jsonl` after C2/Exfiltration schema agreement.
- Updated telemetry failure semantics:
  - Missing or unusable ETL is `capture_error`.
  - Missing optional analytical providers set `telemetry.telemetry_degraded = true`.
  - `Microsoft-Windows-Kernel-Image` and ETW-TI are optional/best-effort.
- Reworked provider language from "required providers" to "required capture capability":
  - telemetry agent must start
  - trace session must run
  - non-empty `.etl` must be retrieved
  - provider availability must be recorded
- Kept `capemon` enabled for MVP validation while ETW coverage is compared side-by-side.
- Added the strict-subset al-khaser/Pafish validation gate as an MVP golden-image acceptance requirement.
- Recorded that no driver modification, driver re-signing, custom QEMU patching, or kernel patching is in MVP scope.

### Rust Tooling

- Created the Rust project with `Cargo.toml`, `Cargo.lock`, and `src/main.rs`.
- Added the `winstdt` CLI surface:
  - `validate-bundle`
  - `mock-consume`
  - `report-bundle`
  - `compare-telemetry`
  - `cleanup-handoff`
  - `monitor-health`
  - `pretriage`
  - `etw-agent start`
  - `etw-agent stop`
  - `etw-agent write-metadata`
- Implemented handoff bundle validation for:
  - `manifest.json`
  - `sample.meta.json`
  - `network/capture.pcapng`
  - `behavior/trace.etl`
  - `hashes.sha256`
- Enforced ETL-only MVP artifact paths:
  - `artifact_paths.trace_etl = behavior/trace.etl`
  - `telemetry.artifact_path = behavior/trace.etl`
- Added graceful degradation checks:
  - degraded telemetry must include degradation reasons
  - unavailable ETW-TI or analytical providers do not invalidate an otherwise usable trace
  - missing/corrupt required artifacts fail the bundle
- Added a mock C2 consumer that can watch and load completed handoff bundles.
- Added static pre-triage support for file type, hashes, PE-like metadata, entropy, strings, and YARA tier hooks.
- Wired static pre-triage to optional local scanner execution:
  - `WINSTDT_YARA_FAST_RULES`
  - `WINSTDT_YARA_DEEP_RULES`
  - local `clamscan` unless `WINSTDT_DISABLE_CLAMAV=1`
  - VirusTotal hash lookup only when `VIRUSTOTAL_API_KEY` or `VT_API_KEY` is set
- Added unit tests in Rust for valid, degraded, invalid, pre-triage, and ETW metadata paths.
- Added JSON/HTML analyst report generation from one shared report model.
- Added telemetry comparison output that keeps `capemon` enabled unless configured coverage data supports disabling it.
- Added handoff retention cleanup and local health monitoring commands.

### Schemas and Fixtures

- Added `schemas/handoff_manifest.schema.json`.
- Added `schemas/sample_meta.schema.json`.
- Added `schemas/report.schema.json`.
- Added `schemas/events.schema.json`.
- Added `schemas/runtime_config.schema.json`.
- Updated manifest contract for:
  - `telemetry.format = etl`
  - `telemetry.telemetry_degraded`
  - provider targeted/enabled/unavailable metadata
  - `etw_ti_status`
  - `artifact_paths.trace_etl`
  - optional `artifact_paths.report_json`
  - optional `artifact_paths.report_html`
  - optional `artifact_paths.events_jsonl`
  - optional `signature`
  - optional `retention_policy`
- Added handoff fixture bundles:
  - valid complete bundle
  - degraded optional-provider bundle
  - invalid missing-ETL bundle
- Added pre-triage fixtures:
  - plain text sample
  - pseudo-PE sample
- Added anti-evasion validation report fixtures:
  - accepted golden image report
  - rejected golden image report

### CAPEv2 Handoff Export

- Added CAPE reporting module:
  - `cape/modules/reporting/winstdt_handoff_export.py`
- Added CAPE reporting configuration overlay:
  - `cape/custom/conf/reporting.conf.d/winstdt_handoff_export.conf`
- Implemented atomic handoff bundle export under `/srv/winstdt/handoff/{session_id}`.
- Exporter copies/records:
  - CAPE PCAP as `network/capture.pcapng`
  - raw ETW trace as `behavior/trace.etl`
  - `manifest.json`
  - `sample.meta.json`
  - `report.json`
  - `report.html`
  - `hashes.sha256`
- Exporter maps missing PCAP or ETL to capture errors.
- Exporter preserves degraded telemetry as completed when the trace itself is usable.
- Exporter includes CAPE task metadata, `capemon` flag, tool versions, provider metadata, and ETW sidecar metadata where present.
- Added Python unit tests for the CAPE reporting module.
- Added documentation in `docs/cape_handoff_export.md`.

### ETW Agent Support

- Added ETW agent configuration:
  - `scripts/etw_agent/etw-agent.config.json`
- Added ETW agent documentation:
  - `scripts/etw_agent/README.md`
- Added Windows validation helper:
  - `scripts/etw_agent/Invoke-EtwAgentValidation.ps1`
- Defined Windows-side expected output paths:
  - raw ETL trace
  - telemetry metadata sidecar
- Added provider target lists and degradation reason vocabulary aligned with the manifest schema.
- Added validation behavior for non-empty ETL trace and telemetry degradation reporting.

### Guest Hardening and Anti-Evasion

- Added host-side libvirt/QEMU anti-evasion hardening:
  - `scripts/harden-libvirt-domain.py`
  - injects SMBIOS/sysinfo OEM values
  - sets KVM hidden state and Hyper-V vendor override
  - adds QEMU ACPI OEM ID/table ID machine options
  - disables the virtio balloon device
  - sets stable disk serials
  - uses libvirt `qemu:override` to present a non-QEMU disk model
  - enforces a 160 GB minimum VM disk size
- Updated the runtime snapshot default to `hardened-baseline-antievasion-v1`.
- Expanded guest hardening:
  - requires 4 logical CPUs, 8 GB RAM, 150 GB disk, and 50 GB free space
  - expands C: to the supported maximum size during apply
  - rejects obvious VM hardware strings
  - seeds profile directories and runs a desktop warm-up
- Re-ran al-khaser/Pafish evidence collection after hardware identity remediation:
  - evidence: `docs/validation/evidence/anti-evasion-20260720-223908/`
  - Windows now reports `Manufacturer=DELL`, `Model=CBX3`
  - disk now reports `WDC WD5000LPCX-75VHAT0`
  - C: expanded to about 160 GB
  - al-khaser disk-size, `SetupDi_diskdrive`, and QEMU registry checks are now `GOOD`
  - Pafish no longer emits Bochs/QEMU BIOS/disk markers
  - remaining required blockers: user-input/mouse evidence, fresh-boot uptime, and one al-khaser ACPI table string finding
  - remaining non-blocking residuals: CPUID hypervisor bit, RDTSC forced-VM-exit timing, WMI fan, and WMI `Win32_SMBIOSMemory` inventory realism
- Added guest hardening scaffold:
  - `scripts/guest_hardening/Invoke-GuestHardening.ps1`
  - `scripts/guest_hardening/example.config.json`
  - `scripts/guest_hardening/README.md`
- Scoped MVP guest hardening to post-VMCloak cleanup and realism improvements.
- Added anti-evasion gate documentation:
  - `docs/validation/anti_evasion_gate.md`
- Added golden image validation report template:
  - `docs/validation/golden_image_report_template.md`
- Documented required MVP validation categories:
  - SMBIOS/DMI strings
  - firmware strings where configurable
  - registry virtualization artifacts
  - host/user/profile names
  - obvious sandbox/security-tool process and service names
  - CPU/RAM/disk realism
  - recent files, browser profile, installed software, downloads/temp profile patterns
  - boot warm-up and interaction evidence
- Documented non-blocking residual-risk categories:
  - RDTSC/timing checks
  - CPUID timing side channels
  - deep hypervisor introspection
- Added benign Windows validation payload:
  - `scripts/validation/Invoke-BenignDetonation.ps1`
  - covers child process, file, registry, DNS, and simulated HTTP egress behavior
- Added CAPE guest-agent staging/validation helper:
  - `scripts/stage-cape-guest-agent.sh`
  - validates current guest agent features
  - stages current CAPE `agent.py` on alternate port `8001`
  - leaves primary port `8000` replacement gated for golden-image reseal
- Added anti-evasion evidence collection helper:
  - `scripts/validation/Invoke-AntiEvasionCollection.ps1`
  - records al-khaser/Pafish hashes, stdout/stderr, timeout status, and system context
  - leaves strict-subset pass/fail mapping as an explicit manual report step
- Added host-side anti-evasion validation wrapper:
  - `scripts/validation/run-anti-evasion-validation.sh`
  - stages local al-khaser/Pafish binaries through the CAPE guest agent
  - runs the in-guest collector
  - retrieves the zipped evidence under `docs/validation/evidence/`
- Added report drafting helper:
  - `scripts/validation/draft-golden-image-report.py`
  - pre-fills metadata, evidence paths, tool hashes, and runtime proof references
  - intentionally leaves strict-subset pass/fail rows pending for human review
- Built Pafish from source for anti-evasion validation:
  - source checkout: `/srv/winstdt/tools/pafish`
  - upstream commit: `b497899ff355ea7b9ecc1f5cd34a9fd1def02aec`
  - built standard x86/x64 binaries with MinGW
  - built a local WinST/DT unattended x64 validation binary that disables Pafish interactive RTT checks and final keypress wait
  - unattended binary: `/srv/winstdt/tools/bin/pafish64-winstdt-unattended.exe`
  - unattended SHA-256: `d387c969a0933250fd79258819a5c92284db2b6f36be24ded3b5429ea74c3f9b`
- Ran initial anti-evasion evidence collection in the Windows guest:
  - initial rejected evidence run: `docs/validation/evidence/anti-evasion-20260720-214438/`
  - downloaded al-khaser release `v1.1.0` x64 archive from GitHub releases
  - al-khaser archive SHA-256: `c38383b12b378e50d0a82b65290a9244c2bf5867ff1ab7fcfac6d399ae820b2e`
  - extracted al-khaser EXE SHA-256: `0cd8a40ff7ceef9c1368446d6ead91549681e88fdfa0f9f5a63c03fe38420baf`
  - installed Microsoft VC++ x64 runtime in the live guest because the release EXE requires `MSVCP140.dll`
  - al-khaser release EXE executed with scoped MVP-relevant arguments and produced stdout plus `log.txt`
  - Pafish found required failures in BOCHS SMBIOS/model, BOCHS BIOS string, and QEMU SCSI identifier.
  - al-khaser found required failures in WMI/core/disk/device/ACPI/user-interaction categories.
  - Pafish found non-blocking residual failures in RDTSC/CPUID hypervisor checks.
  - `docs/validation/golden_image_report_current.md` remains rejected with concrete al-khaser and Pafish findings.
- Cloned al-khaser source under `/srv/winstdt/tools/al-khaser` at commit `f0e5559073fe02c4f50cc8c3ed8d5b302a6a0659`; local Linux and guest environments do not currently have MSBuild/NuGet, so a source build remains pending Visual Studio Build Tools if mappable release output is insufficient.

### Host and Guest Bootstrap

- Added host/guest bootstrap documentation:
  - `docs/host_guest_bootstrap.md`
- Added the single maintained Ubuntu 24.04 setup script:
  - `scripts/setup-ubuntu24-host.sh`
- Added CAPE runtime closure script:
  - `scripts/configure-cape-runtime.sh`
  - targets the live `/opt/CAPEv2` systemd checkout
  - repairs stale Python `libvirt` bindings that require the wrong host
    `libvirt.so` symbol version
  - writes WinST/DT `kvm.conf` machine configuration
  - installs the reporting overlay into the live CAPE tree
  - creates/checks the libvirt domain and `hardened-baseline` snapshot
  - supports gated multi-VM KVM config with `WINSTDT_VM_COUNT`
  - refuses live egress activation without approval metadata
  - pins MongoDB to `8.0.4` on kernel 6.19+/7.x hosts as an explicit compatibility exception
  - enforces local-only MongoDB binding and package holds during readiness post-check
  - restarts MongoDB/CAPE services and runs a readiness post-check
- Implemented stable checklist-style setup dashboard:
  - `[✓]` done
  - `[-]` skipped
  - `[~]` working
  - `[!]` failed
  - per-phase logs
  - aggregate `errors.log`
- Setup logs are written under:
  - `/srv/winstdt/logs/setup/<run-id>/`
- Added resumable/idempotent setup phases:
  - Ubuntu 24.04 preflight
  - APT package setup
  - Rust toolchain
  - users/directories
  - libvirt isolated network
  - CAPEv2 rolling release
  - VMCloak
  - WinST/DT binaries
  - CAPE reporting overlay
  - Windows guest build
- Added `--execute`, `--windows-iso`, `--skip-cape-installers`, `--rerun-cape-installers`, `--log-dir`, and `--fail-phase`.
- Added cached-sudo preflight so the script fails clearly if it cannot run unattended.
- Added command timeout logging through `COMMAND_TIMEOUT_SECONDS`.
- Added host directory layout under `/srv/winstdt`.
- Added install of built Linux and Windows Rust binaries to `/srv/winstdt/bin`.
- Added install of ETW agent files to `/srv/winstdt/scripts/etw_agent`.
- Added install of CAPE reporting overlay into `/opt/CAPEv2`.

### Host Setup Repairs From This Device

- Fixed Ubuntu package naming:
  - replaced unavailable `virt-install` package with `virtinst`
  - added `genisoimage`
  - handled installed `qemu-system-x86_64` and `qemu-img` by command availability
- Added noninteractive APT behavior:
  - `DEBIAN_FRONTEND=noninteractive`
  - `NEEDRESTART_MODE=a`
  - `APT_LISTCHANGES_FRONTEND=none`
  - dpkg force-conf defaults
  - Wireshark debconf preseed
- Added broken package-state recovery:
  - `dpkg --configure -a`
  - `apt-get --fix-broken install`
- Detected and removed foreign `qemu 9.2.2` package that blocked Ubuntu QEMU packages.
- Quarantined source-installed libvirt libraries and unowned libvirt daemons/systemd units that shadowed Ubuntu libvirt.
- Switched libvirt control to packaged `libvirtd` using explicit URI:
  - `qemu+unix:///system?socket=/run/libvirt/libvirt-sock`
- Added `LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu` around `virsh` calls to avoid shadowed libraries.
- Made libvirt network setup idempotent:
  - already-defined network is accepted
  - already-active network is accepted
  - autostart is only applied when needed
- Configured QEMU bridge helper for VMCloak:
  - `/etc/qemu/bridge.conf`
  - `allow virbr-winstdt`
  - setuid on `/usr/lib/qemu/qemu-bridge-helper`
- Fixed CAPEv2 checkout handling:
  - chown `/opt/CAPEv2` to the configured CAPE user
  - run updates as CAPE user
  - use installer marker files under `/srv/winstdt/setup-state`
- Changed VMCloak installation from broken PyPI path to GitHub checkout in a virtualenv:
  - `/srv/winstdt/tools/vmcloak/venv`
  - symlinked `/usr/local/bin/vmcloak`
  - pinned/reinstalled `setuptools<81` for `pkg_resources` compatibility
- Patched VMCloak ISO generation for modern Windows media:
  - added `-allow-limited-size`
- Patched VMCloak Windows 10 unattended template for 22H2:
  - removed `ShowWindowsLive`
  - removed obsolete Defender `DisableAntiSpyware` component
- Changed VMCloak Windows media handling:
  - mounted Windows ISO at `/mnt/winstdt-win10-iso`
  - used `--iso-mount` rather than direct `--iso`
- Fixed guest addressing:
  - host/gateway remains `10.66.0.1`
  - guest IP is `10.66.0.101`
- Enabled VMCloak guest VNC/VRDE for validation:
  - `--vrde --vrde-port 1`
  - viewer path is `gvncviewer localhost:1`
- Made existing VMCloak image detection use `vmcloak list images`.
- Added stale VMCloak qcow2/ISO cleanup only when an image file exists without VMCloak registration.
- Made baseline guest software seeding optional and non-blocking:
  - default `VMCLOAK_BASELINE_DEPS=""`
  - old VMCloak Firefox/Chrome download 404s no longer fail guest build
  - unsupported `7zip` no longer blocks setup
- Completed setup successfully on this device with:
  - `scripts/setup-ubuntu24-host.sh` version `v0.21`
  - log directory `/srv/winstdt/logs/setup/20260720T131931Z`
  - no failed phases

### Local Setup Artifacts

- Moved the licensed Windows 10 ISO to project root:
  - `Win10_22H2_x64.iso`
- Updated `.gitignore` so ISO files are not committed.
- Confirmed VMCloak image exists:
  - `winstdt-win10-22h2`
- Confirmed image disk is present:
  - `~/.vmcloak/image/winstdt-win10-22h2.qcow2`
- Confirmed libvirt isolated network is active:
  - `winstdt-isolated`
  - bridge `virbr-winstdt`

### Documentation

- Added setup audit:
  - `docs/setup_shortcuts_and_remediations.md`
- The setup audit records:
  - shortcut/overlooked requirement
  - failure mode
  - remediation
  - essential/non-essential judgment
  - pros/cons
  - orchestration impact
  - anti-VM and anti-sandbox impact
- Added and updated validation and bootstrap docs listed above.

### Validation Performed

- Ran Rust unit tests during implementation.
- Ran Python reporting-module unit tests during implementation.
- Ran `cargo build --release`.
- Ran `cargo build --release --target x86_64-pc-windows-gnu`.
- Ran setup script syntax checks.
- Ran repeated real setup executions on the Ubuntu 24.04 host until all phases passed.
- Verified VMCloak image registration.
- Verified QCOW2 image existence and non-corrupt qemu-img status during setup debugging.
- Verified isolated libvirt network active state.
- Ran `scripts/configure-cape-runtime.sh --execute` successfully on 2026-07-20.
- Verified CAPE machinery configuration and the `hardened-baseline` snapshot for `winstdt-win10-22h2`.
- Ran CAPE benign validation task `2` and exported a real handoff bundle at `/srv/winstdt/handoff/2`.
- Verified `network/capture.pcapng` and `behavior/trace.etl` are present together in the handoff bundle.
- Ran the Rust bundle validator, mock C2 consumer, and telemetry comparison against the real bundle.
- Ran guest hardening dry-run/apply and ETW validation inside the Windows guest.
- Verified MongoDB `8.0.4` compatibility pin, package holds, localhost-only binding, and CAPE service readiness.
- Capped the Windows ETW agent trace session at 64 MB using circular binary ETL output so CAPE result uploads stay below the configured upload limit.
- Resealed the runtime snapshot as `hardened-baseline-agent022-etw-cap64`.
- Later anti-evasion remediation resealed the current runtime snapshot as
  `hardened-baseline-antievasion-v1`.
- Fixed WinST/DT ETW pickup to upload through CAPE's allowed `aux/` result path and taught the reporting module to normalize those artifacts into the handoff contract.
- Ran CAPE benign validation task `11` through the full analyzer path:
  - CAPE stored `aux/trace.etl` at 49,299,456 bytes, `aux/telemetry.json`, `aux/etw_state.json`, and `dump.pcap`.
  - WinST/DT exported `/srv/winstdt/handoff/11` with `behavior/trace.etl`, `network/capture.pcapng`, `manifest.json`, `sample.meta.json`, `report.json`, `report.html`, and `hashes.sha256`.
  - `/srv/winstdt/bin/winstdt validate-bundle /srv/winstdt/handoff/11` accepted the bundle with `status=Completed`.
  - `/srv/winstdt/bin/winstdt mock-consume /srv/winstdt/handoff --once` accepted the completed task `11` bundle.
  - `compare-telemetry` reported `etw_enabled=4/6`, `telemetry_degraded=true`, and `decision=keep_capemon_enabled`.

### Known Remaining MVP Work

- Complete al-khaser/Pafish strict-subset gate.
- Fill the golden image validation report with al-khaser/Pafish evidence and formally accept or reject the image.

### Deliberate Deferrals

- EVTX handoff and EVTX conversion.
- Structured `events.jsonl` until C2/Exfiltration schema agreement.
- Disabling `capemon` before ETW-vs-capemon comparison data exists.
- Browser/app realism seeding through stale VMCloak remote URLs.
- Custom QEMU or kernel patching.
- Driver modification or re-signing.
- Multi-VM detonation pool.
- Windows 11 guest variant.
- Signed evidence manifest and HSM/timestamp-backed chain of custody.
