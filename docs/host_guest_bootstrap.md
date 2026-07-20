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

Live egress remains disabled. Setting `WINSTDT_LIVE_EGRESS_ENABLED=1` only
passes the script gate when approval metadata is also supplied:
`WINSTDT_LIVE_EGRESS_APPROVAL_ID`, `WINSTDT_LIVE_EGRESS_OWNER`,
`WINSTDT_LIVE_EGRESS_DATE`, `WINSTDT_LIVE_EGRESS_ALLOWED_NETWORKS`, and
`WINSTDT_LIVE_EGRESS_RATE_LIMIT`.

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
current `/opt/CAPEv2/agent/agent.py` on alternate port `8001`. This proves the
guest can run the modern CAPE agent with `execpy`, `logs`, and `subdir_upload`
without killing the only working control channel. CAPE itself still uses
hardcoded guest port `8000`, so primary replacement must be done while resealing
the golden image rather than by changing CAPE configuration.

The benign detonation validation payload is
`scripts/validation/Invoke-BenignDetonation.ps1`. Submit it through CAPE after
ETW validation; it exercises child process, file, registry, DNS, and simulated
HTTP egress behavior.

For al-khaser/Pafish evidence collection, stage those tool binaries into the
guest and run `Invoke-AntiEvasionCollection.ps1`. It records tool hashes, stdout,
stderr, timeout status, and system context under
`C:\ProgramData\WinSTDT\validation\anti-evasion\` for manual strict-subset
mapping into the golden image report.

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
