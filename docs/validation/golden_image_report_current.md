# Golden Image Anti-Evasion Validation Report

## Run Metadata

| Field | Value |
|---|---|
| Report ID | anti-evasion-20260804T105901Z |
| Validation date | 2026-08-04 |
| Validator | WinST/DT anti-evasion evidence collector plus manual strict-subset review |
| Golden image build ID | winstdt-win10-22h2 |
| Golden image path/snapshot | hardened-baseline-antievasion-v1 |
| CAPEv2 git ref |  |
| CAPEv2 `kvm-qemu.sh` used | CAPE KVM machinery active |
| VMCloak build date | 2026-08-04 |
| Post-hardening script/ref | scripts/guest_hardening/Invoke-GuestHardening.ps1 |
| Windows edition/version/build | Caption=Microsoft Windows 10 Pro, Version=10.0.19045, BuildNumber=19045, OSArchitecture=64-bit |
| CPU/RAM/disk configuration | 4 logical CPUs; 8589389824 bytes RAM; disks=DeviceID=C:, Size=171482017792, FreeSpace=151148843008 |
| al-khaser version/ref | sha256=0cd8a40ff7ceef9c1368446d6ead91549681e88fdfa0f9f5a63c03fe38420baf; completed=True; exit_code=unknown |
| Pafish version/ref | sha256=ff24b9da6cddd77f8c19169134eb054130567825eee1008b5a32244e1028e76f; completed=True; exit_code=unknown |

## Detonation Sanity Check

| Check | Result | Evidence/notes |
|---|---|---|
| CAPEv2 stock benign detonation completed | Pass | Blocked pending anti-evasion acceptance |
| Guest booted from hardened snapshot | Pass | hardened-baseline-antievasion-v1 |
| CAPE agent reachable | Pass | CAPE agent was used to stage and retrieve validation evidence |
| Result retrieval completed | Pass | docs/validation/evidence/anti-evasion-20260804-105047 |

## Required Gate Results

Use `Pass`, `Fail`, or `N/A` after reviewing the raw tool output. Any `Fail` in this table rejects the golden image for MVP use.

| Category | al-khaser | Pafish | Evidence/notes |
|---|---|---|---|
| SMBIOS/DMI vendor/product/serial checks | Pending review | Pending review | Review raw outputs under `docs/validation/evidence/anti-evasion-20260804-105047` |
| BIOS/firmware strings where configurable | Pending review | Pending review | Review raw outputs under `docs/validation/evidence/anti-evasion-20260804-105047` |
| Obvious QEMU/KVM/VMware/VirtualBox registry artifacts | Pending review | Pending review | Review raw outputs under `docs/validation/evidence/anti-evasion-20260804-105047` |
| Hostname/username/workgroup blacklist checks | Pending review | Pending review | Review raw outputs under `docs/validation/evidence/anti-evasion-20260804-105047` |
| Obvious sandbox/security-tool process/service-name checks | Pending review | Pending review | Review raw outputs under `docs/validation/evidence/anti-evasion-20260804-105047` |
| Default QEMU disk/CD-ROM/device strings where configurable | Pending review | Pending review | Review raw outputs under `docs/validation/evidence/anti-evasion-20260804-105047` |
| CPU count | Pending review | Pending review | Review raw outputs under `docs/validation/evidence/anti-evasion-20260804-105047` |
| RAM size | Pending review | Pending review | Review raw outputs under `docs/validation/evidence/anti-evasion-20260804-105047` |
| Disk size/free space | Pending review | Pending review | Review raw outputs under `docs/validation/evidence/anti-evasion-20260804-105047` |
| Recent files not empty | Pending review | Pending review | Review raw outputs under `docs/validation/evidence/anti-evasion-20260804-105047` |
| Browser profile not empty | Pending review | Pending review | Review raw outputs under `docs/validation/evidence/anti-evasion-20260804-105047` |
| Normal installed software present | Pending review | Pending review | Review raw outputs under `docs/validation/evidence/anti-evasion-20260804-105047` |
| Downloads/TEMP profile patterns not pristine | Pending review | Pending review | Review raw outputs under `docs/validation/evidence/anti-evasion-20260804-105047` |
| Boot warm-up and human-interaction evidence | Pending review | Pending review | Review raw outputs under `docs/validation/evidence/anti-evasion-20260804-105047` |

## Non-Blocking Findings

These findings do not block MVP acceptance, but every observed failure must be recorded.

| Category | al-khaser | Pafish | Residual-risk note |
|---|---|---|---|
| RDTSC/timing checks | Pending review | Pending review | Record observed failures from `docs/validation/evidence/anti-evasion-20260804-105047` |
| CPUID timing side channels | Pending review | Pending review | Record observed failures from `docs/validation/evidence/anti-evasion-20260804-105047` |
| Debugger checks | Pending review | Pending review | Record observed failures from `docs/validation/evidence/anti-evasion-20260804-105047` |
| Deep hypervisor introspection | Pending review | Pending review | Record observed failures from `docs/validation/evidence/anti-evasion-20260804-105047` |
| Requires driver modification/re-signing | Pending review | Pending review | Record observed failures from `docs/validation/evidence/anti-evasion-20260804-105047` |
| Requires custom QEMU build | Pending review | Pending review | Record observed failures from `docs/validation/evidence/anti-evasion-20260804-105047` |
| Requires kernel-level patching | Pending review | Pending review | Record observed failures from `docs/validation/evidence/anti-evasion-20260804-105047` |
| Malware-specific bypass-code category | Pending review | Pending review | Record observed failures from `docs/validation/evidence/anti-evasion-20260804-105047` |

## Decision

| Field | Value |
|---|---|
| MVP gate decision | Rejected pending evidence review |
| Rejection reason, if any | Strict-subset category mapping has not been completed |
| Required follow-up before use | Review al-khaser/Pafish output, fill every required category, then accept only if no required category fails |
| Residual risk accepted by | Pending |

## Attachments

- Evidence summary: `docs/validation/evidence/anti-evasion-20260804-105047/anti-evasion-20260804-105047/summary.json`
- System context: `docs/validation/evidence/anti-evasion-20260804-105047/anti-evasion-20260804-105047/system-context.json`
- al-khaser result: `docs/validation/evidence/anti-evasion-20260804-105047/anti-evasion-20260804-105047/al-khaser.result.json`
- al-khaser stdout: `docs/validation/evidence/anti-evasion-20260804-105047/anti-evasion-20260804-105047/al-khaser.stdout.txt`
- al-khaser stderr: `docs/validation/evidence/anti-evasion-20260804-105047/anti-evasion-20260804-105047/al-khaser.stderr.txt`
- Pafish result: `docs/validation/evidence/anti-evasion-20260804-105047/anti-evasion-20260804-105047/pafish.result.json`
- Pafish stdout: `docs/validation/evidence/anti-evasion-20260804-105047/anti-evasion-20260804-105047/pafish.stdout.txt`
- Pafish stderr: `docs/validation/evidence/anti-evasion-20260804-105047/anti-evasion-20260804-105047/pafish.stderr.txt`
- CAPEv2 benign detonation task/report: `not-run`
- WinST/DT handoff bundle: `not-run`
