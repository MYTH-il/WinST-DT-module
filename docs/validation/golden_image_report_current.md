# Golden Image Anti-Evasion Validation Report

## Run Metadata

| Field | Value |
|---|---|
| Report ID | anti-evasion-20260720T223908Z |
| Validation date | 2026-07-20 |
| Validator | WinST/DT anti-evasion evidence collector plus manual strict-subset review |
| Golden image build ID | winstdt-win10-22h2 |
| Golden image path/snapshot | hardened-baseline-antievasion-v1 |
| CAPEv2 git ref | fb1cb9307 |
| CAPEv2 `kvm-qemu.sh` used | CAPE KVM machinery active |
| VMCloak build date | Pending |
| Post-hardening script/ref | scripts/guest_hardening/Invoke-GuestHardening.ps1 |
| Windows edition/version/build | Caption=Microsoft Windows 10 Pro, Version=10.0.19045, BuildNumber=19045, OSArchitecture=64-bit |
| CPU/RAM/disk configuration | 4 logical CPUs; 8589389824 bytes RAM; disks=DeviceID=C:, Size=171482017792, FreeSpace=151091179520 |
| al-khaser version/ref | release `v1.1.0`; archive SHA-256 `c38383b12b378e50d0a82b65290a9244c2bf5867ff1ab7fcfac6d399ae820b2e`; EXE SHA-256 `0cd8a40ff7ceef9c1368446d6ead91549681e88fdfa0f9f5a63c03fe38420baf`; executed after installing Microsoft VC++ x64 runtime |
| Pafish version/ref | source `b497899ff355ea7b9ecc1f5cd34a9fd1def02aec`, WinST/DT unattended local diff; sha256=d387c969a0933250fd79258819a5c92284db2b6f36be24ded3b5429ea74c3f9b; completed=True; exit_code=unknown |

## Detonation Sanity Check

| Check | Result | Evidence/notes |
|---|---|---|
| CAPEv2 stock benign detonation completed | Pass | CAPE task 11 completed and exported a valid WinST/DT bundle |
| Guest booted from hardened snapshot | Pass | hardened-baseline-antievasion-v1 |
| CAPE agent reachable | Pass | CAPE agent was used to stage and retrieve validation evidence |
| Result retrieval completed | Pass | docs/validation/evidence/anti-evasion-20260720-223908/anti-evasion-20260720-223908 |

## Required Gate Results

Use `Pass`, `Fail`, or `N/A` after reviewing the raw tool output. Any `Fail` in this table rejects the golden image for MVP use.

| Category | al-khaser | Pafish | Evidence/notes |
|---|---|---|---|
| SMBIOS/DMI vendor/product/serial checks | Pass with WMI caveat | Pass | `system-context.json` reports `Manufacturer=DELL`, `Model=CBX3`; Pafish no longer reports Bochs BIOS markers; al-khaser `Win32_SMBIOSMemory` remains BAD and is tracked as residual WMI inventory realism |
| BIOS/firmware strings where configurable | Partial | Pass | Windows reports `bios.Version=DELL - 1`; Pafish Bochs BIOS checks no longer trigger; al-khaser still reports one ACPI table string failure |
| Obvious QEMU/KVM/VMware/VirtualBox registry artifacts | Pass | Pass | Pafish no longer emits Bochs/QEMU registry markers; al-khaser QEMU registry checks are GOOD in the scoped output |
| Hostname/username/workgroup blacklist checks | Pass | Pass | al-khaser and Pafish username/hostname/path checks passed; system context user is `Administrator`, hostname `FKLIXKSYEAGCDR`, workgroup `WORKGROUP` |
| Obvious sandbox/security-tool process/service-name checks | Pass | Pass | al-khaser process-module/process-name checks passed; Pafish VirtualBox/VMware process and service/file checks passed |
| Default QEMU disk/CD-ROM/device strings where configurable | Pass | Pass | Disk model now reports `WDC WD5000LPCX-75VHAT0`; al-khaser `SetupDi_diskdrive` and QEMU SCSI registry checks are GOOD; Pafish no longer emits QEMU SCSI marker |
| CPU count | Pass | Pass | system context reports 4 logical CPUs; Pafish CPU `<2` checks passed |
| RAM size | Pass with WMI caveat | Pass | al-khaser `GlobalMemoryStatusEx` check passed but WMI memory inventory classes report BAD; Pafish physical memory `<1GB` check passed; system context reports about 8 GB RAM |
| Disk size/free space | Pass | Pass | al-khaser hard disk size WMI, DeviceIoControl, and GetDiskFreeSpaceEx checks are GOOD; system context reports about 171.5 GB C: and 151.1 GB free |
| Recent files not empty | Pending review | Pending review | Not directly resolved by current tool output; review guest profile evidence separately |
| Browser profile not empty | Pending review | Pending review | Not directly resolved by current tool output; review browser/profile seeding separately |
| Normal installed software present | Pending review | Pending review | Not directly resolved by current tool output; review installed software inventory separately |
| Downloads/TEMP profile patterns not pristine | Pass | Pending review | guest hardening apply seeded Downloads, TEMP, and Recent entries before validation; Pafish has no equivalent direct coverage in the unattended run |
| Boot warm-up and human-interaction evidence | Fail | Fail | guest hardening ran a 90-second warm-up, but al-khaser mouse movement and lack-of-user-input checks remain BAD; Pafish uptime marker `hi_sandbox_uptime` appeared after the fresh boot |

## Non-Blocking Findings

These findings do not block MVP acceptance, but every observed failure must be recorded.

| Category | al-khaser | Pafish | Residual-risk note |
|---|---|---|---|
| RDTSC/timing checks | Not run in scoped command | Fail, non-blocking | Pafish `rdtsc forcing VM exit` check traced timing behavior; MVP records this as residual risk |
| CPUID timing side channels | Fail, non-blocking | Fail, non-blocking | al-khaser CPUID hypervisor bit/vendor checks BAD; Pafish hypervisor bit/vendor checks traced `Microsoft Hv` |
| Debugger checks | Not run in scoped command | Pass | Pafish `IsDebuggerPresent` and PEB `BeingDebugged` checks passed |
| Deep hypervisor introspection | Fail, non-blocking | Fail, non-blocking | al-khaser and Pafish CPU hypervisor checks traced virtualization; deep hypervisor mitigation remains outside MVP |
| Requires driver modification/re-signing | N/A observed | N/A observed | No current finding was mapped to driver modification or re-signing |
| Requires custom QEMU build | Partial, non-blocking | Partial, non-blocking | Libvirt/QEMU configuration removed the obvious BOCHS/QEMU SMBIOS and disk identifiers; remaining hypervisor/timing and some WMI/ACPI findings may require deeper platform work outside MVP |
| Requires kernel-level patching | N/A observed | N/A observed | No current finding was mapped to kernel patching |
| Malware-specific bypass-code category | Pending review | Pending review | Record observed failures from `docs/validation/evidence/anti-evasion-20260720-223908/anti-evasion-20260720-223908` |

## Decision

| Field | Value |
|---|---|
| MVP gate decision | Rejected |
| Rejection reason, if any | Required configurable categories improved substantially, but the image still fails boot warm-up/human-interaction evidence and has one al-khaser ACPI table string failure; Pafish also flags fresh-boot uptime after the validation reboot |
| Required follow-up before use | Add a longer pre-detonation dwell/interaction workflow that runs after boot and immediately before analysis, investigate the remaining al-khaser ACPI table string, rerun al-khaser with a longer timeout, and accept only if no required category fails |
| Residual risk accepted by | Pending |

## Attachments

- Evidence summary: `docs/validation/evidence/anti-evasion-20260720-223908/anti-evasion-20260720-223908/summary.json`
- System context: `docs/validation/evidence/anti-evasion-20260720-223908/anti-evasion-20260720-223908/system-context.json`
- al-khaser result: `docs/validation/evidence/anti-evasion-20260720-223908/anti-evasion-20260720-223908/al-khaser.result.json`
- al-khaser stdout: `docs/validation/evidence/anti-evasion-20260720-223908/anti-evasion-20260720-223908/al-khaser.stdout.txt`
- al-khaser stderr: `docs/validation/evidence/anti-evasion-20260720-223908/anti-evasion-20260720-223908/al-khaser.stderr.txt`
- al-khaser sidecar log: `docs/validation/evidence/anti-evasion-20260720-223908/anti-evasion-20260720-223908/al-khaser/log.txt`
- Pafish result: `docs/validation/evidence/anti-evasion-20260720-223908/anti-evasion-20260720-223908/pafish.result.json`
- Pafish stdout: `docs/validation/evidence/anti-evasion-20260720-223908/anti-evasion-20260720-223908/pafish.stdout.txt`
- Pafish stderr: `docs/validation/evidence/anti-evasion-20260720-223908/anti-evasion-20260720-223908/pafish.stderr.txt`
- Pafish sidecar log/markers: `docs/validation/evidence/anti-evasion-20260720-223908/anti-evasion-20260720-223908/pafish/`
- CAPEv2 benign detonation task/report: `/opt/CAPEv2/storage/analyses/11/reports/report.json`
- WinST/DT handoff bundle: `/srv/winstdt/handoff/11`
