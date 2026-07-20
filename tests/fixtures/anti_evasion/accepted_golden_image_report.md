# Golden Image Anti-Evasion Validation Report

## Run Metadata

| Field | Value |
|---|---|
| Report ID | anti-evasion-accepted-example |
| Validation date | 2026-07-19 |
| Validator | example fixture |
| Golden image build ID | win10-22h2-vmcloak-20260719-hardened-a |
| Golden image path/snapshot | example only |
| CAPEv2 git ref | example-cape-ref |
| CAPEv2 `kvm-qemu.sh` used | Yes |
| VMCloak build date | 2026-07-19 |
| Post-hardening script/ref | example-hardening-ref |
| Windows edition/version/build | Windows 10 22H2 x64, example build |
| CPU/RAM/disk configuration | 4 vCPU / 8 GB RAM / 80 GB disk |
| al-khaser version/ref | example-al-khaser-ref |
| Pafish version/ref | example-pafish-ref |

## Detonation Sanity Check

| Check | Result | Evidence/notes |
|---|---|---|
| CAPEv2 stock benign detonation completed | Pass | Example fixture. |
| Guest booted from hardened snapshot | Pass | Example fixture. |
| CAPE agent reachable | Pass | Example fixture. |
| Result retrieval completed | Pass | Example fixture. |

## Required Gate Results

| Category | al-khaser | Pafish | Evidence/notes |
|---|---|---|---|
| SMBIOS/DMI vendor/product/serial checks | Pass | Pass | No obvious default virtualization strings in scoped checks. |
| BIOS/firmware strings where configurable | Pass | Pass | Configurable firmware strings normalized. |
| Obvious QEMU/KVM/VMware/VirtualBox registry artifacts | Pass | Pass | No scoped registry artifact failures. |
| Hostname/username/workgroup blacklist checks | Pass | Pass | Names avoid analysis/default terms. |
| Obvious sandbox/security-tool process/service-name checks | Pass | Pass | No scoped process/service naming failures. |
| Default QEMU disk/CD-ROM/device strings where configurable | Pass | Pass | Configurable device strings normalized. |
| CPU count | Pass | Pass | Meets baseline. |
| RAM size | Pass | Pass | Meets baseline. |
| Disk size/free space | Pass | Pass | Meets baseline. |
| Recent files not empty | Pass | N/A | Profile seeded. |
| Browser profile not empty | Pass | N/A | Browser seeded. |
| Normal installed software present | Pass | N/A | Baseline user software present. |
| Downloads/TEMP profile patterns not pristine | Pass | N/A | Profile directories seeded. |
| Boot warm-up and human-interaction evidence | Pass | N/A | Warm-up and interaction simulation enabled. |

## Non-Blocking Findings

| Category | al-khaser | Pafish | Residual-risk note |
|---|---|---|---|
| RDTSC/timing checks | Fail | Fail | Accepted residual risk for MVP. |
| CPUID timing side channels | Fail | Fail | Accepted residual risk for MVP. |
| Debugger checks | N/A | Pass | No blocking impact. |
| Deep hypervisor introspection | Fail | Fail | Accepted residual risk for MVP. |
| Requires driver modification/re-signing | N/A | N/A | Out of MVP scope. |
| Requires custom QEMU build | N/A | N/A | Out of MVP scope. |
| Requires kernel-level patching | N/A | N/A | Out of MVP scope. |
| Malware-specific bypass-code category | N/A | N/A | Out of MVP scope. |

## Decision

| Field | Value |
|---|---|
| MVP gate decision | Accepted |
| Rejection reason, if any | N/A |
| Required follow-up before use | None for MVP gate. |
| Residual risk accepted by | example approver |

## Attachments

- al-khaser output: example path
- Pafish output: example path
- CAPEv2 benign detonation task/report: example path
- Guest hardening logs: example path
