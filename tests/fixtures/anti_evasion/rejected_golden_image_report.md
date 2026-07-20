# Golden Image Anti-Evasion Validation Report

## Run Metadata

| Field | Value |
|---|---|
| Report ID | anti-evasion-rejected-example |
| Validation date | 2026-07-19 |
| Validator | example fixture |
| Golden image build ID | win10-22h2-vmcloak-20260719-hardened-b |
| Golden image path/snapshot | example only |
| CAPEv2 git ref | example-cape-ref |
| CAPEv2 `kvm-qemu.sh` used | Yes |
| VMCloak build date | 2026-07-19 |
| Post-hardening script/ref | example-hardening-ref |
| Windows edition/version/build | Windows 10 22H2 x64, example build |
| CPU/RAM/disk configuration | 2 vCPU / 4 GB RAM / 40 GB disk |
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

Any `Fail` in this table rejects the image for MVP use.

| Category | al-khaser | Pafish | Evidence/notes |
|---|---|---|---|
| SMBIOS/DMI vendor/product/serial checks | Fail | Fail | Default virtualization strings remain visible. |
| BIOS/firmware strings where configurable | Pass | Pass | Configurable firmware strings normalized. |
| Obvious QEMU/KVM/VMware/VirtualBox registry artifacts | Fail | Fail | Registry still contains scoped VM artifact values. |
| Hostname/username/workgroup blacklist checks | Pass | Pass | Names avoid analysis/default terms. |
| Obvious sandbox/security-tool process/service-name checks | Pass | Pass | No scoped process/service naming failures. |
| Default QEMU disk/CD-ROM/device strings where configurable | Fail | Fail | Default device strings remain visible. |
| CPU count | Fail | Fail | Below baseline. |
| RAM size | Fail | Fail | Below baseline. |
| Disk size/free space | Fail | Fail | Below baseline. |
| Recent files not empty | Pass | N/A | Profile seeded. |
| Browser profile not empty | Pass | N/A | Browser seeded. |
| Normal installed software present | Fail | N/A | No normal user software entries. |
| Downloads/TEMP profile patterns not pristine | Pass | N/A | Profile directories seeded. |
| Boot warm-up and human-interaction evidence | Pass | N/A | Warm-up and interaction simulation enabled. |

## Non-Blocking Findings

| Category | al-khaser | Pafish | Residual-risk note |
|---|---|---|---|
| RDTSC/timing checks | Fail | Fail | Non-blocking, but still recorded. |
| CPUID timing side channels | Fail | Fail | Non-blocking, but still recorded. |
| Debugger checks | N/A | Pass | No blocking impact. |
| Deep hypervisor introspection | Fail | Fail | Non-blocking, but still recorded. |
| Requires driver modification/re-signing | N/A | N/A | Out of MVP scope. |
| Requires custom QEMU build | N/A | N/A | Out of MVP scope. |
| Requires kernel-level patching | N/A | N/A | Out of MVP scope. |
| Malware-specific bypass-code category | N/A | N/A | Out of MVP scope. |

## Decision

| Field | Value |
|---|---|
| MVP gate decision | Rejected |
| Rejection reason, if any | Required static/configurable categories failed. |
| Required follow-up before use | Rebuild or re-harden image and rerun al-khaser/Pafish. |
| Residual risk accepted by | N/A |

## Attachments

- al-khaser output: example path
- Pafish output: example path
- CAPEv2 benign detonation task/report: example path
- Guest hardening logs: example path
