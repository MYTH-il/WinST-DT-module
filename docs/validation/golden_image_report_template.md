# Golden Image Anti-Evasion Validation Report

## Run Metadata

| Field | Value |
|---|---|
| Report ID |  |
| Validation date |  |
| Validator |  |
| Golden image build ID |  |
| Golden image path/snapshot |  |
| CAPEv2 git ref |  |
| CAPEv2 `kvm-qemu.sh` used | Yes/No |
| VMCloak build date |  |
| Post-hardening script/ref |  |
| Windows edition/version/build |  |
| CPU/RAM/disk configuration |  |
| al-khaser version/ref |  |
| Pafish version/ref |  |

## Detonation Sanity Check

| Check | Result | Evidence/notes |
|---|---|---|
| CAPEv2 stock benign detonation completed | Pass/Fail |  |
| Guest booted from hardened snapshot | Pass/Fail |  |
| CAPE agent reachable | Pass/Fail |  |
| Result retrieval completed | Pass/Fail |  |

## Required Gate Results

Use `Pass`, `Fail`, or `N/A` where a tool has no equivalent check. Any `Fail` in this table rejects the golden image for MVP use.

| Category | al-khaser | Pafish | Evidence/notes |
|---|---|---|---|
| SMBIOS/DMI vendor/product/serial checks |  |  |  |
| BIOS/firmware strings where configurable |  |  |  |
| Obvious QEMU/KVM/VMware/VirtualBox registry artifacts |  |  |  |
| Hostname/username/workgroup blacklist checks |  |  |  |
| Obvious sandbox/security-tool process/service-name checks |  |  |  |
| Default QEMU disk/CD-ROM/device strings where configurable |  |  |  |
| CPU count |  |  |  |
| RAM size |  |  |  |
| Disk size/free space |  |  |  |
| Recent files not empty |  |  |  |
| Browser profile not empty |  |  |  |
| Normal installed software present |  |  |  |
| Downloads/TEMP profile patterns not pristine |  |  |  |
| Boot warm-up and human-interaction evidence |  |  |  |

## Non-Blocking Findings

These findings do not block MVP acceptance, but every observed failure must be recorded.

| Category | al-khaser | Pafish | Residual-risk note |
|---|---|---|---|
| RDTSC/timing checks |  |  |  |
| CPUID timing side channels |  |  |  |
| Debugger checks |  |  |  |
| Deep hypervisor introspection |  |  |  |
| Requires driver modification/re-signing |  |  |  |
| Requires custom QEMU build |  |  |  |
| Requires kernel-level patching |  |  |  |
| Malware-specific bypass-code category |  |  |  |

## Decision

| Field | Value |
|---|---|
| MVP gate decision | Accepted/Rejected |
| Rejection reason, if any |  |
| Required follow-up before use |  |
| Residual risk accepted by |  |

## Attachments

List paths or hashes for raw outputs, screenshots, logs, or exported reports:

- al-khaser output:
- Pafish output:
- CAPEv2 benign detonation task/report:
- Guest hardening logs:
