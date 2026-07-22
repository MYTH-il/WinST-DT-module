# Anti-Evasion Hardening Gate

## Purpose

al-khaser and Pafish are strict validation suites for the MVP-scoped anti-evasion baseline. They are not runtime dependencies and not implementation recipes.

The MVP gate is a **Strict Subset Gate**: a golden image must pass the required static/configurable categories below, while out-of-scope findings are recorded as residual risk.

References:

- al-khaser: https://github.com/ayoubfaouzi/al-khaser
- Pafish: https://github.com/a0rtega/pafish
- CAPEv2 KVM/QEMU setup: https://capev2.readthedocs.io/en/latest/installation/host/installation.html

## Required MVP Gate Categories

The golden image is not MVP-acceptable unless all required categories pass for both al-khaser and Pafish where the tool has equivalent coverage.

| Category | Required result | Allowed remediation layer |
|---|---|---|
| SMBIOS/DMI vendor, product, and serial checks | No obvious QEMU/KVM/VMware/VirtualBox/default sandbox strings | SMBIOS/DMI configuration through libvirt/QEMU and VMCloak image configuration |
| BIOS/firmware strings where configurable | No obvious virtualization/default firmware identifiers in configurable fields | CAPEv2 `kvm-qemu.sh`, OVMF/libvirt/QEMU firmware configuration |
| Registry virtualization artifacts | No obvious QEMU/KVM/VMware/VirtualBox keys or values in common detection paths | Post-VMCloak registry cleanup |
| Hostname, username, workgroup, and profile naming | No blacklist/default analysis strings such as sandbox, malware, test, sample, or trivially generated defaults | VMCloak customization and post-build profile normalization |
| Obvious sandbox/security-tool process and service names | No avoidable process or service names that identify the analysis environment | CAPEv2/VMCloak service naming and configuration hygiene |
| Default QEMU disk, CD-ROM, and device model strings where configurable | No default device model strings in interfaces exposed to the guest where libvirt/QEMU can configure them | libvirt/QEMU device configuration |
| CPU count | Meets the configured realism baseline | VMCloak/libvirt resource sizing |
| RAM size | Meets the configured realism baseline | VMCloak/libvirt resource sizing |
| Disk size and free space | Meets the configured realism baseline | VMCloak/libvirt resource sizing and image preparation |
| Recent files | Profile is not trivially empty | Post-VMCloak profile seeding |
| Browser profile | Browser profile is not trivially empty | VMCloak software install and post-build browser seeding |
| Installed software | Normal user software entries exist without analysis-tool naming leakage | VMCloak package install and post-build validation |
| Downloads and TEMP profile patterns | Directories are not pristine/default-empty in a way that trips common checks | Post-VMCloak filesystem seeding |
| Boot warm-up and interaction evidence | Guest is not detonated immediately after fresh boot with no user activity | CAPEv2 task timing and in-guest interaction simulation |

## Non-Blocking Categories

The following findings must be recorded in the validation report, but they do not block MVP acceptance:

- RDTSC and timing checks.
- CPUID timing side channels.
- Debugger checks.
- Deep hypervisor introspection.
- Checks requiring virtio or other driver modification.
- Checks requiring driver renaming or re-signing.
- Checks requiring a custom QEMU build.
- Checks requiring kernel-level patching.
- Checks tied to malware-specific anti-analysis bypass code.

## MVP Exclusions

Do not use al-khaser or Pafish output to justify adding any of the following to MVP scope:

- Modifying virtio drivers.
- Renaming or re-signing drivers.
- Custom kernel patching.
- Non-standard QEMU source modifications.
- Timing-counter defeat work.
- Debugger-bypass engineering.
- Malware-style anti-analysis bypass implementation.

## Acceptance Criteria

A golden image is MVP-acceptable only when:

- CAPEv2 stock detonation works on the image.
- CAPEv2 `kvm-qemu.sh` has been used for host KVM/QEMU setup.
- The VMCloak baseline image has been built and post-hardened.
- al-khaser and Pafish have both been run manually inside the guest.
- All required gate categories pass.
- Every non-blocking failure is recorded in a validation report.
- The validation report records:
  - Golden image build ID.
  - CAPEv2 git ref.
  - VMCloak build date.
  - Windows version/build.
  - al-khaser version/ref.
  - Pafish version/ref.
  - Pass/fail table by category.
  - Residual-risk notes.

## Collection Helper

Provide local compiled validation tool binaries and run the host wrapper:

```bash
scripts/validation/run-anti-evasion-validation.sh \
  --al-khaser /path/to/al-khaser.exe \
  --pafish /path/to/pafish.exe \
  --execute
```

The wrapper stages the tools and collector through the CAPE guest agent, runs
the collector, retrieves a zip archive, and extracts it under:

```text
docs/validation/evidence/<anti-evasion-run-id>/
```

To run manually inside the guest instead, stage the validation tools and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\Invoke-AntiEvasionCollection.ps1 `
  -AlKhaserPath C:\Tools\al-khaser\al-khaser.exe `
  -PafishPath C:\Tools\pafish\pafish.exe
```

The helper writes a timestamped directory under:

```text
C:\ProgramData\WinSTDT\validation\anti-evasion\
```

Expected outputs:

- `summary.json`
- `system-context.json`
- `al-khaser.result.json`
- `al-khaser.stdout.txt`
- `al-khaser.stderr.txt`
- `pafish.result.json`
- `pafish.stdout.txt`
- `pafish.stderr.txt`

The helper does not decide pass/fail automatically. The operator must map raw
tool output into `docs/validation/golden_image_report_current.md` using the
Strict Subset Gate categories above.

After retrieval, draft the current report metadata and attachment paths:

```bash
scripts/validation/draft-golden-image-report.py \
  docs/validation/evidence/<anti-evasion-run-id> \
  --cape-git-ref "$(git -C /opt/CAPEv2 rev-parse --short HEAD)"
```

The draft intentionally leaves every strict-subset category as `Pending review`.
Replace those cells with `Pass`, `Fail`, or `N/A` after inspecting the raw stdout
and stderr. Do not mark the image accepted while any required row is pending or
failed.

## Operating Assumptions

- Strict gate means Strict Subset Gate, not full all-check pass.
- No driver modification or driver re-signing is allowed in MVP.
- CAPEv2 `kvm-qemu.sh` remains the first hardening layer.
- al-khaser and Pafish are both used because their coverage overlaps but is not identical.
