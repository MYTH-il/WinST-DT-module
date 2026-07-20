# Guest Hardening Scripts

This directory is reserved for the post-VMCloak hardening pass that runs once inside the Windows golden image before it is sealed.

MVP hardening is limited to:

- Registry/profile cleanup.
- Hostname, user, workgroup, and profile realism checks.
- Filesystem, browser, recent-document, Downloads, and TEMP seeding.
- Resource-size validation.
- Boot warm-up and human-interaction simulation setup.
- Validation evidence collection for the anti-evasion gate.

MVP hardening explicitly excludes:

- Virtio or other driver modification.
- Driver renaming or re-signing.
- Kernel patching.
- Non-standard QEMU source modifications.
- Timing-counter defeat work.
- Debugger-bypass engineering.
- Malware-style anti-analysis bypass implementation.

Use `Invoke-GuestHardening.ps1` with a reviewed JSON config. The script starts in dry-run mode by default.
