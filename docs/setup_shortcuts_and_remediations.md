# Setup Shortcuts, Failures, Remediations, and Sandbox Impact

Date: 2026-07-20

This document records the shortcuts and overlooked requirements discovered while developing and running `scripts/setup-ubuntu24-host.sh` on the current Ubuntu 24.04 host. It is intentionally written as an engineering audit, not a polished install guide.

The final successful setup run was:

```text
/srv/winstdt/logs/setup/20260720T131931Z
setup script: v0.21
result: no failed phases
```

The Windows VMCloak image now exists as:

```text
winstdt-win10-22h2
```

## Summary

Several issues were caused by assuming a clean Ubuntu 24.04 host while the actual machine already had source-built or foreign virtualization components installed. Other issues came from treating old VMCloak behavior as if it were directly compatible with modern Windows 10 22H2 ISOs and Python 3.12.

The main remediation pattern was to make setup idempotent and state-aware:

- detect already-installed components instead of failing on duplicate state
- recover broken APT/dpkg state before installing packages
- prefer Ubuntu-packaged QEMU/libvirt components over source-built host components
- patch VMCloak where its old assumptions conflict with current Windows media
- treat optional guest software seeding as non-blocking
- keep installer output in logs while showing only a stable checklist in the terminal

## Findings

### 1. Treating the Host as Fresh When It Was Not

What we did:

The setup script initially assumed a fresh Ubuntu 24.04 host. The actual host already had custom QEMU/libvirt state, existing CAPEv2 files, existing networks, and previous partial VMCloak artifacts.

Why it failed:

The script hit conflicts that do not occur on a truly fresh host:

- a foreign `qemu` package was installed
- source-built libvirt libraries under `/usr/local/lib/x86_64-linux-gnu` shadowed Ubuntu libraries
- source-installed libvirt daemons and systemd units conflicted with packaged services
- libvirt network creation failed when the network already existed or was already active
- VMCloak left partial qcow2/ISO artifacts after failed runs

Remediation:

The script now checks existing host state and either skips, repairs, or quarantines conflicting state:

- detects and removes the foreign `qemu` package
- runs `dpkg --configure -a` and `apt-get --fix-broken install`
- quarantines unowned source libvirt files instead of deleting packaged files
- treats existing active libvirt networks as success
- removes stale VMCloak qcow2/ISO artifacts only when VMCloak has not registered the image

Essential:

Yes. Host setup for this project must be idempotent because malware sandbox hosts are rarely rebuilt perfectly from scratch during MVP work.

Pros:

- setup can be rerun safely
- failed phases produce actionable logs
- partial state does not poison every later run
- the final setup state is reproducible enough to continue MVP work

Cons:

- more script complexity
- host-specific repair logic can mask environmental drift
- quarantining source-installed virtualization components may affect other local VM workflows

Impact on orchestration:

Positive. CAPE and VMCloak require predictable QEMU/libvirt behavior. Idempotent setup reduces orchestration failures during guest creation, snapshotting, and later task execution.

Impact on anti-VM and anti-sandbox priorities:

Mixed. Standard Ubuntu-packaged QEMU/libvirt is more maintainable, but it does not improve anti-VM stealth by itself. Removing custom QEMU may reduce any prior anti-fingerprinting modifications that were present. For MVP this is acceptable because the implementation plan explicitly avoids custom QEMU/kernel patching, but it should be recorded as a stealth limitation.

### 2. Using the Wrong Ubuntu Package Name for `virt-install`

What we did:

The initial package list used `virt-install`.

Why it failed:

On Ubuntu 24.04, `virt-install` is provided by the `virtinst` package. APT reported:

```text
Package virt-install is not available
```

Remediation:

The setup package list now installs `virtinst`.

Essential:

Yes for VM lifecycle work. `virt-install` is not the core CAPE runtime, but it is useful for host validation and VM management.

Pros:

- aligns with Ubuntu 24.04 package naming
- avoids hard package failure early in setup

Cons:

- none significant

Impact on orchestration:

Positive. VM tooling availability is more consistent.

Impact on anti-VM and anti-sandbox priorities:

Neutral. This is host tooling only.

### 3. Foreign QEMU Package and Broken DPKG State

What we did:

The host had a foreign `qemu` package installed:

```text
foreign qemu package detected: qemu 9.2.2
```

The setup originally tried to install Ubuntu QEMU packages without handling this conflict.

Why it failed:

The foreign package blocked Ubuntu QEMU package ownership and left package dependencies in a broken state. Logs showed unmet dependencies around `qemu-system-common`, `qemu-system-data`, `qemu-system-s390x`, `qemu-block-extra`, and GUI/SPICE modules.

Remediation:

The script now:

- unholds and removes the foreign `qemu` package
- falls back to `dpkg --remove qemu` if APT cannot purge cleanly
- runs `apt-get --fix-broken install`
- verifies `qemu-system-x86_64` and `qemu-img` by command availability

Essential:

Yes for reliable host setup on this machine.

Pros:

- restores Ubuntu package manager consistency
- gives VMCloak and libvirt a known QEMU baseline
- removes a major source of setup instability

Cons:

- removes a newer QEMU version
- may remove custom QEMU behavior, including any local anti-fingerprinting work
- relying on Ubuntu QEMU 8.2.2 may lag behind upstream bug fixes

Impact on orchestration:

Positive. CAPE/VMCloak compatibility is better with Ubuntu-packaged QEMU/libvirt on Ubuntu 24.04.

Impact on anti-VM and anti-sandbox priorities:

Negative to neutral. If the foreign QEMU had stealth patches, removing it weakens anti-VM posture. However, the locked MVP decision was no custom QEMU/kernel patching, so standard QEMU is acceptable for MVP. Evasion resistance must come from guest hardening, CAPE behavior, ETW telemetry strategy, and validation gates rather than hypervisor modification.

### 4. Source-Built Libvirt Shadowing Ubuntu Libvirt

What we did:

The host had source-built libvirt libraries and daemons installed outside package manager ownership. The setup initially tried to use libvirt normally.

Why it failed:

`virtnetworkd.service` failed, and libvirt socket behavior was inconsistent. Source-installed libraries under `/usr/local/lib/x86_64-linux-gnu` shadowed Ubuntu packaged libvirt libraries. Some unowned libvirt daemons and systemd units also existed under system paths.

Remediation:

The script now:

- moves `/usr/local/lib/x86_64-linux-gnu/libvirt*` into a timestamped disabled directory
- quarantines unowned libvirt daemons/systemd units
- runs `ldconfig`
- uses Ubuntu-packaged monolithic `libvirtd`
- uses an explicit libvirt URI:

```text
qemu+unix:///system?socket=/run/libvirt/libvirt-sock
```

Essential:

Yes on this host. Without it, network setup and VMCloak QEMU launch were unreliable.

Pros:

- restores predictable libvirt service behavior
- avoids stale modular libvirt sockets
- makes `virsh` commands target the expected packaged daemon

Cons:

- modifies host-level virtualization environment
- may break unrelated source-built libvirt experiments
- hides rather than fully documents the prior local libvirt installation provenance

Impact on orchestration:

Strong positive. CAPE orchestration depends on stable libvirt networking and VM lifecycle operations.

Impact on anti-VM and anti-sandbox priorities:

Mixed. Stability improves sandbox reliability, but standard libvirt/QEMU identifiers are easier for malware to fingerprint than a carefully customized hypervisor stack. For MVP this is acceptable; for finished module work, deeper hypervisor fingerprint mitigation remains a separate milestone.

### 5. Libvirt Network Was Not Idempotent

What we did:

The early network script treated `network already active` as failure.

Why it failed:

`virsh net-start winstdt-isolated` returns an error if the network is already active:

```text
Requested operation is not valid: network is already active
```

The dashboard marked the network failed even though the network was already in the desired state.

Remediation:

The setup script now:

- checks whether the network is defined
- checks whether it autostarts
- checks whether it is active
- treats already-defined and already-active state as success/skipped

Essential:

Yes. Setup must be rerunnable.

Pros:

- avoids false failures
- preserves existing working network state
- reduces operator confusion

Cons:

- if the existing network has the correct name but wrong subnet/bridge details, a simple active check may be insufficient

Impact on orchestration:

Positive. Stable network identity is required for VMCloak guest IP assignment and later CAPE routing.

Impact on anti-VM and anti-sandbox priorities:

Neutral to slightly positive. A controlled isolated network supports detonation safety. It does not by itself improve anti-VM stealth.

Remaining concern:

The script should eventually validate the active network XML against expected CIDR, bridge name, DHCP range, and NAT/no-NAT policy instead of only checking active state.

### 6. QEMU Bridge Helper Was Missing or Misconfigured

What we did:

VMCloak launches QEMU with bridged networking. The setup initially did not guarantee `/etc/qemu/bridge.conf` and helper permissions.

Why it failed:

VMCloak/QEMU failed with:

```text
failed to parse default acl file `/etc/qemu/bridge.conf'
qemu-system-x86_64: -netdev type=bridge,br=virbr-winstdt,id=net0: bridge helper failed
```

Remediation:

The setup now writes:

```text
allow virbr-winstdt
```

to `/etc/qemu/bridge.conf`, sets the file to `0644`, and enables setuid on:

```text
/usr/lib/qemu/qemu-bridge-helper
```

Essential:

Yes for VMCloak QEMU bridge mode.

Pros:

- allows VMCloak to attach the guest to the isolated libvirt bridge
- avoids manually launching QEMU as root

Cons:

- setuid helper increases host attack surface
- bridge helper access must stay restricted to the intended bridge

Impact on orchestration:

Positive. Guest provisioning now works with the intended isolated network.

Impact on anti-VM and anti-sandbox priorities:

Neutral. This changes host networking permissions, not guest-visible artifacts. The isolated network supports containment, but does not hide virtualization.

### 7. CAPEv2 Git Ownership and Installer Idempotency

What we did:

The setup initially ran `git -C /opt/cape pull` with sudo/root against a repository owned by another user.

Why it failed:

Git rejected the checkout as dubious ownership:

```text
fatal: detected dubious ownership in repository at '/opt/cape'
```

Remediation:

The script now:

- manages `/opt/cape` ownership as the configured `cape` user
- runs CAPE updates as that user
- writes marker files under `/srv/winstdt/setup-state`
- skips CAPE installer reruns unless explicitly requested

Essential:

Yes. CAPE scripts can make broad host changes and should not be rerun accidentally.

Pros:

- avoids Git safety failures
- prevents repeated CAPE installer side effects
- preserves the decision to use CAPE scripts wherever needed

Cons:

- marker files can drift from reality if a manual change breaks CAPE after the marker is written
- skipped CAPE installers mean the script may not repair every CAPE-level drift by default

Impact on orchestration:

Positive. CAPE is the main orchestration layer, and stable ownership/installer state matters.

Impact on anti-VM and anti-sandbox priorities:

Neutral. CAPE itself may introduce guest-visible artifacts through agent behavior and monitoring, but ownership markers do not affect stealth.

### 8. VMCloak PyPI/Python Compatibility

What we did:

The first approach attempted to install VMCloak from PyPI on Python 3.

Why it failed:

The PyPI package pulled legacy Python 2-era dependencies, including `pefile2`, which failed with syntax errors on Python 3:

```text
SyntaxError: multiple exception types must be parenthesized
```

Later, the GitHub VMCloak install hit Python 3.12/setuptools behavior where `pkg_resources` was absent or deprecated.

Remediation:

The script now:

- installs VMCloak from the `cert-ee/vmcloak` Git repository
- creates a dedicated virtualenv under `/srv/winstdt/tools/vmcloak/venv`
- pins/reinstalls `setuptools<81`
- symlinks `/usr/local/bin/vmcloak`

Essential:

Yes for automated Windows guest image creation.

Pros:

- avoids broken PyPI package path
- isolates VMCloak dependencies from system Python
- makes setup repeatable

Cons:

- depends on an external Git repository at setup time
- VMCloak remains old and needs patching
- pinned setuptools is technical debt

Impact on orchestration:

Positive. VMCloak is now available and can create the golden image.

Impact on anti-VM and anti-sandbox priorities:

Indirect positive. VMCloak enables consistent golden images and post-build hardening. It does not provide complete stealth by itself.

### 9. Windows ISO Was Required but Not Initially Accounted For

What we did:

We began setup automation before making the licensed Windows 10 ISO dependency explicit.

Why it failed:

VMCloak cannot build a Windows guest without installation media. The user also had to move the ISO into the project root for a predictable local path.

Remediation:

The script accepts:

```text
--windows-iso ./Win10_22H2_x64.iso
```

and also detects:

```text
./Win10_22H2_x64.iso
```

as a fallback. ISO files are ignored by Git.

Essential:

Yes. The MVP requires a Windows 10 22H2 x64 guest.

Pros:

- explicit licensed media dependency
- no accidental repository commit of a large proprietary ISO
- stable path for reruns

Cons:

- still requires operator-provided Windows media
- ISO provenance/version must be tracked separately for chain-of-custody quality

Impact on orchestration:

Positive. The setup can now consistently locate the installation media.

Impact on anti-VM and anti-sandbox priorities:

Important. ISO version and edition affect ETW provider availability, Windows behavior, Defender components, and anti-evasion validation. The exact ISO hash should be recorded in the golden image report.

### 10. VMCloak ISO Generation Did Not Handle Large Windows 10 WIM Files

What we did:

VMCloak was used against a modern Windows 10 22H2 ISO.

Why it failed or would fail:

Modern Windows installation media can contain an `install.wim` larger than classic ISO9660 limits. Older VMCloak ISO generation does not account for this by default.

Remediation:

The setup patches VMCloak ISO generation to include:

```text
-allow-limited-size
```

Essential:

Yes for this ISO family if VMCloak generates an unattended ISO containing large Windows media files.

Pros:

- allows VMCloak to generate the unattended ISO
- avoids manual ISO remastering

Cons:

- patching installed package code is brittle
- future VMCloak updates may overwrite or conflict with the patch

Impact on orchestration:

Positive. Guest build can proceed.

Impact on anti-VM and anti-sandbox priorities:

Neutral. This is an install-media compatibility fix.

### 11. VMCloak Win10 Unattend Template Was Not Compatible With Windows 10 22H2

What we did:

VMCloak's stock Windows 10 unattended template was used initially.

Why it failed:

Windows Setup showed:

```text
Windows could not apply unattend settings during pass [specialize].
```

The incompatible elements were legacy settings including:

- `ShowWindowsLive`
- `Security-Malware-Windows-Defender` / `DisableAntiSpyware`

Remediation:

The setup patches VMCloak's Win10 `autounattend.xml` to remove those elements.

Essential:

Yes for unattended install on the Windows 10 22H2 media used here.

Pros:

- lets Windows setup complete
- avoids manual repair during guest install

Cons:

- changes the default Windows security posture less aggressively than older VMCloak expected
- patching VMCloak templates is technical debt
- we must explicitly handle Defender/security state in the later guest hardening pass instead of relying on obsolete unattend keys

Impact on orchestration:

Positive. The golden image can be built without setup specialize failure.

Impact on anti-VM and anti-sandbox priorities:

Mixed. Removing obsolete Defender disable keys avoids installation failure, but it means guest security controls must be managed deliberately later. From an anti-sandbox perspective, a more normal Windows configuration may be better than a visibly broken or aggressively modified one. From malware detonation safety, Defender state must be documented and controlled.

### 12. VMCloak Guest IP Was Initially Wrong

What we did:

An early VMCloak run effectively used the gateway address as the image IP:

```text
Image IP: 10.66.0.1
```

Why it failed or was risky:

`10.66.0.1` is the host bridge/gateway address, not the guest address. Assigning it to the guest conflicts with host networking assumptions.

Remediation:

The script now has separate values:

```text
HOST_IP=10.66.0.1
GUEST_IP=10.66.0.101
```

and passes:

```text
--ip 10.66.0.101
--gateway 10.66.0.1
```

Essential:

Yes.

Pros:

- avoids IP conflicts
- gives CAPE and handoff tools a predictable guest endpoint

Cons:

- static IP can conflict if multiple guest images run on the same isolated network without unique assignment

Impact on orchestration:

Positive for single-VM MVP. For a finished multi-VM pool, guest addressing must become per-VM and CAPE-managed.

Impact on anti-VM and anti-sandbox priorities:

Neutral to slightly negative. Static sandbox subnets can be fingerprinted. For MVP this is acceptable; finished module should randomize or vary network details where practical.

### 13. VMCloak GUI Visibility Was Not Initially Explicit

What we did:

Initial VMCloak runs did not make the VNC/VRDE access path clear enough for operator validation.

Why it failed operationally:

The user needed to inspect the guest setup screen and used `gvncviewer`. There was confusion between `localhost:5901` and display `localhost:1`.

Remediation:

The VMCloak init command now includes:

```text
--vrde --vrde-port 1
```

Operationally, the viewer command is:

```text
gvncviewer localhost:1
```

Essential:

Useful for MVP validation; not essential for headless production detonation.

Pros:

- lets operator see Windows setup failures directly
- speeds diagnosis of guest install issues

Cons:

- GUI exposure is an operational surface
- manual observation does not scale to multi-VM orchestration

Impact on orchestration:

Positive during build/debug, neutral for production if disabled or restricted later.

Impact on anti-VM and anti-sandbox priorities:

Neutral. VNC/VRDE is host-side, but long-term production should ensure no guest-visible artifacts or open access paths are exposed unnecessarily.

### 14. Treating Baseline Guest Software as Required

What we did:

The setup initially tried to install baseline software through VMCloak:

```text
firefox chrome 7zip
```

Why it failed:

`7zip` was not a supported VMCloak dependency. Later, Firefox and Chrome failed because VMCloak's old download URLs returned 404:

```text
https://cuckoo.sh/vmcloak/Firefox_Setup_41.0.2.exe
https://cuckoo.sh/vmcloak/googlechromestandaloneenterprise.msi
```

Remediation:

The script now defaults:

```text
VMCLOAK_BASELINE_DEPS=""
```

Baseline software install is skipped unless explicitly requested. If explicitly requested and it fails, the script logs the failure but does not fail the guest build.

Essential:

No for MVP host/guest setup. It is useful for realism and detonation coverage, but not required to create the golden image or validate ETW/CAPE handoff.

Pros:

- avoids blocking the MVP on stale third-party download URLs
- keeps the golden image build moving
- makes browser/app seeding a separate, explicit enrichment step

Cons:

- guest may be less realistic for malware that expects browsers, archives, documents, or user apps
- anti-sandbox validation may be weaker until realistic software/profile seeding is added
- some samples that require browser components may not execute representative behavior

Impact on orchestration:

Positive for MVP reliability. Negative for full behavioral coverage until guest enrichment is implemented.

Impact on anti-VM and anti-sandbox priorities:

Negative until addressed. A sparse Windows image is easier to classify as a sandbox. This should be handled by a controlled guest enrichment workflow using locally cached installers and hashes, not by relying on old VMCloak remote URLs.

### 15. Setup Script Used CAPE and VMCloak, But Still Added Custom Glue

What we did:

The plan said to use CAPE scripts wherever needed. The setup does call CAPE installers and uses VMCloak, but it also adds custom host repair, overlay installation, Rust binary builds, and VMCloak patching.

Why this was necessary:

CAPE scripts do not know about this project's ETW handoff module, schema validator, VMCloak patch requirements, or this host's broken QEMU/libvirt state.

Remediation:

Custom logic remains inside one setup script, while CAPE installation itself is still delegated to CAPE scripts.

Essential:

Yes. CAPE is the orchestration substrate, not a full installer for this module's ETW artifacts and handoff contract.

Pros:

- one operator command can prepare host, build binaries, install overlays, and prepare guest image
- project-specific assumptions are explicit in one place

Cons:

- script ownership is now ours
- upstream CAPE/VMCloak changes may require maintenance

Impact on orchestration:

Positive. It bridges CAPE's generic sandbox setup with this module's specific ETL/manifest handoff requirements.

Impact on anti-VM and anti-sandbox priorities:

Neutral. The custom glue does not directly improve stealth, but it ensures the module can be installed consistently enough to run later anti-evasion validation.

### 16. TUI Dashboard Hid Installer Output By Design

What we did:

The user requested a stable checklist-style TUI that does not blast the terminal with installer output.

Why this caused friction:

Long-running VMCloak phases looked stuck because the screen only showed:

```text
[~] Windows guest build          running VMCloak init
```

while the real progress was in `10-guest.log`.

Remediation:

The dashboard now prints the exact phase log path and aggregate error path for failed components. The design keeps noisy installer output out of the main screen.

Essential:

Useful, not technically essential.

Pros:

- readable setup progress
- all command output is preserved
- failed component and log path are visible

Cons:

- long phases can appear inactive
- there is no live progress indicator inside a phase

Impact on orchestration:

Neutral. This affects operator experience, not runtime sandbox orchestration.

Impact on anti-VM and anti-sandbox priorities:

Neutral.

Suggested improvement:

Add a periodically updating line showing the last log timestamp or last log line summary without dumping the whole log.

### 17. Command Timeouts Versus Long Windows Installation

What we did:

Commands are wrapped with:

```text
COMMAND_TIMEOUT_SECONDS=7200
```

Why it mattered:

Windows installation can take many minutes and can appear stuck. One earlier run terminated QEMU with signal 15 after operator interruption or timeout-like control flow:

```text
qemu-system-x86_64: terminating on signal 15
```

Remediation:

The timeout is long enough for typical Windows setup and logs timeout events explicitly.

Essential:

Yes. Setup must not hang forever, but Windows install needs enough time.

Pros:

- prevents infinite setup hangs
- keeps failure logs explicit

Cons:

- a slow host could still hit timeout
- `timeout --foreground` around interactive VM build phases can be blunt

Impact on orchestration:

Positive for automation discipline, but should be tuned for slower hardware.

Impact on anti-VM and anti-sandbox priorities:

Neutral.

### 18. Golden Image Versus Complete CAPE Detonation Pipeline

What we did:

The setup successfully built/registered the VMCloak image and installed the project binaries and CAPE reporting overlay.

Original gap:

The setup completion alone did not prove:

- the image is imported into CAPE machinery configuration
- a clean CAPE snapshot exists and is used
- CAPE can submit/revert/detonate a task against this image
- the Windows guest has the ETW agent staged and validated
- `behavior/trace.etl` is produced during a real CAPE task
- PCAP and ETL are present together in a final handoff bundle
- anti-evasion validation has passed against the hardened image

Remediation so far:

The setup script creates the host and golden-image prerequisites. Runtime closure on 2026-07-20 then validated CAPE machinery registration, snapshot existence, guest agent reachability, PCAP capture, ETW capture/retrieval, and final handoff validation for task `11`.

Essential:

Yes. This was the largest remaining MVP gap after host setup; it is now closed for benign validation. Task `11` ran through CAPE's analyzer path, stored analyzer logs, captured PCAP, uploaded ETW through CAPE's allowed `aux/` path, and exported a valid WinST/DT handoff bundle.

Pros:

- clean separation between host bootstrap and runtime validation
- setup no longer pretends to prove the full MVP

Cons:

- setup success can be mistaken for full sandbox readiness
- CAPE resultserver upload path restrictions must be respected for future auxiliary artifacts

Impact on orchestration:

Improved. CAPE task lifecycle validation now passes for benign runtime closure with analyzer logs, CAPE PCAP, ETW upload, and reporting-module export all present in the same CAPE-controlled run.

Impact on anti-VM and anti-sandbox priorities:

High. The golden image must still go through post-VMCloak hardening and strict-subset al-khaser/Pafish validation before it can be considered acceptable for the MVP.

## Current Essential Versus Deferred Items

Essential for MVP setup and orchestration:

- Ubuntu 24.04 package repair and dependency installation
- Ubuntu-packaged QEMU/libvirt consistency
- active `winstdt-isolated` libvirt network
- QEMU bridge helper configuration for `virbr-winstdt`
- CAPEv2 checkout/install markers
- VMCloak from Git in a dedicated virtualenv
- VMCloak patches for Windows 10 22H2 unattended install
- licensed Windows 10 22H2 x64 ISO
- built Windows guest image
- WinST/DT binaries and CAPE reporting overlay installation

Essential runtime validation completed in this environment:

- CAPE machinery configuration for `winstdt-win10-22h2`
- active libvirt domain and `hardened-baseline` snapshot lifecycle
- Windows guest ETW agent staging through the guest agent
- ETL trace creation and retrieval
- PCAP capture retrieval
- final handoff bundle validation

Essential but still pending manual validation:

- filled golden image hardening report based on full anti-evasion evidence
- al-khaser/Pafish strict-subset validation gate

Deferred or non-blocking:

- browser/app baseline seeding through VMCloak
- multi-browser realistic user profile
- custom QEMU/kernel anti-fingerprinting
- Windows 11 guest variant
- structured `events.jsonl`
- ETW-TI promotion from best-effort to validated analytic source

## Net Impact on Project Priorities

Sandbox orchestration:

The remediations improved orchestration reliability substantially. The host now has a stable package state, a working isolated network, a usable VMCloak image, and installed project overlays. The main orchestration risk is no longer host bootstrap; it is the next CAPE lifecycle validation step.

Anti-VM evasiveness:

The setup favors maintainability over stealth. Removing custom QEMU/libvirt state and relying on Ubuntu packages aligns with the MVP constraint of no custom QEMU/kernel patching, but it does not solve hypervisor fingerprinting. This means anti-VM resistance must come from guest hardening, realistic image enrichment, timing mitigations where feasible, and validation gates rather than hypervisor-level concealment.

Anti-sandbox realism:

The image currently prioritizes successful automated build over realism. Skipping Firefox/Chrome/7zip seeding was the correct MVP reliability decision, but it leaves a realism gap. Guest enrichment should be added later through controlled, locally cached installers with hashes, not through VMCloak's stale remote URLs.

Evidence and telemetry:

None of these setup shortcuts changed the locked telemetry design: raw ETW `.etl` handoff remains the MVP behavioral artifact. Runtime validation on 2026-07-20 produced a completed handoff bundle for CAPE task `11` containing both `behavior/trace.etl` and `network/capture.pcapng`; the WinST/DT validator and mock consumer accepted the bundle.

## Recommendations

1. Keep `scripts/setup-ubuntu24-host.sh` as the only host setup script.
2. Treat `v0.21` as the first successful host/bootstrap baseline.
3. Add a setup post-check command that validates exact libvirt network XML, VMCloak image registration, CAPE paths, binary paths, and package versions.
4. Add a separate guest enrichment workflow with local installers and SHA-256 pins.
5. Add CAPE machinery registration and snapshot validation as the next implementation milestone.
6. Add a golden image report for the current ISO and guest image before detonating real samples.
7. Run al-khaser/Pafish strict-subset validation after post-VMCloak hardening, not before.
8. Record any future hypervisor stealth work separately because it is outside the MVP no-custom-QEMU constraint.

## Runtime Closure Attempt: Cached Sudo Missing

Command attempted:

```bash
scripts/configure-cape-runtime.sh --execute
```

Observed result:

```text
passwordless/cached sudo is required. Run 'sudo -v' in a terminal, then retry.
```

Impact:

The repo-owned runtime closure script is implemented, but this session could not
apply host-level mutations under `/opt/CAPEv2`, libvirt, or systemd because no
cached sudo credential was available. This blocks operational proof of CAPE
service readiness, domain creation, snapshot validation, benign CAPE detonation,
and real PCAP+ETL handoff validation in this environment.

Remediation:

Run `sudo -v` in an interactive terminal on the host, then rerun:

```bash
scripts/configure-cape-runtime.sh --execute
```

If the script fails after sudo is available, capture its full output in this
audit and patch the failing idempotent step before rerunning.

Status update:

Resolved on 2026-07-20 by enabling passwordless sudo for this maintenance user.
The runtime script was also changed to use `sudo -n true` instead of
`sudo -n -v`, because this host policy allowed non-interactive command
execution but not sudo credential validation.

## Runtime Closure Remediations: 2026-07-20

Observed issues:

- Python `libvirt` bindings failed to build in CAPE's Poetry environment without `libvirt-dev` and the correct pkg-config search path.
- MongoDB 8.0.26 refused to start on this `7.0.0-28-generic` kernel due the documented MongoDB 8.0 kernel incompatibility.
- The VM initially received a non-configured DHCP address, so CAPE tried to contact the wrong endpoint.
- Libvirt/AppArmor denied access to the original backing-image chain under `/srv/winstdt/images`.
- CAPE looked for the reporting module section by file-stem name, `[winstdt_handoff_export]`, not the older normalized spelling.
- The reporter's atomic temporary directory inherited `0700`, which blocked local validation tools from reading completed bundles.
- The guest image contains the older Cuckoo Agent 1.0 endpoint set; direct execution requires `shell=1` for shell redirection and POST `/retrieve` for artifact retrieval.
- CAPE's guest port is hardcoded to `8000`, so alternate-port modern-agent validation does not by itself change CAPE task execution.
- CAPE resultserver rejects upload paths outside its whitelist; root-level `trace.etl` and nested `behavior/trace.etl` uploads were logged by the guest sender but not persisted by the host.

Remediations applied:

- `scripts/configure-cape-runtime.sh` installs `libvirt-dev` and exports a pkg-config path that includes `/usr/lib64/pkgconfig`.
- The script intentionally downgrades and holds MongoDB packages to `8.0.4` on kernel 6.19+/7.x hosts.
- The script enforces `/etc/mongod.conf` local-only binding (`bindIp: 127.0.0.1`) and fails post-check if MongoDB listens on any non-localhost interface.
- The script adds a static DHCP reservation for `winstdt-win10-22h2` at `10.66.0.101`.
- The script creates a standalone qcow2 clone under `/var/lib/libvirt/images/winstdt` before defining the runtime domain.
- The reporting overlay uses `[winstdt_handoff_export]` and is merged into `/opt/CAPEv2/conf/reporting.conf`.
- The reporter normalizes finalized bundle directory/file permissions to `0755`/`0644`.
- Guest validation evidence was retrieved through the available Cuckoo Agent 1.0 API.
- `scripts/stage-cape-guest-agent.sh --execute` stages and validates CAPE agent `0.22` on alternate guest port `8001` with `execpy`, `logs`, and `subdir_upload`.
- The ETW pickup auxiliary now uploads to allowed CAPE paths: `aux/trace.etl`, `aux/telemetry.json`, and `aux/etw_state.json`.
- The reporting module reads those `aux/` artifacts and normalizes the final handoff bundle to `behavior/trace.etl`.
- The ETW agent uses circular binary ETL output capped at 64 MB to remain under CAPE's upload-size limit.

Evidence:

- `scripts/configure-cape-runtime.sh --execute` passed after the remediations.
- CAPE task `11` completed and produced analyzer logs, `dump.pcap`, `aux/trace.etl`, `aux/telemetry.json`, and `aux/etw_state.json`.
- Task `11` stored `aux/trace.etl` at 49,299,456 bytes, below CAPE's upload limit.
- The final `/srv/winstdt/handoff/11` bundle contains `behavior/trace.etl` and `network/capture.pcapng`, validates as `Completed`, and `mock-consume` accepted it.
- `compare-telemetry` reported `etw_enabled=4/6`, `telemetry_degraded=true`, and `decision=keep_capemon_enabled`.
- The current runtime snapshot is `hardened-baseline-antievasion-v1`.

### Anti-Evasion Hardware Identity Remediation

The first al-khaser/Pafish run on 2026-07-20 rejected the image because Windows
reported obvious virtual hardware identity:

- `Manufacturer=BOCHS_`
- `Model=BXPC____`
- `SystemBiosVersion=BOCHS - 1`
- `QEMU HARDDISK`
- about 80 GB disk capacity

The proper remediation was applied at the libvirt/QEMU layer rather than by
editing Windows registry artifacts after detection. `scripts/configure-cape-runtime.sh`
now calls `scripts/harden-libvirt-domain.py`, which applies:

- libvirt SMBIOS/sysinfo type 0/1/2/3 OEM values
- `<smbios mode="sysinfo"/>`
- KVM hidden state and Hyper-V vendor override
- QEMU ACPI OEM ID/table ID machine options
- virtio balloon removal
- stable disk serial
- libvirt `qemu:override` frontend properties for the emulated disk model
- 160 GB minimum virtual disk sizing

The Windows guest was power-cycled, the active overlay was resized, and
`Invoke-GuestHardening.ps1 -Apply` expanded C: and seeded/warmed the user
profile. The rerun evidence is:

```text
docs/validation/evidence/anti-evasion-20260720-223908/
```

Confirmed improvements:

- Windows now reports `Manufacturer=DELL`, `Model=CBX3`.
- BIOS string changed from `BOCHS - 1` to `DELL - 1`.
- disk model changed from `QEMU HARDDISK` to `WDC WD5000LPCX-75VHAT0`.
- C: expanded to about 160 GB with about 151 GB free.
- al-khaser disk-size, `SetupDi_diskdrive`, and QEMU registry checks moved to
  `GOOD`.
- Pafish no longer emits Bochs/QEMU BIOS/disk markers.

Remaining blockers:

- al-khaser still reports mouse movement and lack-of-user-input failures.
- Pafish reports fresh-boot uptime because validation ran soon after boot.
- al-khaser still reports one ACPI table string failure.
- al-khaser WMI fan and `Win32_SMBIOSMemory` inventory checks remain residual
  platform realism findings.
- CPUID hypervisor bit and RDTSC forced-VM-exit findings remain non-blocking
  timing/deep-hypervisor residual risk under the no-custom-QEMU/kernel MVP
  constraint.

Next remediation should add a longer pre-detonation dwell and interaction
workflow that runs immediately before analysis, then rerun al-khaser with a
longer timeout.

MongoDB security decision:

MongoDB `8.0.4` is intentionally pinned for this host. The reason is kernel
compatibility, not preference: newer MongoDB 8.0 packages failed to start on the
current Linux `7.0.0-28-generic` kernel. This is acceptable only for a local CAPE
analysis host where MongoDB is bound to `127.0.0.1:27017` and is not exposed to
guest VMs, LAN clients, or public interfaces.

Residual risk:

- MongoDB is behind the current patch level.
- Security scanners may flag the pinned package.
- Future CAPE/MongoDB behavior may diverge from latest supported MongoDB.

Compensating controls:

- localhost-only MongoDB binding
- no guest/network exposure
- explicit `apt-mark hold` on all MongoDB server/meta packages
- `winstdt monitor-health` visibility for version, holds, bind address, and exposure

Re-evaluate the pin when MongoDB publishes a fixed secure version compatible with
kernel `6.19+`, the host moves below kernel `6.19`, CAPE no longer requires this
MongoDB runtime, MongoDB is moved to a dedicated compatible-kernel VM, or the
host becomes multi-user, network-exposed, or production-like.
