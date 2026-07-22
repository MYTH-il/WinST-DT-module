# WinST/DT Module — Windows Static & Dynamic Testing
## Implementation Plan for the Unified Malware Detection and Behavioral Analysis Tool

---

## 1. Executive Summary

The WinST/DT module is the Windows-target intake, static-triage, and dynamic-detonation subsystem of the unified platform. It owns everything from "a sample lands on disk" to "a sealed, hash-chained evidence package leaves the module boundary." It does **not** own C2/exfiltration pattern detection — that is entirely the downstream module's job. WinST/DT's only contract with that module is the artifact bundle described in Section 4.

**Build strategy — CAPEv2 as the reused detonation core:** rather than building the detonation orchestration, guest-lifecycle, and reporting engine from scratch, this plan adopts **CAPEv2** (the actively maintained Cuckoo-derived sandbox) as the underlying detonation core, run on top of the same Ubuntu 24.04/KVM/libvirt host described in Section 8. The team's original engineering effort is concentrated in three layers built *on top of* CAPEv2 rather than duplicating what it already does well:
1. **Anti-evasion hardening** applied to CAPEv2's guest images via **VMCloak** (CAPE's own guest-customization tool) plus the additional SMBIOS/registry/filesystem normalization from Section 3.1, layered on top of VMCloak's baseline rather than replacing it.
2. **ETW-based behavioral capture**, run alongside (and eventually potentially replacing) CAPE's native `capemon` user-mode API-hooking agent, for the evasion-resistance reasons detailed in Section 3.3.
3. **A custom reporting/export module** — implemented as a CAPEv2 "reporting module" plugin (CAPE's own extension point, not a fork of its core) — that reformats CAPE's native per-analysis output into the exact C2/Exfiltration handoff contract in Section 3.4.

This keeps the project's original work concentrated on the genuinely novel/high-value pieces (evasion resistance, the ETW capture layer, the handoff contract) while inheriting CAPEv2's years of packer-unpacking, process-injection detection, and static-analysis engineering rather than re-deriving it.

**Repository/language strategy:** this repository is the implementation home for the plan, not a Rust-only application. CAPEv2-integrated components are written in the language CAPEv2 expects (primarily Python for reporting modules, install glue, and CAPE API integration). Custom standalone components that are not dependent on CAPEv2 internals — for example a handoff schema validator, mock C2 consumer, pre-triage worker, or packaging helper — should be written in Rust where practical. The existing Rust hello-world crate is only a starter placeholder and does not constrain the architecture.

Scope boundaries:
- **In scope:** guest VM lifecycle (via CAPEv2 + VMCloak on libvirt/KVM), anti-evasion hardening on top of CAPEv2's baseline, static triage (partially CAPE-native, partially custom pre-triage — Section 3.2), YARA/AV-aggregation scanning, detonation orchestration (CAPEv2's own task queue/machinery, not a custom broker), ETW-based behavioral capture as a CAPE-adjacent addition, PCAP capture (CAPE-native), IOC extraction, per-sample reporting (human + machine readable, via a custom CAPE reporting module), evidence packaging into the handoff contract.
- **Out of scope:** C2 beacon classification, exfiltration heuristics, cross-sample correlation, any long-term threat-intel storage, any Linux/macOS/mobile detonation targets (Windows only for this module), and any modification to CAPEv2's own core analysis/processing pipeline beyond adding reporting-module plugins and guest-image customization.
- **Explicitly excluded from this plan:** anything that would function as offensive tooling. Every anti-evasion technique below is described at the level of "what artifact is normalized and why a sandbox needs to normalize it" — not as a packaged evasion toolkit, and not with implementation-ready shellcode, hook-bypass code, or exploit primitives. Where a public open-source project already solves a piece (al-khaser, Pafish, INetSim, YARA, VMCloak, CAPEv2 itself), the plan says so and defers to it rather than re-deriving the technique.

---

## 2. Architecture Overview

```
                         ┌─────────────────────────────────────────┐
                         │        CAPEv2 Submission (REST API /       │
                         │        utils/submit.py) — sample intake    │
                         └───────────────────┬───────────────────────┘
                                              │
                       ┌──────────────────────┼──────────────────────┐
                       │                       │                      │
                       ▼                       ▼                      │
           ┌───────────────────┐   ┌───────────────────────────┐     │
           │  Pre-Triage         │   │   CAPEv2 Task Queue          │    │
           │  Subsystem (custom) │   │   & Machinery (libvirt/KVM)   │   │
           │  (typing, ssdeep,   │   │  native CAPE scheduling —      │   │
           │  hypothesis list)   │   │  checkout, snapshot revert,     │   │
           └─────────┬──────────┘   │  launch — REUSED, not rebuilt   │   │
                     │              └───────────┬───────────────────┘   │
                     │  (hypothesis fed                                  │
                     │   into CAPE task options)                        │
                     │                          ▼                        │
                     │              ┌─────────────────────────────┐     │
                     │              │  Windows Guest VM              │    │
                     │              │  (VMCloak-built + custom        │   │
                     │              │   anti-evasion overlay)          │   │
                     │              │  - CAPE agent.py (control ch.)   │   │
                     │              │  - capemon (native, optional)    │   │
                     │              │  - ETW agent (custom, primary)   │   │
                     │              │  - interaction simulator (custom)│   │
                     │              └───────────┬───────────────────┘   │
                     │                          │                       │
                     │        ┌─────────────────┼─────────────────┐     │
                     │        ▼                 ▼                 ▼     │
                     │  ┌───────────┐   ┌───────────────┐  ┌─────────────┐
                     │  │ CAPE native│   │ ETW / kernel   │  │ CAPE native  │
                     │  │ PCAP       │   │ event exporter │  │ dropped-file │
                     │  │ (dump.pcap)│   │ (raw ETL)      │  │ + behavior    │
                     │  │            │   │ (custom)       │  │ log (native)  │
                     │  └─────┬─────┘   └───────┬────────┘  └──────┬───────┘
                     │        │                 │                  │
                     └────────┴────────┬────────┴──────────────────┘
                                        ▼
                         ┌───────────────────────────────────┐
                         │  Custom CAPE Reporting Module          │
                         │  (reformats CAPE's native report.json  │
                         │   + raw Windows telemetry into the      │
                         │   handoff contract,                    │
                         │   hash-chains the bundle)               │
                         └───────────────┬─────────────────────┘
                                          ▼
                         ┌───────────────────────────────┐
                         │   Handoff Artifact Bundle        │
                         │   → C2/Exfiltration Module        │
                         └───────────────────────────────┘
```

Control flow is CAPEv2's own — its task queue and machinery module (configured for KVM/libvirt) own detonation scheduling and snapshot-revert-and-launch natively, so this plan does not rebuild that broker. The custom pieces are the pre-triage hypothesis feed (which annotates CAPE task options, e.g. extended timeout, before submission), the parallel ETW capture path, and the reporting-module plugin that owns writing the final, sealed handoff bundle — the only component permitted to do so.

---

## 3. Component-by-Component Design

### 3.1 Guest Environment & Anti-Evasion

**Guest OS choice:** Windows 10 22H2 x64, not Windows 11. Justification: Windows 11's TPM/Secure Boot/VBS requirements add substantial QEMU/OVMF configuration overhead and additional fingerprintable virtualization artifacts (vTPM device presence, HVCI state) for an MVP with a small team. Windows 10 22H2 still receives enough real-world malware targeting to be representative, and its lighter resource footprint allows more disposable clones per host. Windows 11 support is a stretch-goal image variant, not a v1 requirement.

**Provisioning strategy — built via VMCloak, on CAPEv2's machinery:**
- CAPEv2 ships **VMCloak**, a purpose-built tool for exactly this job: scripted, unattended Windows install (its own `autounattend.xml` generation), baseline software installation, and automatic installation of CAPE's `agent.py` control-channel service into the image. The golden image is built through VMCloak rather than a hand-rolled `virt-install` script, so the team inherits VMCloak's existing "lived-in" software seeding and its CAPE-agent bootstrapping for free.
- **The team's original work at this layer** is a post-VMCloak hardening pass: after VMCloak produces its base image, a scripted pass applies the additional SMBIOS/registry/filesystem-noise normalization detailed below — items VMCloak does not fully cover out of the box — before the image is sealed as the golden snapshot. This is implemented as an additional provisioning script layered on top of VMCloak's output, not a modification to VMCloak itself, so upstream VMCloak updates can still be pulled in cleanly.
- Golden image is fully patched, the VMCloak baseline plus the custom hardening pass are both applied, and the VM is shut down cleanly to create the **base QCOW2 snapshot** registered with CAPEv2's `kvm` machinery module.
- Every detonation uses **CAPEv2's own machinery-managed libvirt snapshot + linked-clone mechanism** (its `kvm.py` machinery module handles snapshot-revert-and-launch as part of normal task scheduling) — this plan does not reimplement that broker logic; it configures CAPE's machinery config (`kvm.conf`) to point at the hardened golden snapshot. The golden base is never mutated; CAPE's own revert-per-task behavior gives disposable, per-detonation clones without re-provisioning a full OS each run.
- A scheduled job re-runs the VMCloak build + custom hardening pass on a fixed cadence (e.g., monthly) to pick up patches and refresh "lived-in" noise, keeping the sandbox from becoming trivially fingerprintable by its own staleness, with the refreshed image re-registered in CAPE's machinery config.

**Anti-VM-detection / anti-sandbox remediations (named techniques):**
- **CPUID/MSR hiding:** enable QEMU/KVM's `hv_vendor_id` override and `kvm=off` hidden-hypervisor CPUID leaf masking so `CPUID.1:ECX[31]` (the hypervisor-present bit) and vendor ID strings don't read as KVM.
- **Device/driver disguise:** replace default QEMU device identifiers where this is supported by libvirt/QEMU configuration (e.g., `QEMU HARDDISK`, `QEMU DVD-ROM` strings visible via SCSI INQUIRY/WMI `Win32_DiskDrive.Model`) with generic OEM-style strings. The MVP does **not** modify, rename, or re-sign virtio drivers; that path is too fragile for v1 and can create driver-signing/stability problems. Any remaining literal virtio/QEMU artifacts are measured by al-khaser/Pafish and documented as residual risk unless CAPEv2's own `kvm-qemu.sh` hardening already handles them cleanly.
- **SMBIOS/BIOS/DMI normalization:** set libvirt/QEMU SMBIOS type 0/1/2/3 fields (BIOS vendor, system manufacturer, product name, serial numbers, board serial) to plausible consumer-OEM values (e.g., a Dell/Lenovo-style vendor string) rather than the QEMU defaults, since these are read directly by `wmic bios get`, `Get-CimInstance Win32_ComputerSystem`, and known checks in Pafish/al-khaser.
- **Registry artifact humanization:** populate `HKLM\HARDWARE\Description\System\SystemBiosVersion`, `HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum` (which often contains literal `VBOX`/`VMware`/`QEMU` substrings), and common VM-detection registry keys checked by Pafish (`HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions`, VMware tools keys) — ensure none of the QEMU/KVM equivalents exist under those paths.
- **Hostname/username/domain:** golden image uses a non-default, human-plausible hostname (not `DESKTOP-<random>` default patterns tied to install date) and a domain-joined-looking or plausible workgroup name, avoiding literal strings like "sandbox," "malware," "test," or "sample."
- **"Lived-in" filesystem noise:** seed realistic recent-documents (`%APPDATA%\Microsoft\Windows\Recent`), browser history/cookies/bookmarks (a scripted headless browsing session against benign sites during image build), a handful of installed non-security software entries in `Add/Remove Programs`, and a populated `%TEMP%`/Downloads folder — countering al-khaser's "too clean a machine" heuristics.
- **Resource realism:** allocate ≥4 vCPU / ≥8GB RAM / ≥80GB disk to the guest, since single-core/low-RAM/small-disk configurations are a classic and trivially-checked sandbox tell (`GetSystemInfo`, `GlobalMemoryStatusEx`, free disk space checks).
- **Uptime plausibility:** avoid detonating immediately after a fresh boot; script a short "idle warm-up" period post-boot before sample execution so `GetTickCount`-based freshness checks don't trivially flag a zero-uptime machine.
- **Human-interaction simulation:** a lightweight in-guest agent that generates periodic mouse movement (non-linear, with jitter, not perfectly straight lines), occasional window focus changes, and simulated keyboard activity during the detonation window, to defeat interaction-gated payloads that check for `GetLastInputInfo` idle time or cursor-position deltas.
- **Timing/sleep-acceleration handling:** hook or patch known sleep-acceleration-detection vectors is explicitly **not** done via kernel patching for the MVP (too fragile, too close to offensive tooling); instead the MVP takes the simpler defensive posture of *not* artificially accelerating sleeps at the hypervisor level, and instead extends detonation windows to tolerate malware that legitimately sleeps, with an optional escalation to time-dilation only as a documented stretch goal.
- **RDTSC/timing checks:** documented as a **known partial-failure area** for the MVP (see Section 5) — QEMU/KVM TSC virtualization overhead is inherent, and defeating fine-grained RDTSC-delta VM-detection reliably typically requires hardware-assisted virtualization countermeasures beyond MVP scope.

**Evasion test-suite baseline — what "pass" means for MVP:**
al-khaser and Pafish are strict validation gates for the MVP-scoped static/configurable sandbox-detection subset. They are not runtime dependencies and not implementation recipes. The image must pass checks that can be addressed through CAPEv2 scripts, VMCloak customization, libvirt/QEMU configuration, SMBIOS/DMI settings, registry/profile cleanup, resource realism, and environment humanization. Findings requiring driver modification, driver re-signing, kernel patching, non-standard QEMU builds, or timing-counter defeat are documented as residual risk and deferred.

This is a **Strict Subset Gate**, not a full all-check pass. The golden image cannot pass MVP acceptance unless both tools have been run manually inside the guest and the agreed static/configurable categories pass. Timing, deep hypervisor, debugger, custom-driver, and custom-QEMU findings are recorded in the validation report but do not block MVP.

**Network egress strategy:** MVP uses **INetSim** (or **FakeNet-NG** as an alternative) for simulated internet — DNS, HTTP/HTTPS, SMTP, FTP responders — running on the host or an isolated egress VM, with the guest's only route being to this simulator. This is chosen over live/controlled egress for the MVP because: (a) it removes legal/ethical exposure of the research team's IP participating in live C2 infrastructure, (b) it guarantees the network capture is fully reproducible and safe to share as a teaching artifact, (c) it's the standard approach in CAPE/Cuckoo-style academic sandboxes. **Trade-off for the C2 module:** simulated egress means the C2/Exfiltration module receives connection *attempts* (destination IPs/domains, protocol, payload shape) rather than real C2-server responses — it can detect beaconing cadence, DNS-tunneling-shaped queries, and destination-reputation flags, but cannot observe a live C2 server's actual response content. This is documented explicitly in the handoff contract (Section 4) so the C2 module's design accounts for "attempted, not completed" sessions. A live-egress mode (routed through a monitored, rate-limited, non-attributable egress point) is listed as a stretch goal only, requiring separate ethics/legal review.

### 3.2 Static Analysis Subsystem

**Pre-detonation triage pipeline (ordered):**
1. **File typing** — `libmagic`/`file`-equivalent + container-aware sniffing (PE, ELF, script/text, archive, Office/OLE, PDF). Non-Windows-relevant types are tagged and can short-circuit to a "non-Windows sample" branch (out of WinST/DT scope, handed elsewhere).
2. **Hashing** — MD5, SHA-1, SHA-256, and **ssdeep** (fuzzy hash) computed immediately and used as the sample's canonical identity for the rest of the pipeline.
3. **PE parsing** (via `pefile`-equivalent library): PE header fields (machine type, timestamp, subsystem), section table (names, virtual size vs. raw size — a classic packer tell when they diverge sharply), entry point RVA and which section it lands in, import table (DLL + function names — flag suspicious API combinations like `VirtualAlloc`+`WriteProcessMemory`+`CreateRemoteThread`), export table, resource directory (icons, version info, embedded manifests), Rich header, digital signature (Authenticode) presence and validity, TLS callback table presence (a common anti-debug/early-execution vector worth flagging, not exploiting).
4. **Packer/obfuscation detection** — signature-based (PEiD-style / `Detect It Easy` database) plus heuristic entropy scanning per section; a section with entropy > ~7.2 and executable+writable characteristics is flagged as likely packed/encrypted.
5. **String analysis** — ASCII + UTF-16LE string extraction with a curated regex set for IOC-shaped strings (IPv4/IPv6, URLs, file paths, registry paths, mutex-name patterns, base64 blobs above a length threshold worth flagging for later decode-on-demand).
6. **Entropy analysis** — whole-file and per-section Shannon entropy, feeding the packer heuristic above.
7. **Digital signature validation** — Authenticode chain validation against a bundled trust store; unsigned or invalid-signature binaries get a risk-score bump.

**YARA integration:**
- Rule corpus organized into tiers: a **fast tier** (small, high-confidence rules — magic bytes, known packer signatures, known malware-family string sets) run on every sample synchronously in the triage path; a **deep tier** (larger community rule sets, e.g., a curated subset of YARA-Forge or Neo23x0's signature-base) run asynchronously and its results merged in before the final report is sealed, not blocking triage latency.
- Rule sourcing: pull from a small number of maintained public repositories (checked out as a git submodule, updated on a scheduled job, never live-fetched per-scan) plus a `rules/local/` directory for team-authored rules from CTF/research findings.
- Scan-time placement: fast tier runs immediately after hashing, before full PE parse completes, so an immediate high-confidence YARA hit can short-circuit unnecessary further static work if the sample is trivially known-bad; deep tier runs in parallel with PE/string analysis.
- Performance: `yara-python` compiled rule caching (compile once, reuse the compiled ruleset object across scans within a worker process lifetime) rather than recompiling per sample; deep-tier rule count capped for MVP (a few thousand rules) with a documented scan-time budget (e.g., 5s timeout) to avoid a pathological rule stalling the queue.

**Local multi-engine scanning ("VT-style" aggregation):**
- MVP local aggregator wraps **ClamAV** (open-source, easy to self-host) plus the YARA deep-tier verdict, presented as a unified "N/M engines flagged" style summary — explicitly labeled as heuristic/open-source-only, not a claim of commercial-AV-equivalent coverage.
- **Real VirusTotal API** lookup is a supplementary, optional enrichment step: a hash-only lookup (never uploading the sample itself, to avoid leaking research samples into a public corpus) queried *after* local hashing, cached aggressively, and explicitly non-blocking — if the API is unreachable or rate-limited, the pipeline proceeds without it and marks that field `"vt_lookup": "unavailable"` in the report rather than failing the job.

**Static risk scoring:** a simple weighted sum (not a black-box ML model for MVP) over: YARA fast-tier hit (+high), YARA deep-tier hit (+medium), packer detected (+medium), invalid/missing signature (+low-medium), suspicious import combination present (+medium), VT hash reputation if available (+variable). The resulting score and the specific triggered heuristics are passed to the detonation subsystem as a **hypothesis list** — e.g., "packed + CreateRemoteThread import present" tells the dynamic stage to weight process-injection-related ETW events more heavily in the summary, and to extend the detonation timeout since packed samples often unpack slowly.

### 3.3 Dynamic Detonation Subsystem

**Orchestration — CAPEv2 owns this, not a custom broker:**
- Submission goes through **CAPEv2's own task API** (`utils/submit.py` for CLI/scripted submission, or the Django REST API for programmatic submission from the pre-triage subsystem) rather than a hand-built queue table. CAPE's task table (backed by its own Postgres/MongoDB-configured storage) already tracks `pending → running → completed/failed` status per task, which this plan reuses directly.
- **MongoDB compatibility exception:** on the current kernel `6.19+`/`7.x` host class, MongoDB is intentionally pinned to `8.0.4` because newer MongoDB 8.0 packages fail to start. This is accepted only for a local CAPE analysis host with MongoDB bound to `127.0.0.1:27017`, all MongoDB server/meta packages held, and health monitoring that reports version, hold state, bind address, and exposure status. It is not acceptable for a network-exposed database.
- **VM checkout/snapshot-revert/launch** is handled entirely by CAPE's `kvm` machinery module against the libvirt host from Section 8 — this plan configures `conf/kvm.conf` to point at the hardened golden snapshot (Section 3.1) and defines the guest pool size there; it does not reimplement broker logic.
- **Timeout/kill conditions:** set via CAPE's native per-task `timeout` option (MVP default: 5 minutes, extended to 8–10 minutes when the pre-triage hypothesis list — Section 3.2 — flags "packed," passed in as a task option at submission time rather than a hardcoded value). CAPE's own analyzer already implements a heartbeat-style completion/hang detection; this plan relies on that rather than building a parallel watchdog.
- **Safe teardown** is CAPE-native: its machinery module reverts the guest to the golden snapshot after each task, discarding the overlay automatically as part of normal task completion — no custom teardown code required.

**In-guest instrumentation — ETW added alongside CAPE's native monitor:**
- CAPEv2 ships its own in-guest instrumentation (`capemon`, a user-mode API-hooking DLL injected per-process, the classic Cuckoo-lineage approach) plus `agent.py` as the control channel. This plan **keeps `agent.py`** (needed for CAPE's task control, file drop-off, and result retrieval — no reason to replace it) but treats `capemon`'s hooking as **optional/secondary** rather than the primary source of behavioral truth, for the evasion-resistance reasons below.
- The guest image must run a CAPE agent matching the live CAPEv2 checkout on primary port `8000`. The helper `scripts/stage-cape-guest-agent.sh` may validate a modern agent on alternate port `8001`, but CAPE's runtime uses hardcoded guest port `8000`, so durable replacement belongs in the golden-image reseal workflow.
- **ETW is added as the primary custom instrumentation layer**, running as a separate background service in the VMCloak-built image (installed during the post-VMCloak hardening pass, Section 3.1), consuming Microsoft-documented, built-in providers where available (no custom kernel driver required) and writing raw trace data in `.etl` format. The capture system follows graceful degradation: the trace session is required, but individual analytical providers are feature-flagged instead of being binary pass/fail requirements.
  - **Required capture capability:**
    - The telemetry agent must start.
    - The telemetry trace session must run during detonation.
    - A non-empty raw `.etl` artifact must be retrieved.
    - Provider availability must be recorded in the manifest.
  - **Baseline provider targets:**
    - `Microsoft-Windows-Kernel-Process` — captures process/thread create-exit and image-load context needed for process lineage.
    - `Microsoft-Windows-Kernel-File` — captures file create/write/delete/rename activity.
    - `Microsoft-Windows-Kernel-Registry` — captures registry key/value create/set/delete activity.
    - `Microsoft-Windows-Kernel-Network` — captures TCP/UDP connection events for correlation with CAPE PCAP.
    - These providers are expected for MVP validation, but provider absence degrades telemetry rather than failing the capture session unless the ETL trace itself is unusable.
  - **Optional analytical providers:**
    - `Microsoft-Windows-Kernel-Image` — captures module/image load events where available and stable.
    - `Microsoft-Windows-Threat-Intelligence` (`ETW-TI`) — useful for remote thread creation, memory protection changes, process hollowing-shaped behavior, and other high-signal kernel-level suspicious activity.
    - `Microsoft-Windows-Kernel-Memory`, if later added.
- **ETW-TI and `Kernel-Image` are not MVP blockers.** The telemetry agent must attempt to enable optional providers in probe mode where configured, record whether they are available, and include the result in the handoff manifest. If unavailable or silent, the session remains valid as long as a usable ETL trace and required CAPE-native outputs are present.
- **Why run both during MVP validation, and the plan to converge:** `capemon`'s DLL injection is itself a known sandbox tell that some evasive malware checks for (unexpected modules loaded into its own process), while ETW is kernel-emitted and much harder to detect from user mode. For the MVP, **both run in parallel** — this gives a direct, evidence-based comparison of what each captures on the same sample set, which is valuable both for validating the ETW agent's coverage against CAPE's mature `capemon` baseline and for the project's own evaluation writeup. The documented intent is to **disable `capemon`'s hooking once ETW coverage is validated as sufficient** for the taxonomy below, reducing the guest's fingerprint surface — this is a Section 6 milestone, not a day-one requirement.
- **Low-fingerprint instrumentation:** the ETW consumer runs as a background service under a plausible, non-suspicious process/service name (not `etwagent.exe` or `monitor.exe`), started at boot before the sample is delivered, so no new "monitoring tool just appeared" artifact coincides with detonation start.

**Behavioral event taxonomy captured (merged from CAPE-native + ETW sources):**
- Process tree/lineage (PID/PPID chains, command lines, image paths) — available from both CAPE's native behavioral log and ETW's Kernel-Process provider; the custom reporting module (Section 3.4) prefers the ETW source when both are present, since it's the more evasion-resistant capture path.
- File system operations (create/write/delete/rename, with path and, for small files, a content hash of the final state)
- Registry operations (key/value create/modify/delete, especially `Run`/`RunOnce`, services, scheduled-task-related keys)
- Network connections (5-tuple, direction, byte counts, correlated to PCAP) — CAPE's native `dump.pcap` plus ETW's Kernel-Network events, cross-referenced
- Injected/loaded modules (unusual `LoadLibrary` targets, unsigned DLLs loaded into signed processes)
- Privilege escalation attempts (token manipulation events, UAC bypass-shaped process chains)
- Persistence mechanism creation (Run keys, scheduled tasks, services, startup folder writes) — explicitly flagged as a distinct IOC category in the report

**Human-interaction simulation during detonation:** a jitter-mouse/window-focus agent (custom, installed during the post-VMCloak hardening pass) runs continuously through the detonation window — CAPE's own auxiliary modules include basic human-interaction simulation, but this plan supplements it with the more deliberately non-linear jitter behavior described in Section 3.1, so interaction-gated payloads triggered mid-execution are still covered.

### 3.4 Telemetry Capture & Export — the C2 Module Handoff (critical)

**This entire subsystem is implemented as a custom CAPEv2 reporting module** (dropped into CAPE's `modules/reporting/` directory and registered in `conf/reporting.conf`), which CAPE invokes automatically at the end of every completed task's processing pipeline. This is the cleanest integration point CAPE exposes for exactly this purpose — it runs after CAPE's own processing/signature stages have already populated the task's result dictionary, so the custom module's job is purely to **read CAPE's native results and the parallel ETW capture, then reshape both into the handoff contract** — not to duplicate any capture logic itself.

**Network capture:**
- **CAPE-native**, not custom: CAPEv2 already performs host-side PCAP capture per task (its `dump.pcap`, written under `storage/analyses/<task_id>/`) via a tap on the machinery-managed guest interface. This plan reuses that capture directly rather than standing up a parallel `tcpdump` process — CAPE's existing per-task isolation (one capture file per task ID) already satisfies the per-sample isolation requirement.
- Host-side (not in-guest) capture is CAPE's existing approach, chosen for the same reason this plan would have chosen it independently: a compromised/evasive guest cannot detect or tamper with a capture process it never has access to.
- The custom reporting module's job here is narrow: copy/rename `storage/analyses/<task_id>/dump.pcap` into the handoff bundle's `network/capture.pcapng` path (converting `.pcap` → `.pcapng` if needed for extended metadata support), preserving CAPE's original capture timestamps.

**ETW export:**
- Raw Windows telemetry is retained as **ETL for the MVP**. The ETW agent writes trace-session output to `behavior/trace.etl`; there is no EVTX shipping, EVTX conversion, or JSONL conversion in MVP.
- The raw `.etl` is pulled off the guest via CAPE's existing `agent.py` file-retrieval channel (no separate file-transfer mechanism needed — this plan reuses CAPE's control channel rather than building a new one). A future structured export, likely `events.jsonl`, remains a documented extension once the C2/Exfiltration team confirms required fields and parser ownership.
- Correlation to session: CAPE's own `task_id` is adopted directly as this plan's `session_id` (no separate UUID scheme needed — one less moving part) — every exported event, the PCAP filename, and the directory structure all key off the same CAPE-assigned identifier.

**Exact handoff contract:**

Directory structure per completed detonation (batch handoff — MVP does not need streaming; the C2 module consumes complete sessions, not live ones):

```
/handoff/{session_id}/
    manifest.json              # metadata envelope, see schema below
    sample.meta.json           # static analysis output (hash, PE metadata, YARA/AV verdict)
    network/
        capture.pcapng          # full session capture, host-tap origin
    behavior/
        trace.etl               # raw ETW trace, MVP handoff format
    hashes.sha256               # hash-chain manifest, see Evidence Integrity below
```

`manifest.json` schema (the metadata envelope; exact JSON Schema lives under `schemas/handoff_manifest.schema.json` in the implementation repo):
```json
{
  "schema_version": "1.0",
  "session_id": "string, == CAPEv2 task_id",
  "status": "completed | capture_error | analysis_error | timeout",
  "errors": [
    {
      "stage": "pretriage | cape_submission | detonation | capture | packaging | reporting",
      "code": "string",
      "message": "string"
    }
  ],
  "sample_sha256": "hex",
  "submitted_at_utc": "ISO8601",
  "detonation_start_utc": "ISO8601",
  "detonation_end_utc": "ISO8601",
  "guest_vm_identity": {
    "image_version": "string, golden-image build tag (VMCloak build + hardening pass id)",
    "vm_uuid": "libvirt domain uuid",
    "guest_ip": "string, for correlating PCAP src address"
  },
  "network_mode": "simulated_inetsim | live_egress",
  "static_risk_score": "number",
  "static_hypotheses": ["packed", "suspicious_imports:CreateRemoteThread", "..."],
  "cape_task_id": "integer, CAPEv2's native task identifier (== session_id above)",
  "capemon_enabled": "boolean, whether CAPE's native monitor ran alongside ETW for this session",
  "telemetry": {
    "format": "etl",
    "artifact_path": "behavior/trace.etl",
    "capture_started": true,
    "capture_completed": true,
    "telemetry_degraded": false,
    "degradation_reasons": [
      {
        "provider": "Microsoft-Windows-Kernel-Image",
        "reason": "provider_missing | access_denied | no_events_observed | agent_error | unknown",
        "message": "string"
      }
    ],
    "providers_targeted": [
      "Microsoft-Windows-Kernel-Process",
      "Microsoft-Windows-Kernel-File",
      "Microsoft-Windows-Kernel-Registry",
      "Microsoft-Windows-Kernel-Network",
      "Microsoft-Windows-Kernel-Image",
      "Microsoft-Windows-Threat-Intelligence"
    ],
    "providers_enabled": ["string"],
    "providers_unavailable": [
      {
        "provider": "string",
        "reason": "access_denied | provider_missing | no_events_observed | agent_error | unknown",
        "message": "string"
      }
    ],
    "etw_ti_status": "enabled_and_observed | enabled_no_events | unavailable | not_attempted"
  },
  "tool_versions": {
    "cape_git_ref": "rolling release commit observed at analysis time",
    "winstdt_schema_version": "1.0",
    "winstdt_reporting_module_version": "semver or git ref",
    "winstdt_guest_agent_version": "semver or git ref",
    "yara_rules_ref": "git ref or corpus build id",
    "clamav_db_version": "string"
  },
  "artifact_paths": {
    "pcap": "network/capture.pcapng",
    "trace_etl": "behavior/trace.etl"
  },
  "integrity": {
    "hash_manifest": "hashes.sha256",
    "hash_manifest_sha256": "hex",
    "hash_log_ref": "append-only host log offset/id, if available"
  }
}
```
- **Telemetry capability defaults:** `telemetry.etw_ti_status` is always present. Missing, empty, corrupt, or unretrievable ETL trace data marks the session `"status": "capture_error"` with an error at `"stage": "capture"`. Missing provider data does **not** mark the session `capture_error`; it sets `telemetry.telemetry_degraded = true`, records the provider under `providers_unavailable`, and adds a `degradation_reasons` entry. Missing ETW-TI or `Kernel-Image` does not fail the bundle; `"not_attempted"` is valid only when probe mode did not run and must be treated as a validation gap, not as evidence that ETW-TI is unsupported.
- **Timing model:** batch handoff. The reporting module writes the full bundle for a `session_id` atomically (temp path, then renamed into `/handoff/`) once CAPE marks the task's processing pipeline complete, so the C2 module never sees a partially-written session. A future streaming mode is a documented stretch goal, not MVP.
- **Naming/session convention:** `session_id` **is** CAPEv2's own `task_id` (adopted directly rather than minted separately) and is used as the sole cross-referencing key across every artifact and directory — the C2 module needs no other lookup mechanism, and this plan avoids maintaining a second identifier scheme alongside CAPE's own.
- **Schema validation:** the implementation repo includes Rust-based validation tooling for `manifest.json`, `sample.meta.json`, and the directory structure. This validator is used by both the mock C2 consumer and the final CAPE reporting module tests, so schema drift is caught before a bundle reaches `/handoff/`.

**Evidence integrity:** every file under `/handoff/{session_id}/` is hashed (SHA-256) into `hashes.sha256` at packaging time, and `hashes.sha256` itself is signed (or at minimum, its own hash is recorded in an append-only, host-side log outside the guest's reach) to provide tamper-evidence consistent with a basic forensic chain-of-custody model. Full cryptographic chain-of-custody (timestamping authority, HSM-backed signing) is a stretch goal; the MVP requirement is simple, verifiable SHA-256 manifest hashing.

### 3.5 Reporting & Scoring

**Consolidated per-sample report contains:**
- Static findings summary (hashes, PE metadata highlights, packer verdict, signature validity, YARA hits by rule name, local-AV-aggregate verdict, VT hash-reputation if available)
- Dynamic behavior summary (process tree rendered as a tree/indented list, top file/registry operations, network destinations contacted)
- IOC extraction: dropped files (path + hash), C2-candidate IPs/domains (destination addresses contacted during detonation — raw candidates, not yet classified as true C2, since that classification is the downstream module's job), registry persistence keys created
- YARA/AV verdicts (already computed in static stage, surfaced here)
- Overall risk verdict: a single human-readable tier (e.g., Benign / Suspicious / Malicious) derived from combining the static risk score with a dynamic-behavior score (persistence created, injection observed, network beaconing pattern observed → escalates the tier)

**Machine-readable schema:** the same report content, additionally emitted as `report.json` with a stable, versioned schema (`"schema_version": "1.0"`) so the eventual UI and any other downstream consumer besides the C2 module can rely on field stability across platform iterations. Human-readable HTML report is templated from the same JSON object (single source of truth — never hand-authored separately) to avoid the two forms drifting out of sync. The handoff schemas (`manifest.json`, `sample.meta.json`, and the bundle directory contract) are defined separately from the analyst-facing `report.json` so C2/Exfiltration integration remains stable even if UI reporting evolves.

**Relationship to CAPEv2's own web UI:** CAPEv2 ships a full Django-based web interface with its own per-task report browsing, already populated from its native processing/signature output. This plan does **not** discard that — it's a legitimate, free analyst-facing surface for browsing raw CAPE results (process trees, screenshots, dropped files) during development and debugging. The custom `report.json`/HTML described above is a distinct, purpose-built artifact optimized for this platform's own schema and for feeding the eventual unified-tool UI; the two coexist rather than one replacing the other.

---

## 4. C2/Exfiltration Handoff Contract (summary — full spec is Section 3.4)

The consuming module's implementation only needs: (1) watch `/handoff/` for new `{session_id}` directories (or poll a lightweight "new sessions" table if a filesystem watch isn't desired), (2) read `manifest.json` for timing/identity/status context, (3) consume `network/capture.pcapng` and `behavior/trace.etl`. It must inspect `manifest.json.telemetry.telemetry_degraded` and provider availability before assuming specific event classes are present. No other coupling to WinST/DT internals is required or exposed. A future `behavior/events.jsonl` field can be added once the C2/Exfiltration team confirms its required event schema.

---

## 5. MVP Scope Table

| Capability | MVP | Deferred (stretch) | Justification |
|---|---|---|---|
| CAPEv2 + VMCloak as detonation core | ✅ | | Reuse of a mature, actively maintained sandbox core rather than a rebuild |
| Golden image + snapshot/clone detonation (via CAPE machinery) | ✅ | | Core requirement, now inherited from CAPE's `kvm` machinery module |
| SMBIOS/registry/device anti-evasion baseline (post-VMCloak hardening pass) | ✅ | | Config-only, high value, layered on top of VMCloak's existing baseline |
| `capemon` (CAPE native monitor) running alongside ETW for MVP validation | ✅ (parallel, temporary) | Disabling `capemon` once ETW coverage validated | Direct evidence-based comparison during MVP; converge to ETW-only afterward |
| RDTSC/timing-based evasion countermeasures | | ✅ | Requires hypervisor-level work beyond small-team MVP bandwidth |
| Windows 11 guest support | | ✅ | Added complexity (TPM/VBS) not worth it for v1 |
| Static triage (typing/hash/PE/entropy/strings) | ✅ | | Foundational, cheap, high signal |
| YARA fast + deep tier | ✅ | | Open-source reuse, well-understood integration |
| Local ClamAV aggregation | ✅ | | Self-hostable, no external dependency |
| Full commercial multi-AV aggregation | | ✅ | Licensing/cost prohibitive for a student project |
| VirusTotal hash-lookup enrichment | ✅ (soft dependency) | | Optional, non-blocking, adds value when available |
| ETW trace-session capture with provider feature flags | ✅ | ETW-TI promotion after golden-image validation | Built-in Windows capability, no custom driver needed; missing analytical providers degrade telemetry rather than failing the session |
| Additional custom user-mode API hook instrumentation beyond CAPE `capemon` | | ✅ | CAPE `capemon` runs during MVP validation; building a separate hook framework adds fingerprint risk and engineering cost beyond MVP need |
| Host-side PCAP capture via INetSim | ✅ | | Safe, reproducible, standard academic approach |
| Live/controlled egress mode | | ✅ | Legal/ethics review required first |
| Mouse-jitter/interaction simulation | ✅ | | Cheap, directly defeats a common evasion class |
| Batch handoff artifact bundle | ✅ | | Matches C2 module's stated consumption model |
| Raw ETL behavioral telemetry handoff | ✅ | Structured `events.jsonl` after C2 schema clarification | Uses ETW's natural trace format and avoids premature parsed-event schema commitments |
| Streaming/real-time handoff | | ✅ | Only valuable once C2 module needs near-real-time detection |
| SHA-256 evidence manifest | ✅ | | Minimal chain-of-custody baseline |
| Signed/HSM-backed chain-of-custody | | ✅ | Beyond academic MVP threat model |
| Al-khaser/Pafish: strict static/configurable subset gate | ✅ | | Blocks MVP acceptance until SMBIOS/DMI, BIOS/configurable firmware strings, registry/process/service, configurable device strings, resource realism, and environment-humanization categories pass |
| Al-khaser/Pafish: timing/debugger/deep hypervisor/custom-driver checks | | ✅ (documented residual risk) | Requires timing-counter defeat, debugger-bypass work, driver changes, kernel patching, or custom QEMU work outside MVP |
| Single-VM-at-a-time concurrency | ✅ | | Acceptable v1 throughput; see Section 6 scaling note |
| Multi-VM concurrent detonation pool | | ✅ | Straightforward extension once broker logic is proven |

### 5.1 MVP Feature Checklist

Status legend: `[x] implemented and validated`, `[~] implemented, pending runtime validation`, `[ ] not implemented`, `[gated] implemented behind disabled gate`.

- [x] CAPEv2 rolling-release deployment using CAPE scripts
- [x] Ubuntu 24.04/KVM/libvirt host
- [x] Windows 10 22H2 x64 guest
- [x] VMCloak-built golden image
- [~] Post-VMCloak hardening pass
- [~] Strict-subset al-khaser/Pafish validation gate
- [x] No driver modification/re-signing
- [x] No custom QEMU/kernel patching
- [x] CAPE-native task queue/orchestration
- [x] CAPE-native snapshot/revert lifecycle
- [x] CAPE-native PCAP capture
- [x] INetSim/FakeNet-NG simulated egress
- [x] Static triage: type, hashes, PE metadata, entropy, strings
- [gated] YARA fast/deep tiers
- [gated] Local ClamAV aggregation
- [gated] Optional non-blocking VirusTotal hash lookup
- [x] CAPE `capemon` enabled during validation
- [x] Custom ETW trace-session capture agent
- [x] Raw `.etl` behavioral telemetry handoff
- [x] Provider feature flags in manifest
- [x] `telemetry_degraded` for missing analytical providers
- [x] ETW-TI probe, non-blocking
- [x] Batch handoff bundle
- [x] `manifest.json`, `sample.meta.json`, PCAP, ETL trace, `hashes.sha256`
- [x] Rust schema validator and mock C2 consumer
- [x] Custom CAPE reporting/export module
- [x] Custom JSON/HTML report
- [x] Basic SHA-256 evidence manifest

### 5.2 Finished Module Feature Checklist

Status legend: `[x] implemented and validated`, `[~] implemented, pending runtime validation`, `[ ] not implemented`, `[gated] implemented behind disabled gate`.

- [gated] Multi-VM concurrent detonation pool
- [gated] Windows 11 guest variant
- [ ] ETW-TI promoted if validated reliably
- [gated] Structured `events.jsonl` after C2 schema agreement
- [x] Analytics that check telemetry feature flags before processing
- [gated] Streaming or near-real-time handoff
- [gated] Live/controlled egress mode after legal/ethics review
- [gated] Disable `capemon` if ETW coverage is sufficient
- [gated] Additional custom user-mode API hook instrumentation only if a post-MVP gap analysis proves CAPE `capemon` plus ETW cannot cover a required workflow
- [gated] Timing/RDTSC evasion improvements
- [gated] Deep hypervisor fingerprint mitigation where feasible
- [gated] Signed evidence manifest
- [gated] HSM/timestamp-backed chain of custody
- [gated] Multi-AV/commercial enrichment if licensed
- [x] Longer-term retention policy and cleanup automation
- [x] Monitoring/alerts for golden image staleness, disk pressure, and telemetry degradation rates

---

## 6. Build-Order / Milestone Plan

1. **Install and stand up CAPEv2 + VMCloak on the Ubuntu 24.04/KVM/libvirt host using CAPE's own scripts** (Section 8.10), configured against the `kvm` machinery module, and get a single **unmodified** VMCloak-built Windows guest successfully detonating a benign test binary end-to-end through CAPE's stock pipeline. *Why first:* validates the entire reused core works on your infrastructure before any custom code is layered on top — cheapest point to catch environment/version-mismatch problems.
2. **Anti-evasion hardening pass on top of the VMCloak image**, validated by manually running al-khaser/Pafish inside the guest and confirming the MVP-scoped strict static/configurable subset passes, with non-blocking findings recorded in `docs/validation/golden_image_report_template.md` format. *Why second:* cheap to do before custom instrumentation exists, and validates the environment itself before trusting data captured inside it.
3. **Handoff contract harness and schemas**, built before CAPE-specific export code: define `schemas/handoff_manifest.schema.json`, `schemas/sample_meta.schema.json`, fixture bundles under `tests/fixtures/handoff/`, a Rust validator, and a mock C2 consumer that watches/loads complete bundles. *Why third:* locks the inter-module contract early and lets the C2 team test against stable fixtures before real detonations exist.
4. **Pre-triage static analysis subsystem**, fully decoupled from detonation (built/tested against a static sample corpus independent of the VM work, and independent of CAPE). *Why fourth:* parallelizable with steps 1–3 by a second team member; its output (risk hypotheses) is needed to annotate CAPE task submission options in step 6.
5. **ETW/Windows telemetry capture agent validation**, installed into the hardened Windows 10 22H2 image and run alongside CAPE's native `capemon` against benign, controlled test binaries first (not real malware):
   - Validate that the ETW trace session starts, runs during detonation, produces a non-empty `trace.etl`, and that CAPE retrieves it successfully.
   - Attempt baseline providers with controlled actions: process spawn, file create/write/delete, registry set/delete, and outbound TCP/DNS activity to INetSim.
   - Attempt optional analytical providers (`Kernel-Image`, ETW-TI, and later `Kernel-Memory` if added), record permission/provider errors, run controlled behavior expected to produce relevant events if available, and record whether events were observed.
   - Record provider availability in the manifest; missing providers set `telemetry_degraded = true` rather than `capture_error`.
   - Keep `capemon` enabled in parallel for side-by-side comparison.
   - Do not block this milestone on ETW-TI unless the team later promotes it after successful repeatable validation on the actual golden image.
   *Why fifth:* validates raw ETL retrieval end-to-end and proves the baseline trace-session capability before malware detonations depend on it, while keeping analytical providers as high-value extensions rather than schedule blockers.
6. **Submission integration**: wire the pre-triage hypothesis output (step 4) into CAPEv2 task-submission options (timeout extension, etc.) via `utils/submit.py`/the REST API. *Why now:* CAPE's own orchestration (step 1) and the hypothesis source (step 4) both already exist; this is integration glue, not new capability.
7. **Custom reporting-module plugin**: build the CAPE `modules/reporting/` plugin that reads CAPE's native `dump.pcap`/`report.json` plus raw Windows telemetry, writes the exact handoff bundle from Section 3.4, and passes the Rust contract validator plus the mock C2 consumer from step 3. *Why seventh:* the plugin now targets a proven contract rather than inventing the contract while integrating with CAPE.
8. **Reporting (custom JSON + HTML)**, templated from the packaged artifact, alongside verifying CAPE's own web UI is usable for analyst debugging. *Why near-last:* purely a presentation layer over data that must already exist and be correct.
9. **Convergence decision point**: with enough side-by-side ETW-vs-`capemon` data from steps 5–8, disable `capemon`'s hooking in the guest config if ETW coverage is validated as sufficient, reducing guest fingerprint surface per Section 3.3.
10. Only after 1–9 are stable: revisit deferred items in the MVP scope table as time/team bandwidth allows, starting with multi-VM concurrency (a CAPE machinery config change, highest throughput value) before timing-based evasion countermeasures (highest engineering cost).

**Telemetry acceptance criteria:**
- A benign validation run produces a raw `behavior/trace.etl` artifact.
- Provider availability is recorded in `manifest.json`.
- Baseline providers are attempted with process, file, registry, and network validation actions.
- CAPE-native `dump.pcap` is still present and packaged.
- ETW-TI status is recorded as one of `enabled_and_observed`, `enabled_no_events`, `unavailable`, or `not_attempted`.
- A missing ETW-TI provider does not fail the session.
- A missing `Kernel-Image`, ETW-TI, or other analytical provider does not fail the session.
- A missing provider sets `telemetry.telemetry_degraded = true` with a degradation reason.
- A missing, empty, corrupt, or unretrievable ETL artifact marks the session `capture_error`.

**Telemetry testing scenarios:**
- **Trace-session happy path:** run a benign test binary/script that starts a child process, writes and deletes a file, creates and deletes a registry value, and makes a network request to INetSim. Expected: `behavior/trace.etl` exists, manifest status is `completed`, attempted providers are listed in `telemetry.providers_enabled` or `telemetry.providers_unavailable`, and CAPE PCAP exists.
- **ETW-TI available:** run ETW-TI probe behavior. Expected: `etw_ti_status = "enabled_and_observed"` if events appear, and ETW-TI is listed in `telemetry.providers_enabled`.
- **ETW-TI unavailable:** simulate or observe provider access failure. Expected: bundle remains valid, `status = "completed"` if ETL capture worked, ETW-TI is listed in `telemetry.providers_unavailable`, `telemetry.telemetry_degraded = true`, and `etw_ti_status = "unavailable"`.
- **Optional provider missing:** disable or fail `Kernel-Image` or another analytical provider in a controlled test. Expected: `status = "completed"` if ETL capture worked, `telemetry.telemetry_degraded = true`, and the missing provider appears in `telemetry.providers_unavailable`.
- **ETL artifact missing/unusable:** prevent ETL creation or retrieval in a controlled test. Expected: `status = "capture_error"`, error stage is `capture`, and the failure reason identifies missing, empty, corrupt, or unretrievable ETL data.

**Telemetry validation assumptions:**
- Windows 10 22H2 x64 remains the MVP guest image.
- Raw ETL is the locked MVP handoff telemetry format.
- `capemon` remains enabled during MVP validation for side-by-side comparison.
- ETW-TI can be promoted later only after successful repeatable validation on the actual golden image.

---

## 7. Known Limitations and Risks

- **Timing-based evasion (RDTSC/CPUID-timing) will not be defeated in the MVP.** Mitigation: document this explicitly in every report where a sample's static hypothesis suggests timing-check-capable code, so a human analyst knows to treat a "benign" dynamic verdict with skepticism for those samples.
- **al-khaser/Pafish strictness is scoped, not absolute.** Mitigation: the golden image must pass the required static/configurable gate categories, while timing, debugger, deep hypervisor, driver-modification, kernel-patching, and custom-QEMU findings are captured as residual risk in every golden-image validation report.
- **Simulated network egress means the C2 module only ever sees connection attempts, not real C2 server responses.** Mitigation: the `network_mode` field in the manifest makes this explicit per-session so the C2 module's confidence scoring can account for it.
- **Single-VM-at-a-time throughput** will bottleneck a research team submitting many samples. Mitigation: CAPE's machinery configuration is pool-size-aware from day one, so scaling to N concurrent VMs is a CAPE resource/config change, not a redesign of WinST/DT.
- **Golden image staleness** — if the monthly refresh cadence slips, the environment's "lived-in" plausibility and patch level degrade, which is itself a subtle sandbox tell. Mitigation: automate the refresh as a scheduled job with a monitoring alert if it fails to run.
- **Disk exhaustion from repeated snapshotting** — copy-on-write overlays plus retained raw `.etl`/`.pcapng` evidence accumulate quickly. Mitigation: a retention policy (e.g., raw telemetry and full PCAP retained for N days or M sessions, with schema-validated metadata and report kept indefinitely as the lightweight long-term record), plus a disk-usage guard that pauses CAPE submissions rather than letting a detonation start if free space drops below a threshold.
- **Crashed/hung guest handling** is heuristic (heartbeat timeout) for MVP, which may occasionally kill a legitimately slow-but-fine detonation or fail to catch a guest that's hung in a state that still emits heartbeats. Mitigation: log every forced-kill event distinctly in the report so an analyst can distinguish "malware evaded/hung the sandbox" from "sandbox infrastructure fault" during later review.
- **Corrupted captures** (e.g., a PCAP truncated by an unexpected host issue or a missing, empty, corrupt, or unretrievable ETL trace) should fail the session's packaging step loudly rather than silently shipping a partial artifact — the packaging stage validates required artifact presence and basic format sanity before writing the atomic handoff bundle, and marks the session `"status": "capture_error"` in the manifest rather than omitting the fields, so the C2 module can distinguish "no network activity occurred" from "capture failed." Missing optional providers do not cause `capture_error`; they set `telemetry.telemetry_degraded = true`.
- **Graceful telemetry degradation can reduce analytic fidelity.** Mitigation: downstream analytics must check `manifest.json.telemetry.telemetry_degraded`, `manifest.json.telemetry.providers_enabled`, and `manifest.json.telemetry.providers_unavailable` before processing, and degraded telemetry must be surfaced in the report rather than treated as full-fidelity behavior capture.
- **Upstream dependency risk (new, from the CAPEv2 pivot):** the project intentionally follows CAPEv2 rolling release and therefore depends on CAPEv2's release cadence, its own bugs, and possible breaking changes. Mitigation: record the exact CAPEv2 git commit in every bundle's `tool_versions.cape_git_ref`, maintain a known-good local deployment commit for rollback, and treat `git pull`/script reruns as deliberate upgrade events validated against the contract harness and benign detonation tests.
- **Pinned MongoDB risk:** MongoDB `8.0.4` is behind current patch level and may be flagged by scanners. Mitigation: bind MongoDB to localhost only, fail runtime validation on non-localhost exposure, surface the pin in `monitor-health`, and re-evaluate when MongoDB publishes a fixed secure build for kernel `6.19+`, the host moves below kernel `6.19`, CAPE no longer needs local MongoDB, or the host becomes network-exposed/production-like.
- **Reporting-module coupling to CAPE's internal schema:** the custom reporting module (Section 3.4) reads CAPE's native `report.json` structure, which is CAPE's internal implementation detail, not a documented stable API. Mitigation: write defensive parsing (missing-field tolerance, schema-version logging) in the reporting module so a rolling CAPE update doesn't silently break the handoff bundle, and re-validate the reporting module against CAPE's output after every CAPEv2 upgrade.
- **Dual-monitor (capemon + ETW) resource/complexity overhead during the MVP validation window** — running both increases guest resource usage and gives two potentially-conflicting behavioral logs to reconcile. Mitigation: this is intentionally temporary (Section 6, milestone 8); the reporting module treats ETW as authoritative when both sources report the same event, and discrepancies are logged rather than silently dropped, specifically to build the evidence base needed to justify disabling `capemon` later.

---

## 8. Ubuntu 24.04 LTS — Host Setup & Implementation Details

This section is the concrete, buildable setup guide for standing up the orchestration host. It assumes a clean Ubuntu 24.04 LTS Server install (Server, not Desktop — no need for a GUI on the orchestration host itself; `virt-manager` can be run remotely over SSH/X-forwarding or from a separate workstation) on hardware with VT-x/AMD-V and, ideally, VT-d/AMD-Vi (IOMMU) enabled in firmware for later GPU/USB passthrough flexibility, though IOMMU is not required for the MVP.

### 8.1 Base virtualization stack

```bash
# Confirm hardware virtualization is exposed to the kernel first
egrep -c '(vmx|svm)' /proc/cpuinfo   # must return > 0
```

The primary installation path is CAPEv2's own `kvm-qemu.sh` script from Section 8.10, because it installs KVM/QEMU in the form CAPE expects and includes CAPE-maintained hardening/performance choices. Manual `apt install qemu-kvm ...` setup is a fallback for troubleshooting only, not the default build path.

After the CAPE script finishes and the host is rebooted, `virt-host-validate qemu` is the fastest sanity check that KVM acceleration, cgroups, and secure guest boot support are all correctly wired before any golden-image work begins — run it again after any host kernel/BIOS change.

**OVMF/UEFI firmware:** the golden image build uses OVMF (via the `ovmf` package above) rather than legacy SeaBIOS, since a UEFI boot path is closer to a real consumer machine's boot chain and avoids a class of "this is obviously a bare-QEMU VM" fingerprints tied to legacy BIOS boot on a Windows 10 guest.

### 8.2 Storage layout for golden images and disposable clones

Use a dedicated LVM thin pool or a ZFS dataset for the QCOW2 backing chain — plain ext4 files work but make monitoring the disk-exhaustion risk from Section 7 harder to reason about. For MVP, LVM thin provisioning on Ubuntu is the lower-friction choice (no third-party PPA/module needed, unlike ZFS-on-Linux edge cases with kernel updates):

```bash
sudo apt install -y lvm2
sudo vgcreate winstdt_vg /dev/sdX          # dedicated disk/partition for sandbox storage
sudo lvcreate -L 500G --thinpool winstdt_pool winstdt_vg
```

Directory convention on the host:

```
/srv/winstdt/
  images/golden/win10_22h2_base.qcow2      # golden, read-only after sealing
  images/clones/{session_id}.qcow2         # COW overlay per detonation, deleted on teardown
  handoff/{session_id}/                    # final packaged bundles (Section 3.4/4)
  captures/tmp/{session_id}/                # in-flight ETL before packaging, if staged outside CAPE storage
  rules/yara/                               # YARA rule corpus, git submodule + rules/local/
```

A `systemd-tmpfiles` rule or a simple cron/systemd-timer job enforces the retention policy from Section 7 (delete `captures/tmp` and old `images/clones` overlays past the configured age/count threshold), and a `df`-based disk-guard script pauses CAPE submissions rather than letting a detonation start when free space on the thin pool drops below a configured floor.

### 8.3 Networking: isolated guest bridge + INetSim egress

The guest network must **not** ride the host's normal LAN/uplink — it needs an isolated bridge so the "simulated internet" (Section 3.1) is the guest's only reachable destination, and so a live-malware guest can never reach the real internet or the lab network by accident.

```bash
# Create an isolated libvirt network (NAT disabled, host-only bridge)
sudo tee /etc/libvirt/qemu/networks/winstdt-isolated.xml <<'EOF'
<network>
  <name>winstdt-isolated</name>
  <bridge name="virbr-winstdt" stp="on" delay="0"/>
  <ip address="10.66.0.1" netmask="255.255.255.0">
    <dhcp>
      <range start="10.66.0.100" end="10.66.0.200"/>
    </dhcp>
  </ip>
</network>
EOF

sudo virsh net-define /etc/libvirt/qemu/networks/winstdt-isolated.xml
sudo virsh net-autostart winstdt-isolated
sudo virsh net-start winstdt-isolated
```

This bridge is deliberately **isolated**, not NAT-forwarded to the host's default route. INetSim (or FakeNet-NG) binds to `10.66.0.1` on `virbr-winstdt` and answers every DNS query and every TCP/UDP connection attempt from the guest, regardless of destination — that's what "simulated internet" means concretely at the network layer.

```bash
sudo apt install -y inetsim
```
Key `/etc/inetsim/inetsim.conf` settings for this use case:
```
service_bind_address 10.66.0.1
dns_default_ip 10.66.0.1
start_service dns
start_service http
start_service https
start_service smtp
start_service ftp
```
INetSim is started per-detonation-batch (or left running persistently, since it's stateless per-connection) as a `systemd` service, with its own logging directory correlated into the session capture the same way the PCAP tap is.

**Host-side PCAP capture is CAPE-native.** Configure CAPE's sniffer/routing settings (`auxiliary.conf`, `routing.conf`, and the selected machinery config) so CAPE writes `storage/analyses/<task_id>/dump.pcap` for each analysis. The WinST/DT reporting module only copies/converts that CAPE-owned file into `/srv/winstdt/handoff/{session_id}/network/capture.pcapng`; it does not start a parallel `tcpdump` process and there is no custom detonation broker.

### 8.4 AppArmor considerations

Ubuntu ships libvirt with AppArmor confinement enabled by default (`/etc/apparmor.d/libvirt/`), which is worth **keeping enabled** rather than disabling — it's a genuine defense-in-depth layer given the whole point of this host is to run untrusted binaries inside guests. The one adjustment typically needed is granting the QEMU process profile read access to the golden-image path and read/write to the per-session overlay/capture paths if they live outside libvirt's default `/var/lib/libvirt/images`:
```bash
# /etc/apparmor.d/local/abstractions/libvirt-qemu (local override, survives package updates)
/srv/winstdt/images/** rwk,
/srv/winstdt/captures/** rwk,
```
```bash
sudo systemctl reload apparmor
```

### 8.5 Static analysis toolchain packages

```bash
sudo apt install -y yara python3-pip python3-venv clamav clamav-daemon \
    libmagic1 exiftool

sudo systemctl enable --now clamav-freshclam clamav-daemon

python3 -m venv /srv/winstdt/venv
source /srv/winstdt/venv/bin/activate
pip install pefile yara-python ssdeep python-magic requests
```
ClamAV's `freshclam` service handles signature updates on its own schedule; YARA's rule corpus update (Section 3.2) is a separate scheduled job (`systemd` timer, not `freshclam`) pulling the git submodule of community rules.

### 8.6 ETW capture tooling (host + guest split)

ETW itself is Windows-native and runs inside the guest — there's no Ubuntu package for ETW capture. What lives on the Ubuntu host is: (a) the guest provisioning scripts that install the in-guest telemetry capture agent (a small Python/.NET service using a library equivalent to `krabsetw` or Microsoft's `TraceEvent`, cross-compiled or installed inside the Windows golden image, not on Ubuntu itself), and (b) packaging logic that retrieves raw `.etl` traces through CAPE's existing result-retrieval path. For MVP, no host-side `.etl` parser is required for the C2 handoff. Structured conversion is deferred until the C2/Exfiltration team confirms the required schema and parser ownership.

### 8.7 Orchestration process management

**Queue and broker are CAPEv2's own processes**, not custom systemd units — `cape.py` (the task scheduler/processor) and, if the web UI is used, the Django app, are CAPEv2's native services and are managed via the systemd units CAPEv2's own install docs/`cape2.sh` script generate (Section 8.10 below sets these up). This plan does not duplicate that with a hand-built queue/broker.

What **is** custom, and does need its own systemd units, are the pieces layered on top of CAPE:

```
/etc/systemd/system/winstdt-pretriage.service   # pre-triage static hypothesis worker (Section 3.2)
/etc/systemd/system/winstdt-inetsim.service     # simulated egress, persistent
/etc/systemd/system/winstdt-reporting-watch.service  # optional: triggers/monitors the custom
                                                       # CAPE reporting-module runs; usually
                                                       # unnecessary since CAPE invokes reporting
                                                       # modules natively per completed task
```
Each custom unit runs under a dedicated unprivileged `winstdt` system user (added via `sudo useradd -r -G libvirt winstdt`) rather than root, kept separate from the `cape` service user CAPEv2's own installer creates, with `libvirt` group membership being the only elevated capability the pre-triage worker actually needs (it doesn't touch guests directly, but may query task status). When Section 6's milestone plan reaches multi-VM concurrency, that's a CAPE machinery config change (guest pool size in `kvm.conf`), not a change to these custom units at all — consistent with the scaling note in Section 7.

### 8.8 Golden image build automation (via VMCloak)

With the CAPEv2 pivot, the golden image is built through **VMCloak** rather than a hand-rolled `virt-install` invocation, since VMCloak already understands CAPE's `agent.py` bootstrapping and produces images CAPE's `kvm` machinery module can register directly (VMCloak install steps are covered in Section 8.10 alongside the rest of the CAPEv2 stack). At a high level, the sequence is:

```bash
# (after VMCloak is installed per 8.10)
vmcloak init --win10x64 --iso ./Win10_22H2_x64.iso --network 10.66.0.0/24 \
    --gateway 10.66.0.1 --cpus 4 --ramsize 8192 --hddsize 80 \
    winstdt-golden virbr-winstdt

vmcloak install winstdt-golden office firefox
```
VMCloak's `install` step handles the unattended install and baseline software seeding that Section 3.1's `autounattend.xml` approach previously described by hand. **The team's original work** is the additional hardening pass that runs immediately after this VMCloak build completes and before the image is sealed: the SMBIOS/registry/filesystem-noise normalization script from Section 3.1, applied via a guest-side provisioning script (executed once, in-guest, before final shutdown) that is *not* part of VMCloak itself.

The resulting `.qcow2` is then sealed (Sysprep'd generalization is deliberately **not** run, since Sysprep resets machine-identity artifacts in ways that can reintroduce the "too-fresh, too-generic" fingerprint the anti-evasion baseline is trying to avoid) and registered as the golden base in CAPE's `conf/kvm.conf`, referenced by every subsequent CAPE-managed linked clone.

### 8.9 Minimum host sizing (MVP, single-VM-at-a-time)

| Resource | Minimum | Rationale |
|---|---|---|
| CPU | 8 physical cores (VT-x/AMD-V) | 4 vCPU guest + host-side capture/YARA/packaging headroom |
| RAM | 32 GB | 8 GB guest + INetSim + static-analysis workers + OS overhead |
| Disk | 500 GB, SSD strongly preferred | Golden image + multiple retained sessions' PCAP/ETL before retention-policy cleanup runs |
| Network | Host uplink isolated from `virbr-winstdt`, no bridging between them | Prevents any accidental live-malware egress path (Section 8.3) |

### 8.10 CAPEv2 + VMCloak installation (the reused detonation core)

This is the piece that changes the most from a from-scratch build: rather than writing a queue/broker/machinery layer, this subsection installs CAPEv2 itself using CAPE's own maintained scripts. Manual package installation is only a fallback when debugging a failed script run.

**Service account, matching the pattern from 8.7:**
```bash
sudo useradd -r -m -G libvirt,kvm cape
```

**Clone CAPEv2 rolling release and install with CAPE scripts:**
```bash
sudo -u cape git clone https://github.com/kevoreilly/CAPEv2.git /opt/CAPEv2
cd /opt/CAPEv2

# Read script headers and replace placeholder hardware patterns before running.
sudo chmod a+x installer/kvm-qemu.sh installer/cape2.sh
sudo ./installer/kvm-qemu.sh all cape 2>&1 | tee /opt/CAPEv2/kvm-qemu.log

# Reboot after KVM/QEMU installation, then return to /opt/CAPEv2.
sudo ./installer/cape2.sh base cape 2>&1 | tee /opt/CAPEv2/cape-install.log
git rev-parse HEAD > /opt/CAPEv2/WINSTDT_CAPE_GIT_REF
```

The project follows CAPEv2 rolling release, so the exact `git rev-parse HEAD` value is recorded after every install/upgrade and copied into each handoff bundle's `tool_versions.cape_git_ref`. CAPE upgrades are deliberate `git pull` + script/config validation events, not background updates.

**Configure CAPEv2's `kvm` machinery module** to point at the isolated bridge (8.3) and the golden image (8.8):
```
# /opt/CAPEv2/conf/kvm.conf
[kvm]
machines = winstdt-golden

[winstdt-golden]
label = winstdt-golden
platform = windows
ip = 10.66.0.101
snapshot = hardened-baseline
interface = virbr-winstdt
```
`snapshot = hardened-baseline` refers to the libvirt external snapshot taken *after* both the VMCloak build and the custom anti-evasion hardening pass (8.8) — this is the single most important config line for the whole pivot, since it's what makes CAPE's native revert-per-task behavior use the hardened image rather than a stock VMCloak build.

**Install VMCloak** if the CAPE script has not already installed it (used for image building, 8.8, not for runtime detonation):
```bash
sudo -u cape /opt/CAPEv2/venv/bin/pip install vmcloak
```

**CAPEv2's own systemd units** (generated by `cape2.sh`; do not duplicate these with WinST/DT units):
```
/etc/systemd/system/cape.service          # main task processor/scheduler
/etc/systemd/system/cape-processor.service # result processing (signatures, reporting modules)
/etc/systemd/system/cape-web.service       # Django web UI (optional for MVP, useful for debugging — Section 3.5)
/etc/systemd/system/cape-rooter.service    # privileged network-routing helper CAPE uses for per-task iptables rules
```
`cape-rooter` runs with elevated network privileges by design (it's how CAPE isolates each task's network namespace) — this is upstream CAPE's own security model, reviewed and scoped by its maintainers, and is left as-is rather than modified.

**Drop the custom reporting module** (Section 3.4) into CAPE's extension point once it's written:
```bash
sudo cp winstdt_handoff_export.py /opt/CAPEv2/modules/reporting/
# then register it in /opt/CAPEv2/conf/reporting.conf as its own [winstdt_handoff_export] section, enabled = yes
```
This is the only file this plan adds *inside* CAPE's own directory tree -- everything else (pre-triage worker, ETW agent installed into the guest image, INetSim) lives outside `/opt/CAPEv2`, keeping the boundary between "reused CAPE core" and "original project work" clean and easy to point to in a writeup or defense.
