# WinST/DT Module — Evaluation Report

**Scope of this evaluation:** latest commit (`446ea13`, "Post MVP Commit") of `MYTH-il/WinST-DT-module`, plus the unversioned artifacts supplied separately. The base commit (`8c12285`, v0.21) is out of scope per request — this report evaluates the project as it stands today.

**Evaluation goal, as framed by the project owner:** get the module working and functional for a demonstration — specifically ETW capture, PCAP handoff, and working YARA/VirusTotal/ClamAV integration (static triage), with full dynamic detonation (DT) as a "nice to have, necessary later" item. A secondary, explicit goal is an honest opinion on the network simulation component and on VM realness/stealth toward the guest OS and detonated malware.

---

## 1. Overall Verdict

The project is disciplined, honestly self-assessed, and tracks its own implementation plan closely. The team's own `golden_image_report_current.md` correctly rejects MVP sign-off pending real evidence — that internal honesty is a strength, not a weakness, and this report treats it as reliable ground truth rather than second-guessing it.

The codebase splits cleanly into two very different states of readiness:

| Area | State |
|---|---|
| Static triage (YARA / ClamAV / VirusTotal) | **Functional, close to demo-ready** |
| ETW → PCAP → handoff bundle pipeline | **Functional, one blocking issue away from demo-ready** |
| Network simulation (INetSim) | **Not functional — package installed, never configured or run** |
| VM realness / anti-evasion stealth | **Mostly unimplemented — validation gate honestly reports "Pending" on nearly every check** |

---

## 2. Demo-Critical Path: ETW, PCAP, Handoff, and Static Scanners

### 2.1 What's actually working

In `src/main.rs`:
- `run_yara_tiers()` shells out to the real `yara` CLI against fast/deep rule paths (env-configured), parses hits correctly.
- `run_clamav()` calls `clamscan` and correctly maps exit codes (0 = clean, 1 = infected + parsed signature name, else = error).
- `run_vt_hash_lookup()` performs a real hash-only VirusTotal API v3 lookup via `curl`, parses `last_analysis_stats`, and degrades gracefully to `"not_configured"` / `"unavailable"` when no API key or network is present — matching the plan's "soft dependency, never blocking" design.
- The custom CAPE reporting module (`cape/modules/reporting/winstdt_handoff_export.py`) now produces `report.json` and a properly HTML-escaped `report.html`, in addition to the manifest/hash-chain bundle.
- **Real evidence of an end-to-end run exists:** the team's own validation log shows a completed CAPE task (`task 2`) that produced `dump.pcap` and a 13MB `trace.etl`, packaged into a handoff bundle that the project's own `mock-consume` command accepted as valid.

This is a genuinely strong foundation — most of what a demo needs is already wired and working, not just planned.

### 2.2 What's blocking a clean demo, in priority order

1. **Primary-port CAPE agent mismatch (fix this first).** The guest still answers on port `8000` with the legacy Cuckoo Agent 1.0. The modern agent (`0.22`, with the feature set CAPE's analyzer expects) only validates on the side-channel port `8001`. This is why analyzer logs were not collected during the CAPE-controlled run in the last validation pass. Nothing else in the pipeline can be fully trusted until the golden image is resealed with the modern agent answering on the **primary** port.
2. **Telemetry degradation is currently unexplained.** `compare-telemetry` reports `etw_enabled=4/6`, `telemetry_degraded=true`. Before presenting this live, determine *why* the other two providers are missing (permissions, provider unavailable on this Windows build, or a session-start timing race) rather than discovering it mid-demo.
3. **Rerun the full chain on the resealed image** once #1 is fixed, and bank one clean run with `"status": "completed"` and `telemetry_degraded: false` as the primary demo run. Keep a second, intentionally-degraded run as a secondary talking point ("here's how the pipeline handles partial telemetry gracefully") — that's a legitimate strength worth showing deliberately, not a gap to hide.

### 2.3 On Dynamic Detonation (DT) for the demo

Treat DT as correctly scoped as a stretch item for this specific demo. A working completed task already exists — showing the static pipeline (YARA/ClamAV/VT) live, plus a **pre-captured** DT run and its resulting handoff bundle, is a reasonable and lower-risk demo shape. A live in-front-of-an-audience detonation is not recommended until items 1–2 above are fully closed; live VM demos are exactly the kind of thing that fails at the worst moment.

---

## 3. Network Simulation — Assessment: Not Functional

This is the area with the largest gap between the implementation plan and the actual repository state.

**What exists:**
- `inetsim` is listed as an apt package in `scripts/setup-ubuntu24-host.sh`.
- The isolated bridge (`virbr-winstdt`, `10.66.0.0/24`) is correctly configured via libvirt's own DHCP.

**What does not exist anywhere in the repository:**
- No `/etc/inetsim/inetsim.conf` configuration (`service_bind_address`, `dns_default_ip`, `start_service dns/http/https/smtp/ftp`).
- No systemd enablement of the INetSim service.
- No mechanism ensuring the guest's DNS/gateway traffic actually resolves through INetSim rather than timing out.

**Practical consequence:** a detonated sample attempting outbound network activity currently gets no response at all — not a real one, not a simulated one. A PCAP will still capture the attempt (DNS queries, connection attempts), which is sufficient for the handoff contract's "attempted, not completed" framing described in the implementation plan, but any malware behavior gated on receiving *a response* (C2 check-in confirmation, a resolvable domain, a plausible HTTP response) will not trigger under the current setup.

**Recommended fix, in priority order:**
1. Write and commit an actual `inetsim.conf` bound to `10.66.0.1`, covering at minimum DNS, HTTP, and HTTPS (SMTP/FTP are lower priority for most malware-behavior demos).
2. Enable and start the `inetsim` systemd service as part of host setup — not just install the package.
3. Verify from inside the guest that DNS resolves to `10.66.0.1` and that an HTTP request receives an INetSim response, before trusting any detonation's PCAP as representative.
4. For the demo, run one detonation against a sample with known, benign-but-plausible network behavior (a DNS lookup, an HTTP GET) so the PCAP shows a completed simulated exchange rather than a stalled connection attempt.

This is estimated at roughly a day of focused work and is worth completing before the demo — network simulation is a natural thing for an audience to ask to see.

---

## 4. VM Realness and Anti-Evasion Stealth — Assessment: Mostly Unimplemented

The project's stated goal was realness and stealth of the VM/guest toward detonated malware. This is currently the weakest part of the codebase relative to what the implementation plan describes.

**What `Invoke-GuestHardening.ps1` actually implements:**
- A **resource floor check** (CPU/RAM/disk minimums) — real, functioning, and useful.
- An **identity blocklist check** (computer/user/workgroup name must not contain banned terms like "sandbox") — real, but a negative check only; it prevents an obviously bad name, it does not establish a positive, plausible identity.
- **Directory "seeding"** that creates files literally named `seed-<8-hex-chars>.txt` containing the text `"validation seed"`, purely to reach a minimum file count.

The last item deserves a direct flag: a directory full of identically-named, identically-contentful placeholder files is itself a distinguishing artifact. It satisfies a simple "is this directory empty" check, but a marginally more sophisticated evasion check that inspects file naming or content patterns would flag this as fabricated more easily than an empty directory would. This should not be presented as "lived-in" realism in a demo — it isn't yet.

**Not implemented anywhere in the repository**, despite being specified in the plan:
- SMBIOS/BIOS/DMI vendor-string overrides (still stock QEMU/libvirt defaults).
- Registry artifact scrubbing (e.g., `HKLM\SYSTEM\...\Disk\Enum`, VirtualBox/VMware guest-tool keys).
- QEMU device/driver string disguising.
- Mouse-jitter / human-interaction simulation (mentioned only in README text and test fixtures — no functioning code).
- Boot warm-up delay before detonation (same status — documented, not built).
- CPUID/MSR hypervisor-hiding — correctly deferred per the plan's own MVP scope; not a gap, a deliberate exclusion.

The project's own `golden_image_report_current.md` reflects this accurately: nearly every required anti-evasion gate row is marked "Pending," and the overall decision is **"Rejected pending evidence."** This report treats that self-assessment as correct, not overly conservative.

**Direct assessment:** the stealth/realness objective is currently the least-built part of the module, not merely the least-validated part. If asked in a demo how the sandbox defeats detection checks, the accurate answer today is: resource-size realism and an identity blocklist, with SMBIOS/registry/interaction-simulation work still outstanding. That should be stated plainly rather than implied to be further along.

**Recommended priority if any time remains before the demo** (ordered by stealth value per hour of work):
1. SMBIOS/DMI overrides via the libvirt domain XML `<sysinfo>` block — pure configuration, no new code required, highest value for the effort.
2. A short in-guest registry-scrub pass removing known VBOX/VMware keys and checking QEMU-related `Disk\Enum` strings — small, high value.
3. Replace placeholder-file seeding with genuinely varied content (a few real-looking documents, browser-history entries) rather than `seed-XXXX.txt` files.
4. Mouse-jitter and boot warm-up — lower priority for a demo specifically (not typically something an audience asks to see directly), but should remain on the near-term roadmap.

---

## 5. General Optimization Recommendations

- **Fix the CAPE agent port mismatch before anything else.** It currently blocks the validation gate and undermines confidence in every other result until resolved.
- **Keep CAPEv2 pinned to the exact commit used for the demo** (the project already records a specific git ref, `fb1cb930713a` — continue this practice) and avoid touching it again before presenting.
- Consider a pre-demo health-check command (e.g., extending `winstdt monitor-health`) that verifies: INetSim running and reachable, CAPE agent version on the primary port, golden snapshot present, disk headroom sufficient — so drift is caught automatically ahead of time rather than live.
- The `report.html` output is clean and properly escaped — favor showing this in the demo over raw JSON in a terminal, since it is more audience-friendly and already built.

---

## 6. Summary Table

| Priority | Item | Status | Effort to Close |
|---|---|---|---|
| P0 | CAPE agent primary-port mismatch | Blocking | Reseal golden image with modern agent on port 8000 |
| P0 | Explain/resolve `etw_enabled=4/6` degradation | Blocking clarity | Investigate provider availability/timing |
| P1 | INetSim configuration and service enablement | Not functional | ~1 day |
| P1 | One clean, verified end-to-end demo run | Pending on P0 | Half day once P0 resolved |
| P2 | SMBIOS/DMI overrides via libvirt `<sysinfo>` | Not implemented | Low (config only) |
| P2 | Registry artifact scrub | Not implemented | Low |
| P3 | Realistic profile/browser-history seeding | Weak (placeholder files only) | Medium |
| P3 | Mouse-jitter / interaction simulation | Not implemented | Medium |
| P3 | Boot warm-up delay | Not implemented | Low |
| Deferred (correctly, per plan) | CPUID/MSR hypervisor hiding, custom QEMU/kernel patching | Out of MVP scope | N/A |
