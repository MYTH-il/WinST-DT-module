# WinST/DT CAPE Handoff Export

This directory is a repo-owned overlay for a CAPEv2 rolling-release checkout.
Install CAPEv2 and VMCloak with CAPE's own scripts first, then copy this module
into the checkout. Do not patch CAPE core for the handoff contract.

## Install

```bash
sudo install -m 0644 cape/modules/reporting/winstdt_handoff_export.py \
  /opt/CAPEv2/modules/reporting/winstdt_handoff_export.py

sudo mkdir -p /opt/CAPEv2/custom/conf/reporting.conf.d
sudo install -m 0644 cape/custom/conf/reporting.conf.d/winstdt_handoff_export.conf \
  /opt/CAPEv2/custom/conf/reporting.conf.d/winstdt_handoff_export.conf
```

Set these values in the copied config after every CAPEv2 install or upgrade:

```ini
cape_git_ref = <output of git -C /opt/CAPEv2 rev-parse HEAD>
image_version = <VMCloak build tag + hardening pass id>
winstdt_guest_agent_version = <ETW agent version or git ref>
yara_rules_ref = <YARA corpus commit/build id>
clamav_db_version = <ClamAV DB version>
validator_path = /srv/winstdt/bin/winstdt
```

The module writes complete bundles atomically under:

```text
/srv/winstdt/handoff/{cape_task_id}/
    manifest.json
    sample.meta.json
    network/capture.pcapng
    behavior/trace.etl
    report.json
    report.html
    hashes.sha256
```

If `behavior/trace.etl` or the CAPE PCAP is missing or empty, the module still
writes a bundle with `status = "capture_error"` and records the capture-stage
reason in `manifest.json.errors`. Missing optional ETW providers must be supplied
by the ETW sidecar metadata as provider degradation, not as a capture failure.

## Expected ETW Sidecar

The in-guest ETW agent should leave raw ETL at one of:

```text
storage/analyses/{task_id}/behavior/trace.etl
storage/analyses/{task_id}/winstdt/trace.etl
storage/analyses/{task_id}/files/behavior/trace.etl
storage/analyses/{task_id}/aux/trace.etl
```

The deployed WinST/DT CAPE auxiliary uploads through `aux/trace.etl`,
`aux/telemetry.json`, and `aux/etw_state.json` because CAPE's resultserver
whitelist permits `aux/<file>` uploads but rejects root-level files and nested
custom directories. The reporting module normalizes the final handoff path back
to `behavior/trace.etl`.

It may also leave provider metadata at the matching `telemetry.json` path:

```json
{
  "capture_started": true,
  "capture_completed": true,
  "telemetry_degraded": true,
  "providers_targeted": [
    "Microsoft-Windows-Kernel-Process",
    "Microsoft-Windows-Kernel-File",
    "Microsoft-Windows-Kernel-Registry",
    "Microsoft-Windows-Kernel-Network",
    "Microsoft-Windows-Kernel-Image",
    "Microsoft-Windows-Threat-Intelligence"
  ],
  "providers_enabled": [
    "Microsoft-Windows-Kernel-Process"
  ],
  "providers_unavailable": [
    {
      "provider": "Microsoft-Windows-Kernel-Image",
      "reason": "provider_missing",
      "message": "Provider was not available on this guest image"
    }
  ],
  "etw_ti_status": "not_attempted"
}
```

Without the sidecar, the exporter assumes the ETL trace exists but provider
capability was not observed and sets `etw_ti_status = "not_attempted"`.

## Local CLI Interfaces

The Rust tooling can validate, consume, report on, and inspect bundles without a
live CAPE instance:

```bash
winstdt validate-bundle /srv/winstdt/handoff/{task_id}
winstdt mock-consume /srv/winstdt/handoff --once
winstdt report-bundle /srv/winstdt/handoff/{task_id} --json report.json --html report.html
winstdt compare-telemetry /srv/winstdt/handoff/{task_id}
winstdt cleanup-handoff /srv/winstdt/handoff --max-age-days 30 --min-free-gb 100
winstdt monitor-health --handoff-root /srv/winstdt/handoff
```

`report-bundle` writes JSON and HTML from one shared report model. The HTML uses
plain local path labels for artifacts and does not create links that can break
when a bundle is moved.

## Disabled Gates

Raw ETL remains the authoritative behavioral artifact. Optional extensions stay
disabled unless their environment gates are set:

```text
WINSTDT_ENABLE_EVENTS_JSONL=1
WINSTDT_STREAMING_HANDOFF=1
WINSTDT_LIVE_EGRESS_ENABLED=1
WINSTDT_VM_COUNT=2
WINSTDT_SIGNING_ADAPTER=local_file
WINSTDT_LOCAL_SIGNING_KEY=/srv/winstdt/keys/local-signing.key
```

`WINSTDT_ENABLE_EVENTS_JSONL=1` writes `behavior/events.jsonl` as a structured
summary export while keeping raw `behavior/trace.etl` authoritative. Local
signing records signature metadata in `manifest.json.signature`; HSM signing is
an interface only and fails closed until a real signer adapter is configured.

Live egress is refused by `scripts/configure-cape-runtime.sh` unless approval
metadata is present:

```text
WINSTDT_LIVE_EGRESS_APPROVAL_ID
WINSTDT_LIVE_EGRESS_OWNER
WINSTDT_LIVE_EGRESS_DATE
WINSTDT_LIVE_EGRESS_ALLOWED_NETWORKS
WINSTDT_LIVE_EGRESS_RATE_LIMIT
```
