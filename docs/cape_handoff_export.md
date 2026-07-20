# WinST/DT CAPE Handoff Export

This directory is a repo-owned overlay for a CAPEv2 rolling-release checkout.
Install CAPEv2 and VMCloak with CAPE's own scripts first, then copy this module
into the checkout. Do not patch CAPE core for the handoff contract.

## Install

```bash
sudo install -m 0644 cape/modules/reporting/winstdt_handoff_export.py \
  /opt/cape/modules/reporting/winstdt_handoff_export.py

sudo mkdir -p /opt/cape/custom/conf/reporting.conf.d
sudo install -m 0644 cape/custom/conf/reporting.conf.d/winstdt_handoff_export.conf \
  /opt/cape/custom/conf/reporting.conf.d/winstdt_handoff_export.conf
```

Set these values in the copied config after every CAPEv2 install or upgrade:

```ini
cape_git_ref = <output of git -C /opt/cape rev-parse HEAD>
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
```

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
