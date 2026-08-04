#!/usr/bin/env python3
"""Normalize CAPE/capemon events for the authorized C2 analyzer; never uses fixtures."""
import argparse, json
from datetime import datetime, timedelta, timezone
from pathlib import Path

def parse_time(value):
    if not value: return None
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)

p=argparse.ArgumentParser()
p.add_argument("report", type=Path); p.add_argument("clock_sync", type=Path); p.add_argument("output", type=Path)
a=p.parse_args()
report=json.loads(a.report.read_text(encoding="utf-8"))
clock=json.loads(a.clock_sync.read_text(encoding="utf-8"))
offset_ns=clock.get("offset_ns")
uncertainty_ns=clock.get("uncertainty_ns")
quality=offset_ns is not None and uncertainty_ns is not None and int(uncertainty_ns) <= 5_000_000_000
events=[]
for process in report.get("behavior", {}).get("processes", []):
    for call in process.get("calls", []):
        ts=parse_time(call.get("timestamp"))
        if ts and quality: ts += timedelta(microseconds=int(offset_ns)/1000)
        events.append({
            "timestamp_utc": ts.isoformat().replace("+00:00", "Z") if ts else None,
            "process_id": process.get("process_id"), "process_name": process.get("process_name"),
            "api_call": call.get("api"), "data_type": call.get("category", "unknown"),
            "arguments": call.get("arguments", {}), "source": "cape_capemon"
        })
out={"schema_version":"1.0","clock_correction":{"applied":quality,"offset_ns":offset_ns,"uncertainty_ns":uncertainty_ns},"host_network_correlation_enabled":quality,"events":events}
a.output.parent.mkdir(parents=True, exist_ok=True)
a.output.write_text(json.dumps(out,indent=2)+"\n",encoding="utf-8")
