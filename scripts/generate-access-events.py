#!/usr/bin/env python3
"""Convert real CAPE/capemon calls to the pinned analyzer contract."""
import argparse, json
from datetime import datetime, timezone
from pathlib import Path

API_TYPES={"CryptUnprotectData":"browser_credentials","BCryptDecrypt":"browser_credentials","SetWindowsHookExA":"keystrokes","SetWindowsHookExW":"keystrokes","GetAsyncKeyState":"keystrokes","BitBlt":"screenshot","CreateCompatibleBitmap":"screenshot","GetClipboardData":"clipboard","OpenClipboard":"clipboard","GetComputerNameExA":"system_info","GetComputerNameExW":"system_info","GetUserNameA":"system_info","GetUserNameW":"system_info","ReadFile":"file_access","CreateFileA":"file_access","CreateFileW":"file_access"}
def timestamp(value, offset):
    try:
        dt=datetime.fromtimestamp(float(value),timezone.utc) if isinstance(value,(int,float)) else datetime.fromisoformat(str(value).replace("Z","+00:00"))
        if dt.tzinfo is None: dt=dt.replace(tzinfo=timezone.utc)
        return datetime.fromtimestamp(dt.timestamp()-offset/1e9,timezone.utc).isoformat().replace("+00:00","Z")
    except (TypeError,ValueError,OSError): return None

p=argparse.ArgumentParser(); p.add_argument("report",type=Path); p.add_argument("clock_sync",type=Path); p.add_argument("output",type=Path); p.add_argument("--status",type=Path)
a=p.parse_args(); report=json.loads(a.report.read_text()); clock=json.loads(a.clock_sync.read_text())
measurements=clock.get("measurements",{}); quality=bool(clock.get("quality",{}).get("acceptable")) and bool(measurements)
offsets=[int(v.get("guest_minus_host_ns",0)) for v in measurements.values()]; offset=int(sum(offsets)/len(offsets)) if offsets else 0
events=[]
if quality:
    for proc in report.get("behavior",{}).get("processes",[]):
        for call in proc.get("calls",[]):
            api=str(call.get("api", "")); kind=API_TYPES.get(api); ts=timestamp(call.get("timestamp"),offset)
            if kind and ts: events.append({"timestamp":ts,"data_type":kind,"api_call":api,"process":proc.get("process_name")})
a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(events,indent=2)+"\n")
status={"clock_quality_acceptable":quality,"host_network_correlation_enabled":quality and bool(events),"event_count":len(events),"reason":None if quality else "clock_quality_insufficient"}
if a.status: a.status.parent.mkdir(parents=True,exist_ok=True); a.status.write_text(json.dumps(status,indent=2)+"\n")
