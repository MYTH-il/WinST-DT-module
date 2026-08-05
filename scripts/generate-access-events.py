#!/usr/bin/env python3
"""Export schema-validated CAPE/capemon access events with clock provenance."""
import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from winstdt.access_events import write_access_event_artifacts  # noqa: E402

parser = argparse.ArgumentParser()
parser.add_argument("report", type=Path)
parser.add_argument("clock_sync", type=Path)
parser.add_argument("output", type=Path)
parser.add_argument("--status", type=Path)
parser.add_argument("--etw-events", type=Path)
args = parser.parse_args()
report = json.loads(args.report.read_text(encoding="utf-8"))
clock = json.loads(args.clock_sync.read_text(encoding="utf-8"))
info = report.get("info", {})
if not info.get("started") or not info.get("ended"):
    raise SystemExit("CAPE report lacks the analysis start/end interval")
etw = json.loads(args.etw_events.read_text(encoding="utf-8")) if args.etw_events else None
status_path = args.status or args.output.with_name("access_events.status.json")
write_access_event_artifacts(
    args.output, status_path, report, clock, info["started"], info["ended"], etw,
    PROJECT_ROOT / "schemas/access_events.schema.json",
)
