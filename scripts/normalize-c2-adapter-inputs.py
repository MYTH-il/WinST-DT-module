#!/usr/bin/env python3
"""Normalize optional Suricata and TLS evidence without inventing upstream fields."""
import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--suricata", type=Path)
parser.add_argument("--tls", type=Path)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(name, payload):
    (args.output / name).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


suricata = {"schema_version": "1.0", "status": "not_available", "events": [],
            "adapter_provenance": {"input": None, "input_sha256": None,
                                   "unsupported_fields": []}}
if args.suricata:
    try:
        raw = [json.loads(line) for line in args.suricata.read_text(encoding="utf-8").splitlines() if line]
        supported = {"timestamp", "event_type", "src_ip", "src_port", "dest_ip", "dest_port", "proto", "alert", "dns", "http", "tls"}
        suricata["events"] = [{key: value for key, value in event.items() if key in supported} for event in raw]
        suricata["status"] = "available"
        suricata["adapter_provenance"] = {
            "input": str(args.suricata), "input_sha256": sha(args.suricata),
            "unsupported_fields": sorted({key for event in raw for key in event if key not in supported}),
        }
    except (OSError, ValueError):
        suricata["status"] = "invalid"
write("suricata-input.json", suricata)

tls = {"schema_version": "1.0", "status": "not_available", "records": [],
       "adapter_provenance": {"input": None, "input_sha256": None,
                              "unsupported_fields": []}}
if args.tls:
    try:
        raw = json.loads(args.tls.read_text(encoding="utf-8"))
        raw = raw if isinstance(raw, list) else raw.get("records", [])
        supported = {"timestamp", "server_name", "destination_ip", "destination_port", "ja3", "ja4", "certificate_sha256"}
        tls["records"] = [{key: value for key, value in record.items() if key in supported} for record in raw]
        tls["status"] = "available"
        tls["adapter_provenance"] = {
            "input": str(args.tls), "input_sha256": sha(args.tls),
            "unsupported_fields": sorted({key for record in raw for key in record if key not in supported}),
        }
    except (OSError, ValueError, AttributeError):
        tls["status"] = "invalid"
write("tls-input.json", tls)
