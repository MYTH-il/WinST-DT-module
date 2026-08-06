#!/usr/bin/env python3
"""Normalize patched analyzer output and seal a derived C2 result bundle."""
import argparse
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("stage", type=Path)
parser.add_argument("handoff", type=Path)
parser.add_argument("runtime", type=Path)
parser.add_argument("project", type=Path)
parser.add_argument("--task-id", type=int, required=True)
parser.add_argument("--started-at", required=True)
parser.add_argument("--correlation", choices=("host_network", "network_only"), required=True)
parser.add_argument("--zeek-mode", choices=("native", "upstream_fallback", "pcap_only"), default="pcap_only")
args = parser.parse_args()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def file_hashes(root):
    return {str(path.relative_to(root)): digest(path) for path in sorted(root.rglob("*")) if path.is_file()}


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


stage, output = args.stage, args.stage / "output"
meta = json.loads((args.handoff / "sample.meta.json").read_text(encoding="utf-8"))
handoff_manifest = json.loads((args.handoff / "manifest.json").read_text(encoding="utf-8"))
sample = meta["sample_sha256"].lower()
pcap = digest(stage / "inputs/capture.pcapng")
raw_events = json.loads((output / "exfil_events.json").read_text(encoding="utf-8"))
session_id = str(handoff_manifest["session_id"])
if handoff_manifest["cape_task_id"] != args.task_id or handoff_manifest["sample_sha256"].lower() != sample:
    raise SystemExit("handoff identity does not match result identity")
custody_seed = handoff_manifest["integrity"]["hash_manifest_sha256"].lower()
previous = custody_seed
for index, raw in enumerate(raw_events):
    if raw.get("session_id") != session_id or raw.get("cape_task_id") != args.task_id:
        raise SystemExit(f"event {index} handoff join identity mismatch")
    manifest_link = raw.get("manifest_sha256")
    if (index == 0 and manifest_link != custody_seed) or (index > 0 and manifest_link is not None):
        raise SystemExit("invalid event custody seed placement")
    expected = raw.get("evidence_hash")
    unsigned = dict(raw)
    unsigned.pop("evidence_hash", None)
    actual = hashlib.sha256((previous + json.dumps(unsigned, sort_keys=True)).encode()).hexdigest()
    if expected != actual:
        raise SystemExit(f"event {index} evidence chain mismatch")
    previous = actual
custody_tip = previous
events = []
for row in raw_events:
    row.update(task_id=args.task_id, sample_id=sample, pcap_sha256=pcap, stage_status="complete")
    events.append(row)
write(output / "events.json", {"schema_version": "1.1", "task_id": args.task_id,
                                "sample_id": sample, "pcap_sha256": pcap, "events": events})
(output / "exfil_events.json").unlink()

raw_attribution = json.loads((output / "attribution.json").read_text(encoding="utf-8"))
findings = []
for finding in raw_attribution:
    evidence = [item if isinstance(item, dict) else {"detail": str(item)}
                for item in finding.get("evidence", [])]
    findings.append({"family": finding["family"], "confidence": finding["confidence"],
                     "basis": finding["basis"], "evidence": evidence})
write(output / "attribution.json", {"task_id": args.task_id, "sample_id": sample,
                                     "pcap_sha256": pcap, "findings": findings})
timeline = json.loads((output / "timeline.json").read_text(encoding="utf-8"))
write(output / "timeline.json", {"task_id": args.task_id, "sample_id": sample,
                                  "pcap_sha256": pcap, "entries": timeline})
raw_notes_path = output / "analysis_notes.json"
raw_notes = json.loads(raw_notes_path.read_text(encoding="utf-8")) if raw_notes_path.exists() else {}
correlation = handoff_manifest.get("correlation") or {}
telemetry = handoff_manifest.get("telemetry") or {}
write(raw_notes_path, {"schema_version": "1.0", "task_id": args.task_id,
                       "sample_id": sample, "pcap_sha256": pcap,
                       "session_id": session_id,
                       "network_mode": handoff_manifest["network_mode"],
                       "clock_quality_acceptable": bool(correlation.get("clock_quality_acceptable")),
                       "telemetry_degraded": bool(telemetry.get("telemetry_degraded")),
                       "providers_unavailable": [item.get("provider") for item in telemetry.get("providers_unavailable", []) if isinstance(item, dict) and item.get("provider")],
                       "scope_filter": {"guest_ip": handoff_manifest["guest_vm_identity"]["guest_ip"],
                                        "detonation_start_utc": handoff_manifest["detonation_start_utc"],
                                        "detonation_end_utc": handoff_manifest["detonation_end_utc"],
                                        "applied": True},
                       "notes": list(raw_notes.get("notes") or [])})
if (output / "provenance.json").exists():
    (output / "provenance.json").rename(output / "item-provenance.json")
(output / "iocs").mkdir(exist_ok=True)
for name in ("iocs.csv", "iocs_stix.json"):
    if (output / name).exists():
        (output / name).rename(output / "iocs" / name)
write(output / "iocs/identity.json", {"task_id": args.task_id, "sample_id": sample,
                                      "pcap_sha256": pcap})

before = json.loads((stage / "inputs/handoff-hashes.before.json").read_text())
after = file_hashes(args.handoff)
if before != after:
    raise SystemExit("immutable handoff changed during analysis")
lock = json.loads((args.project / "config/c2-exfil.lock.json").read_text())
runtime_manifest = json.loads((args.runtime / "runtime-manifest.json").read_text())
patch_hashes = [{"name": name, "sha256": digest(args.project / "integrations/c2-exfil-patches" / name)}
                for name in lock["patches"]["series"]]
input_hashes = file_hashes(stage / "inputs")
input_hashes.pop("handoff-hashes.before.json", None)
suricata_status = json.loads((stage / "inputs/suricata-input.json").read_text())["status"]
tls_status = json.loads((stage / "inputs/tls-input.json").read_text())["status"]
zeek_selection = json.loads((stage / "inputs/zeek-selection.json").read_text())
if zeek_selection["zeek_mode"] != args.zeek_mode or zeek_selection["input_pcap_sha256"] != pcap:
    raise SystemExit("Zeek selection provenance does not match the analyzed PCAP")
zeek_limitations = zeek_selection["limitations"]
model_path = args.runtime / "source/data/models/dga_lr.json"
model = json.loads(model_path.read_text(encoding="utf-8"))
provenance = {
    "schema_version": "1.1", "task_id": args.task_id, "sample_sha256": sample,
    "pcap_sha256": pcap, "upstream_repository": lock["repository"],
    "upstream_commit": lock["commit"], "compatibility_patch_hashes": patch_hashes,
    "effective_runtime_tree_sha256": runtime_manifest["effective_tree_sha256"],
    "dependency_lock_sha256": lock["dependency_lock_sha256"], "input_hashes": input_hashes,
    "handoff_hashes": before, "correlation_mode": args.correlation,
    "zeek": {"zeek_mode": args.zeek_mode, "limitations": zeek_limitations,
             "generated_files": zeek_selection["generated_files"],
             "parser_validation": zeek_selection["parser_validation"],
             "input_pcap_sha256": pcap},
    "feed_revisions": [], "model_revisions": [{"name": "offline_explainable_dga_lr",
        "path": "data/models/dga_lr.json", "sha256": digest(model_path),
        "threshold": model.get("threshold", 0.5), "metadata": model.get("meta", {})}],
    "database_schema_version": lock["database_schema_version"],
    "handoff_context": {"session_id": session_id, "cape_task_id": args.task_id,
        "network_mode": handoff_manifest["network_mode"],
        "guest_ip": handoff_manifest["guest_vm_identity"]["guest_ip"],
        "detonation_start_utc": handoff_manifest["detonation_start_utc"],
        "detonation_end_utc": handoff_manifest["detonation_end_utc"],
        "clock_quality_acceptable": bool(correlation.get("clock_quality_acceptable")),
        "telemetry_degraded": bool(telemetry.get("telemetry_degraded")),
        "providers_unavailable": [item.get("provider") for item in telemetry.get("providers_unavailable", []) if isinstance(item, dict) and item.get("provider")],
        "manifest_sha256": custody_seed},
    "custody_chain": {"seed_sha256": custody_seed, "tip_sha256": custody_tip,
                      "event_count": len(events), "verified": True},
    "fixture_usage": False, "started_at_utc": args.started_at,
    "ended_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "warnings": zeek_limitations + zeek_selection["warnings"] + list(raw_notes.get("notes") or []),
    "degraded_features": ["zeek"] if args.zeek_mode != "native" else [],
    "optional_inputs": {"access_events": "available" if args.correlation == "host_network" else "disabled",
                        "handoff_manifest": "available",
                        "static_prior": "available", "suricata": suricata_status,
                        "tls": tls_status,
                        "postgresql": "available" if (output / "sql-verification.json").exists() else "disabled"},
    "stages": {"network": "complete", "handoff_gating": "complete",
               "correlation": "complete" if args.correlation == "host_network" else "not_available",
               "attribution": "complete", "ioc_export": "complete", "zeek": "complete" if args.zeek_mode == "native" else "degraded",
               "postgresql": "complete" if (output / "sql-verification.json").exists() else "not_available"}
}
write(stage / "provenance.json", provenance)
hashes = file_hashes(stage)
hashes.pop("hashes.sha256", None)
(stage / "hashes.sha256").write_text("".join(f"{value}  {name}\n" for name, value in sorted(hashes.items())), encoding="utf-8")
