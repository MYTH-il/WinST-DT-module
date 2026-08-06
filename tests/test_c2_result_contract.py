import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + "\n")


def test_result_schemas_parse():
    for name in ("c2_result_bundle", "c2_network_event", "c2_attribution",
                 "c2_provenance", "c2_analysis_notes"):
        jsonschema.Draft202012Validator.check_schema(
            json.loads((ROOT / f"schemas/{name}.schema.json").read_text()))


def test_rust_validator_accepts_sealed_bundle_and_rejects_mutation(tmp_path):
    binary = ROOT / "target/debug/WinST-DT-module"
    subprocess.run(["cargo", "build", "-q"], cwd=ROOT, check=True)
    task, sample, pcap = 42, "a" * 64, "b" * 64
    handoff = tmp_path / "handoff/42"
    custody = "c" * 64
    write(handoff / "manifest.json", {"schema_version": "1.0", "session_id": "42",
        "cape_task_id": task, "sample_sha256": sample, "network_mode": "simulated_inetsim",
        "guest_vm_identity": {"guest_ip": "10.0.0.5"},
        "detonation_start_utc": "2026-08-05T00:00:00Z",
        "detonation_end_utc": "2026-08-05T00:01:00Z",
        "correlation": {"clock_quality_acceptable": True},
        "telemetry": {"telemetry_degraded": False, "providers_unavailable": []},
        "integrity": {"hash_manifest_sha256": custody}})
    result = tmp_path / "results/42"
    for directory in ("inputs", "output/iocs", "zeek"):
        (result / directory).mkdir(parents=True, exist_ok=True)
    (result / "analyzer.log").write_text("completed\n")
    identity = {"task_id": task, "sample_id": sample, "pcap_sha256": pcap}
    event = {**identity, "event_id": "e1", "timestamp": "2026-08-05T00:00:00Z",
             "session_id": "42", "cape_task_id": task, "manifest_sha256": custody,
             "confidence_tier": "allowlisted", "stage_status": "complete",
             "evidence_hash": "d" * 64}
    write(result / "output/events.json", {"schema_version": "1.1", **identity, "events": [event]})
    write(result / "output/attribution.json", {**identity, "findings": [{
        "family": "controlled", "confidence": "possible", "basis": "behavioural",
        "evidence": [{"event_id": "e1"}]}]})
    write(result / "output/timeline.json", {**identity, "entries": []})
    write(result / "output/analysis_notes.json", {"schema_version": "1.0", **identity,
        "session_id": "42", "network_mode": "simulated_inetsim",
        "clock_quality_acceptable": True, "telemetry_degraded": False,
        "providers_unavailable": [], "scope_filter": {"guest_ip": "10.0.0.5",
        "detonation_start_utc": "2026-08-05T00:00:00Z",
        "detonation_end_utc": "2026-08-05T00:01:00Z", "applied": True}, "notes": []})
    write(result / "output/iocs/identity.json", identity)
    provenance = {"schema_version": "1.1", "task_id": task, "sample_sha256": sample,
        "pcap_sha256": pcap, "upstream_repository": "https://example.invalid/upstream",
        "upstream_commit": "c" * 40, "compatibility_patch_hashes": [{"name": "p", "sha256": "d" * 64}],
        "effective_runtime_tree_sha256": "e" * 64, "dependency_lock_sha256": "f" * 64,
        "input_hashes": {}, "handoff_hashes": {"manifest.json": digest(handoff / "manifest.json")},
        "handoff_context": {"session_id": "42", "cape_task_id": task,
            "network_mode": "simulated_inetsim", "guest_ip": "10.0.0.5",
            "detonation_start_utc": "2026-08-05T00:00:00Z",
            "detonation_end_utc": "2026-08-05T00:01:00Z",
            "clock_quality_acceptable": True, "telemetry_degraded": False,
            "providers_unavailable": [], "manifest_sha256": custody},
        "custody_chain": {"seed_sha256": custody, "tip_sha256": "d" * 64,
            "event_count": 1, "verified": True},
        "correlation_mode": "network_only", "zeek": {"zeek_mode": "pcap_only", "limitations": [], "generated_files": [], "input_pcap_sha256": pcap},
        "feed_revisions": [], "model_revisions": [{"name": "dga", "path": "model.json",
            "sha256": "1" * 64, "threshold": 0.75, "metadata": {}}],
        "database_schema_version": 3, "fixture_usage": False,
        "started_at_utc": "2026-08-05T00:00:00Z", "ended_at_utc": "2026-08-05T00:01:00Z",
        "warnings": [], "degraded_features": [], "optional_inputs": {"access_events": "disabled", "handoff_manifest": "available"},
        "stages": {"network": "complete", "handoff_gating": "complete"}}
    write(result / "provenance.json", provenance)
    for schema_name, document_path in (
        ("c2_network_event", result / "output/events.json"),
        ("c2_analysis_notes", result / "output/analysis_notes.json"),
        ("c2_provenance", result / "provenance.json"),
    ):
        schema = json.loads((ROOT / f"schemas/{schema_name}.schema.json").read_text())
        document = json.loads(document_path.read_text())
        if schema_name == "c2_network_event":
            document = document["events"][0]
        jsonschema.validate(document, schema)
    files = {str(p.relative_to(result)): digest(p) for p in result.rglob("*") if p.is_file()}
    (result / "hashes.sha256").write_text("".join(f"{v}  {k}\n" for k, v in sorted(files.items())))
    for path in result.rglob("*"):
        if path.is_file():
            path.chmod(path.stat().st_mode & ~0o222)
    subprocess.run([str(binary), "validate-c2-result", str(result), "--handoff", str(handoff)], check=True)
    (handoff / "manifest.json").chmod(0o644)
    write(handoff / "manifest.json", {"sample": "changed"})
    failed = subprocess.run([str(binary), "validate-c2-result", str(result), "--handoff", str(handoff)])
    assert failed.returncode != 0
