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
    for name in ("c2_result_bundle", "c2_network_event", "c2_attribution", "c2_provenance"):
        jsonschema.Draft202012Validator.check_schema(
            json.loads((ROOT / f"schemas/{name}.schema.json").read_text()))


def test_rust_validator_accepts_sealed_bundle_and_rejects_mutation(tmp_path):
    binary = ROOT / "target/debug/WinST-DT-module"
    if not binary.exists():
        subprocess.run(["cargo", "build", "-q"], cwd=ROOT, check=True)
    task, sample, pcap = 42, "a" * 64, "b" * 64
    handoff = tmp_path / "handoff/42"
    write(handoff / "manifest.json", {"sample": sample})
    result = tmp_path / "results/42"
    for directory in ("inputs", "output/iocs", "zeek"):
        (result / directory).mkdir(parents=True, exist_ok=True)
    (result / "analyzer.log").write_text("completed\n")
    identity = {"task_id": task, "sample_id": sample, "pcap_sha256": pcap}
    event = {**identity, "event_id": "e1", "timestamp": "2026-08-05T00:00:00Z",
             "confidence_tier": "allowlisted", "stage_status": "complete"}
    write(result / "output/events.json", {**identity, "events": [event]})
    write(result / "output/attribution.json", {**identity, "findings": [{
        "family": "controlled", "confidence": "possible", "basis": "behavioural",
        "evidence": [{"event_id": "e1"}]}]})
    write(result / "output/timeline.json", {**identity, "entries": []})
    write(result / "output/iocs/identity.json", identity)
    provenance = {"schema_version": "1.0", "task_id": task, "sample_sha256": sample,
        "pcap_sha256": pcap, "upstream_repository": "https://example.invalid/upstream",
        "upstream_commit": "c" * 40, "compatibility_patch_hashes": [{"name": "p", "sha256": "d" * 64}],
        "effective_runtime_tree_sha256": "e" * 64, "dependency_lock_sha256": "f" * 64,
        "input_hashes": {}, "handoff_hashes": {"manifest.json": digest(handoff / "manifest.json")},
        "correlation_mode": "network_only", "zeek": {"zeek_mode": "pcap_only", "limitations": [], "generated_files": [], "input_pcap_sha256": pcap},
        "feed_revisions": [], "database_schema_version": 2, "fixture_usage": False,
        "started_at_utc": "2026-08-05T00:00:00Z", "ended_at_utc": "2026-08-05T00:01:00Z",
        "warnings": [], "degraded_features": [], "optional_inputs": {"access_events": "disabled"},
        "stages": {"network": "complete"}}
    write(result / "provenance.json", provenance)
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
