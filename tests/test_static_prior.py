import json
import subprocess
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]


def test_static_prior_preserves_provenance_and_rejects_weak_family_inference(tmp_path):
    bundle = tmp_path / "bundle"
    (bundle / "analysis").mkdir(parents=True)
    (bundle / "sample.meta.json").write_text(json.dumps({"sample_sha256": "a" * 64}))
    (bundle / "analysis/static.json").write_text(json.dumps({
        "compiler": "ControlledFamily compiler", "packer": "ControlledFamily packer",
        "capa": ["T1059", "T1105.001"], "network_iocs": ["Example.TEST", "192.0.2.9"]
    }))
    output = tmp_path / "prior.json"
    subprocess.run(["python3", str(ROOT / "scripts/generate-static-prior.py"),
                    str(bundle), str(output)], check=True)
    value = json.loads(output.read_text())
    schema = json.loads((ROOT / "schemas/c2_static_prior.schema.json").read_text())
    jsonschema.validate(value, schema)
    assert value["family_attribution"] is None
    assert value["sample_sha256"] == "a" * 64
    assert value["source_artifacts"][0]["sha256"]
    assert all(item["provenance"]["source_sha256"] for item in value["iocs"])


def test_adapter_keeps_unknown_fields_only_in_provenance(tmp_path):
    eve = tmp_path / "eve.json"
    eve.write_text(json.dumps({"timestamp": "2026-08-05T00:00:00Z", "event_type": "alert",
                               "dest_ip": "192.0.2.8", "vendor_extension": "kept-by-hash"}) + "\n")
    output = tmp_path / "adapter"
    subprocess.run(["python3", str(ROOT / "scripts/normalize-c2-adapter-inputs.py"),
                    "--suricata", str(eve), "--output", str(output)], check=True)
    value = json.loads((output / "suricata-input.json").read_text())
    schema = json.loads((ROOT / "schemas/suricata_adapter_input.schema.json").read_text())
    jsonschema.validate(value, schema)
    assert "vendor_extension" not in value["events"][0]
    assert "vendor_extension" in value["adapter_provenance"]["unsupported_fields"]


def test_adapter_normalizes_cape_suricata_wrapper(tmp_path):
    source = tmp_path / "suricata.json"
    source.write_text(json.dumps({"tool": "suricata", "result": {"alerts": [], "http": [{
        "timestamp": "2026-08-05T00:00:00Z", "srcip": "10.66.0.101", "srcport": 49152,
        "dstip": "192.168.125.10", "dstport": 8080, "hostname": "validation.winstdt.test",
    }]}}))
    output = tmp_path / "adapter"
    subprocess.run(["python3", str(ROOT / "scripts/normalize-c2-adapter-inputs.py"),
                    "--suricata", str(source), "--output", str(output)], check=True)
    value = json.loads((output / "suricata-input.json").read_text())
    assert value["status"] == "available"
    assert value["events"] == [{
        "event_type": "http", "timestamp": "2026-08-05T00:00:00Z",
        "src_ip": "10.66.0.101", "src_port": 49152,
        "dest_ip": "192.168.125.10", "dest_port": 8080,
    }]
    assert "hostname" in value["adapter_provenance"]["unsupported_fields"]
