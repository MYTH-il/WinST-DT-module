import importlib.util
import csv
import json
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT / "integrations/c2-exfil"
PATCHES = ROOT / "integrations/c2-exfil-patches"
FIXTURES = ROOT / "tests/fixtures/c2-feeds"


@pytest.fixture(scope="module")
def runtime(tmp_path_factory):
    target = tmp_path_factory.mktemp("c2-runtime")
    shutil.copytree(UPSTREAM, target, dirs_exist_ok=True)
    (target / ".winstdt").mkdir()
    (target / "sql/migrations").mkdir(parents=True)
    for patch in (PATCHES / "series").read_text().splitlines():
        subprocess.run(
            ["patch", "--batch", "--forward", "--directory", str(target),
             "-p1", "--input", str(PATCHES / patch)], check=True,
        )
    return target


def load_module(runtime, name):
    spec = importlib.util.spec_from_file_location(name, runtime / "pipeline" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_explicit_identity_and_fixture_controls(runtime):
    source = (runtime / "pipeline/orchestrator.py").read_text()
    assert "--sample-sha256" in source
    assert "--handoff" in source
    assert "load_handoff(args.handoff, strict=True)" in source
    assert "synthetic-test access events require --validation-mode" in source
    assert 'default="data/access_events_fixture.json"' not in source


@pytest.mark.parametrize("kind,name", [
    ("feodo", "feodo.csv"), ("urlhaus", "urlhaus.csv"),
    ("domain", "domains.txt"), ("ja3", "ja3.txt"), ("ja4", "ja4.txt"),
])
def test_strict_feed_formats(runtime, tmp_path, kind, name):
    feed = load_module(runtime, "winstdt_feed_import")
    db = tmp_path / f"{kind}.sqlite"
    result = feed.import_feed(kind, str(FIXTURES / name), str(db), "test/source", "r1")
    assert result["row_count"] == 1
    with sqlite3.connect(db) as conn:
        metadata = conn.execute(
            "SELECT source,revision,input_sha256,row_count FROM feed_imports"
        ).fetchone()
    assert metadata == ("test/source", "r1", result["input_sha256"], 1)


def test_malformed_feed_does_not_mutate_database(runtime, tmp_path):
    feed = load_module(runtime, "winstdt_feed_import")
    db = tmp_path / "rollback.sqlite"
    feed.import_feed("domain", str(FIXTURES / "domains.txt"), str(db), "good", "1")
    with sqlite3.connect(db) as conn:
        before = conn.execute("SELECT * FROM bad_indicators ORDER BY value").fetchall()
    with pytest.raises(feed.FeedError):
        feed.import_feed("feodo", str(FIXTURES / "malformed.csv"), str(db), "bad", "1")
    with sqlite3.connect(db) as conn:
        after = conn.execute("SELECT * FROM bad_indicators ORDER BY value").fetchall()
        imports = conn.execute("SELECT COUNT(*) FROM feed_imports").fetchone()[0]
    assert after == before
    assert imports == 1


def test_attribution_contract(runtime):
    contract = load_module(runtime, "attribution_contract")
    verdict = {"family": "controlled-family", "confidence": "possible",
               "basis": "behavioural", "evidence": [{"event": "e1"}]}
    assert contract.validate_attribution(verdict) == verdict
    with pytest.raises(ValueError):
        contract.validate_attribution({**verdict, "confidence": "strong"})


def test_sql_contract(runtime):
    schema = (runtime / "sql/schema.sql").read_text()
    migration = (runtime / "sql/migrations/002_winstdt_compat.sql").read_text()
    migration3 = (runtime / "sql/migrations/003_upstream_1_2.sql").read_text()
    assert "destination_domain" in schema
    assert "schema_versions" in schema
    assert "allowlisted" in migration
    for column in ("session_id", "cape_task_id", "asn_org", "reputation_note",
                   "reputation_source", "manifest_sha256"):
        assert column in schema and column in migration3
    assert "VALUES ('c2-exfil', 3)" in migration3
    assert "DROP TABLE" not in migration.upper()
    assert "DROP TABLE" not in migration3.upper()


def test_dga_model_is_deterministic_and_runtime_only(runtime):
    classifier = load_module(runtime, "dga_classifier")
    model = classifier.DGAModel.load(str(runtime / "data/models/dga_lr.json"))
    first = model.score("movementhappen")
    assert first.is_dga and first.top_features
    assert first.probability == model.score("movementhappen").probability
    assert not model.score("github").is_dga
    assert "numpy" not in (runtime / "pipeline/dga_classifier.py").read_text()


def test_missing_upstream_pcap_contract_is_recreated_synthetically(runtime, tmp_path):
    export = load_module(runtime, "export_iocs")
    rows = [{"event_id": "e1", "sample_id": "s", "destination_ip": "",
             "destination_port": 0, "destination_domain": "c2.example.test",
             "confidence_tier": "confirmed", "confidence_score": 1.0,
             "reputation_score": 1.0, "reputation_note": "Controlled family C2",
             "reputation_source": "test/feed", "asn_org": "Controlled ASN",
             "mitre_technique_id": "T1071", "timestamp": "2026-08-06T00:00:00Z",
             "evidence_hash": "a" * 64}]
    csv_path = tmp_path / "iocs.csv"
    stix_path = tmp_path / "iocs.json"
    assert export.export_csv(rows, str(csv_path)) == 1
    assert export.export_stix(rows, str(stix_path)) == 1
    csv_rows = list(csv.DictReader(csv_path.open()))
    assert csv_rows[0]["destination_domain"] == "c2.example.test"
    assert csv_rows[0]["reputation_note"] == "Controlled family C2"
    indicators = [item for item in json.loads(stix_path.read_text())["objects"]
                  if item["type"] == "indicator"]
    assert "domain-name:value = 'c2.example.test'" in indicators[0]["pattern"]
