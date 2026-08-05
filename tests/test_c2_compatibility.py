import importlib.util
import shutil
import sqlite3
import subprocess
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
    spec.loader.exec_module(module)
    return module


def test_explicit_identity_and_fixture_controls(runtime):
    source = (runtime / "pipeline/orchestrator.py").read_text()
    assert "--sample-sha256" in source
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
    assert "destination_domain" in schema
    assert "schema_versions" in schema
    assert "allowlisted" in migration
    assert "DROP TABLE" not in migration.upper()
