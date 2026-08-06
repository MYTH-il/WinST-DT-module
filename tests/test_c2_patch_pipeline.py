import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_patch_series_and_lock_are_consistent():
    lock = json.loads((ROOT / "config/c2-exfil.lock.json").read_text())
    patch_root = ROOT / "integrations/c2-exfil-patches"
    names = [line for line in (patch_root / "series").read_text().splitlines() if line and not line.startswith("#")]
    assert names == lock["patches"]["series"]
    lines = "".join(f"{hashlib.sha256((patch_root / name).read_bytes()).hexdigest()}  {name}\n" for name in names)
    assert hashlib.sha256(lines.encode()).hexdigest() == lock["patches"]["series_sha256"]


def test_each_patch_applies_to_a_fresh_copy(tmp_path):
    import shutil
    import subprocess

    source = tmp_path / "source"
    shutil.copytree(ROOT / "integrations/c2-exfil", source)
    (source / ".winstdt").mkdir()
    (source / "sql/migrations").mkdir()
    patch_root = ROOT / "integrations/c2-exfil-patches"
    for name in (patch_root / "series").read_text().splitlines():
        if not name or name.startswith("#"):
            continue
        subprocess.run(
            ["patch", "--batch", "--forward", "--directory", str(source), "-p1", "--input", str(patch_root / name)],
            check=True,
            capture_output=True,
            text=True,
        )
    assert (source / "pipeline/orchestrator.py").is_file()
    assert (source / "pipeline/winstdt_feed_import.py").is_file()
    assert (source / "sql/migrations/002_winstdt_compat.sql").is_file()
    assert (source / "sql/migrations/003_upstream_1_2.sql").is_file()


def test_installer_is_versioned_and_never_deletes_active_runtime():
    script = (ROOT / "scripts/install-c2-analyzer.sh").read_text()
    assert 'runtime_root="$WINSTDT_ROOT/libexec/c2-exfil"' in script
    assert "--require-hashes" in script
    assert "mv -Tf" in script
    assert "rsync --delete" not in script


def test_database_migrator_handles_fresh_v1_v2_and_v3():
    script = (ROOT / "scripts/migrate-c2-database.sh").read_text()
    assert "to_regclass('public.schema_versions')" in script
    assert 'schema_root/schema.sql' in script
    assert '1)' in script and '2)' in script and '3)' in script
    assert "DROP TABLE" not in script.upper()
