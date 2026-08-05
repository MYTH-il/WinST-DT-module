import json
import subprocess
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
CRATE = ROOT / "fixtures/windows-validation"


def test_fixture_is_narrow_and_uses_required_win32_apis():
    source = (CRATE / "src/main.rs").read_text()
    for api in ("CreateFileW", "ReadFile", "GetClipboardData", "GetComputerNameW",
                "GetAddrInfoW", "WinHttpSendRequest"):
        assert api in source
    assert "WINSTDT-CONTROLLED-CANARY/1" in source
    assert "browser" not in source.lower()
    assert "credential" not in source.lower()
    assert 'transmitted_fields' in source


def test_fixture_cross_compiles_as_positive_pe():
    subprocess.run(["cargo", "build", "--release"], cwd=CRATE, check=True)
    binary = CRATE / "target/x86_64-pc-windows-gnu/release/winstdt-windows-validation.exe"
    assert binary.read_bytes()[:2] == b"MZ"
    completed = subprocess.run(["diec", str(binary)], text=True, capture_output=True, check=True)
    assert completed.stdout.strip()


def test_end_to_end_schema_and_fail_closed_trap():
    jsonschema.Draft202012Validator.check_schema(json.loads(
        (ROOT / "schemas/end_to_end_acceptance.schema.json").read_text()))
    script = (ROOT / "scripts/run-end-to-end-validation.sh").read_text()
    assert "trap cleanup EXIT INT TERM" in script
    assert "snapshot-revert" in script
    assert "validate-c2-result" in script
    assert "WINSTDT_POSTGRES_ENABLED=1" in script
    assert "<forward" in script
