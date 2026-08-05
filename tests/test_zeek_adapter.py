import json
import os
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/prepare-zeek-input.py"


def runtime(tmp_path):
    root = tmp_path / "runtime"
    (root / ".venv/bin").mkdir(parents=True)
    (root / ".venv/bin/python").symlink_to(sys.executable)
    (root / "source").symlink_to(ROOT / "integrations/c2-exfil", target_is_directory=True)
    return root


def pcap(tmp_path):
    path = tmp_path / "capture.pcap"
    path.write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    return path


def invoke(tmp_path, native=None, valid_runtime=True):
    output, metadata = tmp_path / "out", tmp_path / "metadata.json"
    selected_runtime = runtime(tmp_path) if valid_runtime else tmp_path / "missing-runtime"
    command = [sys.executable, str(SCRIPT), str(pcap(tmp_path)), str(output),
               "--runtime", str(selected_runtime), "--metadata", str(metadata)]
    if native:
        command += ["--native", str(native)]
    completed = subprocess.run(command, check=True, text=True, capture_output=True)
    return completed.stdout.strip(), json.loads(metadata.read_text())


def test_valid_native_directory_preferred(tmp_path):
    native = tmp_path / "native"; native.mkdir()
    (native / "conn.log").write_text("#fields\tts\tuid\n1\tC1\n")
    mode, metadata = invoke(tmp_path, native)
    assert mode == "native" and metadata["parser_validation"] == "passed"


def test_malformed_native_uses_labeled_fallback(tmp_path):
    native = tmp_path / "native"; native.mkdir()
    (native / "conn.log").write_text("not zeek\n")
    mode, metadata = invoke(tmp_path, native)
    assert mode == "upstream_fallback"
    assert "x509.log unsupported" in metadata["limitations"]
    assert any("failed complete validation" in warning for warning in metadata["warnings"])


def test_fallback_failure_preserves_pcap_only_mode(tmp_path):
    mode, metadata = invoke(tmp_path, valid_runtime=False)
    assert mode == "pcap_only"
    assert metadata["generated_files"] == []
