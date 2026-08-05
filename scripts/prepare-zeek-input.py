#!/usr/bin/env python3
"""Select validated native Zeek evidence or the labeled upstream fallback."""
import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("pcap", type=Path)
parser.add_argument("output", type=Path)
parser.add_argument("--native", type=Path)
parser.add_argument("--runtime", type=Path, required=True)
parser.add_argument("--metadata", type=Path, required=True)
args = parser.parse_args()


def valid_log(path):
    if not path.is_file() or not path.stat().st_size:
        return False
    lines = [line for line in path.read_text(encoding="utf-8", errors="strict").splitlines() if line]
    if not lines:
        return False
    if lines[0].lstrip().startswith("{"):
        return all(isinstance(json.loads(line), dict) for line in lines)
    fields = next((line for line in lines if line.startswith("#fields")), None)
    if not fields:
        return False
    count = len(fields.split("\t")) - 1
    return count > 0 and all(len(line.split("\t")) == count for line in lines if not line.startswith("#"))


def valid_directory(path):
    return path.is_dir() and valid_log(path / "conn.log") and all(
        valid_log(item) for item in path.glob("*.log"))


args.output.mkdir(parents=True, exist_ok=True)
mode, warnings = "pcap_only", []
if args.native and valid_directory(args.native):
    for item in args.native.glob("*.log"):
        shutil.copy2(item, args.output / item.name)
    mode = "native"
elif args.native:
    warnings.append("native Zeek directory failed complete validation; using fallback")
if mode != "native":
    for item in args.output.iterdir():
        if item.is_file():
            item.unlink()
    try:
        subprocess.run([str(args.runtime / ".venv/bin/python"),
                        str(args.runtime / "source/tools/generate_zeek_logs.py"),
                        str(args.pcap), str(args.output)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if valid_directory(args.output):
            mode = "upstream_fallback"
        else:
            warnings.append("upstream fallback did not produce a valid conn.log")
    except (OSError, subprocess.CalledProcessError) as exc:
        warnings.append(f"upstream fallback failed: {exc}")
if mode == "pcap_only":
    for item in args.output.iterdir():
        if item.is_file():
            item.unlink()
limitations = []
if mode == "upstream_fallback":
    limitations = ["not equivalent to native Zeek", "x509.log unsupported", "files.log unsupported"]
elif mode == "pcap_only":
    limitations = ["Zeek enrichment unavailable"]
metadata = {"schema_version": "1.0", "zeek_mode": mode,
            "input_pcap_sha256": hashlib.sha256(args.pcap.read_bytes()).hexdigest(),
            "generated_files": sorted(item.name for item in args.output.glob("*.log")),
            "parser_validation": "passed" if mode != "pcap_only" else "not_available",
            "limitations": limitations, "warnings": warnings}
args.metadata.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
print(mode)
