#!/usr/bin/env python3
"""Generate a provenance-complete, conservative static-prior contract."""
import argparse
import hashlib
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlparse

parser = argparse.ArgumentParser()
parser.add_argument("bundle", type=Path)
parser.add_argument("output", type=Path)
args = parser.parse_args()
meta = json.loads((args.bundle / "sample.meta.json").read_text(encoding="utf-8"))
artifacts, iocs, capabilities, warnings, family = [], [], set(), [], None


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def classify(value):
    value = value.strip()
    try:
        ipaddress.ip_address(value)
        return "ip", value
    except ValueError:
        pass
    parsed = urlparse(value)
    if parsed.scheme in ("http", "https", "ftp") and parsed.hostname:
        return "url", value
    if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value):
        return "hash", value.lower()
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
        return "email", value.lower()
    if re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}", value):
        return "domain", value.lower().rstrip(".")
    return None


def walk(value, key, provenance):
    global family
    if isinstance(value, dict):
        explicit = value.get("family_attribution")
        if isinstance(explicit, dict) and explicit.get("family") and explicit.get("evidence"):
            family = {"family": str(explicit["family"]), "evidence": explicit["evidence"]}
        for child_key, child in value.items():
            walk(child, str(child_key).lower(), provenance)
    elif isinstance(value, list):
        for child in value:
            walk(child, key, provenance)
    elif isinstance(value, str):
        if re.fullmatch(r"T\d{4}(?:\.\d{3})?", value):
            capabilities.add(value)
        if any(token in key for token in ("ioc", "url", "domain", "host", "ip", "email", "hash")):
            found = classify(value)
            if found:
                iocs.append({"type": found[0], "value": found[1], "provenance": provenance})


analysis = args.bundle / "analysis"
for path in sorted(analysis.glob("*.json")) if analysis.is_dir() else []:
    provenance = {"source_path": str(path.relative_to(args.bundle)), "source_sha256": digest(path)}
    artifacts.append({"path": provenance["source_path"], "sha256": provenance["source_sha256"]})
    try:
        walk(json.loads(path.read_text(encoding="utf-8")), "", provenance)
    except (OSError, ValueError) as exc:
        warnings.append(f"{provenance['source_path']}: {exc}")
dedup = {(item["type"], item["value"]): item for item in iocs}
output = {"schema_version": "1.0", "sample_sha256": str(meta["sample_sha256"]).lower(),
          "capa_capabilities": sorted(capabilities), "iocs": list(dedup.values()),
          "family_attribution": family, "source_artifacts": artifacts,
          "extraction_warnings": warnings}
try:
    import jsonschema
    schema = json.loads((Path(__file__).resolve().parents[1] / "schemas/c2_static_prior.schema.json").read_text())
    jsonschema.validate(output, schema)
except ImportError:
    pass
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
