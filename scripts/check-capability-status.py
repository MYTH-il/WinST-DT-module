#!/usr/bin/env python3
"""Reject documentation that claims Working without passed acceptance evidence."""
import argparse
import json
import re
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("documentation", type=Path)
parser.add_argument("ledger", type=Path)
args = parser.parse_args()

entries = json.loads(args.ledger.read_text(encoding="utf-8")).get("entries", {})
failures = []
for line_number, line in enumerate(args.documentation.read_text(encoding="utf-8").splitlines(), 1):
    columns = [column.strip() for column in line.strip().strip("|").split("|")]
    if len(columns) < 3 or columns[1] != "Working":
        continue
    match = re.search(r"\[acceptance:([a-z0-9_]+)\]", columns[2])
    if not match:
        failures.append(f"line {line_number}: Working lacks an acceptance marker")
        continue
    gate = match.group(1)
    if entries.get(gate, {}).get("status") != "passed":
        failures.append(f"line {line_number}: acceptance gate {gate!r} is not passed")
if failures:
    raise SystemExit("\n".join(failures))
print("documented Working capabilities have passed acceptance evidence")
