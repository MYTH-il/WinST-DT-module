#!/usr/bin/env python3
"""Calculate the deterministic SHA-256 used for C2 source/runtime trees."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


IGNORED = {"__pycache__", ".pytest_cache", ".venv"}


def tree_hash(root: Path) -> str:
    lines: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in IGNORED for part in path.parts):
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.relative_to(root)}\n")
    return hashlib.sha256("".join(lines).encode()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    if not args.root.is_dir():
        parser.error(f"not a directory: {args.root}")
    print(tree_hash(args.root))


if __name__ == "__main__":
    main()
