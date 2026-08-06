import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def tree_hash(root: Path) -> str:
    lines = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts or ".pytest_cache" in path.parts:
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.relative_to(root)}\n")
    return hashlib.sha256("".join(lines).encode()).hexdigest()


def test_upstream_and_dependency_locks_match():
    lock = json.loads((ROOT / "config/c2-exfil.lock.json").read_text())
    assert lock["commit"] == "47225ecb439936659e55ffa9118db083bb2f56c2"
    assert tree_hash(ROOT / lock["subtree"]) == lock["upstream_tree_sha256"]
    dependency_lock = ROOT / lock["dependency_lock"]
    assert hashlib.sha256(dependency_lock.read_bytes()).hexdigest() == lock["dependency_lock_sha256"]
    text = dependency_lock.read_text()
    assert "--hash=sha256:" in text
    assert "scapy==" in text and "psycopg==" in text and "pytest==" in text
    assert "numpy==" not in text
