import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def documentation_text():
    paths = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
    return "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in paths)


def test_no_specific_family_run_descriptions():
    text = documentation_text().lower()
    forbidden = ("stealbit", "lockbit", "redline", "stealc", "lumma", "5.149.249.242")
    assert not any(term in text for term in forbidden)
    assert not re.search(r"malware tasks?\s+\d+", text)


def test_upstream_acknowledgment_and_boundary_remain_clear():
    readme = (ROOT / "README.md").read_text()
    assert "C2-Exfil-E-Rakshak" in readme
    assert "demistifying/C2-Exfil-E-Rakshak" in readme
    assert "Raghav Shrivastav" in readme
    assert "actual repository and documentation" in readme
    integration = (ROOT / "docs/c2_exfil_integration.md").read_text()
    assert "byte-for-byte subtree" in integration
    assert "never edits it" in integration
