import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_die_lock_is_complete():
    lock = json.loads((ROOT / "config/cape.lock.json").read_text())
    die = lock["tools"]["diec"]
    assert die == {
        "version": "3.10",
        "url": "https://github.com/horsicq/DIE-engine/releases/download/3.10/die_3.10_Ubuntu_24.04_amd64.deb",
        "sha256": "a64d32fcd95ab5c25cfb01f2e0355f67737eff93d6ae34c80b2b3dbdee721b1b",
        "binary": "/usr/bin/diec",
        "signature_database": "/usr/lib/die/db/",
    }


def test_installer_verifies_before_installing():
    script = (ROOT / "scripts/install-analysis-capabilities.sh").read_text()
    assert script.index('downloaded_sha=') < script.index('apt-get \\\n')
    assert "--force-confold" in script
    assert "known-positive.exe" in script
    assert "known-negative.txt" in script
    assert "grep -Eq '^PE(32|64)?$'" in script
