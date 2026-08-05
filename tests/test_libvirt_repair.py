from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_repair_is_dry_run_and_covers_all_storage_units():
    script = (ROOT / "scripts/repair-libvirt-runtime.sh").read_text()
    assert "EXECUTE=0" in script
    for unit in (
        "virtstoraged.service",
        "virtstoraged.socket",
        "virtstoraged-ro.socket",
        "virtstoraged-admin.socket",
    ):
        assert unit in script
    assert "leaving CAPE stopped" in script
    assert '$WINSTDT_ROOT/backups/libvirt' in script


def test_setup_quarantines_all_storage_units():
    script = (ROOT / "scripts/setup-ubuntu24-host.sh").read_text()
    for suffix in ("service", "socket", "ro.socket", "admin.socket"):
        assert f"/usr/lib/systemd/system/virtstoraged-{suffix}" in script or (
            suffix in {"service", "socket"}
            and f"/usr/lib/systemd/system/virtstoraged.{suffix}" in script
        )


def test_reboot_workflow_requires_distinct_boot_ids():
    script = (ROOT / "scripts/validation/validate-libvirt-reboots.sh").read_text()
    assert "after-reboot-1" in script
    assert "after-reboot-2" in script
    assert "a new host boot was not observed" in script
