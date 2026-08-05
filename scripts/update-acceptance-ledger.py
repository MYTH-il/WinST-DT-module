#!/usr/bin/env python3
"""Evaluate non-reboot live gates and atomically update the acceptance ledger."""
import argparse
import json
import subprocess
import tempfile
import os
from datetime import datetime, timezone
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--execute", action="store_true")
parser.add_argument("--root", type=Path, default=Path("/srv/winstdt/validation"))
args = parser.parse_args()
project = Path(__file__).resolve().parents[1]
ledger_path = args.root / "acceptance-ledger.json"
ledger = json.loads((project / "config/acceptance-ledger.initial.json").read_text())
if ledger_path.exists():
    existing = json.loads(ledger_path.read_text())
    if existing.get("schema_version") == "1.0":
        ledger = existing


def command(entry, command, evidence, limitation=None, environment=None):
    process_environment = os.environ.copy()
    process_environment.update(environment or {})
    completed = subprocess.run(command, cwd=project, text=True, capture_output=True,
                               env=process_environment)
    ledger["entries"][entry] = {
        "status": "passed" if completed.returncode == 0 else "failed",
        "evidence": [evidence, completed.stdout.strip()[-1000:]] if completed.stdout.strip() else [evidence],
        "limitations": ([limitation] if limitation else []) +
                       ([completed.stderr.strip()[-1000:]] if completed.returncode and completed.stderr.strip() else []),
    }


command("libvirt_live_recovery", [str(project / "scripts/repair-libvirt-runtime.sh"), "--validate-only"],
        "repair-libvirt-runtime.sh --validate-only")
command("die_3_10", [str(project / "scripts/validate-analysis-capabilities.sh")],
        "live pinned DIE validation", environment={"WINSTDT_VALIDATE_SELECTED": "die"})
command("c2_compatibility", ["pytest", "-q", "tests/test_c2_patch_pipeline.py",
        "tests/test_c2_compatibility.py", "tests/test_c2_result_contract.py", "tests/test_zeek_adapter.py"],
        "compatibility, bundle, feed and Zeek tests")
network = subprocess.run(["virsh", "net-dumpxml", "winstdt-controlled-services"], text=True, capture_output=True)
network_pass = network.returncode == 0 and "<forward" not in network.stdout
ledger["entries"]["controlled_services_network"] = {
    "status": "passed" if network_pass else "failed",
    "evidence": ["virsh net-dumpxml: no forward element"] if network_pass else [],
    "limitations": [] if network_pass else [network.stderr.strip() or "forwarding element present"],
}
receipt = subprocess.run(["curl", "--fail", "--silent", "--max-time", "3",
                          "http://192.168.125.10:8080/receipts"], text=True, capture_output=True)
ledger["entries"]["controlled_responder_positive"] = {
    "status": "passed" if receipt.returncode == 0 and receipt.stdout.strip() else "failed",
    "evidence": ["private responder returned signed receipt log"] if receipt.stdout.strip() else [],
    "limitations": [] if receipt.returncode == 0 else [receipt.stderr.strip()],
}
reboot_state = args.root / "libvirt-reboots/state.json"
if reboot_state.exists():
    state = json.loads(reboot_state.read_text())
    cycles = state.get("cycles", [])
    passed = state.get("complete") is True and len(cycles) == 3 and \
             [cycle.get("phase") for cycle in cycles] == \
             ["prepare", "after-reboot-1", "after-reboot-2"] and \
             len({cycle.get("boot_id") for cycle in cycles}) == 3 and \
             all(cycle.get("passed") is True for cycle in cycles)
    ledger["entries"]["libvirt_two_reboots"] = {
        "status": "passed" if passed else "pending", "evidence": [str(reboot_state)] if passed else [],
        "limitations": [] if passed else ["requires two operator-initiated reboots"]}
gateway_acceptance = sorted(args.root.glob("gateway-negative/*/acceptance.json"))
if gateway_acceptance:
    value = json.loads(gateway_acceptance[-1].read_text())
    required = {"wrong_destination", "wrong_port", "policy_expiry_open_connection", "byte_quota",
                "connection_ceiling", "dns_pin", "dns_bypass", "responder_unavailable",
                "emergency_stop", "approved_destination"}
    passed = value.get("status") == "passed" and value.get("public_route_absent") is True \
        and value.get("captures_preserved") is True and value.get("gateway_revoked") is True \
        and required.issubset(value.get("tests", {})) \
        and all(value["tests"].get(name) == "passed" for name in required)
    ledger["entries"]["gateway_negative_matrix"] = {
        "status": "passed" if passed else "failed",
        "evidence": [str(gateway_acceptance[-1])] if passed else [],
        "limitations": [] if passed else ["latest gateway negative matrix is incomplete or failed"],
    }
accepted = sorted(args.root.glob("end-to-end/*/acceptance.json"))
if accepted:
    value = json.loads(accepted[-1].read_text())
    if value.get("status") == "passed":
        ledger["entries"]["full_end_to_end"] = {"status":"passed","evidence":[str(accepted[-1])],"limitations":[]}
ledger["updated_at_utc"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
ledger["host_boot_id"] = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
if not args.execute:
    print(json.dumps(ledger, indent=2)); raise SystemExit(0)
args.root.mkdir(parents=True, exist_ok=True)
with tempfile.NamedTemporaryFile("w", dir=args.root, delete=False) as handle:
    json.dump(ledger, handle, indent=2); handle.write("\n"); temporary = Path(handle.name)
temporary.chmod(0o644); temporary.replace(ledger_path)
print(ledger_path)
