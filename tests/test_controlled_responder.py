import json
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]


def test_controlled_network_has_no_forwarding():
    network = (ROOT / "config/libvirt/winstdt-controlled-services.xml").read_text()
    assert "<forward" not in network
    assert "192.168.125.10" in network and "192.168.125.254" in network


def test_responder_is_private_and_never_forwards():
    setup = (ROOT / "scripts/setup-controlled-responder.sh").read_text()
    server = (ROOT / "responder/controlled_responder.py").read_text()
    assert "net.ipv4.ip_forward=0" in setup
    assert "rc-service, sshd, stop" in setup
    assert "packages:" not in setup
    assert "WINSTDT-CONTROLLED-CANARY/1" in server
    assert 'set(request) != {"marker", "run_id", "sequence", "canary"}' in server


def test_receipt_and_approval_schemas_are_valid():
    for name in ("gateway_approval.schema.json", "responder_receipt.schema.json"):
        jsonschema.Draft202012Validator.check_schema(
            json.loads((ROOT / "schemas" / name).read_text()))


def test_gateway_approval_consumption_and_capture_collection_are_fail_closed():
    setup = (ROOT / "scripts/setup-egress-gateway.sh").read_text()
    manager = (ROOT / "scripts/manage-egress-run.sh").read_text()
    assert "consumed-approvals" in setup
    assert "approval already consumed" in setup
    assert "conntrack -D" in setup
    assert "internal.pcap" in setup and "external.pcap" in setup
    assert "gateway-hashes.sha256" in manager
    assert "responder-receipts.jsonl" in manager
