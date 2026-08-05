import importlib.util
import hashlib
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "configure-egress-gateway.py"
SPEC = importlib.util.spec_from_file_location("configure_egress_gateway", MODULE_PATH)
gateway = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(gateway)


class EgressGatewayTests(unittest.TestCase):
    def config(self, destination="192.168.125.10"):
        return {
            "run_id": "unit-test-001",
            "internal_interface": "eth0",
            "external_interface": "eth1",
            "guest_ip": "10.66.0.101",
            "destinations": [{"ip": destination, "protocol": "tcp", "port": 8080}],
            "dns": {"name": "validation.winstdt.test", "pinned_ip": destination},
            "expires_at_utc": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            "max_connections": 8,
            "max_bytes": 10 * 1024 * 1024,
            "approval": {"approval_id": "unit-test-approval", "signer_identity": "test@example",
                         "policy_sha256": "placeholder", "signature_path": "approval.sig"},
        }

    def load(self, config):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            return gateway.load_config(path)

    def test_renders_complete_fail_closed_ruleset(self):
        rules = gateway.render(self.load(self.config()))
        self.assertIn("flush ruleset", rules)
        self.assertIn("chain forward { type filter hook forward priority 0; policy drop;", rules)
        self.assertIn("ip daddr 192.168.125.10 tcp dport 8080", rules)
        self.assertIn("quota run_quota_1", rules)
        self.assertIn("quota name run_quota_1 over counter drop", rules)
        self.assertIn("masquerade", rules)

    def test_rejects_analysis_management_subnet(self):
        with self.assertRaisesRegex(SystemExit, "protected network"):
            self.load(self.config("10.66.0.1"))

    def test_rejects_link_local_metadata_range(self):
        with self.assertRaisesRegex(SystemExit, "protected network"):
            self.load(self.config("169.254.169.254"))

    def test_rejects_unpinned_dns_destination(self):
        config = self.config()
        config["dns"]["pinned_ip"] = "192.0.2.11"
        with self.assertRaisesRegex(SystemExit, "must also be an allowed destination"):
            self.load(config)

    def test_rejects_public_destination(self):
        with self.assertRaisesRegex(SystemExit, "unsupported"):
            self.load(self.config("192.0.2.10"))

    def test_ed25519_approval_binds_id_and_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); key = root / "key"; allowed = root / "allowed"
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
            allowed.write_text("test@example " + (root / "key.pub").read_text())
            path = root / "run.json"; config = self.config(); path.write_text(json.dumps(config))
            normalized = gateway.load_config(path)
            policy = {k: v for k, v in normalized.items() if k != "approval" and not k.startswith("_")}
            config["approval"]["policy_sha256"] = hashlib.sha256(
                json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            path.write_text(json.dumps(config)); normalized = gateway.load_config(path)
            message = root / "approval"; message.write_bytes(gateway.canonical_policy(normalized))
            subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", "winstdt-egress", str(message)], check=True)
            config["approval"]["signature_path"] = "approval.sig"
            path.write_text(json.dumps(config)); (root / "approval.sig").write_bytes((root / "approval.sig").read_bytes())
            gateway.verify_approval(gateway.load_config(path), path, allowed)
            config["approval"]["approval_id"] = "changed"; path.write_text(json.dumps(config))
            with self.assertRaisesRegex(SystemExit, "verification failed"):
                gateway.verify_approval(gateway.load_config(path), path, allowed)


if __name__ == "__main__":
    unittest.main()
