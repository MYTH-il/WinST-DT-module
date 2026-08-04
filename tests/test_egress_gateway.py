import importlib.util
import json
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
    def config(self, destination="192.0.2.10"):
        return {
            "run_id": "unit-test-001",
            "internal_interface": "eth0",
            "external_interface": "eth1",
            "guest_ip": "10.66.0.101",
            "destinations": [{"ip": destination, "protocol": "tcp", "port": 443}],
            "dns": {"name": "test.invalid", "pinned_ip": destination},
            "expires_at_utc": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            "max_connections": 8,
            "max_bytes": 10 * 1024 * 1024,
            "approval_id": "unit-test-approval",
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
        self.assertIn("ip daddr 192.0.2.10 tcp dport 443", rules)
        self.assertIn("quota run_quota_1", rules)
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


if __name__ == "__main__":
    unittest.main()
