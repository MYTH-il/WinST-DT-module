import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "cape"
    / "modules"
    / "reporting"
    / "winstdt_handoff_export.py"
)


def load_module():
    spec = importlib.util.spec_from_file_location("winstdt_handoff_export", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class WinstdtHandoffExportTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()
        self.tempdir = Path(tempfile.mkdtemp(prefix="winstdt-export-test."))
        self.analysis_path = self.tempdir / "analysis"
        self.handoff_root = self.tempdir / "handoff"
        self.analysis_path.mkdir()
        self.options = self.module.ExportOptions(
            handoff_root=self.handoff_root,
            cape_git_ref="cape-test-ref",
            image_version="win10-22h2-test",
            network_mode="simulated_inetsim",
            capemon_enabled=True,
            guest_agent_version="guest-test",
            yara_rules_ref="rules-test",
            clamav_db_version="clamav-test",
            hash_log_ref="unit-test",
            validator_path=None,
            fail_on_validator_error=True,
            pcap_converter=None,
        )

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def test_exports_completed_bundle(self):
        (self.analysis_path / "dump.pcapng").write_bytes(b"pcapng bytes")
        behavior = self.analysis_path / "behavior"
        behavior.mkdir()
        (behavior / "trace.etl").write_bytes(b"etl bytes")
        (behavior / "telemetry.json").write_text(
            json.dumps(
                {
                    "capture_started": True,
                    "capture_completed": True,
                    "providers_targeted": [
                        "Microsoft-Windows-Kernel-Process",
                        "Microsoft-Windows-Kernel-Image",
                    ],
                    "providers_enabled": ["Microsoft-Windows-Kernel-Process"],
                    "providers_unavailable": [
                        {
                            "provider": "Microsoft-Windows-Kernel-Image",
                            "reason": "provider_missing",
                            "message": "Kernel-Image was not available",
                        }
                    ],
                    "etw_ti_status": "not_attempted",
                }
            ),
            encoding="utf-8",
        )

        bundle = self.module.export_handoff_bundle(
            sample_results(), self.analysis_path, self.options
        )

        manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "completed")
        self.assertTrue(manifest["telemetry"]["telemetry_degraded"])
        self.assertEqual(manifest["artifact_paths"]["trace_etl"], "behavior/trace.etl")
        self.assertEqual(manifest["artifact_paths"]["report_json"], "report.json")
        self.assertEqual(manifest["artifact_paths"]["report_html"], "report.html")
        self.assertTrue((bundle / "network" / "capture.pcapng").is_file())
        self.assertTrue((bundle / "behavior" / "trace.etl").is_file())
        self.assertFalse((bundle / "behavior" / "events.jsonl").exists())
        report = json.loads((bundle / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["session_id"], "42")
        self.assertEqual(report["enrichment"]["virustotal"], "not_run")
        self.assertIn(
            "WinST/DT Analyst Report",
            (bundle / "report.html").read_text(encoding="utf-8"),
        )
        hashes = (bundle / "hashes.sha256").read_text(encoding="utf-8")
        self.assertIn("behavior/trace.etl", hashes)
        self.assertIn("report.json", hashes)
        self.assertIn("report.html", hashes)

    def test_missing_etl_exports_capture_error_bundle(self):
        (self.analysis_path / "dump.pcapng").write_bytes(b"pcapng bytes")

        bundle = self.module.export_handoff_bundle(
            sample_results(), self.analysis_path, self.options
        )

        manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "capture_error")
        self.assertIn(
            {
                "stage": "capture",
                "code": "etl_missing",
                "message": "ETW trace.etl artifact is missing or empty",
            },
            manifest["errors"],
        )
        self.assertFalse((bundle / "behavior" / "trace.etl").exists())
        hashes = (bundle / "hashes.sha256").read_text(encoding="utf-8")
        self.assertIn("sample.meta.json", hashes)
        self.assertIn("report.json", hashes)
        self.assertIn("report.html", hashes)
        self.assertIn("network/capture.pcapng", hashes)
        self.assertNotIn("behavior/trace.etl", hashes)

    def test_events_jsonl_is_disabled_by_default_and_gated(self):
        (self.analysis_path / "dump.pcapng").write_bytes(b"pcapng bytes")
        behavior = self.analysis_path / "behavior"
        behavior.mkdir()
        (behavior / "trace.etl").write_bytes(b"etl bytes")
        os.environ["WINSTDT_ENABLE_EVENTS_JSONL"] = "1"
        try:
            bundle = self.module.export_handoff_bundle(
                sample_results(), self.analysis_path, self.options
            )
        finally:
            os.environ.pop("WINSTDT_ENABLE_EVENTS_JSONL", None)

        manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["artifact_paths"]["events_jsonl"], "behavior/events.jsonl")
        event = json.loads((bundle / "behavior" / "events.jsonl").read_text(encoding="utf-8"))
        self.assertEqual(event["event_type"], "bundle_summary")
        self.assertTrue(event["raw"]["etl_authoritative"])
        self.assertIn("behavior/events.jsonl", (bundle / "hashes.sha256").read_text())

    def test_local_signing_adapter_is_gated(self):
        (self.analysis_path / "dump.pcapng").write_bytes(b"pcapng bytes")
        behavior = self.analysis_path / "behavior"
        behavior.mkdir()
        (behavior / "trace.etl").write_bytes(b"etl bytes")
        key_path = self.tempdir / "local-signing.key"
        key_path.write_bytes(b"unit-test-key")
        os.environ["WINSTDT_SIGNING_ADAPTER"] = "local_file"
        os.environ["WINSTDT_LOCAL_SIGNING_KEY"] = str(key_path)
        try:
            bundle = self.module.export_handoff_bundle(
                sample_results(), self.analysis_path, self.options
            )
        finally:
            os.environ.pop("WINSTDT_SIGNING_ADAPTER", None)
            os.environ.pop("WINSTDT_LOCAL_SIGNING_KEY", None)

        manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["signature"]["adapter"], "local_file")
        self.assertTrue((bundle / "integrity" / "signature.sha256").is_file())


def sample_results():
    return {
        "info": {
            "id": 42,
            "status": "reported",
            "started": "2026-07-19 01:02:03",
            "ended": "2026-07-19 01:07:03",
            "machine_uuid": "vm-uuid-test",
            "machine_ip": "10.66.0.101",
        },
        "target": {
            "file": {
                "sha256": "a" * 64,
                "sha1": "b" * 40,
                "md5": "c" * 32,
                "type": "PE executable",
            }
        },
        "winstdt": {
            "pretriage": {
                "sample_sha256": "a" * 64,
                "sample_sha1": "b" * 40,
                "sample_md5": "c" * 32,
                "file_type": "PE executable",
                "static_risk_score": 35.0,
                "static_hypotheses": ["network_iocs_present"],
                "yara": {"fast_hits": [], "deep_hits": []},
                "clamav": {"status": "not_run", "signature": None},
                "vt_lookup": "not_run",
            }
        },
    }


if __name__ == "__main__":
    unittest.main()
