import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "measure-clock-offset.py"
SPEC = importlib.util.spec_from_file_location("measure_clock_offset", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ClockOffsetTests(unittest.TestCase):
    def test_midpoint_offset_and_uncertainty(self):
        sample = MODULE.make_sample(1_000_000_000, 1_010_000_000, 1_008_000_000)
        self.assertEqual(sample["guest_minus_host_ns"], 3_000_000)
        self.assertEqual(sample["uncertainty_ns"], 5_000_100)

    def test_lowest_rtt_sample_is_authoritative(self):
        slow = MODULE.make_sample(1_000_000_000, 1_020_000_000, 1_012_000_000)
        fast = MODULE.make_sample(2_000_000_000, 2_004_000_000, 2_003_000_000)
        measurement = MODULE.build_measurement([slow, fast], "http://guest:8000")
        self.assertEqual(measurement["guest_minus_host_ns"], 1_000_000)
        self.assertEqual(measurement["minimum_round_trip_ns"], 4_000_000)
        result = MODULE.build_result({"start": measurement}, "http://guest:8000", 25_000_000)
        self.assertTrue(result["quality"]["acceptable"])
        self.assertIn("etw_guest_unix_ns", result["correlation_rule"])


if __name__ == "__main__":
    unittest.main()
