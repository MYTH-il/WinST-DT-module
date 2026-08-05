import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from winstdt.access_events import build_access_events


def report(timestamp="2026-08-05T10:00:06Z"):
    return {"behavior": {"processes": [{"process_name": "fixture.exe", "calls": [
        {"api": "GetClipboardData", "timestamp": timestamp}
    ]}]}}


def clock(offset_end=2_000_000_000, uncertainty=1_000_000):
    return {"quality": {"acceptable": True, "maximum_observed_uncertainty_ns": uncertainty},
            "measurements": {
                "start": {"guest_minus_host_ns": 1_000_000_000, "uncertainty_ns": uncertainty,
                          "selected_sample": {"host_midpoint_unix_ns": 1785924000_000000000}},
                "end": {"guest_minus_host_ns": offset_end, "uncertainty_ns": uncertainty,
                        "selected_sample": {"host_midpoint_unix_ns": 1785924060_000000000}}}}


def test_interpolates_and_accepts_real_cape_call():
    events, status = build_access_events(report(), clock(), "2026-08-05T10:00:00Z", "2026-08-05T10:01:00Z")
    assert events[0]["timestamp"].startswith("2026-08-05T10:00:04.9")
    assert status["correlation_eligible"]


def test_requires_start_and_end_measurements():
    value = clock(); del value["measurements"]["end"]
    events, status = build_access_events(report(), value, "2026-08-05T10:00:00Z", "2026-08-05T10:01:00Z")
    assert events == []
    assert status["reason_code"] == "clock_measurements_incomplete"


def test_half_window_uncertainty_disables_correlation():
    _, status = build_access_events(report(), clock(uncertainty=7_500_000_000),
                                    "2026-08-05T10:00:00Z", "2026-08-05T10:01:00Z")
    assert not status["correlation_eligible"]
    assert status["reason_code"] == "clock_uncertainty_exceeds_correlation_limit"


def test_out_of_window_event_rejected():
    events, status = build_access_events(report("2026-08-05T11:00:00Z"), clock(),
                                         "2026-08-05T10:00:00Z", "2026-08-05T10:01:00Z")
    assert events == [] and status["rejected_event_count"] == 1


def test_etw_conflict_disables_correlation():
    _, status = build_access_events(report(), clock(), "2026-08-05T10:00:00Z",
                                    "2026-08-05T10:01:00Z",
                                    [{"timestamp": "2026-08-05T10:00:30Z", "api_call": "ReadFile"}])
    assert status["etw_corroboration_state"] == "conflicting"
    assert status["reason_code"] == "etw_material_conflict"


def test_native_capemon_api_names_are_preserved():
    value = {"behavior": {"processes": [{"process_name": "fixture.exe", "calls": [
        {"api": "NtReadFile", "timestamp": "2026-08-05T10:00:06Z"},
        {"api": "SetClipboardData", "timestamp": "2026-08-05T10:00:07Z"},
        {"api": "GetComputerNameW", "timestamp": "2026-08-05T10:00:08Z"},
    ]}]}}
    events, status = build_access_events(value, clock(), "2026-08-05T10:00:00Z", "2026-08-05T10:01:00Z")
    assert [event["data_type"] for event in events] == ["file_access", "clipboard", "system_info"]
    assert status["correlation_eligible"]
