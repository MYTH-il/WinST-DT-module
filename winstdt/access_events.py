"""Build trustworthy, clock-corrected host access events from CAPE observations."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CORRELATION_WINDOW_SECONDS = 15
MAX_UNCERTAINTY_NS = CORRELATION_WINDOW_SECONDS * 1_000_000_000 // 2
API_TYPES = {
    "CryptUnprotectData": "browser_credentials", "BCryptDecrypt": "browser_credentials",
    "SetWindowsHookExA": "keystrokes", "SetWindowsHookExW": "keystrokes",
    "GetAsyncKeyState": "keystrokes", "BitBlt": "screenshot",
    "CreateCompatibleBitmap": "screenshot", "GetClipboardData": "clipboard",
    "OpenClipboard": "clipboard", "GetComputerNameExA": "system_info",
    "GetComputerNameExW": "system_info", "GetUserNameA": "system_info",
    "GetUserNameW": "system_info", "ReadFile": "file_access",
    "CreateFileA": "file_access", "CreateFileW": "file_access",
    "NtReadFile": "file_access", "NtCreateFile": "file_access",
    "SetClipboardData": "clipboard", "GetComputerNameW": "system_info",
}


def _datetime(value: Any) -> datetime:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), timezone.utc)
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00").replace(" ", "T"))
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _point(measurement: dict, fallback: datetime) -> tuple[int, int, int]:
    selected = measurement.get("selected_sample", {})
    host_ns = int(selected.get("host_midpoint_unix_ns", int(fallback.timestamp() * 1e9)))
    return host_ns, int(measurement["guest_minus_host_ns"]), int(measurement.get("uncertainty_ns", 0))


def _correct(guest: datetime, start: tuple[int, int, int], end: tuple[int, int, int]) -> datetime:
    guest_ns = int(guest.timestamp() * 1e9)
    span = end[0] - start[0]
    fraction = 0.0 if span <= 0 else min(1.0, max(0.0, (guest_ns - start[0]) / span))
    offset = start[1] + int((end[1] - start[1]) * fraction)
    return datetime.fromtimestamp((guest_ns - offset) / 1e9, timezone.utc)


def _validate_events(events: list[dict], schema_path: Path | None) -> None:
    if schema_path:
        try:
            import jsonschema
            jsonschema.validate(events, json.loads(schema_path.read_text(encoding="utf-8")))
            return
        except ImportError:
            pass
    for event in events:
        if set(event) - {"timestamp", "data_type", "api_call", "process"}:
            raise ValueError("undocumented access-event field")
        _datetime(event["timestamp"])
        if event["data_type"] not in set(API_TYPES.values()) or not event["api_call"]:
            raise ValueError("invalid access event")


def _etw_state(events: list[dict], etw_events: list[dict] | None) -> str:
    if not etw_events:
        return "not_available"
    matches = 0
    for event in events:
        when = _datetime(event["timestamp"])
        if any(abs((_datetime(item.get("timestamp")) - when).total_seconds()) <= 2
               and (not item.get("api_call") or item.get("api_call") == event["api_call"])
               and (not item.get("process") or item.get("process") == event.get("process"))
               for item in etw_events if item.get("timestamp")):
            matches += 1
    if matches == len(events):
        return "corroborated"
    return "partially_corroborated" if matches else "conflicting"


def build_access_events(results: dict, clock: dict, analysis_start: Any, analysis_end: Any,
                        etw_events: list[dict] | None = None,
                        schema_path: Path | None = None) -> tuple[list[dict], dict]:
    """Return validated events and a stable eligibility status document."""
    start_time, end_time = _datetime(analysis_start), _datetime(analysis_end)
    measurements = clock.get("measurements", {}) if isinstance(clock, dict) else {}
    reason = None
    if not all(key in measurements for key in ("start", "end")):
        reason = "clock_measurements_incomplete"
        points = None
        maximum_uncertainty = None
    else:
        points = (_point(measurements["start"], start_time),
                  _point(measurements["end"], end_time))
        maximum_uncertainty = max(points[0][2], points[1][2], int(
            clock.get("quality", {}).get("maximum_observed_uncertainty_ns", 0)))
        if not clock.get("quality", {}).get("acceptable", False):
            reason = "clock_quality_rejected"
        elif maximum_uncertainty >= MAX_UNCERTAINTY_NS:
            reason = "clock_uncertainty_exceeds_correlation_limit"

    events, rejected = [], 0
    if points:
        for process in results.get("behavior", {}).get("processes", []):
            if not isinstance(process, dict) or not isinstance(process.get("calls", []), list):
                continue
            for call in process.get("calls", []):
                if not isinstance(call, dict) or call.get("api") not in API_TYPES:
                    continue
                try:
                    corrected = _correct(_datetime(call["timestamp"]), *points)
                except (KeyError, TypeError, ValueError, OSError):
                    rejected += 1
                    continue
                if corrected < start_time or corrected > end_time:
                    rejected += 1
                    continue
                events.append({"timestamp": _iso(corrected), "data_type": API_TYPES[call["api"]],
                               "api_call": call["api"],
                               "process": process.get("process_name") or None})
    try:
        _validate_events(events, schema_path)
    except Exception:
        events, reason = [], "access_event_schema_invalid"
    etw_state = _etw_state(events, etw_events)
    if etw_state == "conflicting":
        reason = "etw_material_conflict"
    if not events and reason is None:
        reason = "no_observed_access_events"
    eligible = reason is None
    status = {
        "schema_version": "1.0", "event_count": len(events), "source": "cape_capemon",
        "etw_corroboration_state": etw_state,
        "clock_algorithm": "linear_start_end_interpolation",
        "maximum_uncertainty_ns": maximum_uncertainty,
        "correlation_eligible": eligible,
        "reason_code": reason, "rejected_event_count": rejected,
    }
    return events, status


def write_access_event_artifacts(events_path: Path, status_path: Path, *args, **kwargs) -> dict:
    events, status = build_access_events(*args, **kwargs)
    events_path.parent.mkdir(parents=True, exist_ok=True)
    events_path.write_text(json.dumps(events, indent=2) + "\n", encoding="utf-8")
    status_path.write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")
    return status
