#!/usr/bin/env python3
"""Measure the Windows guest clock offset relative to the CAPE/PCAP host."""

import argparse
import json
import statistics
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


GUEST_TIME_COMMAND = '"C:\\ProgramData\\WinSTDT\\bin\\winstdt.exe" clock-sample'


def utc_iso(epoch_ns):
    return datetime.fromtimestamp(epoch_ns / 1_000_000_000, timezone.utc).isoformat().replace("+00:00", "Z")


def query_guest_epoch_ns(url, timeout):
    body = urllib.parse.urlencode({"command": GUEST_TIME_COMMAND}).encode()
    t0 = time.time_ns()
    with urllib.request.urlopen(url.rstrip("/") + "/execute", body, timeout=timeout) as response:
        payload = json.load(response)
    t1 = time.time_ns()
    stdout = str(payload.get("stdout", "")).strip()
    try:
        guest_ns = int(stdout)
    except ValueError as exc:
        raise RuntimeError("CAPE agent returned an invalid guest timestamp: {!r}".format(stdout)) from exc
    return make_sample(t0, t1, guest_ns)


def make_sample(host_send_ns, host_receive_ns, guest_ns):
    midpoint_ns = (host_send_ns + host_receive_ns) // 2
    rtt_ns = host_receive_ns - host_send_ns
    return {
        "host_send_unix_ns": host_send_ns,
        "host_receive_unix_ns": host_receive_ns,
        "host_midpoint_unix_ns": midpoint_ns,
        "guest_unix_ns": guest_ns,
        "guest_minus_host_ns": guest_ns - midpoint_ns,
        "round_trip_ns": rtt_ns,
        "uncertainty_ns": (rtt_ns // 2) + 100,
    }


def build_measurement(samples, guest_url):
    best = min(samples, key=lambda item: item["round_trip_ns"])
    offsets = [item["guest_minus_host_ns"] for item in samples]
    return {
        "method": "agent_http_midpoint",
        "measured_at_utc": utc_iso(best["host_midpoint_unix_ns"]),
        "guest_endpoint": guest_url,
        "offset_definition": "guest_utc_minus_host_utc",
        "guest_minus_host_ns": best["guest_minus_host_ns"],
        "uncertainty_ns": best["uncertainty_ns"],
        "minimum_round_trip_ns": best["round_trip_ns"],
        "sample_count": len(samples),
        "offset_spread_ns": max(offsets) - min(offsets),
        "median_guest_minus_host_ns": int(statistics.median(offsets)),
        "selected_sample": best,
    }


def build_result(measurements, guest_url, maximum_uncertainty_ns):
    ordered = sorted(measurements.values(), key=lambda item: item["selected_sample"]["host_midpoint_unix_ns"])
    maximum_observed = max(item["uncertainty_ns"] for item in ordered)
    result = {
        "schema_version": "1.0",
        "guest_endpoint": guest_url,
        "offset_definition": "guest_utc_minus_host_utc",
        "correlation_rule": "host_or_pcap_unix_ns = etw_guest_unix_ns - interpolated_guest_minus_host_ns",
        "measurements": measurements,
        "quality": {
            "maximum_allowed_uncertainty_ns": maximum_uncertainty_ns,
            "maximum_observed_uncertainty_ns": maximum_observed,
            "acceptable": maximum_observed <= maximum_uncertainty_ns,
        },
    }
    if len(ordered) >= 2:
        first, last = ordered[0], ordered[-1]
        elapsed = last["selected_sample"]["host_midpoint_unix_ns"] - first["selected_sample"]["host_midpoint_unix_ns"]
        delta = last["guest_minus_host_ns"] - first["guest_minus_host_ns"]
        result["drift"] = {
            "offset_change_ns": delta,
            "measurement_interval_ns": elapsed,
            "parts_per_million": (delta / elapsed * 1_000_000) if elapsed else None,
            "interpolation": "linear_between_start_and_end",
        }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--guest-url", default="http://10.66.0.101:8000")
    parser.add_argument("--samples", type=int, default=9)
    parser.add_argument("--interval-ms", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--phase", choices=("single", "start", "end"), default="single")
    parser.add_argument("--maximum-uncertainty-ms", type=float, default=25.0)
    args = parser.parse_args()
    if args.samples < 3:
        parser.error("--samples must be at least 3")

    samples = []
    for index in range(args.samples):
        samples.append(query_guest_epoch_ns(args.guest_url, args.timeout))
        if index + 1 < args.samples:
            time.sleep(args.interval_ms / 1000)
    measurement = build_measurement(samples, args.guest_url)
    measurements = {}
    if args.output and args.output.exists() and args.phase != "single":
        existing = json.loads(args.output.read_text(encoding="utf-8"))
        measurements.update(existing.get("measurements", {}))
    measurements[args.phase] = measurement
    result = build_result(measurements, args.guest_url, int(args.maximum_uncertainty_ms * 1_000_000))
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    if not result["quality"]["acceptable"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
