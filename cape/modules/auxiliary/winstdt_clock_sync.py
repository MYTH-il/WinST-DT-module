"""Measure guest/host clock offset for trustworthy host/network correlation."""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import timezone
from email.utils import parsedate_to_datetime
from http.client import HTTPConnection
from pathlib import Path

from lib.cuckoo.common.abstracts import Auxiliary
from lib.cuckoo.common.constants import CUCKOO_GUEST_PORT, CUCKOO_ROOT


class WinstdtClockSync(Auxiliary):
    """Collect bounded start/end samples without executing code in the guest."""

    def __init__(self):
        super().__init__()
        self._start = None
        self._thread = None
        self._stop = threading.Event()

    def _sample(self):
        before = time.time_ns()
        connection = HTTPConnection(self.machine.ip, CUCKOO_GUEST_PORT, timeout=2)
        try:
            connection.request("GET", "/")
            response = connection.getresponse()
            date_header = response.getheader("Date")
            response.read()
        finally:
            connection.close()
        after = time.time_ns()
        guest = parsedate_to_datetime(date_header).astimezone(timezone.utc)
        guest_ns = int(guest.timestamp() * 1_000_000_000)
        midpoint = before + (after - before) // 2
        return {
            "host_start_unix_ns": before,
            "host_end_unix_ns": after,
            "host_midpoint_unix_ns": midpoint,
            "guest_unix_ns": guest_ns,
            "guest_minus_host_ns": guest_ns - midpoint,
            "uncertainty_ns": (after - before) // 2 + 500_000_000,
        }

    def _start_sampler(self):
        deadline = time.monotonic() + 60
        while not self._stop.is_set() and time.monotonic() < deadline:
            try:
                self._start = self._sample()
                return
            except (OSError, ValueError, TypeError):
                self._stop.wait(1)

    def start(self):
        self._thread = threading.Thread(target=self._start_sampler, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        end = None
        try:
            end = self._sample()
        except (OSError, ValueError, TypeError):
            pass
        measurements = {}
        if self._start:
            measurements["start"] = {
                "selected_sample": self._start,
                "guest_minus_host_ns": self._start["guest_minus_host_ns"],
                "uncertainty_ns": self._start["uncertainty_ns"],
            }
        if end:
            measurements["end"] = {
                "selected_sample": end,
                "guest_minus_host_ns": end["guest_minus_host_ns"],
                "uncertainty_ns": end["uncertainty_ns"],
            }
        uncertainties = [value["uncertainty_ns"] for value in measurements.values()]
        maximum = max(uncertainties) if uncertainties else None
        value = {
            "schema_version": "1.0",
            "algorithm": "http_date_midpoint_linear_interpolation",
            "measurements": measurements,
            "quality": {
                "acceptable": len(measurements) == 2 and maximum is not None and maximum < 7_500_000_000,
                "maximum_observed_uncertainty_ns": maximum,
            },
        }
        destination = Path(CUCKOO_ROOT) / "storage" / "analyses" / str(self.task.id) / "aux" / "clock-sync.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
        temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, destination)

