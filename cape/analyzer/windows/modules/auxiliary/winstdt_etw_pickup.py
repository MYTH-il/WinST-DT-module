import logging
import os
import subprocess
import time
from threading import Thread

from lib.common.abstracts import Auxiliary
from lib.common.results import upload_buffer_to_host

log = logging.getLogger(__name__)


class Winstdt_etw_pickup(Auxiliary):
    """Flush and upload the WinST/DT raw ETW artifact at analysis shutdown."""

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        self.enabled = getattr(config, "winstdt_etw_pickup", False)
        self.root = r"C:\ProgramData\WinSTDT"
        self.agent = os.path.join(self.root, "bin", "winstdt.exe")
        self.config_path = os.path.join(self.root, "etw-agent.config.json")
        self.behavior_dir = os.path.join(self.root, "behavior")
        self.start_delay_seconds = 10
        self._start_thread = None

    def start(self):
        if not self.enabled:
            log.debug("WinST/DT ETW pickup auxiliary module not enabled")
            return
        log.info("WinST/DT ETW pickup auxiliary module enabled")
        if not os.path.isfile(self.agent) or not os.path.isfile(self.config_path):
            log.warning("WinST/DT ETW agent/config missing; ETW capture will not start")
            return
        self._start_thread = Thread(target=self._delayed_start_capture)
        self._start_thread.daemon = True
        self._start_thread.start()

    def finish(self):
        if not self.enabled:
            return
        if self._start_thread:
            self._start_thread.join(timeout=45)

        if os.path.isfile(self.agent) and os.path.isfile(self.config_path):
            try:
                self._run_etw_agent("stop")
            except Exception as exc:
                log.warning("WinST/DT ETW stop failed before pickup: %s", exc)
        else:
            log.warning("WinST/DT ETW agent/config missing; pickup will only upload existing files")

        self._upload_if_present("trace.etl", "aux/trace.etl")
        self._upload_if_present("telemetry.json", "aux/telemetry.json")
        self._upload_if_present("etw_state.json", "aux/etw_state.json")

    def _upload_if_present(self, filename, destination):
        path = os.path.join(self.behavior_dir, filename)
        if not os.path.isfile(path):
            log.warning("WinST/DT ETW artifact missing: %s", path)
            return
        if os.path.getsize(path) <= 0:
            log.warning("WinST/DT ETW artifact is empty: %s", path)
            return
        log.info("Uploading WinST/DT ETW artifact %s to %s", path, destination)
        with open(path, "rb") as handle:
            upload_buffer_to_host(handle.read(), destination)

    def _delayed_start_capture(self):
        time.sleep(self.start_delay_seconds)
        try:
            self._run_etw_agent("stop")
        except Exception as exc:
            log.debug("WinST/DT ETW stale-session stop before start returned: %s", exc)
        try:
            self._run_etw_agent("start")
        except Exception as exc:
            log.warning("WinST/DT ETW delayed start failed: %s", exc)

    def _run_etw_agent(self, action):
        try:
            output = subprocess.check_output(
                [self.agent, "etw-agent", "--config", self.config_path, action],
                stderr=subprocess.STDOUT,
                timeout=30,
            )
            if output:
                log.debug("WinST/DT ETW %s output: %s", action, output.decode("utf-8", "replace").strip())
        except subprocess.CalledProcessError as exc:
            output = exc.output.decode("utf-8", "replace").strip() if exc.output else ""
            raise RuntimeError("exit {} output={!r}".format(exc.returncode, output))
