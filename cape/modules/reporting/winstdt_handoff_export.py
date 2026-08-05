"""CAPEv2 reporting module for WinST/DT handoff bundle export.

Install into a CAPEv2 checkout as modules/reporting/winstdt_handoff_export.py
and enable it from reporting.conf. The module is intentionally defensive about
CAPE's results dictionary because this project tracks CAPEv2 rolling release.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from winstdt.access_events import write_access_event_artifacts

try:
    from lib.cuckoo.common.abstracts import Report
    from lib.cuckoo.common.exceptions import CuckooReportError
except ImportError:  # Allows local unit tests without a CAPEv2 checkout.
    class Report:  # type: ignore[no-redef]
        pass

    class CuckooReportError(Exception):  # type: ignore[no-redef]
        pass


SCHEMA_VERSION = "1.0"
MODULE_VERSION = "0.2.0"
TRACE_ETL_PATH = "behavior/trace.etl"
PCAP_PATH = "network/capture.pcapng"
CLOCK_SYNC_PATH = "behavior/clock-sync.json"
HASH_MANIFEST_PATH = "hashes.sha256"
REPORT_JSON_PATH = "report.json"
REPORT_HTML_PATH = "report.html"
EVENTS_JSONL_PATH = "behavior/events.jsonl"
ACCESS_EVENTS_PATH = "behavior/access_events.json"
ACCESS_EVENTS_STATUS_PATH = "behavior/access_events.status.json"
SIGNATURE_PATH = "integrity/signature.sha256"
BASELINE_PROVIDERS = [
    "Microsoft-Windows-Kernel-Process",
    "Microsoft-Windows-Kernel-File",
    "Microsoft-Windows-Kernel-Registry",
    "Microsoft-Windows-Kernel-Network",
]
OPTIONAL_PROVIDERS = [
    "Microsoft-Windows-Kernel-Image",
    "Microsoft-Windows-Threat-Intelligence",
]


@dataclass(frozen=True)
class ExportOptions:
    handoff_root: Path
    cape_git_ref: str
    image_version: str
    network_mode: str
    capemon_enabled: bool
    guest_agent_version: str
    yara_rules_ref: str
    clamav_db_version: str
    hash_log_ref: str
    validator_path: str | None
    fail_on_validator_error: bool
    pcap_converter: str | None
    default_profile: str = "standard"


class WinstdtHandoffExport(Report):
    """Exports CAPE results into the WinST/DT C2 handoff contract."""

    def run(self, results: dict[str, Any]) -> None:
        try:
            options = options_from_mapping(getattr(self, "options", {}))
            bundle = export_handoff_bundle(
                results=results,
                analysis_path=Path(self.analysis_path),
                options=options,
            )
            if options.validator_path:
                validate_exported_bundle(bundle, options)
        except Exception as exc:
            raise CuckooReportError(f"WinST/DT handoff export failed: {exc}") from exc


def options_from_mapping(values: dict[str, Any]) -> ExportOptions:
    def text(name: str, default: str) -> str:
        value = values.get(name, default)
        return str(value).strip() or default

    def boolean(name: str, default: bool) -> bool:
        value = values.get(name, default)
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "yes", "true", "on"}

    validator = text("validator_path", "")
    converter = text("pcap_converter", "")
    return ExportOptions(
        handoff_root=Path(text("handoff_root", "/srv/winstdt/handoff")),
        cape_git_ref=text("cape_git_ref", "unknown"),
        image_version=text("image_version", "unknown"),
        network_mode=text("network_mode", "simulated_inetsim"),
        capemon_enabled=boolean("capemon_enabled", True),
        guest_agent_version=text(
            "winstdt_guest_agent_version", text("guest_agent_version", "unknown")
        ),
        yara_rules_ref=text("yara_rules_ref", "unknown"),
        clamav_db_version=text("clamav_db_version", "unknown"),
        hash_log_ref=text("hash_log_ref", "local"),
        validator_path=validator or None,
        fail_on_validator_error=boolean("fail_on_validator_error", True),
        pcap_converter=converter or "editcap",
        default_profile=text("default_profile", "standard"),
    )


def export_handoff_bundle(
    results: dict[str, Any], analysis_path: Path, options: ExportOptions
) -> Path:
    task_id = get_task_id(results)
    session_id = str(task_id)
    final_bundle = options.handoff_root / session_id

    options.handoff_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f".{session_id}.", dir=str(options.handoff_root)
    ) as tmp_name:
        tmp_bundle = Path(tmp_name)
        (tmp_bundle / "network").mkdir()
        (tmp_bundle / "behavior").mkdir()

        package = build_package_inputs(results, analysis_path, options)
        copy_if_present(package.pcap_source, tmp_bundle / PCAP_PATH, options)
        copy_if_present(package.etl_source, tmp_bundle / TRACE_ETL_PATH, options)
        copy_if_present(package.clock_sync_source, tmp_bundle / CLOCK_SYNC_PATH, options)
        access_status = write_access_events(
            tmp_bundle / ACCESS_EVENTS_PATH, tmp_bundle / ACCESS_EVENTS_STATUS_PATH,
            results, package.clock_sync_source, analysis_path
        )

        profile, resolved_options = resolve_profile(results, options.default_profile)
        capabilities = export_capability_artifacts(
            results, analysis_path, tmp_bundle, profile, resolved_options
        )

        sample_meta = build_sample_meta(results)
        write_json(tmp_bundle / "sample.meta.json", sample_meta)

        manifest = build_manifest(
            results=results,
            options=options,
            package=package,
            sample_meta=sample_meta,
            tmp_bundle=tmp_bundle,
            profile=profile,
            resolved_options=resolved_options,
            capabilities=capabilities,
            access_status=access_status,
        )
        if events_jsonl_enabled():
            write_events_jsonl(tmp_bundle / EVENTS_JSONL_PATH, manifest)
            manifest["artifact_paths"]["events_jsonl"] = EVENTS_JSONL_PATH
        analyst_report = build_analyst_report(manifest, sample_meta)
        write_json(tmp_bundle / REPORT_JSON_PATH, analyst_report)
        write_text(tmp_bundle / REPORT_HTML_PATH, render_analyst_report_html(analyst_report))
        write_hash_manifest(tmp_bundle, manifest["status"])
        manifest["integrity"]["hash_manifest_sha256"] = sha256_file(
            tmp_bundle / HASH_MANIFEST_PATH
        )
        signature = maybe_sign_hash_manifest(tmp_bundle)
        if signature:
            manifest["signature"] = signature
        write_json(tmp_bundle / "manifest.json", manifest)
        make_bundle_readable(tmp_bundle)

        if final_bundle.exists():
            shutil.rmtree(final_bundle)
        os.replace(tmp_bundle, final_bundle)

    return final_bundle


def make_bundle_readable(bundle: Path) -> None:
    for path in bundle.rglob("*"):
        if path.is_dir():
            path.chmod(0o755)
        else:
            path.chmod(0o644)
    bundle.chmod(0o755)


@dataclass(frozen=True)
class PackageInputs:
    pcap_source: Path | None
    etl_source: Path | None
    telemetry_sidecar: dict[str, Any]
    errors: list[dict[str, str]]
    clock_sync_source: Path | None = None


def build_package_inputs(
    results: dict[str, Any], analysis_path: Path, options: ExportOptions
) -> PackageInputs:
    errors: list[dict[str, str]] = []
    pcap_source = first_existing(
        [
            analysis_path / "dump.pcapng",
            analysis_path / "dump.pcap",
            analysis_path / "network" / "dump.pcapng",
            analysis_path / "network" / "dump.pcap",
        ]
    )
    if not usable_file(pcap_source):
        errors.append(capture_error("pcap_missing", "CAPE PCAP artifact is missing or empty"))

    etl_source = first_existing(
        [
            analysis_path / "behavior" / "trace.etl",
            analysis_path / "winstdt" / "trace.etl",
            analysis_path / "files" / "behavior" / "trace.etl",
            analysis_path / "aux" / "trace.etl",
            analysis_path / "trace.etl",
        ]
    )
    if not usable_file(etl_source):
        errors.append(capture_error("etl_missing", "ETW trace.etl artifact is missing or empty"))

    telemetry_sidecar = read_first_json(
        [
            analysis_path / "behavior" / "telemetry.json",
            analysis_path / "winstdt" / "telemetry.json",
            analysis_path / "files" / "behavior" / "telemetry.json",
            analysis_path / "aux" / "telemetry.json",
            analysis_path / "telemetry.json",
        ]
    )
    task_id = get_task_id(results)
    clock_root = Path(os.environ.get("WINSTDT_CLOCK_SYNC_ROOT", "/srv/winstdt/clock-sync"))
    clock_sync_source = first_existing(
        [analysis_path / "aux" / "clock-sync.json", clock_root / f"{task_id}.json"]
    )
    return PackageInputs(pcap_source, etl_source, telemetry_sidecar, errors, clock_sync_source)


def build_sample_meta(results: dict[str, Any]) -> dict[str, Any]:
    target = as_dict(results.get("target"))
    file_info = as_dict(target.get("file"))
    static = as_dict(results.get("static"))
    winstdt = as_dict(results.get("winstdt"))
    pretriage = as_dict(winstdt.get("pretriage"))

    sha256 = first_text(
        pretriage.get("sample_sha256"),
        file_info.get("sha256"),
        results.get("sha256"),
        "0" * 64,
    )
    risk_score = float(first_number(pretriage.get("static_risk_score"), 0.0))
    hypotheses = list_of_text(pretriage.get("static_hypotheses"))

    return {
        "schema_version": SCHEMA_VERSION,
        "sample_sha256": sha256,
        "sample_md5": first_text(pretriage.get("sample_md5"), file_info.get("md5"), ""),
        "sample_sha1": first_text(pretriage.get("sample_sha1"), file_info.get("sha1"), ""),
        "file_type": first_text(
            pretriage.get("file_type"),
            static.get("filetype"),
            file_info.get("type"),
            "unknown",
        ),
        "static_risk_score": risk_score,
        "static_hypotheses": hypotheses,
        "yara": {
            "fast_hits": list_of_rule_names(pretriage.get("yara", {}).get("fast_hits")),
            "deep_hits": list_of_rule_names(pretriage.get("yara", {}).get("deep_hits")),
        },
        "clamav": as_dict(
            pretriage.get("clamav"),
            default={"status": "not_run", "signature": None},
        ),
        "vt_lookup": first_text(pretriage.get("vt_lookup"), "not_run"),
    }


def build_manifest(
    results: dict[str, Any],
    options: ExportOptions,
    package: PackageInputs,
    sample_meta: dict[str, Any],
    tmp_bundle: Path,
    profile: str,
    resolved_options: dict[str, Any],
    capabilities: dict[str, Any],
    access_status: dict[str, Any],
) -> dict[str, Any]:
    info = as_dict(results.get("info"))
    task_id = get_task_id(results)
    telemetry = build_telemetry(package.telemetry_sidecar)
    errors = list(package.errors)
    status = derive_status(results, package, tmp_bundle)
    if status == "capture_error":
        errors.extend(missing_artifact_errors(tmp_bundle))

    return {
        "schema_version": SCHEMA_VERSION,
        "session_id": str(task_id),
        "status": status,
        "errors": dedupe_errors(errors),
        "sample_sha256": sample_meta["sample_sha256"],
        "submitted_at_utc": cape_time(info.get("started")),
        "detonation_start_utc": cape_time(info.get("started")),
        "detonation_end_utc": cape_time(info.get("ended")),
        "guest_vm_identity": {
            "image_version": options.image_version,
            "vm_uuid": first_text(info.get("machine_uuid"), info.get("machine_id"), "unknown"),
            "guest_ip": first_text(info.get("machine_ip"), info.get("guest_ip"), "unknown"),
        },
        "network_mode": options.network_mode,
        "static_risk_score": sample_meta["static_risk_score"],
        "static_hypotheses": sample_meta["static_hypotheses"],
        "cape_task_id": task_id,
        "capemon_enabled": options.capemon_enabled,
        "profile": profile,
        "resolved_options": resolved_options,
        "capabilities": capabilities,
        "correlation": access_status,
        "telemetry": telemetry,
        "tool_versions": {
            "cape_git_ref": options.cape_git_ref,
            "winstdt_schema_version": SCHEMA_VERSION,
            "winstdt_reporting_module_version": MODULE_VERSION,
            "winstdt_guest_agent_version": options.guest_agent_version,
            "yara_rules_ref": options.yara_rules_ref,
            "clamav_db_version": options.clamav_db_version,
        },
        "artifact_paths": {
            "pcap": PCAP_PATH,
            "trace_etl": TRACE_ETL_PATH,
            "report_json": REPORT_JSON_PATH,
            "report_html": REPORT_HTML_PATH,
            "access_events": ACCESS_EVENTS_PATH,
            "access_events_status": ACCESS_EVENTS_STATUS_PATH,
            **({"clock_sync": CLOCK_SYNC_PATH} if usable_file(package.clock_sync_source) else {}),
        },
        "integrity": {
            "hash_manifest": HASH_MANIFEST_PATH,
            "hash_manifest_sha256": "0" * 64,
            "hash_log_ref": options.hash_log_ref,
        },
    }


def build_analyst_report(
    manifest: dict[str, Any], sample_meta: dict[str, Any]
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": cape_time(None),
        "session_id": manifest["session_id"],
        "validation": {
            "status": manifest["status"],
            "telemetry_degraded": manifest["telemetry"]["telemetry_degraded"],
            "warnings": [
                issue["message"]
                for issue in manifest["telemetry"].get("degradation_reasons", [])
            ],
        },
        "sample": {
            "hashes": {
                "sha256": sample_meta.get("sample_sha256"),
                "sha1": sample_meta.get("sample_sha1"),
                "md5": sample_meta.get("sample_md5"),
            },
            "file_type": sample_meta.get("file_type"),
            "static_risk_score": sample_meta.get("static_risk_score"),
            "static_hypotheses": sample_meta.get("static_hypotheses", []),
        },
        "cape": {
            "task_id": manifest["cape_task_id"],
            "status": manifest["status"],
            "submitted_at_utc": manifest["submitted_at_utc"],
            "detonation_start_utc": manifest["detonation_start_utc"],
            "detonation_end_utc": manifest["detonation_end_utc"],
            "guest_vm_identity": manifest["guest_vm_identity"],
            "capemon_enabled": manifest["capemon_enabled"],
        },
        "telemetry": {
            "etw_provider_state": manifest["telemetry"],
            "telemetry_degradation_warnings": manifest["telemetry"].get(
                "degradation_reasons", []
            ),
        },
        "profile": manifest.get("profile"),
        "resolved_options": manifest.get("resolved_options", {}),
        "capabilities": manifest.get("capabilities", {}),
        "artifact_paths": manifest["artifact_paths"],
        "enrichment": {
            "yara": sample_meta.get("yara", {}),
            "clamav": sample_meta.get("clamav", {}),
            "virustotal": sample_meta.get("vt_lookup", "not_run"),
        },
        "residual_anti_evasion_risks": [
            "Timing/RDTSC side channels require manual anti-evasion validation.",
            "CPUID timing side channels remain a residual risk.",
            "Deep hypervisor introspection cannot be fully hidden by repo-level configuration.",
            "Driver, kernel, and custom-QEMU findings require external engineering decisions.",
        ],
    }


def render_analyst_report_html(report: dict[str, Any]) -> str:
    artifacts = "\n".join(
        f"<li><code>{html.escape(str(name))}</code>: <code>{html.escape(str(path))}</code></li>"
        for name, path in report.get("artifact_paths", {}).items()
    )
    model = html.escape(json.dumps(report, indent=2, sort_keys=False))
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        f"<title>WinST/DT Report {html.escape(str(report['session_id']))}</title>"
        "<style>body{font-family:Arial,sans-serif;margin:32px;line-height:1.45;color:#202124}"
        "code,pre{background:#f4f6f8;border:1px solid #d9dde3;border-radius:4px}"
        "code{padding:1px 4px}pre{padding:16px;overflow:auto}.status{font-weight:700}</style>"
        "</head><body>"
        "<h1>WinST/DT Analyst Report</h1>"
        f"<p>Session <code>{html.escape(str(report['session_id']))}</code> validation status: "
        f"<span class=\"status\">{html.escape(str(report['validation']['status']))}</span></p>"
        f"<h2>Artifacts</h2><ul>{artifacts}</ul>"
        f"<h2>Report Model</h2><pre>{model}</pre>"
        "</body></html>\n"
    )


def build_telemetry(sidecar: dict[str, Any]) -> dict[str, Any]:
    targeted = list_of_text(
        sidecar.get("providers_targeted"), BASELINE_PROVIDERS + OPTIONAL_PROVIDERS
    )
    enabled = list_of_text(sidecar.get("providers_enabled"))
    unavailable = list_of_provider_issues(sidecar.get("providers_unavailable"))
    degradation_reasons = list_of_provider_issues(sidecar.get("degradation_reasons"))

    for issue in unavailable:
        if issue not in degradation_reasons:
            degradation_reasons.append(issue)

    telemetry_degraded = bool(sidecar.get("telemetry_degraded")) or bool(degradation_reasons)
    return {
        "format": "etl",
        "artifact_path": TRACE_ETL_PATH,
        "capture_started": bool(sidecar.get("capture_started", True)),
        "capture_completed": bool(sidecar.get("capture_completed", True)),
        "telemetry_degraded": telemetry_degraded,
        "degradation_reasons": degradation_reasons,
        "providers_targeted": targeted,
        "providers_enabled": enabled,
        "providers_unavailable": unavailable,
        "etw_ti_status": first_text(sidecar.get("etw_ti_status"), "not_attempted"),
    }


def derive_status(results: dict[str, Any], package: PackageInputs, tmp_bundle: Path) -> str:
    if package.errors or not usable_file(tmp_bundle / PCAP_PATH) or not usable_file(tmp_bundle / TRACE_ETL_PATH):
        return "capture_error"
    info = as_dict(results.get("info"))
    status = str(info.get("status", "")).lower()
    if "timeout" in status:
        return "timeout"
    if status in {"failed_analysis", "analysis_error"}:
        return "analysis_error"
    return "completed"


def missing_artifact_errors(tmp_bundle: Path) -> list[dict[str, str]]:
    errors = []
    if not usable_file(tmp_bundle / PCAP_PATH):
        errors.append(capture_error("pcap_unusable", "network/capture.pcapng is missing or empty"))
    if not usable_file(tmp_bundle / TRACE_ETL_PATH):
        errors.append(capture_error("etl_unusable", "behavior/trace.etl is missing or empty"))
    return errors


def copy_if_present(source: Path | None, destination: Path, options: ExportOptions) -> None:
    if not usable_file(source):
        return
    assert source is not None
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination == Path(PCAP_PATH) or destination.name.endswith(".pcapng"):
        copy_pcap(source, destination, options)
    else:
        shutil.copy2(source, destination)


def copy_pcap(source: Path, destination: Path, options: ExportOptions) -> None:
    if source.suffix.lower() == ".pcapng":
        shutil.copy2(source, destination)
        return
    if options.pcap_converter:
        converter = shutil.which(options.pcap_converter)
        if converter:
            subprocess.run([converter, str(source), str(destination)], check=True)
            return
    shutil.copy2(source, destination)


def write_hash_manifest(bundle: Path, status: str) -> None:
    del status
    relative_paths = sorted(
        str(path.relative_to(bundle))
        for path in bundle.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", HASH_MANIFEST_PATH}
    )
    lines = [f"{sha256_file(bundle / relative)}  {relative}" for relative in relative_paths]
    (bundle / HASH_MANIFEST_PATH).write_text("\n".join(lines) + "\n", encoding="utf-8")


def validate_exported_bundle(bundle: Path, options: ExportOptions) -> None:
    command = [options.validator_path, "validate-bundle", str(bundle)]
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    if completed.returncode and options.fail_on_validator_error:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())


def first_existing(paths: list[Path]) -> Path | None:
    for path in paths:
        if path.exists():
            return path
    return None


def usable_file(path: Path | None) -> bool:
    return bool(path and path.is_file() and path.stat().st_size > 0)


def read_first_json(paths: list[Path]) -> dict[str, Any]:
    for path in paths:
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8") as handle:
            loaded = json.load(handle)
        return as_dict(loaded)
    return {}


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def write_text(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8")


def write_events_jsonl(path: Path, manifest: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    event = {
        "schema_version": SCHEMA_VERSION,
        "session_id": manifest["session_id"],
        "timestamp_utc": cape_time(None),
        "source": "cape",
        "event_type": "bundle_summary",
        "raw": {
            "status": manifest["status"],
            "cape_task_id": manifest["cape_task_id"],
            "telemetry_degraded": manifest["telemetry"]["telemetry_degraded"],
            "etl_authoritative": True,
        },
    }
    path.write_text(json.dumps(event, sort_keys=False) + "\n", encoding="utf-8")


def events_jsonl_enabled() -> bool:
    return os.environ.get("WINSTDT_ENABLE_EVENTS_JSONL", "").strip().lower() in {
        "1",
        "yes",
        "true",
        "on",
    }


def maybe_sign_hash_manifest(bundle: Path) -> dict[str, Any] | None:
    adapter = os.environ.get("WINSTDT_SIGNING_ADAPTER", "").strip().lower()
    if not adapter:
        return None
    if adapter == "hsm":
        raise RuntimeError(
            "HSM signing is disabled by default and requires a configured signer adapter"
        )
    if adapter != "local_file":
        raise RuntimeError(f"unsupported signing adapter: {adapter}")
    key_path = os.environ.get("WINSTDT_LOCAL_SIGNING_KEY", "").strip()
    if not key_path:
        raise RuntimeError("local_file signing requires WINSTDT_LOCAL_SIGNING_KEY")
    key = Path(key_path).read_bytes()
    digest = hashlib.sha256()
    digest.update(key)
    digest.update((bundle / HASH_MANIFEST_PATH).read_bytes())
    signature_path = bundle / SIGNATURE_PATH
    signature_path.parent.mkdir(parents=True, exist_ok=True)
    signature_path.write_text(digest.hexdigest() + "\n", encoding="utf-8")
    return {
        "adapter": "local_file",
        "algorithm": "sha256(key || hashes.sha256)",
        "key_id": hashlib.sha256(key).hexdigest()[:16],
        "signature_path": SIGNATURE_PATH,
        "signed_at_utc": cape_time(None),
    }


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def get_task_id(results: dict[str, Any]) -> int:
    info = as_dict(results.get("info"))
    task_id = first_number(info.get("id"), info.get("task_id"), results.get("task_id"), 0)
    if int(task_id) <= 0:
        raise ValueError("CAPE task id is missing")
    return int(task_id)


def capture_error(code: str, message: str) -> dict[str, str]:
    return {"stage": "capture", "code": code, "message": message}


def dedupe_errors(errors: list[dict[str, str]]) -> list[dict[str, str]]:
    seen = set()
    deduped = []
    for error in errors:
        key = (error["stage"], error["code"], error["message"])
        if key not in seen:
            deduped.append(error)
            seen.add(key)
    return deduped


def cape_time(value: Any) -> str:
    if isinstance(value, str) and value.strip():
        text = value.strip()
        if text.endswith("Z"):
            return text
        if "T" in text:
            return text + "Z"
        return text.replace(" ", "T") + "Z"
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def first_text(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def first_number(*values: Any) -> float:
    for value in values:
        if value is None:
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return 0.0


def as_dict(value: Any, default: dict[str, Any] | None = None) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {} if default is None else default


def list_of_text(value: Any, default: list[str] | None = None) -> list[str]:
    if value is None:
        return list(default or [])
    if not isinstance(value, list):
        return list(default or [])
    return [str(item) for item in value if str(item).strip()]


def list_of_rule_names(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    names = []
    for item in value:
        if isinstance(item, dict):
            names.append(first_text(item.get("name"), item.get("rule")))
        else:
            names.append(first_text(item))
    return [name for name in names if name]


def list_of_provider_issues(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    issues = []
    for item in value:
        issue = as_dict(item)
        provider = first_text(issue.get("provider"))
        message = first_text(issue.get("message"), "provider unavailable")
        reason = first_text(issue.get("reason"), "unknown")
        if provider:
            issues.append({"provider": provider, "reason": reason, "message": message})
    return issues


PROFILE_OPTIONS = {
    "standard": {"capa": True, "floss": False, "die": True, "trid": True, "screenshots": True, "suricata": True, "tls_interception": False, "memory_dump": False, "volatility": False},
    "deep_static": {"capa": True, "floss": True, "die": True, "trid": True, "screenshots": False, "suricata": True, "tls_interception": False, "memory_dump": False, "volatility": False},
    "tls_intercept": {"capa": True, "floss": False, "die": True, "trid": True, "screenshots": True, "suricata": True, "tls_interception": True, "memory_dump": False, "volatility": False},
    "full_memory": {"capa": True, "floss": False, "die": True, "trid": True, "screenshots": True, "suricata": True, "tls_interception": False, "memory_dump": True, "volatility": True},
    "full_investigation": {"capa": True, "floss": True, "die": True, "trid": True, "screenshots": True, "suricata": True, "tls_interception": False, "memory_dump": True, "volatility": True},
}


def resolve_profile(results: dict[str, Any], default: str) -> tuple[str, dict[str, Any]]:
    info = as_dict(results.get("info"))
    task_options = as_dict(info.get("options"))
    profile = first_text(task_options.get("winstdt_profile"), info.get("winstdt_profile"), default)
    if profile not in PROFILE_OPTIONS:
        profile = default if default in PROFILE_OPTIONS else "standard"
    resolved = dict(PROFILE_OPTIONS[profile])
    for name in resolved:
        if name in task_options:
            resolved[name] = str(task_options[name]).lower() in {"1", "yes", "true", "on"}
    return profile, resolved


def export_capability_artifacts(results: dict[str, Any], analysis: Path, bundle: Path,
                                profile: str, requested: dict[str, Any]) -> dict[str, Any]:
    del profile
    now = cape_time(None)
    source_hash = first_text(as_dict(as_dict(results.get("target")).get("file")).get("sha256"), "0" * 64)
    aliases = {
        "capa": ["capa", "flare_capa"], "floss": ["floss"], "die": ["die"], "trid": ["trid"],
        "screenshots": ["screenshots"], "suricata": ["suricata"],
        "tls_interception": ["tls_interception", "mitmdump"], "memory_dump": ["memory_dump"],
        "volatility": ["volatility", "volatility3"],
    }
    sections = {"static": {}, "dynamic": {}}
    for name, keys in aliases.items():
        value = next((results[k] for k in keys if k in results), None)
        is_requested = bool(requested.get(name))
        status = "not_requested" if not is_requested else "tool_failure"
        count = 0
        if value is not None:
            count = len(value) if isinstance(value, (list, dict)) else 1
            status = "completed" if count else "completed_zero_matches"
            out = bundle / "analysis" / f"{name}.json"
            out.parent.mkdir(parents=True, exist_ok=True)
            write_json(out, {"tool": name, "source_artifact_sha256": source_hash, "result": value})
        entry = {
            "requested": is_requested, "policy": "profile", "status": status,
            "version": "reported_by_cape" if value is not None else "unknown",
            "revision": "reported_by_cape" if value is not None else "unknown",
            "started_at_utc": now, "ended_at_utc": now,
            "source_artifact": source_hash, "result_count": count,
            "warning_error_code": None if value is not None or not is_requested else "result_absent",
            "truncated": False, "timeout": False,
        }
        sections["static" if name in {"capa", "floss", "die", "trid"} else "dynamic"][name] = entry

    copy_capability_tree(analysis / "shots", bundle / "screenshots", 120, 256 * 1024 * 1024)
    copy_capability_tree(analysis / "suricata", bundle / "network/suricata", 10000, 512 * 1024 * 1024)
    copy_capability_tree(analysis / "tls", bundle / "network/tls", 1000, 256 * 1024 * 1024)
    copy_capability_tree(analysis / "volatility", bundle / "memory/volatility", 1000, 512 * 1024 * 1024)
    screenshots = sorted(p for p in (bundle / "screenshots").glob("*") if p.is_file()) if (bundle / "screenshots").is_dir() else []
    if screenshots:
        index = {"capture_method": "qemu", "images": [
            {"path": p.name, "timestamp_utc": datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).isoformat().replace("+00:00", "Z"),
             "sha256": sha256_file(p), "dimensions": None, "deduplicated": False} for p in screenshots
        ]}
        write_json(bundle / "screenshots/index.json", index)
        sections["dynamic"]["screenshots"].update(status="completed", result_count=len(screenshots), warning_error_code=None)
    eve = bundle / "network/suricata/eve.json"
    if usable_file(eve):
        sections["dynamic"]["suricata"].update(status="completed", result_count=sum(1 for _ in eve.open(encoding="utf-8", errors="replace")), warning_error_code=None)
    har = bundle / "network/tls/traffic.har"
    if usable_file(har):
        sections["dynamic"]["tls_interception"].update(status="intercepted", result_count=1, warning_error_code=None)
    volatility_files = list((bundle / "memory/volatility").glob("*.json")) if (bundle / "memory/volatility").is_dir() else []
    if volatility_files:
        sections["dynamic"]["volatility"].update(status="completed", result_count=len(volatility_files), warning_error_code=None)
    memory = first_existing([analysis / "memory.raw", analysis / "memory.dmp"])
    if usable_file(memory) and requested.get("memory_dump"):
        destination = bundle / "memory/memory.raw"
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(memory, destination)
        memory_status = "captured_and_processed" if volatility_files else "captured_processing_failed"
        sections["dynamic"]["memory_dump"].update(status=memory_status, result_count=1,
                                                    warning_error_code=None if volatility_files else "volatility_output_absent")
    return sections


def copy_capability_tree(source: Path, destination: Path, max_files: int, max_bytes: int) -> None:
    if not source.is_dir():
        return
    total = 0
    for index, path in enumerate(sorted(p for p in source.rglob("*") if p.is_file())):
        if index >= max_files or total + path.stat().st_size > max_bytes:
            break
        target = destination / path.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        total += path.stat().st_size


ACCESS_API_TYPES = {
    "CryptUnprotectData": "browser_credentials", "BCryptDecrypt": "browser_credentials",
    "SetWindowsHookExA": "keystrokes", "SetWindowsHookExW": "keystrokes", "GetAsyncKeyState": "keystrokes",
    "BitBlt": "screenshot", "CreateCompatibleBitmap": "screenshot",
    "GetClipboardData": "clipboard", "OpenClipboard": "clipboard",
    "GetComputerNameExA": "system_info", "GetComputerNameExW": "system_info",
    "GetUserNameA": "system_info", "GetUserNameW": "system_info",
    "ReadFile": "file_access", "CreateFileA": "file_access", "CreateFileW": "file_access",
}


def write_access_events(path: Path, status_path: Path, results: dict[str, Any],
                        clock_path: Path | None, analysis_path: Path) -> dict[str, Any]:
    clock = read_first_json([clock_path] if clock_path else [])
    info = as_dict(results.get("info"))
    etw = read_first_json([
        analysis_path / "behavior/etw-events.json",
        analysis_path / "winstdt/etw-events.json",
    ])
    etw_events = etw.get("events") if isinstance(etw.get("events"), list) else None
    status = write_access_event_artifacts(
        path, status_path, results, clock, info.get("started"), info.get("ended"), etw_events
    )
    return {
        "access_events_path": ACCESS_EVENTS_PATH,
        "access_events_status_path": ACCESS_EVENTS_STATUS_PATH,
        "event_count": status["event_count"],
        "source": status["source"],
        "etw_corroboration_state": status["etw_corroboration_state"],
        "clock_algorithm": status["clock_algorithm"],
        "maximum_uncertainty_ns": status["maximum_uncertainty_ns"],
        "host_network_correlation_enabled": status["correlation_eligible"],
        "reason_code": status["reason_code"],
    }


def corrected_timestamp(value: Any, guest_minus_host_ns: int) -> str | None:
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)):
            guest = datetime.fromtimestamp(float(value), timezone.utc)
        else:
            guest = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if guest.tzinfo is None:
                guest = guest.replace(tzinfo=timezone.utc)
        host = guest.timestamp() - guest_minus_host_ns / 1_000_000_000
        return datetime.fromtimestamp(host, timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, TypeError, OSError):
        return None
