#!/usr/bin/env python3
"""Draft a golden-image report from retrieved anti-evasion evidence.

This helper intentionally does not auto-pass or auto-fail the strict subset
gate. al-khaser and Pafish output formats vary by build, and the MVP gate is a
scoped engineering decision. The script pre-fills metadata, evidence paths, and
tool hashes so the reviewer can map raw findings into the required categories.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED_CATEGORIES = [
    "SMBIOS/DMI vendor/product/serial checks",
    "BIOS/firmware strings where configurable",
    "Obvious QEMU/KVM/VMware/VirtualBox registry artifacts",
    "Hostname/username/workgroup blacklist checks",
    "Obvious sandbox/security-tool process/service-name checks",
    "Default QEMU disk/CD-ROM/device strings where configurable",
    "CPU count",
    "RAM size",
    "Disk size/free space",
    "Recent files not empty",
    "Browser profile not empty",
    "Normal installed software present",
    "Downloads/TEMP profile patterns not pristine",
    "Boot warm-up and human-interaction evidence",
]

NON_BLOCKING_CATEGORIES = [
    "RDTSC/timing checks",
    "CPUID timing side channels",
    "Debugger checks",
    "Deep hypervisor introspection",
    "Requires driver modification/re-signing",
    "Requires custom QEMU build",
    "Requires kernel-level patching",
    "Malware-specific bypass-code category",
]


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def first_existing(root: Path, name: str) -> Path | None:
    matches = sorted(root.rglob(name))
    return matches[0] if matches else None


def field(value: Any, default: str = "Pending review") -> str:
    if value is None:
        return default
    if isinstance(value, (str, int, float)):
        return str(value)
    if isinstance(value, list):
        return ", ".join(field(item, "") for item in value)
    if isinstance(value, dict):
        return ", ".join(f"{key}={field(item, '')}" for key, item in value.items())
    return str(value)


def nested(value: dict[str, Any], *keys: str) -> Any:
    current: Any = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def tool_summary(root: Path, name: str) -> tuple[str, str, str]:
    result_path = first_existing(root, f"{name}.result.json")
    if not result_path:
        return "Pending review", "pending", "pending"
    result = read_json(result_path)
    sha256 = field(result.get("sha256"), "unknown")
    completed = field(result.get("completed"), "unknown")
    exit_code = field(result.get("exit_code"), "unknown")
    return f"sha256={sha256}; completed={completed}; exit_code={exit_code}", sha256, str(result_path)


def rel(path: Path | None) -> str:
    return str(path) if path else "pending"


def render(args: argparse.Namespace) -> str:
    evidence_root = args.evidence_root
    system_path = first_existing(evidence_root, "system-context.json")
    summary_path = first_existing(evidence_root, "summary.json")
    system = read_json(system_path) if system_path else {}
    summary = read_json(summary_path) if summary_path else {}

    al_summary, _, al_result = tool_summary(evidence_root, "al-khaser")
    pafish_summary, _, pafish_result = tool_summary(evidence_root, "pafish")

    os_info = nested(system, "windows_version") or {}
    computer = nested(system, "computer_system") or {}
    bios = nested(system, "bios") or {}
    disks = nested(system, "disks") or []

    cpu_ram_disk = (
        f"{field(computer.get('NumberOfLogicalProcessors'))} logical CPUs; "
        f"{field(computer.get('TotalPhysicalMemory'))} bytes RAM; "
        f"disks={field(disks)}"
    )

    lines: list[str] = [
        "# Golden Image Anti-Evasion Validation Report",
        "",
        "## Run Metadata",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Report ID | anti-evasion-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')} |",
        f"| Validation date | {datetime.now(timezone.utc).date().isoformat()} |",
        "| Validator | WinST/DT anti-evasion evidence collector plus manual strict-subset review |",
        f"| Golden image build ID | {args.image_id} |",
        f"| Golden image path/snapshot | {args.snapshot} |",
        f"| CAPEv2 git ref | {args.cape_git_ref} |",
        f"| CAPEv2 `kvm-qemu.sh` used | {args.kvm_qemu_used} |",
        f"| VMCloak build date | {args.vmcloak_build_date} |",
        f"| Post-hardening script/ref | {args.hardening_ref} |",
        f"| Windows edition/version/build | {field(os_info)} |",
        f"| CPU/RAM/disk configuration | {cpu_ram_disk} |",
        f"| al-khaser version/ref | {al_summary} |",
        f"| Pafish version/ref | {pafish_summary} |",
        "",
        "## Detonation Sanity Check",
        "",
        "| Check | Result | Evidence/notes |",
        "|---|---|---|",
        f"| CAPEv2 stock benign detonation completed | Pass | {args.benign_task_note} |",
        f"| Guest booted from hardened snapshot | Pass | {args.snapshot} |",
        "| CAPE agent reachable | Pass | CAPE agent was used to stage and retrieve validation evidence |",
        f"| Result retrieval completed | Pass | {evidence_root} |",
        "",
        "## Required Gate Results",
        "",
        "Use `Pass`, `Fail`, or `N/A` after reviewing the raw tool output. Any `Fail` in this table rejects the golden image for MVP use.",
        "",
        "| Category | al-khaser | Pafish | Evidence/notes |",
        "|---|---|---|---|",
    ]

    for category in REQUIRED_CATEGORIES:
        lines.append(f"| {category} | Pending review | Pending review | Review raw outputs under `{evidence_root}` |")

    lines.extend(
        [
            "",
            "## Non-Blocking Findings",
            "",
            "These findings do not block MVP acceptance, but every observed failure must be recorded.",
            "",
            "| Category | al-khaser | Pafish | Residual-risk note |",
            "|---|---|---|---|",
        ]
    )
    for category in NON_BLOCKING_CATEGORIES:
        lines.append(f"| {category} | Pending review | Pending review | Record observed failures from `{evidence_root}` |")

    lines.extend(
        [
            "",
            "## Decision",
            "",
            "| Field | Value |",
            "|---|---|",
            "| MVP gate decision | Rejected pending evidence review |",
            "| Rejection reason, if any | Strict-subset category mapping has not been completed |",
            "| Required follow-up before use | Review al-khaser/Pafish output, fill every required category, then accept only if no required category fails |",
            "| Residual risk accepted by | Pending |",
            "",
            "## Attachments",
            "",
            f"- Evidence summary: `{rel(summary_path)}`",
            f"- System context: `{rel(system_path)}`",
            f"- al-khaser result: `{al_result}`",
            f"- al-khaser stdout: `{rel(first_existing(evidence_root, 'al-khaser.stdout.txt'))}`",
            f"- al-khaser stderr: `{rel(first_existing(evidence_root, 'al-khaser.stderr.txt'))}`",
            f"- Pafish result: `{pafish_result}`",
            f"- Pafish stdout: `{rel(first_existing(evidence_root, 'pafish.stdout.txt'))}`",
            f"- Pafish stderr: `{rel(first_existing(evidence_root, 'pafish.stderr.txt'))}`",
            f"- CAPEv2 benign detonation task/report: `{args.benign_task_report}`",
            f"- WinST/DT handoff bundle: `{args.handoff_bundle}`",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence_root", type=Path)
    parser.add_argument("--output", type=Path, default=Path("docs/validation/golden_image_report_current.md"))
    parser.add_argument("--image-id", default="winstdt-win10-22h2")
    parser.add_argument("--snapshot", default="hardened-baseline-antievasion-v1")
    parser.add_argument("--cape-git-ref", default="unknown")
    parser.add_argument("--kvm-qemu-used", default="CAPE KVM machinery active")
    parser.add_argument("--vmcloak-build-date", default="Pending")
    parser.add_argument("--hardening-ref", default="scripts/guest_hardening/Invoke-GuestHardening.ps1")
    parser.add_argument("--benign-task-note", default="CAPE task 11 completed and exported a valid WinST/DT bundle")
    parser.add_argument("--benign-task-report", default="/opt/CAPEv2/storage/analyses/11/reports/report.json")
    parser.add_argument("--handoff-bundle", default="/srv/winstdt/handoff/11")
    args = parser.parse_args()

    if not args.evidence_root.is_dir():
        raise SystemExit(f"evidence directory not found: {args.evidence_root}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render(args), encoding="utf-8")
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
