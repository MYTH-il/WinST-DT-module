#!/usr/bin/env python3
"""Validate a run approval and render the gateway's fail-closed nftables policy."""

import argparse
import hashlib
import ipaddress
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path


RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
BLOCKED_DESTINATION_NETWORKS = (
    ipaddress.ip_network("10.66.0.0/24"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
)
CONTROLLED_RESPONDER = ipaddress.ip_address("192.168.125.10")
CONTROLLED_PORTS = {8080, 8443}


def load_config(path: Path) -> dict:
    config = json.loads(path.read_text(encoding="utf-8"))
    required = {
        "run_id", "internal_interface", "external_interface", "guest_ip",
        "destinations", "expires_at_utc", "max_connections", "max_bytes",
        "approval",
    }
    missing = sorted(required - config.keys())
    if missing:
        raise SystemExit(f"missing required fields: {', '.join(missing)}")
    if not RUN_ID.fullmatch(str(config["run_id"])):
        raise SystemExit("run_id contains unsafe characters")
    approval = config["approval"]
    for field in ("approval_id", "signer_identity", "policy_sha256", "signature_path"):
        if not isinstance(approval, dict) or not approval.get(field):
            raise SystemExit(f"approval.{field} is required")
    expiry = datetime.fromisoformat(config["expires_at_utc"].replace("Z", "+00:00"))
    if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
        raise SystemExit("configuration is expired or lacks a timezone")
    if (expiry - datetime.now(timezone.utc)).total_seconds() > 86400:
        raise SystemExit("expiry may not be more than 24 hours in the future")
    config["_expires_epoch"] = int(expiry.timestamp())
    config["guest_ip"] = str(ipaddress.ip_address(config["guest_ip"]))
    if ipaddress.ip_address(config["guest_ip"]).version != 4:
        raise SystemExit("the initial gateway milestone supports IPv4 only")
    for name in ("internal_interface", "external_interface"):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", str(config[name])):
            raise SystemExit(f"invalid {name}")
    if config["internal_interface"] == config["external_interface"]:
        raise SystemExit("gateway interfaces must be different")
    config["max_connections"] = int(config["max_connections"])
    config["max_bytes"] = int(config["max_bytes"])
    if not 1 <= config["max_connections"] <= 1000:
        raise SystemExit("max_connections must be between 1 and 1000 per minute")
    if not 1024 <= config["max_bytes"] <= 1_073_741_824:
        raise SystemExit("max_bytes must be between 1 KiB and 1 GiB")
    if not config["destinations"]:
        raise SystemExit("at least one literal destination is required")
    for destination in config["destinations"]:
        destination["ip"] = str(ipaddress.ip_address(destination["ip"]))
        destination_ip = ipaddress.ip_address(destination["ip"])
        if destination_ip.version != 4:
            raise SystemExit("the initial gateway milestone supports IPv4 only")
        if destination_ip.is_unspecified or any(
            destination_ip in network for network in BLOCKED_DESTINATION_NETWORKS
        ):
            raise SystemExit(f"destination is in a protected network: {destination_ip}")
        if destination_ip != CONTROLLED_RESPONDER:
            raise SystemExit("public or non-responder destinations are unsupported")
        if destination["protocol"] not in ("tcp", "udp"):
            raise SystemExit("protocol must be tcp or udp")
        destination["port"] = int(destination["port"])
        if not 1 <= destination["port"] <= 65535:
            raise SystemExit("invalid destination port")
        if destination["protocol"] != "tcp" or destination["port"] not in CONTROLLED_PORTS:
            raise SystemExit("only controlled responder HTTP/HTTPS ports are permitted")
    dns = config.get("dns")
    if dns:
        if not re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9.-]+", str(dns["name"])):
            raise SystemExit("invalid pinned DNS name")
        dns["pinned_ip"] = str(ipaddress.ip_address(dns["pinned_ip"]))
        if dns["pinned_ip"] not in {d["ip"] for d in config["destinations"]}:
            raise SystemExit("pinned DNS IP must also be an allowed destination")
        if dns["name"].lower().rstrip(".") != "validation.winstdt.test":
            raise SystemExit("only the controlled validation hostname may be pinned")
    return config


def canonical_policy(config: dict) -> bytes:
    policy = {key: value for key, value in config.items()
              if key != "approval" and not key.startswith("_")}
    envelope = {"approval_id": config["approval"]["approval_id"], "policy": policy}
    return (json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n").encode()


def verify_approval(config: dict, config_path: Path, allowed_signers: Path) -> None:
    payload = canonical_policy(config)
    policy = json.dumps({key: value for key, value in config.items()
                         if key != "approval" and not key.startswith("_")},
                        sort_keys=True, separators=(",", ":")).encode()
    actual_hash = hashlib.sha256(policy).hexdigest()
    if actual_hash != config["approval"]["policy_sha256"]:
        raise SystemExit("approval policy hash does not match canonical policy")
    signature = Path(config["approval"]["signature_path"])
    if not signature.is_absolute():
        signature = config_path.parent / signature
    completed = subprocess.run(
        ["ssh-keygen", "-Y", "verify", "-f", str(allowed_signers),
         "-I", config["approval"]["signer_identity"], "-n", "winstdt-egress",
         "-s", str(signature)], input=payload, capture_output=True,
    )
    if completed.returncode:
        raise SystemExit("gateway approval signature verification failed")


def render(config: dict) -> str:
    internal = config["internal_interface"]
    external = config["external_interface"]
    guest = config["guest_ip"]
    lines = [
        "flush ruleset",
        "table inet winstdt_run {",
        " chain input { type filter hook input priority 0; policy drop;",
        '  iifname "lo" accept',
        "  ct state established,related accept",
        f'  iifname "{internal}" ip saddr 10.66.0.1 tcp dport 22 accept',
        f'  iifname "{internal}" ip protocol icmp accept',
        f'  iifname "{external}" udp sport 67 udp dport 68 accept',
    ]
    if config.get("dns"):
        lines.extend([
            f'  iifname "{internal}" ip saddr {guest} udp dport 53 accept',
            f'  iifname "{internal}" ip saddr {guest} tcp dport 53 accept',
        ])
    lines.extend([
        " }",
        " chain forward { type filter hook forward priority 0; policy drop;",
        f'  iifname "{internal}" oifname "{external}" ip saddr {guest} ct state established,related counter accept',
        f'  iifname "{external}" oifname "{internal}" ip daddr {guest} ct state established,related counter accept',
    ])
    for index, destination in enumerate(config["destinations"], start=1):
        proto = destination["protocol"]
        match = (
            f'iifname "{internal}" oifname "{external}" ip saddr {guest} '
            f'ip daddr {destination["ip"]} {proto} dport {destination["port"]}'
        )
        lines.extend([
            f"  {match} quota name run_quota_{index} over counter drop",
            f"  {match} ct state new limit rate {config['max_connections']}/minute counter accept",
        ])
    lines.extend([
        " }",
        " chain postrouting { type nat hook postrouting priority srcnat; policy accept;",
        f'  iifname "{internal}" oifname "{external}" ip saddr {guest} counter masquerade',
        " }",
    ])
    for index in range(1, len(config["destinations"]) + 1):
        lines.append(f" quota run_quota_{index} {{ over {config['max_bytes']} bytes }}")
    lines.extend(["}", ""])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--metadata-output", type=Path)
    parser.add_argument("--allowed-signers", type=Path,
                        default=Path("/srv/winstdt/gateway/approval_allowed_signers"))
    args = parser.parse_args()
    config = load_config(args.config)
    verify_approval(config, args.config, args.allowed_signers)
    rules = render(config)
    if args.output:
        args.output.write_text(rules, encoding="utf-8")
    else:
        print(rules, end="")
    if args.metadata_output:
        metadata = {key: value for key, value in config.items() if not key.startswith("_")}
        metadata["approval_id"] = config["approval"]["approval_id"]
        metadata["expires_epoch"] = config["_expires_epoch"]
        metadata["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
        args.metadata_output.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
