#!/usr/bin/env python3
"""Generate/apply a per-run default-deny nftables ruleset on the gateway VM."""
import argparse, ipaddress, json, subprocess
from datetime import datetime, timezone
from pathlib import Path
p=argparse.ArgumentParser(); p.add_argument("config",type=Path); p.add_argument("--execute",action="store_true"); p.add_argument("--output",type=Path)
a=p.parse_args(); c=json.loads(a.config.read_text())
expiry=datetime.fromisoformat(c["expires_at_utc"].replace("Z","+00:00"))
if expiry <= datetime.now(timezone.utc): raise SystemExit("configuration is expired")
if not c.get("approval_id") or c["approval_id"] == "REQUIRED": raise SystemExit("approval_id is required")
guest=str(ipaddress.ip_address(c["guest_ip"])); rules=[]
for d in c["destinations"]:
    ip=str(ipaddress.ip_address(d["ip"])); proto=d["protocol"]
    if proto not in ("tcp","udp"): raise SystemExit("protocol must be tcp or udp")
    port=int(d["port"])
    if not 1 <= port <= 65535: raise SystemExit("invalid port")
    match=f'ip saddr {guest} ip daddr {ip} {proto} dport {port}'
    rules.append(f'{match} counter quota over {int(c["max_bytes"])} bytes drop')
    rules.append(f'{match} ct state new limit rate {int(c["max_connections"])}/minute accept')
text='''flush table inet winstdt\ntable inet winstdt {\n chain forward { type filter hook forward priority 0; policy drop;\n  ct state established,related accept\n  iifname "lo" accept\n'''+''.join('  '+r+'\n' for r in rules)+''' }\n}\n'''
if a.output: a.output.write_text(text)
else: print(text,end='')
if a.execute: subprocess.run(["nft","-f",str(a.output)] if a.output else ["nft","-f","-"],input=None if a.output else text,text=True,check=True)
