#!/usr/bin/env python3
import argparse, hashlib, importlib.metadata, json, subprocess
from datetime import datetime, timezone
from pathlib import Path

p=argparse.ArgumentParser(); p.add_argument("lock",type=Path); p.add_argument("output",type=Path); p.add_argument("--cape-dir",type=Path,default=Path("/opt/CAPEv2")); p.add_argument("--suricata-rules",type=Path,required=True)
a=p.parse_args(); lock=json.loads(a.lock.read_text())
def digest(path):
 h=hashlib.sha256()
 with path.open("rb") as f:
  for chunk in iter(lambda:f.read(1024*1024),b""): h.update(chunk)
 return h.hexdigest()
rules=a.suricata_rules
enabled=sum(1 for line in rules.open(encoding="utf-8",errors="ignore") if line.lstrip().startswith(("alert ","drop ","reject ")))
metadata={"schema_version":"1.0","generated_at_utc":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),"cape_commit":lock["cape"]["commit"],"tools":{"flare_capa":lock["tools"]["flare_capa"],"floss":lock["tools"]["floss"],"volatility3":lock["tools"]["volatility3"],"suricata":{"version":subprocess.check_output(["suricata","--build-info"],text=True).splitlines()[0]}},"external_data":lock["external_data"],"suricata":{"rules_path":str(rules),"rules_sha256":digest(rules),"enabled_rule_count":enabled,"mode":"passive_offline_pcap"}}
a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(metadata,indent=2)+"\n")
