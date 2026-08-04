#!/usr/bin/env python3
"""Generate the authorized analyzer's static-prior contract from a handoff."""
import argparse, ipaddress, json, re
from pathlib import Path
from urllib.parse import urlparse

p=argparse.ArgumentParser(); p.add_argument("bundle",type=Path); p.add_argument("output",type=Path); a=p.parse_args()
meta=json.loads((a.bundle/"sample.meta.json").read_text()); values=[]; capabilities=[]
for path in (a.bundle/"analysis").glob("*.json") if (a.bundle/"analysis").is_dir() else []:
    data=json.loads(path.read_text())
    def walk(v,key=""):
        if isinstance(v,dict):
            for k,x in v.items(): walk(x,str(k).lower())
        elif isinstance(v,list):
            for x in v: walk(x,key)
        elif isinstance(v,str):
            if re.fullmatch(r"T\d{4}(?:\.\d{3})?",v): capabilities.append(v)
            if any(x in key for x in ("ioc","url","domain","host","ip","email")): values.append(v.strip())
    walk(data)
ind=[]
for value in values:
    kind=None
    try: ipaddress.ip_address(value); kind="ip"
    except ValueError:
        if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",value): kind="email"
        elif urlparse(value).scheme in ("http","https","ftp"): kind="url"
        elif re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}",value): kind="domain"
    if kind: ind.append({"type":kind,"value":value})
dedup={(x["type"],x["value"].lower()):x for x in ind}
out={"sample_sha256":meta.get("sample_sha256"),"family":None,"capabilities":sorted(set(capabilities)),"c2_indicators":list(dedup.values())}
a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(out,indent=2)+"\n")
