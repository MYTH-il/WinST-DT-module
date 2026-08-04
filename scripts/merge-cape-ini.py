#!/usr/bin/env python3
"""Merge complete INI sections while keeping timestamped backups outside CAPE."""
import argparse, configparser, shutil
from datetime import datetime, timezone
from pathlib import Path
p=argparse.ArgumentParser(); p.add_argument("target",type=Path); p.add_argument("overlay",type=Path); p.add_argument("--backup-root",type=Path,required=True)
a=p.parse_args()
if not a.target.is_file(): raise SystemExit(f"missing CAPE config: {a.target}")
stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
backup=a.backup_root/stamp/a.target.name; backup.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(a.target,backup)
base=configparser.ConfigParser(interpolation=None,strict=False); base.optionxform=str
over=configparser.ConfigParser(interpolation=None,strict=False); over.optionxform=str
base.read(a.target); over.read(a.overlay)
for section in over.sections():
    if not base.has_section(section): base.add_section(section)
    for key,value in over.items(section): base.set(section,key,value)
with a.target.open("w",encoding="utf-8") as f: base.write(f,space_around_delimiters=True)
