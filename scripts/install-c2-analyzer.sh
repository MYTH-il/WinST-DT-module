#!/usr/bin/env bash
set -euo pipefail
EXECUTE=0
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; WINSTDT_ROOT="${WINSTDT_ROOT:-/srv/winstdt}"
while [ "$#" -gt 0 ]; do case "$1" in --execute) EXECUTE=1;; -h|--help) echo 'Usage: scripts/install-c2-analyzer.sh [--execute]'; exit 0;; *) exit 2;; esac; shift; done
commit="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["commit"])' "$PROJECT_ROOT/config/c2-exfil.lock.json")"
actual="$(git -C "$PROJECT_ROOT" log --all --format=%B --grep='git-subtree-dir: integrations/c2-exfil' -n 1 | sed -n 's/^git-subtree-split: //p')"
[ "$actual" = "$commit" ] || { echo "C2 subtree mismatch: expected=$commit actual=${actual:-unknown}" >&2; exit 1; }
echo "+ python3 -m venv $WINSTDT_ROOT/venvs/c2-exfil"
echo "+ pip install -r config/c2-exfil-requirements.lock.txt"
[ "$EXECUTE" -eq 1 ] || { echo 'dry-run complete'; exit 0; }
sudo install -d -m 0755 "$WINSTDT_ROOT/venvs" "$WINSTDT_ROOT/c2-results"
sudo python3 -m venv "$WINSTDT_ROOT/venvs/c2-exfil"
sudo "$WINSTDT_ROOT/venvs/c2-exfil/bin/pip" install --disable-pip-version-check -r "$PROJECT_ROOT/config/c2-exfil-requirements.lock.txt"
sudo install -d -m 0750 "$WINSTDT_ROOT/integrations/c2-exfil" "$WINSTDT_ROOT/libexec/c2-exfil"
sudo rsync -a --delete "$PROJECT_ROOT/integrations/c2-exfil/" "$WINSTDT_ROOT/integrations/c2-exfil/"
sudo install -m 0750 "$PROJECT_ROOT/scripts/generate-static-prior.py" "$WINSTDT_ROOT/libexec/c2-exfil/generate-static-prior.py"
sudo install -m 0750 "$PROJECT_ROOT/scripts/run-c2-analyzer.sh" "$WINSTDT_ROOT/libexec/c2-exfil/run-c2-analyzer.sh"
sudo install -m 0640 "$PROJECT_ROOT/config/c2-exfil.lock.json" "$WINSTDT_ROOT/integrations/c2-exfil/winstdt.lock.json"
sudo chown -R "${CAPE_USER:-cape}:${CAPE_USER:-cape}" "$WINSTDT_ROOT/venvs/c2-exfil" "$WINSTDT_ROOT/c2-results" "$WINSTDT_ROOT/integrations/c2-exfil" "$WINSTDT_ROOT/libexec/c2-exfil"
