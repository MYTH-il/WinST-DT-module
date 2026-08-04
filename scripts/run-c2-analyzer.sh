#!/usr/bin/env bash
set -euo pipefail
BUNDLE="${1:?Usage: scripts/run-c2-analyzer.sh /path/to/handoff/task_id}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; WINSTDT_ROOT="${WINSTDT_ROOT:-/srv/winstdt}"
ANALYZER_ROOT="${C2_ANALYZER_ROOT:-$WINSTDT_ROOT/integrations/c2-exfil}"
LIBEXEC_ROOT="${WINSTDT_C2_LIBEXEC:-$WINSTDT_ROOT/libexec/c2-exfil}"
task_id="$(basename "$BUNDLE")"; [[ "$task_id" =~ ^[0-9]+$ ]] || { echo 'bundle basename must be a numeric task id' >&2; exit 2; }
validator="${WINSTDT_VALIDATOR:-$WINSTDT_ROOT/bin/winstdt}"; "$validator" validate-bundle "$BUNDLE"
pcap="$BUNDLE/network/capture.pcapng"; test -s "$pcap" || { echo 'non-empty original PCAP required' >&2; exit 1; }
final="$WINSTDT_ROOT/c2-results/$task_id"; test ! -e "$final" || { echo "derived result already exists: $final" >&2; exit 1; }
stage="$(mktemp -d "$WINSTDT_ROOT/c2-results/.${task_id}.XXXXXX")"; trap 'test ! -d "$stage" || mv "$stage" "$stage.failed"' EXIT
mkdir -p "$stage/inputs" "$stage/data"; cp "$pcap" "$stage/inputs/capture.pcapng"
access="$BUNDLE/behavior/access_events.json"; correlation=false; analyzer_access="inputs/access_events.disabled.json"
if test -s "$access" && python3 -c 'import json,sys; raise SystemExit(0 if json.load(open(sys.argv[1])) else 1)' "$access"; then cp "$access" "$stage/inputs/access_events.json"; correlation=true; analyzer_access="inputs/access_events.json"; else printf '[]\n' >"$stage/inputs/access_events.json"; fi
test -f "$ANALYZER_ROOT/pipeline/orchestrator.py" || { echo "deployed analyzer missing: $ANALYZER_ROOT" >&2; exit 1; }
python3 "$LIBEXEC_ROOT/generate-static-prior.py" "$BUNDLE" "$stage/inputs/static-prior.json"
(cd "$stage" && "$WINSTDT_ROOT/venvs/c2-exfil/bin/python" "$ANALYZER_ROOT/pipeline/orchestrator.py" inputs/capture.pcapng "$analyzer_access" --static-prior inputs/static-prior.json) >"$stage/analyzer.log" 2>&1
upstream="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["commit"])' "$ANALYZER_ROOT/winstdt.lock.json")"
STAGE="$stage" TASK="$task_id" UPSTREAM="$upstream" CORRELATION="$correlation" python3 - <<'PY'
import hashlib,json,os
from datetime import datetime,timezone
from pathlib import Path
s=Path(os.environ['STAGE']); hashes={}
for p in sorted(x for x in s.rglob('*') if x.is_file()): hashes[str(p.relative_to(s))]=hashlib.sha256(p.read_bytes()).hexdigest()
(s/'provenance.json').write_text(json.dumps({'schema_version':'1.0','task_id':int(os.environ['TASK']),'upstream_commit':os.environ['UPSTREAM'],'generated_at_utc':datetime.now(timezone.utc).isoformat().replace('+00:00','Z'),'host_network_correlation_enabled':os.environ['CORRELATION']=='true','fixture_events_used':False,'hashes':hashes},indent=2)+'\n')
PY
mv "$stage" "$final"; trap - EXIT; echo "$final"
