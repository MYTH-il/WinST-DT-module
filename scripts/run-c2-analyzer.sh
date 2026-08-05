#!/usr/bin/env bash
set -euo pipefail

BUNDLE="${1:?Usage: scripts/run-c2-analyzer.sh /path/to/handoff/task_id}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WINSTDT_ROOT="${WINSTDT_ROOT:-/srv/winstdt}"
RUNTIME="${C2_ANALYZER_RUNTIME:-$WINSTDT_ROOT/libexec/c2-exfil/current}"
ANALYZER_ROOT="$RUNTIME/source"
PYTHON="$RUNTIME/.venv/bin/python"
RESULT_ROOT="$WINSTDT_ROOT/c2-results"
task_id="$(basename "$BUNDLE")"
[[ "$task_id" =~ ^[0-9]+$ ]] || { echo 'bundle basename must be a numeric task id' >&2; exit 2; }
validator="${WINSTDT_VALIDATOR:-$WINSTDT_ROOT/bin/winstdt}"
"$validator" validate-bundle "$BUNDLE"
pcap="$BUNDLE/network/capture.pcapng"
test -s "$pcap" || { echo 'non-empty original PCAP required' >&2; exit 1; }
test -x "$PYTHON" && test -f "$ANALYZER_ROOT/pipeline/orchestrator.py" || {
  echo "versioned C2 runtime is unavailable: $RUNTIME" >&2; exit 1;
}
final="$RESULT_ROOT/$task_id"
test ! -e "$final" || { echo "immutable derived result already exists: $final" >&2; exit 1; }
mkdir -p "$RESULT_ROOT"
staging_parent="$(mktemp -d "$RESULT_ROOT/.${task_id}.staging.XXXXXX")"
stage="$staging_parent/$task_id"
mkdir -p "$stage/inputs" "$stage/output/iocs" "$stage/zeek" "$stage/data"
failed="$RESULT_ROOT/.${task_id}.failed.$(date -u +%Y%m%dT%H%M%SZ)"
cleanup() { test ! -d "$staging_parent" || mv "$staging_parent" "$failed"; }
trap cleanup EXIT
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cp "$pcap" "$stage/inputs/capture.pcapng"
cp "$BUNDLE/sample.meta.json" "$stage/inputs/sample.meta.json"
python3 - "$BUNDLE" >"$stage/inputs/handoff-hashes.before.json" <<'PY'
import hashlib,json,sys
from pathlib import Path
root=Path(sys.argv[1]); print(json.dumps({str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob('*')) if p.is_file()},sort_keys=True))
PY
sample_sha256="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sample_sha256"])' "$BUNDLE/sample.meta.json")"
pcap_sha256="$(sha256sum "$pcap" | awk '{print $1}')"
access="$BUNDLE/behavior/access_events.json"
access_status="$BUNDLE/behavior/access_events.status.json"
correlation="network_only"
access_args=(--access-events-source disabled)
if test -s "$access" && test -s "$access_status" && python3 - "$access" "$access_status" <<'PY'
import json,sys
events=json.load(open(sys.argv[1])); status=json.load(open(sys.argv[2]))
raise SystemExit(0 if events and status.get('correlation_eligible') and status.get('source')=='cape_capemon' else 1)
PY
then
  cp "$access" "$stage/inputs/access_events.json"
  cp "$access_status" "$stage/inputs/access_events.status.json"
  correlation="host_network"
  access_args=(--access-events inputs/access_events.json --access-events-source real)
fi
python3 "$PROJECT_ROOT/scripts/generate-static-prior.py" "$BUNDLE" "$stage/inputs/static-prior.json"
suricata_args=(); tls_args=()
test ! -s "$BUNDLE/network/suricata/eve.json" || suricata_args=(--suricata "$BUNDLE/network/suricata/eve.json")
test ! -s "$BUNDLE/network/tls/records.json" || tls_args=(--tls "$BUNDLE/network/tls/records.json")
python3 "$PROJECT_ROOT/scripts/normalize-c2-adapter-inputs.py" "${suricata_args[@]}" "${tls_args[@]}" --output "$stage/inputs"
(cd "$stage" && "$PYTHON" "$ANALYZER_ROOT/pipeline/orchestrator.py" inputs/capture.pcapng \
  --analysis-id "$task_id" --sample-sha256 "$sample_sha256" --pcap-sha256 "$pcap_sha256" \
  "${access_args[@]}" --static-prior inputs/static-prior.json) >"$stage/analyzer.log" 2>&1
if [ "${WINSTDT_POSTGRES_ENABLED:-0}" = 1 ]; then
  (cd "$stage" && "$PYTHON" "$ANALYZER_ROOT/pipeline/db_loader.py" output/exfil_events.json)
  DATABASE_URL="${DATABASE_URL:?DATABASE_URL is required when PostgreSQL loading is enabled}" \
    "$PYTHON" - "$stage/output/sql-verification.json" "$task_id" "$sample_sha256" "$pcap_sha256" <<'PY'
import json,os,sys,psycopg
path,task,sample,pcap=sys.argv[1:]
with psycopg.connect(os.environ['DATABASE_URL']) as conn, conn.cursor() as cur:
    cur.execute('select count(*) from exfil_events where sample_id=%s',(sample,)); count=cur.fetchone()[0]
json.dump({'task_id':int(task),'sample_id':sample,'pcap_sha256':pcap,'row_count':count},open(path,'w')); open(path,'a').write('\n')
PY
fi
python3 "$PROJECT_ROOT/scripts/build-c2-result.py" "$stage" "$BUNDLE" "$RUNTIME" "$PROJECT_ROOT" \
  --task-id "$task_id" --started-at "$started_at" --correlation "$correlation" --zeek-mode pcap_only
chmod -R a-w "$stage"
"$validator" validate-c2-result "$stage" --handoff "$BUNDLE"
mv "$stage" "$final"
rmdir "$staging_parent"
trap - EXIT
echo "$final"
