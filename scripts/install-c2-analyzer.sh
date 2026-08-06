#!/usr/bin/env bash
set -euo pipefail

EXECUTE=0
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WINSTDT_ROOT="${WINSTDT_ROOT:-/srv/winstdt}"
CAPE_USER="${CAPE_USER:-cape}"
C2_RUNNER_USER="${C2_RUNNER_USER:-${SUDO_USER:-$(id -un)}}"
C2_RUNNER_GROUP="${C2_RUNNER_GROUP:-$(id -gn "$C2_RUNNER_USER")}"
LOCK_FILE="${C2_LOCK_FILE:-$PROJECT_ROOT/config/c2-exfil.lock.json}"
PATCH_ROOT="$PROJECT_ROOT/integrations/c2-exfil-patches"

usage() { echo 'Usage: scripts/install-c2-analyzer.sh [--execute]'; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --execute) EXECUTE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
  shift
done

read_lock() {
  python3 - "$LOCK_FILE" "$1" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
for component in sys.argv[2].split("."):
    value = value[component]
print(value)
PY
}
log() { printf '[c2-install] %s\n' "$*"; }

commit="$(read_lock commit)"
subtree="$(read_lock subtree)"
effective="$(read_lock effective_version)"
expected_tree="$(read_lock upstream_tree_sha256)"
dependency_lock="$(read_lock dependency_lock)"
expected_dependency="$(read_lock dependency_lock_sha256)"
expected_series="$(read_lock patches.series_sha256)"
source_root="$PROJECT_ROOT/$subtree"
runtime_root="$WINSTDT_ROOT/libexec/c2-exfil"
target="$runtime_root/$effective"

actual_split="$(git -C "$PROJECT_ROOT" log --all --format=%B --grep='git-subtree-dir: integrations/c2-exfil' -n 1 | sed -n 's/^git-subtree-split: //p')"
[ "$actual_split" = "$commit" ] || { echo "C2 subtree revision mismatch: expected=$commit actual=${actual_split:-unknown}" >&2; exit 1; }
actual_tree="$(python3 "$PROJECT_ROOT/scripts/c2-tree-hash.py" "$source_root")"
[ "$actual_tree" = "$expected_tree" ] || { echo "C2 subtree hash mismatch: expected=$expected_tree actual=$actual_tree" >&2; exit 1; }
actual_dependency="$(sha256sum "$PROJECT_ROOT/$dependency_lock" | awk '{print $1}')"
[ "$actual_dependency" = "$expected_dependency" ] || { echo 'C2 dependency lock hash mismatch' >&2; exit 1; }

mapfile -t patches < <(sed '/^[[:space:]]*\($\|#\)/d' "$PATCH_ROOT/series")
[ "${#patches[@]}" -gt 0 ] || { echo 'empty compatibility patch series' >&2; exit 1; }
series_lines=""
for patch_name in "${patches[@]}"; do
  patch_path="$PATCH_ROOT/$patch_name"
  test -s "$patch_path" || { echo "missing patch: $patch_path" >&2; exit 1; }
  patch_hash="$(sha256sum "$patch_path" | awk '{print $1}')"
  series_lines+="$patch_hash  $patch_name"$'\n'
done
actual_series="$(printf '%s' "$series_lines" | sha256sum | awk '{print $1}')"
[ "$actual_series" = "$expected_series" ] || { echo "patch series hash mismatch: expected=$expected_series actual=$actual_series" >&2; exit 1; }

log "verified upstream=$commit tree=$actual_tree"
log "effective runtime: $target"
for patch_name in "${patches[@]}"; do log "patch: $patch_name"; done
if [ "$EXECUTE" -eq 0 ]; then
  log 'dry-run complete; no runtime changes made'
  exit 0
fi

sudo install -d -m 0755 "$runtime_root"
sudo install -d -m 0750 -o "$C2_RUNNER_USER" -g "$C2_RUNNER_GROUP" "$WINSTDT_ROOT/c2-results"
test ! -e "$target" || { echo "effective runtime already exists: $target" >&2; exit 1; }
stage="$(sudo mktemp -d "$runtime_root/.${effective}.XXXXXX")"
cleanup() { sudo test ! -d "$stage" || sudo mv "$stage" "$stage.failed"; }
trap cleanup EXIT
sudo chmod 0755 "$stage"
sudo install -d -m 0755 "$stage/source"
sudo cp -a "$source_root/." "$stage/source/"
sudo install -d -m 0755 "$stage/source/.winstdt"
sudo install -d -m 0755 "$stage/source/sql/migrations"
for patch_name in "${patches[@]}"; do
  sudo patch --batch --forward --directory "$stage/source" -p1 --input "$PATCH_ROOT/$patch_name"
done
sudo python3 -m venv "$stage/.venv"
sudo "$stage/.venv/bin/pip" install --disable-pip-version-check --require-hashes -r "$PROJECT_ROOT/$dependency_lock"

collected="$(cd "$stage/source" && sudo "$stage/.venv/bin/pytest" --collect-only -q | tail -n1 | awk '{print $1}')"
[ "$collected" = 268 ] || { echo "unexpected upstream test count: $collected" >&2; exit 1; }
upstream_result="$(mktemp)"
(cd "$stage/source" && sudo "$stage/.venv/bin/pytest" -q \
  --deselect tests/test_schema_contract.py::test_sample_present \
  --deselect tests/test_schema_contract.py::test_rows_have_attribution_populated \
  --deselect tests/test_schema_contract.py::test_attribution_reaches_csv_export) | tee "$upstream_result"
grep -Eq '254 passed, 11 skipped, 3 deselected' "$upstream_result" || {
  echo 'unexpected upstream test result; expected 254 passed, 11 skipped, 3 deselected' >&2
  rm -f "$upstream_result"; exit 1;
}
rm -f "$upstream_result"
log 'upstream packaging note: three tests requiring an ignored Redline PCAP were explicitly deselected'
sudo "$stage/.venv/bin/python" -m pytest -q \
  "$PROJECT_ROOT/tests/test_c2_patch_pipeline.py" \
  "$PROJECT_ROOT/tests/test_c2_compatibility.py"

if [ "${WINSTDT_POSTGRES_ENABLED:-0}" = 1 ]; then
  test -n "${DATABASE_URL:-}" || { echo 'DATABASE_URL is required when PostgreSQL is enabled' >&2; exit 1; }
  C2_ANALYZER_RUNTIME="$stage" "$PROJECT_ROOT/scripts/migrate-c2-database.sh" --execute
fi

effective_tree="$(sudo python3 "$PROJECT_ROOT/scripts/c2-tree-hash.py" "$stage/source")"
manifest_tmp="$(mktemp)"
python3 - "$manifest_tmp" "$commit" "$effective" "$actual_tree" "$actual_series" "$effective_tree" "$actual_dependency" <<'PY'
import json, sys
from datetime import datetime, timezone
path, commit, version, source_hash, series_hash, effective_hash, dependency_hash = sys.argv[1:]
data = {
    "schema_version": "1.0",
    "upstream_commit": commit,
    "effective_version": version,
    "upstream_tree_sha256": source_hash,
    "patch_series_sha256": series_hash,
    "effective_tree_sha256": effective_hash,
    "dependency_lock_sha256": dependency_hash,
    "validated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "upstream_tests_collected": 268,
    "upstream_tests_passed": 254,
    "upstream_tests_skipped": 11,
    "upstream_tests_deselected_missing_corpus": 3,
}
open(path, "w", encoding="utf-8").write(json.dumps(data, indent=2) + "\n")
PY
sudo install -m 0644 "$manifest_tmp" "$stage/runtime-manifest.json"
rm -f "$manifest_tmp"
sudo chown -R "$CAPE_USER:$CAPE_USER" "$stage"
sudo mv "$stage" "$target"
trap - EXIT
link_tmp="$runtime_root/.current.$effective"
sudo ln -s "$effective" "$link_tmp"
sudo mv -Tf "$link_tmp" "$runtime_root/current"
sudo chown -h "$CAPE_USER:$CAPE_USER" "$runtime_root/current"
log "promoted $target"
