#!/usr/bin/env bash
set -euo pipefail

EXECUTE=0
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CAPE_DIR="${CAPE_DIR:-/opt/CAPEv2}"
CAPE_USER="${CAPE_USER:-cape}"
WINSTDT_ROOT="${WINSTDT_ROOT:-/srv/winstdt}"
LOCK_FILE="${LOCK_FILE:-$PROJECT_ROOT/config/cape.lock.json}"

usage() { printf '%s\n' 'Usage: scripts/install-analysis-capabilities.sh [--execute]' 'Dry-run is the default. External data hashes must be pinned before --execute.'; }
while [ "$#" -gt 0 ]; do case "$1" in --execute) EXECUTE=1;; -h|--help) usage; exit 0;; *) echo "unknown argument: $1" >&2; exit 2;; esac; shift; done
log() { printf '[analysis-install] %s\n' "$*"; }
run() { log "+ $*"; [ "$EXECUTE" -eq 0 ] || sudo "$@"; }

read_lock() { python3 - "$LOCK_FILE" "$1" <<'PY'
import json,sys
v=json.load(open(sys.argv[1], encoding='utf-8'))
for part in sys.argv[2].split('.'):
    v=v[part]
print(v)
PY
}

test -f "$LOCK_FILE" || { echo "missing lock file: $LOCK_FILE" >&2; exit 1; }
expected="$(read_lock cape.commit)"
actual="$(git -c safe.directory="$CAPE_DIR" -C "$CAPE_DIR" rev-parse HEAD 2>/dev/null || true)"
[ "$actual" = "$expected" ] || { echo "CAPE revision mismatch: expected=$expected actual=${actual:-missing}" >&2; exit 1; }
if ! git -c safe.directory="$CAPE_DIR" -C "$CAPE_DIR" diff --quiet || ! git -c safe.directory="$CAPE_DIR" -C "$CAPE_DIR" diff --cached --quiet || [ -n "$(git -c safe.directory="$CAPE_DIR" -C "$CAPE_DIR" ls-files --others --exclude-standard)" ]; then
  log 'CAPE worktree has local divergence; it will be preserved and overlays only will be installed'
fi

capa="$(read_lock tools.flare_capa.version)"
floss="$(read_lock tools.floss.version)"
vol="$(read_lock tools.volatility3.version)"
die_version="$(read_lock tools.diec.version)"
die_url="$(read_lock tools.diec.url)"
die_sha256="$(read_lock tools.diec.sha256)"
die_binary="$(read_lock tools.diec.binary)"
die_database="$(read_lock tools.diec.signature_database)"
run install -d -m 0750 -o "$CAPE_USER" -g "$CAPE_USER" "$WINSTDT_ROOT/rules/capa" "$WINSTDT_ROOT/rules/suricata" "$WINSTDT_ROOT/symbols/volatility" "$WINSTDT_ROOT/backups/cape"
run -u "$CAPE_USER" bash -lc "cd '$CAPE_DIR' && /etc/poetry/bin/poetry run pip install 'flare-capa==$capa' 'flare-floss==$floss' 'volatility3==$vol'"
run apt-get install -y ca-certificates curl gcc-mingw-w64-x86-64 suricata suricata-update jq unzip

die_cache="$WINSTDT_ROOT/cache/die/die_${die_version}_Ubuntu_24.04_amd64.deb"
run install -d -m 0750 "$(dirname "$die_cache")"
if [ "$EXECUTE" -eq 1 ]; then
  if sudo test -e "$die_cache"; then
    cached_sha="$(sudo sha256sum "$die_cache" | awk '{print $1}')"
    [ "$cached_sha" = "$die_sha256" ] || {
      echo "cached DIE package hash mismatch: expected=$die_sha256 actual=$cached_sha" >&2
      exit 1
    }
  else
    run curl --proto '=https' --tlsv1.2 --fail --location --retry 3 \
      --connect-timeout 15 --max-time 180 --output "$die_cache.part" "$die_url"
    downloaded_sha="$(sudo sha256sum "$die_cache.part" | awk '{print $1}')"
    [ "$downloaded_sha" = "$die_sha256" ] || {
      echo "downloaded DIE package hash mismatch: expected=$die_sha256 actual=$downloaded_sha" >&2
      exit 1
    }
    run mv "$die_cache.part" "$die_cache"
  fi
  # apt may resolve dependencies, but the only DIE payload it receives is the
  # already verified local package. Existing conffiles are retained.
  run env DEBIAN_FRONTEND=noninteractive apt-get \
    -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
    install -y --no-install-recommends "$die_cache"
  test -x "$die_binary" || { echo "DIE binary missing after install: $die_binary" >&2; exit 1; }
  version_output="$("$die_binary" --version 2>&1)"
  printf '%s\n' "$version_output" | grep -Fq "$die_version" || {
    echo "unexpected DIE version output: $version_output" >&2
    exit 1
  }
  sudo -u "$CAPE_USER" test -r "$die_database" || {
    echo "CAPE processor cannot read DIE signature database: $die_database" >&2
    exit 1
  }
  die_fixture_dir="$(mktemp -d)"
  trap 'rm -rf -- "$die_fixture_dir"' EXIT
  chmod 0755 "$die_fixture_dir"
  x86_64-w64-mingw32-gcc -Os -s \
    "$PROJECT_ROOT/tests/fixtures/die/known-positive.c" -o "$die_fixture_dir/known-positive.exe"
  chmod 0644 "$die_fixture_dir/known-positive.exe"
  positive_output="$(sudo -u "$CAPE_USER" "$die_binary" "$die_fixture_dir/known-positive.exe" 2>&1)"
  printf '%s\n' "$positive_output" | grep -Eq '^PE(32|64)?$' || {
    echo "DIE did not identify the known-positive PE fixture: $positive_output" >&2
    exit 1
  }
  negative_output="$(sudo -u "$CAPE_USER" "$die_binary" "$PROJECT_ROOT/tests/fixtures/die/known-negative.txt" 2>&1 || true)"
  printf '%s\n' "$positive_output" >"$die_fixture_dir/positive.out"
  printf '%s\n' "$negative_output" >"$die_fixture_dir/negative.out"
  if printf '%s\n' "$negative_output" | grep -Eiq 'PE32|Portable executable'; then
    echo 'DIE incorrectly classified the negative text fixture as a PE executable' >&2
    exit 1
  fi
fi
run install -d -m 0755 "$CAPE_DIR/custom/conf/processing.conf.d" "$CAPE_DIR/custom/conf/integrations.conf.d" "$CAPE_DIR/custom/conf/auxiliary.conf.d" "$CAPE_DIR/custom/conf/memory.conf.d"
run install -m 0644 "$PROJECT_ROOT/cape/custom/conf/processing.conf.d/winstdt_analysis.conf" "$CAPE_DIR/custom/conf/processing.conf.d/winstdt_analysis.conf"
run install -m 0644 "$PROJECT_ROOT/cape/custom/conf/integrations.conf.d/winstdt_analysis.conf" "$CAPE_DIR/custom/conf/integrations.conf.d/winstdt_analysis.conf"
run install -m 0644 "$PROJECT_ROOT/cape/custom/conf/auxiliary.conf.d/winstdt_analysis.conf" "$CAPE_DIR/custom/conf/auxiliary.conf.d/winstdt_analysis.conf"
run install -m 0644 "$PROJECT_ROOT/cape/custom/conf/memory.conf.d/winstdt_full_memory.conf" "$CAPE_DIR/custom/conf/memory.conf.d/winstdt_full_memory.conf"
run chmod 0755 "$CAPE_DIR/data/trid/trid"
if [ "$EXECUTE" -eq 1 ]; then
  rules_source="${SURICATA_RULE_FILE:-/etc/suricata/rules/suricata.rules}"
  expected_rules="$(read_lock external_data.suricata_rules.sha256)"
  test -s "$rules_source" || { echo "pinned Suricata source rules missing: $rules_source" >&2; exit 1; }
  actual_rules="$(sha256sum "$rules_source" | awk '{print $1}')"
  [ "$actual_rules" = "$expected_rules" ] || { echo "Suricata rules hash mismatch: expected=$expected_rules actual=$actual_rules" >&2; exit 1; }
  run install -m 0640 -o "$CAPE_USER" -g "$CAPE_USER" "$rules_source" "$WINSTDT_ROOT/rules/suricata/suricata.rules"
  run cp -a /etc/suricata/suricata.yaml /etc/suricata/winstdt.yaml
  run sed -i "s#^default-rule-path:.*#default-rule-path: $WINSTDT_ROOT/rules/suricata#" /etc/suricata/winstdt.yaml
  run suricata -T -c /etc/suricata/winstdt.yaml
fi
if [ "$EXECUTE" -eq 1 ]; then
  for spec in \
    "integrations.conf:$PROJECT_ROOT/cape/custom/conf/integrations.conf.d/winstdt_analysis.conf" \
    "processing.conf:$PROJECT_ROOT/cape/custom/conf/processing.conf.d/winstdt_analysis.conf" \
    "auxiliary.conf:$PROJECT_ROOT/cape/custom/conf/auxiliary.conf.d/winstdt_analysis.conf" \
    "memory.conf:$PROJECT_ROOT/cape/custom/conf/memory.conf.d/winstdt_full_memory.conf"; do
    name="${spec%%:*}"; overlay="${spec#*:}"
    sudo python3 "$PROJECT_ROOT/scripts/merge-cape-ini.py" "$CAPE_DIR/conf/$name" "$overlay" \
      --backup-root "$WINSTDT_ROOT/backups/cape"
    sudo chown "$CAPE_USER:$CAPE_USER" "$CAPE_DIR/conf/$name"
  done
fi
if [ "$EXECUTE" -eq 1 ] && [ -z "${VOLATILITY_SYMBOL_ARCHIVE:-}" ]; then
  VOLATILITY_SYMBOL_ARCHIVE="$WINSTDT_ROOT/cache/volatility/windows.zip"
  symbols_url="$(read_lock external_data.volatility_symbols.url)"
  symbols_size="$(read_lock external_data.volatility_symbols.size_bytes)"
  run install -d -m 0750 -o "$CAPE_USER" -g "$CAPE_USER" "$(dirname "$VOLATILITY_SYMBOL_ARCHIVE")"
  if ! sudo test -s "$VOLATILITY_SYMBOL_ARCHIVE" || [ "$(sudo stat -c %s "$VOLATILITY_SYMBOL_ARCHIVE" 2>/dev/null || true)" != "$symbols_size" ]; then
    run curl --fail --location --retry 3 --output "$VOLATILITY_SYMBOL_ARCHIVE.part" "$symbols_url"
    run mv "$VOLATILITY_SYMBOL_ARCHIVE.part" "$VOLATILITY_SYMBOL_ARCHIVE"
  fi
fi
if [ -n "${VOLATILITY_SYMBOL_ARCHIVE:-}" ]; then
  expected_symbols="$(read_lock external_data.volatility_symbols.sha256)"
  case "$expected_symbols" in REQUIRED_*|RECORD_*) echo 'pin volatility_symbols.sha256 before installing the archive' >&2; exit 1;; esac
  actual_symbols="$(sudo sha256sum "$VOLATILITY_SYMBOL_ARCHIVE" | awk '{print $1}')"
  [ "$actual_symbols" = "$expected_symbols" ] || { echo "Volatility symbols hash mismatch" >&2; exit 1; }
  run install -m 0640 -o "$CAPE_USER" -g "$CAPE_USER" "$VOLATILITY_SYMBOL_ARCHIVE" "$WINSTDT_ROOT/symbols/volatility/windows.zip"
  symbol_dir="$(sudo -u "$CAPE_USER" bash -lc "cd '$CAPE_DIR' && /etc/poetry/bin/poetry run python -c 'import pathlib,volatility3; print(pathlib.Path(volatility3.__file__).parent / \"symbols\")'")"
  run install -m 0640 -o "$CAPE_USER" -g "$CAPE_USER" "$VOLATILITY_SYMBOL_ARCHIVE" "$symbol_dir/windows.zip"
fi
if [ "$EXECUTE" -eq 1 ]; then
  run python3 "$PROJECT_ROOT/scripts/write-analysis-capability-metadata.py" "$LOCK_FILE" "$WINSTDT_ROOT/analysis-capabilities.json" --cape-dir "$CAPE_DIR" --suricata-rules "$WINSTDT_ROOT/rules/suricata/suricata.rules"
  run chown "$CAPE_USER:$CAPE_USER" "$WINSTDT_ROOT/analysis-capabilities.json"
  run chmod 0640 "$WINSTDT_ROOT/analysis-capabilities.json"
fi
log 'Rule/signature updates are disabled during analysis; only the pinned Volatility archive may be fetched during installation.'
[ "$EXECUTE" -eq 0 ] && log 'dry-run complete; no changes made'
