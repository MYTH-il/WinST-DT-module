#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CAPE_DIR="${CAPE_DIR:-/opt/CAPEv2}"
LOCK_FILE="${LOCK_FILE:-$PROJECT_ROOT/config/cape.lock.json}"
FAIL=0
SELECTED=",${WINSTDT_VALIDATE_SELECTED:-capa,floss,die,trid,suricata,volatility},"
selected() { [[ "$SELECTED" == *",$1,"* ]]; }
pass() { printf '[PASS] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*" >&2; FAIL=1; }
check_cmd() { command -v "$1" >/dev/null 2>&1 && pass "$1 available" || fail "$1 unavailable"; }
lock_value() { python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); [None for p in sys.argv[2].split(".") if not (v:=v[p])]; print(v)' "$LOCK_FILE" "$1"; }
tree_hash() { find "$1" -type f -print0 | sort -z | xargs -0 sha256sum | sed "s#  $1/##" | sha256sum | awk '{print $1}'; }

python3 -m json.tool "$LOCK_FILE" >/dev/null && pass 'lock file is valid JSON' || fail 'invalid lock file'
expected="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["cape"]["commit"])' "$LOCK_FILE")"
actual="$(git -c safe.directory="$CAPE_DIR" -C "$CAPE_DIR" rev-parse HEAD 2>/dev/null || true)"
[ "$actual" = "$expected" ] && pass "CAPE revision $expected" || fail "CAPE revision expected=$expected actual=${actual:-missing}"
selected die && check_cmd diec
if selected die && command -v diec >/dev/null 2>&1; then
  die_version="$(lock_value tools.diec.version)"
  die_binary="$(lock_value tools.diec.binary)"
  die_database="$(lock_value tools.diec.signature_database)"
  "$die_binary" --version 2>&1 | grep -Fq "$die_version" \
    && pass "DIE version $die_version" || fail "unexpected DIE version"
  sudo -u "${CAPE_USER:-cape}" test -r "$die_database" \
    && pass 'DIE signature database readable by processor' || fail 'DIE signature database unreadable by processor'
fi
selected suricata && check_cmd suricata
if selected trid; then
  test -x "$CAPE_DIR/data/trid/trid" && pass 'TRiD executable' || fail 'TRiD executable missing/not executable'
  test -r "$CAPE_DIR/data/trid/triddefs.trd" && pass 'TRiD definitions readable' || fail 'TRiD definitions missing/unreadable'
fi
if selected suricata && command -v suricata >/dev/null 2>&1; then
  rules_root="${WINSTDT_ROOT:-/srv/winstdt}/rules/suricata"
  sudo suricata -T -c /etc/suricata/winstdt.yaml >/dev/null 2>&1 \
    && sudo -u "${CAPE_USER:-cape}" test -r "$rules_root/suricata.rules" \
    && sudo -u "${CAPE_USER:-cape}" test -r "$rules_root/winstdt-controlled-canary.rules" \
    && grep -q 'winstdt-controlled-canary.rules' /etc/suricata/winstdt-cape.yaml \
    && grep -q 'winstdt-cape.yaml' /etc/suricata/winstdt.yaml \
    && pass 'Suricata configuration and processor access' || fail 'Suricata configuration or processor access'
fi
for module in capa floss volatility3; do
  capability="$module"; [ "$module" = volatility3 ] && capability=volatility
  selected "$capability" || continue
  sudo -u "${CAPE_USER:-cape}" bash -lc "cd '$CAPE_DIR' && /etc/poetry/bin/poetry run python -c 'import $module'" >/dev/null 2>&1 && pass "$module import" || fail "$module import"
done
if selected capa; then
  actual="$(tree_hash "$CAPE_DIR/data/capa-rules")"; expected_hash="$(lock_value external_data.capa_rules.sha256)"
  [ "$actual" = "$expected_hash" ] && pass 'CAPA rules snapshot hash' || fail "CAPA rules hash expected=$expected_hash actual=$actual"
fi
if selected floss; then
  actual="$(tree_hash "$CAPE_DIR/data/flare-signatures")"; expected_hash="$(lock_value external_data.floss_signatures.sha256)"
  [ "$actual" = "$expected_hash" ] && pass 'FLOSS signatures snapshot hash' || fail "FLOSS signatures hash expected=$expected_hash actual=$actual"
fi
if selected suricata && [ -s "${WINSTDT_ROOT:-/srv/winstdt}/rules/suricata/suricata.rules" ]; then
  actual="$(sha256sum "${WINSTDT_ROOT:-/srv/winstdt}/rules/suricata/suricata.rules" | awk '{print $1}')"; expected_hash="$(lock_value external_data.suricata_rules.sha256)"
  [ "$actual" = "$expected_hash" ] && pass 'Suricata rules snapshot hash' || fail "Suricata rules hash expected=$expected_hash actual=$actual"
fi
python3 - "$LOCK_FILE" "${WINSTDT_VALIDATE_SELECTED:-capa,floss,die,trid,suricata,volatility}" <<'PY' || FAIL=1
import json,sys
d=json.load(open(sys.argv[1]))['external_data']
selected=set(sys.argv[2].split(','))
mapping={'capa_rules':'capa','floss_signatures':'floss','trid_definitions':'trid','suricata_rules':'suricata','volatility_symbols':'volatility'}
bad=[k for k,v in d.items() if mapping[k] in selected and str(v['sha256']).startswith(('REQUIRED_', 'RECORD_'))]
if bad:
 print('[FAIL] unpinned external data: '+', '.join(bad), file=sys.stderr); raise SystemExit(1)
print('[PASS] external data revisions and hashes pinned')
PY
if selected volatility; then
  sudo -u "${CAPE_USER:-cape}" test -s "${WINSTDT_ROOT:-/srv/winstdt}/symbols/volatility/windows.zip" && pass 'offline Volatility Windows symbols available' || fail 'offline Volatility Windows symbols unavailable (set VOLATILITY_SYMBOL_ARCHIVE during installation)'
fi
exit "$FAIL"
