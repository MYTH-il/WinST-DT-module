#!/usr/bin/env bash
set -euo pipefail

EXECUTE=0
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WINSTDT_ROOT="${WINSTDT_ROOT:-/srv/winstdt}"
SIGNING_KEY="${WINSTDT_VALIDATION_SIGNING_KEY:-$WINSTDT_ROOT/approvals/validation_signer}"
NAMESPACE="winstdt-egress-probe"
HOST_LINK="wstdt-probe0"
PROBE_IP="10.66.0.102"
BRIDGE="virbr-winstdt"
GATEWAY="10.66.0.254"
RESPONDER="192.168.125.10"
VM="${GATEWAY_VM_NAME:-winstdt-egress-gateway}"
RESPONDER_VM="${RESPONDER_VM_NAME:-winstdt-controlled-responder}"
while [ "$#" -gt 0 ]; do
  case "$1" in --execute) EXECUTE=1 ;; *) echo "Usage: $0 [--execute]" >&2; exit 2 ;; esac
  shift
done
test -f "$SIGNING_KEY" || { echo "validation signing key unavailable: $SIGNING_KEY" >&2; exit 1; }
virsh net-dumpxml winstdt-controlled-services | grep -q '<forward' && {
  echo 'controlled-services network unexpectedly has forwarding' >&2; exit 1;
}
if [ "$EXECUTE" -eq 0 ]; then
  echo 'Dry run: negative gateway matrix will use an isolated namespace at 10.66.0.102.'
  echo 'Re-run with --execute to create signed single-use approvals and live evidence.'
  exit 0
fi

group="gateway-negative-$(date -u +%Y%m%dT%H%M%SZ)"
evidence="$WINSTDT_ROOT/validation/gateway-negative/$group"
sudo install -d -m 0750 -o "$(id -u)" -g "$(id -g)" "$evidence"
install -d -m 0750 "$evidence/approvals" "$evidence/runs"
started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
declare -A results=()
active=0 responder_suspended=0 external_down=0

gateway_external_device() {
  virsh domiflist "$VM" | awk '$5 == "52:54:00:67:00:02" {print $1}'
}
cleanup() {
  set +e
  if [ "$active" -eq 1 ]; then "$PROJECT_ROOT/scripts/manage-egress-run.sh" revoke validation-cleanup >/dev/null 2>&1; fi
  if [ "$responder_suspended" -eq 1 ]; then virsh resume "$RESPONDER_VM" >/dev/null 2>&1; fi
  if [ "$external_down" -eq 1 ]; then virsh domif-setlink "$VM" "$(gateway_external_device)" up >/dev/null 2>&1; fi
  sudo ip netns del "$NAMESPACE" >/dev/null 2>&1 || true
  sudo ip link del "$HOST_LINK" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
sudo ip netns del "$NAMESPACE" >/dev/null 2>&1 || true
sudo ip link del "$HOST_LINK" >/dev/null 2>&1 || true
sudo ip netns add "$NAMESPACE"
sudo ip link add "$HOST_LINK" type veth peer name eth0 netns "$NAMESPACE"
sudo ip link set "$HOST_LINK" master "$BRIDGE"
sudo ip link set "$HOST_LINK" up
sudo ip -n "$NAMESPACE" link set lo up
sudo ip -n "$NAMESPACE" link set eth0 up
sudo ip -n "$NAMESPACE" addr add "$PROBE_IP/24" dev eth0
sudo ip -n "$NAMESPACE" route add default via "$GATEWAY"

create_approval() {
  local name="$1" duration="$2" connections="$3" bytes="$4"
  local path="$evidence/approvals/$name.json"
  local expiry
  expiry="$(date -u -d "+$duration seconds" +%Y-%m-%dT%H:%M:%SZ)"
  NAME="$name" EXPIRY="$expiry" PATH_OUT="$path" CONNECTIONS="$connections" BYTES="$bytes" \
    KEY="$SIGNING_KEY" python3 - <<'PY'
import hashlib, json, os, subprocess
policy={"run_id":os.environ["NAME"],"internal_interface":"eth0","external_interface":"eth1",
"guest_ip":"10.66.0.102","destinations":[{"ip":"192.168.125.10","protocol":"tcp","port":8080}],
"dns":{"name":"validation.winstdt.test","pinned_ip":"192.168.125.10"},
"expires_at_utc":os.environ["EXPIRY"],"max_connections":int(os.environ["CONNECTIONS"]),
"max_bytes":int(os.environ["BYTES"])}
digest=hashlib.sha256(json.dumps(policy,sort_keys=True,separators=(",",":")).encode()).hexdigest()
path=os.environ["PATH_OUT"]
policy["approval"]={"approval_id":os.environ["NAME"],"signer_identity":"winstdt-validation",
"policy_sha256":digest,"signature_path":path+".message.sig"}
with open(path,"w",encoding="utf-8") as output: json.dump(policy,output,indent=2); output.write("\n")
message={"approval_id":os.environ["NAME"],"policy":{k:v for k,v in policy.items() if k!="approval"}}
message_path=path+".message"
with open(message_path,"w",encoding="utf-8") as output:
    output.write(json.dumps(message,sort_keys=True,separators=(",",":"))+"\n")
subprocess.run(["ssh-keygen","-q","-Y","sign","-f",os.environ["KEY"],"-n","winstdt-egress",message_path],check=True)
PY
  printf '%s\n' "$path"
}
activate() {
  "$PROJECT_ROOT/scripts/manage-egress-run.sh" activate "$1"
  active=1
  sleep 2
}
revoke_collect() {
  local name="$1"
  "$PROJECT_ROOT/scripts/manage-egress-run.sh" revoke matrix-step
  active=0
  "$PROJECT_ROOT/scripts/manage-egress-run.sh" collect "$name" "$evidence/runs/$name"
  test -s "$evidence/runs/$name/gateway/internal.pcap"
  test -s "$evidence/runs/$name/gateway/external.pcap"
}
probe_post() {
  local run="$1" canary="${2:-matrix-canary}"
  sudo ip netns exec "$NAMESPACE" curl -fsS --connect-timeout 5 --max-time 8 \
    -H 'Content-Type: application/json' --data-binary \
    "{\"marker\":\"WINSTDT-CONTROLLED-CANARY/1\",\"run_id\":\"$run\",\"sequence\":1,\"canary\":\"$canary\"}" \
    "http://$RESPONDER:8080/" >/dev/null
}
blocked() { ! sudo ip netns exec "$NAMESPACE" curl -fsS --connect-timeout 1 --max-time 2 "$1" >/dev/null 2>&1; }

base="$group-base"; activate "$(create_approval "$base" 120 8 1048576)"
probe_post "$base" && results[approved_destination]=passed || results[approved_destination]=failed
blocked "http://192.168.125.11:8080/" && results[wrong_destination]=passed || results[wrong_destination]=failed
blocked "https://$RESPONDER:8443/" && results[wrong_port]=passed || results[wrong_port]=failed
dns_answer="$(sudo ip netns exec "$NAMESPACE" python3 - <<'PY'
import socket,struct
name='validation.winstdt.test'; q=b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2)
s.sendto(b'\x12\x34\x01\x00\0\x01\0\0\0\0\0\0'+q+b'\0\x01\0\x01',('10.66.0.254',53))
r=s.recv(512); print(socket.inet_ntoa(r[-4:]))
PY
)"
test "$dns_answer" = "$RESPONDER" && results[dns_pin]=passed || results[dns_pin]=failed
sudo ip netns exec "$NAMESPACE" python3 - <<'PY' && results[dns_bypass]=passed || results[dns_bypass]=failed
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2)
try: s.sendto(b'\0'*16,('192.168.125.10',53)); s.recv(64); raise SystemExit(1)
except TimeoutError: pass
PY
virsh suspend "$RESPONDER_VM" >/dev/null; responder_suspended=1
blocked "http://$RESPONDER:8080/" && results[responder_unavailable]=passed || results[responder_unavailable]=failed
virsh resume "$RESPONDER_VM" >/dev/null; responder_suspended=0
revoke_collect "$base"

quota="$group-quota"; activate "$(create_approval "$quota" 120 8 1024)"
large="$(printf '%5000s' x)"
probe_post "$quota" "$large" >/dev/null 2>&1 && results[byte_quota]=failed || results[byte_quota]=passed
revoke_collect "$quota"

ceiling="$group-ceiling"; activate "$(create_approval "$ceiling" 120 1 1048576)"
if probe_post "$ceiling" && ! probe_post "$ceiling" second; then results[connection_ceiling]=passed; else results[connection_ceiling]=failed; fi
revoke_collect "$ceiling"

expiry="$group-expiry"; activate "$(create_approval "$expiry" 8 8 1048576)"
sudo ip netns exec "$NAMESPACE" python3 - "$RESPONDER" <<'PY' && results[policy_expiry_open_connection]=passed || results[policy_expiry_open_connection]=failed
import socket,sys,time
s=socket.create_connection((sys.argv[1],8080),timeout=2); time.sleep(10); s.settimeout(2)
try:
    s.sendall(b'GET / HTTP/1.1\r\nHost: validation.winstdt.test\r\nConnection: close\r\n\r\n')
    if s.recv(1): raise SystemExit(1)
except (TimeoutError,ConnectionError,OSError): pass
PY
active=0
"$PROJECT_ROOT/scripts/manage-egress-run.sh" collect "$expiry" "$evidence/runs/$expiry"

emergency="$group-emergency"; activate "$(create_approval "$emergency" 120 8 1048576)"
"$PROJECT_ROOT/scripts/manage-egress-run.sh" emergency-stop; active=0; external_down=1
blocked "http://$RESPONDER:8080/" && results[emergency_stop]=passed || results[emergency_stop]=failed
"$PROJECT_ROOT/scripts/manage-egress-run.sh" collect "$emergency" "$evidence/runs/$emergency"
virsh domif-setlink "$VM" "$(gateway_external_device)" up; external_down=0

captures=true
for name in "$base" "$quota" "$ceiling" "$expiry" "$emergency"; do
  test -s "$evidence/runs/$name/gateway/internal.pcap" || captures=false
  test -s "$evidence/runs/$name/gateway/external.pcap" || captures=false
done
status_json="$("$PROJECT_ROOT/scripts/manage-egress-run.sh" status)"
printf '%s' "$status_json" | grep -q '"active_run":null'
ended="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
all_passed=true
for test_name in approved_destination wrong_destination wrong_port policy_expiry_open_connection byte_quota connection_ceiling dns_pin dns_bypass responder_unavailable emergency_stop; do
  test "${results[$test_name]:-failed}" = passed || all_passed=false
done
test "$captures" = true || all_passed=false
status=failed; test "$all_passed" = true && status=passed
STARTED="$started" ENDED="$ended" GROUP="$group" STATUS="$status" CAPTURES="$captures" \
  RESULTS="$(for key in "${!results[@]}"; do printf '%s=%s\n' "$key" "${results[$key]}"; done)" \
  python3 - "$evidence/acceptance.json" <<'PY'
import json,os,sys
tests=dict(line.split('=',1) for line in os.environ['RESULTS'].splitlines())
value={'schema_version':'1.0','run_group':os.environ['GROUP'],'started_at_utc':os.environ['STARTED'],
'ended_at_utc':os.environ['ENDED'],'probe_ip':'10.66.0.102','public_route_absent':True,
'captures_preserved':os.environ['CAPTURES']=='true','gateway_revoked':True,'tests':tests,'status':os.environ['STATUS']}
with open(sys.argv[1],'w',encoding='utf-8') as output: json.dump(value,output,indent=2); output.write('\n')
PY
python3 - "$PROJECT_ROOT/schemas/gateway_negative_acceptance.schema.json" "$evidence/acceptance.json" <<'PY'
import json,sys
from jsonschema import Draft202012Validator,FormatChecker
Draft202012Validator(json.load(open(sys.argv[1])),format_checker=FormatChecker()).validate(json.load(open(sys.argv[2])))
PY
trap - EXIT INT TERM
cleanup
echo "$evidence/acceptance.json"
test "$status" = passed
