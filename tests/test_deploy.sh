#!/bin/bash
# Tests for smartzone.sh against the mock SmartZone API (tests/mock_smartzone.py).
# Builds a throwaway PKI: root R (self-signed), R' (same key as R, cross-signed by X), intermediate I (by R), leaf L (by I).
# acme.sh would hand the hook ca.cer = [I, R'] — the cross-signed tail SmartZone rejects.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; HOOK="$HERE/../smartzone.sh"
T="$(mktemp -d)"; trap 'kill "$MOCK" 2>/dev/null; rm -rf "$T"' EXIT
PASS=0; FAIL=0
ok()   { echo "  ok   - $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL - $1"; FAIL=$((FAIL+1)); }
assert_eq() { [ "$1" = "$2" ] && ok "$3" || fail "$3 (got '$1', want '$2')"; }
assert_grep() { grep -q -- "$1" "$2" && ok "$3" || { fail "$3"; sed 's/^/        /' "$2"; }; }

echo "# building test PKI in $T"
cd "$T" || exit 1
openssl ecparam -name prime256v1 -genkey -noout -out x.key 2>/dev/null
openssl req -x509 -new -key x.key -subj "/CN=Other Root X" -days 30 -out x.pem 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out r.key 2>/dev/null
openssl req -x509 -new -key r.key -subj "/CN=Test Root R" -days 30 -out r_self.pem -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
openssl req -new -key r.key -subj "/CN=Test Root R" -out r.csr 2>/dev/null
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' > ca.ext
openssl x509 -req -in r.csr -CA x.pem -CAkey x.key -CAcreateserial -days 30 -extfile ca.ext -out r_cross.pem 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out i.key 2>/dev/null
openssl req -new -key i.key -subj "/CN=Test Issuing CA I" -out i.csr 2>/dev/null
openssl x509 -req -in i.csr -CA r_self.pem -CAkey r.key -CAcreateserial -days 30 -extfile ca.ext -out i.pem 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out leaf.key 2>/dev/null
openssl req -new -key leaf.key -subj "/CN=controller.example.test" -out leaf.csr 2>/dev/null
printf 'basicConstraints=CA:FALSE\nsubjectAltName=DNS:controller.example.test\n' > leaf.ext
openssl x509 -req -in leaf.csr -CA i.pem -CAkey i.key -CAcreateserial -days 30 -extfile leaf.ext -out leaf.pem 2>/dev/null
cat i.pem r_cross.pem > ca.cer; cat leaf.pem ca.cer > fullchain.cer
# second leaf for tests that need a distinct fingerprint
openssl ecparam -name prime256v1 -genkey -noout -out leaf2.key 2>/dev/null
openssl req -new -key leaf2.key -subj "/CN=controller2.example.test" -out leaf2.csr 2>/dev/null
openssl x509 -req -in leaf2.csr -CA i.pem -CAkey i.key -CAcreateserial -days 30 -extfile leaf.ext -out leaf2.pem 2>/dev/null
cat leaf2.pem ca.cer > fullchain2.cer
mkdir -p cadir; cp r_self.pem cadir/test-root-r.pem; cp x.pem cadir/other-root-x.pem
LEAF_FP=$(openssl x509 -in leaf.pem -outform DER | shasum -a 256 | cut -d' ' -f1)
EXP=$(openssl x509 -in leaf.pem -noout -enddate | cut -d= -f2)
YMD=$(python3 -c "import time,sys; print(time.strftime('%Y%m%d', time.strptime(sys.argv[1], '%b %d %H:%M:%S %Y %Z')))" "$EXP")

PORT=$((20000 + RANDOM % 20000)); STATE="$T/state.json"
python3 "$HERE/mock_smartzone.py" "$PORT" "$STATE" & MOCK=$!
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/" && break; sleep 0.1; done

run_hook() { # extra env as args
  env SZ_ENV=/nonexistent SZ_SCHEME=http SZ_HOST=127.0.0.1 SZ_PORT="$PORT" SZ_USER=admin SZ_PASS=secret SZ_CA_DIR="$T/cadir" "$@" \
    bash -c ". '$HOOK'; smartzone_deploy controller.example.test '$T/${LEAF:-leaf}.key' '$T/${LEAF:-leaf}.pem' '$T/ca.cer' '$T/fullchain${LEAF#leaf}.cer'" > "$T/out.log" 2>&1
  echo $?
}
state() { python3 -c "import json,sys; s=json.load(open('$STATE')); print(eval(sys.argv[1]))" "$1"; }

echo "# 1. fresh deploy: resolves self-signed root, uploads, maps MANAGEMENT_WEB+HOTSPOT"
rc=$(run_hook SZ_SERVICES=MANAGEMENT_WEB,HOTSPOT SZ_NAME_PREFIX=acme)
assert_eq "$rc" 0 "exit code 0"
assert_grep "root subject=CN=Test Root R" "$T/out.log" "picked the SELF-SIGNED Test Root R (not the cross-signed copy)"
assert_grep "1 intermediate(s)" "$T/out.log" "dropped the cross-signed tail, kept the issuing CA as intermediate"
assert_eq "$(state "[c['name'] for c in s['certs'] if c['name'].startswith('acme')][0]")" "acme-$YMD" "store name is <prefix>-<notAfter YYYYMMDD>"
assert_eq "$(state "s['mapping']['MANAGEMENT_WEB']==s['mapping']['HOTSPOT'] and s['mapping']['MANAGEMENT_WEB'] is not None")" "True" "both services mapped to the new cert"
assert_eq "$(state "s['mapping']['COMMUNICATOR']")" "11111111-1111-1111-1111-111111111111" "COMMUNICATOR untouched"
assert_grep "mapping now" "$T/out.log" "reports mapping after PATCH"

echo "# 2. re-run with the same certificate: duplicate fingerprint -> re-use, no second entry, still exit 0"
rc=$(run_hook SZ_SERVICES=MANAGEMENT_WEB,HOTSPOT SZ_NAME_PREFIX=acme)
assert_eq "$rc" 0 "exit code 0 on re-run"
assert_eq "$(state "len([c for c in s['certs'] if c['fp']=='$LEAF_FP'])")" "1" "exactly one entry with the leaf fingerprint"
assert_grep "re-using" "$T/out.log" "logged the re-use"

echo "# 3. prune: an older unmapped cert with the prefix is deleted; mapped and foreign ones stay"
python3 - "$STATE" <<'PY'
import json,sys; s=json.load(open(sys.argv[1]))
s['certs'].append({"id":"old-1","name":"ACME-20200101","fp":"oldfp"})      # prefix match, case-insensitive, unmapped -> prune
s['certs'].append({"id":"keep-1","name":"CustomerPortal","fp":"keepfp"})   # no prefix -> keep
json.dump(s,open(sys.argv[1],'w'))
PY
kill "$MOCK"; wait "$MOCK" 2>/dev/null
python3 "$HERE/mock_smartzone.py" "$PORT" "$STATE" "$STATE" & MOCK=$!
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/" && break; sleep 0.1; done
rc=$(run_hook SZ_SERVICES=MANAGEMENT_WEB,HOTSPOT SZ_NAME_PREFIX=acme SZ_PRUNE=1)
assert_eq "$rc" 0 "exit code 0"
assert_eq "$(state "[c['id'] for c in s['certs'] if c['id']=='old-1']")" "[]" "old prefix cert pruned"
assert_eq "$(state "[c['id'] for c in s['certs'] if c['id']=='keep-1']")" "['keep-1']" "non-prefix cert kept"
assert_eq "$(state "len([c for c in s['certs'] if c['fp']=='$LEAF_FP'])")" "1" "live cert kept"
rc=$(run_hook SZ_SERVICES=MANAGEMENT_WEB SZ_NAME_PREFIX=acme SZ_PRUNE=0)
assert_eq "$rc" 0 "SZ_PRUNE=0 run exits 0"

echo "# 4. failures are loud: bad password -> non-zero; no self-signed root available -> non-zero, nothing uploaded"
rc=$(run_hook SZ_PASS=wrong)
assert_eq "$rc" 1 "wrong password -> rc 1"
assert_grep "ERROR login" "$T/out.log" "login error logged"
before=$(state "len(s['certs'])")
rc=$(run_hook SZ_CA_DIR="$T/empty-dir")
assert_eq "$rc" 2 "no root found -> rc 2"
assert_eq "$(state "len(s['certs'])")" "$before" "nothing uploaded without a root"

echo "# 5. name length: long prefix is truncated to 32 chars (distinct certificate so dedupe does not short-circuit)"
rc=$(LEAF=leaf2 run_hook SZ_NAME_PREFIX=this-is-a-very-long-prefix-for-naming SZ_PRUNE=0)
assert_eq "$rc" 0 "exit 0 with long prefix"
assert_eq "$(state "max(len(c['name']) for c in s['certs'])")" "32" "store name capped at 32"

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
