#!/bin/bash
# RUCKUS SmartZone (SZ / vSZ-E / vSZ-H) certificate deploy hook for acme.sh
# Installs the renewed certificate through the SmartZone public API and maps it
# to the controller services (Management Web, Hotspot, AP Portal, Communicator).
#
#   acme.sh --deploy -d controller.example.com --ecc --deploy-hook smartzone
#
# Configuration: $HOME/.acme.sh/smartzone.env (chmod 600; acme.sh upgrades do not touch it)
#   SZ_HOST=controller.example.com   SZ_PORT=8443        SZ_API=v13_0
#   SZ_USER=admin                     SZ_PASS=secret
#   SZ_SERVICES=MANAGEMENT_WEB,HOTSPOT   # AP_PORTAL and COMMUNICATOR also valid; COMMUNICATOR affects AP control traffic
#   SZ_NAME_PREFIX=acme               # store name = <prefix>-<notAfter YYYYMMDD>, 32 chars max
#   SZ_PRUNE=1                        # delete older, unmapped certificates whose name starts with the prefix
#   SZ_CA_DIR=/etc/ssl/certs          # where to look for the self-signed root (colon-separated list allowed)
#   SZ_SCHEME=https SZ_INSECURE=1     # SZ_INSECURE=0 to verify the controller's TLS certificate
#
# Why this exists: SmartZone rejects an upload whose rootData is not a self-signed root
# (HTTP 422 ScgCertEventHandler.onPrePersist.notMatch). acme.sh's ca.cer usually ends with a
# cross-signed root, so the hook resolves the matching self-signed root from the system CA store.
# The controller also refuses a second copy of the same certificate (422 "fingerprint is
# duplicated"); the hook then re-uses the existing entry. Re-runs are idempotent.
#
# Copyright (c) 2026 CyB0rgg <dev@bluco.re>
# License: MIT
# Version: 1.0.0
########  Public functions #####################
#domain keyfile certfile cafile fullchain
smartzone_deploy() {
  _cdomain="$1"; _ckey="$2"; _ccert="$3"; _cca="$4"; _cfullchain="$5"
  : "${SZ_ENV:=$HOME/.acme.sh/smartzone.env}"
  if [ -f "$SZ_ENV" ]; then
    # shellcheck disable=SC1090
    . "$SZ_ENV"
  fi
  : "${SZ_HOST:?SZ_HOST not set (see $SZ_ENV)}"; : "${SZ_USER:?SZ_USER not set}"; : "${SZ_PASS:?SZ_PASS not set}"
  : "${SZ_PORT:=8443}"; : "${SZ_API:=v13_0}"; : "${SZ_SERVICES:=MANAGEMENT_WEB}"; : "${SZ_NAME_PREFIX:=acme}"; : "${SZ_PRUNE:=1}"
  : "${SZ_CA_DIR:=/etc/ssl/certs:/usr/share/ca-certificates/mozilla}"; : "${SZ_SCHEME:=https}"; : "${SZ_INSECURE:=1}"
  export SZ_HOST SZ_PORT SZ_API SZ_USER SZ_PASS SZ_SERVICES SZ_NAME_PREFIX SZ_PRUNE SZ_CA_DIR SZ_SCHEME SZ_INSECURE
  if ! command -v _info >/dev/null 2>&1; then _info() { echo "$*"; }; _err() { echo "$*" >&2; }; fi
  _info "smartzone: deploying $_cdomain to $SZ_SCHEME://$SZ_HOST:$SZ_PORT ($SZ_API) services=$SZ_SERVICES"
  if ! command -v python3 >/dev/null 2>&1; then _err "smartzone: python3 is required"; return 1; fi
  if ! command -v openssl >/dev/null 2>&1; then _err "smartzone: openssl is required"; return 1; fi
  python3 - "$_ckey" "$_ccert" "$_cca" <<'PY'
import glob, json, os, ssl, subprocess, sys, time, urllib.request, http.cookiejar
key_f, cert_f, ca_f = sys.argv[1:4]
H = os.environ; BASE = f"{H['SZ_SCHEME']}://{H['SZ_HOST']}:{H['SZ_PORT']}/wsg/api/public/{H['SZ_API']}"
def pem_blocks(t):
    out, cur = [], []
    for l in t.splitlines():
        if l.startswith("-----BEGIN"): cur = [l]
        elif l.startswith("-----END"): cur.append(l); out.append("\n".join(cur) + "\n"); cur = []
        elif cur: cur.append(l)
    return out
def x509(pem, *args):
    return subprocess.run(["openssl", "x509", "-noout", *args], input=pem, capture_output=True, text=True).stdout.strip()
def subj(pem): return x509(pem, "-subject")
def issuer(pem): return x509(pem, "-issuer").replace("issuer=", "subject=", 1)
def self_signed(pem): return subj(pem) == issuer(pem)
leaf = open(cert_f).read(); key = open(key_f).read(); chain = pem_blocks(open(ca_f).read())
# resolve a SELF-SIGNED root: last chain cert if self-signed; else a system root with the same subject
# (drop the cross-signed copy); else a system root that issued the last chain cert.
roots = []
for d in H["SZ_CA_DIR"].split(":"):
    roots += glob.glob(os.path.join(d, "*.pem")) + glob.glob(os.path.join(d, "*.crt"))
def find_root(subject):
    for f in roots:
        try: pem = open(f).read()
        except OSError: continue
        if pem.count("BEGIN CERTIFICATE") == 1 and subj(pem) == subject and self_signed(pem): return pem
    return None
inter, root = chain, None
if chain and self_signed(chain[-1]): inter, root = chain[:-1], chain[-1]
elif chain:
    r = find_root(subj(chain[-1]))
    if r: inter, root = chain[:-1], r
    else:
        r = find_root(issuer(chain[-1]))
        if r: inter, root = chain, r
if root is None: print("smartzone: ERROR no self-signed root found for the chain (set SZ_CA_DIR)", file=sys.stderr); sys.exit(2)
print(f"smartzone: chain = {len(inter)} intermediate(s) + root {subj(root)}")
end = x509(leaf, "-enddate").split("=", 1)[1]
ymd = time.strftime("%Y%m%d", time.strptime(end, "%b %d %H:%M:%S %Y %Z"))
name = f"{H['SZ_NAME_PREFIX']}-{ymd}"[:32]
ctx = ssl.create_default_context()
if H["SZ_INSECURE"] == "1": ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj), urllib.request.HTTPSHandler(context=ctx))
def call(m, p, b=None):
    r = urllib.request.Request(BASE + p, data=(json.dumps(b).encode() if b is not None else None), method=m,
                               headers={"Content-Type": "application/json;charset=UTF-8"})
    try:
        with op.open(r, timeout=90) as x: raw = x.read(); return x.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e: return e.code, e.read().decode(errors="replace")
st, b = call("POST", "/session", {"username": H["SZ_USER"], "password": H["SZ_PASS"]})
if st != 200: print("smartzone: ERROR login", st, b, file=sys.stderr); sys.exit(1)
rc = 0
try:
    st, lst = call("GET", "/certstore/certificate")
    if st != 200 or not isinstance(lst, dict): print("smartzone: ERROR reading certificate store", st, lst, file=sys.stderr); sys.exit(3)
    certs = lst.get("list", [])
    existing = next((c for c in certs if c.get("name") == name), None)
    if existing:
        cid = existing["id"]; print(f"smartzone: certificate {name} already present ({cid}), re-using")
    else:
        st, res = call("POST", "/certstore/certificate", {"name": name, "description": f"acme.sh deploy {time.strftime('%Y-%m-%d')}",
                       "data": leaf, "intermediateData": inter, "rootData": root, "privateKeyData": key, "passphrase": ""})
        if st == 422 and "fingerprint is duplicated" in str(res):
            # same certificate already in the store under another name: reuse it
            import re as _re
            m = _re.search(r"other Scg Cert \(([^)]+)\)", str(res))
            dup = next((c for c in certs if m and c.get("name") == m.group(1)), None)
            if not dup: print("smartzone: ERROR duplicate fingerprint but entry not found:", res, file=sys.stderr); sys.exit(3)
            cid, name = dup["id"], dup["name"]; print(f"smartzone: certificate already in store as {name} ({cid}), re-using")
        elif st not in (200, 201): print("smartzone: ERROR upload", st, res, file=sys.stderr); sys.exit(3)
        else:
            cid = res["id"]; print(f"smartzone: uploaded {name} -> {cid}")
    services = [s.strip() for s in H["SZ_SERVICES"].split(",") if s.strip()]
    st, res = call("PATCH", "/certstore/setting/serviceCertificates", [{"service": s, "certificate": {"id": cid, "name": name}} for s in services])
    if st != 204: print("smartzone: ERROR mapping", st, res, file=sys.stderr); sys.exit(4)
    print("smartzone: mapped", ",".join(services), "->", name)
    time.sleep(3)
    st, setting = call("GET", "/certstore/setting")
    if st != 200 or not isinstance(setting, dict): print("smartzone: ERROR reading certificate setting", st, setting, file=sys.stderr); sys.exit(4)
    mapped = {s["certificate"]["id"] for s in setting.get("serviceCertificates", []) if s.get("certificate")}
    print("smartzone: mapping now:", [(s["service"], (s.get("certificate") or {}).get("name")) for s in setting.get("serviceCertificates", [])])
    if H["SZ_PRUNE"] == "1":
        pre = H["SZ_NAME_PREFIX"].lower()
        for c in certs:
            if c["id"] != cid and c["id"] not in mapped and (c.get("name") or "").lower().startswith(pre):
                st, res = call("DELETE", f"/certstore/certificate/{c['id']}")
                print(f"smartzone: pruned {c['name']} ({c['id']}) -> {st}")
finally:
    call("DELETE", "/session")
sys.exit(rc)
PY
  _rc=$?
  if [ "$_rc" -ne 0 ]; then _err "smartzone: deploy failed (rc=$_rc)"; return "$_rc"; fi
  _info "smartzone: done"
  return 0
}
