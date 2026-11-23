#!/usr/bin/env python3
"""Minimal mock of the RUCKUS SmartZone public API, enough to exercise smartzone.sh.

Implements, under /wsg/api/public/<ver>/:
  POST   session                              -> 200 + JSESSIONID cookie (checks username/password)
  DELETE session                              -> 200
  GET    certstore/certificate                -> {"list": [...]}
  POST   certstore/certificate                -> 201 {"id"} | 422 duplicate fingerprint | 422 notMatch (non self-signed root)
  DELETE certstore/certificate/<id>           -> 204 | 422 if mapped
  GET    certstore/setting                    -> {"serviceCertificates": [...]}
  PATCH  certstore/setting/serviceCertificates-> 204
State is dumped to the file given as argv[2] on every change so the test can assert on it.
Usage: mock_smartzone.py <port> <statefile> [seed.json]
"""
import hashlib, json, subprocess, sys, uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

USER, PASS = "admin", "secret"
state = {"certs": [], "mapping": {"MANAGEMENT_WEB": None, "HOTSPOT": None, "AP_PORTAL": None, "COMMUNICATOR": "11111111-1111-1111-1111-111111111111"}}
state["certs"].append({"id": "11111111-1111-1111-1111-111111111111", "name": "Default Certificate - RSA 2048", "fp": "default"})
sessions = set()

def fingerprint(pem):
    der = subprocess.run(["openssl", "x509", "-outform", "DER"], input=pem.encode(), capture_output=True).stdout
    return hashlib.sha256(der).hexdigest()

def self_signed(pem):
    s = subprocess.run(["openssl", "x509", "-noout", "-subject", "-issuer"], input=pem, capture_output=True, text=True).stdout.splitlines()
    return len(s) == 2 and s[0].split("=", 1)[1] == s[1].split("=", 1)[1]

def dump():
    json.dump(state, open(sys.argv[2], "w"), indent=1)

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, body=None):
        data = json.dumps(body).encode() if body is not None else b""
        self.send_response(code)
        if data: self.send_header("Content-Type", "application/json;charset=UTF-8")
        self.send_header("Content-Length", str(len(data)))
        if getattr(self, "_cookie", None): self.send_header("Set-Cookie", self._cookie)
        self.end_headers(); self.wfile.write(data)
    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"null") if n else None
    def _authed(self):
        c = self.headers.get("Cookie", "")
        return any(f"JSESSIONID={s}" in c for s in sessions)
    def _route(self):
        p = self.path.split("?")[0]
        parts = p.strip("/").split("/")  # wsg api public vX_Y ...
        return parts[4:] if len(parts) > 4 else []
    def do_POST(self):
        r = self._route(); b = self._body()
        if r == ["session"]:
            if b and b.get("username") == USER and b.get("password") == PASS:
                sid = uuid.uuid4().hex; sessions.add(sid); self._cookie = f"JSESSIONID={sid}; Path=/wsg"
                return self._send(200, {"controllerVersion": "7.1.0.0.0"})
            return self._send(401, {"message": "bad credentials"})
        if not self._authed(): return self._send(401, {"message": "no session"})
        if r == ["certstore", "certificate"]:
            if not self_signed(b["rootData"]):
                return self._send(422, {"message": "error.com.ruckuswireless.scg.domain.service.config.handler.ScgCertEventHandler.onPrePersist.notMatch", "errorCode": 302, "errorType": "Business rule violation"})
            fp = fingerprint(b["data"])
            for c in state["certs"]:
                if c["fp"] == fp:
                    return self._send(422, {"message": f"fingerprint is duplicated with other Scg Cert ({c['name']}): {fp}", "errorCode": 302, "errorType": "Business rule violation"})
            cid = str(uuid.uuid4()); state["certs"].append({"id": cid, "name": b["name"], "fp": fp, "intermediates": len(b.get("intermediateData") or []), "root_self_signed": True})
            dump(); return self._send(201, {"id": cid})
        self._send(404, {"message": "unknown"})
    def do_GET(self):
        if not self._authed(): return self._send(401, {"message": "no session"})
        r = self._route()
        if r == ["certstore", "certificate"]:
            return self._send(200, {"totalCount": len(state["certs"]), "list": [{"id": c["id"], "name": c["name"], "description": ""} for c in state["certs"]]})
        if r == ["certstore", "setting"]:
            names = {c["id"]: c["name"] for c in state["certs"]}
            return self._send(200, {"serviceCertificates": [{"service": s, "certificate": ({"id": cid, "name": names.get(cid)} if cid else None)} for s, cid in state["mapping"].items()]})
        self._send(404, {"message": "unknown"})
    def do_PATCH(self):
        if not self._authed(): return self._send(401, {"message": "no session"})
        if self._route() == ["certstore", "setting", "serviceCertificates"]:
            for item in self._body():
                state["mapping"][item["service"]] = item["certificate"]["id"]
            dump(); return self._send(204)
        self._send(404, {"message": "unknown"})
    def do_DELETE(self):
        r = self._route()
        if r == ["session"]:
            sessions.clear(); return self._send(200)
        if not self._authed(): return self._send(401, {"message": "no session"})
        if r[:2] == ["certstore", "certificate"] and len(r) == 3:
            if r[2] in state["mapping"].values(): return self._send(422, {"message": "certificate in use"})
            state["certs"] = [c for c in state["certs"] if c["id"] != r[2]]; dump(); return self._send(204)
        self._send(404, {"message": "unknown"})

if __name__ == "__main__":
    if len(sys.argv) > 3:
        state = json.load(open(sys.argv[3]))
    dump()
    HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
