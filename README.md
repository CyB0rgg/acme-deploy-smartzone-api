# RUCKUS SmartZone API Deploy Hook for ACME.sh

**Copyright (c) CyB0rgg <dev@bluco.re>**

An [acme.sh](https://github.com/acmesh-official/acme.sh) deploy hook that installs a renewed certificate on a RUCKUS SmartZone controller (SZ100/SZ300/SZ144, vSZ-E, vSZ-H) through the SmartZone public API and maps it to the controller services. No GUI, no CSR round-trip, no SSH.

acme.sh already ships `deploy/ruckus.sh`, but that targets ZoneDirector and Unleashed through their web forms. SmartZone has a proper REST API and a certificate store with service mapping, and that is what this hook drives.

## What it does

1. Logs in (`POST /session`, cookie session).
2. Uploads the leaf certificate, the intermediate(s) and a **self-signed** root (`POST /certstore/certificate`).
3. Maps the services you list to the new certificate (`PATCH /certstore/setting/serviceCertificates`).
4. Optionally prunes older, unmapped certificates that carry your name prefix.
5. Logs out.

Re-running it is safe: if the same certificate is already in the store the controller reports a duplicate fingerprint and the hook re-uses that entry instead of failing.

## Two SmartZone behaviours this hook exists for

- **The root must be self-signed.** SmartZone rejects an upload whose `rootData` is not a self-signed certificate with HTTP 422 `ScgCertEventHandler.onPrePersist.notMatch`. The `ca.cer` acme.sh hands to deploy hooks usually ends with a *cross-signed* root (ZeroSSL and Let's Encrypt chains both do this). The hook looks the real self-signed root up in the system CA store (`SZ_CA_DIR`) and sends that instead, dropping the cross-signed copy. If it cannot find one it stops before uploading anything.
- **Fingerprints are unique.** A second upload of the same certificate under another name is refused (422 `fingerprint is duplicated with other Scg Cert (...)`). The hook treats that as "already installed" and continues with the mapping.

## Requirements

- acme.sh 3.x on a host that can reach the controller's management port (default 8443).
- `python3` and `openssl` on that host (Debian/Ubuntu: both present with acme.sh's own dependencies).
- A SmartZone administrator account. API versions `v5_1` through `v14_0` use the same certificate-store schema; tested on vSZ-H 7.x with `v13_0`.

## Install

```sh
cp smartzone.sh ~/.acme.sh/deploy/smartzone.sh
chmod 755 ~/.acme.sh/deploy/smartzone.sh
cp examples/smartzone.env.example ~/.acme.sh/smartzone.env
chmod 600 ~/.acme.sh/smartzone.env
$EDITOR ~/.acme.sh/smartzone.env
```

acme.sh upgrades overwrite upstream hooks in `deploy/` but leave extra files alone, so the hook and its env file survive `acme.sh --upgrade`.

## Configure

`~/.acme.sh/smartzone.env`:

| Variable | Default | Meaning |
|---|---|---|
| `SZ_HOST` | (required) | Controller management address |
| `SZ_PORT` | `8443` | Management port |
| `SZ_API` | `v13_0` | Public API version (`GET /wsg/api/public/apiInfo` lists what the controller supports) |
| `SZ_USER`, `SZ_PASS` | (required) | Administrator credentials |
| `SZ_SERVICES` | `MANAGEMENT_WEB` | Comma-separated: `MANAGEMENT_WEB`, `HOTSPOT`, `AP_PORTAL`, `COMMUNICATOR` |
| `SZ_NAME_PREFIX` | `acme` | Store name becomes `<prefix>-<notAfter as YYYYMMDD>`, capped at 32 characters |
| `SZ_PRUNE` | `1` | Delete older, unmapped certificates whose name starts with the prefix (case-insensitive) |
| `SZ_CA_DIR` | `/etc/ssl/certs:/usr/share/ca-certificates/mozilla` | Where to find the self-signed root; colon-separated list |
| `SZ_SCHEME` | `https` | Only change for testing |
| `SZ_INSECURE` | `1` | `0` verifies the controller's TLS certificate (sensible once this hook has installed one) |

`COMMUNICATOR` is the certificate your access points authenticate the controller with. Leave it on the RUCKUS default unless you have read the SmartZone documentation on replacing it and know what happens to APs that do not trust your CA.

## Use

```sh
acme.sh --deploy -d controller.example.com --ecc --deploy-hook smartzone
```

acme.sh records the hook in the domain's conf and runs it after every renewal. A successful run logs the chain it built, the store name, the resulting service mapping and anything it pruned:

```
smartzone: deploying controller.example.com to https://10.0.0.5:8443 (v13_0) services=MANAGEMENT_WEB,HOTSPOT
smartzone: chain = 1 intermediate(s) + root subject=C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication Root E46
smartzone: uploaded acme-20270221 -> 5f1c2a0e-0000-4000-8000-000000000001
smartzone: mapped MANAGEMENT_WEB,HOTSPOT -> acme-20270221
smartzone: mapping now: [('MANAGEMENT_WEB', 'acme-20270221'), ('HOTSPOT', 'acme-20270221'), ('COMMUNICATOR', 'Default Certificate - RSA 2048')]
smartzone: pruned acme-20261123 (…) -> 204
```

The controller restarts its web and subscriber services for a few seconds after the mapping change.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Installed and mapped (or already installed) |
| 1 | Missing tools, missing configuration, or login failed |
| 2 | No self-signed root found for the chain |
| 3 | Upload rejected by the controller |
| 4 | Service mapping rejected by the controller |

## Tests

`tests/test_deploy.sh` builds a throwaway PKI (self-signed root, a cross-signed copy of it, an issuing CA, a leaf), runs the hook against `tests/mock_smartzone.py`, a small mock of the SmartZone certificate API that enforces the same two rules as the real controller, and checks root selection, naming, mapping, duplicate handling, pruning and failure paths.

```sh
bash tests/test_deploy.sh
```

## Notes

- Key type does not matter to the controller; RSA and ECDSA leaves both import. Current SmartZone releases ship an ECDSA P-256 default certificate of their own.
- On a cluster every member must be up for the import to succeed; a down node produces "Failed to clean and save related files of server certificate to filesystem".
- If the controller sits behind a hypervisor-level firewall (for example a Proxmox VM firewall with `policy_in: DROP`), the acme.sh host needs an explicit allow to the management port, even on the same VLAN.

## License

MIT, see `LICENSE`.
