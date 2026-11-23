# Changelog

## v1.0.0 (2026-11-23)

- Initial release: certificate upload, service mapping and pruning through the SmartZone public API.
- Resolves a self-signed root from the system CA store because SmartZone rejects cross-signed roots (`onPrePersist.notMatch`).
- Re-uses an existing store entry when the controller reports a duplicate fingerprint, so re-runs are idempotent.
- Test suite with a mock SmartZone certificate API (`tests/`).
