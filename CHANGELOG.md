# Changelog

All notable changes to this project are documented in this file.

## [1.2.0] - 2026-08-01

### Added

- CLI help (`--help` / `-h`) with usage examples.
- Simulation mode `--check`: scans certificates, shows expiry dates and which ones would be renewed, without modifying anything or restarting OpenLiteSpeed.
- Clear handling of invalid arguments (unknown options, invalid thresholds, unknown domains).
- `set -euo pipefail` and consistent logging helpers.
- OpenLiteSpeed restart is now secured: the binary is checked for existence/executability before restart, with a clear warning otherwise.
- Single-domain mode now also detects ECC certificates (`<domain>_ecc`).

### Changed

- Replaced fragile `ls | head` with `find` (robust against filenames with spaces).
- Final summary now reports: certificates checked, needing renewal, renewed, failed, and the actual OpenLiteSpeed restart status.
- The `--force` behavior is documented in the code (workaround for CyberPanel's broken renewal scheduler).

## [1.1.0] - 2026-08-01

### Added

- Auto mode in `renew-ssl.sh`: scans all certificates registered in `acme.sh` and renews every one expiring within a configurable threshold (default: 10 days).
- ECC certificate detection (`_ecc` folders are renewed with the `--ecc` flag).
- OpenLiteSpeed is now restarted once at the end, only if at least one certificate was renewed.
- `README.md` documentation for the new modes and cron setup.

### Changed

- `renew-ssl.sh` no longer requires a domain argument; single-domain mode is still supported for backward compatibility.

## [1.0.0] - 2026-08-01

### Added

- Initial release:
  - `renew-ssl.sh` — renews an existing certificate via `acme.sh` and installs it to `/etc/letsencrypt/live/<domain>/`.
  - `fix-ssl.sh` — full re-issue of a certificate (webroot method, production Let's Encrypt CA, `www` subdomain included).
  - `README.md` with usage, permissions and cron instructions.
