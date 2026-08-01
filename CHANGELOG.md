# Changelog

## [1.0.0] - 2026-08-01

### Added
- Automatic renewal of expiring SSL certificates managed by CyberPanel/acme.sh.
- Full certificate repair workflow with fresh Let's Encrypt issuance.
- ECC certificate support.
- Automatic installation into `/etc/letsencrypt/live/<domain>/`.
- OpenLiteSpeed reload handling.
- Automatic certificate expiry detection.
- Dry-run/check mode for safe verification.

### Fixed
- Recovery from certificates stuck in Let's Encrypt staging mode.
- Workaround for CyberPanel renewal scheduler failures.

### Documentation
- Added troubleshooting instructions.
- Added CyberPanel/OpenLiteSpeed requirements.
- Added debugging commands.
