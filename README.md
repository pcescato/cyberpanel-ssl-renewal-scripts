# CyberPanel SSL Renewal Scripts

Bash scripts to renew and repair SSL certificates on CyberPanel 2.x directly via `acme.sh`, bypassing CyberPanel's unreliable built-in renewal scheduler.

## Why this exists

- CyberPanel can report a **successful SSL renewal** while the certificate actually served remains close to expiration.
- In some cases `acme.sh` is left configured with the **Let's Encrypt staging** CA, so "renewals" produce certificates that browsers reject.
- These scripts renew — and repair — certificates **directly via `acme.sh`**, without going through the panel.

## Requirements

- CyberPanel 2.x
- OpenLiteSpeed
- `acme.sh` installed at `/root/.acme.sh/` (CyberPanel default)
- `curl` — used by `fix-ssl.sh` to validate the webroot challenge path (optional: without it, that check is skipped with a warning)
- **Root access** — the scripts write to `/etc/letsencrypt/live/`, read `/root/.acme.sh/`, and restart OpenLiteSpeed

## Scripts

### `renew-ssl.sh` — Renew certificates

Renews certificates that were previously issued and installed with `acme.sh`.

It supports three modes:

- **Auto mode (recommended):** scans all certificates registered in `acme.sh` and renews every one that expires within a configurable number of days (default: **10**).
- **Single domain mode:** renews one specific domain, ignoring expiry (works for both RSA and ECC certificates).
- **Check mode (`--check`):** simulation that scans certificates and reports which ones would be renewed, without modifying anything.

What it does for each certificate to renew:

1. **Renews the certificate** with `acme.sh --renew ... --force`. `--force` makes sure the renewal runs even if `acme.sh` thinks the certificate is still valid (useful to work around CyberPanel's broken scheduler).
2. **Installs the new certificate** into `/etc/letsencrypt/live/<domain>/` (`privkey.pem` and `fullchain.pem`), the location CyberPanel and LiteSpeed expect it.
3. **Restarts OpenLiteSpeed** once at the end (only if at least one certificate was renewed), so the new certificates are picked up.
4. ECC certificates (`<domain>_ecc` folders) are detected and renewed with the proper `--ecc` flag.

The expiry date is read from each certificate with `openssl x509`, so only certificates that really are close to expiring trigger a renewal.

### `fix-ssl.sh` — Issue a fresh certificate (full fix)

A more thorough, step-by-step fix that re-issues the certificate from scratch. Use this one when renewal fails or the certificate is in a broken/staging state.

Before replacing a certificate, the script creates a timestamped backup of the existing certificate and acme.sh configuration. Backups are stored in `/root/ssl-backups/<domain>/<timestamp>/`, kept after a successful fix, and the script refuses to remove the old registration if the backup could not be created.

The script also validates the result end to end: **before issuing** it checks that the HTTP-01 challenge path is actually reachable from the public internet, and **after installing** it checks that the certificate really served by the server matches the new one.

What it does:

1. **Validates the webroot challenge path** before any `acme.sh` call: writes a temporary file in `/home/<domain>/public_html/.well-known/acme-challenge/` and fetches it over HTTP with `curl` (mirroring Let's Encrypt's HTTP-01 request). If the file is not served correctly, the script stops before issuing, since `acme.sh` would fail too.
2. Creates a timestamped backup of the existing certificate and acme.sh configuration in `/root/ssl-backups/<domain>/<timestamp>/`.
3. Switches `acme.sh` to the **Let's Encrypt production** CA (in case it was left in staging mode).
4. Removes any existing `acme.sh` registration for the domain (errors are ignored).
5. **Issues a new certificate** for `<domain>` and `www.<domain>` using the **webroot** method against `/home/<domain>/public_html`.
6. Creates `/etc/letsencrypt/live/<domain>/` and **installs** the certificate there.
7. Restarts OpenLiteSpeed to reload the certificate.
8. **Verifies the served certificate**: shows the local certificate validity dates, then compares the SHA256 fingerprint of the installed certificate with the one presented by the server over HTTPS (`openssl s_client -connect <domain>:443 -servername <domain>`). If they differ, OpenLiteSpeed is still serving the old certificate and the script reports it as an error.

### Differences

| | `renew-ssl.sh` | `fix-ssl.sh` |
|---|---|---|
| Purpose | Regular renewal | Full re-issue / repair |
| Needs webroot | No | Yes (performs HTTP-01 challenge) |
| Domains | All expiring (or one specific) | `<domain>` and `www.<domain>` |
| Speed | Fast | Slower (forces a new issue) |

## Usage

```bash
# Auto mode: renew every certificate expiring within 10 days
./renew-ssl.sh

# Auto mode with a custom threshold (e.g. 30 days)
./renew-ssl.sh 30

# Single domain mode: renew a specific certificate (RSA or ECC)
./renew-ssl.sh example.com

# Simulation: show expiry dates and which certificates would be renewed
./renew-ssl.sh --check

# Help
./renew-ssl.sh --help

# Full re-issue / repair
./fix-ssl.sh example.com
```

Replace `example.com` with your actual domain. The domain must be hosted in CyberPanel (the webroot `/home/<domain>/public_html` must exist for `fix-ssl.sh`).

## Debugging

Check what `acme.sh` knows about your certificates:

```bash
acme.sh --list
```

Verify the certificate **actually served** by the web server (adjust host and port if needed):

```bash
openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null \
    | openssl x509 -noout -dates
```

The `notAfter` date should be within the next ~90 days for a valid Let's Encrypt certificate. If the served certificate is close to expiration, run `renew-ssl.sh example.com`, or `fix-ssl.sh example.com` to re-issue it from scratch.

Before changing anything, `./renew-ssl.sh --check` shows every certificate, its expiry date, and which ones would be renewed — useful to confirm the diagnosis first.

## Permissions

Both scripts need to be executable. Run from the directory containing the scripts:

```bash
chmod +x renew-ssl.sh fix-ssl.sh
```

Because they access `/root/.acme.sh/`, `/etc/letsencrypt/`, the site webroot and restart OpenLiteSpeed, they **must be run as `root`**. Do not run them as an unprivileged user.

## Automate with cron

To renew certificates automatically, add a cron job that calls `renew-ssl.sh` in auto mode. Edit the root crontab:

```bash
crontab -e
```

Add a single line (auto mode scans every domain):

```cron
0 3 * * 0 /root/cyberpanel-ssl-renewal-script/renew-ssl.sh >> /var/log/ssl-renew.log 2>&1
```

The line above runs every Sunday at 03:00 AM (server time) and appends the output to a log file so you can check what happened. Any certificate expiring within 10 days (the default threshold) gets renewed.

Tips:

- Run it daily if you prefer (`0 3 * * *`); the script only renews certificates whose expiry is within the threshold, so a daily run costs almost nothing.
- Adjust the threshold with an argument: `/root/cyberpanel-ssl-renewal-script/renew-ssl.sh 30`.
- Make sure the script has execute permission (`chmod +x renew-ssl.sh`); cron requires an absolute path and runs as root.

If a renewal ever fails, you can still run `fix-ssl.sh example.com` manually to re-issue the certificate from scratch.

## License

[MIT](LICENSE)
