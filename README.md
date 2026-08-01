# CyberPanel SSL Renewal Scripts

CyberPanel's built-in automatic SSL renewal has stopped working in some setups, so these two scripts perform the renewal directly with `acme.sh`, the ACME client used by CyberPanel.

## Scripts

### `renew-ssl.sh` — Renew certificates

Renews certificates that were previously issued and installed with `acme.sh`.

It supports two modes:

- **Auto mode (recommended):** scans all certificates registered in `acme.sh` and renews every one that expires within a configurable number of days (default: **10**).
- **Single domain mode:** renews one specific domain, ignoring expiry.

What it does for each certificate to renew:

1. **Renews the certificate** with `acme.sh --renew ... --force`. `--force` makes sure the renewal runs even if `acme.sh` thinks the certificate is still valid (useful to work around CyberPanel's broken scheduler).
2. **Installs the new certificate** into `/etc/letsencrypt/live/<domain>/` (`privkey.pem` and `fullchain.pem`), the location CyberPanel and LiteSpeed expect it.
3. **Restarts OpenLiteSpeed** once at the end (only if at least one certificate was renewed), so the new certificates are picked up.
4. ECC certificates (`<domain>_ecc` folders) are detected and renewed with the proper `--ecc` flag.

The expiry date is read from each certificate with `openssl x509`, so only certificates that really are close to expiring trigger a renewal.

### `fix-ssl.sh` — Issue a fresh certificate (full fix)

A more thorough, step-by-step fix that re-issues the certificate from scratch. Use this one when renewal fails or the certificate is in a broken/staging state.

What it does:

1. Switches `acme.sh` to the **Let's Encrypt production** CA (in case it was left in staging mode).
2. Removes any existing `acme.sh` registration for the domain (errors are ignored).
3. **Issues a new certificate** for `<domain>` and `www.<domain>` using the **webroot** method against `/home/<domain>/public_html`.
4. Creates `/etc/letsencrypt/live/<domain>/` and **installs** the certificate there.
5. Restarts OpenLiteSpeed to reload the certificate.
6. Prints the certificate validity dates as a final check.

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

# Single domain mode: renew a specific certificate
./renew-ssl.sh example.com

# Full re-issue / repair
./fix-ssl.sh example.com
```

Replace `example.com` with your actual domain. The domain must be hosted in CyberPanel (the webroot `/home/<domain>/public_html` must exist for `fix-ssl.sh`).

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
