#!/usr/bin/env bash
#
# fix-ssl.sh — Re-issues an SSL certificate for CyberPanel via acme.sh.
#
# CyberPanel 2.x can leave acme.sh in staging mode or with a broken
# certificate. This script re-issues the certificate from scratch: it switches
# acme.sh to the Let's Encrypt production CA, removes the previous domain
# registration, issues a new certificate (HTTP-01 via the webroot), installs
# it in /etc/letsencrypt/live/<domain>/ and restarts OpenLiteSpeed.
#
# Before issuing, it checks that the HTTP-01 challenge path is actually
# reachable from the public internet. After installation, it checks that the
# certificate really served by the server matches the new certificate.
#
# BEFORE removing the previous registration (acme.sh --remove), the script
# backs up the existing certificate and acme.sh configuration in
# /root/ssl-backups/<domain>/<timestamp>/.
#
# Dependencies: bash, acme.sh, tar, openssl, curl (curl is optional: the
# webroot validation is skipped with a warning if it is absent).

set -euo pipefail

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

DOMAIN="${1:-}"

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 domain.tld"
    exit 1
fi

ACME="/root/.acme.sh/acme.sh"
ACME_HOME="/root/.acme.sh"
WEBROOT="/home/${DOMAIN}/public_html"
CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
LSWS="/usr/local/lsws/bin/lswsctrl"

BACKUP_ROOT="/root/ssl-backups/${DOMAIN}"
BACKUP_DIR=""   # set by backup_cert()
ARCHIVE=""      # set by backup_cert()
CURRENT_STEP=""

# --------------------------------------------------------------------------
# Error reporting
# --------------------------------------------------------------------------

# Last-resort handler for set -e: reports the step that failed and exits.
report_error() {
    local rc=$?
    if [ -n "$CURRENT_STEP" ]; then
        echo "Error during step: ${CURRENT_STEP} (code ${rc})" >&2
    else
        echo "Unexpected error (code ${rc})" >&2
    fi
    exit "$rc"
}
trap 'report_error' ERR

# Fails a step that ran after the old acme.sh registration was removed.
# The pre-remove backup is the only way back, so its restore command is
# always printed.
fail_after_remove() {
    echo "Error: $*" >&2
    if [ -n "$ARCHIVE" ]; then
        echo "The previous certificate is not lost, it is backed up at:" >&2
        echo "  ${ARCHIVE}" >&2
        echo "Restore: tar -xzf ${ARCHIVE} -P -C / && ${LSWS} restart" >&2
    fi
    exit 1
}

# --------------------------------------------------------------------------
# Webroot validation (HTTP-01 challenge reachability)
# --------------------------------------------------------------------------

# Verifies that the HTTP-01 challenge path will be reachable from the public
# internet before calling acme.sh. Writes a random test file in the webroot
# and fetches it over plain HTTP with curl (mirroring what Let's Encrypt will
# do during issuance). Stops the script before any acme.sh call if the file
# is not served correctly. curl is optional: if absent the check is skipped
# with a warning.
check_acme_challenge_path() {
    local challenge_dir="${WEBROOT}/.well-known/acme-challenge"
    local test_file="acme-test-${DOMAIN}-$$-${RANDOM}"
    local test_token="ok-${test_file}"
    local url="http://${DOMAIN}/.well-known/acme-challenge/${test_file}"
    local response=""

    if [ ! -d "$WEBROOT" ]; then
        echo "Error: webroot not found: $WEBROOT" >&2
        echo "Check the CyberPanel site path" >&2
        exit 1
    fi

    if ! command -v curl >/dev/null 2>&1; then
        echo "Warning: curl not found, webroot validation skipped." >&2
        return 0
    fi

    # Guarded explicitly: under set -e bash does not run the ERR trap for a
    # failing command inside a function, it just makes the function return
    # non-zero and exits silently at the call site.
    if ! mkdir -p "$challenge_dir"; then
        echo "Error: cannot create $challenge_dir (webroot not writable?)." >&2
        echo "The HTTP-01 challenge cannot be served: stopping before issuance." >&2
        exit 1
    fi
    if ! printf '%s' "$test_token" > "$challenge_dir/$test_file"; then
        echo "Error: cannot write the test file into the webroot." >&2
        echo "The HTTP-01 challenge cannot be served: stopping before issuance." >&2
        exit 1
    fi

    # -L mirrors Let's Encrypt, which follows HTTP->HTTPS redirects. -f makes
    # curl fail on any HTTP error. The content returned must match the token.
    response=$(curl -fsSL --connect-timeout 5 --max-time 20 "$url" 2>/dev/null) || response=""

    rm -f "$challenge_dir/$test_file" 2>/dev/null || true
    rmdir "$challenge_dir" 2>/dev/null || true
    rmdir "${WEBROOT}/.well-known" 2>/dev/null || true

    if [ "$response" != "$test_token" ]; then
        echo "Error: the HTTP-01 challenge is not publicly reachable." >&2
        echo "  Tested URL: $url" >&2
        echo "The test file was not served correctly (DNS, port 80," >&2
        echo "vhost redirect or rewrite). acme.sh would fail during" >&2
        echo "issuance: stopping before any modification." >&2
        exit 1
    fi

    echo "HTTP-01 challenge reachable: $url -> OK"
}

# --------------------------------------------------------------------------
# Backup (before any destructive operation)
# --------------------------------------------------------------------------

# Creates a timestamped backup of the existing acme.sh registration (RSA
# and/or ECC) and of the installed certificate in /etc/letsencrypt, so the
# previous working state can always be restored:
#   tar -xzf backup.tar.gz -P -C / && /usr/local/lsws/bin/lswsctrl restart
# tar is used with absolute paths (-P). Nothing is removed or replaced until
# this backup is safely in place.
backup_cert() {
    local timestamp
    local source_dirs=()
    local item

    for item in \
        "${ACME_HOME}/${DOMAIN}" \
        "${ACME_HOME}/${DOMAIN}_ecc" \
        "${CERT_DIR}"; do
        [ -e "$item" ] && source_dirs+=("$item")
    done

    if [ "${#source_dirs[@]}" -eq 0 ]; then
        echo "No existing certificate to back up (first installation?)."
        return 0
    fi

    if ! timestamp=$(date +%Y%m%d-%H%M%S); then
        echo "Error: date missing or unreadable." >&2
        echo "No removal or replacement has been performed." >&2
        exit 1
    fi
    BACKUP_DIR="${BACKUP_ROOT}/${timestamp}"
    ARCHIVE="${BACKUP_DIR}/backup.tar.gz"

    echo "Creating backup before certificate replacement..."
    echo "Backup folder : ${BACKUP_DIR}"

    if ! mkdir -p "$BACKUP_DIR"; then
        echo "Error: cannot create the backup folder: $BACKUP_DIR" >&2
        echo "No removal or replacement has been performed." >&2
        exit 1
    fi
    if ! tar -czf "$ARCHIVE" -P -C / "${source_dirs[@]}"; then
        echo "Error: failed to create the backup." >&2
        echo "No removal or replacement has been performed." >&2
        exit 1
    fi

    echo "Backup created: ${ARCHIVE}"
}

# --------------------------------------------------------------------------
# Post-installation verification (served certificate)
# --------------------------------------------------------------------------

# Normalizes an openssl fingerprint ("SHA256 Fingerprint=AB:CD:.." or
# "sha256 Fingerprint=..") into plain uppercase hex so that comparisons are
# independent of the OpenSSL version / label casing.
normalize_fingerprint() {
    printf '%s\n' "$1" | sed 's/^.*=//' | tr -d ':' | tr 'a-f' 'A-F'
}

# Verifies that the certificate actually served by the server matches the
# newly installed one. Compares the SHA256 fingerprint of the local
# certificate with the one presented by the server over HTTPS. A mismatch
# means OpenLiteSpeed is probably still serving the previous certificate.
verify_served_certificate() {
    local local_fingerprint=""
    local served_fingerprint=""

    if ! local_fingerprint=$(openssl x509 -in "$CERT_DIR/fullchain.pem" -noout -fingerprint -sha256 2>/dev/null); then
        echo "Error: cannot read the local certificate: $CERT_DIR/fullchain.pem" >&2
        fail_after_remove "reading the local certificate failed"
    fi
    local_fingerprint=$(normalize_fingerprint "$local_fingerprint")

    if command -v timeout >/dev/null 2>&1; then
        served_fingerprint=$(timeout 15 openssl s_client -connect "${DOMAIN}:443" -servername "$DOMAIN" </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null) || true
    else
        served_fingerprint=$(openssl s_client -connect "${DOMAIN}:443" -servername "$DOMAIN" </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null) || true
    fi
    served_fingerprint=$(normalize_fingerprint "$served_fingerprint")

    if [ -z "$served_fingerprint" ]; then
        echo "Error: cannot obtain the certificate served by ${DOMAIN}:443." >&2
        echo "OpenLiteSpeed may still be serving the previous certificate, or" >&2
        echo "HTTPS is unreachable. Restart OpenLiteSpeed ($LSWS restart)," >&2
        echo "then run $0 ${DOMAIN}." >&2
        exit 1
    fi

    if [ "$served_fingerprint" != "$local_fingerprint" ]; then
        echo "Error: OpenLiteSpeed is still serving the previous certificate." >&2
        echo "  Local certificate: $local_fingerprint" >&2
        echo "  Served certificate: $served_fingerprint" >&2
        echo "Restart OpenLiteSpeed ($LSWS restart), then run $0 ${DOMAIN}." >&2
        exit 1
    fi

    echo "The certificate actually served by ${DOMAIN} matches the new certificate (identical SHA256)."
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

echo "======================================"
echo " SSL Renewal: ${DOMAIN}"
echo "======================================"

# Check acme.sh
if [ ! -x "$ACME" ]; then
    echo "Error: acme.sh not found" >&2
    exit 1
fi

# Check required tools
command -v openssl >/dev/null 2>&1 || { echo "Error: openssl not found" >&2; exit 1; }
command -v tar     >/dev/null 2>&1 || { echo "Error: tar not found" >&2; exit 1; }

CURRENT_STEP="[1/8] HTTP-01 challenge check"
echo "[1/8] HTTP-01 challenge check"
check_acme_challenge_path

CURRENT_STEP="[2/8] Backup of the previous certificate"
echo "[2/8] Backup of the previous certificate"
backup_cert

CURRENT_STEP="[3/8] Switch to Let's Encrypt production"
echo "[3/8] Switch to Let's Encrypt production"
if ! "$ACME" --set-default-ca --server letsencrypt; then
    echo "Error: acme.sh could not switch to the production CA." >&2
    exit 1
fi

CURRENT_STEP="[4/8] Remove any staging mode registration"
echo "[4/8] Remove any staging mode registration"
"$ACME" --remove -d "$DOMAIN" >/dev/null 2>&1 || true

CURRENT_STEP="[5/8] Issue the certificate"
echo "[5/8] Issue the certificate"
if ! "$ACME" --issue \
    -d "$DOMAIN" \
    -d "www.$DOMAIN" \
    -w "$WEBROOT" \
    --force; then
    fail_after_remove "certificate issuance failed"
fi

CURRENT_STEP="[6/8] Install the certificate"
echo "[6/8] Install the certificate"
if ! { mkdir -p "$CERT_DIR" && "$ACME" --install-cert \
    -d "$DOMAIN" \
    --key-file "$CERT_DIR/privkey.pem" \
    --fullchain-file "$CERT_DIR/fullchain.pem" \
    --reloadcmd "$LSWS restart"; }; then
    fail_after_remove "certificate installation failed"
fi

CURRENT_STEP="[7/8] Restart OpenLiteSpeed"
echo "[7/8] Restart OpenLiteSpeed"
if ! "$LSWS" restart; then
    echo "Error: the certificate is installed, but OpenLiteSpeed did not restart." >&2
    echo "Restart it manually: $LSWS restart" >&2
    exit 1
fi

CURRENT_STEP="[8/8] Verify the served certificate"
echo "[8/8] Verify the served certificate"
if ! openssl x509 \
    -in "$CERT_DIR/fullchain.pem" \
    -noout \
    -dates; then
    fail_after_remove "verifying the local certificate failed"
fi
verify_served_certificate

echo
echo "SSL successfully renewed for ${DOMAIN}"
if [ -n "$ARCHIVE" ]; then
    echo
    echo "Backup of the previous certificate kept:"
    echo "  ${ARCHIVE}"
    echo "Manual restore if needed:"
    echo "  tar -xzf ${ARCHIVE} -P -C / && ${LSWS} restart"
fi
