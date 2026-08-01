#!/usr/bin/env bash
#
# fix-ssl.sh — Ré-émet un certificat SSL pour CyberPanel via acme.sh.
#
# CyberPanel 2.x peut laisser acme.sh en mode staging ou avec un certificat
# cassé. Ce script re-émet un certificat de zéro : il bascule acme.sh sur le
# CA de production Let's Encrypt, supprime l'ancienne inscription du domaine,
# émet un nouveau certificat (HTTP-01 via le webroot), l'installe dans
# /etc/letsencrypt/live/<domain>/ puis redémarre OpenLiteSpeed.
#
# Avant d'émettre, il vérifie que le chemin du challenge HTTP-01 est
# réellement accessible publiquement. Après installation, il vérifie que le
# certificat réellement servi par le serveur correspond au nouveau certificat.
#
# AVANT de supprimer l'ancienne inscription (acme.sh --remove), le script
# sauvegarde le certificat existant et la configuration acme.sh dans
# /root/ssl-backups/<domain>/<timestamp>/.
#
# Dependencies: bash, acme.sh, tar, openssl, curl (curl est optionnel : la
# validation du webroot est ignorée avec un avertissement s'il est absent).

set -euo pipefail

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

DOMAIN="${1:-}"

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 domaine.tld"
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
        echo "Erreur lors de l'étape : ${CURRENT_STEP} (code ${rc})" >&2
    else
        echo "Erreur inattendue (code ${rc})" >&2
    fi
    exit "$rc"
}
trap 'report_error' ERR

# Fails a step that ran after the old acme.sh registration was removed.
# The pre-remove backup is the only way back, so its restore command is
# always printed.
fail_after_remove() {
    echo "Erreur : $*" >&2
    if [ -n "$ARCHIVE" ]; then
        echo "L'ancien certificat n'est pas perdu, il est sauvegardé :" >&2
        echo "  ${ARCHIVE}" >&2
        echo "Restauration : tar -xzf ${ARCHIVE} -P -C / && ${LSWS} restart" >&2
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
        echo "Erreur : webroot introuvable : $WEBROOT" >&2
        echo "Vérifie le chemin du site CyberPanel" >&2
        exit 1
    fi

    if ! command -v curl >/dev/null 2>&1; then
        echo "Avertissement : curl introuvable, validation du webroot ignorée." >&2
        return 0
    fi

    # Guarded explicitly: under set -e bash does not run the ERR trap for a
    # failing command inside a function, it just makes the function return
    # non-zero and exits silently at the call site.
    if ! mkdir -p "$challenge_dir"; then
        echo "Erreur : impossible de créer $challenge_dir (webroot non inscriptible ?)." >&2
        echo "Le challenge HTTP-01 ne pourra pas être servi : arrêt avant émission." >&2
        exit 1
    fi
    if ! printf '%s' "$test_token" > "$challenge_dir/$test_file"; then
        echo "Erreur : impossible d'écrire le fichier de test dans le webroot." >&2
        echo "Le challenge HTTP-01 ne pourra pas être servi : arrêt avant émission." >&2
        exit 1
    fi

    # -L mirrors Let's Encrypt, which follows HTTP->HTTPS redirects. -f makes
    # curl fail on any HTTP error. The content returned must match the token.
    response=$(curl -fsSL --connect-timeout 5 --max-time 20 "$url" 2>/dev/null) || response=""

    rm -f "$challenge_dir/$test_file" 2>/dev/null || true
    rmdir "$challenge_dir" 2>/dev/null || true
    rmdir "${WEBROOT}/.well-known" 2>/dev/null || true

    if [ "$response" != "$test_token" ]; then
        echo "Erreur : le challenge HTTP-01 n'est pas accessible publiquement." >&2
        echo "  URL testée : $url" >&2
        echo "Le fichier de test n'a pas été servi correctement (DNS, port 80," >&2
        echo "redirection ou réécriture du vhost). acme.sh échouerait lors de" >&2
        echo "l'émission : arrêt avant toute modification." >&2
        exit 1
    fi

    echo "Challenge HTTP-01 accessible : $url -> OK"
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
        echo "Aucun certificat existant à sauvegarder (première installation ?)."
        return 0
    fi

    if ! timestamp=$(date +%Y%m%d-%H%M%S); then
        echo "Erreur : date introuvable ou illisible." >&2
        echo "Aucune suppression ou remplacement n'a été effectué." >&2
        exit 1
    fi
    BACKUP_DIR="${BACKUP_ROOT}/${timestamp}"
    ARCHIVE="${BACKUP_DIR}/backup.tar.gz"

    echo "Creating backup before certificate replacement..."
    echo "Backup folder : ${BACKUP_DIR}"

    if ! mkdir -p "$BACKUP_DIR"; then
        echo "Erreur : impossible de créer le dossier de sauvegarde : $BACKUP_DIR" >&2
        echo "Aucune suppression ou remplacement n'a été effectué." >&2
        exit 1
    fi
    if ! tar -czf "$ARCHIVE" -P -C / "${source_dirs[@]}"; then
        echo "Erreur : échec de la création de la sauvegarde." >&2
        echo "Aucune suppression ou remplacement n'a été effectué." >&2
        exit 1
    fi

    echo "Sauvegarde créée : ${ARCHIVE}"
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
        echo "Erreur : impossible de lire le certificat local : $CERT_DIR/fullchain.pem" >&2
        fail_after_remove "la lecture du certificat local a échoué"
    fi
    local_fingerprint=$(normalize_fingerprint "$local_fingerprint")

    if command -v timeout >/dev/null 2>&1; then
        served_fingerprint=$(timeout 15 openssl s_client -connect "${DOMAIN}:443" -servername "$DOMAIN" </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null) || true
    else
        served_fingerprint=$(openssl s_client -connect "${DOMAIN}:443" -servername "$DOMAIN" </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null) || true
    fi
    served_fingerprint=$(normalize_fingerprint "$served_fingerprint")

    if [ -z "$served_fingerprint" ]; then
        echo "Erreur : impossible d'obtenir le certificat servi par ${DOMAIN}:443." >&2
        echo "OpenLiteSpeed sert peut-être encore l'ancien certificat, ou HTTPS est" >&2
        echo "injoignable. Redémarrez OpenLiteSpeed ($LSWS restart), puis relancez" >&2
        echo "$0 ${DOMAIN}." >&2
        exit 1
    fi

    if [ "$served_fingerprint" != "$local_fingerprint" ]; then
        echo "Erreur : OpenLiteSpeed sert encore l'ancien certificat." >&2
        echo "  Certificat local : $local_fingerprint" >&2
        echo "  Certificat servi : $served_fingerprint" >&2
        echo "Redémarrez OpenLiteSpeed ($LSWS restart), puis relancez $0 ${DOMAIN}." >&2
        exit 1
    fi

    echo "Le certificat réellement servi par ${DOMAIN} correspond au nouveau certificat (SHA256 identique)."
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

echo "======================================"
echo " Renouvellement SSL : ${DOMAIN}"
echo "======================================"

# Check acme.sh
if [ ! -x "$ACME" ]; then
    echo "Erreur : acme.sh introuvable" >&2
    exit 1
fi

# Check required tools
command -v openssl >/dev/null 2>&1 || { echo "Erreur : openssl introuvable" >&2; exit 1; }
command -v tar     >/dev/null 2>&1 || { echo "Erreur : tar introuvable" >&2; exit 1; }

CURRENT_STEP="[1/8] Vérification du challenge HTTP-01"
echo "[1/8] Vérification du challenge HTTP-01"
check_acme_challenge_path

CURRENT_STEP="[2/8] Sauvegarde de l'ancien certificat"
echo "[2/8] Sauvegarde de l'ancien certificat"
backup_cert

CURRENT_STEP="[3/8] Passage sur Let's Encrypt production"
echo "[3/8] Passage sur Let's Encrypt production"
if ! "$ACME" --set-default-ca --server letsencrypt; then
    echo "Erreur : acme.sh n'a pas pu basculer sur le CA de production." >&2
    exit 1
fi

CURRENT_STEP="[4/8] Suppression éventuelle du mode staging"
echo "[4/8] Suppression éventuelle du mode staging"
"$ACME" --remove -d "$DOMAIN" >/dev/null 2>&1 || true

CURRENT_STEP="[5/8] Émission du certificat"
echo "[5/8] Émission du certificat"
if ! "$ACME" --issue \
    -d "$DOMAIN" \
    -d "www.$DOMAIN" \
    -w "$WEBROOT" \
    --force; then
    fail_after_remove "l'émission du certificat a échoué"
fi

CURRENT_STEP="[6/8] Installation du certificat"
echo "[6/8] Installation du certificat"
if ! { mkdir -p "$CERT_DIR" && "$ACME" --install-cert \
    -d "$DOMAIN" \
    --key-file "$CERT_DIR/privkey.pem" \
    --fullchain-file "$CERT_DIR/fullchain.pem" \
    --reloadcmd "$LSWS restart"; }; then
    fail_after_remove "l'installation du certificat a échoué"
fi

CURRENT_STEP="[7/8] Redémarrage OpenLiteSpeed"
echo "[7/8] Redémarrage OpenLiteSpeed"
if ! "$LSWS" restart; then
    echo "Erreur : le certificat est installé, mais OpenLiteSpeed n'a pas redémarré." >&2
    echo "Redémarrez-le manuellement : $LSWS restart" >&2
    exit 1
fi

CURRENT_STEP="[8/8] Vérification du certificat servi"
echo "[8/8] Vérification du certificat servi"
if ! openssl x509 \
    -in "$CERT_DIR/fullchain.pem" \
    -noout \
    -dates; then
    fail_after_remove "la vérification du certificat local a échoué"
fi
verify_served_certificate

echo
echo "SSL renouvelé avec succès pour ${DOMAIN}"
if [ -n "$ARCHIVE" ]; then
    echo
    echo "Sauvegarde de l'ancien certificat conservée :"
    echo "  ${ARCHIVE}"
    echo "Restauration manuelle si nécessaire :"
    echo "  tar -xzf ${ARCHIVE} -P -C / && ${LSWS} restart"
fi
