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
# AVANT de supprimer l'ancienne inscription (acme.sh --remove), le script
# sauvegarde le certificat existant et la configuration acme.sh dans
# /root/ssl-backups/<domain>/<timestamp>/.
#
# Dependencies: bash, acme.sh, tar, openssl (no others).

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

    # Guarded explicitly: under set -e bash does not run the ERR trap for a
    # failing command inside a function, it just makes the function return
    # non-zero and exits silently at the call site.
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

# Check webroot
if [ ! -d "$WEBROOT" ]; then
    echo "Erreur : webroot introuvable : $WEBROOT" >&2
    echo "Vérifie le chemin du site CyberPanel" >&2
    exit 1
fi

CURRENT_STEP="[1/7] Sauvegarde de l'ancien certificat"
echo "[1/7] Sauvegarde de l'ancien certificat"
backup_cert

CURRENT_STEP="[2/7] Passage sur Let's Encrypt production"
echo "[2/7] Passage sur Let's Encrypt production"
if ! "$ACME" --set-default-ca --server letsencrypt; then
    echo "Erreur : acme.sh n'a pas pu basculer sur le CA de production." >&2
    exit 1
fi

CURRENT_STEP="[3/7] Suppression éventuelle du mode staging"
echo "[3/7] Suppression éventuelle du mode staging"
"$ACME" --remove -d "$DOMAIN" >/dev/null 2>&1 || true

CURRENT_STEP="[4/7] Émission du certificat"
echo "[4/7] Émission du certificat"
if ! "$ACME" --issue \
    -d "$DOMAIN" \
    -d "www.$DOMAIN" \
    -w "$WEBROOT" \
    --force; then
    fail_after_remove "l'émission du certificat a échoué"
fi

CURRENT_STEP="[5/7] Installation du certificat"
echo "[5/7] Installation du certificat"
if ! { mkdir -p "$CERT_DIR" && "$ACME" --install-cert \
    -d "$DOMAIN" \
    --key-file "$CERT_DIR/privkey.pem" \
    --fullchain-file "$CERT_DIR/fullchain.pem" \
    --reloadcmd "$LSWS restart"; }; then
    fail_after_remove "l'installation du certificat a échoué"
fi

CURRENT_STEP="[6/7] Redémarrage OpenLiteSpeed"
echo "[6/7] Redémarrage OpenLiteSpeed"
if ! "$LSWS" restart; then
    echo "Erreur : le certificat est installé, mais OpenLiteSpeed n'a pas redémarré." >&2
    echo "Redémarrez-le manuellement : $LSWS restart" >&2
    exit 1
fi

CURRENT_STEP="[7/7] Vérification"
echo "[7/7] Vérification"
if ! openssl x509 \
    -in "$CERT_DIR/fullchain.pem" \
    -noout \
    -dates; then
    fail_after_remove "la vérification du certificat a échoué"
fi

echo
echo "SSL renouvelé avec succès pour ${DOMAIN}"
if [ -n "$ARCHIVE" ]; then
    echo
    echo "Sauvegarde de l'ancien certificat conservée :"
    echo "  ${ARCHIVE}"
    echo "Restauration manuelle si nécessaire :"
    echo "  tar -xzf ${ARCHIVE} -P -C / && ${LSWS} restart"
fi
