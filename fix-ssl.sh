#!/usr/bin/env bash

set -e

DOMAIN="$1"

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 domaine.tld"
    exit 1
fi

ACME="/root/.acme.sh/acme.sh"
WEBROOT="/home/${DOMAIN}/public_html"
CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"

echo "======================================"
echo " Renouvellement SSL : ${DOMAIN}"
echo "======================================"

# Vérification acme.sh
if [ ! -x "$ACME" ]; then
    echo "Erreur : acme.sh introuvable"
    exit 1
fi

# Vérification webroot
if [ ! -d "$WEBROOT" ]; then
    echo "Erreur : webroot introuvable : $WEBROOT"
    echo "Vérifie le chemin du site CyberPanel"
    exit 1
fi

echo "[1/6] Passage sur Let's Encrypt production"
$ACME --set-default-ca --server letsencrypt

echo "[2/6] Suppression éventuelle du mode staging"
$ACME --remove -d "$DOMAIN" >/dev/null 2>&1 || true

echo "[3/6] Émission du certificat"

$ACME --issue \
    -d "$DOMAIN" \
    -d "www.$DOMAIN" \
    -w "$WEBROOT" \
    --force

echo "[4/6] Installation du certificat"

mkdir -p "$CERT_DIR"

$ACME --install-cert \
    -d "$DOMAIN" \
    --key-file "$CERT_DIR/privkey.pem" \
    --fullchain-file "$CERT_DIR/fullchain.pem" \
    --reloadcmd "/usr/local/lsws/bin/lswsctrl restart"

echo "[5/6] Redémarrage OpenLiteSpeed"

/usr/local/lsws/bin/lswsctrl restart

echo "[6/6] Vérification"

openssl x509 \
    -in "$CERT_DIR/fullchain.pem" \
    -noout \
    -dates

echo
echo "SSL renouvelé avec succès pour $DOMAIN"
