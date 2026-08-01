#!/usr/bin/env bash

ACME="/root/.acme.sh/acme.sh"
ACME_HOME="/root/.acme.sh"
LSWS="/usr/local/lsws/bin/lswsctrl"

if [ ! -x "$ACME" ]; then
    echo "Erreur : acme.sh introuvable ($ACME)"
    exit 1
fi

if [ ! -d "$ACME_HOME" ]; then
    echo "Erreur : $ACME_HOME introuvable"
    exit 1
fi

# Résout le vrai nom de domaine et le flag ECC depuis un répertoire acme.sh
resolve_domain() {
    local dir_name="$1"
    if [[ "$dir_name" == *_ecc ]]; then
        DOMAIN_NAME="${dir_name%_ecc}"
        ECC_ARGS=(--ecc)
    else
        DOMAIN_NAME="$dir_name"
        ECC_ARGS=()
    fi
}

renew_one() {
    local dir_name="$1"
    resolve_domain "$dir_name"
    local cert_dir="/etc/letsencrypt/live/${DOMAIN_NAME}"

    echo "  -> renouvellement de ${DOMAIN_NAME} en cours..."

    mkdir -p "$cert_dir"

    if ! "$ACME" --renew -d "$DOMAIN_NAME" --force "${ECC_ARGS[@]}"; then
        echo "  -> ECHEC du renouvellement pour ${DOMAIN_NAME}"
        return 1
    fi

    if ! "$ACME" --install-cert \
        -d "$DOMAIN_NAME" \
        "${ECC_ARGS[@]}" \
        --key-file "$cert_dir/privkey.pem" \
        --fullchain-file "$cert_dir/fullchain.pem"; then
        echo "  -> ECHEC de l'installation pour ${DOMAIN_NAME}"
        return 1
    fi

    echo "  -> ${DOMAIN_NAME} renouvelé avec succès"
    return 0
}

# Mode domaine unique : ./renew-ssl.sh example.com
if [ -n "$1" ] && [ -d "$ACME_HOME/$1" ]; then
    if renew_one "$1"; then
        echo "Redémarrage d'OpenLiteSpeed..."
        "$LSWS" restart
    fi
    exit $?
fi

# Mode automatique : ./renew-ssl.sh [jours] (défaut : 10)
threshold="${1:-10}"
now_epoch=$(date +%s)
found=0
renewed=0
failed=0

shopt -s nullglob

echo "Recherche des certificats expirant dans moins de ${threshold} jours..."

for cert_dir in "$ACME_HOME"/*/; do
    dir_name=$(basename "$cert_dir")
    [ "$dir_name" = "acme.sh" ] && continue

    cert_file=$(ls "$cert_dir"*.cer 2>/dev/null | head -n1)
    [ -z "$cert_file" ] && continue

    end_date=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2-)
    [ -z "$end_date" ] && continue

    end_epoch=$(date -d "$end_date" +%s 2>/dev/null) || continue
    remaining=$(( (end_epoch - now_epoch) / 86400 ))

    resolve_domain "$dir_name"
    found=$((found + 1))
    echo "  [${DOMAIN_NAME}] expire dans ${remaining} jour(s)"

    if [ "$remaining" -le "$threshold" ]; then
        if renew_one "$dir_name"; then
            renewed=$((renewed + 1))
        else
            failed=$((failed + 1))
        fi
    fi
done

echo "Résumé : ${found} certificat(s) trouvé(s), ${renewed} renouvelé(s), ${failed} échec(s)."

if [ "$renewed" -gt 0 ]; then
    echo "Redémarrage d'OpenLiteSpeed..."
    "$LSWS" restart
fi
