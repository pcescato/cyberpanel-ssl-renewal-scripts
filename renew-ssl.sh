#!/usr/bin/env bash
#
# renew-ssl.sh — Renouvellement des certificats SSL CyberPanel via acme.sh.
#
# CyberPanel 2.x embarque un scheduler de renouvellement SSL qui peut tomber
# en panne. Ce script contourne ce scheduler en appelant acme.sh directement.
#
# Les certificats renouvelés sont installés dans
# /etc/letsencrypt/live/<domaine>/ (privkey.pem + fullchain.pem), l'emplacement
# attendu par CyberPanel et OpenLiteSpeed.
#
# Dépendances : bash, acme.sh, openssl, date, find (aucune autre).

set -euo pipefail

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

ACME="${ACME:-/root/.acme.sh/acme.sh}"        # client ACME (acme.sh)
ACME_HOME="${ACME_HOME:-/root/.acme.sh}"      # registres des certificats
LSWS="${LSWS:-/usr/local/lsws/bin/lswsctrl}"  # contrôle OpenLiteSpeed
CERT_BASE="${CERT_BASE:-/etc/letsencrypt/live}"  # dossier cible CyberPanel
DEFAULT_THRESHOLD=10                          # fenêtre d'expiration (jours)

MODE=auto
SIMULATION=0
THRESHOLD="$DEFAULT_THRESHOLD"
DOMAIN=""

# --------------------------------------------------------------------------
# Journalisation
# --------------------------------------------------------------------------

log() { printf '[renew-ssl][%s] %s\n' "$(date '+%F %T')" "$*"; }

warn() { printf '[renew-ssl][%s][WARN] %s\n' "$(date '+%F %T')" "$*" >&2; }

die() {
    printf '[renew-ssl][ERREUR] %s\n' "$*" >&2
    exit 1
}

# --------------------------------------------------------------------------
# Aide et gestion des arguments
# --------------------------------------------------------------------------

usage() {
    cat <<'EOF'
Usage:
  renew-ssl.sh [OPTIONS] [ARG]

Modes :
  renew-ssl.sh                 Mode auto : renouvelle les certificats qui
                               expirent dans les 10 prochains jours.
  renew-ssl.sh <jours>         Mode auto avec seuil personnalisé.
  renew-ssl.sh <domaine>       Mode domaine unique : force le renouvellement
                               d'un domaine précis (RSA ou ECC).
  renew-ssl.sh --check         Simulation : liste les certificats et indique
                               lesquels seraient renouvelés, sans rien
                               modifier ni redémarrer OpenLiteSpeed.

Options :
  -h, --help                   Affiche cette aide.

Exemples :
  renew-ssl.sh
  renew-ssl.sh 30
  renew-ssl.sh example.com
  renew-ssl.sh --check

Variables d'environnement (optionnelles) :
  ACME, ACME_HOME, LSWS, CERT_BASE   Chemins personnalisés.
EOF
}

# Parse les arguments et définit MODE / SIMULATION / THRESHOLD / DOMAIN.
parse_args() {
    case "${1:-}" in
        '')
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --check)
            SIMULATION=1
            ;;
        -*)
            die "Option inconnue : $1" $'\n'"Utilisez -h ou --help pour l'aide."
            ;;
        *[!0-9]*)
            MODE=single
            DOMAIN="$1"
            ;;
        *)
            THRESHOLD="$1"
            ;;
    esac

    if ! [[ "$THRESHOLD" =~ ^[0-9]+$ ]]; then
        die "Seuil invalide : $THRESHOLD (entier positif attendu)"
    fi
}

# --------------------------------------------------------------------------
# Vérifications préalables
# --------------------------------------------------------------------------

verify_prereqs() {
    [ -x "$ACME" ] || die "acme.sh introuvable ou non exécutable : $ACME"
    [ -d "$ACME_HOME" ] || die "Dossier acme.sh introuvable : $ACME_HOME"
    command -v openssl >/dev/null 2>&1 || die "openssl introuvable"
    command -v date    >/dev/null 2>&1 || die "date introuvable"
    command -v find    >/dev/null 2>&1 || die "find introuvable"
}

# --------------------------------------------------------------------------
# Helpers sur les certificats
# --------------------------------------------------------------------------

# Retourne le vrai nom de domaine depuis un répertoire acme.sh
# (enlève le suffixe _ecc des certificats ECC).
domain_name() {
    local dir_name="$1"
    if [[ "$dir_name" == *_ecc ]]; then
        printf '%s\n' "${dir_name%_ecc}"
    else
        printf '%s\n' "$dir_name"
    fi
}

# Retourne le premier fichier .cer d'un répertoire de certificat.
# Utilise find (robuste avec les espaces) plutôt que "ls | head".
cert_file_in() {
    local cert_dir="$1"
    find "$cert_dir" -maxdepth 1 -type f -name '*.cer' -print -quit 2>/dev/null || true
}

# Retourne le nombre de jours restants avant expiration (vide si erreur).
days_until_expiry() {
    local cert_file="$1"
    local end_date end_epoch now_epoch

    end_date=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null \
        | cut -d= -f2- || true)
    [ -n "$end_date" ] || return 0

    end_epoch=$(date -d "$end_date" +%s 2>/dev/null || true)
    [ -n "$end_epoch" ] || return 0

    now_epoch=$(date +%s)
    printf '%s\n' "$(( (end_epoch - now_epoch) / 86400 ))"
}

# --------------------------------------------------------------------------
# Renouvellement d'un certificat
# --------------------------------------------------------------------------

# Renouvelle un certificat (un répertoire acme.sh = un certificat).
# En simulation (--check), n'effectue aucun changement.
renew_one() {
    local dir_name="$1"
    local domain
    local ecc_args=()
    local cert_dir

    domain=$(domain_name "$dir_name")
    [[ "$dir_name" == *_ecc ]] && ecc_args=(--ecc)
    cert_dir="$CERT_BASE/$domain"

    if [ "$SIMULATION" -eq 1 ]; then
        log "(simulation) $domain : serait renouvelé — aucun changement effectué"
        return 0
    fi

    log "Renouvellement de $domain en cours..."

    # --force est volontaire : le scheduler de renouvellement intégré à
    # CyberPanel est défaillant, on force donc la réémission dès qu'on a
    # décidé qu'un renouvellement était nécessaire (fenêtre d'expiration
    # dépassée en mode auto, ou demande explicite en mode domaine unique).
    if ! "$ACME" --renew -d "$domain" --force "${ecc_args[@]}"; then
        warn "Échec du renouvellement pour $domain"
        return 1
    fi

    mkdir -p "$cert_dir"

    if ! "$ACME" --install-cert \
        -d "$domain" \
        "${ecc_args[@]}" \
        --key-file "$cert_dir/privkey.pem" \
        --fullchain-file "$cert_dir/fullchain.pem"; then
        warn "Échec de l'installation pour $domain"
        return 1
    fi

    log "$domain renouvelé avec succès"
    return 0
}

# --------------------------------------------------------------------------
# Redémarrage OpenLiteSpeed
# --------------------------------------------------------------------------

# Redémarre OpenLiteSpeed uniquement si le binaire est présent et exécutable.
restart_ols() {
    if [ ! -x "$LSWS" ]; then
        warn "OpenLiteSpeed introuvable ou non exécutable : $LSWS"
        warn "Certificats installés, mais OpenLiteSpeed n'a pas été redémarré."
        return 1
    fi
    log "Redémarrage d'OpenLiteSpeed..."
    "$LSWS" restart
}

# Restart unique, uniquement si au moins un certificat a été renouvelé.
# En simulation, ne redémarre jamais. Positionne la variable RESTART_STATUS
# à "yes", "no", "no (simulation)" ou "failed".
restart_ols_if_needed() {
    local renewed="$1"

    RESTART_STATUS="no"
    [ "$SIMULATION" -eq 1 ] && RESTART_STATUS="no (simulation)"

    if [ "$SIMULATION" -eq 1 ] || [ "$renewed" -eq 0 ]; then
        return 0
    fi

    if restart_ols; then
        RESTART_STATUS="yes"
    else
        RESTART_STATUS="failed"
    fi
}

# --------------------------------------------------------------------------
# Résumé final
# --------------------------------------------------------------------------

summary() {
    local checked="$1" needing="$2" renewed="$3" failed="$4"
    local restart_status="$5"

    printf '\n=====================================\n'
    printf 'Certificates checked: %s\n' "$checked"
    printf 'Certificates needing renewal: %s\n' "$needing"
    printf 'Successfully renewed: %s\n' "$renewed"
    printf 'Failed: %s\n' "$failed"
    printf 'OpenLiteSpeed restart: %s\n' "$restart_status"
    printf '=====================================\n'
}

# --------------------------------------------------------------------------
# Modes d'exécution
# --------------------------------------------------------------------------

# Mode automatique : scanne tous les certificats et renouvelle ceux dont
# l'expiration tombe dans la fenêtre définie par le seuil.
run_auto_mode() {
    local threshold="$1"
    local checked=0 needing=0 renewed=0 failed=0
    local cert_dir dir_name cert_file remaining domain
    local rc=0

    log "Recherche des certificats expirant dans moins de ${threshold} jour(s)..."

    shopt -s nullglob
    for cert_dir in "$ACME_HOME"/*/; do
        # Dossier réservé au client acme.sh lui-même.
        dir_name=${cert_dir%/}
        dir_name=${dir_name##*/}
        [ "$dir_name" = "acme.sh" ] && continue

        cert_file=$(cert_file_in "$cert_dir")
        [ -n "$cert_file" ] || continue

        remaining=$(days_until_expiry "$cert_file")
        [ -n "$remaining" ] || continue

        checked=$((checked + 1))
        domain=$(domain_name "$dir_name")
        printf '  - %s (expire dans %s jour(s))\n' "$domain" "$remaining"

        if [ "$remaining" -le "$threshold" ]; then
            needing=$((needing + 1))
            if renew_one "$dir_name"; then
                renewed=$((renewed + 1))
            else
                failed=$((failed + 1))
            fi
        fi
    done

    restart_ols_if_needed "$renewed"
    [ "$RESTART_STATUS" = "failed" ] && rc=1
    summary "$checked" "$needing" "$renewed" "$failed" "$RESTART_STATUS"

    if [ "$failed" -gt 0 ] || [ "$rc" -ne 0 ]; then
        exit 1
    fi
    exit 0
}

# Mode domaine unique : force le renouvellement d'un domaine précis.
# Fonctionne avec un certificat RSA (<domaine>) et/ou ECC (<domaine>_ecc).
run_single_domain_mode() {
    local domain="$1"
    local dir_list=()
    local dir_name
    local checked=0 needing=0 renewed=0 failed=0
    local rc=0

    [ -d "$ACME_HOME/$domain" ] && dir_list+=("$domain")
    [ -d "$ACME_HOME/${domain}_ecc" ] && dir_list+=("${domain}_ecc")

    if [ "${#dir_list[@]}" -eq 0 ]; then
        die "Aucun certificat trouvé pour $domain dans $ACME_HOME" \
            $'\n'"Vérifiez le nom de domaine, ou utilisez --check pour lister les certificats."
    fi

    for dir_name in "${dir_list[@]}"; do
        checked=$((checked + 1))
        needing=$((needing + 1))
        if renew_one "$dir_name"; then
            renewed=$((renewed + 1))
        else
            failed=$((failed + 1))
        fi
    done

    restart_ols_if_needed "$renewed"
    [ "$RESTART_STATUS" = "failed" ] && rc=1
    summary "$checked" "$needing" "$renewed" "$failed" "$RESTART_STATUS"

    if [ "$failed" -gt 0 ] || [ "$rc" -ne 0 ]; then
        exit 1
    fi
    exit 0
}

# --------------------------------------------------------------------------
# Point d'entrée
# --------------------------------------------------------------------------

main() {
    parse_args "$@"
    verify_prereqs

    if [ "$MODE" = "single" ]; then
        run_single_domain_mode "$DOMAIN"
    else
        run_auto_mode "$THRESHOLD"
    fi
}

main "$@"
