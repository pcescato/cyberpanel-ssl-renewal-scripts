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

# Retourne le fichier du certificat feuille (celui du domaine), et non la CA
# ou la chaîne. Un répertoire acme.sh contient plusieurs .cer :
#   <domaine>.cer   -> certificat du domaine (feuille)  <-- celui qu'on veut
#   ca.cer          -> certificat de l'autorité (CA)      (ex. expire en 2028)
#   fullchain.cer   -> feuille + CA (chaîne complète)
# Sans ce tri, on peut lire la date d'expiration de la CA au lieu de celle du
# domaine et faussement écarter le certificat. On préfère donc <répertoire>.cer,
# puis fullchain.cer (openssl lit la feuille en premier), et en dernier recours
# tout .cer qui n'est ni la CA ni la chaîne. Utilise find (robuste espaces).
cert_file_in() {
    local cert_dir="$1"
    local dir_name file
    dir_name=${cert_dir%/}
    dir_name=${dir_name##*/}

    if [ -f "$cert_dir/$dir_name.cer" ]; then
        printf '%s\n' "$cert_dir/$dir_name.cer"
        return 0
    fi

    if [ -f "$cert_dir/fullchain.cer" ]; then
        printf '%s\n' "$cert_dir/fullchain.cer"
        return 0
    fi

    while IFS= read -r -d '' file; do
        case "${file##*/}" in
            ca.cer|chain.cer|fullchain.cer) continue ;;
        esac
        printf '%s\n' "$file"
        return 0
    done < <(find "$cert_dir" -maxdepth 1 -type f -name '*.cer' -print0 2>/dev/null || true)

    return 0
}

# Retourne le nombre de jours restants avant expiration (vide si erreur).
days_until_expiry() {
    local cert_file="$1"
    local end_date month day time year month_num end_epoch now_epoch remaining

    end_date=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null || true)
    end_date=${end_date#notAfter=}

    if [ -z "$end_date" ]; then
        warn "Impossible de lire la date d'expiration de : $cert_file"
        return 0
    fi

    # La sortie d'openssl a toujours le format fixe "Mmm DD HH:MM:SS YYYY GMT"
    # (mois en anglais, heure GMT), indépendamment de la locale du système.
    # On parse ces champs nous-mêmes puis on construit une date ISO-8601, dont
    # le parsing par `date -d` est fiable et identique sur toutes les locales
    # et versions de GNU date — contrairement au parsing direct de la chaîne
    # libre anglaise "Oct 29 22:00:54 2026 GMT", qui peut être mal interprétée
    # selon la locale/version (ex. "expire dans 763 jour(s)" au lieu de 89).
    read -r month day time year _ <<< "$end_date"

    case "$month" in
        Jan) month_num=01 ;; Feb) month_num=02 ;; Mar) month_num=03 ;;
        Apr) month_num=04 ;; May) month_num=05 ;; Jun) month_num=06 ;;
        Jul) month_num=07 ;; Aug) month_num=08 ;; Sep) month_num=09 ;;
        Oct) month_num=10 ;; Nov) month_num=11 ;; Dec) month_num=12 ;;
        *) warn "Mois inattendu ('$month') dans : $end_date"
           return 0 ;;
    esac

    if ! [[ "$day" =~ ^[0-9]{1,2}$ ]] || ! [[ "$time" =~ ^[0-9]{2}:[0-9]{2}:[0-9]{2}$ ]] \
        || ! [[ "$year" =~ ^[0-9]{4}$ ]]; then
        warn "Date d'expiration illisible : $end_date"
        return 0
    fi

    end_epoch=$(date -u -d "$year-$month_num-$day $time UTC" +%s 2>/dev/null || true)
    if [ -z "$end_epoch" ]; then
        warn "Impossible d'interpréter la date d'expiration : $end_date"
        return 0
    fi

    now_epoch=$(date +%s)
    remaining=$(( (end_epoch - now_epoch) / 86400 ))

    # Garde-fou : un certificat ACME (Let's Encrypt / ZeroSSL) est valable au
    # maximum ~90 jours. Une valeur dans plusieurs centaines de jours (ou un
    # passé lointain) trahit un calcul erroné : on ignore le certificat plutôt
    # que de le renouveler (ou de l'afficher) à tort.
    if [ "$remaining" -gt 400 ] || [ "$remaining" -lt -400 ]; then
        warn "Date d'expiration aberrante pour $cert_file : $end_date (${remaining} jour(s)) — certificat ignoré"
        return 0
    fi

    printf '%s\n' "$remaining"
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
