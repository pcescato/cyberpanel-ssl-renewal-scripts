#!/usr/bin/env bash
#
# renew-ssl.sh — CyberPanel SSL certificate renewal via acme.sh.
#
# CyberPanel 2.x ships an SSL renewal scheduler that can break. This script
# bypasses it by calling acme.sh directly.
#
# Renewed certificates are installed into
# /etc/letsencrypt/live/<domain>/ (privkey.pem + fullchain.pem), the location
# expected by CyberPanel and OpenLiteSpeed.
#
# Dependencies: bash, acme.sh, openssl, date, find (no others).

set -euo pipefail

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

ACME="${ACME:-/root/.acme.sh/acme.sh}"        # ACME client (acme.sh)
ACME_HOME="${ACME_HOME:-/root/.acme.sh}"      # certificate registrations
LSWS="${LSWS:-/usr/local/lsws/bin/lswsctrl}"  # OpenLiteSpeed control
CERT_BASE="${CERT_BASE:-/etc/letsencrypt/live}"  # CyberPanel target directory
DEFAULT_THRESHOLD=10                          # expiry window (days)

MODE=auto
SIMULATION=0
THRESHOLD="$DEFAULT_THRESHOLD"
DOMAIN=""

# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------

log() { printf '[renew-ssl][%s] %s\n' "$(date '+%F %T')" "$*"; }

warn() { printf '[renew-ssl][%s][WARN] %s\n' "$(date '+%F %T')" "$*" >&2; }

die() {
    printf '[renew-ssl][ERROR] %s\n' "$*" >&2
    exit 1
}

# --------------------------------------------------------------------------
# Help and argument handling
# --------------------------------------------------------------------------

usage() {
    cat <<'EOF'
Usage:
  renew-ssl.sh [OPTIONS] [ARG]

Modes:
  renew-ssl.sh                 Auto mode: renews certificates that expire
                               within the next 10 days.
  renew-ssl.sh <days>          Auto mode with a custom threshold.
  renew-ssl.sh <domain>        Single domain mode: forces renewal of a
                               specific domain (RSA or ECC).
  renew-ssl.sh --check         Simulation: lists the certificates and shows
                               which ones would be renewed, without changing
                               anything or restarting OpenLiteSpeed.

Options:
  -h, --help                   Shows this help.

Examples:
  renew-ssl.sh
  renew-ssl.sh 30
  renew-ssl.sh example.com
  renew-ssl.sh --check

Environment variables (optional):
  ACME, ACME_HOME, LSWS, CERT_BASE   Custom paths.
EOF
}

# Parse the arguments and set MODE / SIMULATION / THRESHOLD / DOMAIN.
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
            die "Unknown option: $1" $'\n'"Use -h or --help for help."
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
        die "Invalid threshold: $THRESHOLD (a positive integer is expected)"
    fi
}

# --------------------------------------------------------------------------
# Pre-flight checks
# --------------------------------------------------------------------------

verify_prereqs() {
    [ -x "$ACME" ] || die "acme.sh not found or not executable: $ACME"
    [ -d "$ACME_HOME" ] || die "acme.sh directory not found: $ACME_HOME"
    command -v openssl >/dev/null 2>&1 || die "openssl not found"
    command -v date    >/dev/null 2>&1 || die "date not found"
    command -v find    >/dev/null 2>&1 || die "find not found"
}

# --------------------------------------------------------------------------
# Certificate helpers
# --------------------------------------------------------------------------

# Returns the real domain name from an acme.sh directory
# (strips the _ecc suffix of ECC certificates).
domain_name() {
    local dir_name="$1"
    if [[ "$dir_name" == *_ecc ]]; then
        printf '%s\n' "${dir_name%_ecc}"
    else
        printf '%s\n' "$dir_name"
    fi
}

# Returns the leaf certificate file (the domain one), not the CA or the
# chain. An acme.sh directory contains several .cer files:
#   <domain>.cer   -> the domain certificate (leaf)  <-- the one we want
#   ca.cer          -> the CA certificate              (e.g. valid until 2028)
#   fullchain.cer   -> leaf + CA (full chain)
# Without this filtering, the CA expiry date may be read instead of the
# domain's and the certificate wrongly skipped. We prefer <directory>.cer,
# then fullchain.cer (openssl reads the leaf first), and as a last resort any
# .cer that is neither the CA nor the chain. Uses find (space-safe).
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

# Returns the number of days remaining before expiry (empty on error).
days_until_expiry() {
    local cert_file="$1"
    local end_date month day time year month_num end_epoch now_epoch remaining

    end_date=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null || true)
    end_date=${end_date#notAfter=}

    if [ -z "$end_date" ]; then
        warn "Cannot read the expiry date from: $cert_file"
        return 0
    fi

    # openssl output always uses the fixed format "Mmm DD HH:MM:SS YYYY GMT"
    # (English months, GMT time), regardless of the system locale.
    # We parse these fields ourselves and build an ISO-8601 date, whose
    # parsing by `date -d` is reliable and identical across all locales and
    # GNU date versions — unlike directly parsing the free-form English string
    # "Oct 29 22:00:54 2026 GMT", which can be misread depending on
    # locale/version (e.g. "expires in 763 days" instead of 89).
    read -r month day time year _ <<< "$end_date"

    case "$month" in
        Jan) month_num=01 ;; Feb) month_num=02 ;; Mar) month_num=03 ;;
        Apr) month_num=04 ;; May) month_num=05 ;; Jun) month_num=06 ;;
        Jul) month_num=07 ;; Aug) month_num=08 ;; Sep) month_num=09 ;;
        Oct) month_num=10 ;; Nov) month_num=11 ;; Dec) month_num=12 ;;
        *) warn "Unexpected month ('$month') in: $end_date"
           return 0 ;;
    esac

    if ! [[ "$day" =~ ^[0-9]{1,2}$ ]] || ! [[ "$time" =~ ^[0-9]{2}:[0-9]{2}:[0-9]{2}$ ]] \
        || ! [[ "$year" =~ ^[0-9]{4}$ ]]; then
        warn "Unreadable expiry date: $end_date"
        return 0
    fi

    end_epoch=$(date -u -d "$year-$month_num-$day $time UTC" +%s 2>/dev/null || true)
    if [ -z "$end_epoch" ]; then
        warn "Cannot interpret the expiry date: $end_date"
        return 0
    fi

    now_epoch=$(date +%s)
    remaining=$(( (end_epoch - now_epoch) / 86400 ))

    # Safety net: an ACME certificate (Let's Encrypt / ZeroSSL) is valid for
    # at most ~90 days. A value several hundred days away (or far in the past)
    # signals a bad calculation: skip the certificate instead of renewing (or
    # displaying) it wrongly.
    if [ "$remaining" -gt 400 ] || [ "$remaining" -lt -400 ]; then
        warn "Abnormal expiry date for $cert_file: $end_date (${remaining} day(s)) — certificate skipped"
        return 0
    fi

    printf '%s\n' "$remaining"
}

# --------------------------------------------------------------------------
# Renewing a certificate
# --------------------------------------------------------------------------

# Renews a certificate (one acme.sh directory = one certificate).
# In simulation mode (--check), does not change anything.
renew_one() {
    local dir_name="$1"
    local domain
    local ecc_args=()
    local cert_dir

    domain=$(domain_name "$dir_name")
    [[ "$dir_name" == *_ecc ]] && ecc_args=(--ecc)
    cert_dir="$CERT_BASE/$domain"

    if [ "$SIMULATION" -eq 1 ]; then
        log "(simulation) $domain: would be renewed — no change made"
        return 0
    fi

    log "Renewing $domain..."

    # --force is intentional: CyberPanel's built-in renewal scheduler is
    # unreliable, so we force re-issuance as soon as we decide a renewal is
    # needed (expiry window exceeded in auto mode, or explicit request in
    # single-domain mode).
    if ! "$ACME" --renew -d "$domain" --force "${ecc_args[@]}"; then
        warn "Renewal failed for $domain"
        return 1
    fi

    mkdir -p "$cert_dir"

    if ! "$ACME" --install-cert \
        -d "$domain" \
        "${ecc_args[@]}" \
        --key-file "$cert_dir/privkey.pem" \
        --fullchain-file "$cert_dir/fullchain.pem"; then
        warn "Installation failed for $domain"
        return 1
    fi

    log "$domain renewed successfully"
    return 0
}

# --------------------------------------------------------------------------
# OpenLiteSpeed restart
# --------------------------------------------------------------------------

# Restarts OpenLiteSpeed only if the binary is present and executable.
restart_ols() {
    if [ ! -x "$LSWS" ]; then
        warn "OpenLiteSpeed not found or not executable: $LSWS"
        warn "Certificates installed, but OpenLiteSpeed was not restarted."
        return 1
    fi
    log "Restarting OpenLiteSpeed..."
    "$LSWS" restart
}

# Single restart, only if at least one certificate was renewed.
# Never restarts in simulation mode. Sets the RESTART_STATUS variable to
# "yes", "no", "no (simulation)" or "failed".
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
# Final summary
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
# Execution modes
# --------------------------------------------------------------------------

# Auto mode: scans all certificates and renews those whose expiry falls
# within the threshold window.
run_auto_mode() {
    local threshold="$1"
    local checked=0 needing=0 renewed=0 failed=0
    local cert_dir dir_name cert_file remaining domain
    local rc=0

    log "Searching for certificates expiring within ${threshold} day(s)..."

    shopt -s nullglob
    for cert_dir in "$ACME_HOME"/*/; do
        # Directory reserved for the acme.sh client itself.
        dir_name=${cert_dir%/}
        dir_name=${dir_name##*/}
        [ "$dir_name" = "acme.sh" ] && continue

        cert_file=$(cert_file_in "$cert_dir")
        [ -n "$cert_file" ] || continue

        remaining=$(days_until_expiry "$cert_file")
        [ -n "$remaining" ] || continue

        checked=$((checked + 1))
        domain=$(domain_name "$dir_name")
        printf '  - %s (expires in %s day(s))\n' "$domain" "$remaining"

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

# Single-domain mode: forces the renewal of a specific domain.
# Works with an RSA certificate (<domain>) and/or ECC (<domain>_ecc).
run_single_domain_mode() {
    local domain="$1"
    local dir_list=()
    local dir_name
    local checked=0 needing=0 renewed=0 failed=0
    local rc=0

    [ -d "$ACME_HOME/$domain" ] && dir_list+=("$domain")
    [ -d "$ACME_HOME/${domain}_ecc" ] && dir_list+=("${domain}_ecc")

    if [ "${#dir_list[@]}" -eq 0 ]; then
        die "No certificate found for $domain in $ACME_HOME" \
            $'\n'"Check the domain name, or use --check to list the certificates."
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
# Entry point
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
