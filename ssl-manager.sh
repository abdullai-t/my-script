#!/bin/bash
#
# SSL Manager - Automated Certificate Management for Bitnami Multisite
# Supports issue, renew, revoke, and auto Apache configuration linking
#

set -e

# ============================================================================
# Configuration
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config/settings.conf"
LOG_FILE="${SCRIPT_DIR}/logs/ssl-manager.log"
LOCK_FILE="${SCRIPT_DIR}/ssl-manager.lock"
DOMAINS_FILE="${SCRIPT_DIR}/certs/domains.list"

WEBROOT="/bitnami/wordpress"
CONFIG_DIR="/bitnami/wordpress/wp-content/certbot/config"
WORK_DIR="/bitnami/wordpress/wp-content/certbot/work"
LOGS_DIR="/bitnami/wordpress/wp-content/certbot/logs"
CERTBOT_PATH="/usr/bin/certbot"
APACHE_CONF_DIR="/opt/bitnami/apache2/conf/vhosts"
MAIN_SSL_CONF="/opt/bitnami/apache2/conf/bitnami/bitnami-ssl.conf"
APACHE_BIN="/opt/bitnami/ctlscript.sh"
LETSENCRYPT_EMAIL="admin@example.com"
CHALLENGE_METHOD="standalone"
RENEWAL_DAYS=30

# ============================================================================
# Helper Functions
# ============================================================================

log() {
  local level=$1; shift
  local message="$@"
  local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  echo "[${timestamp}] [${level}] ${message}" >> "$LOG_FILE"
  echo "[${level}] ${message}"
}

error_exit() {
  log ERROR "$1"
  cleanup
  exit 1
}

cleanup() {
  [ -f "$LOCK_FILE" ] && rm -f "$LOCK_FILE"
}

acquire_lock() {
  if [ -f "$LOCK_FILE" ]; then
    local lock_pid=$(cat "$LOCK_FILE")
    if ps -p "$lock_pid" > /dev/null 2>&1; then
      error_exit "Another instance running (PID: $lock_pid)"
    fi
    rm -f "$LOCK_FILE"
  fi
  echo $$ > "$LOCK_FILE"
}

validate_domain() {
  local domain=$1
  if [[ ! "$domain" =~ ^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$ ]]; then
    error_exit "Invalid domain: $domain"
  fi
}

create_directories() {
  mkdir -p "$CONFIG_DIR" "$WORK_DIR" "$LOGS_DIR"
  mkdir -p "$WEBROOT/.well-known/acme-challenge"
  mkdir -p "$APACHE_CONF_DIR"
  mkdir -p "$(dirname "$LOG_FILE")"
}

get_cert_expiry() {
  local domain=$1
  local cert_file="${CONFIG_DIR}/live/${domain}/cert.pem"
  [ -f "$cert_file" ] && openssl x509 -enddate -noout -in "$cert_file" | cut -d= -f2
}

days_until_expiry() {
  local domain=$1
  local expiry=$(get_cert_expiry "$domain")
  [ -z "$expiry" ] && echo 999 && return
  local expiry_epoch=$(date -d "$expiry" +%s)
  local now_epoch=$(date +%s)
  echo $(( (expiry_epoch - now_epoch) / 86400 ))
}

track_domain() {
  local domain=$1
  touch "$DOMAINS_FILE"
  grep -qx "$domain" "$DOMAINS_FILE" || echo "$domain" >> "$DOMAINS_FILE"
}

untrack_domain() {
  local domain=$1
  [ -f "$DOMAINS_FILE" ] && sed -i "/^${domain}$/d" "$DOMAINS_FILE"
}

link_certificate_to_apache() {
  local domain=$1
  local conf_file="${APACHE_CONF_DIR}/${domain}-ssl.conf"
  local cert_path="${CONFIG_DIR}/live/${domain}"

  log INFO "Linking certificate for $domain to Apache..."

  cat > "$conf_file" <<EOF
<VirtualHost *:443>
  ServerName $domain
  DocumentRoot "/opt/bitnami/wordpress"
  SSLEngine on
  SSLCertificateFile "$cert_path/cert.pem"
  SSLCertificateKeyFile "$cert_path/privkey.pem"
  SSLCertificateChainFile "$cert_path/chain.pem"
  <Directory "/opt/bitnami/wordpress">
    AllowOverride All
    Require all granted
  </Directory>
</VirtualHost>
EOF

  log INFO "SSL vhost created: $conf_file"

  if ! grep -q "$conf_file" "$MAIN_SSL_CONF"; then
    echo "Include \"$conf_file\"" >> "$MAIN_SSL_CONF"
  fi

  "$APACHE_BIN" reload apache
  log INFO "Apache reloaded"
}

remove_apache_link() {
  local domain=$1
  local conf_file="${APACHE_CONF_DIR}/${domain}-ssl.conf"
  if [ -f "$conf_file" ]; then
    rm -f "$conf_file"
    log INFO "Removed Apache vhost for $domain"
    sed -i "\|$conf_file|d" "$MAIN_SSL_CONF"
    "$APACHE_BIN" reload apache
  fi
}

# ============================================================================
# Certificate Operations
# ============================================================================

issue_certificate() {
  local domain=$1
  validate_domain "$domain"
  create_directories
  log INFO "Issuing certificate for $domain"

  "$CERTBOT_PATH" certonly --webroot -w "$WEBROOT" -d "$domain" \
    --email "$LETSENCRYPT_EMAIL" --agree-tos --non-interactive \
    --config-dir "$CONFIG_DIR" --work-dir "$WORK_DIR" --logs-dir "$LOGS_DIR"

  track_domain "$domain"
  link_certificate_to_apache "$domain"
  log INFO "Certificate issued and configured for $domain"
}

renew_all_certificates() {
  log INFO "Renewing all certificates..."
  "$CERTBOT_PATH" renew --config-dir "$CONFIG_DIR" --work-dir "$WORK_DIR" --logs-dir "$LOGS_DIR" --quiet
  "$APACHE_BIN" reload apache
}

revoke_certificate() {
  local domain=$1
  validate_domain "$domain"
  local cert_path="${CONFIG_DIR}/live/${domain}/cert.pem"
  [ ! -f "$cert_path" ] && error_exit "No certificate found for $domain"

  log INFO "Revoking certificate for $domain"
  "$CERTBOT_PATH" revoke --cert-path "$cert_path" --config-dir "$CONFIG_DIR" --work-dir "$WORK_DIR" --logs-dir "$LOGS_DIR" --non-interactive
  untrack_domain "$domain"
  remove_apache_link "$domain"
}

list_certificates() {
  [ ! -f "$DOMAINS_FILE" ] && { echo "No domains tracked."; return; }
  printf "%-30s %-25s %-10s\n" "DOMAIN" "EXPIRY" "DAYS LEFT"
  while read -r domain; do
    [ -z "$domain" ] && continue
    local expiry=$(get_cert_expiry "$domain")
    local days=$(days_until_expiry "$domain")
    printf "%-30s %-25s %-10s\n" "$domain" "$expiry" "$days"
  done < "$DOMAINS_FILE"
}

# ============================================================================
# Main Logic
# ============================================================================

show_usage() {
  echo "Usage: $(basename $0) [issue|renew-all|revoke|list] <domain>"
  echo
  echo "Examples:"
  echo "  $(basename $0) issue example.com"
  echo "  $(basename $0) renew-all"
  echo "  $(basename $0) revoke example.com"
  echo "  $(basename $0) list"
}

main() {
  [ $# -lt 1 ] && show_usage && exit 0
  acquire_lock
  trap cleanup EXIT

  local cmd=$1
  shift
  local domain=$1

  case "$cmd" in
    issue)
      [ -z "$domain" ] && error_exit "Domain required"
      issue_certificate "$domain"
      ;;
    renew-all)
      renew_all_certificates
      ;;
    revoke)
      [ -z "$domain" ] && error_exit "Domain required"
      revoke_certificate "$domain"
      ;;
    list)
      list_certificates
      ;;
    *)
      show_usage
      ;;
  esac
}

main "$@"
