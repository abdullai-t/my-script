#!/bin/bash
#
# SSL Manager - Certificate Management Script for Lightsail/Bitnami
# Usage: ssl-manager.sh [command] [domain] [options]
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

# Default settings (can be overridden by config file)
WEBROOT="/bitnami/wordpress"
CONFIG_DIR="/bitnami/wordpress/wp-content/certbot/config"
WORK_DIR="/bitnami/wordpress/wp-content/certbot/work"
LOGS_DIR="/bitnami/wordpress/wp-content/certbot/logs"
CERTBOT_PATH="/usr/bin/certbot"
LETSENCRYPT_EMAIL=""
CHALLENGE_METHOD="webroot"
RENEWAL_DAYS=30
DRY_RUN=false
JSON_OUTPUT=false
BACKUP_CERTS=true

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ============================================================================
# Helper Functions
# ============================================================================

log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}" >> "$LOG_FILE"
    
    if [ "$JSON_OUTPUT" = false ]; then
        case $level in
            ERROR)
                echo -e "${RED}[ERROR]${NC} ${message}" >&2
                ;;
            SUCCESS)
                echo -e "${GREEN}[SUCCESS]${NC} ${message}"
                ;;
            WARN)
                echo -e "${YELLOW}[WARN]${NC} ${message}"
                ;;
            INFO)
                echo -e "${BLUE}[INFO]${NC} ${message}"
                ;;
            *)
                echo "[${level}] ${message}"
                ;;
        esac
    fi
}

json_output() {
    local success=$1
    local domain=$2
    local action=$3
    local message=$4
    local expiry=${5:-""}
    local cert_path=${6:-""}
    
    cat <<EOF
{
  "success": ${success},
  "domain": "${domain}",
  "action": "${action}",
  "message": "${message}",
  "expiry": "${expiry}",
  "cert_path": "${cert_path}",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
}

error_exit() {
    local message=$1
    local exit_code=${2:-1}
    log ERROR "$message"
    
    if [ "$JSON_OUTPUT" = true ]; then
        json_output false "${DOMAIN:-unknown}" "${ACTION:-unknown}" "$message"
    fi
    
    cleanup
    exit $exit_code
}

cleanup() {
    if [ -f "$LOCK_FILE" ]; then
        rm -f "$LOCK_FILE"
    fi
}

acquire_lock() {
    if [ -f "$LOCK_FILE" ]; then
        local lock_pid=$(cat "$LOCK_FILE")
        if ps -p "$lock_pid" > /dev/null 2>&1; then
            error_exit "Another instance is running (PID: $lock_pid)" 6
        else
            log WARN "Stale lock file found, removing..."
            rm -f "$LOCK_FILE"
        fi
    fi
    echo $$ > "$LOCK_FILE"
}

validate_domain() {
    local domain=$1
    if [[ ! "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
        error_exit "Invalid domain format: $domain" 2
    fi
}

validate_email() {
    local email=$1
    if [[ ! "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        error_exit "Invalid email format: $email" 2
    fi
}

check_dependencies() {
    log INFO "Checking dependencies..."
    
    if [ ! -f "$CERTBOT_PATH" ]; then
        error_exit "Certbot not found at $CERTBOT_PATH" 10
    fi
    
    if [ ! -d "$WEBROOT" ]; then
        error_exit "Webroot directory not found: $WEBROOT" 10
    fi
    
    if [ -z "$LETSENCRYPT_EMAIL" ]; then
        error_exit "LETSENCRYPT_EMAIL not configured" 10
    fi
    
    validate_email "$LETSENCRYPT_EMAIL"
}

create_directories() {
    log INFO "Creating necessary directories..."
    mkdir -p "$CONFIG_DIR" "$WORK_DIR" "$LOGS_DIR"
    mkdir -p "${WEBROOT}/.well-known/acme-challenge"
    mkdir -p "$(dirname "$LOG_FILE")"
    mkdir -p "$(dirname "$DOMAINS_FILE")"
    chmod -R 755 "${WEBROOT}/.well-known"
}

check_dns() {
    local domain=$1
    log INFO "Checking DNS for $domain..."
    
    local server_ip=$(curl -s ifconfig.me)
    local dns_ip=$(dig +short "$domain" | tail -n1)
    
    if [ -z "$dns_ip" ]; then
        log WARN "DNS lookup failed for $domain"
        return 1
    fi
    
    if [ "$dns_ip" != "$server_ip" ]; then
        log WARN "DNS mismatch: $domain points to $dns_ip, but server IP is $server_ip"
        return 1
    fi
    
    log SUCCESS "DNS check passed for $domain"
    return 0
}

check_port() {
    local port=$1
    log INFO "Checking if port $port is available..."
    
    if netstat -tuln | grep -q ":${port} "; then
        log SUCCESS "Port $port is open"
        return 0
    else
        log WARN "Port $port is not accessible"
        return 1
    fi
}

backup_certificate() {
    local domain=$1
    
    if [ "$BACKUP_CERTS" = false ]; then
        return 0
    fi
    
    local cert_dir="${CONFIG_DIR}/live/${domain}"
    
    if [ -d "$cert_dir" ]; then
        local backup_dir="${CONFIG_DIR}/backup/${domain}_$(date +%Y%m%d_%H%M%S)"
        log INFO "Backing up existing certificate to $backup_dir"
        mkdir -p "$backup_dir"
        cp -r "$cert_dir" "$backup_dir/"
        log SUCCESS "Certificate backed up"
    fi
}

get_cert_expiry() {
    local domain=$1
    local cert_file="${CONFIG_DIR}/live/${domain}/cert.pem"
    
    if [ -f "$cert_file" ]; then
        openssl x509 -enddate -noout -in "$cert_file" | cut -d= -f2
    else
        echo ""
    fi
}

days_until_expiry() {
    local domain=$1
    local expiry=$(get_cert_expiry "$domain")
    
    if [ -z "$expiry" ]; then
        echo "999"
        return
    fi
    
    local expiry_epoch=$(date -d "$expiry" +%s)
    local now_epoch=$(date +%s)
    local days=$(( ($expiry_epoch - $now_epoch) / 86400 ))
    echo "$days"
}

track_domain() {
    local domain=$1
    touch "$DOMAINS_FILE"
    if ! grep -q "^${domain}$" "$DOMAINS_FILE"; then
        echo "$domain" >> "$DOMAINS_FILE"
    fi
}

untrack_domain() {
    local domain=$1
    if [ -f "$DOMAINS_FILE" ]; then
        sed -i "/^${domain}$/d" "$DOMAINS_FILE"
    fi
}

# ============================================================================
# Certificate Operations
# ============================================================================

issue_certificate() {
    local domain=$1
    
    log INFO "Issuing certificate for $domain..."
    validate_domain "$domain"
    check_dependencies
    create_directories
    
    # Pre-flight checks
    if [ "$CHALLENGE_METHOD" = "webroot" ]; then
        check_dns "$domain" || log WARN "DNS check failed, continuing anyway..."
        check_port 80 || log WARN "Port 80 check failed, continuing anyway..."
    fi
    
    # Build certbot command
    local cmd="$CERTBOT_PATH certonly"
    
    case "$CHALLENGE_METHOD" in
        standalone)
            cmd="$cmd --standalone"
            ;;
        dns)
            cmd="$cmd --manual --preferred-challenges dns"
            ;;
        webroot|*)
            cmd="$cmd --webroot -w $WEBROOT"
            ;;
    esac
    
    cmd="$cmd -d $domain"
    cmd="$cmd --email $LETSENCRYPT_EMAIL"
    cmd="$cmd --agree-tos"
    cmd="$cmd --non-interactive"
    cmd="$cmd --config-dir $CONFIG_DIR"
    cmd="$cmd --work-dir $WORK_DIR"
    cmd="$cmd --logs-dir $LOGS_DIR"
    
    if [ "$DRY_RUN" = true ]; then
        cmd="$cmd --dry-run"
        log INFO "Running in dry-run mode"
    fi
    
    log INFO "Executing: $cmd"
    
    # Execute certbot
    local output
    local exit_code=0
    output=$(eval "$cmd" 2>&1) || exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        local expiry=$(get_cert_expiry "$domain")
        local cert_path="${CONFIG_DIR}/live/${domain}"
        
        track_domain "$domain"
        log SUCCESS "Certificate issued successfully for $domain"
        
        if [ "$JSON_OUTPUT" = true ]; then
            json_output true "$domain" "issue" "Certificate issued successfully" "$expiry" "$cert_path"
        fi
        
        return 0
    else
        log ERROR "Failed to issue certificate: $output"
        
        if [ "$JSON_OUTPUT" = true ]; then
            json_output false "$domain" "issue" "Failed to issue certificate: $output"
        fi
        
        return 4
    fi
}

renew_certificate() {
    local domain=$1
    
    log INFO "Renewing certificate for $domain..."
    validate_domain "$domain"
    check_dependencies
    
    backup_certificate "$domain"
    
    local cmd="$CERTBOT_PATH renew"
    cmd="$cmd --cert-name $domain"
    cmd="$cmd --config-dir $CONFIG_DIR"
    cmd="$cmd --work-dir $WORK_DIR"
    cmd="$cmd --logs-dir $LOGS_DIR"
    cmd="$cmd --non-interactive"
    
    if [ "$DRY_RUN" = true ]; then
        cmd="$cmd --dry-run"
        log INFO "Running in dry-run mode"
    fi
    
    log INFO "Executing: $cmd"
    
    local output
    local exit_code=0
    output=$(eval "$cmd" 2>&1) || exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        local expiry=$(get_cert_expiry "$domain")
        local cert_path="${CONFIG_DIR}/live/${domain}"
        
        log SUCCESS "Certificate renewed successfully for $domain"
        
        if [ "$JSON_OUTPUT" = true ]; then
            json_output true "$domain" "renew" "Certificate renewed successfully" "$expiry" "$cert_path"
        fi
        
        return 0
    else
        log ERROR "Failed to renew certificate: $output"
        
        if [ "$JSON_OUTPUT" = true ]; then
            json_output false "$domain" "renew" "Failed to renew certificate: $output"
        fi
        
        return 4
    fi
}

renew_all_certificates() {
    log INFO "Renewing all certificates..."
    
    if [ ! -f "$DOMAINS_FILE" ]; then
        log WARN "No domains tracked"
        return 0
    fi
    
    local renewed=0
    local failed=0
    
    while IFS= read -r domain; do
        [ -z "$domain" ] && continue
        
        local days=$(days_until_expiry "$domain")
        
        if [ "$days" -le "$RENEWAL_DAYS" ]; then
            log INFO "Certificate for $domain expires in $days days, renewing..."
            
            if renew_certificate "$domain"; then
                ((renewed++))
            else
                ((failed++))
            fi
        else
            log INFO "Certificate for $domain expires in $days days, skipping..."
        fi
    done < "$DOMAINS_FILE"
    
    log INFO "Renewal complete. Renewed: $renewed, Failed: $failed"
    
    if [ "$JSON_OUTPUT" = true ]; then
        json_output true "all" "renew-all" "Renewed: $renewed, Failed: $failed"
    fi
}

revoke_certificate() {
    local domain=$1
    
    log INFO "Revoking certificate for $domain..."
    validate_domain "$domain"
    check_dependencies
    
    backup_certificate "$domain"
    
    local cert_path="${CONFIG_DIR}/live/${domain}/cert.pem"
    
    if [ ! -f "$cert_path" ]; then
        error_exit "Certificate not found for $domain" 4
    fi
    
    local cmd="$CERTBOT_PATH revoke"
    cmd="$cmd --cert-path $cert_path"
    cmd="$cmd --config-dir $CONFIG_DIR"
    cmd="$cmd --work-dir $WORK_DIR"
    cmd="$cmd --logs-dir $LOGS_DIR"
    cmd="$cmd --non-interactive"
    
    if [ "$DRY_RUN" = true ]; then
        log INFO "Would revoke certificate for $domain (dry-run)"
        return 0
    fi
    
    log INFO "Executing: $cmd"
    
    local output
    local exit_code=0
    output=$(eval "$cmd" 2>&1) || exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        untrack_domain "$domain"
        log SUCCESS "Certificate revoked successfully for $domain"
        
        if [ "$JSON_OUTPUT" = true ]; then
            json_output true "$domain" "revoke" "Certificate revoked successfully"
        fi
        
        return 0
    else
        log ERROR "Failed to revoke certificate: $output"
        
        if [ "$JSON_OUTPUT" = true ]; then
            json_output false "$domain" "revoke" "Failed to revoke certificate: $output"
        fi
        
        return 4
    fi
}

list_certificates() {
    log INFO "Listing all managed certificates..."
    
    if [ ! -f "$DOMAINS_FILE" ]; then
        log WARN "No domains tracked"
        return 0
    fi
    
    if [ "$JSON_OUTPUT" = true ]; then
        echo "{"
        echo '  "domains": ['
        local first=true
        while IFS= read -r domain; do
            [ -z "$domain" ] && continue
            
            local expiry=$(get_cert_expiry "$domain")
            local days=$(days_until_expiry "$domain")
            local status="unknown"
            
            if [ -z "$expiry" ]; then
                status="not_issued"
            elif [ "$days" -lt 0 ]; then
                status="expired"
            elif [ "$days" -le 7 ]; then
                status="expiring_soon"
            else
                status="valid"
            fi
            
            if [ "$first" = false ]; then
                echo ","
            fi
            first=false
            
            echo -n "    {"
            echo -n '"domain": "'"$domain"'", '
            echo -n '"expiry": "'"$expiry"'", '
            echo -n '"days_until_expiry": '"$days"', '
            echo -n '"status": "'"$status"'"'
            echo -n "}"
        done < "$DOMAINS_FILE"
        echo ""
        echo "  ]"
        echo "}"
    else
        printf "%-30s %-20s %-15s %s\n" "DOMAIN" "EXPIRY" "DAYS LEFT" "STATUS"
        printf "%-30s %-20s %-15s %s\n" "------" "------" "---------" "------"
        
        while IFS= read -r domain; do
            [ -z "$domain" ] && continue
            
            local expiry=$(get_cert_expiry "$domain")
            local days=$(days_until_expiry "$domain")
            
            if [ -z "$expiry" ]; then
                printf "%-30s %-20s %-15s %s\n" "$domain" "N/A" "N/A" "Not issued"
            elif [ "$days" -lt 0 ]; then
                printf "%-30s %-20s %-15s %s\n" "$domain" "$expiry" "$days" "EXPIRED"
            elif [ "$days" -le 7 ]; then
                printf "%-30s %-20s %-15s %s\n" "$domain" "$expiry" "$days" "EXPIRING SOON"
            else
                printf "%-30s %-20s %-15s %s\n" "$domain" "$expiry" "$days" "Valid"
            fi
        done < "$DOMAINS_FILE"
    fi
}

status_certificate() {
    local domain=$1
    
    validate_domain "$domain"
    
    local expiry=$(get_cert_expiry "$domain")
    local days=$(days_until_expiry "$domain")
    local cert_path="${CONFIG_DIR}/live/${domain}"
    
    if [ -z "$expiry" ]; then
        if [ "$JSON_OUTPUT" = true ]; then
            json_output false "$domain" "status" "Certificate not found"
        else
            log ERROR "Certificate not found for $domain"
        fi
        return 1
    fi
    
    if [ "$JSON_OUTPUT" = true ]; then
        json_output true "$domain" "status" "Certificate found" "$expiry" "$cert_path"
    else
        echo "Domain: $domain"
        echo "Expiry: $expiry"
        echo "Days until expiry: $days"
        echo "Certificate path: $cert_path"
    fi
}

# ============================================================================
# Main Function
# ============================================================================

show_usage() {
    cat <<EOF
SSL Manager - Certificate Management Script

Usage: $(basename $0) [command] [domain] [options]

Commands:
  issue <domain>       Issue a new certificate
  renew <domain>       Renew an existing certificate
  renew-all            Renew all certificates expiring within $RENEWAL_DAYS days
  revoke <domain>      Revoke a certificate
  list                 List all managed certificates
  status <domain>      Show certificate status
  test <domain>        Test certificate issuance (dry-run)

Options:
  --json               Output in JSON format
  --dry-run            Perform dry-run (test mode)
  --help               Show this help message

Examples:
  $(basename $0) issue example.com
  $(basename $0) renew example.com --json
  $(basename $0) list
  $(basename $0) test example.com

Configuration: $CONFIG_FILE
Logs: $LOG_FILE
EOF
}

main() {
    # Load configuration if exists
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    fi
    
    # Parse arguments
    if [ $# -eq 0 ]; then
        show_usage
        exit 0
    fi
    
    local command=$1
    shift
    
    # Parse options
    while [[ $# -gt 0 ]]; do
        case $1 in
            --json)
                JSON_OUTPUT=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                DOMAIN=$1
                shift
                ;;
        esac
    done
    
    ACTION=$command
    
    # Acquire lock
    acquire_lock
    trap cleanup EXIT
    
    # Execute command
    case $command in
        issue)
            if [ -z "$DOMAIN" ]; then
                error_exit "Domain required for issue command" 2
            fi
            issue_certificate "$DOMAIN"
            ;;
        renew)
            if [ -z "$DOMAIN" ]; then
                error_exit "Domain required for renew command" 2
            fi
            renew_certificate "$DOMAIN"
            ;;
        renew-all)
            renew_all_certificates
            ;;
        revoke)
            if [ -z "$DOMAIN" ]; then
                error_exit "Domain required for revoke command" 2
            fi
            revoke_certificate "$DOMAIN"
            ;;
        list)
            list_certificates
            ;;
        status)
            if [ -z "$DOMAIN" ]; then
                error_exit "Domain required for status command" 2
            fi
            status_certificate "$DOMAIN"
            ;;
        test)
            if [ -z "$DOMAIN" ]; then
                error_exit "Domain required for test command" 2
            fi
            DRY_RUN=true
            issue_certificate "$DOMAIN"
            ;;
        *)
            error_exit "Unknown command: $command" 2
            ;;
    esac
}

# Run main function
main "$@"
