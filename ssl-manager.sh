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
CHALLENGE_METHOD="standalone"
RENEWAL_DAYS=30
DRY_RUN=false
JSON_OUTPUT=false
BACKUP_CERTS=true
SKIP_DNS_CHECK=false
SKIP_WEBROOT_CHECK=false
AUTO_APACHE_RESTART=true
APACHE_CTL="/opt/bitnami/ctlscript.sh"
APACHE_VHOSTS_DIR="/opt/bitnami/apache2/conf/vhosts"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Track if we stopped Apache
APACHE_WAS_STOPPED=false

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
    # Restart Apache if we stopped it
    if [ "$APACHE_WAS_STOPPED" = true ] && [ "$AUTO_APACHE_RESTART" = true ]; then
        log INFO "Restarting Apache..."
        $APACHE_CTL start apache >/dev/null 2>&1 || true
    fi
    
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
    
    if [ "$CHALLENGE_METHOD" = "webroot" ] && [ ! -d "$WEBROOT" ]; then
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
    
    if [ "$CHALLENGE_METHOD" = "webroot" ]; then
        mkdir -p "${WEBROOT}/.well-known/acme-challenge"
        chmod -R 755 "${WEBROOT}/.well-known"
    fi
    
    mkdir -p "$(dirname "$LOG_FILE")"
    mkdir -p "$(dirname "$DOMAINS_FILE")"
}

stop_apache() {
    if [ "$CHALLENGE_METHOD" != "standalone" ]; then
        return 0
    fi
    
    if [ "$AUTO_APACHE_RESTART" = false ]; then
        log WARN "AUTO_APACHE_RESTART is disabled, Apache must be stopped manually"
        return 0
    fi
    
    log INFO "Stopping Apache for standalone mode..."
    
    if $APACHE_CTL status apache >/dev/null 2>&1; then
        $APACHE_CTL stop apache >/dev/null 2>&1 || {
            log WARN "Failed to stop Apache cleanly, trying force stop..."
            killall httpd 2>/dev/null || true
        }
        APACHE_WAS_STOPPED=true
        sleep 2
        log SUCCESS "Apache stopped"
    else
        log INFO "Apache already stopped"
    fi
}

start_apache() {
    if [ "$APACHE_WAS_STOPPED" = true ] && [ "$AUTO_APACHE_RESTART" = true ]; then
        log INFO "Starting Apache..."
        $APACHE_CTL start apache >/dev/null 2>&1 || {
            log ERROR "Failed to start Apache"
            return 1
        }
        sleep 2
        log SUCCESS "Apache started"
        APACHE_WAS_STOPPED=false
    fi
}

check_webroot_access() {
    local domain=$1
    
    if [ "$CHALLENGE_METHOD" != "webroot" ]; then
        return 0
    fi
    
    if [ "$SKIP_WEBROOT_CHECK" = true ]; then
        log INFO "Skipping webroot access check (SKIP_WEBROOT_CHECK=true)"
        return 0
    fi
    
    log INFO "Testing webroot access for $domain..."
    
    local test_file="${WEBROOT}/.well-known/acme-challenge/test-$(date +%s).txt"
    local test_content="certbot-test-$(date +%s)"
    
    echo "$test_content" > "$test_file" 2>/dev/null || {
        log ERROR "Cannot write to ${WEBROOT}/.well-known/acme-challenge/"
        return 1
    }
    
    chmod 644 "$test_file"
    sleep 1
    
    local response=$(curl -s --max-time 10 -L "http://${domain}/.well-known/acme-challenge/$(basename $test_file)" 2>/dev/null)
    rm -f "$test_file"
    
    if [ "$response" = "$test_content" ]; then
        log SUCCESS "Webroot access test passed"
        return 0
    else
        log WARN "Webroot access test failed - switching to standalone mode"
        CHALLENGE_METHOD="standalone"
        return 1
    fi
}

check_dns() {
    local domain=$1
    
    if [ "$SKIP_DNS_CHECK" = true ]; then
        log INFO "Skipping DNS check (SKIP_DNS_CHECK=true)"
        return 0
    fi
    
    log INFO "Checking DNS for $domain..."
    
    local server_ip=$(curl -4 -s --max-time 10 ifconfig.me 2>/dev/null)
    
    if [ -z "$server_ip" ]; then
        log WARN "Could not determine server IP address"
        return 1
    fi
    
    local dns_ip=$(dig +short "$domain" A 2>/dev/null | grep -E '^[0-9.]+$' | head -n1)
    
    if [ -z "$dns_ip" ]; then
        log WARN "DNS lookup failed for $domain (no A record found)"
        return 1
    fi
    
    if [ "$dns_ip" != "$server_ip" ]; then
        log WARN "DNS mismatch: $domain points to $dns_ip, but server IP is $server_ip"
        return 1
    fi
    
    log SUCCESS "DNS check passed for $domain (IP: $server_ip)"
    return 0
}

check_port() {
    local port=$1
    log INFO "Checking if port $port is available..."
    
    if netstat -tuln 2>/dev/null | grep -q ":${port} "; then
        log SUCCESS "Port $port is open"
        return 0
    elif ss -tuln 2>/dev/null | grep -q ":${port} "; then
        log SUCCESS "Port $port is open"
        return 0
    else
        log WARN "Port $port may not be accessible"
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
        openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null | cut -d= -f2
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
    
    local expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null)
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

create_ssl_vhost() {
    local domain=$1
    local vhost_file="${APACHE_VHOSTS_DIR}/${domain}-ssl.conf"
    local ssl_conf="/opt/bitnami/apache2/conf/bitnami/bitnami-ssl.conf"
    local include_line="IncludeOptional /opt/bitnami/apache2/conf/vhosts/${domain}-ssl.conf"
    
    log INFO "Creating SSL VirtualHost configuration for $domain..."
    
    # Create vhosts directory if it doesn't exist
    if [ ! -d "$APACHE_VHOSTS_DIR" ]; then
        mkdir -p "$APACHE_VHOSTS_DIR"
    fi
    
    # Create the SSL VirtualHost configuration
    cat > "$vhost_file" <<EOF
<VirtualHost *:443>
  ServerName ${domain}
  DocumentRoot "/opt/bitnami/wordpress"

  SSLEngine on
  SSLCertificateFile "/bitnami/wordpress/wp-content/certbot/config/live/${domain}/cert.pem"
  SSLCertificateKeyFile "/bitnami/wordpress/wp-content/certbot/config/live/${domain}/privkey.pem"
  SSLCertificateChainFile "/bitnami/wordpress/wp-content/certbot/config/live/${domain}/chain.pem"

  # Force HTTPS redirect
  RewriteEngine On
  RewriteCond %{HTTPS} !=on
  RewriteRule ^/(.*) https://%{SERVER_NAME}/\$1 [R,L]

  <Directory "/opt/bitnami/wordpress">
    Options -Indexes +FollowSymLinks -MultiViews
    AllowOverride All
    Require all granted
    
    # WordPress Multisite rules
    RewriteEngine On
    RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
    RewriteBase /
    RewriteRule ^index\.php\$ - [L]
    
    # add a trailing slash to /wp-admin
    RewriteRule ^wp-admin\$ wp-admin/ [R=301,L]
    
    RewriteCond %{REQUEST_FILENAME} -f [OR]
    RewriteCond %{REQUEST_FILENAME} -d
    RewriteRule ^ - [L]
    RewriteRule ^(wp-(content|admin|includes).*) \$1 [L]
    RewriteRule ^(.*\.php)\$ \$1 [L]
    RewriteRule . index.php [L]
  </Directory>
  
  # Security headers
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
  Header always set X-Frame-Options "SAMEORIGIN"
  Header always set X-Content-Type-Options "nosniff"
  
  # Logs
  ErrorLog "/opt/bitnami/apache2/logs/${domain}-error.log"
  CustomLog "/opt/bitnami/apache2/logs/${domain}-access.log" combined
</VirtualHost>
EOF

    if [ $? -eq 0 ]; then
        log SUCCESS "SSL VirtualHost configuration created: $vhost_file"
        
        # Add Include directive to bitnami-ssl.conf if not already present
        if [ -f "$ssl_conf" ]; then
            if ! grep -q "$include_line" "$ssl_conf"; then
                log INFO "Adding Include directive to bitnami-ssl.conf..."
                echo "" >> "$ssl_conf"
                echo "# SSL VirtualHost for ${domain}" >> "$ssl_conf"
                echo "$include_line" >> "$ssl_conf"
                log SUCCESS "Include directive added to bitnami-ssl.conf"
            else
                log INFO "Include directive already exists in bitnami-ssl.conf"
            fi
        else
            log WARN "bitnami-ssl.conf not found at $ssl_conf"
        fi
        
        # Test Apache configuration
        /opt/bitnami/apache2/bin/apachectl configtest >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            log SUCCESS "Apache configuration test passed"
            return 0
        else
            log WARN "Apache configuration test failed, but config file was created"
            return 1
        fi
    else
        log ERROR "Failed to create SSL VirtualHost configuration"
        return 1
    fi
}

remove_ssl_vhost() {
    local domain=$1
    local vhost_file="${APACHE_VHOSTS_DIR}/${domain}-ssl.conf"
    local ssl_conf="/opt/bitnami/apache2/conf/bitnami/bitnami-ssl.conf"
    local include_line="IncludeOptional /opt/bitnami/apache2/conf/vhosts/${domain}-ssl.conf"
    
    if [ -f "$vhost_file" ]; then
        log INFO "Removing SSL VirtualHost configuration for $domain..."
        rm -f "$vhost_file"
        log SUCCESS "SSL VirtualHost configuration removed"
    fi
    
    # Remove Include directive from bitnami-ssl.conf
    if [ -f "$ssl_conf" ]; then
        if grep -q "$include_line" "$ssl_conf"; then
            log INFO "Removing Include directive from bitnami-ssl.conf..."
            # Remove the include line and the comment line before it
            sed -i "/# SSL VirtualHost for ${domain}/d" "$ssl_conf"
            sed -i "\|$include_line|d" "$ssl_conf"
            log SUCCESS "Include directive removed from bitnami-ssl.conf"
        fi
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
        check_webroot_access "$domain" || log WARN "Webroot check failed, using standalone mode"
    fi
    
    check_dns "$domain" || log WARN "DNS check failed, but continuing..."
    
    # Stop Apache if using standalone
    if [ "$CHALLENGE_METHOD" = "standalone" ]; then
        stop_apache
        check_port 80 || log WARN "Port 80 may not be accessible"
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
    
    log INFO "Executing certbot..."
    
    # Execute certbot
    local output
    local exit_code=0
    output=$(eval "$cmd" 2>&1) || exit_code=$?
    
    # Restart Apache if needed
    start_apache
    
    if [ $exit_code -eq 0 ]; then
        local expiry=$(get_cert_expiry "$domain")
        local cert_path="${CONFIG_DIR}/live/${domain}"
        
        track_domain "$domain"
        
        # Create SSL VirtualHost configuration
        create_ssl_vhost "$domain"
        
        log SUCCESS "Certificate issued successfully for $domain"
        log INFO "Certificate expires: $expiry"
        log INFO "Certificate path: $cert_path"
        
        if [ "$JSON_OUTPUT" = true ]; then
            json_output true "$domain" "issue" "Certificate issued successfully" "$expiry" "$cert_path"
        fi
        
        return 0
    else
        log ERROR "Failed to issue certificate"
        echo "$output" | grep -E "(Error|Failed|Problem)" | head -5 | while read line; do
            log ERROR "$line"
        done
        
        if [ "$JSON_OUTPUT" = true ]; then
            json_output false "$domain" "issue" "Failed to issue certificate"
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
    
    # Stop Apache if using standalone
    if [ "$CHALLENGE_METHOD" = "standalone" ]; then
        stop_apache
    fi
    
    local cmd="$CERTBOT_PATH renew"
    cmd="$cmd --cert-name $domain"
    cmd="$cmd --config-dir $CONFIG_DIR"
    cmd="$cmd --work-dir $WORK_DIR"
    cmd="$cmd --logs-dir $LOGS_DIR"
    cmd="$cmd --non-interactive"
    
    # Force renewal if certificate is valid but user wants to renew
    cmd="$cmd --force-renewal"
    
    if [ "$DRY_RUN" = true ]; then
        cmd="$cmd --dry-run"
        log INFO "Running in dry-run mode"
    fi
    
    log INFO "Executing certbot renew..."
    
    local output
    local exit_code=0
    output=$(eval "$cmd" 2>&1) || exit_code=$?
    
    # Restart Apache
    start_apache
    
    if [ $exit_code -eq 0 ]; then
        local expiry=$(get_cert_expiry "$domain")
        local cert_path="${CONFIG_DIR}/live/${domain}"
        
        # Update SSL VirtualHost configuration in case cert paths changed
        create_ssl_vhost "$domain"
        
        log SUCCESS "Certificate renewed successfully for $domain"
        log INFO "New expiry: $expiry"
        
        if [ "$JSON_OUTPUT" = true ]; then
            json_output true "$domain" "renew" "Certificate renewed successfully" "$expiry" "$cert_path"
        fi
        
        return 0
    else
        log ERROR "Failed to renew certificate"
        
        if [ "$JSON_OUTPUT" = true ]; then
            json_output false "$domain" "renew" "Failed to renew certificate"
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
    local skipped=0
    
    # Stop Apache once if using standalone
    if [ "$CHALLENGE_METHOD" = "standalone" ]; then
        stop_apache
    fi
    
    while IFS= read -r domain; do
        [ -z "$domain" ] && continue
        
        local days=$(days_until_expiry "$domain")
        
        if [ "$days" -le "$RENEWAL_DAYS" ]; then
            log INFO "Certificate for $domain expires in $days days, renewing..."
            
            # Renew without stopping/starting Apache for each domain
            local saved_restart=$AUTO_APACHE_RESTART
            AUTO_APACHE_RESTART=false
            
            if renew_certificate "$domain"; then
                ((renewed++))
            else
                ((failed++))
            fi
            
            AUTO_APACHE_RESTART=$saved_restart
        else
            log INFO "Certificate for $domain expires in $days days, skipping..."
            ((skipped++))
        fi
    done < "$DOMAINS_FILE"
    
    # Start Apache after all renewals
    start_apache
    
    log INFO "Renewal complete. Renewed: $renewed, Failed: $failed, Skipped: $skipped"
    
    if [ "$JSON_OUTPUT" = true ]; then
        json_output true "all" "renew-all" "Renewed: $renewed, Failed: $failed, Skipped: $skipped"
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
    
    log INFO "Executing certbot revoke..."
    
    local output
    local exit_code=0
    output=$(eval "$cmd" 2>&1) || exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        untrack_domain "$domain"
        
        # Remove SSL VirtualHost configuration
        remove_ssl_vhost "$domain"
        
        log SUCCESS "Certificate revoked successfully for $domain"
        
        if [ "$JSON_OUTPUT" = true ]; then
            json_output true "$domain" "revoke" "Certificate revoked successfully"
        fi
        
        return 0
    else
        log ERROR "Failed to revoke certificate"
        
        if [ "$JSON_OUTPUT" = true ]; then
            json_output false "$domain" "revoke" "Failed to revoke certificate"
        fi
        
        return 4
    fi
}

list_certificates() {
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
        printf "%-40s %-25s %-15s %s\n" "DOMAIN" "EXPIRY" "DAYS LEFT" "STATUS"
        printf "%-40s %-25s %-15s %s\n" "------" "------" "---------" "------"
        
        while IFS= read -r domain; do
            [ -z "$domain" ] && continue
            
            local expiry=$(get_cert_expiry "$domain")
            local days=$(days_until_expiry "$domain")
            
            if [ -z "$expiry" ]; then
                printf "%-40s %-25s %-15s %s\n" "$domain" "N/A" "N/A" "Not issued"
            elif [ "$days" -lt 0 ]; then
                printf "%-40s %-25s %-15s %s\n" "$domain" "$expiry" "$days" "EXPIRED"
            elif [ "$days" -le 7 ]; then
                printf "%-40s %-25s %-15s %s\n" "$domain" "$expiry" "$days" "EXPIRING SOON"
            else
                printf "%-40s %-25s %-15s %s\n" "$domain" "$expiry" "$days" "Valid"
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
  issue <domain>       Issue a new certificate and create SSL VirtualHost
  renew <domain>       Renew an existing certificate
  renew-all            Renew all certificates expiring within $RENEWAL_DAYS days
  revoke <domain>      Revoke a certificate and remove SSL VirtualHost
  list                 List all managed certificates
  status <domain>      Show certificate status
  test <domain>        Test certificate issuance (dry-run)

Options:
  --json               Output in JSON format
  --dry-run            Perform dry-run (test mode)
  --skip-dns           Skip DNS validation check
  --skip-webroot       Skip webroot access check
  --standalone         Use standalone mode (stops Apache)
  --webroot            Use webroot mode
  --no-restart         Don't auto-restart Apache
  --help               Show this help message

Features:
  - Automatically stops/starts Apache in standalone mode
  - Creates SSL VirtualHost config at: ${APACHE_VHOSTS_DIR}/{domain}-ssl.conf
  - Includes WordPress Multisite rewrite rules
  - Adds security headers (HSTS, X-Frame-Options, etc.)
  - Force-renews certificates even if not due

Examples:
  $(basename $0) issue example.com
  $(basename $0) issue example.com --standalone
  $(basename $0) renew example.com --json
  $(basename $0) test example.com --skip-dns
  $(basename $0) list

Configuration: $CONFIG_FILE
Logs: $LOG_FILE
Challenge Method: $CHALLENGE_METHOD
VirtualHosts Dir: $APACHE_VHOSTS_DIR
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
            --skip-dns)
                SKIP_DNS_CHECK=true
                shift
                ;;
            --skip-webroot)
                SKIP_WEBROOT_CHECK=true
                shift
                ;;
            --standalone)
                CHALLENGE_METHOD="standalone"
                shift
                ;;
            --webroot)
                CHALLENGE_METHOD="webroot"
                shift
                ;;
            --no-restart)
                AUTO_APACHE_RESTART=false
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
    trap cleanup EXIT INT TERM
    
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
