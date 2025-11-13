#!/bin/bash
#
# SSL Manager Installation Script
# This script sets up the SSL Manager on Bitnami Lightsail
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  SSL Manager Installation for Lightsail${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root or with sudo${NC}"
    exit 1
fi

# Configuration
INSTALL_DIR="/opt/ssl-manager"
WEBROOT="/bitnami/wordpress"
WEB_USER="daemon"

# Detect email
echo -e "${YELLOW}Configuration${NC}"
read -p "Enter your email for Let's Encrypt notifications: " LETSENCRYPT_EMAIL

if [ -z "$LETSENCRYPT_EMAIL" ]; then
    echo -e "${RED}Email is required${NC}"
    exit 1
fi

# Verify email format
if [[ ! "$LETSENCRYPT_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    echo -e "${RED}Invalid email format${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}Creating directories...${NC}"

# Create directory structure
mkdir -p "$INSTALL_DIR"/{config,lib,logs,certs}
mkdir -p "$WEBROOT/wp-content/certbot"/{config,work,logs}
mkdir -p "$WEBROOT/.well-known/acme-challenge"

echo -e "${GREEN}✓ Directories created${NC}"

# Create configuration file
echo -e "${BLUE}Creating configuration file...${NC}"

cat > "$INSTALL_DIR/config/settings.conf" <<EOF
# SSL Manager Configuration

# Paths
WEBROOT="$WEBROOT"
CONFIG_DIR="$WEBROOT/wp-content/certbot/config"
WORK_DIR="$WEBROOT/wp-content/certbot/work"
LOGS_DIR="$WEBROOT/wp-content/certbot/logs"
CERTBOT_PATH="/usr/bin/certbot"

# Let's Encrypt Configuration
LETSENCRYPT_EMAIL="$LETSENCRYPT_EMAIL"

# Challenge method: webroot, standalone, or dns
CHALLENGE_METHOD="standalone"

# Auto-renewal: renew certificates within N days of expiry
RENEWAL_DAYS=30

# Logging
LOG_FILE="$INSTALL_DIR/logs/ssl-manager.log"
LOG_LEVEL="INFO"

# Safety Options
DRY_RUN=false
BACKUP_CERTS=true
EOF

echo -e "${GREEN}✓ Configuration file created${NC}"

# Set proper permissions
echo -e "${BLUE}Setting permissions...${NC}"

chown -R root:root "$INSTALL_DIR"
chmod 750 "$INSTALL_DIR"
chmod 640 "$INSTALL_DIR/config/settings.conf"
chmod 755 "$INSTALL_DIR/logs"
chmod 755 "$INSTALL_DIR/certs"

chown -R $WEB_USER:$WEB_USER "$WEBROOT/wp-content/certbot"
chmod -R 755 "$WEBROOT/wp-content/certbot"

chown -R $WEB_USER:$WEB_USER "$WEBROOT/.well-known"
chmod -R 755 "$WEBROOT/.well-known"

echo -e "${GREEN}✓ Permissions set${NC}"

# Install main script
echo -e "${BLUE}Installing main script...${NC}"

# Download the main script from GitHub
if wget -q https://raw.githubusercontent.com/abdullai-t/my-script/main/ssl-manager.sh -O "$INSTALL_DIR/ssl-manager.sh"; then
    chmod 750 "$INSTALL_DIR/ssl-manager.sh"
    echo -e "${GREEN}✓ Main script downloaded and installed${NC}"
else
    echo -e "${RED}✗ Failed to download main script${NC}"
    echo -e "${YELLOW}Please manually download ssl-manager.sh to $INSTALL_DIR/${NC}"
    echo -e "${YELLOW}wget https://raw.githubusercontent.com/abdullai-t/my-script/main/ssl-manager.sh -O $INSTALL_DIR/ssl-manager.sh${NC}"
    echo -e "${YELLOW}Then run: chmod 750 $INSTALL_DIR/ssl-manager.sh${NC}"
fi

# Create symlink
echo -e "${BLUE}Creating command symlink...${NC}"

if [ -L /usr/local/bin/ssl-manager ]; then
    rm /usr/local/bin/ssl-manager
fi

ln -s "$INSTALL_DIR/ssl-manager.sh" /usr/local/bin/ssl-manager

echo -e "${GREEN}✓ Symlink created${NC}"

# Add alias to bashrc for bitnami user
echo -e "${BLUE}Adding command alias for bitnami user...${NC}"

BITNAMI_BASHRC="/home/bitnami/.bashrc"

if [ -f "$BITNAMI_BASHRC" ]; then
    # Check if alias already exists
    if ! grep -q "alias ssl-manager=" "$BITNAMI_BASHRC"; then
        echo "" >> "$BITNAMI_BASHRC"
        echo "# SSL Manager alias" >> "$BITNAMI_BASHRC"
        echo 'alias ssl-manager="sudo /opt/ssl-manager/ssl-manager.sh"' >> "$BITNAMI_BASHRC"
        echo -e "${GREEN}✓ Alias added to bitnami user bashrc${NC}"
    else
        echo -e "${GREEN}✓ Alias already exists in bashrc${NC}"
    fi
else
    echo -e "${YELLOW}⚠ Bitnami user bashrc not found, skipping alias${NC}"
fi

# Add alias to root bashrc as well
ROOT_BASHRC="/root/.bashrc"

if [ -f "$ROOT_BASHRC" ]; then
    if ! grep -q "alias ssl-manager=" "$ROOT_BASHRC"; then
        echo "" >> "$ROOT_BASHRC"
        echo "# SSL Manager alias" >> "$ROOT_BASHRC"
        echo 'alias ssl-manager="sudo /opt/ssl-manager/ssl-manager.sh"' >> "$ROOT_BASHRC"
        echo -e "${GREEN}✓ Alias added to root bashrc${NC}"
    fi
fi

echo -e "${GREEN}✓ Command alias configured${NC}"

# Configure sudo access
echo -e "${BLUE}Configuring sudo access...${NC}"

SUDOERS_FILE="/etc/sudoers.d/ssl-manager"

cat > "$SUDOERS_FILE" <<EOF
# Allow web user to run SSL Manager
$WEB_USER ALL=(ALL) NOPASSWD: $INSTALL_DIR/ssl-manager.sh
$WEB_USER ALL=(ALL) NOPASSWD: /usr/local/bin/ssl-manager
EOF

chmod 440 "$SUDOERS_FILE"

# Validate sudoers file
if visudo -c -f "$SUDOERS_FILE" >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Sudo access configured${NC}"
else
    echo -e "${RED}✗ Sudoers file validation failed${NC}"
    rm "$SUDOERS_FILE"
    exit 1
fi

# Check if certbot is installed
echo -e "${BLUE}Checking dependencies...${NC}"

if ! command -v certbot &> /dev/null; then
    echo -e "${YELLOW}Certbot not found. Installing...${NC}"
    
    if command -v apt-get &> /dev/null; then
        apt-get update
        apt-get install -y certbot
    elif command -v yum &> /dev/null; then
        yum install -y certbot
    else
        echo -e "${RED}Could not install certbot. Please install manually.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Certbot installed${NC}"
else
    echo -e "${GREEN}✓ Certbot found${NC}"
fi

# Setup cron for auto-renewal
echo -e "${BLUE}Setting up auto-renewal cron job...${NC}"

CRON_FILE="/etc/cron.d/ssl-manager"

cat > "$CRON_FILE" <<EOF
# SSL Manager Auto-Renewal
# Runs daily at 2:00 AM
0 2 * * * root $INSTALL_DIR/ssl-manager.sh renew-all >> $INSTALL_DIR/logs/cron.log 2>&1
EOF

chmod 644 "$CRON_FILE"

echo -e "${GREEN}✓ Cron job created${NC}"

# Create test script
echo -e "${BLUE}Creating test script...${NC}"

cat > "$INSTALL_DIR/test.sh" <<'EOF'
#!/bin/bash
# SSL Manager Test Script

echo "Testing SSL Manager installation..."
echo ""

# Test 1: Check if script exists
if [ -f /usr/local/bin/ssl-manager ]; then
    echo "✓ SSL Manager command found"
else
    echo "✗ SSL Manager command not found"
    exit 1
fi

# Test 2: Check configuration
if [ -f /opt/ssl-manager/config/settings.conf ]; then
    echo "✓ Configuration file exists"
else
    echo "✗ Configuration file not found"
    exit 1
fi

# Test 3: Check directories
for dir in /opt/ssl-manager/{logs,certs,config} /bitnami/wordpress/wp-content/certbot/{config,work,logs}; do
    if [ -d "$dir" ]; then
        echo "✓ Directory exists: $dir"
    else
        echo "✗ Directory missing: $dir"
        exit 1
    fi
done

# Test 4: Test command execution
echo ""
echo "Running: ssl-manager --help"
ssl-manager --help

echo ""
echo "All tests passed! SSL Manager is ready to use."
echo ""
echo "Try: ssl-manager test yourdomain.com"
EOF

chmod 755 "$INSTALL_DIR/test.sh"

echo -e "${GREEN}✓ Test script created${NC}"

# Configure Apache SSL configuration
echo -e "${BLUE}Configuring Apache SSL settings...${NC}"

BITNAMI_SSL_CONF="/opt/bitnami/apache2/conf/bitnami/bitnami-ssl.conf"

# Backup original bitnami-ssl.conf if it exists
if [ -f "$BITNAMI_SSL_CONF" ]; then
    cp "$BITNAMI_SSL_CONF" "$BITNAMI_SSL_CONF.backup.$(date +%Y%m%d_%H%M%S)"
    echo -e "${GREEN}✓ Backed up original bitnami-ssl.conf${NC}"
fi

# Create new bitnami-ssl.conf optimized for SSL Manager
cat > "$BITNAMI_SSL_CONF" <<'EOF'
# Default SSL Virtual Host configuration.

<IfModule !ssl_module>
  LoadModule ssl_module modules/mod_ssl.so
</IfModule>

Listen 443
SSLProtocol all -SSLv2 -SSLv3
SSLHonorCipherOrder on
SSLCipherSuite "EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH+aRSA+SHA256 EECDH !aNULL !eNULL !LOW !3DES !MD5 !EXP !PSK !SRP !DSS !EDH !RC4"
SSLPassPhraseDialog  builtin
SSLSessionCache "shmcb:/opt/bitnami/apache/logs/ssl_scache(512000)"
SSLSessionCacheTimeout  300


IncludeOptional /opt/bitnami/apache2/conf/vhosts/*.conf
EOF

echo -e "${GREEN}✓ Apache SSL configuration updated${NC}"

# Test Apache configuration
if /opt/bitnami/apache2/bin/apachectl configtest >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Apache configuration test passed${NC}"
else
    echo -e "${YELLOW}⚠ Apache configuration test failed, but continuing...${NC}"
    echo -e "${YELLOW}  You may need to manually check the Apache configuration${NC}"
fi

# Installation complete
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Installation Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "${BLUE}Quick Start:${NC}"
echo ""
echo "  Test installation:"
echo "    $INSTALL_DIR/test.sh"
echo ""
echo "  Issue a certificate:"
echo "    ssl-manager issue yourdomain.com"
echo ""
echo "  Test certificate (dry-run):"
echo "    ssl-manager test yourdomain.com"
echo ""
echo "  List certificates:"
echo "    ssl-manager list"
echo ""
echo "  View status:"
echo "    ssl-manager status yourdomain.com"
echo ""
echo -e "${BLUE}Configuration:${NC}"
echo "  Location: $INSTALL_DIR/config/settings.conf"
echo "  Email: $LETSENCRYPT_EMAIL"
echo ""
echo -e "${BLUE}Logs:${NC}"
echo "  Location: $INSTALL_DIR/logs/ssl-manager.log"
echo ""
echo -e "${BLUE}Auto-Renewal:${NC}"
echo "  Cron job installed: Daily at 2:00 AM"
echo "  Certificates will be renewed $RENEWAL_DAYS days before expiry"
echo ""
echo -e "${YELLOW}Important:${NC}"
echo "  - Make sure your domain DNS points to this server"
echo "  - Port 80 must be accessible for webroot validation"
echo "  - Run 'ssl-manager test <domain>' before issuing real certificates"
echo ""
echo -e "${BLUE}Next Steps:${NC}"
echo "  1. Logout and login again, OR run: source ~/.bashrc"
echo "  2. Test command: ssl-manager --help"
echo "  3. Issue certificate: ssl-manager issue yourdomain.com"
echo ""
