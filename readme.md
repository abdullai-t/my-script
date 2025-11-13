# SSL Manager - Quick Installation Guide

Complete SSL certificate automation for AWS Lightsail WordPress Multisite in under 10 minutes.

---

## Prerequisites

- AWS Lightsail WordPress Multisite instance
- Domain(s) with DNS pointing to your server
- SSH access to your server

---


## Step 1: Connect to Your Server via SSH

## Step 2: Install SSL Manager (One Command)

```bash
wget https://raw.githubusercontent.com/abdullai-t/my-script/main/install.sh && \
chmod +x install.sh && \
sudo ./install.sh
```

**When prompted, enter your email:**
```
Enter your email for Let's Encrypt notifications: admin@yourdomain.com
```

**Installation takes ~2 minutes.**

---

## Step 5: Test Installation

```bash
ssl-manager --help
```

**Expected output:**
```
SSL Manager - Certificate Management Script
Usage: ssl-manager.sh [command] [domain] [options]
...
```

---

## Step 6: Issue Your First Certificate

```bash
# Test first (dry-run, no real certificate)
ssl-manager test yourdomain.com

# If test passes, issue real certificate
ssl-manager issue yourdomain.com
```

**What happens:**
- Apache stops automatically
- Certificate is issued via Let's Encrypt
- SSL VirtualHost config is created
- Apache restarts automatically
- Takes ~30 seconds

---

## Step 7: Issue Certificates for All Domains

```bash
ssl-manager issue www.yourdomain.com
ssl-manager issue dev.yourdomain.com
ssl-manager issue staging.yourdomain.com
```

**Or issue multiple domains efficiently:**

```bash
# Stop Apache once
sudo /opt/bitnami/ctlscript.sh stop apache

# Issue all certificates
ssl-manager issue yourdomain.com --no-restart
ssl-manager issue www.yourdomain.com --no-restart
ssl-manager issue dev.yourdomain.com --no-restart

# Start Apache once
sudo /opt/bitnami/ctlscript.sh start apache
```

---

## Step 8: Verify Certificates

```bash
# List all certificates
ssl-manager list
```

**Expected output:**
```
DOMAIN                    EXPIRY                   DAYS LEFT    STATUS
------                    ------                   ---------    ------
yourdomain.com            Feb 11 12:00:00 2026     90          Valid
www.yourdomain.com        Feb 11 12:00:00 2026     90          Valid
dev.yourdomain.com        Feb 11 12:00:00 2026     90          Valid
```

**Test HTTPS:**
```bash
curl -I https://yourdomain.com
# Should return 200 OK with HTTPS
```

---

## Step 9: Configure WordPress (Optional)

Edit WordPress config:
```bash
sudo nano /bitnami/wordpress/wp-config.php
```

Add these lines before `/* That's all, stop editing! */`:
```php
define('FORCE_SSL_ADMIN', true);
define('FORCE_SSL_LOGIN', true);
```

Save and exit (`Ctrl+X`, `Y`, `Enter`).

---

## ✅ Done! Auto-Renewal is Already Set Up

Certificates will automatically renew **daily at 2:00 AM** when they have 30 days or less until expiry.

**Monitor auto-renewal:**
```bash
# Check cron job
cat /etc/cron.d/ssl-manager

# View renewal logs
tail -50 /opt/ssl-manager/logs/cron.log
```

---

## 📋 Essential Commands

```bash
# Issue certificate
ssl-manager issue domain.com

# Renew certificate
ssl-manager renew domain.com

# Renew all expiring certificates
ssl-manager renew-all

# List all certificates
ssl-manager list

# Check certificate status
ssl-manager status domain.com

# View logs
tail -f /opt/ssl-manager/logs/ssl-manager.log

# Test without issuing
ssl-manager test domain.com
```

---

## 🔧 Troubleshooting

### DNS Not Resolving

```bash
# Check DNS
dig +short yourdomain.com

# If wrong IP, update DNS and wait
# Skip DNS check temporarily:
ssl-manager issue domain.com --skip-dns
```

### Apache Won't Start

```bash
# Check Apache config
sudo /opt/bitnami/apache2/bin/apachectl configtest

# View errors
sudo tail -50 /opt/bitnami/apache2/logs/error_log

# Restart Apache
sudo /opt/bitnami/ctlscript.sh restart apache
```

### Certificate Issuance Failed

```bash
# View detailed logs
tail -100 /opt/ssl-manager/logs/ssl-manager.log
tail -100 /bitnami/wordpress/wp-content/certbot/logs/letsencrypt.log

# Verify port 80 is open
curl -I http://yourdomain.com

# Try again with verbose logging
ssl-manager issue domain.com
```

### Check Configuration

```bash
# View current config
cat /opt/ssl-manager/config/settings.conf

# Edit if needed
sudo nano /opt/ssl-manager/config/settings.conf
```

---

## 🎯 Quick Reference

| What | Command |
|------|---------|
| **Install** | `wget https://raw.githubusercontent.com/abdullai-t/my-script/main/install.sh && chmod +x install.sh && sudo ./install.sh` |
| **Issue cert** | `ssl-manager issue domain.com` |
| **List certs** | `ssl-manager list` |
| **Renew all** | `ssl-manager renew-all` |
| **View logs** | `tail -f /opt/ssl-manager/logs/ssl-manager.log` |
| **Check status** | `ssl-manager status domain.com` |
| **Test cert** | `ssl-manager test domain.com` |

---

## 📁 Important Locations

```bash
/opt/ssl-manager/                                          # Installation directory
/opt/ssl-manager/config/settings.conf                      # Configuration
/opt/ssl-manager/logs/ssl-manager.log                      # Main log
/opt/ssl-manager/logs/cron.log                            # Auto-renewal log
/opt/ssl-manager/certs/domains.list                       # Tracked domains
/bitnami/wordpress/wp-content/certbot/config/live/        # Certificates
/opt/bitnami/apache2/conf/vhosts/                         # SSL VirtualHost configs
/opt/bitnami/apache2/conf/bitnami/bitnami-ssl.conf        # Main SSL config
```

---

## 🚀 What Happens Automatically

✅ **On Certificate Issuance:**
1. Apache stops
2. Certificate issued via Let's Encrypt
3. SSL VirtualHost config created at `/opt/bitnami/apache2/conf/vhosts/{domain}-ssl.conf`
4. Include directive added to `bitnami-ssl.conf`
5. Apache restarts
6. Domain tracked for auto-renewal

✅ **Daily at 2:00 AM:**
1. Script checks all certificates
2. Renews any expiring within 30 days
3. Updates VirtualHost configs
4. Logs everything

✅ **Security Features:**
- HSTS headers enabled
- X-Frame-Options set
- X-Content-Type-Options set
- WordPress Multisite rewrite rules included
- Certificate backups before renewal

---

## 🎓 Advanced Tips

### Issue Multiple Domains Efficiently

```bash
domains=("example.com" "www.example.com" "dev.example.com")
sudo /opt/bitnami/ctlscript.sh stop apache
for domain in "${domains[@]}"; do
  ssl-manager issue "$domain" --no-restart
done
sudo /opt/bitnami/ctlscript.sh start apache
```

### Monitor Certificate Expiry

```bash
# See what will renew soon
ssl-manager list | grep -E "EXPIRING|EXPIRED"

# Count valid certificates
ssl-manager list | grep -c "Valid"
```

### Force Immediate Renewal

```bash
# Even if not due
ssl-manager renew domain.com
```

### View Certificate Details

```bash
openssl x509 -text -noout -in \
  /bitnami/wordpress/wp-content/certbot/config/live/domain.com/cert.pem
```

---

## ❓ FAQ

**Q: How often are certificates renewed?**  
A: Automatically when they have 30 days or less until expiry.

**Q: Can I change the renewal threshold?**  
A: Yes, edit `RENEWAL_DAYS` in `/opt/ssl-manager/config/settings.conf`

**Q: Does it work with wildcard certificates?**  
A: Yes, but requires DNS challenge method. Contact support for setup.

**Q: What if I have many subdomains?**  
A: Issue a certificate for each subdomain, or use a wildcard certificate.

**Q: Can I use this on non-Bitnami setups?**  
A: Yes, but paths may need adjustment in the configuration file.

**Q: Where are certificate backups stored?**  
A: `/bitnami/wordpress/wp-content/certbot/config/backup/`

---

## 📞 Support & Resources

- **Full Documentation:** [GitHub README](https://github.com/abdullai-t/my-script)
- **Script Source:** [ssl-manager.sh](https://github.com/abdullai-t/my-script/blob/main/ssl-manager.sh)
- **Installation Script:** [install.sh](https://github.com/abdullai-t/my-script/blob/main/install.sh)
- **Let's Encrypt Docs:** [letsencrypt.org/docs](https://letsencrypt.org/docs/)
- **Certbot Docs:** [certbot.eff.org/docs](https://certbot.eff.org/docs/)

---

## 🎉 You're All Set!

Your SSL certificates are now:
- ✅ Issued and active
- ✅ Automatically renewing
- ✅ Properly configured in Apache
- ✅ Monitored and logged

**Total setup time: ~10 minutes**  
**Maintenance required: Zero** (fully automated)

Visit your site: `https://yourdomain.com` 🔒
