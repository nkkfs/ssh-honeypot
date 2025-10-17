#!/bin/bash
# Security Hardening Script for Honeypot VPS
# Run this BEFORE installing the honeypot

echo "🔒 Hardening VPS for Honeypot deployment..."

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Get your current IP for SSH access
echo -e "${YELLOW}What's your current IP address for SSH access?${NC}"
echo "This will be whitelisted in the firewall."
read -p "Enter your IP (or press Enter to detect automatically): " USER_IP

if [ -z "$USER_IP" ]; then
    USER_IP=$(curl -s ifconfig.me)
    echo "Detected IP: $USER_IP"
fi

# Update system
echo -e "${YELLOW}Updating system...${NC}"
apt update && apt upgrade -y

# Install essential security tools
echo -e "${YELLOW}Installing security tools...${NC}"
apt install -y ufw fail2ban unattended-upgrades logwatch rkhunter chkrootkit

# Configure automatic updates
echo -e "${YELLOW}Configuring automatic security updates...${NC}"
echo 'Unattended-Upgrade::Automatic-Reboot "false";' >> /etc/apt/apt.conf.d/50unattended-upgrades
systemctl enable unattended-upgrades
systemctl start unattended-upgrades

# Disable unnecessary services
echo -e "${YELLOW}Disabling unnecessary services...${NC}"
systemctl disable apache2 2>/dev/null || true
systemctl disable nginx 2>/dev/null || true
systemctl disable mysql 2>/dev/null || true
systemctl disable postgresql 2>/dev/null || true

# Secure SSH configuration
echo -e "${YELLOW}Securing SSH configuration...${NC}"
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

cat > /etc/ssh/sshd_config << 'EOF'
# Secure SSH Configuration for Honeypot VPS

# Basic settings
Port 2223
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Authentication
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# Security settings
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no

# Timeouts
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 60

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Restrictions
MaxAuthTries 3
MaxSessions 2
MaxStartups 2

# Only allow specific users (create honeypot-admin user)
AllowUsers honeypot-admin
EOF

# Create admin user for management
echo -e "${YELLOW}Creating admin user...${NC}"
useradd -m -s /bin/bash honeypot-admin
usermod -aG sudo honeypot-admin

echo -e "${YELLOW}Set password for honeypot-admin user:${NC}"
passwd honeypot-admin

# Setup SSH key authentication
echo -e "${YELLOW}Setting up SSH key authentication...${NC}"
sudo -u honeypot-admin mkdir -p /home/honeypot-admin/.ssh
sudo -u honeypot-admin chmod 700 /home/honeypot-admin/.ssh

echo "Paste your public SSH key (contents of ~/.ssh/id_rsa.pub):"
read -r SSH_KEY
echo "$SSH_KEY" | sudo -u honeypot-admin tee /home/honeypot-admin/.ssh/authorized_keys
sudo -u honeypot-admin chmod 600 /home/honeypot-admin/.ssh/authorized_keys

# Configure firewall
echo -e "${YELLOW}Configuring firewall...${NC}"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Allow SSH from your IP only
ufw allow from $USER_IP to any port 2223
ufw allow from $USER_IP to any port 8080  # Dashboard access

# Allow honeypot ports from anywhere
ufw allow 22    # SSH honeypot
ufw allow 2222  # Alternative SSH port
ufw allow 80    # HTTP honeypot (future)
ufw allow 443   # HTTPS honeypot (future)

# Enable firewall
ufw --force enable

# Configure fail2ban
echo -e "${YELLOW}Configuring fail2ban...${NC}"
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 86400
findtime = 600
maxretry = 3
ignoreip = 127.0.0.1/8 $USER_IP

[sshd]
enabled = true
port = 2223
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[sshd-ddos]
enabled = true
port = 2223
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 2
EOF

systemctl enable fail2ban
systemctl restart fail2ban

# Configure logwatch
echo -e "${YELLOW}Configuring log monitoring...${NC}"
cat > /etc/logwatch/conf/logwatch.conf << 'EOF'
LogDir = /var/log
MailTo = admin@yourdomain.com
MailFrom = Logwatch
Print = No
Save = /var/cache/logwatch
Range = yesterday
Detail = Med
Service = All
mailer = "/usr/sbin/sendmail -t"
EOF

# Setup rootkit detection
echo -e "${YELLOW}Setting up rootkit detection...${NC}"
rkhunter --update
rkhunter --propupd

# Create monitoring cron jobs
cat > /etc/cron.d/security-monitoring << 'EOF'
# Security monitoring cron jobs

# Daily log report
0 6 * * * root /usr/sbin/logwatch --output mail --mailto admin@yourdomain.com --detail high

# Weekly rootkit scan
0 2 * * 0 root /usr/bin/rkhunter --cronjob --update --quiet

# Daily system integrity check
0 3 * * * root /usr/bin/chkrootkit | grep -v "nothing found" | mail -s "ChkRootkit Report" admin@yourdomain.com

# Disk space monitoring
0 */6 * * * root if [ $(df / | tail -1 | awk '{print $5}' | sed 's/%//') -gt 80 ]; then echo "Disk space critical: $(df -h /)" | mail -s "Disk Space Alert" admin@yourdomain.com; fi
EOF

# Create system hardening script
cat > /opt/system-harden.sh << 'EOF'
#!/bin/bash
# Additional system hardening

# Disable core dumps
echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf

# Network security
cat >> /etc/sysctl.conf << 'EOL'

# Network security settings
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
EOL

sysctl -p

# Secure shared memory
echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab

# Set file permissions
chmod 700 /root
chmod 600 /etc/ssh/sshd_config
chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 600 /etc/shadow
chmod 600 /etc/gshadow
EOF

chmod +x /opt/system-harden.sh
/opt/system-harden.sh

# Create backup script for system config
cat > /opt/backup-system-config.sh << 'EOF'
#!/bin/bash
# Backup critical system configuration

BACKUP_DIR="/opt/system-backups/$(date +%Y%m%d)"
mkdir -p $BACKUP_DIR

# Backup configurations
cp -r /etc/ssh/ $BACKUP_DIR/
cp -r /etc/fail2ban/ $BACKUP_DIR/
cp /etc/ufw/user.rules $BACKUP_DIR/
cp /etc/crontab $BACKUP_DIR/
cp -r /etc/cron.d/ $BACKUP_DIR/

# Create archive
tar -czf /opt/system-backups/system-config-$(date +%Y%m%d).tar.gz $BACKUP_DIR/

# Keep only 7 days of backups
find /opt/system-backups/ -name "*.tar.gz" -mtime +7 -delete
find /opt/system-backups/ -type d -mtime +7 -exec rm -rf {} \;

echo "System configuration backed up to: /opt/system-backups/system-config-$(date +%Y%m%d).tar.gz"
EOF

chmod +x /opt/backup-system-config.sh

# Schedule backup
(crontab -l 2>/dev/null; echo "0 1 * * * /opt/backup-system-config.sh") | crontab -

# Restart SSH with new configuration
systemctl restart sshd

# Final security check
echo -e "${YELLOW}Running final security check...${NC}"
ss -tlnp | grep :22 && echo -e "${RED}Warning: Port 22 still open${NC}"
ss -tlnp | grep :2223 && echo -e "${GREEN}SSH correctly moved to port 2223${NC}"

echo -e "${GREEN}🎉 VPS Security Hardening Complete!${NC}"
echo ""
echo "📋 Security Summary:"
echo "• SSH moved to port 2223 (key-based auth only)"
echo "• Firewall configured (UFW)"
echo "• Fail2ban protecting SSH"
echo "• Automatic security updates enabled"
echo "• Rootkit detection scheduled"
echo "• Log monitoring configured"
echo "• Admin user: honeypot-admin"
echo ""
echo "🔑 Connection Info:"
echo "• SSH: ssh -p 2223 honeypot-admin@YOUR_SERVER_IP"
echo "• Only your IP ($USER_IP) can access SSH and dashboard"
echo ""
echo "⚠️  IMPORTANT:"
echo "1. Test SSH connection NOW before installing honeypot"
echo "2. Save your SSH private key securely"
echo "3. Update email addresses in monitoring configs"
echo "4. Consider setting up VPN for additional security"
echo ""
echo "🚀 Ready for honeypot installation!"
echo "Run the honeypot install script when ready."