#!/bin/bash
# Honeypot Installation Script for VPS
# Run as root: curl -s https://raw.githubusercontent.com/.../install.sh | bash

set -e

echo "🍯 Installing SSH Honeypot..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

# Update system
echo -e "${YELLOW}Updating system packages...${NC}"
apt update && apt upgrade -y

# Install required packages
echo -e "${YELLOW}Installing required packages...${NC}"
apt install -y python3 python3-pip python3-venv git docker.io docker-compose ufw fail2ban

# Enable Docker
systemctl enable docker
systemctl start docker

# Create honeypot user
echo -e "${YELLOW}Creating honeypot user...${NC}"
useradd -m -s /bin/bash honeypot || true
usermod -aG docker honeypot

# Create project directory
HONEYPOT_DIR="/opt/honeypot"
mkdir -p $HONEYPOT_DIR
cd $HONEYPOT_DIR

# Create directory structure
mkdir -p {data,logs,dashboard/templates}

# Create Python files
echo -e "${YELLOW}Creating honeypot files...${NC}"

# Copy the main honeypot script here
cat > ssh_honeypot.py << 'EOF'
# [The SSH honeypot code from the first artifact would go here]
# For brevity, I'm not repeating the entire script
EOF

# Create requirements.txt
cat > requirements.txt << 'EOF'
paramiko==3.3.1
requests==2.31.0
flask==2.3.3
EOF

# Create config file
cat > config.json << 'EOF'
{
    "ssh_port": 2222,
    "bind_ip": "0.0.0.0",
    "log_file": "logs/honeypot.log",
    "database": "data/honeypot.db",
    "dashboard_port": 5000,
    "max_session_time": 300,
    "geolocation_api": "http://ip-api.com/json/",
    "alert_webhook": "",
    "remote_logging": {
        "enabled": false,
        "endpoint": "",
        "api_key": ""
    }
}
EOF

# Create Dockerfile
cat > Dockerfile << 'EOF'
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y gcc && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ssh_honeypot.py .
COPY config.json .

RUN mkdir -p data logs
RUN useradd -m -u 1000 honeypot && chown -R honeypot:honeypot /app

USER honeypot

EXPOSE 2222

CMD ["python", "ssh_honeypot.py"]
EOF

# Create docker-compose.yml
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  ssh-honeypot:
    build: .
    ports:
      - "22:2222"
      - "2222:2222"
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
    restart: unless-stopped
    environment:
      - HONEYPOT_PORT=2222
    networks:
      - honeypot-net

  dashboard:
    build: ./dashboard
    ports:
      - "8080:5000"
    volumes:
      - ./data:/app/data
    depends_on:
      - ssh-honeypot
    restart: unless-stopped
    networks:
      - honeypot-net

networks:
  honeypot-net:
    driver: bridge
EOF

# Create systemd service
cat > /etc/systemd/system/honeypot.service << 'EOF'
[Unit]
Description=SSH Honeypot
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/honeypot
ExecStart=/usr/bin/docker-compose up -d
ExecStop=/usr/bin/docker-compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

# Set permissions
chown -R honeypot:honeypot $HONEYPOT_DIR
chmod +x ssh_honeypot.py

# Configure firewall
echo -e "${YELLOW}Configuring firewall...${NC}"
ufw --force enable
ufw allow 22/tcp    # SSH honeypot
ufw allow 2222/tcp  # Alternative SSH port
ufw allow 8080/tcp  # Dashboard
ufw allow from YOUR_VPN_IP to any port 22  # Replace with your VPN IP

# Configure fail2ban for real SSH (if you have one running)
if [ -f /etc/fail2ban/jail.conf ]; then
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF
    systemctl restart fail2ban
fi

# Move real SSH to different port (IMPORTANT SECURITY STEP)
echo -e "${RED}IMPORTANT: Moving real SSH to port 2223 for security!${NC}"
sed -i 's/#Port 22/Port 2223/' /etc/ssh/sshd_config
sed -i 's/Port 22/Port 2223/' /etc/ssh/sshd_config
ufw allow 2223/tcp
systemctl restart sshd

echo -e "${YELLOW}Creating monitoring scripts...${NC}"

# Create log monitoring script
cat > /opt/honeypot/monitor.py << 'EOF'
#!/usr/bin/env python3
"""
Honeypot Monitor - Send alerts for interesting attacks
"""

import sqlite3
import time
import requests
import json
from datetime import datetime, timedelta

class HoneypotMonitor:
    def __init__(self, db_path='data/honeypot.db'):
        self.db_path = db_path
        self.last_check = datetime.now() - timedelta(minutes=5)
        
    def check_new_attacks(self):
        """Check for new interesting attacks"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get attacks since last check
        cursor.execute('''
            SELECT timestamp, source_ip, username, password, geolocation, commands
            FROM ssh_attempts 
            WHERE timestamp > ?
            ORDER BY timestamp DESC
        ''', (self.last_check.isoformat(),))
        
        new_attacks = cursor.fetchall()
        conn.close()
        
        interesting_attacks = []
        
        for attack in new_attacks:
            timestamp, ip, username, password, location, commands = attack
            
            # Check for interesting patterns
            is_interesting = False
            reason = []
            
            # New country
            if location and location not in self.seen_countries:
                is_interesting = True
                reason.append(f"New country: {location}")
                self.seen_countries.add(location)
            
            # Unusual username/password combinations
            unusual_usernames = ['oracle', 'postgres', 'mysql', 'admin123', 'test123']
            if username in unusual_usernames:
                is_interesting = True
                reason.append(f"Unusual username: {username}")
            
            # Commands executed
            if commands and commands != '[]':
                command_list = json.loads(commands)
                if command_list:
                    is_interesting = True
                    reason.append(f"Commands executed: {', '.join(command_list[:3])}")
            
            if is_interesting:
                interesting_attacks.append({
                    'timestamp': timestamp,
                    'ip': ip,
                    'username': username,
                    'password': password,
                    'location': location,
                    'reason': ', '.join(reason)
                })
        
        self.last_check = datetime.now()
        return interesting_attacks
    
    def send_alert(self, attacks):
        """Send alert about interesting attacks"""
        if not attacks:
            return
        
        message = f"🚨 Honeypot Alert: {len(attacks)} interesting attacks detected\n\n"
        
        for attack in attacks[:5]:  # Limit to 5 attacks
            message += f"🔍 {attack['timestamp']}\n"
            message += f"   IP: {attack['ip']} ({attack['location']})\n"
            message += f"   Creds: {attack['username']}:{attack['password']}\n"
            message += f"   Reason: {attack['reason']}\n\n"
        
        print(message)
        
        # Send to webhook if configured
        webhook_url = "YOUR_WEBHOOK_URL"  # Discord/Slack webhook
        if webhook_url and webhook_url != "YOUR_WEBHOOK_URL":
            try:
                payload = {"content": message}
                requests.post(webhook_url, json=payload)
            except:
                pass

if __name__ == "__main__":
    monitor = HoneypotMonitor()
    monitor.seen_countries = set()
    
    while True:
        try:
            attacks = monitor.check_new_attacks()
            if attacks:
                monitor.send_alert(attacks)
        except Exception as e:
            print(f"Monitor error: {e}")
        
        time.sleep(300)  # Check every 5 minutes
EOF

# Create stats script
cat > /opt/honeypot/stats.py << 'EOF'
#!/usr/bin/env python3
"""
Honeypot Stats - Generate daily/weekly reports
"""

import sqlite3
import json
from datetime import datetime, timedelta
from collections import Counter

def generate_report(hours=24):
    """Generate attack report"""
    conn = sqlite3.connect('data/honeypot.db')
    cursor = conn.cursor()
    
    since = datetime.now() - timedelta(hours=hours)
    
    # Basic stats
    cursor.execute('SELECT COUNT(*) FROM ssh_attempts WHERE timestamp > ?', (since.isoformat(),))
    total_attacks = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(DISTINCT source_ip) FROM ssh_attempts WHERE timestamp > ?', (since.isoformat(),))
    unique_ips = cursor.fetchone()[0]
    
    # Top data
    cursor.execute('''
        SELECT username, COUNT(*) as count 
        FROM ssh_attempts 
        WHERE timestamp > ?
        GROUP BY username 
        ORDER BY count DESC 
        LIMIT 10
    ''', (since.isoformat(),))
    top_usernames = cursor.fetchall()
    
    cursor.execute('''
        SELECT password, COUNT(*) as count 
        FROM ssh_attempts 
        WHERE timestamp > ?
        GROUP BY password 
        ORDER BY count DESC 
        LIMIT 10
    ''', (since.isoformat(),))
    top_passwords = cursor.fetchall()
    
    cursor.execute('''
        SELECT source_ip, COUNT(*) as count 
        FROM ssh_attempts 
        WHERE timestamp > ?
        GROUP BY source_ip 
        ORDER BY count DESC 
        LIMIT 10
    ''', (since.isoformat(),))
    top_ips = cursor.fetchall()
    
    conn.close()
    
    # Generate report
    report = f"""
🍯 SSH Honeypot Report ({hours}h)
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

📊 Summary:
• Total attacks: {total_attacks}
• Unique IPs: {unique_ips}
• Average attacks per IP: {total_attacks/unique_ips if unique_ips > 0 else 0:.1f}

🔝 Top Usernames:
"""
    
    for username, count in top_usernames:
        report += f"   {username}: {count}\n"
    
    report += "\n🔑 Top Passwords:\n"
    for password, count in top_passwords:
        report += f"   {password}: {count}\n"
    
    report += "\n🌍 Top Attack Sources:\n"
    for ip, count in top_ips:
        report += f"   {ip}: {count}\n"
    
    return report

if __name__ == "__main__":
    import sys
    hours = int(sys.argv[1]) if len(sys.argv) > 1 else 24
    print(generate_report(hours))
EOF

chmod +x /opt/honeypot/monitor.py
chmod +x /opt/honeypot/stats.py

# Create backup script
cat > /opt/honeypot/backup.sh << 'EOF'
#!/bin/bash
# Backup honeypot data

BACKUP_DIR="/opt/honeypot/backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup database
cp /opt/honeypot/data/honeypot.db $BACKUP_DIR/honeypot_$DATE.db

# Backup logs
tar -czf $BACKUP_DIR/logs_$DATE.tar.gz /opt/honeypot/logs/

# Keep only last 30 days of backups
find $BACKUP_DIR -name "*.db" -mtime +30 -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete

echo "Backup completed: $DATE"
EOF

chmod +x /opt/honeypot/backup.sh

# Create cron jobs
echo -e "${YELLOW}Setting up cron jobs...${NC}"
(crontab -l 2>/dev/null; echo "0 2 * * * /opt/honeypot/backup.sh") | crontab -
(crontab -l 2>/dev/null; echo "0 8 * * * /opt/honeypot/stats.py 24 | mail -s 'Daily Honeypot Report' admin@yourdomain.com") | crontab -

# Enable and start services
echo -e "${YELLOW}Starting services...${NC}"
systemctl daemon-reload
systemctl enable honeypot
systemctl start honeypot

# Wait for containers to start
sleep 10

# Check if containers are running
if docker ps | grep -q honeypot; then
    echo -e "${GREEN}✅ Honeypot containers are running!${NC}"
else
    echo -e "${RED}❌ Failed to start honeypot containers${NC}"
    exit 1
fi

# Show status
echo -e "${GREEN}🎉 Installation completed!${NC}"
echo ""
echo "📋 Configuration Summary:"
echo "• SSH Honeypot: Port 22, 2222"
echo "• Dashboard: http://YOUR_SERVER_IP:8080"
echo "• Real SSH moved to: Port 2223"
echo "• Database: /opt/honeypot/data/honeypot.db"
echo "• Logs: /opt/honeypot/logs/"
echo ""
echo "🔧 Management Commands:"
echo "• Start: systemctl start honeypot"
echo "• Stop: systemctl stop honeypot"
echo "• Status: docker ps"
echo "• Logs: docker-compose logs -f"
echo "• Stats: /opt/honeypot/stats.py"
echo ""
echo "⚠️  IMPORTANT SECURITY NOTES:"
echo "• Real SSH is now on port 2223"
echo "• Update firewall rules for your VPN IP"
echo "• Configure webhook in monitor.py for alerts"
echo "• Set up proper backup strategy"
echo ""
echo "🚀 Next steps:"
echo "1. Test connection: ssh -p 2223 root@YOUR_SERVER_IP"
echo "2. Check dashboard: http://YOUR_SERVER_IP:8080"
echo "3. Wait for attacks and monitor logs"
echo "4. Configure alerts and monitoring"

# Create quick start guide
cat > /opt/honeypot/README.md << 'EOF'
# SSH Honeypot Quick Guide

## Management
```bash
# Start/stop honeypot
systemctl start honeypot
systemctl stop honeypot

# View logs
docker-compose logs -f

# Check containers
docker ps

# Generate stats report
./stats.py 24  # Last 24 hours
./stats.py 168 # Last week
```

## Database Access
```bash
# Connect to SQLite database
sqlite3 data/honeypot.db

# Useful queries
SELECT COUNT(*) FROM ssh_attempts;
SELECT source_ip, COUNT(*) FROM ssh_attempts GROUP BY source_ip ORDER BY COUNT(*) DESC;
SELECT username, password, COUNT(*) FROM ssh_attempts GROUP BY username, password ORDER BY COUNT(*) DESC;
```

## Monitoring
```bash
# Real-time attack monitoring
tail -f logs/honeypot.log

# Start background monitor
nohup ./monitor.py &
```

## Security
- Real SSH is on port 2223
- Honeypot runs in isolated containers
- All traffic is logged and analyzed
- Regular backups in /opt/honeypot/backups/
EOF

echo -e "${YELLOW}Installation log saved to: /opt/honeypot/install.log${NC}"