#!/bin/bash
# Improved Auto Setup VPS: Nginx + Docker + SSL + Security
# Author: Improved Version
# Version: 2.0

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration
SCRIPT_VERSION="2.0"
LOG_FILE="/var/log/vps-setup-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/vps-setup-backups"
SSH_PORT="2222"
TOTAL_STEPS=18

# Initialize
STEP=0
DOMAIN=""
EMAIL=""
CREATE_USER="n"
USERNAME=""

# Colors
readonly GREEN="\033[0;32m"
readonly RED="\033[0;31m"
readonly YELLOW="\033[1;33m"
readonly BLUE="\033[0;34m"
readonly PURPLE="\033[0;35m"
readonly NC="\033[0m" # No Color

# Logging setup
exec > >(tee -a "$LOG_FILE")
exec 2>&1

# Utility functions
function show_banner() {
    clear
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════╗"

    # Calculate padding for first line
    local line1="VPS Auto Setup v${SCRIPT_VERSION}"
    local line1_len=${#line1}
    local padding1=$(( (62 - line1_len) / 2 ))
    local padding1_right=$(( 62 - line1_len - padding1 ))

    # Calculate padding for second line
    local line2="Nginx + Docker + SSL + Security"
    local line2_len=${#line2}
    local padding2=$(( (62 - line2_len) / 2 ))
    local padding2_right=$(( 62 - line2_len - padding2 ))

    printf "║%*s%s%*s║\n" $padding1 "" "$line1" $padding1_right ""
    printf "║%*s%s%*s║\n" $padding2 "" "$line2" $padding2_right ""
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

function progress() {
    STEP=$((STEP+1))
    echo -e "\n${BLUE}[${STEP}/${TOTAL_STEPS}] $1...${NC}"
}

function success() {
    echo -e "${GREEN}✅ Hoàn tất:${NC} $1"
}

function warning() {
    echo -e "${YELLOW}⚠️  Cảnh báo:${NC} $1"
}

function error() {
    echo -e "${RED}❌ Lỗi:${NC} $1"
    echo -e "${RED}Chi tiết lỗi đã được ghi vào: ${LOG_FILE}${NC}"
    exit 1
}

function info() {
    echo -e "${BLUE}ℹ️  Thông tin:${NC} $1"
}

# Validation functions
function validate_email() {
    local email=$1
    if [[ ! $email =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        return 1
    fi
    return 0
}

function validate_domain() {
    local domain=$1

    # Check basic requirements
    if [[ -z "$domain" ]]; then
        return 1
    fi

    # Check length (max 253 characters for full domain)
    if [[ ${#domain} -gt 253 ]]; then
        return 1
    fi

    # Check if it has at least one dot
    if [[ ! "$domain" == *.* ]]; then
        return 1
    fi

    # Check for valid characters (letters, numbers, dots, hyphens)
    if [[ ! "$domain" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        return 1
    fi

    # Check that it doesn't start or end with hyphen or dot
    if [[ "$domain" =~ ^[.-]|[.-]$ ]]; then
        return 1
    fi

    # Check for consecutive dots
    if [[ "$domain" =~ \.\. ]]; then
        return 1
    fi

    # Check each part (between dots) - no part should start/end with hyphen
    local IFS='.'
    local -a PARTS
    read -ra PARTS <<< "$domain"
    for part in "${PARTS[@]}"; do
        if [[ -z "$part" ]] || [[ ${#part} -gt 63 ]] || [[ "$part" =~ ^-|-$ ]]; then
            return 1
        fi
    done

    return 0
}

function validate_username() {
    local username=$1
    if [[ ! $username =~ ^[a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$)$ ]]; then
        return 1
    fi
    return 0
}

# System checks
function check_prerequisites() {
    progress "Kiểm tra hệ thống"
    
    # Check OS
    if [[ ! -f /etc/debian_version ]]; then
        error "Script chỉ hỗ trợ Debian/Ubuntu"
    fi
    
    # Check root privileges
    if [[ $EUID -ne 0 ]]; then
        error "Script cần chạy với quyền root (sudo ./script.sh)"
    fi
    
    # Check internet connection
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        error "Không có kết nối internet"
    fi
    
    # Create backup directory
    mkdir -p "$BACKUP_DIR"
    
    success "Hệ thống phù hợp để chạy script"
}

# User input with validation
function get_user_input() {
    progress "Thu thập thông tin cấu hình"
    
    # Domain input
    while true; do
        read -p "Nhập domain name (vd: example.com): " DOMAIN
        if [[ -n "$DOMAIN" ]] && validate_domain "$DOMAIN"; then
            break
        else
            echo -e "${RED}Domain không hợp lệ. Vui lòng nhập lại.${NC}"
        fi
    done
    
    # Email input
    while true; do
        read -p "Nhập email cho SSL certificate: " EMAIL
        if [[ -n "$EMAIL" ]] && validate_email "$EMAIL"; then
            break
        else
            echo -e "${RED}Email không hợp lệ. Vui lòng nhập lại.${NC}"
        fi
    done
    
    # User creation option
    read -p "Tạo user non-root? (y/n): " CREATE_USER
    if [[ "$CREATE_USER" =~ ^[Yy]$ ]]; then
        while true; do
            read -p "Nhập tên user: " USERNAME
            if [[ -n "$USERNAME" ]] && validate_username "$USERNAME"; then
                break
            else
                echo -e "${RED}Username không hợp lệ (chỉ chữ thường, số, dấu gạch dưới, gạch ngang).${NC}"
            fi
        done
    fi
    
    # SSH port
    read -p "SSH port (mặc định 2222): " input_port
    SSH_PORT=${input_port:-2222}
    
    success "Thông tin cấu hình đã thu thập"
}

# Check if package is installed
function is_installed() {
    dpkg -l "$1" &> /dev/null
}

# Backup configuration files
function backup_config() {
    local file=$1
    if [[ -f "$file" ]]; then
        cp "$file" "$BACKUP_DIR/$(basename "$file").backup.$(date +%Y%m%d-%H%M%S)"
        info "Đã backup: $file"
    fi
}

# System update and basic packages
function update_system() {
    progress "Cập nhật hệ thống và cài đặt gói cơ bản"
    
    export DEBIAN_FRONTEND=noninteractive
    apt update || error "Không thể update package list"
    apt upgrade -y || error "Không thể upgrade hệ thống"
    apt autoremove -y
    
    # Install basic packages
    local packages=(
        "curl" "wget" "git" "unzip" "htop" "net-tools" "ufw" 
        "fail2ban" "software-properties-common" "apt-transport-https" 
        "ca-certificates" "gnupg" "lsb-release" "dnsutils" "rsync"
        "logrotate" "cron" "vim" "nano"
    )
    
    for package in "${packages[@]}"; do
        if ! is_installed "$package"; then
            apt install -y "$package" || warning "Không cài được $package"
        fi
    done
    
    success "Hệ thống đã được cập nhật"
}

# Create non-root user
function create_user() {
    if [[ "$CREATE_USER" =~ ^[Yy]$ ]]; then
        progress "Tạo user non-root: $USERNAME"
        
        if id "$USERNAME" &>/dev/null; then
            warning "User $USERNAME đã tồn tại"
        else
            adduser --disabled-password --gecos "" "$USERNAME"
            usermod -aG sudo "$USERNAME"
            
            # Setup SSH directory for new user
            mkdir -p "/home/$USERNAME/.ssh"
            chmod 700 "/home/$USERNAME/.ssh"
            chown "$USERNAME:$USERNAME" "/home/$USERNAME/.ssh"
            
            success "User $USERNAME đã được tạo"
        fi
    fi
}

# Configure firewall
function setup_firewall() {
    progress "Cấu hình firewall (UFW)"
    
    # Reset UFW to defaults
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow specific ports
    ufw allow "$SSH_PORT"/tcp comment 'SSH'
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    
    # Enable UFW
    ufw --force enable
    
    success "Firewall đã được cấu hình"
}

# Install and configure Docker
function install_docker() {
    progress "Cài đặt Docker và Docker Compose"
    
    if command -v docker &> /dev/null; then
        success "Docker đã được cài đặt"
    else
        # Add Docker's official GPG key
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
        
        # Add Docker repository
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        
        # Install Docker
        apt update
        apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
        
        # Enable and start Docker
        systemctl enable docker
        systemctl start docker
        
        # Add users to docker group
        if [[ "$CREATE_USER" =~ ^[Yy]$ ]]; then
            usermod -aG docker "$USERNAME"
        fi
        
        success "Docker đã được cài đặt"
    fi
}

# Install and configure Nginx
function install_nginx() {
    progress "Cài đặt và cấu hình Nginx"
    
    if is_installed nginx; then
        warning "Nginx đã được cài đặt"
    else
        apt install -y nginx || error "Không thể cài đặt Nginx"
        systemctl enable nginx
        systemctl start nginx
    fi
    
    # Backup original config
    backup_config "/etc/nginx/nginx.conf"
    
    # Optimize Nginx configuration
    cat > /etc/nginx/conf.d/optimization.conf <<EOF
# Rate limiting
limit_req_zone \$binary_remote_addr zone=login:10m rate=5r/m;
limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;

# Gzip compression
gzip on;
gzip_vary on;
gzip_min_length 1024;
gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json;

# Security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;

# Hide Nginx version
server_tokens off;
EOF
    
    success "Nginx đã được cài đặt và cấu hình"
}

# Configure domain
function configure_domain() {
    progress "Cấu hình Nginx cho domain: $DOMAIN"
    
    # Create web directory
    mkdir -p "/var/www/$DOMAIN/html"
    chown -R www-data:www-data "/var/www/$DOMAIN"
    
    # Create initial index page
    cat > "/var/www/$DOMAIN/html/index.html" <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>Welcome to $DOMAIN</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }
        .container { max-width: 600px; margin: 0 auto; }
        .success { color: #28a745; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="success">🎉 Server Setup Complete!</h1>
        <p>Domain: <strong>$DOMAIN</strong></p>
        <p>Server is running Nginx with SSL</p>
        <p><small>Setup completed on $(date)</small></p>
    </div>
</body>
</html>
EOF
    
    # Create Nginx server block
    cat > "/etc/nginx/sites-available/$DOMAIN" <<EOF
server {
    listen 80;
    server_name $DOMAIN www.$DOMAIN;
    root /var/www/$DOMAIN/html;
    index index.html index.htm index.php;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Rate limiting
    limit_req zone=api burst=20 nodelay;

    # File upload limit
    client_max_body_size 50M;

    # Main location
    location / {
        try_files \$uri \$uri/ =404;
    }

    # Security locations
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }

    location ~ ~$ {
        deny all;
        access_log off;
        log_not_found off;
    }

    # Static files caching
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|pdf|txt)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Logs
    access_log /var/log/nginx/$DOMAIN.access.log;
    error_log /var/log/nginx/$DOMAIN.error.log;
}
EOF
    
    # Enable site
    ln -sf "/etc/nginx/sites-available/$DOMAIN" "/etc/nginx/sites-enabled/"
    
    # Remove default site
    rm -f /etc/nginx/sites-enabled/default
    
    # Test and reload Nginx
    nginx -t || error "Cấu hình Nginx không hợp lệ"
    systemctl reload nginx
    
    success "Domain $DOMAIN đã được cấu hình"
}

# Install SSL certificate
function install_ssl() {
    progress "Cài đặt SSL certificate với Let's Encrypt"
    
    if command -v certbot &> /dev/null; then
        info "Certbot đã được cài đặt"
    else
        apt install -y certbot python3-certbot-nginx || error "Không thể cài đặt Certbot"
    fi
    
    # Check DNS resolution
    if ! dig +short "$DOMAIN" | grep -E '^[0-9.]+$' > /dev/null; then
        warning "Domain $DOMAIN chưa trỏ đến server này. SSL có thể thất bại."
        read -p "Tiếp tục cài SSL? (y/n): " continue_ssl
        if [[ ! "$continue_ssl" =~ ^[Yy]$ ]]; then
            warning "Bỏ qua cài đặt SSL"
            return
        fi
    fi
    
    # Obtain SSL certificate
    certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" \
            --non-interactive \
            --agree-tos \
            --email "$EMAIL" \
            --redirect || warning "Không thể tạo SSL certificate. Kiểm tra DNS của domain."
    
    success "SSL certificate đã được cài đặt"
}

# Setup SSL auto-renewal
function setup_ssl_renewal() {
    progress "Thiết lập auto-renewal cho SSL"
    
    # Create renewal script
    cat > /usr/local/bin/certbot-renewal.sh <<'EOF'
#!/bin/bash
/usr/bin/certbot renew --quiet
/usr/bin/systemctl reload nginx
EOF
    chmod +x /usr/local/bin/certbot-renewal.sh
    
    # Add to crontab
    if ! crontab -l 2>/dev/null | grep -q "certbot-renewal"; then
        (crontab -l 2>/dev/null; echo "0 3 * * * /usr/local/bin/certbot-renewal.sh") | crontab -
    fi
    
    success "Auto-renewal SSL đã được thiết lập"
}

# Configure SSH security
function secure_ssh() {
    progress "Cấu hình bảo mật SSH"
    
    backup_config "/etc/ssh/sshd_config"
    
    # SSH hardening
    cat > /etc/ssh/sshd_config.d/99-custom.conf <<EOF
# Custom SSH security configuration
Port $SSH_PORT
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowUsers $USERNAME
EOF
    
    # Test SSH config
    sshd -t || error "Cấu hình SSH không hợp lệ"
    
    warning "SSH sẽ chuyển sang port $SSH_PORT và chỉ cho phép key authentication"
    warning "Hãy đảm bảo bạn đã setup SSH key trước khi restart SSH service"
    
    success "SSH đã được cấu hình bảo mật"
}

# Configure Fail2Ban
function configure_fail2ban() {
    progress "Cấu hình Fail2Ban"
    
    # Create custom jail configuration
    cat > /etc/fail2ban/jail.d/custom.conf <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 24h

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
logpath = /var/log/nginx/*error*.log
maxretry = 5

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
logpath = /var/log/nginx/*error*.log
maxretry = 10
EOF
    
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    success "Fail2Ban đã được cấu hình"
}

# Setup log rotation
function setup_logrotation() {
    progress "Cấu hình log rotation"
    
    # Nginx log rotation
    cat > /etc/logrotate.d/nginx <<EOF
/var/log/nginx/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 www-data adm
    sharedscripts
    prerotate
        if [ -d /etc/logrotate.d/httpd-prerotate ]; then \
            run-parts /etc/logrotate.d/httpd-prerotate; \
        fi \
    endscript
    postrotate
        invoke-rc.d nginx rotate >/dev/null 2>&1
    endscript
}
EOF
    
    # System log rotation for our setup logs
    cat > /etc/logrotate.d/vps-setup <<EOF
/var/log/vps-setup*.log {
    weekly
    missingok
    rotate 12
    compress
    delaycompress
    notifempty
    create 0644 root root
}
EOF
    
    success "Log rotation đã được cấu hình"
}

# Install monitoring tools
function install_monitoring() {
    progress "Cài đặt công cụ monitoring cơ bản"
    
    # Install netdata for system monitoring
    if ! command -v netdata &> /dev/null; then
        bash <(curl -Ss https://my-netdata.io/kickstart.sh) --dont-wait || warning "Không thể cài đặt Netdata"
    fi
    
    # Setup basic system monitoring script
    cat > /usr/local/bin/system-health-check.sh <<'EOF'
#!/bin/bash
# Basic system health check

LOG_FILE="/var/log/system-health.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Check disk usage
DISK_USAGE=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 90 ]; then
    echo "$DATE - WARNING: Disk usage is ${DISK_USAGE}%" >> $LOG_FILE
fi

# Check memory usage
MEM_USAGE=$(free | grep '^Mem:' | awk '{printf "%.0f", $3/$2 * 100.0}')
if [ $MEM_USAGE -gt 90 ]; then
    echo "$DATE - WARNING: Memory usage is ${MEM_USAGE}%" >> $LOG_FILE
fi

# Check load average
LOAD_AVG=$(uptime | awk -F'load average:' '{print $2}' | cut -d, -f1 | xargs)
if (( $(echo "$LOAD_AVG > 4" | bc -l) )); then
    echo "$DATE - WARNING: High load average: $LOAD_AVG" >> $LOG_FILE
fi
EOF
    
    chmod +x /usr/local/bin/system-health-check.sh
    
    # Add to crontab for regular checks
    if ! crontab -l 2>/dev/null | grep -q "system-health-check"; then
        (crontab -l 2>/dev/null; echo "*/15 * * * * /usr/local/bin/system-health-check.sh") | crontab -
    fi
    
    success "Monitoring tools đã được cài đặt"
}

# System optimization
function optimize_system() {
    progress "Tối ưu hóa hệ thống"
    
    # Kernel parameters optimization
    cat >> /etc/sysctl.conf <<EOF

# VPS Optimization
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 65536 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_congestion_control = bbr
EOF
    
    sysctl -p
    
    # Update timezone to Vietnam
    timedatectl set-timezone Asia/Ho_Chi_Minh
    
    success "Hệ thống đã được tối ưu hóa"
}

# Create summary and final instructions
function show_summary() {
    progress "Tạo báo cáo hoàn thành"
    
    local summary_file="/root/vps-setup-summary.txt"
    
    cat > "$summary_file" <<EOF
========================================
VPS SETUP COMPLETION SUMMARY
========================================
Date: $(date)
Domain: $DOMAIN
Email: $EMAIL
SSH Port: $SSH_PORT
$(if [[ "$CREATE_USER" =~ ^[Yy]$ ]]; then echo "Username: $USERNAME"; fi)

INSTALLED SERVICES:
- Nginx (Web server)
- Docker & Docker Compose
- Let's Encrypt SSL
- UFW Firewall
- Fail2Ban (Intrusion prevention)
- Netdata (System monitoring)

SECURITY CONFIGURATIONS:
- SSH hardened (key-only authentication)
- Firewall configured
- Rate limiting enabled
- Security headers added
- Log rotation configured

IMPORTANT NEXT STEPS:
1. Setup SSH key for user: $USERNAME
   ssh-keygen -t ed25519 -C "your_email@example.com"
   
2. Copy SSH key to server:
   ssh-copy-id -p $SSH_PORT $USERNAME@your_server_ip

3. Test SSH connection BEFORE closing current session:
   ssh -p $SSH_PORT $USERNAME@your_server_ip

4. Restart SSH service after confirming key access:
   systemctl restart ssh

5. Access monitoring: http://$DOMAIN:19999

FILES LOCATION:
- Logs: $LOG_FILE
- Backups: $BACKUP_DIR
- Web root: /var/www/$DOMAIN/html

========================================
EOF
    
    echo -e "\n${GREEN}🎉 VPS SETUP HOÀN TẤT! 🎉${NC}"
    echo -e "${GREEN}===========================================${NC}"
    echo -e "${BLUE}Domain:${NC} $DOMAIN"
    echo -e "${BLUE}SSL:${NC} Đã cài đặt (nếu DNS đúng)"
    echo -e "${BLUE}SSH Port:${NC} $SSH_PORT"
    if [[ "$CREATE_USER" =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}User:${NC} $USERNAME"
    fi
    echo -e "${GREEN}===========================================${NC}"
    echo -e "\n${YELLOW}⚠️  QUAN TRỌNG:${NC}"
    echo -e "1. Đọc file hướng dẫn: ${BLUE}$summary_file${NC}"
    echo -e "2. Setup SSH key TRƯỚC KHI đóng session này"
    echo -e "3. Test SSH connection trên port $SSH_PORT"
    echo -e "\n${BLUE}Log file:${NC} $LOG_FILE"
    echo -e "${BLUE}Backup files:${NC} $BACKUP_DIR"
}

# Main execution
function main() {
    show_banner
    check_prerequisites
    get_user_input
    update_system
    create_user
    setup_firewall
    install_docker
    install_nginx
    configure_domain
    install_ssl
    setup_ssl_renewal
    secure_ssh
    configure_fail2ban
    setup_logrotation
    install_monitoring
    optimize_system
    show_summary
    
    echo -e "\n${GREEN}✨ Script completed successfully! ✨${NC}"
}

# Error handling
trap 'error "Script interrupted or failed at step $STEP"' ERR

# Run main function
main "$@"