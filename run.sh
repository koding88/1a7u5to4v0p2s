#!/bin/bash
# Improved Auto Setup VPS: Nginx + Docker + SSL + Security
# Author: koding88
# Version: 2.0
#
# Usage:
#   ./run.sh           - Interactive menu mode
#   ./run.sh --auto    - Auto full setup mode
#   ./run.sh --full    - Auto full setup mode

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration
SCRIPT_VERSION="2.0"
LOG_FILE="/var/log/vps-setup-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/vps-setup-backups"
SSH_PORT="22"
TOTAL_STEPS=16

# Initialize
STEP=0
DOMAIN=""
EMAIL=""
CREATE_USER="n"
USERNAME=""
SETUP_PROXY="n"
PROXY_PORT=""

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

# Detect existing configuration
function detect_existing_config() {
    # Detect existing domain from nginx sites-enabled
    local existing_domain=""
    if [[ -d /etc/nginx/sites-enabled ]]; then
        for site in /etc/nginx/sites-enabled/*; do
            if [[ -f "$site" ]] && [[ "$(basename "$site")" != "default" ]]; then
                existing_domain=$(basename "$site")
                break
            fi
        done
    fi

    # Detect existing email from Let's Encrypt
    local existing_email=""
    if [[ -f /etc/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory/*/regr.json ]]; then
        existing_email=$(grep -o '"mailto:[^"]*"' /etc/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory/*/regr.json 2>/dev/null | head -1 | sed 's/"mailto://;s/"//')
    fi

    # Detect existing SSH port
    local existing_ssh_port="22"
    if [[ -f /etc/ssh/sshd_config.d/99-custom.conf ]]; then
        existing_ssh_port=$(grep "^Port" /etc/ssh/sshd_config.d/99-custom.conf 2>/dev/null | awk '{print $2}' || echo "22")
    elif grep -q "^Port" /etc/ssh/sshd_config 2>/dev/null; then
        existing_ssh_port=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}')
    fi

    # Detect existing non-root user (exclude system users)
    local existing_user=""
    while IFS=: read -r username _ uid _ _ home shell; do
        if [[ $uid -ge 1000 ]] && [[ $uid -lt 65534 ]] && [[ "$username" != "nobody" ]] && [[ "$shell" != "/usr/sbin/nologin" ]] && [[ "$shell" != "/bin/false" ]]; then
            existing_user="$username"
            break
        fi
    done < /etc/passwd

    # Set global variables
    EXISTING_DOMAIN="$existing_domain"
    EXISTING_EMAIL="$existing_email"
    EXISTING_SSH_PORT="$existing_ssh_port"
    EXISTING_USER="$existing_user"
}

# User input with validation
function get_user_input() {
    progress "Thu thập thông tin cấu hình"

    # Detect existing configuration first
    detect_existing_config

    # Show existing configuration if any
    if [[ -n "$EXISTING_DOMAIN" ]] || [[ -n "$EXISTING_EMAIL" ]] || [[ "$EXISTING_SSH_PORT" != "22" ]] || [[ -n "$EXISTING_USER" ]]; then
        echo -e "\n${BLUE}🔍 Phát hiện cấu hình hiện có:${NC}"
        [[ -n "$EXISTING_DOMAIN" ]] && echo -e "${YELLOW}Domain:${NC} $EXISTING_DOMAIN"
        [[ -n "$EXISTING_EMAIL" ]] && echo -e "${YELLOW}Email:${NC} $EXISTING_EMAIL"
        echo -e "${YELLOW}SSH Port:${NC} $EXISTING_SSH_PORT"
        [[ -n "$EXISTING_USER" ]] && echo -e "${YELLOW}User:${NC} $EXISTING_USER"
        echo ""
    fi

    # Domain input
    if [[ -n "$EXISTING_DOMAIN" ]]; then
        read -p "Domain hiện tại: $EXISTING_DOMAIN. Thay đổi? (y/n): " change_domain
        if [[ "$change_domain" =~ ^[Yy]$ ]]; then
            while true; do
                read -p "Nhập domain name mới: " DOMAIN
                if [[ -n "$DOMAIN" ]] && validate_domain "$DOMAIN"; then
                    break
                else
                    echo -e "${RED}Domain không hợp lệ. Vui lòng nhập lại.${NC}"
                fi
            done
        else
            DOMAIN="$EXISTING_DOMAIN"
        fi
    else
        while true; do
            read -p "Nhập domain name (vd: example.com): " DOMAIN
            if [[ -n "$DOMAIN" ]] && validate_domain "$DOMAIN"; then
                break
            else
                echo -e "${RED}Domain không hợp lệ. Vui lòng nhập lại.${NC}"
            fi
        done
    fi

    # Email input
    if [[ -n "$EXISTING_EMAIL" ]]; then
        read -p "Email hiện tại: $EXISTING_EMAIL. Thay đổi? (y/n): " change_email
        if [[ "$change_email" =~ ^[Yy]$ ]]; then
            while true; do
                read -p "Nhập email mới cho SSL certificate: " EMAIL
                if [[ -n "$EMAIL" ]] && validate_email "$EMAIL"; then
                    break
                else
                    echo -e "${RED}Email không hợp lệ. Vui lòng nhập lại.${NC}"
                fi
            done
        else
            EMAIL="$EXISTING_EMAIL"
        fi
    else
        while true; do
            read -p "Nhập email cho SSL certificate: " EMAIL
            if [[ -n "$EMAIL" ]] && validate_email "$EMAIL"; then
                break
            else
                echo -e "${RED}Email không hợp lệ. Vui lòng nhập lại.${NC}"
            fi
        done
    fi

    # User creation option
    if [[ -n "$EXISTING_USER" ]]; then
        read -p "User hiện tại: $EXISTING_USER. Tạo user mới? (y/n): " CREATE_USER
        if [[ "$CREATE_USER" =~ ^[Yy]$ ]]; then
            while true; do
                read -p "Nhập tên user mới: " USERNAME
                if [[ -n "$USERNAME" ]] && validate_username "$USERNAME"; then
                    break
                else
                    echo -e "${RED}Username không hợp lệ (chỉ chữ thường, số, dấu gạch dưới, gạch ngang).${NC}"
                fi
            done
        else
            CREATE_USER="n"
            USERNAME="$EXISTING_USER"
        fi
    else
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
    fi

    # SSH port
    if [[ "$EXISTING_SSH_PORT" != "22" ]]; then
        read -p "SSH port hiện tại: $EXISTING_SSH_PORT. Thay đổi? (y/n): " change_ssh_port
        if [[ "$change_ssh_port" =~ ^[Yy]$ ]]; then
            read -p "SSH port mới (mặc định 22): " input_port
            SSH_PORT=${input_port:-22}
        else
            SSH_PORT="$EXISTING_SSH_PORT"
        fi
    else
        read -p "SSH port (mặc định 22): " input_port
        SSH_PORT=${input_port:-22}
    fi

    # Reverse proxy option
    read -p "Cấu hình reverse proxy cho ứng dụng backend? (y/n): " SETUP_PROXY
    if [[ "$SETUP_PROXY" =~ ^[Yy]$ ]]; then
        while true; do
            read -p "Nhập port của ứng dụng backend (vd: 3000): " PROXY_PORT
            if [[ "$PROXY_PORT" =~ ^[0-9]+$ ]] && [[ "$PROXY_PORT" -ge 1 ]] && [[ "$PROXY_PORT" -le 65535 ]]; then
                break
            else
                echo -e "${RED}Port không hợp lệ. Vui lòng nhập số từ 1-65535.${NC}"
            fi
        done
    fi

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

    # Check if UFW is already configured
    if ufw status | grep -q "Status: active"; then
        warning "UFW đã được kích hoạt"
        # Check if our ports are already configured
        if ufw status | grep -q "$SSH_PORT/tcp" && ufw status | grep -q "80/tcp" && ufw status | grep -q "443/tcp"; then
            success "Firewall đã được cấu hình đầy đủ"
            return
        else
            info "Thêm các rule còn thiếu"
        fi
    else
        # Reset UFW to defaults
        ufw --force reset

        # Default policies
        ufw default deny incoming
        ufw default allow outgoing
    fi

    # Allow specific ports (only if not already allowed)
    if ! ufw status | grep -q "$SSH_PORT/tcp"; then
        ufw allow "$SSH_PORT"/tcp comment 'SSH'
    fi
    if ! ufw status | grep -q "80/tcp"; then
        ufw allow 80/tcp comment 'HTTP'
    fi
    if ! ufw status | grep -q "443/tcp"; then
        ufw allow 443/tcp comment 'HTTPS'
    fi

    # Enable UFW if not already enabled
    if ! ufw status | grep -q "Status: active"; then
        ufw --force enable
    fi

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

    # Remove old optimization config if exists (to avoid conflicts)
    if [[ -f /etc/nginx/conf.d/optimization.conf ]]; then
        backup_config "/etc/nginx/conf.d/optimization.conf"
        rm -f /etc/nginx/conf.d/optimization.conf
        info "Đã xóa file optimization.conf cũ"
    fi

    # Create new Nginx optimization configuration
    cat > /etc/nginx/conf.d/optimization.conf <<EOF
# Rate limiting
limit_req_zone \$binary_remote_addr zone=login:10m rate=5r/m;
limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;

# Note: Gzip compression is already enabled in main nginx.conf
# Additional gzip settings can be configured there if needed

# Security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;

# Hide Nginx version
server_tokens off;
EOF

    # Test nginx configuration
    if ! nginx -t; then
        error "Cấu hình Nginx không hợp lệ sau khi tạo optimization.conf"
    fi
    
    success "Nginx đã được cài đặt và cấu hình"
}

# Configure domain
function configure_domain() {
    progress "Cấu hình Nginx cho domain: $DOMAIN"

    # Remove old configuration files if they exist
    if [[ -f "/etc/nginx/sites-available/$DOMAIN" ]]; then
        backup_config "/etc/nginx/sites-available/$DOMAIN"
        rm -f "/etc/nginx/sites-available/$DOMAIN"
        info "Đã xóa file cấu hình cũ: /etc/nginx/sites-available/$DOMAIN"
    fi

    if [[ -L "/etc/nginx/sites-enabled/$DOMAIN" ]]; then
        rm -f "/etc/nginx/sites-enabled/$DOMAIN"
        info "Đã xóa symlink cũ: /etc/nginx/sites-enabled/$DOMAIN"
    fi

    # For API backend, we don't need static files
    # Just create basic directory structure
    mkdir -p "/var/www/$DOMAIN"
    chown -R www-data:www-data "/var/www/$DOMAIN"

    # Ensure we have proxy port configured
    if [[ -z "$PROXY_PORT" ]]; then
        while true; do
            read -p "Nhập port của API backend (vd: 3000): " PROXY_PORT
            if [[ "$PROXY_PORT" =~ ^[0-9]+$ ]] && [[ "$PROXY_PORT" -ge 1 ]] && [[ "$PROXY_PORT" -le 65535 ]]; then
                break
            else
                echo -e "${RED}Port không hợp lệ. Vui lòng nhập số từ 1-65535.${NC}"
            fi
        done
        SETUP_PROXY="y"
    fi
    
    # Check if www subdomain exists for nginx config
    local nginx_server_name="$DOMAIN"
    if dig +short "www.$DOMAIN" | grep -E '^[0-9.]+$' > /dev/null; then
        nginx_server_name="$DOMAIN www.$DOMAIN"
    fi

    # Create Nginx server block with reverse proxy (default for API backend)
    cat > "/etc/nginx/sites-available/$DOMAIN" <<EOF
server {
    listen 80;
    server_name $nginx_server_name;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Rate limiting for API
    limit_req zone=api burst=20 nodelay;

    # File upload limit for API
    client_max_body_size 50M;

    # Swagger UI location - must be before the main location block
    location /swagger/swagger/ {
        # Reverse proxy to backend application
        proxy_pass http://127.0.0.1:$PROXY_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # Add CORS headers for Swagger UI
        add_header 'Access-Control-Allow-Origin' '*';
        add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS';
        add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range';
        add_header 'Access-Control-Expose-Headers' 'Content-Length,Content-Range';

        # Handle OPTIONS request for CORS
        if (\$request_method = 'OPTIONS') {
            add_header 'Access-Control-Allow-Origin' '*';
            add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS';
            add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range';
            add_header 'Access-Control-Max-Age' 1728000;
            add_header 'Content-Type' 'text/plain; charset=utf-8';
            add_header 'Content-Length' 0;
            return 204;
        }
    }

    # Main location - Reverse proxy to API backend
    location / {
        # Reverse proxy to backend application
        proxy_pass http://127.0.0.1:$PROXY_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
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

    # Auto-deploy SSL if certificate exists but not configured
    if [[ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]] && ! grep -q "listen.*443.*ssl" "/etc/nginx/sites-available/$DOMAIN" 2>/dev/null; then
        info "Phát hiện SSL certificate có sẵn cho $DOMAIN"
        info "Đang tự động deploy SSL vào Nginx config..."

        if certbot --nginx -d "$DOMAIN" --redirect --non-interactive --reinstall 2>/dev/null; then
            success "Đã tự động deploy SSL certificate"
        else
            warning "Tự động deploy SSL thất bại. Bạn có thể chạy option 7 để cài SSL thủ công."
        fi
    fi

    success "Domain $DOMAIN đã được cấu hình"
}

# Install SSL certificate
function install_ssl() {
    progress "Cài đặt SSL certificate với Let's Encrypt"

    # Check if SSL certificate already exists for domain
    if [[ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
        warning "SSL certificate cho $DOMAIN đã tồn tại"

        # Check if Nginx config has SSL configured
        if ! grep -q "listen.*443.*ssl" "/etc/nginx/sites-available/$DOMAIN" 2>/dev/null; then
            info "SSL certificate tồn tại nhưng chưa được deploy vào Nginx config"
            info "Đang deploy SSL certificate vào Nginx..."

            # Deploy existing certificate to Nginx config
            if certbot --nginx -d "$DOMAIN" --redirect --non-interactive --reinstall 2>/dev/null; then
                success "Đã deploy SSL certificate vào Nginx config"
            else
                # If non-interactive fails, try interactive mode
                warning "Deploy tự động thất bại, chuyển sang chế độ tương tác..."
                certbot --nginx -d "$DOMAIN" --redirect || warning "Không thể deploy SSL certificate vào Nginx"
            fi
        else
            info "SSL certificate đã được cấu hình trong Nginx"
        fi

        success "SSL certificate đã được cài đặt"
        return
    fi

    if command -v certbot &> /dev/null; then
        info "Certbot đã được cài đặt"
    else
        apt install -y certbot python3-certbot-nginx || error "Không thể cài đặt Certbot"
    fi
    
    # Check DNS resolution for main domain
    if ! dig +short "$DOMAIN" | grep -E '^[0-9.]+$' > /dev/null; then
        warning "Domain $DOMAIN chưa trỏ đến server này. SSL có thể thất bại."
        read -p "Tiếp tục cài SSL? (y/n): " continue_ssl
        if [[ ! "$continue_ssl" =~ ^[Yy]$ ]]; then
            warning "Bỏ qua cài đặt SSL"
            return
        fi
    fi

    # Check if www subdomain exists
    local domains_to_certify="$DOMAIN"
    if dig +short "www.$DOMAIN" | grep -E '^[0-9.]+$' > /dev/null; then
        domains_to_certify="$DOMAIN,www.$DOMAIN"
        info "Phát hiện www subdomain, sẽ tạo SSL cho cả hai"
    else
        info "Không phát hiện www subdomain, chỉ tạo SSL cho domain chính"
    fi

    # Obtain SSL certificate
    certbot --nginx -d "$DOMAIN" $(if [[ "$domains_to_certify" == *"www"* ]]; then echo "-d www.$DOMAIN"; fi) \
            --non-interactive \
            --agree-tos \
            --email "$EMAIL" \
            --redirect || warning "Không thể tạo SSL certificate. Kiểm tra DNS của domain."
    
    success "SSL certificate đã được cài đặt"
}

# Setup SSL auto-renewal
function setup_ssl_renewal() {
    progress "Thiết lập auto-renewal cho SSL"

    # Check if auto-renewal is already configured
    if [[ -f /usr/local/bin/certbot-renewal.sh ]] && crontab -l 2>/dev/null | grep -q "certbot-renewal"; then
        warning "Auto-renewal SSL đã được thiết lập"
        success "Auto-renewal SSL đã được thiết lập"
        return
    fi

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

    # Check if SSH is already hardened
    if [[ -f /etc/ssh/sshd_config.d/99-custom.conf ]]; then
        warning "SSH đã được cấu hình bảo mật"
        success "SSH đã được cấu hình bảo mật"
        return
    fi

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

    # Check if Fail2Ban is already configured
    if [[ -f /etc/fail2ban/jail.d/custom.conf ]] && systemctl is-active --quiet fail2ban; then
        warning "Fail2Ban đã được cấu hình và đang chạy"
        success "Fail2Ban đã được cấu hình"
        return
    fi

    # Install fail2ban if not installed
    if ! is_installed fail2ban; then
        apt install -y fail2ban || error "Không thể cài đặt Fail2Ban"
    fi

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

    # Check if custom log rotation is already configured
    if [[ -f /etc/logrotate.d/vps-setup ]]; then
        warning "Log rotation đã được cấu hình"
        success "Log rotation đã được cấu hình"
        return
    fi

    # Nginx log rotation (only if nginx is installed)
    if is_installed nginx; then
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
    fi

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
    
    # Add to crontab for regular checks (only if not already added)
    if ! crontab -l 2>/dev/null | grep -q "system-health-check"; then
        (crontab -l 2>/dev/null; echo "*/15 * * * * /usr/local/bin/system-health-check.sh") | crontab -
        info "Đã thêm system health check vào crontab"
    else
        info "System health check đã có trong crontab"
    fi
    
    success "Monitoring tools đã được cài đặt"
}

# System optimization
function optimize_system() {
    progress "Tối ưu hóa hệ thống"

    # Check if system optimization is already applied
    if grep -q "# VPS Optimization" /etc/sysctl.conf; then
        warning "Hệ thống đã được tối ưu hóa"
        success "Hệ thống đã được tối ưu hóa"
        return
    fi

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
$(if [[ "$CREATE_USER" =~ ^[Yy]$ ]] || [[ -n "$USERNAME" ]]; then echo "Username: $USERNAME"; fi)
$(if [[ "$SETUP_PROXY" =~ ^[Yy]$ ]]; then echo "Reverse Proxy: Port $PROXY_PORT"; fi)

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
    echo -e "${BLUE}Email:${NC} $EMAIL"
    echo -e "${BLUE}SSL:${NC} Đã cài đặt (nếu DNS đúng)"
    echo -e "${BLUE}SSH Port:${NC} $SSH_PORT"
    if [[ "$CREATE_USER" =~ ^[Yy]$ ]] || [[ -n "$USERNAME" ]]; then
        echo -e "${BLUE}User:${NC} $USERNAME"
    fi
    if [[ "$SETUP_PROXY" =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}Reverse Proxy:${NC} Port $PROXY_PORT"
    fi
    echo -e "${GREEN}===========================================${NC}"
    echo -e "\n${YELLOW}⚠️  QUAN TRỌNG:${NC}"
    echo -e "1. Đọc file hướng dẫn: ${BLUE}$summary_file${NC}"
    echo -e "2. Setup SSH key TRƯỚC KHI đóng session này"
    echo -e "3. Test SSH connection trên port $SSH_PORT"
    echo -e "\n${BLUE}Log file:${NC} $LOG_FILE"
    echo -e "${BLUE}Backup files:${NC} $BACKUP_DIR"
}

# Show current configuration
function show_current_config() {
    echo -e "\n${BLUE}📋 CẤU HÌNH HIỆN TẠI${NC}"
    echo -e "${BLUE}===========================================${NC}"

    detect_existing_config

    # Domain
    if [[ -n "$EXISTING_DOMAIN" ]]; then
        echo -e "${GREEN}✅ Domain:${NC} $EXISTING_DOMAIN"
        if [[ -f "/etc/nginx/sites-enabled/$EXISTING_DOMAIN" ]]; then
            echo -e "   ${YELLOW}└─ Nginx:${NC} Đã cấu hình"
        fi
        if [[ -f "/etc/letsencrypt/live/$EXISTING_DOMAIN/fullchain.pem" ]]; then
            echo -e "   ${YELLOW}└─ SSL:${NC} Đã cài đặt"
        fi
    else
        echo -e "${RED}❌ Domain:${NC} Chưa cấu hình"
    fi

    # Email
    if [[ -n "$EXISTING_EMAIL" ]]; then
        echo -e "${GREEN}✅ Email:${NC} $EXISTING_EMAIL"
    else
        echo -e "${RED}❌ Email:${NC} Chưa cấu hình"
    fi

    # SSH
    echo -e "${GREEN}✅ SSH Port:${NC} $EXISTING_SSH_PORT"
    if [[ -f /etc/ssh/sshd_config.d/99-custom.conf ]]; then
        echo -e "   ${YELLOW}└─ Security:${NC} Đã hardening"
    else
        echo -e "   ${YELLOW}└─ Security:${NC} Chưa hardening"
    fi

    # User
    if [[ -n "$EXISTING_USER" ]]; then
        echo -e "${GREEN}✅ User:${NC} $EXISTING_USER"
    else
        echo -e "${YELLOW}⚠️  User:${NC} Chỉ có root"
    fi

    # Services
    echo -e "\n${BLUE}🔧 DỊCH VỤ${NC}"

    # Docker
    if command -v docker &> /dev/null; then
        echo -e "${GREEN}✅ Docker:${NC} Đã cài đặt"
    else
        echo -e "${RED}❌ Docker:${NC} Chưa cài đặt"
    fi

    # Nginx
    if is_installed nginx; then
        echo -e "${GREEN}✅ Nginx:${NC} Đã cài đặt"
    else
        echo -e "${RED}❌ Nginx:${NC} Chưa cài đặt"
    fi

    # UFW
    if ufw status | grep -q "Status: active"; then
        echo -e "${GREEN}✅ Firewall:${NC} Đã kích hoạt"
    else
        echo -e "${RED}❌ Firewall:${NC} Chưa kích hoạt"
    fi

    # Fail2Ban
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        echo -e "${GREEN}✅ Fail2Ban:${NC} Đang chạy"
    else
        echo -e "${RED}❌ Fail2Ban:${NC} Chưa chạy"
    fi

    # Monitoring
    if command -v netdata &> /dev/null; then
        echo -e "${GREEN}✅ Monitoring:${NC} Netdata đã cài"
    else
        echo -e "${RED}❌ Monitoring:${NC} Chưa cài đặt"
    fi

    echo -e "${BLUE}===========================================${NC}"
    echo -e "\n${PURPLE}💡 TÍNH NĂNG BỔ SUNG${NC}"
    echo -e "${YELLOW}15.${NC} Kiểm tra cấu hình máy (CPU, RAM, SSD)"
    echo -e "${YELLOW}16.${NC} Kiểm tra thông tin mạng (IP, Ports, Speed)"
    echo -e "${YELLOW}17.${NC} Kiểm tra Docker containers"
    echo -e "${YELLOW}18.${NC} Dừng Docker containers"
    echo -e "${YELLOW}19.${NC} Khởi động lại Nginx"
    echo -e "${YELLOW}20.${NC} Xem cấu hình Nginx + Domain"
    echo -e "${BLUE}===========================================${NC}"
}

# Show menu
function show_menu() {
    echo -e "\n${PURPLE}🚀 VPS SETUP MENU${NC}"
    echo -e "${PURPLE}===========================================${NC}"
    echo -e "${YELLOW} 0.${NC} Hiển thị cấu hình hiện tại"
    echo -e "${YELLOW} 1.${NC} Cập nhật hệ thống và cài gói cơ bản"
    echo -e "${YELLOW} 2.${NC} Tạo/quản lý user non-root"
    echo -e "${YELLOW} 3.${NC} Cấu hình firewall (UFW)"
    echo -e "${YELLOW} 4.${NC} Cài đặt Docker & Docker Compose"
    echo -e "${YELLOW} 5.${NC} Cài đặt và cấu hình Nginx"
    echo -e "${YELLOW} 6.${NC} Cấu hình domain cho Nginx"
    echo -e "${YELLOW} 7.${NC} Cài đặt SSL certificate"
    echo -e "${YELLOW} 8.${NC} Thiết lập SSL auto-renewal"
    echo -e "${YELLOW} 9.${NC} Cấu hình bảo mật SSH"
    echo -e "${YELLOW}10.${NC} Cấu hình Fail2Ban"
    echo -e "${YELLOW}11.${NC} Cấu hình log rotation"
    echo -e "${YELLOW}12.${NC} Cài đặt monitoring tools"
    echo -e "${YELLOW}13.${NC} Tối ưu hóa hệ thống"
    echo -e "${YELLOW}14.${NC} Tạo báo cáo tổng kết"
    echo -e "${BLUE}15.${NC} 💻 Kiểm tra cấu hình máy (CPU, RAM, SSD)"
    echo -e "${BLUE}16.${NC} 🌐 Kiểm tra thông tin mạng (IP, Ports, Speed)"
    echo -e "${BLUE}17.${NC} 🐳 Kiểm tra Docker containers"
    echo -e "${BLUE}18.${NC} 🛑 Dừng Docker containers"
    echo -e "${BLUE}19.${NC} 🔄 Khởi động lại Nginx"
    echo -e "${BLUE}20.${NC} 📋 Xem cấu hình Nginx + Domain"
    echo -e "${GREEN}88.${NC} 🚀 AUTO SETUP FOR DEPLOY (Steps 1-14)"
    echo -e "${RED} q.${NC} Thoát"
    echo -e "${PURPLE}===========================================${NC}"
}

# Handle menu choice
function handle_menu_choice() {
    local choice=$1

    case $choice in
        0)
            show_current_config
            ;;
        1)
            update_system
            ;;
        2)
            get_user_input_for_user_creation
            create_user
            ;;
        3)
            setup_firewall
            ;;
        4)
            install_docker
            ;;
        5)
            install_nginx
            ;;
        6)
            get_user_input_for_domain
            configure_domain
            ;;
        7)
            get_user_input_for_ssl
            install_ssl
            ;;
        8)
            setup_ssl_renewal
            ;;
        9)
            secure_ssh
            ;;
        10)
            configure_fail2ban
            ;;
        11)
            setup_logrotation
            ;;
        12)
            install_monitoring
            ;;
        13)
            optimize_system
            ;;
        14)
            show_summary
            ;;
        15)
            check_system_specs
            ;;
        16)
            check_network_info
            ;;
        17)
            check_docker_containers
            ;;
        18)
            stop_docker_containers
            ;;
        19)
            restart_nginx
            ;;
        20)
            view_nginx_config
            ;;
        88)
            auto_setup_for_deploy
            ;;
        q|Q)
            echo -e "\n${GREEN}👋 Cảm ơn bạn đã sử dụng VPS Setup Script!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}❌ Lựa chọn không hợp lệ. Vui lòng thử lại.${NC}"
            ;;
    esac
}

# Auto setup for deployment
function auto_setup_for_deploy() {
    echo -e "\n${GREEN}🚀 BẮT ĐẦU AUTO SETUP FOR DEPLOY...${NC}"
    echo -e "${BLUE}Chạy các bước cần thiết cho deployment (Steps 1-14)${NC}"
    echo ""

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

    echo -e "\n${GREEN}✨ Auto setup for deploy completed successfully! ✨${NC}"
    echo -e "${YELLOW}💡 Tip: Sử dụng các tính năng bổ sung (15-20) để monitoring và quản lý server${NC}"
}

# System information functions
function check_system_specs() {
    echo -e "\n${BLUE}💻 THÔNG TIN CẤU HÌNH MÁY${NC}"
    echo -e "${BLUE}===========================================${NC}"

    # CPU Information
    echo -e "${GREEN}🔧 CPU:${NC}"
    local cpu_model=$(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)
    local cpu_cores=$(nproc)
    local cpu_threads=$(grep -c processor /proc/cpuinfo)
    echo -e "   Model: $cpu_model"
    echo -e "   Cores: $cpu_cores"
    echo -e "   Threads: $cpu_threads"

    # Load average
    local load_avg=$(uptime | awk -F'load average:' '{print $2}')
    echo -e "   Load Average:$load_avg"

    # RAM Information
    echo -e "\n${GREEN}🧠 RAM:${NC}"
    local ram_info=$(free -h | grep "Mem:")
    local ram_total=$(echo $ram_info | awk '{print $2}')
    local ram_used=$(echo $ram_info | awk '{print $3}')
    local ram_free=$(echo $ram_info | awk '{print $4}')
    local ram_percent=$(free | grep Mem | awk '{printf("%.1f%%", $3/$2 * 100.0)}')
    echo -e "   Total: $ram_total"
    echo -e "   Used: $ram_used ($ram_percent)"
    echo -e "   Free: $ram_free"

    # Swap Information
    local swap_info=$(free -h | grep "Swap:")
    if [[ -n "$swap_info" ]]; then
        local swap_total=$(echo $swap_info | awk '{print $2}')
        local swap_used=$(echo $swap_info | awk '{print $3}')
        echo -e "   Swap: $swap_used / $swap_total"
    fi

    # Storage Information
    echo -e "\n${GREEN}💾 STORAGE:${NC}"
    df -h | grep -E '^/dev/' | while read line; do
        local device=$(echo $line | awk '{print $1}')
        local size=$(echo $line | awk '{print $2}')
        local used=$(echo $line | awk '{print $3}')
        local avail=$(echo $line | awk '{print $4}')
        local percent=$(echo $line | awk '{print $5}')
        local mount=$(echo $line | awk '{print $6}')
        echo -e "   $device ($mount): $used / $size ($percent used)"
    done

    # System uptime
    echo -e "\n${GREEN}⏰ UPTIME:${NC}"
    local uptime_info=$(uptime -p)
    echo -e "   $uptime_info"

    # OS Information
    echo -e "\n${GREEN}🐧 OS:${NC}"
    if [[ -f /etc/os-release ]]; then
        local os_name=$(grep "PRETTY_NAME" /etc/os-release | cut -d'"' -f2)
        echo -e "   $os_name"
    fi
    local kernel=$(uname -r)
    echo -e "   Kernel: $kernel"

    echo -e "${BLUE}===========================================${NC}"
}

function check_network_info() {
    echo -e "\n${BLUE}🌐 THÔNG TIN MẠNG${NC}"
    echo -e "${BLUE}===========================================${NC}"

    # IP Information
    echo -e "${GREEN}📍 IP ADDRESS:${NC}"

    # Public IP
    local public_ip=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "Không thể lấy IP")
    echo -e "   Public IP: $public_ip"

    # Private IP
    local private_ip=$(ip route get 8.8.8.8 | awk '{print $7; exit}' 2>/dev/null || echo "Không xác định")
    echo -e "   Private IP: $private_ip"

    # Network interfaces
    echo -e "\n${GREEN}🔌 NETWORK INTERFACES:${NC}"
    ip -4 addr show | grep -E "inet.*scope global" | while read line; do
        local interface=$(echo $line | awk '{print $NF}')
        local ip=$(echo $line | awk '{print $2}' | cut -d'/' -f1)
        echo -e "   $interface: $ip"
    done

    # Open ports
    echo -e "\n${GREEN}🚪 OPEN PORTS:${NC}"
    if command -v ss &> /dev/null; then
        echo -e "   TCP Listening Ports:"
        ss -tlnp | grep LISTEN | awk '{print $4}' | cut -d: -f2 | sort -n | uniq | head -10 | while read port; do
            local service=$(ss -tlnp | grep ":$port " | awk '{print $6}' | head -1)
            echo -e "     Port $port: $service"
        done
    elif command -v netstat &> /dev/null; then
        echo -e "   TCP Listening Ports:"
        netstat -tlnp 2>/dev/null | grep LISTEN | awk '{print $4}' | cut -d: -f2 | sort -n | uniq | head -10 | while read port; do
            echo -e "     Port $port"
        done
    else
        echo -e "   ${YELLOW}Cần cài đặt ss hoặc netstat để xem ports${NC}"
    fi

    # Network speed test
    echo -e "\n${GREEN}🚀 NETWORK SPEED TEST:${NC}"
    echo -e "   ${YELLOW}Đang test tốc độ mạng...${NC}"

    # Test ping to domestic and international servers
    echo -e "   Ping Test:"

    # Vietnam servers
    local vn_ping=$(ping -c 3 8.8.8.8 2>/dev/null | tail -1 | awk -F'/' '{print $5}' 2>/dev/null || echo "N/A")
    echo -e "     Google DNS: ${vn_ping}ms"

    local cf_ping=$(ping -c 3 1.1.1.1 2>/dev/null | tail -1 | awk -F'/' '{print $5}' 2>/dev/null || echo "N/A")
    echo -e "     Cloudflare: ${cf_ping}ms"

    # Download speed test (simple)
    echo -e "   Download Test:"
    if command -v wget &> /dev/null; then
        local download_speed=$(timeout 10 wget -O /dev/null http://speedtest.ftp.otenet.gr/files/test1Mb.db 2>&1 | grep -o '[0-9.]*[KMG]B/s' | tail -1 || echo "N/A")
        echo -e "     Speed: $download_speed"
    else
        echo -e "     ${YELLOW}Cần wget để test download speed${NC}"
    fi

    echo -e "${BLUE}===========================================${NC}"
}

function check_docker_containers() {
    echo -e "\n${BLUE}🐳 DOCKER CONTAINERS${NC}"
    echo -e "${BLUE}===========================================${NC}"

    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Docker chưa được cài đặt${NC}"
        read -p "Bạn có muốn cài đặt Docker không? (y/n): " install_docker
        if [[ "$install_docker" =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}Đang cài đặt Docker...${NC}"
            install_docker
            echo -e "${GREEN}✅ Docker đã được cài đặt${NC}"
        else
            echo -e "${YELLOW}Bỏ qua kiểm tra Docker containers${NC}"
            return
        fi
    fi

    # Check Docker service status
    if ! systemctl is-active --quiet docker; then
        echo -e "${YELLOW}⚠️  Docker service không chạy. Đang khởi động...${NC}"
        systemctl start docker
    fi

    echo -e "${GREEN}🔍 RUNNING CONTAINERS:${NC}"

    # Get running containers
    local running_containers=$(docker ps --format "table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}\t{{.Names}}" 2>/dev/null)

    if [[ -z "$running_containers" ]] || [[ "$running_containers" == *"CONTAINER ID"* ]] && [[ $(echo "$running_containers" | wc -l) -eq 1 ]]; then
        echo -e "   ${YELLOW}Không có container nào đang chạy${NC}"
    else
        echo "$running_containers"
    fi

    echo -e "\n${GREEN}📊 DOCKER STATS:${NC}"
    local total_containers=$(docker ps -a --format "{{.ID}}" 2>/dev/null | wc -l)
    local running_count=$(docker ps --format "{{.ID}}" 2>/dev/null | wc -l)
    local stopped_count=$((total_containers - running_count))

    echo -e "   Total containers: $total_containers"
    echo -e "   Running: $running_count"
    echo -e "   Stopped: $stopped_count"

    # Docker images
    echo -e "\n${GREEN}🖼️  DOCKER IMAGES:${NC}"
    local images_count=$(docker images --format "{{.ID}}" 2>/dev/null | wc -l)
    echo -e "   Total images: $images_count"

    if [[ $images_count -gt 0 ]]; then
        echo -e "   Recent images:"
        docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" 2>/dev/null | head -6
    fi

    # Option to view container logs
    if [[ $running_count -gt 0 ]]; then
        echo -e "\n${YELLOW}💡 Muốn xem logs của container nào đó?${NC}"
        read -p "Nhập Container ID/Name để xem logs (hoặc Enter để bỏ qua): " container_for_logs

        if [[ -n "$container_for_logs" ]]; then
            echo -e "\n${GREEN}📋 LOGS FOR CONTAINER: $container_for_logs${NC}"
            echo -e "${YELLOW}Hiển thị 50 dòng log cuối:${NC}"
            echo "----------------------------------------"

            if docker logs --tail 50 "$container_for_logs" 2>/dev/null; then
                echo "----------------------------------------"
                echo -e "${GREEN}✅ Logs hiển thị thành công${NC}"

                # Option to follow logs
                read -p "Muốn theo dõi logs real-time? (y/n): " follow_logs
                if [[ "$follow_logs" =~ ^[Yy]$ ]]; then
                    echo -e "${YELLOW}Đang theo dõi logs real-time (Ctrl+C để dừng)...${NC}"
                    docker logs -f "$container_for_logs" 2>/dev/null || echo -e "${RED}❌ Không thể theo dõi logs${NC}"
                fi
            else
                echo -e "${RED}❌ Không thể lấy logs cho container: $container_for_logs${NC}"
                echo -e "${YELLOW}Kiểm tra lại Container ID hoặc Name${NC}"
            fi
        fi
    fi

    echo -e "${BLUE}===========================================${NC}"
}

function stop_docker_containers() {
    echo -e "\n${BLUE}🛑 DỪNG DOCKER CONTAINERS${NC}"
    echo -e "${BLUE}===========================================${NC}"

    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Docker chưa được cài đặt${NC}"
        return
    fi

    # Get running containers
    local running_containers=$(docker ps --format "{{.ID}} {{.Names}} {{.Image}}" 2>/dev/null)

    if [[ -z "$running_containers" ]]; then
        echo -e "${YELLOW}Không có container nào đang chạy${NC}"
        return
    fi

    echo -e "${GREEN}🔍 CONTAINERS ĐANG CHẠY:${NC}"
    echo -e "${YELLOW}ID\t\tNAME\t\tIMAGE${NC}"
    echo "$running_containers"

    echo -e "\n${YELLOW}Nhập Container ID hoặc Name để dừng (hoặc 'all' để dừng tất cả, 'q' để thoát):${NC}"
    read -p "Lựa chọn: " container_choice

    case $container_choice in
        "q"|"Q")
            echo -e "${BLUE}Hủy thao tác${NC}"
            return
            ;;
        "all"|"ALL")
            echo -e "${YELLOW}Đang dừng tất cả containers...${NC}"
            docker stop $(docker ps -q) 2>/dev/null
            if [[ $? -eq 0 ]]; then
                echo -e "${GREEN}✅ Đã dừng tất cả containers${NC}"
            else
                echo -e "${RED}❌ Có lỗi khi dừng containers${NC}"
            fi
            ;;
        *)
            if [[ -n "$container_choice" ]]; then
                echo -e "${YELLOW}Đang dừng container: $container_choice${NC}"
                docker stop "$container_choice" 2>/dev/null
                if [[ $? -eq 0 ]]; then
                    echo -e "${GREEN}✅ Đã dừng container: $container_choice${NC}"
                else
                    echo -e "${RED}❌ Không thể dừng container: $container_choice${NC}"
                    echo -e "${YELLOW}Kiểm tra lại Container ID hoặc Name${NC}"
                fi
            else
                echo -e "${RED}❌ Vui lòng nhập Container ID hoặc Name${NC}"
            fi
            ;;
    esac

    echo -e "${BLUE}===========================================${NC}"
}

# Nginx management functions
function restart_nginx() {
    echo -e "\n${BLUE}🔄 KHỞI ĐỘNG LẠI NGINX${NC}"
    echo -e "${BLUE}===========================================${NC}"

    # Check if Nginx is installed
    if ! is_installed nginx; then
        echo -e "${RED}❌ Nginx chưa được cài đặt${NC}"
        return
    fi

    # Test configuration first
    echo -e "${YELLOW}Đang kiểm tra cấu hình Nginx...${NC}"
    if nginx -t; then
        echo -e "${GREEN}✅ Cấu hình Nginx hợp lệ${NC}"

        # Show current status
        echo -e "\n${YELLOW}Trạng thái hiện tại:${NC}"
        systemctl status nginx --no-pager -l

        # Restart Nginx
        echo -e "\n${YELLOW}Đang khởi động lại Nginx...${NC}"
        systemctl restart nginx

        if systemctl is-active --quiet nginx; then
            echo -e "${GREEN}✅ Nginx đã được khởi động lại thành công${NC}"

            # Show new status
            echo -e "\n${YELLOW}Trạng thái sau khi restart:${NC}"
            systemctl status nginx --no-pager -l | head -10
        else
            echo -e "${RED}❌ Lỗi khi khởi động lại Nginx${NC}"
            echo -e "${YELLOW}Chi tiết lỗi:${NC}"
            systemctl status nginx --no-pager -l | head -15
        fi
    else
        echo -e "${RED}❌ Cấu hình Nginx không hợp lệ. Không thể restart.${NC}"
        echo -e "${YELLOW}Vui lòng kiểm tra và sửa lỗi cấu hình trước khi restart.${NC}"
    fi

    echo -e "${BLUE}===========================================${NC}"
}

function view_nginx_config() {
    echo -e "\n${BLUE}📋 CẤU HÌNH NGINX${NC}"
    echo -e "${BLUE}===========================================${NC}"

    # Check if Nginx is installed
    if ! is_installed nginx; then
        echo -e "${RED}❌ Nginx chưa được cài đặt${NC}"
        return
    fi

    # Nginx service status
    echo -e "${GREEN}🔧 NGINX STATUS:${NC}"
    if systemctl is-active --quiet nginx; then
        echo -e "   Status: ${GREEN}Running${NC}"
    else
        echo -e "   Status: ${RED}Stopped${NC}"
    fi

    local nginx_version=$(nginx -v 2>&1 | cut -d'/' -f2)
    echo -e "   Version: $nginx_version"

    # Main configuration
    echo -e "\n${GREEN}📄 MAIN CONFIG:${NC}"
    echo -e "   File: /etc/nginx/nginx.conf"
    if [[ -f /etc/nginx/nginx.conf ]]; then
        echo -e "   Size: $(du -h /etc/nginx/nginx.conf | cut -f1)"
        echo -e "   Modified: $(stat -c %y /etc/nginx/nginx.conf | cut -d'.' -f1)"
    fi

    # Available sites
    echo -e "\n${GREEN}🌐 AVAILABLE SITES:${NC}"
    if [[ -d /etc/nginx/sites-available ]]; then
        local sites_count=$(ls -1 /etc/nginx/sites-available/ 2>/dev/null | wc -l)
        echo -e "   Total sites: $sites_count"

        if [[ $sites_count -gt 0 ]]; then
            echo -e "   Sites:"
            for site in /etc/nginx/sites-available/*; do
                if [[ -f "$site" ]]; then
                    local site_name=$(basename "$site")
                    local enabled_status=""
                    if [[ -L "/etc/nginx/sites-enabled/$site_name" ]]; then
                        enabled_status="${GREEN}(enabled)${NC}"
                    else
                        enabled_status="${YELLOW}(disabled)${NC}"
                    fi
                    echo -e "     - $site_name $enabled_status"
                fi
            done
        fi
    fi

    # Enabled sites
    echo -e "\n${GREEN}✅ ENABLED SITES:${NC}"
    if [[ -d /etc/nginx/sites-enabled ]]; then
        local enabled_count=$(ls -1 /etc/nginx/sites-enabled/ 2>/dev/null | wc -l)
        echo -e "   Active sites: $enabled_count"
    fi

    # Show domain configurations
    detect_existing_config
    if [[ -n "$EXISTING_DOMAIN" ]]; then
        echo -e "\n${GREEN}🔍 DOMAIN CONFIG: $EXISTING_DOMAIN${NC}"
        local config_file="/etc/nginx/sites-available/$EXISTING_DOMAIN"

        if [[ -f "$config_file" ]]; then
            echo -e "   Config file: $config_file"
            echo -e "   Size: $(du -h "$config_file" | cut -f1)"
            echo -e "   Modified: $(stat -c %y "$config_file" | cut -d'.' -f1)"

            # Extract key information from config
            echo -e "\n   ${YELLOW}Configuration details:${NC}"

            # Server name
            local server_names=$(grep "server_name" "$config_file" | sed 's/.*server_name //;s/;//' | xargs)
            echo -e "     Server names: $server_names"

            # Listen ports
            local listen_ports=$(grep "listen" "$config_file" | sed 's/.*listen //;s/;//' | xargs)
            echo -e "     Listen ports: $listen_ports"

            # Check if it's reverse proxy
            if grep -q "proxy_pass" "$config_file"; then
                local proxy_target=$(grep "proxy_pass" "$config_file" | sed 's/.*proxy_pass //;s/;//' | xargs)
                echo -e "     Proxy target: ${GREEN}$proxy_target${NC}"
                echo -e "     Type: ${GREEN}Reverse Proxy (API Backend)${NC}"
            else
                echo -e "     Type: ${YELLOW}Static Files${NC}"
            fi

            # SSL status
            if grep -q "listen.*443.*ssl" "$config_file"; then
                echo -e "     SSL: ${GREEN}Enabled${NC}"
            else
                echo -e "     SSL: ${YELLOW}HTTP only${NC}"
            fi

            # Show recent config (last 20 lines)
            echo -e "\n   ${YELLOW}Recent config (last 20 lines):${NC}"
            tail -20 "$config_file" | sed 's/^/     /'
        else
            echo -e "   ${RED}Config file not found${NC}"
        fi
    fi

    # Configuration test
    echo -e "\n${GREEN}🧪 CONFIG TEST:${NC}"
    if nginx -t 2>/dev/null; then
        echo -e "   Status: ${GREEN}Valid${NC}"
    else
        echo -e "   Status: ${RED}Invalid${NC}"
        echo -e "   ${YELLOW}Errors:${NC}"
        nginx -t 2>&1 | sed 's/^/     /'
    fi

    echo -e "${BLUE}===========================================${NC}"
}

# Helper functions for individual menu items
function get_user_input_for_user_creation() {
    detect_existing_config

    if [[ -n "$EXISTING_USER" ]]; then
        read -p "User hiện tại: $EXISTING_USER. Tạo user mới? (y/n): " CREATE_USER
        if [[ "$CREATE_USER" =~ ^[Yy]$ ]]; then
            while true; do
                read -p "Nhập tên user mới: " USERNAME
                if [[ -n "$USERNAME" ]] && validate_username "$USERNAME"; then
                    break
                else
                    echo -e "${RED}Username không hợp lệ (chỉ chữ thường, số, dấu gạch dưới, gạch ngang).${NC}"
                fi
            done
        else
            CREATE_USER="n"
            USERNAME="$EXISTING_USER"
        fi
    else
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
    fi
}

function get_user_input_for_domain() {
    detect_existing_config

    if [[ -n "$EXISTING_DOMAIN" ]]; then
        read -p "Domain hiện tại: $EXISTING_DOMAIN. Thay đổi? (y/n): " change_domain
        if [[ "$change_domain" =~ ^[Yy]$ ]]; then
            while true; do
                read -p "Nhập domain name mới: " DOMAIN
                if [[ -n "$DOMAIN" ]] && validate_domain "$DOMAIN"; then
                    break
                else
                    echo -e "${RED}Domain không hợp lệ. Vui lòng nhập lại.${NC}"
                fi
            done
        else
            DOMAIN="$EXISTING_DOMAIN"
        fi
    else
        while true; do
            read -p "Nhập domain name (vd: example.com): " DOMAIN
            if [[ -n "$DOMAIN" ]] && validate_domain "$DOMAIN"; then
                break
            else
                echo -e "${RED}Domain không hợp lệ. Vui lòng nhập lại.${NC}"
            fi
        done
    fi

    # Reverse proxy option
    read -p "Cấu hình reverse proxy cho ứng dụng backend? (y/n): " SETUP_PROXY
    if [[ "$SETUP_PROXY" =~ ^[Yy]$ ]]; then
        while true; do
            read -p "Nhập port của ứng dụng backend (vd: 3000): " PROXY_PORT
            if [[ "$PROXY_PORT" =~ ^[0-9]+$ ]] && [[ "$PROXY_PORT" -ge 1 ]] && [[ "$PROXY_PORT" -le 65535 ]]; then
                break
            else
                echo -e "${RED}Port không hợp lệ. Vui lòng nhập số từ 1-65535.${NC}"
            fi
        done
    fi
}

function get_user_input_for_ssl() {
    detect_existing_config

    if [[ -z "$DOMAIN" ]]; then
        if [[ -n "$EXISTING_DOMAIN" ]]; then
            DOMAIN="$EXISTING_DOMAIN"
        else
            while true; do
                read -p "Nhập domain name cho SSL: " DOMAIN
                if [[ -n "$DOMAIN" ]] && validate_domain "$DOMAIN"; then
                    break
                else
                    echo -e "${RED}Domain không hợp lệ. Vui lòng nhập lại.${NC}"
                fi
            done
        fi
    fi

    if [[ -z "$EMAIL" ]]; then
        if [[ -n "$EXISTING_EMAIL" ]]; then
            read -p "Email hiện tại: $EXISTING_EMAIL. Thay đổi? (y/n): " change_email
            if [[ "$change_email" =~ ^[Yy]$ ]]; then
                while true; do
                    read -p "Nhập email mới cho SSL certificate: " EMAIL
                    if [[ -n "$EMAIL" ]] && validate_email "$EMAIL"; then
                        break
                    else
                        echo -e "${RED}Email không hợp lệ. Vui lòng nhập lại.${NC}"
                    fi
                done
            else
                EMAIL="$EXISTING_EMAIL"
            fi
        else
            while true; do
                read -p "Nhập email cho SSL certificate: " EMAIL
                if [[ -n "$EMAIL" ]] && validate_email "$EMAIL"; then
                    break
                else
                    echo -e "${RED}Email không hợp lệ. Vui lòng nhập lại.${NC}"
                fi
            done
        fi
    fi
}

# Main execution
function main() {
    local first_arg="${1:-}"
    show_banner
    check_prerequisites

    # Check if running with --auto or --full argument for backward compatibility
    if [[ "$first_arg" == "--auto" ]] || [[ "$first_arg" == "--full" ]]; then
        echo -e "\n${GREEN}🚀 Chạy auto setup for deploy...${NC}"
        auto_setup_for_deploy
        return
    fi

    # Show current configuration on startup
    show_current_config

    # Menu loop
    while true; do
        show_menu
        read -p "Nhập lựa chọn của bạn: " choice
        echo ""

        handle_menu_choice "$choice"

        # Pause before showing menu again (except for quit)
        if [[ "$choice" != "q" ]] && [[ "$choice" != "Q" ]]; then
            echo ""
            read -p "Nhấn Enter để tiếp tục..."
        fi
    done
}

# Error handling
trap 'error "Script interrupted or failed at step $STEP"' ERR

# Run main function
main "$@"