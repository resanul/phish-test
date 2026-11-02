#!/bin/bash
set -euo pipefail

APP="/opt/phish-test"
ENV_FILE="/etc/phish-test.env"
SERVICE="phish-test"
DEFAULT_PORT="8899"

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: Please run as root (sudo ./setup-ssl.sh)."
  exit 1
fi

detect_ip() {
  ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1"
}

open_firewall_port() {
  local port="$1"
  if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    echo "Configuring firewalld port $port/tcp..."
    firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
}

open_firewall_services() {
  if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    echo "Configuring firewalld services (http, https)..."
    firewall-cmd --permanent --add-service=http >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-service=https >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
}

set_env_var() {
  local key="$1"
  local val="$2"
  touch "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  if grep -qs "^${key}=" "$ENV_FILE"; then
    sed -i "s|^${key}=.*|${key}=${val}|" "$ENV_FILE"
  else
    printf '%s=%s\n' "$key" "$val" >> "$ENV_FILE"
  fi
}

generate_ssl_cert() {
  local cert_out="$1"
  local key_out="$2"
  local host_ident="$3"

  mkdir -p "$(dirname "$cert_out")" "$(dirname "$key_out")"

  local ca_dir="/etc/pki/tls/certs"
  local ca_key_dir="/etc/pki/tls/private"
  local ca_cert="$ca_dir/trust-root-ca.crt"
  local ca_key="$ca_key_dir/trust-root-ca.key"

  mkdir -p "$ca_dir" "$ca_key_dir"

  # 1. Ensure Trust Bank Enterprise Root CA exists
  if [ ! -f "$ca_cert" ] || [ ! -f "$ca_key" ]; then
    echo "Creating Trust Bank Enterprise Root CA ($ca_cert)..."
    openssl genrsa -out "$ca_key" 4096 2>/dev/null
    openssl req -x509 -new -nodes -key "$ca_key" -sha256 -days 3650       -out "$ca_cert"       -subj "/C=BD/O=Trust Bank PLC/OU=Information Security/CN=Trust Bank Enterprise Root CA" 2>/dev/null
    chmod 600 "$ca_key"
    chmod 644 "$ca_cert"
    echo "[OK] Enterprise Root CA created successfully."
  fi

  # Copy to app data directory so server.py can serve it at /ca.crt
  mkdir -p "$APP/data" 2>/dev/null || true
  cp -f "$ca_cert" "$APP/data/trust-root-ca.crt" 2>/dev/null || true
  chmod 644 "$APP/data/trust-root-ca.crt" 2>/dev/null || true

  # 2. Check existing certificate
  if [ -f "$cert_out" ] && [ -f "$key_out" ]; then
    if openssl x509 -in "$cert_out" -text -noout 2>/dev/null | grep -q "$host_ident" &&        openssl x509 -in "$cert_out" -issuer -noout 2>/dev/null | grep -q "Trust Bank Enterprise Root CA"; then
      echo "Existing CA-signed SSL certificate matching $host_ident found: $cert_out"
      return 0
    fi
    echo "Regenerating certificate to ensure Enterprise Root CA signature and multi-SAN support..."
    rm -f "$cert_out" "$key_out"
  fi

  # 3. Build comprehensive SAN
  local san="DNS:localhost,IP:127.0.0.1"
  if [[ "$host_ident" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    san="$san,IP:$host_ident"
  else
    san="$san,DNS:$host_ident,DNS:*.$host_ident"
  fi

  if [[ "$san" != *"172.31.105.11"* ]]; then
    san="$san,IP:172.31.105.11"
  fi
  if [[ "$san" != *"tblbdpromotion.com"* ]]; then
    san="$san,DNS:tblbdpromotion.com,DNS:*.tblbdpromotion.com"
  fi

  echo "Generating SSL certificate for $host_ident signed by Trust Bank Enterprise Root CA..."
  echo "SAN entries: $san"

  local ext_file
  ext_file="$(mktemp)"
  cat > "$ext_file" <<EXT
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = $san
EXT

  local csr_file
  csr_file="$(mktemp)"
  openssl genrsa -out "$key_out" 2048 2>/dev/null
  openssl req -new -key "$key_out" -out "$csr_file"     -subj "/C=BD/O=Trust Bank PLC/OU=Security Operations/CN=$host_ident" 2>/dev/null

  openssl x509 -req -in "$csr_file" -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial     -out "$cert_out" -days 825 -sha256 -extfile "$ext_file" 2>/dev/null

  rm -f "$ext_file" "$csr_file"
  chmod 600 "$key_out"
  chmod 644 "$cert_out"
  echo "[OK] Certificate signed by Enterprise Root CA generated: $cert_out"
}

setup_direct() {
  local host_ident="${1:-}"
  if [ -z "$host_ident" ]; then
    local auto_ip
    auto_ip="$(detect_ip)"
    read -rp "Enter server IP or Domain [default: $auto_ip]: " host_ident
    host_ident="${host_ident:-$auto_ip}"
  fi

  local port
  port="$(grep -E "^PORT=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || echo "$DEFAULT_PORT")"
  port="${port:-$DEFAULT_PORT}"

  echo "--- Mode 1: Direct Python SSL Setup ---"
  local cert_path="$APP/data/cert.pem"
  local key_path="$APP/data/key.pem"

  generate_ssl_cert "$cert_path" "$key_path" "$host_ident"

  set_env_var "SSL_ENABLED" "1"
  set_env_var "SSL_CERT" "$cert_path"
  set_env_var "SSL_KEY" "$key_path"

  local base_url="https://${host_ident}"
  if [ "$port" != "443" ]; then
    base_url="${base_url}:${port}"
  fi
  set_env_var "PUBLIC_BASE_URL" "$base_url"

  # Ensure systemd service file loads /etc/phish-test.env
  local svc_file="/etc/systemd/system/${SERVICE}.service"
  if [ -f "$svc_file" ] && ! grep -qs "EnvironmentFile" "$svc_file"; then
    echo "Adding EnvironmentFile=-$ENV_FILE to $svc_file..."
    sed -i '/\[Service\]/a EnvironmentFile=-'"$ENV_FILE" "$svc_file"
  fi

  open_firewall_port "$port"

  echo "Restarting $SERVICE..."
  systemctl daemon-reload
  systemctl restart "$SERVICE"

  echo "Verifying HTTPS health check..."
  if curl -fsSk --noproxy "*" --max-time 10 "https://127.0.0.1:${port}/1.html" >/dev/null 2>&1; then
    echo "✓ HTTPS health check passed!"
    echo "=========================================================="
    echo " HTTPS is now active!"
    echo " Access URL:      $base_url/admin"
    echo " Base URL:        $base_url"
    echo " Certificate:     $cert_path"
    echo " Private Key:     $key_path"
    echo "=========================================================="
    echo "Note: As this is a self-signed certificate, your browser"
    echo "will display an initial security warning. Click 'Advanced'"
    echo "-> 'Proceed' to access."
  else
    echo "WARNING: Direct HTTPS check failed. Service status and recent logs:"
    systemctl status "$SERVICE" --no-pager -l || true
    journalctl -u "$SERVICE" -n 25 --no-pager || true
  fi
}

setup_nginx() {
  local host_ident="${1:-}"
  if [ -z "$host_ident" ]; then
    local auto_ip
    auto_ip="$(detect_ip)"
    read -rp "Enter server IP or Domain [default: $auto_ip]: " host_ident
    host_ident="${host_ident:-$auto_ip}"
  fi

  echo "--- Mode 2: Enterprise Nginx Reverse Proxy Setup ---"

  if ! command -v nginx >/dev/null 2>&1; then
    echo "Installing Nginx via dnf/yum..."
    if command -v dnf >/dev/null 2>&1; then
      dnf install -y nginx
    else
      yum install -y nginx
    fi
  fi

  local cert_dir="/etc/pki/tls/certs"
  local key_dir="/etc/pki/tls/private"
  local cert_path="$cert_dir/phish-test.crt"
  local key_path="$key_dir/phish-test.key"

  generate_ssl_cert "$cert_path" "$key_path" "$host_ident"

  # SELinux permission for Nginx to connect to network upstream
  if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" != "Disabled" ]; then
    echo "Configuring SELinux boolean httpd_can_network_connect..."
    setsebool httpd_can_network_connect 1 2>/dev/null || true
    setsebool -P httpd_can_network_connect 1 2>/dev/null || true
  fi

  # In Nginx mode, backend runs HTTP on 8899, Nginx handles HTTPS on 443
  set_env_var "SSL_ENABLED" "0"
  set_env_var "SSL_CERT" ""
  set_env_var "SSL_KEY" ""
  set_env_var "PORT" "$DEFAULT_PORT"
  set_env_var "PUBLIC_BASE_URL" "https://${host_ident}"

  echo "Writing Nginx configuration /etc/nginx/conf.d/phish-test.conf..."
  cat > /etc/nginx/conf.d/phish-test.conf <<CONF
server {
    listen 80;
    server_name _;

    location /ca.crt {
        alias /etc/pki/tls/certs/trust-root-ca.crt;
        default_type application/x-x509-ca-cert;
        add_header Content-Disposition 'attachment; filename="TrustBank-RootCA.crt"';
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name _;

    ssl_certificate $cert_path;
    ssl_certificate_key $key_path;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;

    client_max_body_size 10M;

    location / {
        proxy_pass http://127.0.0.1:$DEFAULT_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Ssl on;
        proxy_redirect off;
    }
}
CONF

  nginx -t

  open_firewall_services

  echo "Restarting $SERVICE and Nginx..."
  systemctl daemon-reload
  systemctl restart "$SERVICE"
  systemctl enable --now nginx
  systemctl restart nginx

  echo "Verifying HTTPS health check through Nginx..."
  if curl -fsSk --noproxy "*" --max-time 10 "https://127.0.0.1/1.html" >/dev/null 2>&1; then
    echo "✓ Nginx HTTPS reverse proxy is active and healthy!"
    echo "=========================================================="
    echo " HTTPS (Port 443) is now active!"
    echo " Access URL:      https://$host_ident/admin"
    echo " Base URL:        https://$host_ident"
    echo " Port 80:         Automatically redirected to HTTPS (443)"
    echo " Server Cert:     $cert_path"
    echo " Root CA Cert:    /etc/pki/tls/certs/trust-root-ca.crt"
    echo " CA Download URL: http://$host_ident/ca.crt"
    echo "=========================================================="
    echo ""
    echo ">> To remove 'Not secure' in Chrome on Windows (1-Time Setup):"
    echo " 1. Visit: http://$host_ident/ca.crt to download 'TrustBank-RootCA.crt'"
    echo " 2. Double-click the file -> 'Install Certificate...'"
    echo " 3. Select 'Local Machine' -> Next"
    echo " 4. Choose 'Place all certificates in the following store' -> Browse"
    echo " 5. Select 'Trusted Root Certification Authorities' -> Next -> Finish"
    echo " 6. Reopen Chrome -> https://$host_ident and https://tblbdpromotion.com"
    echo "    will both show the SECURE LOCK (PROTECTED)!"
  else
    echo "WARNING: Nginx HTTPS check failed. Check status:"
    systemctl status nginx --no-pager || true
  fi
}

disable_ssl() {
  echo "Disabling SSL..."
  set_env_var "SSL_ENABLED" "0"
  local host_ident
  host_ident="$(detect_ip)"
  set_env_var "PUBLIC_BASE_URL" "http://${host_ident}:${DEFAULT_PORT}"

  if [ -f /etc/nginx/conf.d/phish-test.conf ]; then
    rm -f /etc/nginx/conf.d/phish-test.conf
    systemctl reload nginx 2>/dev/null || true
  fi

  systemctl daemon-reload
  systemctl restart "$SERVICE"
  echo "SSL disabled. Server is running on http://${host_ident}:${DEFAULT_PORT}"
}

ACTION="${1:-}"
ARG_HOST="${2:-}"

case "$ACTION" in
  direct)
    setup_direct "$ARG_HOST"
    ;;
  nginx)
    setup_nginx "$ARG_HOST"
    ;;
  disable)
    disable_ssl
    ;;
  *)
    echo "=========================================================="
    echo " Trust PhishGuard - Red Hat Enterprise Linux SSL Setup"
    echo "=========================================================="
    echo " 1) Direct Python SSL (Fastest, no extra packages, port 8899)"
    echo " 2) Nginx Reverse Proxy (Recommended, standard port 80 & 443)"
    echo " 3) Disable SSL (Revert to HTTP)"
    echo " 4) Exit"
    echo "=========================================================="
    read -rp "Select an option [1-4]: " choice
    case "$choice" in
      1) setup_direct ;;
      2) setup_nginx ;;
      3) disable_ssl ;;
      *) echo "Exiting."; exit 0 ;;
    esac
    ;;
esac
