#!/bin/bash
set -euo pipefail

DUCK_DOMAIN="${1:-tblbdpromotion}"
TOKEN="${2:-cb7a49cb-107d-49e2-8668-bb19425121ca}"
PRIVATE_IP="${3:-172.31.105.11}"
PROXY_URL="${4:-http://172.31.3.25:3128}"
FULL_DOMAIN="${DUCK_DOMAIN}.duckdns.org"

# Export proxy settings for all tools (curl, certbot, python)
export http_proxy="$PROXY_URL"
export https_proxy="$PROXY_URL"
export HTTP_PROXY="$PROXY_URL"
export HTTPS_PROXY="$PROXY_URL"
export no_proxy="localhost,127.0.0.1,172.31.105.11,*.tblbd.com"
export NO_PROXY="localhost,127.0.0.1,172.31.105.11,*.tblbd.com"

echo "=========================================================="
echo " Trust PhishGuard - Automatic Let's Encrypt SSL via DuckDNS"
echo "=========================================================="
echo " Domain:     https://${FULL_DOMAIN}/"
echo " Local IP:   ${PRIVATE_IP}"
echo " Proxy:      ${PROXY_URL}"
echo "=========================================================="

echo "Step 1: Pointing DuckDNS domain to local IP ${PRIVATE_IP} via proxy..."
UPDATE_RESP=$(curl -s -x "$PROXY_URL" --max-time 20 "https://www.duckdns.org/update?domains=${DUCK_DOMAIN}&token=${TOKEN}&ip=${PRIVATE_IP}" || echo "FAIL")
echo "DuckDNS Response: ${UPDATE_RESP}"

if [[ "$UPDATE_RESP" != *"OK"* ]]; then
    echo "WARNING: DuckDNS IP update response was: $UPDATE_RESP"
else
    echo "✓ DuckDNS IP successfully pointed to $PRIVATE_IP"
fi

echo "Step 2: Ensuring Certbot and Nginx are installed..."
if ! command -v certbot >/dev/null 2>&1; then
    echo "Installing certbot..."
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y certbot || true
    elif command -v yum >/dev/null 2>&1; then
        yum install -y certbot || true
    fi
fi

AUTH_HOOK="/tmp/duckdns-auth.sh"
cat > "$AUTH_HOOK" <<EOF
#!/bin/bash
echo "Setting DuckDNS TXT challenge via proxy..."
curl -s -x "${PROXY_URL}" --max-time 20 "https://www.duckdns.org/update?domains=${DUCK_DOMAIN}&token=${TOKEN}&txt=\${CERTBOT_VALIDATION}"
echo "Waiting 60 seconds for DuckDNS DNS propagation..."
sleep 60
EOF
chmod +x "$AUTH_HOOK"

CLEANUP_HOOK="/tmp/duckdns-cleanup.sh"
cat > "$CLEANUP_HOOK" <<EOF
#!/bin/bash
echo "Clearing DuckDNS TXT challenge..."
curl -s -x "${PROXY_URL}" --max-time 20 "https://www.duckdns.org/update?domains=${DUCK_DOMAIN}&token=${TOKEN}&txt=&clear=true" >/dev/null 2>&1 || true
EOF
chmod +x "$CLEANUP_HOOK"

echo "Step 3: Requesting official Let's Encrypt public SSL certificate (DNS-01 challenge)..."
certbot certonly --manual \
  --preferred-challenges dns \
  --manual-auth-hook "$AUTH_HOOK" \
  --manual-cleanup-hook "$CLEANUP_HOOK" \
  -d "$FULL_DOMAIN" \
  --agree-tos \
  --register-unsafely-without-email \
  --non-interactive \

rm -f "$AUTH_HOOK" "$CLEANUP_HOOK"

CERT_PATH="/etc/letsencrypt/live/${FULL_DOMAIN}/fullchain.pem"
KEY_PATH="/etc/letsencrypt/live/${FULL_DOMAIN}/privkey.pem"

if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
    echo "ERROR: Certificate files not found at $CERT_PATH"
    exit 1
fi

echo "Step 4: Updating Nginx configuration and Base URL..."
NGINX_CONF="/etc/nginx/conf.d/phish-test.conf"
if [ -f "$NGINX_CONF" ]; then
    sed -i "s|ssl_certificate .*|ssl_certificate ${CERT_PATH};|" "$NGINX_CONF"
    sed -i "s|ssl_certificate_key .*|ssl_certificate_key ${KEY_PATH};|" "$NGINX_CONF"
fi

ENV_FILE="/etc/phish-test.env"
if [ -f "$ENV_FILE" ]; then
    if grep -qs "^PUBLIC_BASE_URL=" "$ENV_FILE"; then
        sed -i "s|^PUBLIC_BASE_URL=.*|PUBLIC_BASE_URL=https://${FULL_DOMAIN}|" "$ENV_FILE"
    else
        echo "PUBLIC_BASE_URL=https://${FULL_DOMAIN}" >> "$ENV_FILE"
    fi
fi

if command -v nginx >/dev/null 2>&1; then
    nginx -t
    systemctl restart nginx
fi

if systemctl is-active --quiet phish-test 2>/dev/null; then
    systemctl restart phish-test
fi

echo "=========================================================="
echo " [SUCCESS] Genuine Public SSL Active!"
echo " Domain:          https://${FULL_DOMAIN}/"
echo " Certificate:     ${CERT_PATH}"
echo " Local Target IP: ${PRIVATE_IP}"
echo "=========================================================="
echo " Any employee can now visit https://${FULL_DOMAIN}/2.html?t=..."
echo " and Chrome/Edge will show the SECURE LOCK (🔒) automatically!"
echo " No certificate installation required on any client PC!"
echo "=========================================================="
