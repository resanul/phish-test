#!/bin/bash
set -euo pipefail

APP="/opt/phish-test"
SERVICE="phish-test"
PORT="${PORT:-8899}"
if [ -f /etc/phish-test.env ]; then
  ENV_PORT="$(grep -E "^PORT=" /etc/phish-test.env 2>/dev/null | cut -d'=' -f2 || true)"
  [ -n "$ENV_PORT" ] && PORT="$ENV_PORT"
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: Run as root."
  exit 1
fi

SRC="$(cd "$(dirname "$0")" && pwd)"

if [ "$SRC" != "$APP" ]; then
  echo "This installer expects the Git repository at $APP."
  echo "Clone it first, then run: cd $APP && ./install.sh"
  exit 1
fi

mkdir -p "$APP/templates" "$APP/logs" "$APP/data"

chmod 755 "$APP/server.py" "$APP/update.sh" "$APP/rollback.sh" "$APP/install.sh" "$APP/setup-ssl.sh"

if [ -f /etc/systemd/system/$SERVICE.service ]; then
  cp -a /etc/systemd/system/$SERVICE.service /etc/systemd/system/$SERVICE.service.backup.$(date +%Y%m%d_%H%M%S)
fi

cat > /etc/systemd/system/$SERVICE.service <<'UNIT'
[Unit]
Description=Internal Phishing Simulation Template Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/phish-test
ExecStart=/usr/bin/python3 /opt/phish-test/server.py
Environment=PORT=8899
EnvironmentFile=-/etc/phish-test.env
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable $SERVICE
systemctl restart $SERVICE

python3 -m py_compile "$APP/server.py"

SCHEME="http"
if grep -qs "^SSL_ENABLED=1" /etc/phish-test.env 2>/dev/null || [ "${SSL_ENABLED:-0}" = "1" ] || [ "$PORT" = "443" ]; then
  SCHEME="https"
fi

if ! curl -fsSk --max-time 10 "${SCHEME}://127.0.0.1:$PORT/1.html" >/dev/null 2>&1; then
  ALT_SCHEME="https"
  [ "$SCHEME" = "https" ] && ALT_SCHEME="http"
  if ! curl -fsSk --max-time 5 "${ALT_SCHEME}://127.0.0.1:$PORT/1.html" >/dev/null 2>&1; then
    echo "ERROR: Health check failed."
    systemctl --no-pager status $SERVICE || true
    exit 1
  fi
fi

echo
echo "Installation/service setup successful."
echo "IMPORTANT: Configure ADMIN_PASSWORD in /etc/phish-test.env (mode 600)."
echo "Example: printf 'ADMIN_PASSWORD=%s\\n' '<strong-random-password>' > /etc/phish-test.env"
echo "Then run: chmod 600 /etc/phish-test.env && systemctl daemon-reload && systemctl restart $SERVICE"
