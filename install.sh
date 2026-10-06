#!/bin/bash
set -euo pipefail

APP="/opt/phish-simulation"
SERVICE="phish-simulation"
PORT="${PORT:-8080}"

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

chmod 755 "$APP/server.py" "$APP/update.sh" "$APP/rollback.sh" "$APP/install.sh"

if [ -f /etc/systemd/system/$SERVICE.service ]; then
  cp -a /etc/systemd/system/$SERVICE.service /etc/systemd/system/$SERVICE.service.backup.$(date +%Y%m%d_%H%M%S)
fi

cat > /etc/systemd/system/$SERVICE.service <<'UNIT'
[Unit]
Description=Internal Phishing Simulation Template Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/phish-simulation
ExecStart=/usr/bin/python3 /opt/phish-simulation/server.py
Environment=PORT=8080
EnvironmentFile=-/etc/phish-simulation.env
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable $SERVICE
systemctl restart $SERVICE

python3 -m py_compile "$APP/server.py"

if ! curl -fsS --max-time 10 "http://127.0.0.1:$PORT/1.html" >/dev/null; then
  echo "ERROR: Health check failed."
  systemctl --no-pager status $SERVICE || true
  exit 1
fi

echo
echo "Installation/service setup successful."
echo "IMPORTANT: Configure ADMIN_PASSWORD in /etc/phish-simulation.env (mode 600)."
echo "Example: printf 'ADMIN_PASSWORD=%s\\n' '<strong-random-password>' > /etc/phish-simulation.env"
echo "Then run: chmod 600 /etc/phish-simulation.env && systemctl daemon-reload && systemctl restart $SERVICE"
