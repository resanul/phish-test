#!/usr/bin/env bash
set -euo pipefail
APP="/opt/phish-simulation"
SERVICE="/etc/systemd/system/phish-simulation.service"
PORT="${PORT:-8080}"
[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo ./install.sh"; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }
mkdir -p "$APP"
cp -a . "$APP/"
chmod 755 "$APP/server.py"
mkdir -p "$APP/logs"
cat > "$SERVICE" <<EOF
[Unit]
Description=Internal Phishing Simulation Template Server
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP
ExecStart=/usr/bin/python3 $APP/server.py
Environment=PORT=$PORT
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now phish-simulation.service
echo "Ready: http://SERVER-IP:$PORT/1.html"
echo "Templates: /1.html through /10.html"
echo "Logs: $APP/logs/access.log"
