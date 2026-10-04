#!/bin/bash
set -euo pipefail
APP=/opt/phish-simulation
SRC="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$APP/templates" "$APP/logs" "$APP/data"
/bin/cp -f "$SRC/server.py" "$APP/server.py"
/bin/cp -f "$SRC"/templates/*.html "$APP/templates/"
chmod 755 "$APP/server.py"
cat > /etc/systemd/system/phish-simulation.service <<'UNIT'
[Unit]
Description=Internal Phishing Simulation Template Server
After=network.target
[Service]
Type=simple
WorkingDirectory=/opt/phish-simulation
ExecStart=/usr/bin/python3 /opt/phish-simulation/server.py
Environment=PORT=8080
Environment=ADMIN_PASSWORD=CHANGE_ME
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable phish-simulation
systemctl restart phish-simulation
