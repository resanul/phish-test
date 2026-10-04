#!/usr/bin/env bash
set -euo pipefail
APP="/opt/phish-simulation"
SERVICE="/etc/systemd/system/phish-simulation.service"
PORT="${PORT:-8080}"
ADMIN_TOKEN="${ADMIN_TOKEN:-$(openssl rand -hex 24)}"
[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo ./install.sh"; exit 1; }
apt-get update
apt-get install -y python3 python3-venv openssl
mkdir -p "$APP"
cp -a backend "$APP/"
python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install --upgrade pip
"$APP/venv/bin/pip" install -r "$APP/backend/requirements.txt"
mkdir -p "$APP/backend/data"
cat > "$APP/.env" <<EOF
HOST=0.0.0.0
PORT=$PORT
ADMIN_TOKEN=$ADMIN_TOKEN
PHISH_DB=$APP/backend/data/simulation.db
EOF
chmod 600 "$APP/.env"
cat > "$SERVICE" <<EOF
[Unit]
Description=Internal Security Awareness Simulation Service
After=network.target
[Service]
Type=simple
WorkingDirectory=$APP/backend
EnvironmentFile=$APP/.env
ExecStart=$APP/venv/bin/python $APP/backend/app.py
Restart=always
RestartSec=3
User=root
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now phish-simulation.service
echo "Installed: http://SERVER-IP:$PORT/"
echo "Admin token: $ADMIN_TOKEN"
