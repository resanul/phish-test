#!/bin/bash
set -euo pipefail
APP=/opt/phish-simulation
SRC="$(cd "$(dirname "$0")" && pwd)"
if [ ! -d "$APP" ]; then echo "ERROR: $APP does not exist. Use ./install.sh"; exit 1; fi
BACKUP="$APP-backup-$(date +%Y%m%d-%H%M%S)"
/bin/cp -a "$APP" "$BACKUP"
/bin/cp -f "$SRC/server.py" "$APP/server.py"
/bin/cp -f "$SRC"/templates/*.html "$APP/templates/"
python3 -m py_compile "$APP/server.py"
systemctl daemon-reload
systemctl restart phish-simulation
systemctl --no-pager status phish-simulation
