#!/bin/bash
set -euo pipefail

APP="/opt/phish-simulation"
SERVICE="phish-simulation"
PORT="${PORT:-8080}"
STATE="$APP/.deploy-state"

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: Run as root."
  exit 1
fi

if [ ! -d "$APP/.git" ]; then
  echo "ERROR: $APP is not a Git clone."
  exit 1
fi

cd "$APP"

CURRENT="$(git rev-parse HEAD)"

if [ "$#" -ge 1 ]; then
  TARGET="$1"
else
  if [ -f "$STATE" ]; then
    TARGET="$(sed -n 's/^previous=//p' "$STATE" | tail -1)"
  else
    TARGET="$(git rev-list --max-count=2 HEAD | tail -1)"
  fi
fi

if [ -z "${TARGET:-}" ]; then
  echo "ERROR: No rollback target found."
  exit 1
fi

TARGET="$(git rev-parse "$TARGET^{commit}")"

if [ "$TARGET" = "$CURRENT" ]; then
  echo "Already at $TARGET"
  exit 0
fi

echo "Current:  $CURRENT"
echo "Rollback: $TARGET"

git reset --hard "$TARGET"
python3 -m py_compile "$APP/server.py"
systemctl daemon-reload
systemctl restart "$SERVICE"

if ! curl -fsS --max-time 10 "http://127.0.0.1:$PORT/1.html" >/dev/null; then
  echo "ERROR: Health check failed. Restoring $CURRENT..."
  git reset --hard "$CURRENT"
  python3 -m py_compile "$APP/server.py"
  systemctl restart "$SERVICE"
  exit 1
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
printf 'previous=%s\ncurrent=%s\ndeployed_at=%s\n' "$CURRENT" "$TARGET" "$STAMP" > "$STATE"

echo "Rollback successful: $TARGET"
