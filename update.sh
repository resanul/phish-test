#!/bin/bash
set -euo pipefail

APP="/opt/phish-simulation"
BRANCH="${BRANCH:-main}"
SERVICE="phish-simulation"
PORT="${PORT:-8080}"
STATE="$APP/.deploy-state"

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: Run as root."
  exit 1
fi

if [ ! -d "$APP/.git" ]; then
  echo "ERROR: $APP is not a Git clone."
  echo "Run the one-time Git setup shown in README.md, then run ./update.sh again."
  exit 1
fi

cd "$APP"

if ! git remote get-url origin >/dev/null 2>&1; then
  echo "ERROR: Git remote 'origin' is not configured."
  exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "ERROR: Local Git changes detected. Commit/stash them or use FORCE=1."
  git status --short
  exit 1
fi

CURRENT="$(git rev-parse HEAD)"
echo "Current commit: $CURRENT"

echo "Fetching origin/$BRANCH..."
git fetch --prune origin "$BRANCH"

TARGET="$(git rev-parse "origin/$BRANCH")"
echo "Target commit:  $TARGET"

if [ "$CURRENT" = "$TARGET" ]; then
  echo "Already up to date."
  exit 0
fi

if [ "${FORCE:-0}" != "1" ]; then
  if ! git diff --quiet "$CURRENT" "$TARGET"; then
    :
  fi
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
mkdir -p "$APP/.deploy-backups"
printf 'previous=%s\ncurrent=%s\ndeployed_at=%s\n' "$CURRENT" "$TARGET" "$STAMP" > "$STATE"

echo "Updating to $TARGET..."
git reset --hard "$TARGET"

echo "Validating Python..."
python3 -m py_compile "$APP/server.py"

echo "Restarting $SERVICE..."
systemctl daemon-reload
systemctl restart "$SERVICE"

echo "Health check..."
if ! curl -fsS --max-time 10 "http://127.0.0.1:$PORT/1.html" >/dev/null; then
  echo "ERROR: Health check failed. Rolling back to $CURRENT..."
  git reset --hard "$CURRENT"
  python3 -m py_compile "$APP/server.py"
  systemctl restart "$SERVICE"
  echo "Rollback completed: $CURRENT"
  exit 1
fi

printf 'previous=%s\ncurrent=%s\ndeployed_at=%s\n' "$CURRENT" "$TARGET" "$STAMP" > "$STATE"

echo
echo "========================================"
echo "Deployment successful"
echo "Previous: $CURRENT"
echo "Current:  $TARGET"
echo "========================================"
echo "Rollback: ./rollback.sh $CURRENT"
