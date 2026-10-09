#!/bin/bash
set -euo pipefail

APP="/opt/phish-simulation"
BRANCH="${BRANCH:-main}"
SERVICE="phish-simulation"
PORT="${PORT:-8899}"
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
  echo "ERROR: Local Git changes detected. Commit/stash them before updating."
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

STAMP="$(date +%Y%m%d-%H%M%S)"
mkdir -p "$APP/.deploy-backups"
printf 'previous=%s\ncurrent=%s\ndeployed_at=%s\n' "$CURRENT" "$TARGET" "$STAMP" > "$STATE"

health_check() {
  local url="http://127.0.0.1:${PORT}/1.html"

  echo "Waiting for $SERVICE to become healthy..."

  for i in {1..15}; do
    if systemctl is-active --quiet "$SERVICE" && \
       curl -fsS --max-time 3 "$url" >/dev/null 2>&1; then
      echo "Health check passed."
      return 0
    fi

    echo "Waiting for service... ($i/15)"
    sleep 1
  done

  echo "Health check failed after 15 seconds."
  return 1
}

rollback() {
  echo "Rolling back to $CURRENT..."
  git reset --hard "$CURRENT"

  echo "Validating rollback..."
  python3 -m py_compile "$APP/server.py"

  echo "Restarting $SERVICE after rollback..."
  systemctl daemon-reload
  systemctl restart "$SERVICE"

  if health_check; then
    echo "Rollback completed successfully: $CURRENT"
  else
    echo "CRITICAL: Rollback service health check failed."
    echo "Check: systemctl status $SERVICE --no-pager"
    echo "Check: journalctl -u $SERVICE -n 100 --no-pager"
    return 1
  fi
}

echo "Updating to $TARGET..."
git reset --hard "$TARGET"

echo "Validating Python..."
if ! python3 -m py_compile "$APP/server.py"; then
  echo "ERROR: Python validation failed."
  rollback
  exit 1
fi

echo "Restarting $SERVICE..."
systemctl daemon-reload
systemctl restart "$SERVICE"

echo "Health check..."
if ! health_check; then
  echo "ERROR: Deployment health check failed."
  if rollback; then
    exit 1
  else
    exit 2
  fi
fi

printf 'previous=%s\ncurrent=%s\ndeployed_at=%s\n' "$CURRENT" "$TARGET" "$STAMP" > "$STATE"

echo
echo "========================================"
echo "Deployment successful"
echo "Previous: $CURRENT"
echo "Current:  $TARGET"
echo "========================================"
echo "Rollback: ./rollback.sh $CURRENT"
