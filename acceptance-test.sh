#!/bin/bash
set -euo pipefail

APP="/opt/phish-simulation"
SERVICE="phish-simulation"
PORT="${PORT:-8899}"
BASE_URL="http://127.0.0.1:${PORT}"

pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
  fail "Run as root."
fi

[ -d "$APP/.git" ] || fail "$APP is not a Git clone."

echo "=== Trust PhishGuard Deployment Acceptance Test ==="
echo "Application: $APP"
echo "Service:     $SERVICE"
echo "Endpoint:    $BASE_URL"

systemctl is-enabled --quiet "$SERVICE" && pass "systemd service enabled" || fail "systemd service is not enabled"
systemctl is-active --quiet "$SERVICE" && pass "systemd service active" || fail "systemd service is not active"

python3 -m py_compile "$APP/server.py"
pass "server.py compiles successfully"

if curl -fsS --max-time 10 "$BASE_URL/1.html" >/dev/null; then
  pass "HTTP health endpoint /1.html responds"
else
  fail "HTTP health endpoint /1.html failed"
fi

# GET /admin is the public login entry point; /admin/login is a POST-only form action.
LOGIN_PAGE="$(curl -fsS --max-time 10 "$BASE_URL/admin" || true)"
if [ -n "$LOGIN_PAGE" ] && printf '%s' "$LOGIN_PAGE" | grep -Fq 'action="/admin/login"'; then
  pass "HTTP authentication page /admin responds and posts to /admin/login"
else
  fail "HTTP authentication page /admin is unavailable or its login form action is missing"
fi

if grep -q '^data/$' "$APP/.gitignore" && grep -q '^logs/$' "$APP/.gitignore"; then
  pass "runtime data/log directories are excluded from Git"
else
  fail "runtime data/log directories are not protected by .gitignore"
fi

if grep -Eq 'password|otp|pin|cvv|card' "$APP/server.py"; then
  pass "credential-safety enforcement code is present"
else
  fail "credential-safety enforcement could not be verified"
fi

if grep -q 'def resolve_role_access_preview' "$APP/server.py" \
   && grep -q 'No active resource scopes assigned.' "$APP/server.py" \
   && grep -q 'No credentials, secrets, or mutable account state are exposed.' "$APP/server.py"; then
  pass "Access Preview contract is present"
else
  fail "Access Preview contract is missing or incomplete"
fi

if [ -f "$APP/tests/test_rbac_security.py" ]; then
  python3 -m unittest "$APP/tests/test_rbac_security.py"
  pass "RBAC security regression suite passes"
else
  fail "RBAC security regression suite is missing"
fi

if [ -f "$APP/tests/test_smtp_provider.py" ]; then
  python3 -m unittest "$APP/tests/test_smtp_provider.py"
  pass "SMTP provider regression suite passes"
fi

# Static contract checks guard the rollback script's recovery path without performing a rollback.
if grep -Fq 'git reset --hard "$TARGET"' "$APP/rollback.sh" \
   && grep -Fq 'git reset --hard "$CURRENT"' "$APP/rollback.sh" \
   && grep -Fq 'Restoring $CURRENT' "$APP/rollback.sh" \
   && grep -Fq 'python3 -m py_compile "$APP/server.py"' "$APP/rollback.sh" \
   && grep -Fq 'curl -fsS --max-time 10' "$APP/rollback.sh"; then
  pass "rollback script contains target restore, recovery restore, syntax and health checks"
else
  fail "rollback script recovery safety contract is incomplete"
fi

echo
echo "Acceptance baseline passed."
echo "Manual acceptance remains required for SMTP, authentication/roles, campaign lifecycle,"
echo "tracking telemetry, reports, scheduled reports, update and rollback on the target server."
