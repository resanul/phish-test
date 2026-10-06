# Phishing Simulation Template Server

Private internal security-awareness simulation server.

## Deployment model

The server is deployed directly from this Git repository.

Runtime data is intentionally kept outside Git:
- `data/` — SQLite database
- `logs/` — access logs
- `.deploy-state` — deployment metadata

## One-time server setup

The server must have Git access to this private repository.

Recommended SSH remote:

```bash
cd /opt
git clone git@github.com:resanul/phish.git phish-simulation
cd /opt/phish-simulation
chmod +x install.sh update.sh rollback.sh
./install.sh
```

If the application already exists from the older copy-based installer, back it up first and migrate the existing `data/` and `logs/` directories before using the Git workflow.

## Normal update

```bash
cd /opt/phish-simulation
./update.sh
```

The script:
1. Fetches `origin/main`
2. Resets the application code to the latest commit
3. Preserves ignored runtime directories
4. Validates `server.py`
5. Restarts systemd
6. Checks `/1.html`
7. Automatically rolls back if the health check fails

For a simple HTML-only change, restart is harmless and keeps the workflow consistent.

## Rollback

Rollback to the previous deployment:

```bash
cd /opt/phish-simulation
./rollback.sh
```

Rollback to a specific commit:

```bash
./rollback.sh <commit-sha>
```

Useful history:

```git log --oneline --decorate -10```

## Important

Do not commit:
- admin passwords
- SQLite database
- access logs
- production secrets

Set the admin password only in the protected environment file:

`/etc/phish-simulation.env`

Example:

```bash
printf 'ADMIN_PASSWORD=%s\n' '<strong-random-password>' > /etc/phish-simulation.env
chmod 600 /etc/phish-simulation.env
systemctl daemon-reload
systemctl restart phish-simulation
```

The systemd unit loads this file with `EnvironmentFile=-/etc/phish-simulation.env`.

## Trust PhishGuard enterprise capabilities

The platform currently includes:

- Controlled campaigns with timezone-aware scheduling, business-day windows, batching, rate limits, retries, pause/resume/cancel and send-by enforcement.
- Recipient profiles, groups, suppression and import validation.
- Campaign/recipient tracking tokens, delivery, click, action, report, QR and bot telemetry with event deduplication.
- Training courses, assignments, pass/fail tracking, overdue state and remediation campaign linkage.
- Executive reporting: campaign comparison, department/monthly reports, risk/resilience trends, PDF export and scheduled PDF email reports.
- Template Builder with sender metadata, version history, ownership/status, safe reusable variables and non-tracked test-send.
- Landing-page editor with versioning and credential-field safety validation.
- SMTP provider profiles, encrypted secrets, connectivity diagnostics and an OAuth2/XOAUTH2 authentication abstraction.
- Security hardening: CSRF protection, security headers, login rate limiting, role-based admin permissions and idle/absolute session timeouts.

### Safe template variables

Reusable simulation variables are intentionally limited to non-secret recipient/campaign metadata:

`{{name}}`, `{{email}}`, `{{employee_id}}`, `{{department}}`, `{{designation}}`, `{{location}}`, `{{manager}}`, `{{language}}`, `{{timezone}}`, `{{campaign_name}}`, `{{tracking_link}}`, `{{report_link}}`, `{{qr_link}}`.

The platform must never request, collect, store, export or process passwords, OTPs, PINs, CVVs, full card numbers or authentication secrets.

### SMTP diagnostics

From an enabled SMTP profile, **Run Diagnostics** performs:

1. DNS resolution
2. TCP connection
3. TLS/session negotiation
4. SMTP authentication when configured
5. Optional one-message send to an explicitly supplied test recipient

Diagnostic output never displays SMTP passwords or tokens.

