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

Recommended clone command:

```bash
cd /opt
git clone https://github.com/resanul/phish-test.git phish-test
cd /opt/phish-test
chmod +x install.sh update.sh rollback.sh
./install.sh
```

If the application already exists from the older copy-based installer, back it up first and migrate the existing `data/` and `logs/` directories before using the Git workflow.

## Normal update

```bash
cd /opt/phish-test
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
cd /opt/phish-test
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

`/etc/phish-test.env`

Example:

```bash
printf 'ADMIN_PASSWORD=%s\n' '<strong-random-password>' > /etc/phish-test.env
# Approved corporate HTTP proxy for outbound SMTP (defaults to 172.31.105.10:3128):
printf 'SMTP_PROXY_HOST=172.31.105.10\nSMTP_PROXY_PORT=3128\n' >> /etc/phish-test.env
# Or URL format:
# printf 'SMTP_PROXY=http://172.31.105.10:3128\n' >> /etc/phish-test.env
# Or explicit direct connection mode (bypassing proxy if allowed by policy):
# printf 'SMTP_DIRECT_CONNECT=1\n' >> /etc/phish-test.env
chmod 600 /etc/phish-test.env
systemctl daemon-reload
systemctl restart phish-test
```

The systemd unit loads this file with `EnvironmentFile=-/etc/phish-test.env`.

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

### SMTP diagnostics and corporate proxy routing

All outbound SMTP traffic (diagnostics, template test sends, campaign test sends, and live campaign dispatches) routes through the corporate HTTP CONNECT proxy (`172.31.105.10:3128` by default, configurable via `SMTP_PROXY`, `SMTP_PROXY_HOST`/`SMTP_PROXY_PORT`, or `SMTP_DIRECT_CONNECT=1`).

From an enabled SMTP profile, **Run Diagnostics** performs:

1. DNS resolution (verifies proxy host and SMTP destination)
2. TCP connection (establishes HTTP CONNECT tunnel to proxy, reporting any 403 or gateway rejections)
3. TLS/session negotiation (STARTTLS or implicit SSL/TLS with full certificate verification over the tunnel)
4. SMTP authentication when configured (password or OAuth2/XOAUTH2)
5. Optional one-message send to an explicitly supplied test recipient

Diagnostic output never displays SMTP passwords or tokens.

