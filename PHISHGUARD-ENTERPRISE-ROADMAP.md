# Trust PhishGuard — Enterprise Phishing Simulation Platform Roadmap

> **Purpose:** Internal, authorized security-awareness simulation platform.
>
> **Safety boundary:** The platform must never request, collect, store, export, or process real passwords, OTPs, PINs, CVVs, full card numbers, authentication secrets, or other credential material.

## Product Vision
PhishGuard is being developed as a full internal phishing-simulation and security-awareness platform, not only a dashboard. The planning reference set is Microsoft Attack Simulation Training, KnowBe4, and Gophish.

## Admin Navigation Target
- Overview
- Campaigns
- Email Templates
- Landing Pages
- SMTP Providers
- Recipients
- Groups & Departments
- Training
- Reports
- Risk & Trends
- Exports
- Settings
- Audit Log

## Phase 1 — Mail Delivery Core
- [x] SMTP provider profiles and presets: Gmail, Google Workspace Relay, Zoho, Microsoft 365, Amazon SES, SendGrid, Mailgun, Custom SMTP
- [x] STARTTLS / SSL-TLS / no-auth relay option
- [x] Encrypted SMTP secret at rest
- [x] SMTP test email
- [ ] Provider connectivity diagnostics: DNS -> TCP -> TLS -> AUTH -> send
- [ ] OAuth 2.0 abstraction

## Phase 2 — Campaign Engine
- [x] SMTP profile, template, landing page and recipient-group selection
- [x] Campaign lifecycle/status
- [x] Immediate controlled launch
- [x] Scheduled launch
- [x] Campaign-specific tracking and delivery records
- [ ] Start date/time/timezone UI
- [ ] Business days/hours
- [ ] Sending windows
- [ ] Throttling / batch size
- [ ] Send-by deadline
- [ ] Pause/resume/cancel
- [ ] Pre-launch validation
- [ ] Test-send before launch

## Phase 3 — Enterprise Users
- [x] CSV recipient import
- [x] Employee ID, name, email, department, groups
- [ ] Designation
- [ ] Location
- [ ] Manager
- [ ] Language
- [ ] Timezone
- [ ] User profile
- [ ] Suppression/exclusion management
- [ ] Duplicate handling and validation report
- [ ] Import history

## Phase 4 — Tracking & Telemetry
- [x] Click and non-secret form/action events
- [x] Campaign/recipient event linkage
- [x] Timestamp, source IP, User-Agent
- [x] Delivery status
- [ ] Normalized event taxonomy: delivered, open, click, form_action, report, QR_scan, training_assigned, training_completed, bot_detected
- [ ] Tracking token
- [ ] Report-phish event
- [ ] QR-scan event
- [ ] Bot/security-scanner detection and filtering policy
- [ ] Event deduplication/idempotency

**Open tracking must never be fabricated; if it is not reliably measurable it must be shown as unavailable/not collected.**

## Phase 5 — Risk Engine
- [x] Basic heuristic risk score
- [x] Failure count and user risk level
- [ ] Repeat offender logic
- [ ] Department risk
- [ ] Campaign risk
- [ ] Risk trend/history
- [ ] Remediation status
- [ ] Configurable scoring
- [ ] Explainable score factors

## Phase 6 — Training
- [x] Training-record database foundation
- [ ] Training courses/course catalog
- [ ] Assignment
- [ ] Due date
- [ ] Completion percentage/status
- [ ] Pass/fail
- [ ] Overdue
- [ ] Remediation campaign linkage
- [ ] Training dashboard

## Phase 7 — Executive Reporting
- [x] Campaign report foundation
- [x] CSV export
- [ ] Campaign comparison
- [ ] Department report
- [ ] Monthly report
- [ ] Executive dashboard
- [ ] Risk/resilience trends
- [ ] PDF report
- [ ] Scheduled reports
- [ ] Date-range/report filters

## Email Template / Payload Builder
Target metadata:
- Template name
- Subject
- From name
- From email
- Reply-To
- Preheader
- HTML body
- Plain-text body
- Tracking link/token
- Language
- Difficulty
- Category
- Brand
- Industry
- Tags

Current:
- [x] Template metadata table and builder
- [x] Subject, preheader, HTML, plain text
- [x] Category, difficulty, language, brand, industry, tags
- [x] Preview
- [ ] From-name/from-email/reply-to metadata at template level
- [ ] Test-send from template
- [ ] Version history
- [ ] Ownership/status/archiving
- [ ] Safe reusable variable/token system

## Landing Page System
- [x] Landing-page registry and template mapping
- [x] Campaign selection and preview
- [ ] Full editor
- [ ] Versioning
- [ ] Safe field-policy validation

Simulation policy: landing pages may collect approved identity/contact metadata only; never credentials.

## SMTP Security
- Secrets never committed to Git.
- Secrets never displayed in plaintext after save.
- Secrets excluded from CSV/export.
- Current local encrypted secret storage uses a server-local 0600 key.
- Future secret-store abstraction: HashiCorp Vault / AWS Secrets Manager / Azure Key Vault.
- Modern authentication where provider requires it.
- Test and launch actions audited.

## Campaign Scheduler
Target controls:
- Start date/time/timezone
- Business days/hours
- Sending rate
- Batch size
- Send-by

Current:
- [x] Background scheduler and scheduled launch
- [ ] Timezone-safe validation
- [ ] Business-day calendar
- [ ] Sending window
- [ ] Rate limiting
- [ ] Batch queue
- [ ] Retry/backoff
- [ ] Pause/resume/cancel
- [ ] Send-by enforcement

## Reporting Metrics
Required where genuinely measurable:
- Targeted
- Delivered
- Opened (only when genuinely measured)
- Clicked
- Submitted/action
- Reported
- Training assigned/completed
- High/Medium/Low risk
- Click rate
- Action rate
- Report rate
- Training completion

Never fabricate metrics.

## Security / Governance
- Admin authentication and secure session cookie
- Audit logging
- Explicit launch authorization
- Future least-privilege roles
- Secret protection
- Input validation
- CSRF protection
- Rate limiting
- Security headers
- Safe template validation
- Error messages must not expose secrets
- Backup/restore
- Deployment rollback and health checks
- No credential collection/storage/export

## Development Order
1. Template builder completion
2. Training module
3. Enterprise recipient profile fields
4. Tracking/event taxonomy + bot detection
5. Risk engine expansion
6. Campaign scheduler/throttling
7. Landing-page editor
8. Executive reports/dashboard
9. Security hardening
10. Documentation and deployment acceptance testing

## Definition of Done
PhishGuard is enterprise-ready for the internal simulation use case when SMTP, campaigns, recipients/groups, reusable templates/landing pages, controlled scheduling, reliable campaign/recipient event correlation, bot handling, explainable risk history, training tracking, truthful reporting, protected secrets, audited admin actions, and deployment/rollback controls are all complete.

## Current Repository Snapshot
The repository already contains foundations for Trust PhishGuard UI, SQLite runtime data, SMTP profiles/encrypted secrets, SMTP test sending, campaigns, recipients/groups, immediate/scheduled delivery, campaign tracking/reporting, risk foundation, training foundation, template builder, CSV export, audit logging, and deployment/update/rollback scripts.

**This roadmap is the source-of-truth checklist for subsequent implementation work.**
