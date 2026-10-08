# Trust PhishGuard — Admin & RBAC Modernization Plan

> **Workstream:** Enterprise Administration, RBAC, Permission Governance
> **Repository:** `resanul/phish`
> **Status:** Planning baseline recorded; implementation will proceed in small atomic commits.
> **Safety boundary:** This workstream is for the authorized internal phishing-simulation platform. It must never introduce collection, storage, export, or processing of passwords, OTPs, PINs, CVVs, full card numbers, or other authentication secrets.

## 1. Operating Rule

For every implementation step:

1. **Check current progress first.**
2. Identify exactly one next task.
3. Implement only that task.
4. Run focused validation.
5. Mark the task complete in Git/documentation.
6. Create a small atomic commit.
7. Only then continue to the next task.

Production/deployment operations must not be blocked by bundling unrelated changes.

---

## 2. Baseline Checked — 2026-10-06

### Repository baseline

Current main branch head at planning time:

`2efd933a942bd07125804b518d73395e48a03739` — `Fix PDF binary line endings`

Recent reporting/PDF work is present, including:

- Reports query handling
- Reports filter fixes
- PDF route handling
- PDF binary line-ending fix

### Existing admin/RBAC baseline

The application already has:

- Admin authentication
- Hashed admin passwords
- Active/inactive administrator state
- Session-based administrator role
- Administrator management page
- Existing built-in roles
- Module-level role enforcement
- Audit logging for administrator role updates
- Self-disable protection for the current administrator

Current built-in role model:

- Administrator
- Campaign Manager
- Reporting Analyst
- SMTP Manager
- Security Auditor

### Current limitation identified

The current implementation is **role-based but not yet a full custom RBAC system**.

The role-to-module mapping is currently hard-coded in application code. The administrator page can modify the role/status of existing accounts, but it does not yet provide a complete enterprise workflow for:

- Creating administrators
- Creating custom roles
- Editing custom roles
- Assigning granular permissions
- Viewing a permission matrix
- Previewing effective access
- Managing role assignments independently from URL/module logic
- Resource-level scoping
- Privileged-permission warnings
- Full role lifecycle/audit governance

Therefore the next workstream is **RBAC modernization**, not a replacement of the existing security controls.

---

## 3. Target UX

### Main Administration screen

Navigation:

- **Administrators**
- **Roles**
- **Permission Matrix**

Header:

- Administration
- Manage administrators, roles and access policies
- **+ Add Administrator**

Summary cards:

- Administrators
- Active
- Roles
- Custom Roles
- Disabled

Administrator table:

| Column | Purpose |
|---|---|
| Administrator | Name + email |
| Role | Assigned role |
| Access | Permission summary |
| Status | Active/Disabled |
| Last Activity | Latest audited activity |
| Actions | View / Edit / Permissions / Disable / Reset / Audit |

Administrator actions:

- View profile
- Edit role
- View permissions
- Disable account
- Reset password
- View audit activity

---

## 4. Add Administrator

The administrator creation panel should be visually similar to the current reference design, but more enterprise-oriented.

Fields:

- Full name
- Email
- Temporary password
- Role
- Account status

Live **Access Preview**:

- Modules available
- Permission count
- High-risk permissions
- Effective access summary

Actions:

- Cancel
- Create Administrator

Security rules:

- Temporary password must satisfy the existing password policy.
- Passwords are stored only as hashes.
- Passwords are never displayed after creation.
- Secrets must never enter Git, logs, CSV exports, reports, or audit metadata.
- Prevent disabling/demoting the last effective super administrator.
- Audit administrator creation, role assignment, status changes, and privileged changes.

---

## 5. Roles Screen

Role cards/table should show:

- Role name
- Description
- Built-in / Custom
- Administrator count
- Permission count
- Risk level
- Created/updated information
- Actions

Built-in roles:

1. Administrator / Super Admin
2. Campaign Manager
3. Reporting Analyst
4. SMTP Manager
5. Security Auditor

Example custom roles:

- Security Awareness Manager
- Phishing Campaign Operator
- Training Coordinator
- Executive Reporting Viewer
- SOC Auditor
- SMTP Operations

Custom roles should be clearly distinguished from protected built-in roles.

---

## 6. Create/Edit Custom Role

Role form:

- Role name
- Description
- Built-in/custom indicator
- Permission search
- Permission groups
- Privileged-permission warning
- Live permission summary

Permission groups:

### Campaigns

- campaign.view
- campaign.create
- campaign.edit
- campaign.launch
- campaign.delete

### Templates

- template.view
- template.create
- template.edit
- template.archive

### Landing Pages

- landing_page.view
- landing_page.create
- landing_page.edit

### Recipients

- recipient.view
- recipient.create
- recipient.edit
- recipient.import

### Groups

- group.view
- group.manage

### Training

- training.view
- training.manage
- training.assign

### Reports

- report.view
- report.export
- report.schedule

### Risk

- risk.view
- risk.manage

### SMTP

- smtp.view
- smtp.manage
- smtp.diagnostics

### Audit

- audit.view

### Administrators

- admin.view
- admin.create
- admin.edit
- admin.disable

### Roles

- role.view
- role.create
- role.edit
- role.delete

---

## 7. Permission Model

Target authorization hierarchy:

```
Administrator
    |
    v
Role
    |
    v
Permission
    |
    v
Resource Scope (future)
```

Permission format:

`resource.action`

Examples:

- `campaign.launch`
- `report.export`
- `smtp.manage`
- `admin.disable`
- `role.create`

Future resource scopes may support:

- All campaigns
- Specific campaign groups
- Awareness campaigns only
- Specific departments
- Specific organizational units

Resource scoping is deliberately a later phase so the initial migration remains small and safe.

---

## 8. Backend Data Model Target

Recommended tables:

### `rbac_roles`

- id
- name
- slug
- description
- built_in
- active
- created_at
- updated_at

### `rbac_permissions`

- id
- resource
- action
- label
- description
- risk_level
- active

### `rbac_role_permissions`

- role_id
- permission_id
- created_at

### `rbac_resource_scopes`

- id
- role_id
- permission_id
- scope_kind
- scope_value
- active
- created_at
- updated_at

The initial model supports generic scope kinds without changing permission resolution or enforcement yet. Planned values include campaign, campaign group, campaign type, department, and organizational unit; `scope_value` carries the selected resource identifier or a documented wildcard such as `*`.

### Administrator migration

Existing administrator records must remain compatible during migration.

The migration must:

- Preserve existing accounts.
- Preserve existing roles.
- Preserve active/inactive state.
- Preserve password hashes.
- Avoid requiring password resets.
- Avoid breaking current sessions unnecessarily.
- Keep rollback possible.

A future `role_id` reference may replace the current role-name dependency after compatibility validation.

---

## 9. Authorization Architecture

Replace direct role-to-URL authorization with:

```
request
  -> authenticated admin
  -> assigned role
  -> role permissions
  -> route/action permission
  -> optional resource scope
  -> allow/deny
```

Route enforcement should map application actions to permissions instead of embedding role names throughout handlers.

Example:

```text
GET /admin/reports       -> report.view
POST /admin/reports.pdf  -> report.export
POST /admin/campaigns    -> campaign.create
POST /admin/campaigns/launch -> campaign.launch
POST /admin/admins/save  -> admin.edit
POST /admin/admins/create -> admin.create
```

A compatibility layer should keep the existing module-level authorization working while granular permissions are introduced.

---

## 10. Privileged Permission UX

The following should be treated as privileged:

- Manage administrators
- Manage roles
- Manage SMTP
- Export sensitive telemetry
- Modify security settings

When selected:

> **Privileged permission**
>
> This permission grants elevated control and may affect security-sensitive operations.

The UI should require deliberate confirmation before saving a role containing privileged permissions.

---

## 11. Audit & Governance

Audit events should cover:

- ADMIN_CREATE
- ADMIN_ROLE_UPDATE
- ADMIN_DISABLE
- ADMIN_ENABLE
- ADMIN_PASSWORD_RESET
- ROLE_CREATE
- ROLE_UPDATE
- ROLE_DELETE
- ROLE_PERMISSION_UPDATE
- PRIVILEGED_PERMISSION_GRANT

Audit records should identify:

- Actor
- Action
- Target
- Timestamp
- Relevant non-secret metadata

Never record:

- Passwords
- Temporary passwords
- SMTP secrets
- OAuth tokens
- Authentication secrets

---

## 12. Implementation Phases

### Phase A — Administration UX

- [x] Baseline audit and gap analysis
- [x] Administrator creation schema compatibility
- [x] Add Administrator creation backend
- [x] Add Administrator workflow
- [x] Administrator profile/access preview
- [x] Existing-role assignment
- [x] Administrator status controls
- [x] Safe self/last-admin protection
- [x] Mark milestone

### Phase B — Role Management

- [x] Roles tab
- [x] Built-in role display
- [x] Custom role persistence foundation
- [x] Custom role creation
- [x] Custom role editing
- [x] Custom role duplication
- [x] Safe custom role deletion
- [x] Administrator assignment counts
- [x] Mark milestone

### Phase C — Permission Catalog

- [x] Permission catalog schema
- [x] Seed permission definitions
- [x] Permission search/filter
- [x] Permission matrix UI
- [x] Risk/privilege classification
- [x] Mark milestone

### Phase D — True RBAC Enforcement

- [x] Role-permission persistence
- [x] Permission resolver
- [x] Route/action permission mapping
- [x] Compatibility layer for current roles
- [x] Granular enforcement
- [x] Access-preview resolver
- [x] Mark milestone

### Phase E — Governance & Hardening

- [ ] Role-change audit events
- [ ] Privileged-permission confirmation
- [ ] Last-super-admin protection
- [ ] Effective-permission view
- [x] Access review workflow
- [x] Security regression tests
- [x] Mark milestone

### Phase F — Optional Resource Scoping

- [x] Resource scope model
- [x] Scope assignment UI
- [x] Scoped permission evaluation
- [x] Scope audit events
- [ ] Regression tests
- [ ] Mark milestone

---

## 13. Atomic Commit Plan

Each implementation step should normally be one small commit.

Suggested sequence:

1. `Document admin/RBAC modernization baseline`
2. `Add administrator creation schema compatibility`
3. `Add administrator creation backend`
4. `Add administrator creation UI`
5. `Add administrator access preview`
6. `Add roles administration view`
7. `Add custom role persistence`
8. `Add custom role create/edit UI`
9. `Add permission catalog`
10. `Add role permission assignments`
11. `Add permission resolver`
12. `Map routes to permissions`
13. `Add permission matrix`
14. `Add privileged permission warnings`
15. `Add RBAC governance audit events`
16. `Add RBAC regression tests`
17. `Update deployment acceptance coverage`
18. `Mark RBAC modernization milestone`

Do not combine all of these into one large commit.

---

## 14. Progress Rule

At the start of every work session:

> **CHECK → IDENTIFY ONE TASK → IMPLEMENT → VALIDATE → MARK → COMMIT**

Current status:

- [x] Baseline repository/progress checked
- [x] Existing admin/RBAC implementation reviewed
- [x] RBAC modernization gap identified
- [x] Full implementation plan recorded
- [ ] Phase A — Administrator creation
- [ ] Phase B — Role management
- [ ] Phase C — Permission catalog
- [ ] Phase D — True RBAC enforcement
- [ ] Phase E — Governance/hardening
- [ ] Phase F — Resource scoping

**Completed milestone:** Phase A — Administration UX is complete, including administrator creation, access preview, existing-role assignment, status controls, and safe self/last-admin protection.

**Completed task:** Phase B — Safe custom role deletion is complete, including built-in protection and reference checks before removal.

**Completed task:** Phase B — Administrator assignment counts are now displayed for built-in and custom roles from current administrator assignments.

**Completed milestone:** Phase B — Role Management is complete, covering protected built-in role display, custom role persistence and lifecycle, safe deletion, and administrator assignment counts.

**Completed task:** Phase C — Permission catalog schema is already present in the backend, including resource/action identity, labels/descriptions, risk classification, active state, uniqueness, and role-permission foreign-key structure.

**Completed task:** Phase C — Seed permission definitions are now seeded idempotently in the backend with 38 resource/action definitions.

**Completed task:** Phase C — Permission search/filter is now available in the administrator Permission Catalog with text search and resource filtering across the seeded definitions.

**Completed task:** Phase C — Permission matrix UI is now available as a read-only resource/action grid in the administrator Permission Catalog, with the existing search/resource filters applied to the matrix.

**Completed task:** Phase C — Risk/privilege classification is now applied to the permission catalog, with elevated and privileged definitions explicitly classified while remaining permissions default to normal.

**Completed milestone:** Phase C — Permission Catalog is complete, including the permission schema, seeded definitions, search/filter, read-only matrix, and risk/privilege classification.

**Completed task:** Phase D — Role-permission persistence is complete for custom roles, including validated permission assignment persistence, replacement semantics, built-in/inactive protection, and ROLE_PERMISSION_UPDATE audit logging. Authorization resolution and enforcement remain separate Phase D tasks.

**Completed task:** Phase D — Permission resolver is complete for persisted custom-role assignments, with inactive-role and inactive-permission filtering. Route/action enforcement remains a separate Phase D task.

**Completed task:** Phase D — Route/action permission mapping is now defined for the current admin GET/POST routes, including create/edit distinctions for shared save handlers. The mapping is declarative only; compatibility and enforcement remain separate Phase D tasks.

**Completed task:** Phase D — Compatibility layer for current roles is complete. Built-in roles now resolve to permission keys that mirror their existing module-level access, while custom roles continue using persisted assignments. Enforcement remains a separate Phase D task.\n\n**Completed task:** Phase D — Granular enforcement is complete. Mapped admin routes now enforce the effective permission set resolved from built-in compatibility roles or persisted custom-role assignments, while unmapped legacy admin routes retain the existing role gate during migration.

**Completed task:** Phase D — Access-preview resolver is complete. The backend now exposes a read-only structured preview derived from the same effective-permission resolver used by enforcement, including modules, permission count, permission metadata, risk counts, and elevated/privileged permissions. No credentials, secrets, or mutable account state are included.

**Completed task:** Phase D — Access Preview UI is now wired to the existing resolver. Administrator previews display the effective permission metadata, module list, permission count, risk counts, and elevated/privileged permissions from the same backend resolver used for enforcement.

**Completed milestone:** Phase D — True RBAC Enforcement is complete, including custom-role permission persistence, effective permission resolution, declarative route/action mapping, built-in compatibility, granular mapped-route enforcement, and the non-secret access-preview resolver.

**Completed task:** Phase E — Privileged-permission confirmation is now enforced for custom-role permission assignments. The UI requires explicit confirmation when privileged permissions are selected, and the backend rejects unconfirmed privileged grants. A first-time privileged grant also records a non-secret PRIVILEGED_PERMISSION_GRANT audit event.

**Completed task:** Phase E — Role-change audit events now record both the previous and new role/status values for administrator changes, while retaining non-secret actor, target, timestamp, and IP metadata.

**Completed task:** Phase E — Last-super-admin protection is enforced for demotion/disable attempts, and blocked attempts now create a non-secret ADMIN_LAST_SUPERADMIN_BLOCKED audit event.

**Completed task:** Phase E — Effective-permission view is complete through the resolver-backed Access Preview UI, which displays the same effective permission set used by enforcement.

**Completed task:** Phase E — Access review workflow is complete. Administrators can record a non-secret review snapshot for a selected account, including reviewer, timestamp, role/status, effective permission count, and risk-level counts; the review is also audit logged.

**Completed task:** Phase E — Security regression tests are now covered by an isolated temporary-DB regression suite for custom-role resolution, access-review route authorization, privileged-grant auditing, last-super-admin protection auditing, and access-review auditing.

**Completed milestone:** Phase E — Governance & Hardening is complete, covering privileged-permission confirmation, role-change audit metadata, last-super-admin protection, effective-permission view, access review workflow, and security regression tests.

**Completed tasks:** Phase F — Resource scope model, scope assignment UI, and scoped permission evaluation are now implemented. Custom-role permissions with active scope assignments are evaluated against explicit request context; multiple values within a scope kind are alternatives, multiple scope kinds are cumulative, wildcard `*` matches any non-empty context value, and missing scope context fails closed.

**Completed task:** Phase F — Scope audit events are now recorded for non-secret scope assignment updates and scope-based access denials; scope values are limited to explicit RBAC context and no credential material is logged.

**Next task:** Phase F — Regression tests.

---

## 15. External UX Research References

The design direction is informed by established enterprise IAM/RBAC patterns, without copying any vendor interface:

- Okta Custom Admin Roles: role + permissions + granular least-privilege model.
- Microsoft 365 / Microsoft Entra: role assignment workflows, searchable administration, role-centric access management.
- Auth0 RBAC: role-centric permission assignment and permission detail views.

Reference pages:

- Okta custom admin roles: https://help.okta.com/en-us/Content/Topics/security/custom-admin-role/create-role.htm
- Okta custom admin roles overview: https://help.okta.com/en-us/content/topics/security/custom-admin-role/custom-admin-roles.htm
- Okta role permissions: https://help.okta.com/en-us/content/topics/security/custom-admin-role/about-role-permissions.htm
- Microsoft 365 admin roles: https://learn.microsoft.com/en-us/microsoft-365/admin/add-users/assign-admin-roles
- Microsoft Entra role management: https://learn.microsoft.com/en-gb/entra/identity/role-based-access-control/manage-roles-portal
- Auth0 role creation: https://auth0.com/docs/manage-users/access-control/configure-core-rbac/roles/create-roles
- Auth0 role permissions: https://auth0.com/docs/manage-users/access-control/configure-core-rbac/roles/view-role-permissions