#!/usr/bin/env python3
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

SERVER=Path(__file__).resolve().parents[1] / "server.py"

def load_server():
    spec=importlib.util.spec_from_file_location("phishguard_server",SERVER)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class RBACSecurityRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=load_server()
        cls.tmp=tempfile.TemporaryDirectory()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        # Each test gets a fresh seeded database so permission rows and role
        # assignments from one test cannot leak into another.
        self.server.DB=os.path.join(self.tmp.name,self._testMethodName+".db")
        self.server.db().close()
        self.handler=self.server.Handler.__new__(self.server.Handler)
        self.handler.current_admin=lambda: {"username":"reviewer@example.com","role":"Custom Reviewer"}
        c=self.server.db()
        ts=self.server.now()
        c.execute("INSERT OR IGNORE INTO rbac_roles(name,slug,description,built_in,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                  ("Custom Reviewer","custom-reviewer","Regression role fixture",0,1,ts,ts))
        role_id=c.execute("SELECT id FROM rbac_roles WHERE name='Custom Reviewer'").fetchone()["id"]
        permission_id=c.execute("SELECT id FROM rbac_permissions WHERE resource='admin' AND action='view'").fetchone()["id"]
        c.execute("INSERT OR IGNORE INTO rbac_role_permissions(role_id,permission_id,created_at) VALUES(?,?,?)",
                  (role_id,permission_id,ts))
        c.commit()
        c.close()

    def test_custom_role_resolver_uses_active_permissions_only(self):
        c=self.server.db()
        ts=self.server.now()
        c.execute("INSERT OR IGNORE INTO rbac_roles(name,slug,description,built_in,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                  ("Custom Reviewer","custom-reviewer","Regression role",0,1,ts,ts))
        role_id=c.execute("SELECT id FROM rbac_roles WHERE name='Custom Reviewer'").fetchone()["id"]
        c.execute("INSERT OR IGNORE INTO rbac_permissions(resource,action,label,description,risk_level,active) VALUES(?,?,?,?,?,1)",
                  ("admin","view","View admins","View administrator access","normal"))
        permission_id=c.execute("SELECT id FROM rbac_permissions WHERE resource='admin' AND action='view'").fetchone()["id"]
        c.execute("INSERT OR IGNORE INTO rbac_role_permissions(role_id,permission_id,created_at) VALUES(?,?,?)",
                  (role_id,permission_id,ts))
        c.execute("INSERT OR IGNORE INTO rbac_permissions(resource,action,label,description,risk_level,active) VALUES(?,?,?,?,?,0)",
                  ("admin","disable","Disable admins","Disabled regression permission","privileged"))
        # The seeded catalog may already contain this key as active; force the
        # fixture into the inactive state rather than relying on INSERT OR IGNORE.
        c.execute("UPDATE rbac_permissions SET active=0 WHERE resource='admin' AND action='disable'")
        inactive_permission_id=c.execute("SELECT id FROM rbac_permissions WHERE resource='admin' AND action='disable'").fetchone()["id"]
        c.execute("INSERT OR IGNORE INTO rbac_role_permissions(role_id,permission_id,created_at) VALUES(?,?,?)",
                  (role_id,inactive_permission_id,ts))
        c.commit()
        c.close()
        self.assertEqual(self.handler.resolve_role_permissions("Custom Reviewer"),{"admin.view"})

    def test_permission_seed_is_idempotent_and_preserves_disabled_definitions(self):
        c=self.server.db()
        initial_count=c.execute("SELECT COUNT(*) FROM rbac_permissions").fetchone()[0]
        c.execute("UPDATE rbac_permissions SET active=0 WHERE resource='campaign' AND action='view'")
        c.commit()
        c.close()

        # db() runs schema setup and permission seeding; repeated initialization
        # must not duplicate rows or reactivate an intentionally disabled definition.
        self.server.db().close()
        c=self.server.db()
        final_count=c.execute("SELECT COUNT(*) FROM rbac_permissions").fetchone()[0]
        row=c.execute("SELECT active FROM rbac_permissions WHERE resource='campaign' AND action='view'").fetchone()
        c.close()
        self.assertEqual(final_count,initial_count)
        self.assertIsNotNone(row)
        self.assertEqual(row["active"],0)

    def test_access_review_snapshot_uses_access_preview_resolver(self):
        source=SERVER.read_text(encoding="utf-8")
        start=source.find("if p.path==\"/admin/admins/review\":")
        end=source.find("if p.path==\"/admin/admins/save\":",start)
        review_block=source[start:end]
        self.assertIn("resolve_role_access_preview(target[\"role\"])",review_block)
        self.assertIn("counts=access_preview[\"risk_counts\"]",review_block)

    def test_access_review_route_requires_admin_view_permission(self):
        self.assertEqual(self.server.route_permission("/admin/admins/review","POST",{}),"admin.view")
        self.assertTrue(self.handler.permission_allowed("/admin/admins/review","POST",{}))

    def test_route_permission_map_catalog_and_method_coverage(self):
        mapping=self.server.RBAC_ROUTE_PERMISSION_MAP
        self.assertEqual(set(mapping),{"GET","POST"})
        c=self.server.db()
        catalog={f"{row['resource']}.{row['action']}" for row in c.execute(
            "SELECT resource,action FROM rbac_permissions WHERE active=1"
        ).fetchall()}
        c.close()

        for method,routes in mapping.items():
            for path,value in routes.items():
                self.assertTrue(path.startswith("/admin/") or path=="/admin.csv",(method,path))
                values=set(value.values()) if isinstance(value,dict) else {value}
                self.assertTrue(values,(method,path))
                for permission in values:
                    self.assertIn(permission,catalog,(method,path,permission))
                # A mapped route must not accidentally grant the same mapping
                # through another HTTP method unless separately declared.
                other_method="POST" if method=="GET" else "GET"
                if path not in mapping.get(other_method,{}):
                    self.assertIsNone(self.server.route_permission(path,other_method,{}),(path,other_method))

        self.assertEqual(self.server.route_permission("/admin/campaigns/save","POST",{}),"campaign.create")
        self.assertEqual(self.server.route_permission("/admin/campaigns/save","POST",{"id":["42"]}),"campaign.edit")
        self.assertEqual(self.server.route_permission("/admin/templates/save","POST",{}),"template.create")
        self.assertEqual(self.server.route_permission("/admin/templates/save","POST",{"id":["42"]}),"template.edit")
        self.assertEqual(self.server.route_permission("/admin/templates/test-send","POST",{}),"template.edit")
        self.assertFalse(self.handler.permission_allowed("/admin/templates/test-send","POST",{}))
        self.assertIsNone(self.server.route_permission("/admin/campaigns/save","GET",{}))
        self.assertIsNone(self.server.route_permission("/admin/campaigns/launch","DELETE",{}))

    def test_unmapped_admin_routes_fail_closed_instead_of_legacy_role_fallback(self):
        # The legacy role gate allowed every unknown path for Administrator.
        # Unknown routes must now deny even for Administrator; login/logout
        # and the dashboard are handled by explicit request flow outside this check.
        self.handler.current_admin=lambda: {"username":"admin@example.com","role":"Administrator"}
        self.assertIsNone(self.server.route_permission("/admin/unmapped-legacy","GET",{}))
        self.assertFalse(self.handler.permission_allowed("/admin/unmapped-legacy","GET",{}))
        self.assertFalse(self.handler.permission_allowed("/admin/unmapped-legacy","POST",{}))

    def test_legacy_csv_export_and_settings_require_explicit_permissions(self):
        self.assertEqual(self.server.route_permission("/admin.csv","GET"),"report.export")
        self.assertEqual(self.server.route_permission("/admin/settings","GET"),"risk.manage")
        self.assertFalse(self.handler.permission_allowed("/admin.csv","GET"))
        self.assertFalse(self.handler.permission_allowed("/admin/settings","GET"))

        c=self.server.db()
        ts=self.server.now()
        role_id=c.execute("SELECT id FROM rbac_roles WHERE name='Custom Reviewer'").fetchone()["id"]
        for resource,action in (("report","export"),("risk","manage")):
            permission_id=c.execute(
                "SELECT id FROM rbac_permissions WHERE resource=? AND action=? AND active=1",
                (resource,action)
            ).fetchone()["id"]
            c.execute(
                "INSERT OR IGNORE INTO rbac_role_permissions(role_id,permission_id,created_at) VALUES(?,?,?)",
                (role_id,permission_id,ts)
            )
        c.commit()
        c.close()
        self.assertTrue(self.handler.permission_allowed("/admin.csv","GET"))
        self.assertTrue(self.handler.permission_allowed("/admin/settings","GET"))

    def test_privileged_and_last_superadmin_audit_guards_remain_present(self):
        source=SERVER.read_text(encoding="utf-8")
        self.assertIn('name="confirm_privileged"',source)
        self.assertIn('"PRIVILEGED_PERMISSION_GRANT"',source)
        self.assertIn('"ADMIN_LAST_SUPERADMIN_BLOCKED"',source)
        self.assertIn('"ADMIN_ACCESS_REVIEW"',source)
        self.assertIn('"RBAC_SCOPE_ASSIGNMENT_UPDATE"',source)
        self.assertIn('"RBAC_SCOPE_ACCESS_DENIED"',source)
        self.assertIn("Resource scopes",source)
        self.assertIn("No active resource scopes assigned.",source)

    def test_access_preview_risk_counts_match_permission_risk_levels(self):
        c=self.server.db()
        ts=self.server.now()
        c.execute("INSERT OR IGNORE INTO rbac_roles(name,slug,description,built_in,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                  ("Risk Preview Reviewer","risk-preview-reviewer","Risk count regression role",0,1,ts,ts))
        role_id=c.execute("SELECT id FROM rbac_roles WHERE name='Risk Preview Reviewer'").fetchone()["id"]
        permissions=[
            ("campaign","view","View campaigns","normal"),
            ("campaign","launch","Launch campaigns","elevated"),
            ("report","export","Export reports","privileged")
        ]
        for resource,action,label,risk in permissions:
            c.execute("INSERT OR IGNORE INTO rbac_permissions(resource,action,label,description,risk_level,active) VALUES(?,?,?,?,?,1)",
                      (resource,action,label,"Risk count regression permission",risk))
            permission_id=c.execute("SELECT id FROM rbac_permissions WHERE resource=? AND action=?",(resource,action)).fetchone()["id"]
            c.execute("INSERT OR IGNORE INTO rbac_role_permissions(role_id,permission_id,created_at) VALUES(?,?,?)",(role_id,permission_id,ts))
        c.commit()
        c.close()
        preview=self.handler.resolve_role_access_preview("Risk Preview Reviewer")
        self.assertEqual(preview["risk_counts"],{"normal":1,"elevated":1,"privileged":1})
        self.assertEqual(
            {item["risk_level"] for item in preview["high_risk_permissions"]},
            {"elevated","privileged"}
        )
        self.assertEqual(len(preview["high_risk_permissions"]),2)

    def test_access_preview_builtin_role_ignores_persisted_scopes(self):
        c=self.server.db()
        ts=self.server.now()
        c.execute("INSERT OR IGNORE INTO rbac_roles(name,slug,description,built_in,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                  ("Campaign Manager","campaign-manager","Built-in compatibility role",1,1,ts,ts))
        role_id=c.execute("SELECT id FROM rbac_roles WHERE name='Campaign Manager'").fetchone()["id"]
        permission_id=c.execute("SELECT id FROM rbac_permissions WHERE resource='campaign' AND action='view'").fetchone()["id"]
        c.execute("INSERT OR IGNORE INTO rbac_role_permissions(role_id,permission_id,created_at) VALUES(?,?,?)",
                  (role_id,permission_id,ts))
        c.execute("INSERT OR IGNORE INTO rbac_resource_scopes(role_id,permission_id,scope_kind,scope_value,active,created_at,updated_at) VALUES(?,?,?,?,1,?,?)",
                  (role_id,permission_id,"campaign","999",ts,ts))
        c.commit()
        c.close()
        preview=self.handler.resolve_role_access_preview("Campaign Manager")
        self.assertIn("campaign.view",{item["key"] for item in preview["permissions"]})
        self.assertEqual(preview["scopes"],[])

    def test_access_preview_summary_matches_effective_permissions(self):
        preview=self.handler.resolve_role_access_preview("Custom Reviewer")
        self.assertEqual(preview["permission_count"],len(preview["permissions"]))
        self.assertEqual(
            preview["modules"],
            sorted({item["resource"] for item in preview["permissions"]})
        )

    def test_access_preview_snapshot_exposes_only_non_secret_access_fields(self):
        preview=self.handler.resolve_role_access_preview("Custom Reviewer")
        self.assertEqual(
            set(preview),
            {"role","permission_count","modules","permissions","high_risk_permissions","risk_counts","scopes"}
        )
        for item in preview["permissions"] + preview["high_risk_permissions"]:
            self.assertEqual(
                set(item),
                {"key","resource","action","label","description","risk_level"}
            )
        for item in preview["scopes"]:
            self.assertEqual(set(item),{"permission","scope_kind","scope_value"})
        self.assertNotIn("password", preview)
        self.assertNotIn("password_hash", preview)
        self.assertNotIn("token", preview)
        self.assertNotIn("secret", preview)
        self.assertNotIn("session", preview)

    def test_access_preview_without_role_returns_safe_empty_snapshot(self):
        self.handler.current_admin=lambda: None
        preview=self.handler.resolve_role_access_preview()
        self.assertIsNone(preview["role"])
        self.assertEqual(preview["permission_count"],0)
        self.assertEqual(preview["permissions"],[])
        self.assertEqual(preview["high_risk_permissions"],[])
        self.assertEqual(preview["scopes"],[])

    def test_access_preview_inactive_builtin_role_returns_empty_snapshot(self):
        c=self.server.db()
        ts=self.server.now()
        c.execute("INSERT OR IGNORE INTO rbac_roles(name,slug,description,built_in,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                  ("Campaign Manager","campaign-manager","Built-in role regression",1,1,ts,ts))
        row=c.execute("SELECT id,active FROM rbac_roles WHERE name='Campaign Manager'").fetchone()
        self.assertIsNotNone(row)
        previous_active=row["active"]
        c.execute("UPDATE rbac_roles SET active=0 WHERE name='Campaign Manager'")
        c.commit()
        c.close()
        try:
            self.assertEqual(self.handler.resolve_role_permissions("Campaign Manager"),set())
            preview=self.handler.resolve_role_access_preview("Campaign Manager")
            self.assertEqual(preview["permission_count"],0)
            self.assertEqual(preview["permissions"],[])
            self.assertEqual(preview["scopes"],[])
        finally:
            c=self.server.db()
            c.execute("UPDATE rbac_roles SET active=? WHERE name='Campaign Manager'",(previous_active,))
            c.commit()
            c.close()

    def test_access_preview_inactive_custom_role_returns_empty_snapshot(self):
        c=self.server.db()
        ts=self.server.now()
        c.execute("INSERT OR IGNORE INTO rbac_roles(name,slug,description,built_in,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                  ("Inactive Preview Reviewer","inactive-preview-reviewer","Inactive preview regression role",0,0,ts,ts))
        role_id=c.execute("SELECT id FROM rbac_roles WHERE name='Inactive Preview Reviewer'").fetchone()["id"]
        c.execute("INSERT OR IGNORE INTO rbac_permissions(resource,action,label,description,risk_level,active) VALUES(?,?,?,?,?,1)",
                  ("campaign","view","View campaigns","Inactive preview regression permission","normal"))
        permission_id=c.execute("SELECT id FROM rbac_permissions WHERE resource='campaign' AND action='view'").fetchone()["id"]
        c.execute("INSERT OR IGNORE INTO rbac_role_permissions(role_id,permission_id,created_at) VALUES(?,?,?)",
                  (role_id,permission_id,ts))
        c.commit()
        c.close()
        preview=self.handler.resolve_role_access_preview("Inactive Preview Reviewer")
        self.assertEqual(preview["permission_count"],0)
        self.assertEqual(preview["permissions"],[])
        self.assertEqual(preview["scopes"],[])

    def test_access_preview_state_matrix_consistency(self):
        c=self.server.db()
        ts=self.server.now()
        c.execute("INSERT OR IGNORE INTO rbac_roles(name,slug,description,built_in,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                  ("Campaign Manager","campaign-manager","Built-in state matrix role",1,1,ts,ts))
        builtin_id=c.execute("SELECT id FROM rbac_roles WHERE name='Campaign Manager'").fetchone()["id"]
        c.execute("INSERT OR IGNORE INTO rbac_roles(name,slug,description,built_in,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                  ("State Matrix Reviewer","state-matrix-reviewer","Custom state matrix role",0,1,ts,ts))
        custom_id=c.execute("SELECT id FROM rbac_roles WHERE name='State Matrix Reviewer'").fetchone()["id"]
        c.execute("INSERT OR IGNORE INTO rbac_role_permissions(role_id,permission_id,created_at) SELECT ?,id,? FROM rbac_permissions WHERE resource='campaign' AND action='view'",
                  (custom_id,ts))
        permission_id=c.execute("SELECT id FROM rbac_permissions WHERE resource='campaign' AND action='view'").fetchone()["id"]
        c.execute("INSERT INTO rbac_resource_scopes(role_id,permission_id,scope_kind,scope_value,active,created_at,updated_at) VALUES(?,?,?,?,1,?,?)",
                  (custom_id,permission_id,"campaign","matrix-123",ts,ts))
        c.commit()
        c.close()

        def assert_summary_consistent(preview):
            permissions=preview["permissions"]
            self.assertEqual(preview["permission_count"],len(permissions))
            self.assertEqual(preview["modules"],sorted({item["resource"] for item in permissions}))
            expected={"normal":0,"elevated":0,"privileged":0}
            for item in permissions:
                expected[item["risk_level"]]=expected.get(item["risk_level"],0)+1
            self.assertEqual(preview["risk_counts"],expected)
            self.assertEqual(
                preview["high_risk_permissions"],
                [item for item in permissions if item["risk_level"] in ("elevated","privileged")]
            )

        # Active built-in: compatibility permissions are effective, custom scopes are not.
        builtin=self.handler.resolve_role_access_preview("Campaign Manager")
        self.assertGreater(builtin["permission_count"],0)
        assert_summary_consistent(builtin)
        self.assertEqual(builtin["scopes"],[])

        # Inactive built-in: all effective access summaries fail closed.
        c=self.server.db()
        c.execute("UPDATE rbac_roles SET active=0 WHERE id=?",(builtin_id,))
        c.commit()
        c.close()
        inactive_builtin=self.handler.resolve_role_access_preview("Campaign Manager")
        self.assertEqual(inactive_builtin["permission_count"],0)
        self.assertEqual(inactive_builtin["modules"],[])
        self.assertEqual(inactive_builtin["permissions"],[])
        self.assertEqual(inactive_builtin["high_risk_permissions"],[])
        self.assertEqual(inactive_builtin["risk_counts"],{"normal":0,"elevated":0,"privileged":0})
        self.assertEqual(inactive_builtin["scopes"],[])

        # Active custom: assigned permission and its active scope appear consistently.
        custom=self.handler.resolve_role_access_preview("State Matrix Reviewer")
        assert_summary_consistent(custom)
        self.assertEqual(custom["scopes"],[{"permission":"campaign.view","scope_kind":"campaign","scope_value":"matrix-123"}])

        # Inactive custom: persisted assignments/scopes cannot appear effective.
        c=self.server.db()
        c.execute("UPDATE rbac_roles SET active=0 WHERE id=?",(custom_id,))
        c.commit()
        c.close()
        inactive_custom=self.handler.resolve_role_access_preview("State Matrix Reviewer")
        self.assertEqual(inactive_custom["permission_count"],0)
        self.assertEqual(inactive_custom["modules"],[])
        self.assertEqual(inactive_custom["permissions"],[])
        self.assertEqual(inactive_custom["high_risk_permissions"],[])
        self.assertEqual(inactive_custom["risk_counts"],{"normal":0,"elevated":0,"privileged":0})
        self.assertEqual(inactive_custom["scopes"],[])

        # Unknown role name and absent current role both produce safe empty snapshots.
        missing=self.handler.resolve_role_access_preview("Missing Role")
        self.assertEqual(missing["permission_count"],0)
        self.assertEqual(missing["modules"],[])
        self.assertEqual(missing["permissions"],[])
        self.assertEqual(missing["scopes"],[])
        self.handler.current_admin=lambda: None
        no_role=self.handler.resolve_role_access_preview()
        self.assertIsNone(no_role["role"])
        self.assertEqual(no_role["permission_count"],0)
        self.assertEqual(no_role["modules"],[])
        self.assertEqual(no_role["permissions"],[])
        self.assertEqual(no_role["scopes"],[])

    def test_access_preview_includes_active_resource_scopes(self):
        c=self.server.db()
        ts=self.server.now()
        c.execute("INSERT OR IGNORE INTO rbac_roles(name,slug,description,built_in,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                  ("Preview Scope Reviewer","preview-scope-reviewer","Preview scope regression role",0,1,ts,ts))
        role_id=c.execute("SELECT id FROM rbac_roles WHERE name='Preview Scope Reviewer'").fetchone()["id"]
        c.execute("INSERT OR IGNORE INTO rbac_permissions(resource,action,label,description,risk_level,active) VALUES(?,?,?,?,?,1)",
                  ("campaign","view","View campaigns","Preview scope permission","normal"))
        permission_id=c.execute("SELECT id FROM rbac_permissions WHERE resource='campaign' AND action='view'").fetchone()["id"]
        c.execute("INSERT OR IGNORE INTO rbac_role_permissions(role_id,permission_id,created_at) VALUES(?,?,?)",(role_id,permission_id,ts))
        c.execute("INSERT INTO rbac_resource_scopes(role_id,permission_id,scope_kind,scope_value,active,created_at,updated_at) VALUES(?,?,?,?,1,?,?)",
                  (role_id,permission_id,"campaign","123",ts,ts))
        c.execute("INSERT INTO rbac_resource_scopes(role_id,permission_id,scope_kind,scope_value,active,created_at,updated_at) VALUES(?,?,?,?,0,?,?)",
                  (role_id,permission_id,"campaign","999",ts,ts))
        c.commit()
        c.close()
        preview=self.handler.resolve_role_access_preview("Preview Scope Reviewer")
        self.assertEqual(preview["scopes"],[{"permission":"campaign.view","scope_kind":"campaign","scope_value":"123"}])
        c=self.server.db()
        c.execute("DELETE FROM rbac_role_permissions WHERE role_id=? AND permission_id=?",(role_id,permission_id))
        c.commit()
        c.close()
        self.assertEqual(self.handler.resolve_role_access_preview("Preview Scope Reviewer")["scopes"],[])

    def test_scoped_permission_allows_matching_context_and_denies_mismatch(self):
        c=self.server.db()
        ts=self.server.now()
        c.execute("INSERT OR IGNORE INTO rbac_roles(name,slug,description,built_in,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                  ("Scoped Reviewer","scoped-reviewer","Scope regression role",0,1,ts,ts))
        role_id=c.execute("SELECT id FROM rbac_roles WHERE name='Scoped Reviewer'").fetchone()["id"]
        c.execute("INSERT OR IGNORE INTO rbac_permissions(resource,action,label,description,risk_level,active) VALUES(?,?,?,?,?,1)",
                  ("campaign","view","View campaigns","Scope regression permission","normal"))
        permission_id=c.execute("SELECT id FROM rbac_permissions WHERE resource='campaign' AND action='view'").fetchone()["id"]
        c.execute("INSERT OR IGNORE INTO rbac_role_permissions(role_id,permission_id,created_at) VALUES(?,?,?)",
                  (role_id,permission_id,ts))
        c.execute("INSERT INTO rbac_resource_scopes(role_id,permission_id,scope_kind,scope_value,active,created_at,updated_at) VALUES(?,?,?,?,1,?,?)",
                  (role_id,permission_id,"campaign","123",ts,ts))
        c.commit()
        c.close()
        self.handler.client_address=("127.0.0.1",12345)
        self.assertTrue(self.handler.scoped_permission_allowed(
            "Scoped Reviewer","campaign.view","/admin/campaigns","GET",query="id=123"
        ))
        self.assertFalse(self.handler.scoped_permission_allowed(
            "Scoped Reviewer","campaign.view","/admin/campaigns","GET",query="id=999"
        ))

    def test_scoped_permission_fails_closed_on_ambiguous_context(self):
        c=self.server.db()
        ts=self.server.now()
        c.execute("INSERT OR IGNORE INTO rbac_roles(name,slug,description,built_in,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                  ("Ambiguous Scope Reviewer","ambiguous-scope-reviewer","Ambiguous context regression role",0,1,ts,ts))
        role_id=c.execute("SELECT id FROM rbac_roles WHERE name='Ambiguous Scope Reviewer'").fetchone()["id"]
        c.execute("INSERT OR IGNORE INTO rbac_permissions(resource,action,label,description,risk_level,active) VALUES(?,?,?,?,?,1)",
                  ("campaign","view","View campaigns","Ambiguous context regression permission","normal"))
        permission_id=c.execute("SELECT id FROM rbac_permissions WHERE resource='campaign' AND action='view'").fetchone()["id"]
        c.execute("INSERT OR IGNORE INTO rbac_role_permissions(role_id,permission_id,created_at) VALUES(?,?,?)",
                  (role_id,permission_id,ts))
        c.execute("INSERT INTO rbac_resource_scopes(role_id,permission_id,scope_kind,scope_value,active,created_at,updated_at) VALUES(?,?,?,?,1,?,?)",
                  (role_id,permission_id,"campaign","123",ts,ts))
        c.commit()
        c.close()
        self.handler.client_address=("127.0.0.1",12345)

        # Repeated query values must not silently select the first identifier.
        self.assertFalse(self.handler.scoped_permission_allowed(
            "Ambiguous Scope Reviewer","campaign.view","/admin/campaigns","GET",
            query="id=123&id=999"
        ))
        # A conflicting form value and query value must also fail closed.
        self.assertFalse(self.handler.scoped_permission_allowed(
            "Ambiguous Scope Reviewer","campaign.view","/admin/campaigns","POST",
            form={"id":["123"]},query="id=999"
        ))
        # Equivalent aliases with the same value remain unambiguous.
        context=self.handler.scope_context(
            "/admin/campaigns","POST",
            form={"id":["123"],"campaign_id":["123"]},query="id=123"
        )
        self.assertEqual(context["campaign"],"123")

    def test_scoped_permission_combines_scope_kinds_and_wildcard(self):
        c=self.server.db()
        ts=self.server.now()
        c.execute("INSERT OR IGNORE INTO rbac_roles(name,slug,description,built_in,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                  ("Multi Scope Reviewer","multi-scope-reviewer","Multi-scope regression role",0,1,ts,ts))
        role_id=c.execute("SELECT id FROM rbac_roles WHERE name='Multi Scope Reviewer'").fetchone()["id"]
        c.execute("INSERT OR IGNORE INTO rbac_permissions(resource,action,label,description,risk_level,active) VALUES(?,?,?,?,?,1)",
                  ("campaign","edit","Edit campaigns","Multi-scope regression permission","normal"))
        permission_id=c.execute("SELECT id FROM rbac_permissions WHERE resource='campaign' AND action='edit'").fetchone()["id"]
        c.execute("INSERT OR IGNORE INTO rbac_role_permissions(role_id,permission_id,created_at) VALUES(?,?,?)",
                  (role_id,permission_id,ts))
        scopes=[
            (role_id,permission_id,"campaign","123",1,ts,ts),
            (role_id,permission_id,"campaign_group","Finance",1,ts,ts),
            (role_id,permission_id,"campaign_type","*",1,ts,ts)
        ]
        c.executemany("INSERT INTO rbac_resource_scopes(role_id,permission_id,scope_kind,scope_value,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",scopes)
        c.commit()
        c.close()
        self.handler.client_address=("127.0.0.1",12345)
        self.assertTrue(self.handler.scoped_permission_allowed(
            "Multi Scope Reviewer","campaign.edit","/admin/campaigns","POST",
            form={"id":["123"],"group_name":["Finance"],"campaign_type":["awareness"]}
        ))
        self.assertFalse(self.handler.scoped_permission_allowed(
            "Multi Scope Reviewer","campaign.edit","/admin/campaigns","POST",
            form={"id":["123"],"group_name":["HR"],"campaign_type":["awareness"]}
        ))
        self.assertFalse(self.handler.scoped_permission_allowed(
            "Multi Scope Reviewer","campaign.edit","/admin/campaigns","POST",
            form={"id":["123"],"group_name":["Finance"]}
        ))

    def test_access_preview_scope_markup_is_escaped_and_has_empty_state(self):
        source=SERVER.read_text(encoding="utf-8")
        self.assertIn('scope_rows=""',source)
        self.assertIn('esc(item["permission"])',source)
        self.assertIn('esc(item["scope_kind"])',source)
        self.assertIn('esc(item["scope_value"])',source)
        self.assertIn("No active resource scopes assigned.",source)

    def test_scope_denial_is_audited_without_secret_fields(self):
        c=self.server.db()
        ts=self.server.now()
        c.execute("INSERT OR IGNORE INTO rbac_roles(name,slug,description,built_in,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                  ("Audit Scope Reviewer","audit-scope-reviewer","Audit regression role",0,1,ts,ts))
        role_id=c.execute("SELECT id FROM rbac_roles WHERE name='Audit Scope Reviewer'").fetchone()["id"]
        c.execute("INSERT OR IGNORE INTO rbac_permissions(resource,action,label,description,risk_level,active) VALUES(?,?,?,?,?,1)",
                  ("recipient","view","View recipients","Audit scope regression permission","normal"))
        permission_id=c.execute("SELECT id FROM rbac_permissions WHERE resource='recipient' AND action='view'").fetchone()["id"]
        c.execute("INSERT OR IGNORE INTO rbac_role_permissions(role_id,permission_id,created_at) VALUES(?,?,?)",
                  (role_id,permission_id,ts))
        c.execute("INSERT INTO rbac_resource_scopes(role_id,permission_id,scope_kind,scope_value,active,created_at,updated_at) VALUES(?,?,?,?,1,?,?)",
                  (role_id,permission_id,"department","Finance",ts,ts))
        c.commit()
        c.close()
        self.handler.client_address=("127.0.0.1",12345)
        self.assertFalse(self.handler.scoped_permission_allowed(
            "Audit Scope Reviewer","recipient.view","/admin/recipients","GET",query="department=HR&password=redacted"
        ))
        c=self.server.db()
        audit_row=c.execute(
            "SELECT action,details FROM audit_logs WHERE action='RBAC_SCOPE_ACCESS_DENIED' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        c.close()
        self.assertIsNotNone(audit_row)
        self.assertIn("scope_kind=department",audit_row["details"])
        self.assertIn("actual=HR",audit_row["details"])
        self.assertNotIn("password",audit_row["details"])

    def test_audit_redacts_authentication_secrets_and_preserves_governance_metadata(self):
        details='role_id=7 permission_count=3 password=plain-password token:abc123 otp="123456" api_key=key-value'
        self.server.audit("reviewer@example.com","ROLE_PERMISSION_UPDATE",details,"127.0.0.1")

        c=self.server.db()
        row=c.execute(
            "SELECT action,details FROM audit_logs WHERE action='ROLE_PERMISSION_UPDATE' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        c.close()
        self.assertIsNotNone(row)
        self.assertIn("role_id=7",row["details"])
        self.assertIn("permission_count=3",row["details"])
        for secret in ("plain-password","abc123","123456","key-value"):
            self.assertNotIn(secret,row["details"])
        for field in ("password","token","otp","api_key"):
            self.assertRegex(row["details"],field+r"\\s*[=:]\\[REDACTED\\]")
        self.assertEqual(row["action"],"ROLE_PERMISSION_UPDATE")

        source=SERVER.read_text(encoding="utf-8")
        for action in (
            "ROLE_PERMISSION_UPDATE",
            "PRIVILEGED_PERMISSION_GRANT",
            "ROLE_CREATE",
            "ROLE_UPDATE",
            "ROLE_DELETE",
            "RBAC_SCOPE_ASSIGNMENT_UPDATE",
            "RBAC_SCOPE_ACCESS_DENIED",
        ):
            self.assertIn('"'+action+'"',source)

if __name__=="__main__":
    unittest.main(verbosity=2)
