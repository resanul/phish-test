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
        cls.server.DB=os.path.join(cls.tmp.name,"rbac-test.db")
        cls.server.db().close()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.handler=self.server.Handler.__new__(self.server.Handler)
        self.handler.current_admin=lambda: {"username":"reviewer@example.com","role":"Custom Reviewer"}

    def test_custom_role_resolver_uses_active_permissions_only(self):
        c=self.server.db()
        ts=self.server.now()
        c.execute("INSERT INTO rbac_roles(name,slug,description,built_in,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                  ("Custom Reviewer","custom-reviewer","Regression role",0,1,ts,ts))
        role_id=c.execute("SELECT id FROM rbac_roles WHERE name='Custom Reviewer'").fetchone()["id"]
        c.execute("INSERT INTO rbac_permissions(resource,action,label,description,risk_level,active) VALUES(?,?,?,?,?,1)",
                  ("admin","view","View admins","View administrator access","normal"))
        permission_id=c.execute("SELECT id FROM rbac_permissions WHERE resource='admin' AND action='view'").fetchone()["id"]
        c.execute("INSERT INTO rbac_role_permissions(role_id,permission_id,created_at) VALUES(?,?,?)",
                  (role_id,permission_id,ts))
        c.execute("INSERT INTO rbac_permissions(resource,action,label,description,risk_level,active) VALUES(?,?,?,?,?,0)",
                  ("admin","disable","Disable admins","Disabled regression permission","privileged"))
        c.commit()
        c.close()
        self.assertEqual(self.handler.resolve_role_permissions("Custom Reviewer"),{"admin.view"})

    def test_access_review_snapshot_uses_access_preview_resolver(self):
        source=open(os.path.join(os.path.dirname(__file__),"..","server.py")).read()
        start=source.find("if p.path==\"/admin/admins/review\":")
        end=source.find("if p.path==\"/admin/admins/save\":",start)
        review_block=source[start:end]
        self.assertIn("resolve_role_access_preview(target[\"role\"])",review_block)
        self.assertIn("counts=access_preview[\"risk_counts\"]",review_block)

    def test_access_review_route_requires_admin_view_permission(self):
        self.assertEqual(self.server.route_permission("/admin/admins/review","POST",{}),"admin.view")
        self.assertTrue(self.handler.permission_allowed("/admin/admins/review","POST",{}))

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

    def test_access_preview_without_role_returns_safe_empty_snapshot(self):
        self.handler.current_admin=lambda: None
        preview=self.handler.resolve_role_access_preview()
        self.assertIsNone(preview["role"])
        self.assertEqual(preview["permission_count"],0)
        self.assertEqual(preview["permissions"],[])
        self.assertEqual(preview["high_risk_permissions"],[])
        self.assertEqual(preview["scopes"],[])

    def test_access_preview_inactive_custom_role_returns_empty_snapshot(self):
        c=self.server.db()
        ts=self.server.now()
        c.execute("INSERT INTO rbac_roles(name,slug,description,built_in,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                  ("Inactive Preview Reviewer","inactive-preview-reviewer","Inactive preview regression role",0,0,ts,ts))
        role_id=c.execute("SELECT id FROM rbac_roles WHERE name='Inactive Preview Reviewer'").fetchone()["id"]
        c.execute("INSERT INTO rbac_permissions(resource,action,label,description,risk_level,active) VALUES(?,?,?,?,?,1)",
                  ("campaign","view","View campaigns","Inactive preview regression permission","normal"))
        permission_id=c.execute("SELECT id FROM rbac_permissions WHERE resource='campaign' AND action='view'").fetchone()["id"]
        c.execute("INSERT INTO rbac_role_permissions(role_id,permission_id,created_at) VALUES(?,?,?)",
                  (role_id,permission_id,ts))
        c.commit()
        c.close()
        preview=self.handler.resolve_role_access_preview("Inactive Preview Reviewer")
        self.assertEqual(preview["permission_count"],0)
        self.assertEqual(preview["permissions"],[])
        self.assertEqual(preview["scopes"],[])

    def test_access_preview_includes_active_resource_scopes(self):
        c=self.server.db()
        ts=self.server.now()
        c.execute("INSERT INTO rbac_roles(name,slug,description,built_in,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                  ("Preview Scope Reviewer","preview-scope-reviewer","Preview scope regression role",0,1,ts,ts))
        role_id=c.execute("SELECT id FROM rbac_roles WHERE name='Preview Scope Reviewer'").fetchone()["id"]
        c.execute("INSERT INTO rbac_permissions(resource,action,label,description,risk_level,active) VALUES(?,?,?,?,?,1)",
                  ("campaign","view","View campaigns","Preview scope permission","normal"))
        permission_id=c.execute("SELECT id FROM rbac_permissions WHERE resource='campaign' AND action='view'").fetchone()["id"]
        c.execute("INSERT INTO rbac_role_permissions(role_id,permission_id,created_at) VALUES(?,?,?)",(role_id,permission_id,ts))
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
        c.execute("INSERT INTO rbac_roles(name,slug,description,built_in,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                  ("Scoped Reviewer","scoped-reviewer","Scope regression role",0,1,ts,ts))
        role_id=c.execute("SELECT id FROM rbac_roles WHERE name='Scoped Reviewer'").fetchone()["id"]
        c.execute("INSERT INTO rbac_permissions(resource,action,label,description,risk_level,active) VALUES(?,?,?,?,?,1)",
                  ("campaign","view","View campaigns","Scope regression permission","normal"))
        permission_id=c.execute("SELECT id FROM rbac_permissions WHERE resource='campaign' AND action='view'").fetchone()["id"]
        c.execute("INSERT INTO rbac_role_permissions(role_id,permission_id,created_at) VALUES(?,?,?)",
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

    def test_scoped_permission_combines_scope_kinds_and_wildcard(self):
        c=self.server.db()
        ts=self.server.now()
        c.execute("INSERT INTO rbac_roles(name,slug,description,built_in,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                  ("Multi Scope Reviewer","multi-scope-reviewer","Multi-scope regression role",0,1,ts,ts))
        role_id=c.execute("SELECT id FROM rbac_roles WHERE name='Multi Scope Reviewer'").fetchone()["id"]
        c.execute("INSERT INTO rbac_permissions(resource,action,label,description,risk_level,active) VALUES(?,?,?,?,?,1)",
                  ("campaign","edit","Edit campaigns","Multi-scope regression permission","normal"))
        permission_id=c.execute("SELECT id FROM rbac_permissions WHERE resource='campaign' AND action='edit'").fetchone()["id"]
        c.execute("INSERT INTO rbac_role_permissions(role_id,permission_id,created_at) VALUES(?,?,?)",
                  (role_id,permission_id,ts))
        scopes=[
            (role_id,permission_id,"campaign","123",1,ts,ts),
            (role_id,permission_id,"department","Finance",1,ts,ts),
            (role_id,permission_id,"campaign_type","*",1,ts,ts)
        ]
        c.executemany("INSERT INTO rbac_resource_scopes(role_id,permission_id,scope_kind,scope_value,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",scopes)
        c.commit()
        c.close()
        self.handler.client_address=("127.0.0.1",12345)
        self.assertTrue(self.handler.scoped_permission_allowed(
            "Multi Scope Reviewer","campaign.edit","/admin/campaigns","POST",
            form={"id":["123"],"department":["Finance"],"campaign_type":["awareness"]}
        ))
        self.assertFalse(self.handler.scoped_permission_allowed(
            "Multi Scope Reviewer","campaign.edit","/admin/campaigns","POST",
            form={"id":["123"],"department":["HR"],"campaign_type":["awareness"]}
        ))
        self.assertFalse(self.handler.scoped_permission_allowed(
            "Multi Scope Reviewer","campaign.edit","/admin/campaigns","POST",
            form={"id":["123"],"department":["Finance"]}
        ))

    def test_access_preview_scope_markup_is_escaped_and_has_empty_state(self):
        source=open(os.path.join(os.path.dirname(__file__),"..","server.py")).read()
        self.assertIn('scope_rows=""',source)
        self.assertIn('esc(item["permission"])',source)
        self.assertIn('esc(item["scope_kind"])',source)
        self.assertIn('esc(item["scope_value"])',source)
        self.assertIn("No active resource scopes assigned.",source)

    def test_scope_denial_is_audited_without_secret_fields(self):
        c=self.server.db()
        ts=self.server.now()
        c.execute("INSERT INTO rbac_roles(name,slug,description,built_in,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                  ("Audit Scope Reviewer","audit-scope-reviewer","Audit regression role",0,1,ts,ts))
        role_id=c.execute("SELECT id FROM rbac_roles WHERE name='Audit Scope Reviewer'").fetchone()["id"]
        c.execute("INSERT INTO rbac_permissions(resource,action,label,description,risk_level,active) VALUES(?,?,?,?,?,1)",
                  ("recipient","view","View recipients","Audit scope regression permission","normal"))
        permission_id=c.execute("SELECT id FROM rbac_permissions WHERE resource='recipient' AND action='view'").fetchone()["id"]
        c.execute("INSERT INTO rbac_role_permissions(role_id,permission_id,created_at) VALUES(?,?,?)",
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

if __name__=="__main__":
    unittest.main(verbosity=2)
