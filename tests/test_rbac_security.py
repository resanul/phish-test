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

    def test_access_review_route_requires_admin_view_permission(self):
        self.assertEqual(self.server.route_permission("/admin/admins/review","POST",{}),"admin.view")
        self.assertTrue(self.handler.permission_allowed("/admin/admins/review","POST",{}))

    def test_privileged_and_last_superadmin_audit_guards_remain_present(self):
        source=SERVER.read_text(encoding="utf-8")
        self.assertIn('name="confirm_privileged"',source)
        self.assertIn('"PRIVILEGED_PERMISSION_GRANT"',source)
        self.assertIn('"ADMIN_LAST_SUPERADMIN_BLOCKED"',source)
        self.assertIn('"ADMIN_ACCESS_REVIEW"',source)

if __name__=="__main__":
    unittest.main(verbosity=2)
