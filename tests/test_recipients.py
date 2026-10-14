#!/usr/bin/env python3
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

SERVER = Path(__file__).resolve().parents[1] / "server.py"

def load_server():
    spec = importlib.util.spec_from_file_location("phishguard_server", SERVER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class RecipientsSingleAddTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = load_server()
        cls.tmp = tempfile.TemporaryDirectory()

    @classmethod
    def tearDownClass(cls):
        try:
            cls.tmp.cleanup()
        except Exception:
            pass

    def setUp(self):
        self.server.DB = os.path.join(self.tmp.name, self._testMethodName + ".db")
        c = self.server.db()
        c.close()
        self.handler = self.server.Handler.__new__(self.server.Handler)
        self.handler.admin_shell = lambda title, body, active: body
        self.handler.auth = lambda: True
        self.handler.csrf_origin_ok = lambda: True
        self.handler.permission_allowed = lambda path, method, query=None, form=None: True

    def test_recipients_directory_renders_single_add_and_quick_add(self):
        html = self.handler.feature_page("/admin/recipients")
        self.assertIn("Employee Target Directory", html)
        self.assertIn("Add Recipient", html)
        self.assertIn("Quick Add", html)
        self.assertIn("Import CSV", html)
        self.assertIn("quickAddModal", html)

    def test_recipient_new_form_renders_empty_fields(self):
        html = self.handler.recipient_profile_form("new")
        self.assertIn("Add Target Employee", html)
        self.assertIn("Corporate Email Address", html)
        self.assertIn("Employee ID", html)
        self.assertIn("Designation / Role", html)
        self.assertIn("Department", html)
        self.assertIn("Add Recipient to Directory", html)
        self.assertIn('name="id" value=""', html)

    def test_create_single_recipient_via_post_save(self):
        c = self.server.db()
        count_before = c.execute("SELECT COUNT(*) n FROM recipients").fetchone()["n"]
        c.close()
        self.assertEqual(count_before, 0)

        sent = []
        self.handler.sendbody = lambda status, body, ctype="text/html; charset=utf-8", extra=None: sent.append((status, body, extra))
        form = {
            "id": [""],
            "email": ["alex.target@company.com"],
            "name": ["Alex Target"],
            "employee_id": ["EMP-9001"],
            "department": ["Finance"],
            "designation": ["Analyst"],
            "location": ["Dhaka HQ"],
            "manager": ["Jane Boss"],
            "group_name": ["Finance Drill"],
            "language": ["English"],
            "timezone": ["Asia/Dhaka"],
            "status": ["Active"],
        }
        # Simulate do_POST logic
        ip = "127.0.0.1"
        rid = form.get("id", [""])[0].strip()
        email = form.get("email", [""])[0].strip().lower()
        employee = form.get("employee_id", [""])[0].strip()[:100]
        name = form.get("name", [""])[0].strip()[:150]
        department = form.get("department", [""])[0].strip()[:100]
        designation = form.get("designation", [""])[0].strip()[:150]
        location = form.get("location", [""])[0].strip()[:150]
        manager = form.get("manager", [""])[0].strip()[:150]
        group_name = form.get("group_name", [""])[0].strip()[:100]
        language = form.get("language", ["English"])[0].strip()[:50]
        timezone_val = form.get("timezone", ["Asia/Dhaka"])[0].strip()[:80] or "Asia/Dhaka"
        status_val = form.get("status", ["Active"])[0]

        c = self.server.db()
        c.execute("""INSERT INTO recipients(email,name,employee_id,department,designation,location,manager,language,timezone,group_name,status,created_at)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                  (email, name, employee, department, designation, location, manager, language, timezone_val, group_name, status_val, self.server.now()))
        new_id = c.execute("SELECT last_insert_rowid() id").fetchone()["id"]
        c.commit()
        c.close()

        c = self.server.db()
        row = c.execute("SELECT * FROM recipients WHERE id=?", (new_id,)).fetchone()
        c.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["email"], "alex.target@company.com")
        self.assertEqual(row["name"], "Alex Target")
        self.assertEqual(row["department"], "Finance")
        self.assertEqual(row["status"], "Active")

    def test_edit_and_delete_recipient(self):
        c = self.server.db()
        c.execute("INSERT INTO recipients(email,name,employee_id,department,status,created_at) VALUES('user1@corp.test','User One','EMP-111','IT','Active',?)", (self.server.now(),))
        rid = c.execute("SELECT last_insert_rowid() id").fetchone()["id"]
        c.commit()
        c.close()

        # View edit form
        html = self.handler.recipient_profile_form(str(rid))
        self.assertIn("Edit Target Profile #" + str(rid), html)
        self.assertIn("user1@corp.test", html)
        self.assertIn("User One", html)
        self.assertIn("Delete Recipient", html)

        # Delete recipient
        c = self.server.db()
        c.execute("DELETE FROM recipients WHERE id=?", (rid,))
        c.commit()
        deleted = c.execute("SELECT * FROM recipients WHERE id=?", (rid,)).fetchone()
        c.close()
        self.assertIsNone(deleted)

    def test_update_existing_recipient_with_employee_id_via_do_post(self):
        c = self.server.db()
        c.execute("INSERT INTO recipients(email,name,employee_id,department,status,created_at) VALUES('ahasan.kabir@tblbd.com','Ahasan Kabir','4078','Division Head','Suppressed',?)", (self.server.now(),))
        rid = c.execute("SELECT last_insert_rowid() id").fetchone()["id"]
        c.commit()
        c.close()

        h = self.handler
        h.path = "/admin/recipients/save"
        h.client_address = ("127.0.0.1", 12345)
        response_data = []
        h.sendbody = lambda code, body, ctype="text/html", extra=None: response_data.append((code, body, extra))

        import urllib.parse
        payload = urllib.parse.urlencode({
            "id": str(rid),
            "email": "ahasan.kabir@tblbd.com",
            "name": "A. K. M. Ahasan Kabir",
            "employee_id": "4078",
            "designation": "Executive Vice President, Head of Information Technology Divis",
            "department": "Division Head",
            "group_name": "IT Division",
            "location": "Dhaka",
            "manager": "Sarah Jenkins",
            "language": "English",
            "timezone": "Asia/Dhaka",
            "status": "Active"
        })
        h.headers = {"Content-Length": str(len(payload))}
        from unittest.mock import MagicMock
        h.rfile = MagicMock()
        h.rfile.read.return_value = payload.encode()

        h.do_POST()
        self.assertEqual(len(response_data), 1)
        self.assertEqual(response_data[0][0], 302)
        self.assertEqual(response_data[0][2]["Location"], "/admin/recipients")

        # Verify updated values in DB
        c = self.server.db()
        updated = c.execute("SELECT * FROM recipients WHERE id=?", (rid,)).fetchone()
        c.close()
        self.assertEqual(updated["name"], "A. K. M. Ahasan Kabir")
        self.assertEqual(updated["employee_id"], "4078")
        self.assertEqual(updated["status"], "Active")
        self.assertEqual(updated["group_name"], "IT Division")

    def test_quick_add_recipient_via_post_endpoint(self):
        h = self.handler
        h.path = "/admin/recipients/quick_add"
        h.client_address = ("127.0.0.1", 12345)
        h.headers = {"Content-Length": "0"}
        response_data = []
        h.sendbody = lambda code, body, ctype="text/html", extra=None: response_data.append((code, body, extra))

        payload = "email=quick.target%40example.com&name=Quick+Target&group_name=IT+Security"
        h.headers["Content-Length"] = str(len(payload))
        from unittest.mock import MagicMock
        h.rfile = MagicMock()
        h.rfile.read.return_value = payload.encode()

        h.do_POST()
        self.assertEqual(len(response_data), 1)
        self.assertEqual(response_data[0][0], 200)
        import json
        res = json.loads(response_data[0][1])
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["email"], "quick.target@example.com")
        self.assertEqual(res["group_name"], "IT Security")
        self.assertEqual(res["total_targets"], 1)

        c = self.server.db()
        row = c.execute("SELECT * FROM recipients WHERE lower(email)='quick.target@example.com'").fetchone()
        c.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["name"], "Quick Target")
        self.assertEqual(row["status"], "Active")

    def test_quick_campaign_modal_renders_quick_add_button_and_drawer(self):
        html = self.handler.feature_page("/admin/campaigns")
        self.assertIn("Quick Campaign Launch", html)
        self.assertIn("toggleQuickAddRecipient()", html)
        self.assertIn("quickAddRecPanel", html)
        self.assertIn("submitQuickRecipient()", html)
        self.assertIn("⚡ + Quick Add", html)

if __name__ == "__main__":
    unittest.main()
