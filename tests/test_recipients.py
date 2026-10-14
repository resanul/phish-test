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

    def test_groups_table_renders_multiple_departments_as_pills(self):
        c = self.server.db()
        c.execute("INSERT INTO groups_tbl(id, name, department, created_at) VALUES(2, 'IT Division', 'IT System, Network & Infrastructure', ?)", (self.server.now(),))
        c.execute("INSERT INTO recipients(id, email, name, department, group_name, status, created_at) VALUES(6, 'head@company.com', 'Ahasan Kabir', 'Division Head', 'IT Division', 'Active', ?)", (self.server.now(),))
        c.commit()
        c.close()

        html = self.handler.feature_page("/admin/groups")
        self.assertIn("IT Division", html)
        self.assertIn("📁 IT System", html)
        self.assertIn("📁 Network &amp; Infrastructure", html)
        self.assertIn("📁 Division Head", html)
        self.assertIn("3 Depts:", html)
        self.assertIn("1 Members", html)
        self.assertIn('href="/admin/groups?id=2"', html)

    def test_group_form_edit_and_create_support_multiple_departments(self):
        c = self.server.db()
        c.execute("INSERT INTO groups_tbl(id, name, department, created_at) VALUES(2, 'IT Division', 'IT System', ?)", (self.server.now(),))
        c.execute("INSERT INTO recipients(id, email, name, department, group_name, status, created_at) VALUES(6, 'head@company.com', 'Ahasan Kabir', 'Division Head', 'IT Division', 'Active', ?)", (self.server.now(),))
        c.commit()
        c.close()

        html_edit = self.handler.group_form("2")
        self.assertIn("Edit Group: IT Division", html_edit)
        self.assertIn("IT System, Division Head", html_edit)
        self.assertIn("updateDeptPreview()", html_edit)
        self.assertIn("Delete Group", html_edit)

        html_new = self.handler.group_form(None)
        self.assertIn("New Target Group", html_new)
        self.assertIn("Save Group", html_new)

    def test_group_save_and_update_via_post(self):
        h = self.handler
        h.path = "/admin/groups/save"
        h.client_address = ("127.0.0.1", 12345)
        response_data = []
        h.sendbody = lambda code, body, ctype="text/html", extra=None: response_data.append((code, body, extra))

        payload = "name=Operations+Division&department=Procurement%2C+Logistics"
        h.headers = {"Content-Length": str(len(payload))}
        from unittest.mock import MagicMock
        h.rfile = MagicMock()
        h.rfile.read.return_value = payload.encode()
        h.do_POST()
        self.assertEqual(len(response_data), 1)
        self.assertEqual(response_data[0][0], 302)

        c = self.server.db()
        row = c.execute("SELECT * FROM groups_tbl WHERE name='Operations Division'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["department"], "Procurement, Logistics")
        gid = row["id"]

        response_data.clear()
        payload2 = f"id={gid}&name=Operations+Division&department=Procurement%2C+Logistics%2C+Inventory"
        h.headers = {"Content-Length": str(len(payload2))}
        h.rfile.read.return_value = payload2.encode()
        h.do_POST()
        self.assertEqual(len(response_data), 1)
        self.assertEqual(response_data[0][0], 302)

        row2 = c.execute("SELECT * FROM groups_tbl WHERE id=?", (gid,)).fetchone()
        self.assertEqual(row2["department"], "Procurement, Logistics, Inventory")
        c.close()

    def test_group_delete_via_post(self):
        c = self.server.db()
        c.execute("INSERT INTO groups_tbl(id, name, department, created_at) VALUES(99, 'Temporary Group', 'Temp Dept', ?)", (self.server.now(),))
        c.commit()
        c.close()

        h = self.handler
        h.path = "/admin/groups/delete"
        h.client_address = ("127.0.0.1", 12345)
        response_data = []
        h.sendbody = lambda code, body, ctype="text/html", extra=None: response_data.append((code, body, extra))

        payload = "id=99"
        h.headers = {"Content-Length": str(len(payload))}
        from unittest.mock import MagicMock
        h.rfile = MagicMock()
        h.rfile.read.return_value = payload.encode()
        h.do_POST()
        self.assertEqual(len(response_data), 1)
        self.assertEqual(response_data[0][0], 302)

        c = self.server.db()
        row = c.execute("SELECT * FROM groups_tbl WHERE id=99").fetchone()
        c.close()
        self.assertIsNone(row)

    def test_recipient_profile_form_splits_departments_and_maps_groups(self):
        c = self.server.db()
        c.execute("INSERT INTO groups_tbl(name, department, created_at) VALUES('IT Division', 'Division Head, IT System, Network', ?)", (self.server.now(),))
        c.commit()
        c.close()

        html = self.handler.recipient_profile_form("new")
        self.assertIn('<option value="Division Head">', html)
        self.assertIn('<option value="IT System">', html)
        self.assertIn('<option value="Network">', html)
        self.assertIn("groupDeptsMap", html)
        self.assertIn("IT Division", html)

    def test_queue_campaign_targets_multi_department_division(self):
        c = self.server.db()
        c.execute("INSERT INTO groups_tbl(name, department, created_at) VALUES('IT Division', 'Division Head, IT System, Network', ?)", (self.server.now(),))
        c.execute("INSERT INTO recipients(email, name, department, group_name, status, created_at) VALUES('u1@test.com', 'User 1', 'Division Head', 'IT Division', 'Active', ?)", (self.server.now(),))
        c.execute("INSERT INTO recipients(email, name, department, group_name, status, created_at) VALUES('u2@test.com', 'User 2', 'IT System', '', 'Active', ?)", (self.server.now(),))
        c.execute("INSERT INTO recipients(email, name, department, group_name, status, created_at) VALUES('u3@test.com', 'User 3', 'HR', 'Human Resources', 'Active', ?)", (self.server.now(),))
        c.execute("INSERT INTO campaigns(name, status, template, group_name, created_at) VALUES('IT Awareness Drill', 'Scheduled', 'tbl-notice', 'IT Division', ?)", (self.server.now(),))
        cid = c.execute("SELECT last_insert_rowid() id").fetchone()["id"]
        c.commit()
        c.close()

        count = self.server.queue_campaign(cid)
        self.assertEqual(count, 2)

    def test_client_ip_extracts_from_forwarded_headers(self):
        h = self.handler
        h.client_address = ("127.0.0.1", 54321)
        h.headers = {"X-Forwarded-For": "172.31.105.50, 10.0.0.1"}
        self.assertEqual(h.client_ip(), "172.31.105.50")

        h.headers = {"X-Real-IP": "172.31.105.99"}
        self.assertEqual(h.client_ip(), "172.31.105.99")

        h.headers = {}
        self.assertEqual(h.client_ip(), "127.0.0.1")

    def test_user_journeys_merges_click_and_submission_for_same_user(self):
        events = [
            {"id": 10, "event": "delivered", "email": "resanul@gmail.com", "campaign_id": "1", "template": "1", "ts": "2026-10-14T07:18:00Z", "ip": "smtp"},
            {"id": 11, "event": "click", "email": "resanul@gmail.com", "campaign_id": "1", "template": "1", "ts": "2026-10-14T07:18:11Z", "ip": "172.31.105.50", "name": "Mir Resanul Karim"},
            {"id": 12, "event": "form_action", "email": "resanul@gmail.com", "campaign_id": "", "template": "1 (Apex Rewards)", "ts": "2026-10-14T07:19:14Z", "ip": "172.31.105.50", "name": "Mir Resanul Karim", "mobile": "01754698458"},
        ]
        journeys = self.server.build_user_journeys(events, {"1": "1 (Apex Rewards)"})
        # Should be merged into ONE single journey instead of two rows
        self.assertEqual(len(journeys), 1)
        j = journeys[0]
        self.assertTrue(j["has_delivered"])
        self.assertTrue(j["has_click"])
        self.assertTrue(j["has_action"])
        self.assertEqual(j["mobile"], "01754698458")
        self.assertEqual(j["ip"], "172.31.105.50")
        self.assertEqual(len(j["events"]), 3)

if __name__ == "__main__":
    unittest.main()
