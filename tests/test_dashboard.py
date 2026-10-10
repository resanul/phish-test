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

class DashboardTelemetryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = load_server()
        cls.tmp = tempfile.TemporaryDirectory()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.server.DB = os.path.join(self.tmp.name, self._testMethodName + ".db")
        self.server.db().close()
        self.handler = self.server.Handler.__new__(self.server.Handler)

    def test_dashboard_renders_without_error_on_empty_database(self):
        # On a fresh installation, events table has 0 rows.
        # Ensure ZeroDivisionError is not raised when calculating 7-day trend or template bars.
        html = self.handler.dashboard()
        self.assertIn("Dashboard", html)
        self.assertIn("TOTAL EVENTS", html)
        self.assertIn("0", html)
        self.assertIn("No template activity yet.", html)

    def test_campaign_form_renders_modern_design_and_controls(self):
        self.handler.admin_shell = lambda title, body, active: body
        html = self.handler.campaign_form()
        self.assertIn("Simulation Campaign", html)
        self.assertIn("camp-editor", html)
        self.assertIn("camp-card", html)
        self.assertIn("day-chip", html)
        self.assertIn("Simulation Summary", html)
        self.assertIn("business_days_input", html)
        self.assertIn("Save as Draft", html)
        self.assertIn("Draft (Safe Mode)", html)
        self.assertIn("Active (Live Simulation)", html)
        self.assertIn("Scheduled (Future)", html)
        self.assertIn("selectStatus", html)
        self.assertIn("action_mode", html)

    def test_campaign_save_as_draft_without_smtp_or_landing(self):
        from unittest.mock import MagicMock
        import urllib.parse
        h = self.server.Handler.__new__(self.server.Handler)
        h.path = "/admin/campaigns/save"
        h.client_address = ("127.0.0.1", 12345)
        h.auth = lambda: True
        h.csrf_origin_ok = lambda: True
        h.permission_allowed = lambda *a, **k: True

        payload = urllib.parse.urlencode({
            "name": "Draft Drill 2026",
            "action_mode": "draft",
            "template": "1",
            "group_name": "",
            "subject": "Phishing Test",
            "batch_size": "50",
            "rate_per_minute": "60",
            "retry_max": "2",
            "retry_backoff_seconds": "5",
            "business_days": "Sun,Mon,Tue,Wed,Thu",
            "window_start": "09:00",
            "window_end": "17:00"
        }).encode("utf-8")

        h.rfile = MagicMock()
        h.rfile.read.return_value = payload
        h.headers = {"Content-Length": str(len(payload))}
        response_data = []
        h.sendbody = lambda code, body, ctype="text/html", extra=None: response_data.append((code, body, extra))

        h.do_POST()
        self.assertEqual(len(response_data), 1)
        self.assertEqual(response_data[0][0], 302)
        self.assertEqual(response_data[0][2]["Location"], "/admin/campaigns")

        c = self.server.db()
        camp = c.execute("SELECT * FROM campaigns WHERE name=?", ("Draft Drill 2026",)).fetchone()
        c.close()
        self.assertIsNotNone(camp)
        self.assertEqual(camp["status"], "Draft")

    def test_campaign_save_and_launch_redirects_to_launch(self):
        from unittest.mock import MagicMock
        import urllib.parse
        c = self.server.db()
        c.execute("INSERT OR IGNORE INTO smtp_profiles(name,host,port,security,from_email,enabled,created_at,updated_at) VALUES('Test SMTP','smtp.test.com',587,'STARTTLS','phish@test.com',1,'2026-01-01','2026-01-01')")
        c.commit()
        smtp_id = c.execute("SELECT id FROM smtp_profiles WHERE enabled=1").fetchone()
        landing_id = c.execute("SELECT id FROM landing_pages WHERE status='Enabled'").fetchone()["id"]
        c.close()

        h = self.server.Handler.__new__(self.server.Handler)
        h.path = "/admin/campaigns/save"
        h.client_address = ("127.0.0.1", 12345)
        h.auth = lambda: True
        h.csrf_origin_ok = lambda: True
        h.permission_allowed = lambda *a, **k: True

        payload = urllib.parse.urlencode({
            "name": "Live Drill 2026",
            "action_mode": "launch",
            "template": "1",
            "smtp_profile_id": str(smtp_id["id"]),
            "landing_page_id": str(landing_id),
            "group_name": "",
            "subject": "Phishing Test Launch",
            "batch_size": "50",
            "rate_per_minute": "60",
            "retry_max": "2",
            "retry_backoff_seconds": "5",
            "business_days": "Sun,Mon,Tue,Wed,Thu",
            "window_start": "09:00",
            "window_end": "17:00"
        }).encode("utf-8")

        h.rfile = MagicMock()
        h.rfile.read.return_value = payload
        h.headers = {"Content-Length": str(len(payload))}
        response_data = []
        h.sendbody = lambda code, body, ctype="text/html", extra=None: response_data.append((code, body, extra))

        h.do_POST()
        self.assertEqual(len(response_data), 1)
        self.assertEqual(response_data[0][0], 302)

        c = self.server.db()
        camp = c.execute("SELECT * FROM campaigns WHERE name=?", ("Live Drill 2026",)).fetchone()
        c.close()
        self.assertIsNotNone(camp)
        self.assertEqual(camp["status"], "Active")
        self.assertEqual(response_data[0][2]["Location"], f"/admin/campaigns/launch?id={camp['id']}")

    def test_landing_page_form_renders_builder_and_presets(self):
        self.handler.admin_shell = lambda title, body, active: body
        html = self.handler.landing_page_form(None)
        self.assertIn("Create Simulation Landing Page", html)
        self.assertIn("lp-editor", html)
        self.assertIn("setDevice('mobile')", html)
        self.assertIn("previewFrame", html)
        self.assertIn("Microsoft 365 Sign-In", html)
        self.assertIn("loadPreset('m365')", html)

    def test_landing_page_directory_renders(self):
        self.handler.admin_shell = lambda title, body, active: body
        html = self.handler.feature_page("/admin/landing-pages")
        self.assertIn("Simulation Landing Pages", html)
        self.assertIn("/admin/landing-pages/new", html)
        self.assertIn("+ Create Landing Page", html)

    def test_quick_campaign_ui_and_modal(self):
        self.handler.admin_shell = lambda title, body, active: body
        html = self.handler.feature_page("/admin/campaigns")
        self.assertIn("⚡ Quick Campaign", html)
        self.assertIn("quickCampModal", html)
        self.assertIn("/admin/campaigns/quick", html)
        self.assertIn("⚡ Instant Launch Now", html)

if __name__ == "__main__":
    unittest.main()


