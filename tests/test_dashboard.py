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
        import gc
        gc.collect()
        try:
            cls.tmp.cleanup()
        except Exception:
            pass

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

    def test_dashboard_clickable_stat_cards_and_drilldown_modal(self):
        dash_html = self.handler.dashboard()
        self.assertIn("stat clickable", dash_html)
        self.assertIn("openStatDrilldown('total')", dash_html)
        self.assertIn("openStatDrilldown('clicks')", dash_html)
        self.assertIn("openStatDrilldown('submissions')", dash_html)
        self.assertIn("openStatDrilldown('ips')", dash_html)
        self.assertIn("stat-hint", dash_html)
        self.assertIn("statDrilldownModal", dash_html)
        self.assertIn("statModalSearch", dash_html)
        self.assertIn("statModalTbody", dash_html)

    def test_stat_details_api_all_types(self):
        import json
        c = self.server.db()
        c.execute("""INSERT INTO events(ts,ip,template,event,name,email,user_agent)
                     VALUES('2026-10-13T10:00:00Z','172.31.10.5','1','click','Alice Doe','alice@example.com','Mozilla/5.0')""")
        c.execute("""INSERT INTO events(ts,ip,template,event,name,email,user_agent)
                     VALUES('2026-10-13T10:05:00Z','172.31.10.5','1','submitted','Alice Doe','alice@example.com','Mozilla/5.0')""")
        c.commit()
        c.close()

        for stype in ("total", "clicks", "submissions", "ips"):
            sent = []
            self.handler.sendbody = lambda code, body, ctype="text/html", extra=None: sent.append((code, body))
            self.handler.stat_details_api(f"type={stype}")
            self.assertEqual(len(sent), 1, f"Should send 1 response for {stype}")
            code, body = sent[0]
            self.assertEqual(code, 200)
            data = json.loads(body)
            self.assertTrue(data["ok"])
            self.assertEqual(data["type"], stype)
            self.assertIn("summary", data)
            self.assertIn("items", data)
            self.assertIn("columns", data)

    def test_stat_details_api_route_dispatch_in_do_get(self):
        import json
        self.handler.path = "/admin/api/stat_details?type=total"
        self.handler.client_address = ("127.0.0.1", 12345)
        self.handler.headers = {}
        self.handler.auth = lambda: True
        self.handler.permission_allowed = lambda *a, **k: True
        sent = []
        self.handler.sendbody = lambda code, body, ctype="text/html", extra=None: sent.append((code, body))
        self.handler.do_GET()
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0][0], 200)
        data = json.loads(sent[0][1])
        self.assertTrue(data["ok"])
        self.assertEqual(data["type"], "total")

    def test_campaign_report_modern_html_and_downloads(self):
        c = self.server.db()
        c.execute("INSERT INTO campaigns(name,status,targeted,created_at) VALUES('Q1 Security Drill','Active',10,'2026-10-13T10:00:00Z')")
        cid = c.execute("SELECT last_insert_rowid() id").fetchone()["id"]
        c.execute("INSERT INTO recipients(email,name,department) VALUES('john@bank.com','John Doe','Finance')")
        rid = c.execute("SELECT last_insert_rowid() id").fetchone()["id"]
        c.execute("INSERT INTO campaign_deliveries(campaign_id,recipient_id,status,sent_at) VALUES(?,?,'Sent','2026-10-13T10:01:00Z')",(cid,rid))
        c.execute("INSERT INTO events(campaign_id,recipient_id,email,event,ts,ip,template) VALUES(?,?,'john@bank.com','click','2026-10-13T10:02:00Z','127.0.0.1','1')",(cid,rid))
        c.commit()
        c.close()

        self.handler.admin_shell = lambda title, body, active: body
        html = self.handler.campaign_report(str(cid))
        self.assertIn("Q1 Security Drill", html)
        self.assertIn("Simulation Engagement Funnel", html)
        self.assertIn("Target Engagement Telemetry", html)
        self.assertIn("DISPATCH & DELIVERY", html)
        self.assertIn("LINK CLICKS", html)
        self.assertIn("FORM COMPROMISE", html)
        self.assertIn("PHISH REPORTED", html)
        self.assertIn(f"/admin/reports/campaign.csv?id={cid}", html)
        self.assertIn(f"/admin/reports/campaign.pdf?id={cid}", html)
        self.assertIn("window.print()", html)
        self.assertIn("filterRecTable()", html)

    def test_campaign_report_csv_and_pdf_exports(self):
        c = self.server.db()
        c.execute("INSERT INTO campaigns(name,status,targeted,created_at) VALUES('Export Test Drill','Active',5,'2026-10-13T10:00:00Z')")
        cid = c.execute("SELECT last_insert_rowid() id").fetchone()["id"]
        c.execute("INSERT INTO recipients(email,name,department,employee_id) VALUES('audit@bank.com','Audit User','Risk & Compliance','EMP-99')")
        rid = c.execute("SELECT last_insert_rowid() id").fetchone()["id"]
        c.execute("INSERT INTO campaign_deliveries(campaign_id,recipient_id,status,sent_at) VALUES(?,?,'Sent','2026-10-13T10:01:00Z')",(cid,rid))
        c.commit()
        c.close()

        # CSV Export
        sent_csv = []
        self.handler.client_address = ("127.0.0.1", 12345)
        self.handler.sendbody = lambda code, body, ctype="text/html", extra=None: sent_csv.append((code, body, ctype, extra))
        self.handler.campaign_report_csv(str(cid))
        self.assertEqual(len(sent_csv), 1)
        code, body, ctype, extra = sent_csv[0]
        self.assertEqual(code, 200)
        self.assertEqual(ctype, "text/csv")
        self.assertIn("attachment; filename=", extra.get("Content-Disposition", ""))
        self.assertIn("campaign_id,campaign_name,email,name,department,employee_id,delivery_status", body)
        self.assertIn("audit@bank.com", body)

        # PDF Export
        sent_pdf = []
        self.handler.sendbody = lambda code, body, ctype="text/html", extra=None: sent_pdf.append((code, body, ctype, extra))
        self.handler.campaign_report_pdf(str(cid))
        self.assertEqual(len(sent_pdf), 1)
        code, body, ctype, extra = sent_pdf[0]
        self.assertEqual(code, 200)
        self.assertEqual(ctype, "application/pdf")
        self.assertIn("attachment; filename=", extra.get("Content-Disposition", ""))
        self.assertTrue(body.startswith(b"%PDF-"))

    def test_reports_csv_export_views(self):
        c = self.server.db()
        c.execute("INSERT INTO campaigns(name,status,targeted,created_at) VALUES('Monthly Drill','Active',1,'2026-10-13T10:00:00Z')")
        c.execute("INSERT INTO events(ts,ip,template,event,name,email) VALUES('2026-10-13T10:00:00Z','172.31.10.5','1','click','User','u@bank.com')")
        c.commit()
        c.close()

        self.handler.client_address = ("127.0.0.1", 12345)

        # Main / Campaigns CSV
        sent = []
        self.handler.sendbody = lambda code, body, ctype="text/html", extra=None: sent.append((code, body, ctype, extra))
        self.handler.reports_csv_export("")
        self.assertEqual(sent[0][0], 200)
        self.assertEqual(sent[0][2], "text/csv")
        self.assertIn("campaign_id,campaign_name,status", sent[0][1])

        # Department CSV
        sent_dept = []
        self.handler.sendbody = lambda code, body, ctype="text/html", extra=None: sent_dept.append((code, body, ctype, extra))
        self.handler.reports_csv_export("view=department")
        self.assertEqual(sent_dept[0][0], 200)
        self.assertEqual(sent_dept[0][2], "text/csv")
        self.assertIn("department,total_users,clicked_users", sent_dept[0][1])

        # Monthly CSV
        sent_month = []
        self.handler.sendbody = lambda code, body, ctype="text/html", extra=None: sent_month.append((code, body, ctype, extra))
        self.handler.reports_csv_export("view=monthly")
        self.assertEqual(sent_month[0][0], 200)
        self.assertEqual(sent_month[0][2], "text/csv")
        self.assertIn("month,total_events,clicks,actions,reports", sent_month[0][1])

    def test_reports_routing_in_do_get(self):
        c = self.server.db()
        c.execute("INSERT INTO campaigns(name,status,targeted,created_at) VALUES('Route Test Drill','Active',1,'2026-10-13T10:00:00Z')")
        cid = c.execute("SELECT last_insert_rowid() id").fetchone()["id"]
        c.commit()
        c.close()

        self.handler.client_address = ("127.0.0.1", 12345)
        self.handler.headers = {}
        self.handler.auth = lambda: True
        self.handler.permission_allowed = lambda *a, **k: True

        # Test GET /admin/reports/campaign.csv?id=CID
        sent = []
        self.handler.sendbody = lambda code, body, ctype="text/html", extra=None: sent.append((code, body, ctype))
        self.handler.path = f"/admin/reports/campaign.csv?id={cid}"
        self.handler.do_GET()
        self.assertEqual(sent[0][0], 200)
        self.assertEqual(sent[0][2], "text/csv")

        # Test GET /admin/reports/campaign.pdf?id=CID
        sent_pdf = []
        self.handler.sendbody = lambda code, body, ctype="text/html", extra=None: sent_pdf.append((code, body, ctype))
        self.handler.path = f"/admin/reports/campaign.pdf?id={cid}"
        self.handler.do_GET()
        self.assertEqual(sent_pdf[0][0], 200)
        self.assertEqual(sent_pdf[0][2], "application/pdf")

        # Test GET /admin/reports?campaign_id=CID&export=csv
        sent_qs_csv = []
        self.handler.sendbody = lambda code, body, ctype="text/html", extra=None: sent_qs_csv.append((code, body, ctype))
        self.handler.path = f"/admin/reports?campaign_id={cid}&export=csv"
        self.handler.do_GET()
        self.assertEqual(sent_qs_csv[0][0], 200)
        self.assertEqual(sent_qs_csv[0][2], "text/csv")

        # Test GET /admin/reports.csv
        sent_rep_csv = []
        self.handler.sendbody = lambda code, body, ctype="text/html", extra=None: sent_rep_csv.append((code, body, ctype))
        self.handler.path = "/admin/reports.csv"
        self.handler.do_GET()
        self.assertEqual(sent_rep_csv[0][0], 200)
        self.assertEqual(sent_rep_csv[0][2], "text/csv")

    def test_main_reports_page_has_individual_download_buttons(self):
        c = self.server.db()
        c.execute("INSERT INTO campaigns(name,status,targeted,created_at) VALUES('List Drill 101','Active',5,'2026-10-13T10:00:00Z')")
        cid = c.execute("SELECT last_insert_rowid() id").fetchone()["id"]
        c.commit()
        c.close()

        self.handler.admin_shell = lambda title, body, active: body
        html = self.handler.feature_page("/admin/reports", "")
        self.assertIn("List Drill 101", html)
        self.assertIn(f"/admin/reports?campaign_id={cid}", html)
        self.assertIn(f"/admin/reports/campaign.csv?id={cid}", html)
        self.assertIn(f"/admin/reports/campaign.pdf?id={cid}", html)
        self.assertIn("/admin/reports.pdf", html)
        self.assertIn("/admin/reports.csv", html)

    def test_admin_shell_collapsible_responsive_sidebar(self):
        # Instantiate handler without mocked admin_shell to test actual admin_shell rendering
        handler = self.server.Handler.__new__(self.server.Handler)
        html = handler.admin_shell("Test Page", "<p>Content Here</p>", "Campaigns")
        self.assertIn('id="mainLayout"', html)
        self.assertIn('id="adminSidebar"', html)
        self.assertIn('id="sideCollapseBtn"', html)
        self.assertNotIn('id="topbarToggleBtn"', html)
        self.assertIn('class="side-backdrop"', html)
        self.assertIn('data-tooltip="Campaigns"', html)
        self.assertIn('class="side-text"', html)
        self.assertIn('toggleSidebar', html)
        self.assertIn('toggleMobileNav', html)
        self.assertIn('closeMobileNav', html)
        self.assertIn('mobile-menu-btn', html)
        self.assertIn('side-close-btn', html)
        self.assertIn('.layout.collapsed{grid-template-columns:68px 1fr}', html)
        self.assertIn('localStorage.getItem', html)

if __name__ == "__main__":
    unittest.main()



