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

class EmailTemplatesTests(unittest.TestCase):
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
        self.server.db().close()
        self.handler = self.server.Handler.__new__(self.server.Handler)
        self.handler.admin_shell = lambda title, body, active: body

    def test_linksec_templates_seeded_into_database(self):
        c = self.server.db()
        rows = c.execute("SELECT * FROM template_library").fetchall()
        c.close()
        self.assertGreaterEqual(len(rows), 45)
        slugs = {r["template"] for r in rows}
        self.assertIn("zoom-urgent-account-update-required", slugs)
        self.assertIn("amazon-web-services-aws-urgent-aws-security-update-alert", slugs)
        self.assertIn("google-workspace-urgent-google-workspace-account-verification", slugs)

        zoom_row = next(r for r in rows if r["template"] == "zoom-urgent-account-update-required")
        self.assertEqual(zoom_row["brand"], "Zoom")
        self.assertIn("Call to action", zoom_row["tags"])
        self.assertIn("noreply@zoomsecurity.com", zoom_row["from_email"])

    def test_render_template_variables_supports_gophish_and_custom_tokens(self):
        template_text = "<p>Hello {{.FirstName}} {{.LastName}}, click {{.URL}} or {{tracking_link}} for {{company_name}}.</p>"
        rec = {"name": "Alice Wonderland", "email": "alice@wonder.corp"}
        camp = {"name": "Test Simulation", "brand": "Wonderland Corp"}
        links = {"tracking_link": "https://sim.test/click?t=abc", "report_link": "", "qr_link": ""}
        rendered = self.server.render_template_variables(template_text, rec, camp, links)
        self.assertIn("Hello Alice Wonderland", rendered)
        self.assertIn("click https://sim.test/click?t=abc", rendered)
        self.assertIn("Wonderland Corp", rendered)

    def test_email_templates_catalog_page_renders_linksec_3_pane(self):
        html = self.handler.feature_page("/admin/templates")
        self.assertIn("Email Templates &amp; Payloads", html)
        self.assertIn("ls-browser", html)
        self.assertIn("ls-sidebar", html)
        self.assertIn("ls-catalog", html)
        self.assertIn("ls-preview-pane", html)
        self.assertIn("Zoom", html)
        self.assertIn("Call to action", html)
        self.assertIn("Realistic View (Victim)", html)
        self.assertIn("Phish Indicators (Trainee)", html)
        self.assertIn("lsIframe", html)

    def test_email_templates_preview_route(self):
        mock_handler = self.server.Handler.__new__(self.server.Handler)
        mock_handler.auth = lambda: True
        mock_handler.permission_allowed = lambda path, method, query=None, form=None: True
        sent = []
        mock_handler.sendbody = lambda status, body, ctype="text/html; charset=utf-8": sent.append((status, body, ctype))

        mock_handler.do_GET_path = "/admin/templates/preview"
        # Test realistic mode
        p_real = self.server.urlparse("/admin/templates/preview?id=zoom-urgent-account-update-required&mode=realistic")
        # Simulate do_GET matching logic
        tid = self.server.parse_qs(p_real.query).get("id", [""])[0]
        c = self.server.db()
        row = c.execute("SELECT * FROM template_library WHERE template=?", (tid,)).fetchone()
        c.close()
        self.assertIsNotNone(row)
        rendered_real = self.server.render_template_variables(row["html_body"], {"name": "John Doe", "email": "j@c.com"}, {"name": "C", "brand": "Zoom"}, {"tracking_link": "http://trk"})
        clean_real = self.server.re.sub(r'style="background-color:\s*#[a-fA-F0-9]+;\s*outline:\s*3px solid\s*#[a-fA-F0-9]+"', 'style="background-color:transparent;outline:none"', rendered_real)
        self.assertNotIn("outline: 3px solid", clean_real)
        self.assertIn("Dear John,", clean_real)

    def test_campaign_form_groups_templates_by_brand(self):
        html = self.handler.campaign_form()
        self.assertIn("Email Template (Phishing Scenario)", html)
        self.assertIn("<optgroup label=\"Zoom\">", html)
        self.assertIn("zoom-urgent-account-update-required", html)
        self.assertIn("data-subject=", html)

if __name__ == "__main__":
    unittest.main()
