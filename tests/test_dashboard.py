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

if __name__ == "__main__":
    unittest.main()


