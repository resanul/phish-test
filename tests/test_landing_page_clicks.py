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

class LandingPageClickTelemetryTests(unittest.TestCase):
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
        self.handler.client_address = ("127.0.0.1", 54321)
        self.handler.headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

    def test_direct_landing_page_visit_records_click_and_each_reload_creates_new_event(self):
        # 1. First visit to /1.html (Apex Rewards) without campaign token
        self.handler.path = "/1.html"
        sent = []
        self.handler.sendbody = lambda code, body, ctype="text/html; charset=utf-8", extra=None: sent.append((code, body))
        self.handler.do_GET()
        self.assertEqual(sent[-1][0], 200)

        c = self.server.db()
        ev1 = c.execute("SELECT * FROM events WHERE event='click'").fetchall()
        self.assertEqual(len(ev1), 1)
        self.assertEqual(ev1[0]["template"], "1")
        self.assertEqual(ev1[0]["ip"], "127.0.0.1")

        # 2. First reload (second visit)
        self.handler.do_GET()
        ev2 = c.execute("SELECT * FROM events WHERE event='click'").fetchall()
        self.assertEqual(len(ev2), 2, "Reloading the landing page should record another click event")

        # 3. Second reload (third visit)
        self.handler.do_GET()
        ev3 = c.execute("SELECT * FROM events WHERE event='click'").fetchall()
        self.assertEqual(len(ev3), 3, "Every reload should create a new click event")
        c.close()

        # 4. Verify dashboard displays the 3 clicks
        dash_html = self.handler.dashboard()
        self.assertIn("CLICKS", dash_html)
        self.assertIn('<div class="num">3</div>', dash_html)
        self.assertIn("1 (Apex Rewards)", dash_html)

    def test_campaign_token_visit_and_reload_records_all_clicks_and_dashboard(self):
        c = self.server.db()
        c.execute("INSERT INTO campaigns(name,template,status,created_at) VALUES('Q4 Phish Test','3','Active','2026-10-10')")
        camp_id = c.execute("SELECT last_insert_rowid() id").fetchone()["id"]
        c.execute("INSERT INTO recipients(email,name,status,created_at) VALUES('victim@example.com','Victim User','Pending','2026-10-10')")
        rec_id = c.execute("SELECT last_insert_rowid() id").fetchone()["id"]
        c.commit()
        c.close()
        token = self.server.create_tracking_token(camp_id, rec_id)

        # 1. Recipient opens simulation landing page with token
        self.handler.path = f"/3.html?t={token}"
        sent = []
        self.handler.sendbody = lambda code, body, ctype="text/html; charset=utf-8", extra=None: sent.append((code, body))
        self.handler.do_GET()
        self.assertEqual(sent[-1][0], 200)

        c = self.server.db()
        ev1 = c.execute("SELECT * FROM events WHERE event='click'").fetchall()
        self.assertEqual(len(ev1), 1)
        self.assertEqual(ev1[0]["email"], "victim@example.com")
        self.assertEqual(ev1[0]["name"], "Victim User")

        # 2. Recipient reloads the page
        self.handler.do_GET()
        ev2 = c.execute("SELECT * FROM events WHERE event='click'").fetchall()
        self.assertEqual(len(ev2), 2, "Reloading simulation link must create a new click event")

        # 3. Recipient reloads again
        self.handler.do_GET()
        ev3 = c.execute("SELECT * FROM events WHERE event='click'").fetchall()
        self.assertEqual(len(ev3), 3)
        c.close()

        # 4. Dashboard shows updated telemetry
        dash_html = self.handler.dashboard()
        self.assertIn('<div class="num">3</div>', dash_html)
        self.assertIn("Victim User", dash_html)
        self.assertIn("victim@example.com", dash_html)
        self.assertIn("3 (Microsoft 365)", dash_html)

if __name__ == "__main__":
    unittest.main()
