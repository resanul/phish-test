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

    def test_trust_bank_gozayaan_landing_page_serving_and_submission(self):
        # 1. Test GET /trust-gozayaan-travel-oct26.html
        self.handler.path = "/trust-gozayaan-travel-oct26.html"
        sent = []
        self.handler.sendbody = lambda code, body, ctype="text/html; charset=utf-8", extra=None: sent.append((code, body))
        self.handler.do_GET()
        self.assertEqual(sent[-1][0], 200)
        self.assertIn("Trust Bank", sent[-1][1])
        self.assertIn("GoZayaan", sent[-1][1])
        self.assertIn("+8809678332211", sent[-1][1])
        self.assertIn("10% off flights", sent[-1][1])
        self.assertIn("65% off hotels", sent[-1][1])

        # 2. Test GET /11.html
        self.handler.path = "/11.html"
        self.handler.do_GET()
        self.assertEqual(sent[-1][0], 200)
        self.assertIn("Trust Bank", sent[-1][1])

        # 3. Test POST /submit
        import io
        from urllib.parse import urlencode
        form_data = {
            "name": "Mir Resanul Karim",
            "email": "resanul@gmail.com",
            "mobile": "01754698458",
            "card_type": "Trust Bank Platinum Credit Card",
            "template": "trust-gozayaan-travel-oct26"
        }
        encoded = urlencode(form_data).encode("utf-8")
        self.handler.path = "/submit"
        self.handler.headers = {"Content-Length": str(len(encoded)), "User-Agent": "Mozilla/5.0"}
        self.handler.rfile = io.BytesIO(encoded)
        self.handler.do_POST()
        self.assertEqual(sent[-1][0], 200)

        c = self.server.db()
        ev = c.execute("SELECT * FROM events WHERE event='form_action' ORDER BY id DESC LIMIT 1").fetchone()
        self.assertIsNotNone(ev)
        self.assertEqual(ev["name"], "Mir Resanul Karim")
        self.assertEqual(ev["email"], "resanul@gmail.com")
        self.assertEqual(ev["mobile"], "01754698458")
        self.assertEqual(ev["card_type"], "Trust Bank Platinum Credit Card")
        c.close()

    def test_recipient_attribution_when_different_email_entered_on_form(self):
        c = self.server.db()
        c.execute("INSERT INTO campaigns(name,template,status,created_at) VALUES('Campaign 13','11','Active','2026-10-14')")
        camp_id = c.execute("SELECT last_insert_rowid() id").fetchone()["id"]
        c.execute("INSERT INTO recipients(email,name,employee_id,status,created_at) VALUES('saad.abser@tblbd.com','Saad Abser','EMP-01','Pending','2026-10-14')")
        saad_id = c.execute("SELECT last_insert_rowid() id").fetchone()["id"]
        c.execute("INSERT INTO recipients(email,name,employee_id,status,created_at) VALUES('resanul@gmail.com','Mir Resanul Karim','EMP-02','Pending','2026-10-14')")
        resanul_id = c.execute("SELECT last_insert_rowid() id").fetchone()["id"]
        c.commit()
        c.close()

        saad_token = self.server.create_tracking_token(camp_id, saad_id)
        resanul_token = self.server.create_tracking_token(camp_id, resanul_id)

        # 1. Simulate deliveries for both recipients
        self.server.record("smtp", "11", "delivered", "Saad Abser", "saad.abser@tblbd.com", "", "campaign-delivery", "EMP-01", "", camp_id, saad_id, saad_token)
        self.server.record("smtp", "11", "delivered", "Mir Resanul Karim", "resanul@gmail.com", "", "campaign-delivery", "EMP-02", "", camp_id, resanul_id, resanul_token)

        # 2. Resanul clicks his email link (Saad NEVER clicks)
        self.handler.path = f"/11.html?t={resanul_token}"
        sent = []
        self.handler.sendbody = lambda code, body, ctype="text/html; charset=utf-8", extra=None: sent.append((code, body))
        self.handler.do_GET()
        self.assertEqual(sent[-1][0], 200)

        # 3. Resanul submits form, but enters Saad's email into the input field!
        import io
        from urllib.parse import urlencode
        form_data = {
            "name": "Saad Abser",
            "email": "saad.abser@tblbd.com",
            "mobile": "01711223344",
            "card_type": "Trust Bank Platinum",
            "template": "11",
            "t": resanul_token
        }
        encoded = urlencode(form_data).encode("utf-8")
        self.handler.path = f"/submit?t={resanul_token}"
        self.handler.headers = {"Content-Length": str(len(encoded)), "User-Agent": "Mozilla/5.0"}
        self.handler.rfile = io.BytesIO(encoded)
        self.handler.do_POST()
        self.assertEqual(sent[-1][0], 200)

        # 4. In events table:
        # The form_action MUST belong to Resanul (recipient_id=resanul_id, email=resanul@gmail.com)
        c = self.server.db()
        saad_actions = c.execute("SELECT * FROM events WHERE email='saad.abser@tblbd.com' AND event='form_action'").fetchall()
        self.assertEqual(len(saad_actions), 0, "Saad never clicked or submitted, no form_action should be attributed to Saad")

        res_action = c.execute("SELECT * FROM events WHERE email='resanul@gmail.com' AND event='form_action'").fetchone()
        self.assertIsNotNone(res_action, "Resanul submitted the form, so compromise must be attributed to Resanul")
        self.assertEqual(str(res_action["recipient_id"]), str(resanul_id))
        self.assertIn("Typed: saad.abser@tblbd.com", res_action["card_type"])

        # 5. In User Journeys:
        all_events = [dict(r) for r in c.execute("SELECT * FROM events WHERE campaign_id=?", (camp_id,)).fetchall()]
        c.close()

        journeys = self.server.build_user_journeys(all_events, {"11": "11 (Trust Bank x GoZayaan)"})
        saad_j = next((j for j in journeys if j["email"] == "saad.abser@tblbd.com"), None)
        res_j = next((j for j in journeys if j["email"] == "resanul@gmail.com"), None)

        self.assertIsNotNone(saad_j)
        self.assertIsNotNone(res_j)

        # Saad: ONLY delivered (1 event)
        self.assertTrue(saad_j["has_delivered"])
        self.assertFalse(saad_j["has_click"])
        self.assertFalse(saad_j["has_action"])
        self.assertEqual(len(saad_j["events"]), 1)

        # Resanul: delivered + click + form_action (3 events)
        self.assertTrue(res_j["has_delivered"])
        self.assertTrue(res_j["has_click"])
        self.assertTrue(res_j["has_action"])
        self.assertEqual(len(res_j["events"]), 3)

    def test_database_self_healing_heals_mismatched_recipient_emails(self):
        c = self.server.db()
        c.execute("INSERT INTO recipients(email,name,employee_id,status,created_at) VALUES('resanul@gmail.com','Mir Resanul Karim','EMP-99','Pending','2026-10-14')")
        rec_id = c.execute("SELECT last_insert_rowid() id").fetchone()["id"]
        # Corrupted historical event where recipient_id=rec_id, but email is typed as saad
        c.execute("""INSERT INTO events(ts,ip,template,event,name,email,mobile,recipient_id,campaign_id)
                     VALUES('2026-10-14T11:00:00Z','172.31.105.10','11','form_action','Saad Abser','saad.abser@tblbd.com','01711223344',?,'13')""", (rec_id,))
        # Reset healed flag to simulate startup migration
        c.execute("DELETE FROM system_settings WHERE key='event_recipient_email_healed_v2'")
        c.commit()
        c.close()

        # Re-run db() to trigger self-healing
        c2 = self.server.db()
        healed_ev = c2.execute("SELECT * FROM events WHERE recipient_id=? AND event='form_action'", (rec_id,)).fetchone()
        self.assertIsNotNone(healed_ev)
        self.assertEqual(healed_ev["email"], "resanul@gmail.com", "Self-healing must restore the authentic recipient email")
        self.assertEqual(healed_ev["name"], "Mir Resanul Karim")
        self.assertEqual(healed_ev["employee_id"], "EMP-99")
        c2.close()

if __name__ == "__main__":
    unittest.main()

