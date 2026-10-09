#!/usr/bin/env python3
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

SERVER=Path(__file__).resolve().parents[1] / "server.py"

def load_server():
    spec=importlib.util.spec_from_file_location("phishguard_server",SERVER)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class SMTPProviderUnitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=load_server()
        cls.tmp=tempfile.TemporaryDirectory()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.server.DB=os.path.join(self.tmp.name,self._testMethodName+".db")
        self.server.SMTP_KEY=os.path.join(self.tmp.name,".smtp_key_"+self._testMethodName)
        self.server.db().close()
        self.handler=self.server.Handler.__new__(self.server.Handler)
        self.handler.current_admin=lambda: {"username":"admin@example.com","role":"Administrator"}
        self.handler.csrf_origin_ok=lambda: True
        self.handler.permission_allowed=lambda *args, **kwargs: True

    def test_smtp_presets_contain_all_enterprise_providers(self):
        providers=self.server.SMTP_PROVIDERS
        expected=["Gmail","Google Workspace Relay","Zoho","Microsoft 365","Amazon SES","SendGrid","Mailgun","Custom SMTP"]
        for p in expected:
            self.assertIn(p,providers)
            self.assertIn("host",providers[p])
            self.assertIn("port",providers[p])
            self.assertIn("security",providers[p])
            self.assertEqual(providers[p]["security"],"STARTTLS")

    def test_secret_encryption_and_decryption_roundtrip(self):
        secret="MySuperSecretP@ssword123!"
        enc=self.server.encrypt_secret(secret)
        self.assertNotEqual(enc,secret)
        self.assertTrue(len(enc)>0)
        dec=self.server.decrypt_secret(enc)
        self.assertEqual(dec,secret)

    def test_secret_encryption_handles_empty(self):
        self.assertEqual(self.server.encrypt_secret(""),"")
        self.assertEqual(self.server.decrypt_secret(""),"")

    def test_sanitize_audit_details_redacts_credentials(self):
        details="profile=Gmail password=SecretP@ss123 token=abcxyz client_secret=key999"
        sanitized=self.server.sanitize_audit_details(details)
        self.assertNotIn("SecretP@ss123",sanitized)
        self.assertNotIn("abcxyz",sanitized)
        self.assertNotIn("key999",sanitized)
        self.assertIn("[REDACTED]",sanitized)

    def test_smtp_form_renders_valid_json_presets_and_status(self):
        html=self.handler.smtp_form()
        self.assertIn("Add SMTP Provider",html)
        self.assertIn('<select id="provider" name="provider"',html)
        self.assertIn('<select name="enabled">',html)
        self.assertIn('<option value="1" selected>Enabled</option>',html)
        # Verify JSON presets are valid JS and not broken by html.escape &quot;
        self.assertIn('const presets={"Gmail":',html)
        self.assertNotIn('&quot;Gmail&quot;',html)
        self.assertIn('authFields();',html)

    def test_smtp_form_edit_existing_profile(self):
        c=self.server.db()
        enc=self.server.encrypt_secret("old-secret")
        c.execute("""INSERT INTO smtp_profiles(name,provider,host,port,security,username,password_enc,from_name,from_email,reply_to,auth_method,enabled,created_at,updated_at)
                     VALUES('Corporate Relay','Gmail','smtp.gmail.com',587,'STARTTLS','user@example.com',?,'Corp Security','security@example.com','reply@example.com','password',0,?,?)""",
                  (enc,self.server.now(),self.server.now()))
        pid=c.execute("SELECT id FROM smtp_profiles WHERE name='Corporate Relay'").fetchone()["id"]
        c.commit(); c.close()

        html=self.handler.smtp_form(str(pid))
        self.assertIn("Edit SMTP Provider",html)
        self.assertIn('value="Corporate Relay"',html)
        self.assertIn('<option value="0" selected>Disabled</option>',html)
        self.assertIn("Delete Provider",html)
        self.assertIn("Open Diagnostics",html)

    def test_smtp_authenticate_password(self):
        mock_smtp=MagicMock()
        enc=self.server.encrypt_secret("secret_pass")
        profile={
            "username":"user@example.com",
            "password_enc":enc,
            "auth_method":"password"
        }
        self.server.smtp_authenticate(mock_smtp,profile)
        mock_smtp.login.assert_called_once_with("user@example.com","secret_pass")

    def test_smtp_authenticate_oauth2(self):
        mock_smtp=MagicMock()
        enc=self.server.encrypt_secret("ya29.access_token_123")
        profile={
            "username":"user@example.com",
            "oauth_token_enc":enc,
            "auth_method":"oauth2"
        }
        self.server.smtp_authenticate(mock_smtp,profile)
        mock_smtp.auth.assert_called_once()
        args,kwargs=mock_smtp.auth.call_args
        self.assertEqual(args[0],"XOAUTH2")
        auth_func=args[1]
        self.assertEqual(auth_func(),"\x00user@example.com\x00ya29.access_token_123")

    def test_smtp_authenticate_oauth2_missing_token_raises(self):
        mock_smtp=MagicMock()
        profile={
            "username":"user@example.com",
            "oauth_token_enc":"",
            "auth_method":"oauth2"
        }
        with self.assertRaises(RuntimeError):
            self.server.smtp_authenticate(mock_smtp,profile)

    def test_smtp_diagnostics_empty_host_fails_dns(self):
        profile={"host":"","port":587,"security":"STARTTLS"}
        results=self.server.smtp_diagnostics(profile)
        self.assertEqual(len(results),1)
        self.assertEqual(results[0]["stage"],"DNS")
        self.assertEqual(results[0]["status"],"FAIL")

    def test_smtp_delete_unused_profile(self):
        c=self.server.db()
        c.execute("""INSERT INTO smtp_profiles(name,provider,host,port,security,username,from_name,from_email,enabled,created_at,updated_at)
                     VALUES('To Delete','Custom SMTP','mail.test',587,'STARTTLS','u','N','u@test.com',1,?,?)""",
                  (self.server.now(),self.server.now()))
        pid=c.execute("SELECT id FROM smtp_profiles WHERE name='To Delete'").fetchone()["id"]
        c.commit(); c.close()

        # Execute deletion via Handler
        h=self.handler
        h.path="/admin/smtp/delete"
        h.client_address=("127.0.0.1",12345)
        h.auth=lambda: True
        h.headers={}
        h.rfile=MagicMock()
        h.rfile.read.return_value=f"id={pid}".encode()
        h.headers={"Content-Length":str(len(f"id={pid}"))}
        response_data=[]
        h.sendbody=lambda code,body,ctype="text/html",extra=None: response_data.append((code,body,extra))

        h.do_POST()
        self.assertEqual(len(response_data),1)
        self.assertEqual(response_data[0][0],302)
        self.assertEqual(response_data[0][2]["Location"],"/admin/smtp")

        c=self.server.db()
        remaining=c.execute("SELECT COUNT(*) n FROM smtp_profiles WHERE id=?",(pid,)).fetchone()["n"]
        c.close()
        self.assertEqual(remaining,0)

    def test_smtp_delete_blocked_when_in_use_by_campaign(self):
        c=self.server.db()
        c.execute("""INSERT INTO smtp_profiles(name,provider,host,port,security,username,from_name,from_email,enabled,created_at,updated_at)
                     VALUES('In Use Profile','Custom SMTP','mail.test',587,'STARTTLS','u','N','u@test.com',1,?,?)""",
                  (self.server.now(),self.server.now()))
        pid=c.execute("SELECT id FROM smtp_profiles WHERE name='In Use Profile'").fetchone()["id"]
        c.execute("""INSERT INTO campaigns(name,template,status,targeted,smtp_profile_id,created_at,updated_at)
                     VALUES('Active Camp',1,'Active',10,?,?,?)""",
                  (pid,self.server.now(),self.server.now()))
        c.commit(); c.close()

        h=self.handler
        h.path="/admin/smtp/delete"
        h.client_address=("127.0.0.1",12345)
        h.auth=lambda: True
        h.headers={"Content-Length":str(len(f"id={pid}"))}
        h.rfile=MagicMock()
        h.rfile.read.return_value=f"id={pid}".encode()
        response_data=[]
        h.sendbody=lambda code,body,ctype="text/html",extra=None: response_data.append((code,body,extra))

        h.do_POST()
        self.assertEqual(len(response_data),1)
        self.assertEqual(response_data[0][0],400)
        self.assertIn("Cannot Delete SMTP Provider",response_data[0][1])

        c=self.server.db()
        remaining=c.execute("SELECT COUNT(*) n FROM smtp_profiles WHERE id=?",(pid,)).fetchone()["n"]
        c.close()
        self.assertEqual(remaining,1)

    def test_smtp_save_create_and_update_with_enabled_flag(self):
        # 1. Create new profile
        payload="name=New+SES&provider=Amazon+SES&host=email-smtp.us-east-1.amazonaws.com&port=587&security=STARTTLS&username=ses_user&password=my_secret_pass&from_name=PhishGuard&from_email=notify@example.com&reply_to=support@example.com&auth_method=password&enabled=1"
        h=self.handler
        h.path="/admin/smtp/save"
        h.client_address=("127.0.0.1",12345)
        h.auth=lambda: True
        h.headers={"Content-Length":str(len(payload))}
        h.rfile=MagicMock()
        h.rfile.read.return_value=payload.encode()
        response_data=[]
        h.sendbody=lambda code,body,ctype="text/html",extra=None: response_data.append((code,body,extra))

        h.do_POST()
        self.assertEqual(len(response_data),1)
        self.assertEqual(response_data[0][0],302)
        self.assertEqual(response_data[0][2]["Location"],"/admin/smtp")

        c=self.server.db()
        row=c.execute("SELECT * FROM smtp_profiles WHERE name='New SES'").fetchone()
        c.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["enabled"],1)
        self.assertEqual(row["provider"],"Amazon SES")
        self.assertEqual(self.server.decrypt_secret(row["password_enc"]),"my_secret_pass")

        # 2. Update profile: disable it and retain password when password is empty
        pid=row["id"]
        update_payload=f"id={pid}&name=New+SES+Updated&provider=Amazon+SES&host=email-smtp.us-east-1.amazonaws.com&port=587&security=STARTTLS&username=ses_user_updated&password=&from_name=PhishGuard&from_email=notify@example.com&reply_to=support@example.com&auth_method=password&enabled=0"
        h.headers={"Content-Length":str(len(update_payload))}
        h.rfile.read.return_value=update_payload.encode()
        response_data.clear()

        h.do_POST()
        self.assertEqual(len(response_data),1)
        self.assertEqual(response_data[0][0],302)

        c=self.server.db()
        updated_row=c.execute("SELECT * FROM smtp_profiles WHERE id=?",(pid,)).fetchone()
        c.close()
        self.assertEqual(updated_row["name"],"New SES Updated")
        self.assertEqual(updated_row["username"],"ses_user_updated")
        self.assertEqual(updated_row["enabled"],0) # Verified enabled=0 works!
        # Secret is retained
        self.assertEqual(self.server.decrypt_secret(updated_row["password_enc"]),"my_secret_pass")

    def test_smtp_diagnostics_page_renders_with_sendbody(self):
        c=self.server.db()
        c.execute("INSERT INTO smtp_profiles(name,provider,host,port,security,from_name,from_email,enabled,created_at,updated_at) VALUES('Diag Test','Custom SMTP','mail.example.com',587,'STARTTLS','Test','test@example.com',1,?,?)",(self.server.now(),self.server.now()))
        pid=c.execute("SELECT id FROM smtp_profiles WHERE name='Diag Test'").fetchone()["id"]
        c.commit(); c.close()

        h=self.handler
        h.path=f"/admin/smtp/diagnostics?id={pid}"
        h.client_address=("127.0.0.1",12345)
        h.auth=lambda: True
        h.headers={}
        response_data=[]
        h.sendbody=lambda code,body,ctype="text/html",extra=None: response_data.append((code,body,extra))

        h.do_GET()
        self.assertEqual(len(response_data),1)
        self.assertEqual(response_data[0][0],200)
        self.assertIn("SMTP Connectivity Diagnostics",response_data[0][1])
        self.assertIn("Diag Test",response_data[0][1])

if __name__=="__main__":
    unittest.main()

