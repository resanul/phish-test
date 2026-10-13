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

class SSLTests(unittest.TestCase):
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
        self.handler.command = "GET"
        self.handler.headers = {}
        self.handler.connection = None

    def test_is_https_detection(self):
        # Default with no headers and no SSL
        orig_ssl = self.server.SSL_ENABLED
        try:
            self.server.SSL_ENABLED = False
            self.assertFalse(self.handler.is_https())

            # X-Forwarded-Proto
            self.handler.headers = {"X-Forwarded-Proto": "https"}
            self.assertTrue(self.handler.is_https())

            # X-Forwarded-Ssl
            self.handler.headers = {"X-Forwarded-Ssl": "on"}
            self.assertTrue(self.handler.is_https())

            # SSL_ENABLED flag
            self.handler.headers = {}
            self.server.SSL_ENABLED = True
            self.assertTrue(self.handler.is_https())
        finally:
            self.server.SSL_ENABLED = orig_ssl

    def test_get_public_base_url_with_https(self):
        orig_base = self.server.PUBLIC_BASE_URL
        orig_ssl = self.server.SSL_ENABLED
        try:
            self.server.PUBLIC_BASE_URL = ""
            self.server.SSL_ENABLED = False

            # Insecure HTTP
            url = self.server.get_public_base_url("phish.test:8899", is_secure=False)
            self.assertTrue(url.startswith("http://"))

            # Secure HTTPS
            url = self.server.get_public_base_url("phish.test:8899", is_secure=True)
            self.assertTrue(url.startswith("https://"))

            # Fallback 127.0.0.1 with SSL_ENABLED when no setting exists
            c = self.server.db()
            c.execute("DELETE FROM system_settings WHERE key='public_base_url'")
            c.commit()
            c.close()
            self.server.PUBLIC_BASE_URL = ""
            self.server.SSL_ENABLED = True
            url = self.server.get_public_base_url()
            self.assertTrue(url.startswith("https://127.0.0.1"))
        finally:
            self.server.PUBLIC_BASE_URL = orig_base
            self.server.SSL_ENABLED = orig_ssl

    def test_sendbody_includes_hsts_under_https(self):
        headers_sent = {}
        def mock_send_response(code):
            headers_sent["status"] = code
        def mock_send_header(k, v):
            headers_sent[k] = v
        def mock_end_headers():
            pass
        def mock_write(*args):
            pass

        self.handler.send_response = mock_send_response
        self.handler.send_header = mock_send_header
        self.handler.end_headers = mock_end_headers
        self.handler.wfile = type("WFile", (), {"write": staticmethod(mock_write)})()

        # Under HTTP: No HSTS
        self.handler.headers = {"X-Forwarded-Proto": "http"}
        orig_ssl = self.server.SSL_ENABLED
        try:
            self.server.SSL_ENABLED = False
            self.handler.sendbody(200, "hello")
            self.assertNotIn("Strict-Transport-Security", headers_sent)

            # Under HTTPS: HSTS header is present
            headers_sent.clear()
            self.handler.headers = {"X-Forwarded-Proto": "https"}
            self.handler.sendbody(200, "hello")
            self.assertIn("Strict-Transport-Security", headers_sent)
            self.assertIn("max-age=31536000", headers_sent["Strict-Transport-Security"])
        finally:
            self.server.SSL_ENABLED = orig_ssl

    def test_self_signed_cert_generation(self):
        cert_path = os.path.join(self.tmp.name, "test_cert.pem")
        key_path = os.path.join(self.tmp.name, "test_key.pem")

        out_cert, out_key = self.server.ensure_self_signed_cert(cert_path, key_path)
        self.assertTrue(os.path.exists(out_cert))
        self.assertTrue(os.path.exists(out_key))
        with open(out_cert, "r") as f:
            content = f.read()
            self.assertIn("BEGIN CERTIFICATE", content)
        with open(out_key, "r") as f:
            content = f.read()
            self.assertIn("PRIVATE KEY", content)

if __name__ == "__main__":
    unittest.main()
