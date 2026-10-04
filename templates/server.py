#!/usr/bin/env python3
import os
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("PORT", "8080"))
LOG_DIR = os.path.join(ROOT, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "access.log")

class SimulationHandler(SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        client = self.client_address[0]
        now = datetime.now(timezone.utc).isoformat()
        line = f"{now} ip={client} path={self.path} " + (fmt % args) + "\n"
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
        print(line, end="")

    def translate_path(self, path):
        clean = path.split("?", 1)[0].split("#", 1)[0]
        if clean == "/":
            clean = "/1.html"
        return os.path.join(ROOT, clean.lstrip("/"))

if __name__ == "__main__":
    os.chdir(ROOT)
    server = ThreadingHTTPServer(("0.0.0.0", PORT), SimulationHandler)
    print(f"Phishing simulation server listening on 0.0.0.0:{PORT}")
    print(f"Templates: {ROOT}")
    server.serve_forever()
