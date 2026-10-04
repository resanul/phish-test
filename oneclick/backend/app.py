import os, sqlite3
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template, abort
BASE=os.path.dirname(os.path.abspath(__file__))
DB=os.environ.get("PHISH_DB",os.path.join(BASE,"data","simulation.db"))
ADMIN_TOKEN=os.environ.get("ADMIN_TOKEN","CHANGE_ME")
app=Flask(__name__,template_folder="templates")
def init_db():
 os.makedirs(os.path.dirname(DB),exist_ok=True)
 with sqlite3.connect(DB) as c:
  c.execute("""CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT,event_type TEXT NOT NULL,campaign_id TEXT NOT NULL,name TEXT,email TEXT,ip_address TEXT NOT NULL,user_agent TEXT,created_at TEXT NOT NULL)""")
def client_ip(): return request.remote_addr or "unknown"
@app.get("/")
def index(): return render_template("apex_rewards.html")
@app.post("/api/event")
def event():
 d=request.get_json(silent=True) or {}
 forbidden={"password","passwd","pass","otp","pin","card","cvv","cvc"}
 if any(str(k).lower() in forbidden for k in d): return jsonify(error="credential/payment fields are not accepted"),400
 with sqlite3.connect(DB) as c:
  c.execute("INSERT INTO events(event_type,campaign_id,name,email,ip_address,user_agent,created_at) VALUES(?,?,?,?,?,?,?)",
   (str(d.get("event_type","click"))[:40],str(d.get("campaign_id","PHISH-APEX-001"))[:80],str(d.get("name","")).strip()[:160],str(d.get("email","")).strip()[:254],client_ip(),request.headers.get("User-Agent","")[:500],datetime.now(timezone.utc).isoformat()))
 return jsonify(ok=True)
@app.get("/admin/events")
def events():
 if request.headers.get("X-Admin-Token")!=ADMIN_TOKEN: abort(401)
 with sqlite3.connect(DB) as c:
  c.row_factory=sqlite3.Row
  rows=c.execute("SELECT * FROM events ORDER BY id DESC").fetchall()
 return jsonify([dict(x) for x in rows])
@app.get("/health")
def health(): return jsonify(status="ok")
init_db()
if __name__=="__main__": app.run(host=os.environ.get("HOST","127.0.0.1"),port=int(os.environ.get("PORT","8080")))