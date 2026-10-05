#!/usr/bin/env python3
import os, sqlite3, csv, io, secrets, html
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from http import cookies
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
BASE="/opt/phish-simulation"; TEMPLATES=BASE+"/templates"; DATA=BASE+"/data"; LOGS=BASE+"/logs"
DB=DATA+"/phish.db"; LOG=LOGS+"/access.log"; PORT=int(os.environ.get("PORT","8080"))
ADMIN_PASSWORD=os.environ.get("ADMIN_PASSWORD","CHANGE_ME"); SESSIONS=set()
os.makedirs(TEMPLATES,exist_ok=True); os.makedirs(DATA,exist_ok=True); os.makedirs(LOGS,exist_ok=True)
def db():
 c=sqlite3.connect(DB); c.row_factory=sqlite3.Row
 c.execute("CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT,ts TEXT NOT NULL,ip TEXT NOT NULL,template TEXT NOT NULL,event TEXT NOT NULL,name TEXT,email TEXT,mobile TEXT,user_agent TEXT,employee_id TEXT,card_type TEXT)")
 cols={row[1] for row in c.execute("PRAGMA table_info(events)").fetchall()}
 for col in ("employee_id","card_type"):
  if col not in cols:c.execute(f"ALTER TABLE events ADD COLUMN {col} TEXT")
 c.commit(); return c
def record(ip,t,event,name="",email="",mobile="",ua="",employee_id="",card_type=""):
 c=db(); c.execute("INSERT INTO events(ts,ip,template,event,name,email,mobile,user_agent,employee_id,card_type) VALUES(?,?,?,?,?,?,?,?,?,?)",(datetime.now(timezone.utc).isoformat(),ip,t,event,name,email,mobile,ua,employee_id,card_type)); c.commit(); c.close()
def format_datetime(ts):
 dt=datetime.fromisoformat(ts.replace("Z","+00:00")).astimezone(ZoneInfo("Asia/Dhaka"))
 return dt.strftime("%d-%b-%Y"),dt.strftime("%I:%M:%S %p")
def access(ip,path,code):
 with open(LOG,"a",encoding="utf-8") as f:f.write(f"{datetime.now(timezone.utc).isoformat()} ip={ip} path={path} code={code}\n")
def page(title,body):
 return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title><style>body{{font-family:Arial;background:#f3f4f6;margin:0;color:#111827}}.wrap{{max-width:1250px;margin:25px auto;padding:0 16px}}.card{{background:white;padding:20px;border-radius:10px;box-shadow:0 2px 10px #0001;margin-bottom:18px}}.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}.stat{{background:white;padding:18px;border-radius:10px}}.num{{font-size:28px;font-weight:bold}}table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{padding:9px;border-bottom:1px solid #ddd;text-align:left}}th{{background:#f9fafb}}a,button{{background:#111827;color:#fff;padding:9px 13px;border-radius:6px;text-decoration:none;border:0}}@media(max-width:800px){{.stats{{grid-template-columns:repeat(2,1fr)}}table{{font-size:11px}}}}</style></head><body><div class="wrap">{body}</div></body></html>"""
class Handler(BaseHTTPRequestHandler):
 def sendbody(self,code,body,ctype="text/html; charset=utf-8",extra=None):
  b=body.encode() if isinstance(body,str) else body; self.send_response(code); self.send_header("Content-Type",ctype); self.send_header("Content-Length",str(len(b)))
  if extra:
   for k,v in extra.items():self.send_header(k,v)
  self.end_headers()
  if self.command!="HEAD":self.wfile.write(b)
 def auth(self):
  c=cookies.SimpleCookie(self.headers.get("Cookie","")); s=c.get("admin_session"); return bool(s and s.value in SESSIONS)
 def do_HEAD(self):self.do_GET()
 def do_GET(self):
  p=urlparse(self.path); path=p.path; ip=self.client_address[0]; ua=self.headers.get("User-Agent","")
  if path=="/admin":
   if not self.auth():return self.sendbody(200,page("Admin Login",'<div class="card"><h1>Phishing Simulation Admin</h1><form method="post" action="/admin/login"><input type="password" name="password" placeholder="Admin password" required style="padding:10px;width:280px"><br><br><button>Login</button></form></div>'))
   c=db(); rows=c.execute("SELECT * FROM events ORDER BY id DESC LIMIT 500").fetchall(); clicks=c.execute("SELECT COUNT(*) n FROM events WHERE event='click'").fetchone()["n"]; subs=c.execute("SELECT COUNT(*) n FROM events WHERE event='submitted'").fetchone()["n"]; ips=c.execute("SELECT COUNT(DISTINCT ip) n FROM events").fetchone()["n"]; c.close()
   trs="".join((lambda d,t: f"<tr><td>{html.escape(d)}</td><td>{html.escape(t)}</td><td>{html.escape(r['event'])}</td><td>{html.escape(r['template'])}</td><td>{html.escape(r['ip'])}</td><td>{html.escape(r['name'] or '')}</td><td>{html.escape(r['employee_id'] or '')}</td><td>{html.escape(r['email'] or '')}</td><td>{html.escape(r['mobile'] or '')}</td><td>{html.escape(r['card_type'] or '')}</td></tr>")(*format_datetime(r['ts'])) for r in rows)
   body=f"""<h1>Phishing Simulation Admin</h1><div class="card"><a href="/admin.csv">Export CSV</a></div><div class="stats"><div class="stat">Clicks<div class="num">{clicks}</div></div><div class="stat">Submissions<div class="num">{subs}</div></div><div class="stat">Unique IPs<div class="num">{ips}</div></div><div class="stat">Records<div class="num">{len(rows)}</div></div></div><div class="card"><h2>Activity</h2><table><tr><th>Date</th><th>Time</th><th>Event</th><th>Template</th><th>Local IP</th><th>Name</th><th>Employee ID</th><th>Email</th><th>Mobile</th><th>Card Type</th></tr>{trs or '<tr><td colspan="10">No activity</td></tr>'}</table></div>"""
   return self.sendbody(200,page("Admin Dashboard",body))
  if path=="/admin.csv":
   if not self.auth():return self.sendbody(403,"Forbidden","text/plain")
   c=db(); rows=c.execute("SELECT ts,event,template,ip,name,email,mobile,user_agent FROM events ORDER BY id DESC").fetchall(); c.close(); out=io.StringIO(); w=csv.writer(out); w.writerow(["timestamp","event","template","local_ip","name","employee_id","email","mobile","card_type","user_agent"])
   for r in rows:w.writerow([r["ts"],r["event"],r["template"],r["ip"],r["name"] or "",r["employee_id"] or "",r["email"] or "",r["mobile"] or "",r["card_type"] or "",r["user_agent"] or ""])
   return self.sendbody(200,out.getvalue(),"text/csv",{"Content-Disposition":"attachment; filename=phish-simulation.csv"})
  if path.startswith("/") and path.endswith(".html") and path[1:-5].isdigit():
   t=path[1:]; fn=os.path.join(TEMPLATES,t)
   if os.path.isfile(fn):
    record(ip,t,"click",ua=ua); access(ip,path,200)
    with open(fn,"rb") as f:return self.sendbody(200,f.read())
  access(ip,path,404); return self.sendbody(404,"404 File not found","text/plain")
 def do_POST(self):
  p=urlparse(self.path); ip=self.client_address[0]; n=int(self.headers.get("Content-Length","0")); form=parse_qs(self.rfile.read(n).decode("utf-8","replace"))
  if p.path=="/admin/login":
   if secrets.compare_digest(form.get("password",[""])[0],ADMIN_PASSWORD):
    sid=secrets.token_urlsafe(32); SESSIONS.add(sid); ck=cookies.SimpleCookie(); ck["admin_session"]=sid; ck["admin_session"]["HttpOnly"]=True; ck["admin_session"]["SameSite"]="Strict"
    return self.sendbody(302,b"",extra={"Location":"/admin","Set-Cookie":ck["admin_session"].OutputString()})
   return self.sendbody(401,"Invalid password","text/plain")
  if p.path=="/submit":
   t=form.get("template",["unknown"])[0][:50]; name=form.get("name",[""])[0][:150]; employee_id=form.get("employee_id",[""])[0][:100]; email=form.get("email",[""])[0][:200]; mobile=form.get("mobile",[""])[0][:50]; card_type=form.get("card_type",[""])[0][:100]
   record(ip,t,"submitted",name,email,mobile,self.headers.get("User-Agent",""),employee_id,card_type); access(ip,p.path,200)
   return self.sendbody(200,page("Simulation Complete","<div class='card'><h1>Security Awareness Simulation</h1><p>Simulation complete. No password, OTP, PIN, CVV or card information was requested or stored.</p></div>"))
  return self.sendbody(404,"Not found","text/plain")
if __name__=="__main__":db().close(); ThreadingHTTPServer(("0.0.0.0",PORT),Handler).serve_forever()
