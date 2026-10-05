#!/usr/bin/env python3
import os, sqlite3, csv, io, secrets, html, smtplib, ssl, subprocess, tempfile, re
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from http import cookies
from datetime import datetime, timezone, timedelta
from email.message import EmailMessage
from email.utils import formataddr
from zoneinfo import ZoneInfo

BASE="/opt/phish-simulation"
TEMPLATES=BASE+"/templates"
DATA=BASE+"/data"
LOGS=BASE+"/logs"
DB=DATA+"/phish.db"
LOG=LOGS+"/access.log"
PORT=int(os.environ.get("PORT","8080"))
ADMIN_USERNAME=os.environ.get("ADMIN_USERNAME","admin")
ADMIN_PASSWORD=os.environ.get("ADMIN_PASSWORD","CHANGE_ME")
SESSIONS=set()
TZ=ZoneInfo("Asia/Dhaka")
SMTP_KEY=DATA+"/.smtp_master_key"
SMTP_PROVIDERS={
    "Gmail":{"host":"smtp.gmail.com","port":587,"security":"STARTTLS"},
    "Google Workspace Relay":{"host":"smtp-relay.gmail.com","port":587,"security":"STARTTLS"},
    "Zoho":{"host":"smtp.zoho.com","port":587,"security":"STARTTLS"},
    "Microsoft 365":{"host":"smtp.office365.com","port":587,"security":"STARTTLS"},
    "Amazon SES":{"host":"email-smtp.us-east-1.amazonaws.com","port":587,"security":"STARTTLS"},
    "SendGrid":{"host":"smtp.sendgrid.net","port":587,"security":"STARTTLS"},
    "Mailgun":{"host":"smtp.mailgun.org","port":587,"security":"STARTTLS"},
    "Custom SMTP":{"host":"","port":587,"security":"STARTTLS"}
}

def now():
    return datetime.now(timezone.utc).isoformat()

os.makedirs(TEMPLATES,exist_ok=True)
os.makedirs(DATA,exist_ok=True)
os.makedirs(LOGS,exist_ok=True)

def db():
    c=sqlite3.connect(DB)
    c.row_factory=sqlite3.Row
    c.execute("""CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL, ip TEXT NOT NULL, template TEXT NOT NULL,
        event TEXT NOT NULL, name TEXT, email TEXT, mobile TEXT,
        user_agent TEXT, employee_id TEXT, card_type TEXT)""")
    cols={row[1] for row in c.execute("PRAGMA table_info(events)").fetchall()}
    for col in ("employee_id","card_type"):
        if col not in cols:
            c.execute(f"ALTER TABLE events ADD COLUMN {col} TEXT")
    c.executescript("""
    CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, created_at TEXT);
    CREATE TABLE IF NOT EXISTS campaigns(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,template TEXT,status TEXT NOT NULL DEFAULT 'Draft',targeted INTEGER DEFAULT 0,created_at TEXT,updated_at TEXT);
    CREATE TABLE IF NOT EXISTS recipients(id INTEGER PRIMARY KEY AUTOINCREMENT,campaign_id INTEGER,email TEXT,name TEXT,employee_id TEXT,department TEXT,group_name TEXT,status TEXT DEFAULT 'Pending',created_at TEXT);
    CREATE TABLE IF NOT EXISTS groups_tbl(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT UNIQUE,department TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS landing_pages(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT UNIQUE,template TEXT,status TEXT DEFAULT 'Enabled',created_at TEXT);
    CREATE TABLE IF NOT EXISTS risk_scores(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE,score REAL DEFAULT 0,level TEXT DEFAULT 'Low',failures INTEGER DEFAULT 0,last_event TEXT,updated_at TEXT);
    CREATE TABLE IF NOT EXISTS training_records(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE,completion REAL DEFAULT 0,course TEXT,updated_at TEXT);
    CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY AUTOINCREMENT,ts TEXT,admin TEXT,action TEXT,details TEXT,ip TEXT);
    CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT);
    CREATE TABLE IF NOT EXISTS smtp_profiles(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        provider TEXT NOT NULL DEFAULT 'Custom SMTP',
        host TEXT NOT NULL,
        port INTEGER NOT NULL DEFAULT 587,
        security TEXT NOT NULL DEFAULT 'STARTTLS',
        username TEXT,
        password_enc TEXT,
        from_name TEXT,
        from_email TEXT NOT NULL,
        reply_to TEXT,
        enabled INTEGER DEFAULT 1,
        created_at TEXT,
        updated_at TEXT
    );
    """)
    if not c.execute("SELECT 1 FROM admins WHERE username=?",(ADMIN_USERNAME,)).fetchone():
        c.execute("INSERT INTO admins(username,created_at) VALUES(?,?)",(ADMIN_USERNAME,datetime.now(timezone.utc).isoformat()))
    for i in range(1,11):
        c.execute("INSERT OR IGNORE INTO landing_pages(name,template,status,created_at) VALUES(?,?,?,?)",(f"Landing Page {i}",str(i),"Enabled",datetime.now(timezone.utc).isoformat()))
    c.commit()
    return c

def record(ip,t,event,name="",email="",mobile="",ua="",employee_id="",card_type=""):
    c=db()
    c.execute(
        "INSERT INTO events(ts,ip,template,event,name,email,mobile,user_agent,employee_id,card_type) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (datetime.now(timezone.utc).isoformat(),ip,t,event,name,email,mobile,ua,employee_id,card_type))
    c.commit()
    if email:
        row=c.execute("SELECT * FROM risk_scores WHERE email=?",(email,)).fetchone()
        failures=(row["failures"] if row else 0)+(1 if event in ("click","submitted") else 0)
        score=min(100,failures*20); level="High" if score>=70 else ("Medium" if score>=40 else "Low")
        c.execute("""INSERT INTO risk_scores(email,score,level,failures,last_event,updated_at) VALUES(?,?,?,?,?,?)
        ON CONFLICT(email) DO UPDATE SET score=excluded.score,level=excluded.level,failures=excluded.failures,last_event=excluded.last_event,updated_at=excluded.updated_at""",(email,score,level,failures,event,now()))
        c.commit()
    c.close()

def ensure_smtp_key():
    os.makedirs(DATA,exist_ok=True)
    if not os.path.exists(SMTP_KEY):
        subprocess.run(["openssl","rand","-base64","48"],check=True,stdout=open(SMTP_KEY,"w"),stderr=subprocess.DEVNULL)
        os.chmod(SMTP_KEY,0o600)
    else:
        os.chmod(SMTP_KEY,0o600)
    return SMTP_KEY

def encrypt_secret(value):
    if not value:
        return ""
    key=ensure_smtp_key()
    p=subprocess.run(
        ["openssl","enc","-aes-256-cbc","-pbkdf2","-salt","-a","-A","-pass",f"file:{key}"],
        input=value.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
    return p.stdout.decode().strip()

def decrypt_secret(value):
    if not value:
        return ""
    key=ensure_smtp_key()
    p=subprocess.run(
        ["openssl","enc","-d","-aes-256-cbc","-pbkdf2","-a","-A","-pass",f"file:{key}"],
        input=value.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
    return p.stdout.decode()

def smtp_send_test(profile,to_email):
    host=profile["host"]; port=int(profile["port"]); security=profile["security"]
    msg=EmailMessage()
    msg["From"]=formataddr((profile["from_name"] or "Trust PhishGuard",profile["from_email"]))
    msg["To"]=to_email
    msg["Subject"]="Trust PhishGuard SMTP test"
    msg.set_content("This is an SMTP connectivity test from Trust PhishGuard. No credentials are requested or collected.")
    if security=="SSL/TLS":
        with smtplib.SMTP_SSL(host,port,context=ssl.create_default_context(),timeout=15) as smtp:
            if profile["username"]: smtp.login(profile["username"],decrypt_secret(profile["password_enc"]))
            smtp.send_message(msg)
    else:
        with smtplib.SMTP(host,port,timeout=15) as smtp:
            smtp.ehlo()
            if security=="STARTTLS":
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
            if profile["username"]: smtp.login(profile["username"],decrypt_secret(profile["password_enc"]))
            smtp.send_message(msg)

def audit(admin,action,details,ip):
    c=db()
    c.execute("INSERT INTO audit_logs(ts,admin,action,details,ip) VALUES(?,?,?,?,?)",(now(),admin,action,details,ip))
    c.commit(); c.close()

def format_datetime(ts):
    dt=datetime.fromisoformat(ts.replace("Z","+00:00")).astimezone(TZ)
    return dt.strftime("%d-%b-%Y"),dt.strftime("%I:%M:%S %p")

def access(ip,path,code):
    with open(LOG,"a",encoding="utf-8") as f:
        f.write(f"{datetime.now(timezone.utc).isoformat()} ip={ip} path={path} code={code}\n")

def esc(v):
    return html.escape("" if v is None else str(v), quote=True)

def page(title,body,css=""):
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} · Trust PhishGuard</title>
<style>
*{{box-sizing:border-box}}body{{margin:0;background:#f4f7f6;color:#12231d;font-family:Inter,Segoe UI,Arial,sans-serif}}
a{{color:inherit}}button,input,select{{font:inherit}}
{css}
</style></head><body>{body}</body></html>"""

LOGIN_CSS="""
.login-shell{min-height:100vh;display:grid;grid-template-columns:1.05fr .95fr;background:#071b15}
.login-left{padding:56px 7vw;color:#fff;display:flex;flex-direction:column;justify-content:center;background:linear-gradient(145deg,#071b15,#0d3b2c)}
.brand{display:flex;gap:13px;align-items:center;font-weight:800;font-size:24px}.brand-mark{width:42px;height:42px;border-radius:12px;background:#20b486;display:grid;place-items:center;color:#062218;font-weight:900}
.login-left h1{font-size:clamp(36px,5vw,62px);line-height:1.02;margin:55px 0 20px;letter-spacing:-2px}.login-left p{max-width:570px;color:#b8d1c8;font-size:17px;line-height:1.7}.feature-row{display:flex;gap:10px;flex-wrap:wrap;margin-top:34px}.feature{border:1px solid #2b5c4d;background:#0e3027;border-radius:999px;padding:9px 13px;font-size:12px;color:#d7ebe4}
.login-right{background:#f7faf9;display:grid;place-items:center;padding:30px}.login-card{width:min(440px,100%);background:#fff;border:1px solid #dce7e2;border-radius:24px;padding:38px;box-shadow:0 24px 70px #00140d18}.login-card h2{margin:0 0 7px;font-size:28px}.muted{color:#71817b;font-size:14px}.field{margin-top:20px}.field label{display:block;font-size:13px;font-weight:700;margin-bottom:8px}.field input{width:100%;padding:13px 14px;border:1px solid #ccd9d4;border-radius:10px;outline:none}.field input:focus{border-color:#15966f;box-shadow:0 0 0 3px #15966f18}.login-btn{width:100%;border:0;border-radius:10px;padding:14px;background:#087b59;color:#fff;font-weight:800;cursor:pointer;margin-top:24px}.notice{margin-top:22px;padding:12px 14px;border-radius:10px;background:#edf8f4;color:#2b6554;font-size:12px;line-height:1.5}.trust{margin-top:25px;text-align:center;color:#84938e;font-size:12px}
@media(max-width:850px){.login-shell{grid-template-columns:1fr}.login-left{padding:35px}.login-left h1{margin:35px 0 15px}.login-right{padding:25px}}
"""

DASH_CSS="""
.topbar{height:72px;background:#071b15;color:#fff;display:flex;align-items:center;justify-content:space-between;padding:0 30px}.topbrand{display:flex;align-items:center;gap:11px;font-weight:800}.mark{width:35px;height:35px;border-radius:10px;background:#20b486;color:#062218;display:grid;place-items:center;font-weight:900}.top-actions{display:flex;gap:9px;align-items:center}.top-actions a{padding:8px 12px;border:1px solid #31564b;border-radius:8px;text-decoration:none;font-size:12px}
.wrap{max-width:1440px;margin:auto;padding:28px}.hero{display:flex;justify-content:space-between;align-items:flex-end;margin-bottom:22px}.hero h1{margin:0;font-size:29px;letter-spacing:-.7px}.hero p{margin:7px 0 0;color:#71817b;font-size:13px}.export{background:#087b59;color:#fff;text-decoration:none;padding:10px 14px;border-radius:9px;font-size:13px;font-weight:700}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.stat{background:#fff;border:1px solid #e0e9e5;border-radius:15px;padding:19px}.stat-label{font-size:12px;color:#71817b;font-weight:700}.num{font-size:30px;font-weight:800;margin-top:8px}.delta{font-size:11px;color:#087b59;margin-top:7px}.grid{display:grid;grid-template-columns:1.35fr .65fr;gap:15px;margin-top:15px}.card{background:#fff;border:1px solid #e0e9e5;border-radius:15px;padding:19px}.card h3{margin:0;font-size:15px}.sub{color:#81908b;font-size:11px;margin-top:5px}.bars{margin-top:20px;display:grid;gap:13px}.bar-row{display:grid;grid-template-columns:105px 1fr 45px;gap:10px;align-items:center;font-size:12px}.bar{height:9px;background:#edf2f0;border-radius:20px;overflow:hidden}.bar>i{display:block;height:100%;background:#149b73;border-radius:20px}.trend{height:185px;display:flex;align-items:end;gap:8px;margin-top:20px;padding:0 3px}.day{flex:1;display:flex;flex-direction:column;justify-content:end;align-items:center;height:100%;gap:7px}.daybar{width:100%;max-width:42px;background:#159b73;border-radius:6px 6px 2px 2px;min-height:3px}.day small{font-size:10px;color:#82908b}.day b{font-size:10px;color:#53645d}.activity{margin-top:15px}.table-wrap{overflow:auto;margin-top:15px}.table{width:100%;border-collapse:collapse;font-size:12px;min-width:850px}.table th{background:#f7faf8;text-align:left;color:#667770;font-size:11px}.table th,.table td{padding:11px 9px;border-bottom:1px solid #edf1ef;white-space:nowrap}.pill{display:inline-block;padding:4px 8px;border-radius:999px;font-size:10px;font-weight:800}.click{background:#eaf6f1;color:#087b59}.submitted{background:#e9f0ff;color:#345ca8}.filter{display:flex;gap:8px;align-items:center;margin-top:14px}.filter input{border:1px solid #d3dfda;border-radius:8px;padding:8px 10px;font-size:12px}.filter button{border:0;background:#e9f1ee;padding:8px 11px;border-radius:8px;cursor:pointer;font-size:12px}
@media(max-width:900px){.stats{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}.hero{align-items:flex-start;gap:15px;flex-direction:column}}@media(max-width:520px){.wrap{padding:18px}.stats{grid-template-columns:1fr 1fr}.topbar{padding:0 16px}.top-actions span{display:none}}
"""

class Handler(BaseHTTPRequestHandler):
    def sendbody(self,code,body,ctype="text/html; charset=utf-8",extra=None):
        b=body.encode() if isinstance(body,str) else body
        self.send_response(code)
        self.send_header("Content-Type",ctype)
        self.send_header("Content-Length",str(len(b)))
        if extra:
            for k,v in extra.items(): self.send_header(k,v)
        self.end_headers()
        if self.command!="HEAD": self.wfile.write(b)

    def auth(self):
        c=cookies.SimpleCookie(self.headers.get("Cookie",""))
        s=c.get("admin_session")
        return bool(s and s.value in SESSIONS)

    def login_page(self,error=""):
        err=f'<div style="margin-top:14px;color:#a12d2d;font-size:13px">{esc(error)}</div>' if error else ""
        body=f"""<div class="login-shell"><section class="login-left">
<div class="brand"><div class="brand-mark">✓</div><div>Trust PhishGuard</div></div>
<h1>Security awareness, measured.</h1>
<p>Centralized phishing simulation monitoring for campaign activity, user engagement and security-awareness outcomes.</p>
<div class="feature-row"><span class="feature">Campaign Management</span><span class="feature">Risk Analytics</span><span class="feature">Live Activity</span><span class="feature">Executive Reports</span></div>
</section><section class="login-right"><div class="login-card">
<h2>Admin Sign In</h2><div class="muted">Sign in to the Trust PhishGuard control center.</div>
{err}<form method="post" action="/admin/login">
<div class="field"><label>Admin Username</label><input name="username" autocomplete="username" placeholder="Enter username" required></div>
<div class="field"><label>Password</label><input type="password" name="password" autocomplete="current-password" placeholder="Enter password" required></div>
<button class="login-btn">Sign in securely</button></form>
<div class="notice">Protected admin area · Simulation telemetry only. No password, OTP, PIN, CVV or full card-number data is requested or stored.</div>
<div class="trust">Trust Bank PLC · Information Security</div>
</div></section></div>"""
        return page("Admin Sign In",body,LOGIN_CSS)

    def dashboard(self):
        c=db()
        total=c.execute("SELECT COUNT(*) n FROM events").fetchone()["n"]
        clicks=c.execute("SELECT COUNT(*) n FROM events WHERE event='click'").fetchone()["n"]
        subs=c.execute("SELECT COUNT(*) n FROM events WHERE event='submitted'").fetchone()["n"]
        ips=c.execute("SELECT COUNT(DISTINCT ip) n FROM events").fetchone()["n"]
        templates=c.execute("SELECT template, COUNT(*) n FROM events GROUP BY template ORDER BY n DESC").fetchall()
        recent=c.execute("SELECT * FROM events ORDER BY id DESC LIMIT 80").fetchall()
        since=(datetime.now(timezone.utc)-timedelta(days=6)).isoformat()
        trend=c.execute("SELECT substr(ts,1,10) d, COUNT(*) n FROM events WHERE ts>=? GROUP BY d ORDER BY d", (since,)).fetchall()
        c.close()

        rate=(subs/clicks*100) if clicks else 0
        max_t=max([r["n"] for r in templates],default=1)
        bars="".join(f'<div class="bar-row"><span>Template {esc(r["template"])}</span><div class="bar"><i style="width:{r["n"]/max_t*100:.0f}%"></i></div><b>{r["n"]}</b></div>' for r in templates[:8]) or '<div class="sub">No template activity yet.</div>'

        byday={r["d"]:r["n"] for r in trend}
        days=[]
        now=datetime.now(timezone.utc)
        for i in range(6,-1,-1):
            d=(now-timedelta(days=i)).date().isoformat()
            days.append((d,byday.get(d,0)))
        max_d=max([x[1] for x in days],default=1)
        trend_html="".join(f'<div class="day"><b>{n}</b><div class="daybar" style="height:{max(3,n/max_d*135):.0f}px"></div><small>{d[5:]}</small></div>' for d,n in days)

        rows=[]
        for r in recent:
            d,t=format_datetime(r["ts"])
            rows.append(f'<tr><td>{esc(d)}</td><td>{esc(t)}</td><td><span class="pill {esc(r["event"])}">{esc(r["event"])}</span></td><td>{esc(r["template"])}</td><td>{esc(r["ip"])}</td><td>{esc(r["name"])}</td><td>{esc(r["email"])}</td><td>{esc(r["mobile"])}</td></tr>')
        table="".join(rows) or '<tr><td colspan="8">No activity yet.</td></tr>'

        body=f"""<header class="topbar"><div class="topbrand"><div class="mark">✓</div>Trust PhishGuard</div><div class="top-actions"><span style="font-size:11px;color:#b8d1c8">ADMIN CONTROL CENTER</span><a href="/admin.csv">Export CSV</a><a href="/admin/logout">Logout</a></div></header>
<main class="wrap"><div class="hero"><div><h1>Security Awareness Dashboard</h1><p>Simulation telemetry and engagement overview · Asia/Dhaka</p></div></div>
<section class="stats"><div class="stat"><div class="stat-label">TOTAL EVENTS</div><div class="num">{total}</div><div class="delta">All recorded activity</div></div><div class="stat"><div class="stat-label">CLICKS</div><div class="num">{clicks}</div><div class="delta">Simulation page visits</div></div><div class="stat"><div class="stat-label">SUBMISSIONS</div><div class="num">{subs}</div><div class="delta">Form actions recorded</div></div><div class="stat"><div class="stat-label">ACTION RATE</div><div class="num">{rate:.1f}%</div><div class="delta">{ips} unique source IPs</div></div></section>
<section class="grid"><div class="card"><h3>7-Day Activity</h3><div class="sub">Recorded simulation events by UTC day</div><div class="trend">{trend_html}</div></div><div class="card"><h3>Template Performance</h3><div class="sub">Total events by template</div><div class="bars">{bars}</div></div></section>
<section class="card activity"><h3>Recent Activity</h3><div class="sub">Latest simulation events · dates and times shown in Bangladesh Standard Time</div><div class="filter"><input id="q" oninput="filterRows()" placeholder="Filter IP, template, email..."><button onclick="document.getElementById('q').value='';filterRows()">Clear</button></div><div class="table-wrap"><table class="table"><thead><tr><th>Date</th><th>Time</th><th>Event</th><th>Template</th><th>Source IP</th><th>Name</th><th>Email</th><th>Mobile</th></tr></thead><tbody id="rows">{table}</tbody></table></div></section></main>
<script>
function filterRows(){{const q=document.getElementById('q').value.toLowerCase();document.querySelectorAll('#rows tr').forEach(r=>r.style.display=r.innerText.toLowerCase().includes(q)?'':'none')}}
</script>"""
        dashboard_main=body[body.index("<main"):body.rindex("</main>")+7]
        return self.admin_shell("Overview",dashboard_main,"Overview")

    def admin_shell(self,title,content,active):
        nav=[("Overview","/admin"),("Campaigns","/admin/campaigns"),("Templates","/admin/templates"),("Landing Pages","/admin/landing-pages"),("SMTP Providers","/admin/smtp"),("Users & Groups","/admin/users"),("Reports","/admin/reports"),("Risk & Trends","/admin/risk"),("Exports","/admin/exports"),("Settings","/admin/settings"),("Audit Log","/admin/audit")]
        links="".join('<a href="%s" class="%s">%s</a>'%(u,"active" if n==active else "",n) for n,u in nav)
        css=DASH_CSS+".layout{display:grid;grid-template-columns:220px 1fr;min-height:calc(100vh - 68px)}.side{background:#0b241c;color:#b8d1c8;padding:16px}.side a{display:block;padding:9px;border-radius:8px;text-decoration:none;font-size:12px;margin:2px 0}.side a:hover,.side a.active{background:#164536;color:#fff}.main{padding:26px;max-width:1500px}.card{background:#fff;border:1px solid #e0e9e5;border-radius:14px;padding:18px}.table{width:100%;border-collapse:collapse;font-size:12px}.table th,.table td{padding:10px;border-bottom:1px solid #edf1ef;text-align:left}.table th{background:#f7faf8}.btn{display:inline-block;padding:9px 12px;border-radius:8px;border:1px solid #d5e0dc;text-decoration:none;font-size:12px;font-weight:700}.primary{background:#087b59;color:#fff}.form{display:grid;gap:12px;max-width:700px}.form input,.form select{padding:10px;border:1px solid #ccd9d4;border-radius:8px}.pill{padding:4px 8px;border-radius:999px;background:#eaf6f1;color:#087b59;font-size:10px;font-weight:800}@media(max-width:800px){.layout{grid-template-columns:1fr}.side{display:flex;overflow:auto}.side a{white-space:nowrap}}";
        body='<header style="height:68px;background:#071b15;color:#fff;display:flex;align-items:center;justify-content:space-between;padding:0 25px"><b>✓ Trust PhishGuard</b><span><a style="color:#fff;margin-right:15px" href="/admin.csv">CSV</a><a style="color:#fff" href="/admin/logout">Logout</a></span></header><div class="layout"><aside class="side">'+links+'</aside><main class="main">'+content+'</main></div>';
        return page(title,body,css)

    def feature_page(self,path):
        c=db()
        if path=="/admin/campaigns":
            rows=c.execute("SELECT * FROM campaigns ORDER BY id DESC").fetchall(); c.close()
            table="".join('<tr><td>%s</td><td>%s</td><td>Template %s</td><td>%s</td><td><span class="pill">%s</span></td><td><a class="btn" href="/admin/campaigns?id=%s">Edit</a></td></tr>'%(r["id"],esc(r["name"]),esc(r["template"]),r["targeted"],esc(r["status"]),r["id"]) for r in rows) or '<tr><td colspan="6">No campaigns yet.</td></tr>'
            return self.admin_shell("Campaigns",'<h1>Campaigns</h1><p>Create, pause and complete simulation campaigns.</p><p><a class="btn primary" href="/admin/campaigns/new">+ New Campaign</a></p><div class="card"><table class="table"><tr><th>ID</th><th>Name</th><th>Template</th><th>Targeted</th><th>Status</th><th></th></tr>'+table+'</table></div>',"Campaigns")
        if path=="/admin/templates":
            files=sorted([x for x in os.listdir(TEMPLATES) if x.endswith(".html") and x[:-5].isdigit()],key=lambda x:int(x[:-5])); c.close()
            table="".join('<tr><td>%s</td><td><span class="pill">Enabled</span></td><td><a class="btn" target="_blank" href="/%s">Preview</a></td></tr>'%(x[:-5],x) for x in files)
            return self.admin_shell("Templates",'<h1>Templates</h1><p>Existing simulation templates.</p><div class="card"><table class="table"><tr><th>Template</th><th>Status</th><th>Preview</th></tr>'+table+'</table></div>',"Templates")
        if path=="/admin/landing-pages":
            rows=c.execute("SELECT * FROM landing_pages ORDER BY id").fetchall(); c.close()
            table="".join('<tr><td>%s</td><td>%s</td><td>%s</td><td><a class="btn" target="_blank" href="/%s.html">Preview</a></td></tr>'%(r["id"],esc(r["name"]),esc(r["status"]),esc(r["template"])) for r in rows)
            return self.admin_shell("Landing Pages",'<h1>Landing Pages</h1><p>Template-to-landing-page mapping.</p><div class="card"><table class="table"><tr><th>ID</th><th>Name</th><th>Status</th><th></th></tr>'+table+'</table></div>',"Landing Pages")
        if path=="/admin/smtp":
            rows=c.execute("SELECT id,name,provider,host,port,security,username,from_name,from_email,reply_to,enabled,updated_at FROM smtp_profiles ORDER BY id DESC").fetchall(); c.close()
            table="".join('<tr><td>%s</td><td>%s</td><td>%s:%s</td><td>%s</td><td>%s</td><td><span class="pill">%s</span></td><td><a class="btn" href="/admin/smtp?id=%s">Edit</a></td></tr>'%(r["id"],esc(r["name"]),esc(r["host"]),r["port"],esc(r["security"]),esc(r["from_email"]),"Enabled" if r["enabled"] else "Disabled",r["id"]) for r in rows) or '<tr><td colspan="7">No SMTP profiles configured.</td></tr>'
            note='<div style="margin:12px 0;padding:12px;background:#edf8f4;border-radius:9px;font-size:12px;color:#2b6554">SMTP passwords are encrypted at rest with a server-local 0600 key. They are never displayed, exported or committed to Git.</div>'
            return self.admin_shell("SMTP Providers",'<h1>SMTP Providers</h1><p>Enterprise mail-delivery profiles for simulation campaigns and test messages.</p>'+note+'<p><a class="btn primary" href="/admin/smtp/new">+ Add SMTP Provider</a></p><div class="card"><table class="table"><tr><th>ID</th><th>Name</th><th>Server</th><th>Security</th><th>From</th><th>Status</th><th></th></tr>'+table+'</table></div>',"SMTP Providers")
        if path=="/admin/users":
            rows=c.execute("SELECT email,MAX(name) name,MAX(employee_id) employee_id,COUNT(*) events,SUM(event='click') clicks,SUM(event='submitted') submissions FROM events WHERE email!='' GROUP BY email ORDER BY events DESC").fetchall(); c.close()
            table="".join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>'%(esc(r["email"]),esc(r["name"]),esc(r["employee_id"]),r["events"],r["clicks"] or 0,r["submissions"] or 0) for r in rows) or '<tr><td colspan="6">No users recorded yet.</td></tr>'
            return self.admin_shell("Users",'<h1>Users & Groups</h1><p>Observed simulation users and engagement.</p><div class="card"><table class="table"><tr><th>Email</th><th>Name</th><th>Employee ID</th><th>Events</th><th>Clicks</th><th>Submissions</th></tr>'+table+'</table></div>',"Users & Groups")
        if path=="/admin/risk":
            rows=c.execute("SELECT * FROM risk_scores ORDER BY score DESC").fetchall(); c.close()
            table="".join('<tr><td>%s</td><td>%s</td><td>%.0f</td><td><span class="pill">%s</span></td></tr>'%(esc(r["email"]),r["failures"],r["score"],r["level"]) for r in rows) or '<tr><td colspan="4">No risk data yet.</td></tr>'
            return self.admin_shell("Risk",'<h1>Risk & Trends</h1><p>Heuristic user risk from observed simulation events.</p><div class="card"><table class="table"><tr><th>User</th><th>Failures</th><th>Score</th><th>Risk</th></tr>'+table+'</table></div>',"Risk & Trends")
        if path=="/admin/audit":
            rows=c.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200").fetchall(); c.close()
            table="".join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>'%(esc(format_datetime(r["ts"])[0]),esc(format_datetime(r["ts"])[1]),esc(r["action"]),esc(r["details"])) for r in rows) or '<tr><td colspan="4">No audit records.</td></tr>'
            return self.admin_shell("Audit",'<h1>Audit Log</h1><p>Administrative actions and exports.</p><div class="card"><table class="table"><tr><th>Date</th><th>Time</th><th>Action</th><th>Details</th></tr>'+table+'</table></div>',"Audit Log")
        if path in ("/admin/reports","/admin/exports"):
            total=c.execute("SELECT COUNT(*) n FROM events").fetchone()["n"]; clicks=c.execute("SELECT COUNT(*) n FROM events WHERE event='click'").fetchone()["n"]; subs=c.execute("SELECT COUNT(*) n FROM events WHERE event='submitted'").fetchone()["n"]; c.close(); rate=subs/clicks*100 if clicks else 0
            title="Reports" if path.endswith("reports") else "Exports"; return self.admin_shell(title,'<h1>'+title+'</h1><p>Measured telemetry only; no fabricated phishing/report rates.</p><div class="card"><h3>Total events: %s</h3><p>Clicks: %s · Submissions: %s · Action rate: %.1f%%</p><a class="btn primary" href="/admin.csv">Export CSV</a></div>'%(total,clicks,subs,rate),title)
        if path=="/admin/settings":
            c.close(); return self.admin_shell("Settings",'<h1>Settings</h1><div class="card"><p>Admin credentials are environment variables. Database: SQLite. Timezone: Asia/Dhaka.</p><p>Simulation policy: never request or store passwords, OTPs, PINs, CVV or full card numbers.</p></div>',"Settings")
        c.close(); return None

    def smtp_form(self,sid=None):
        c=db(); r=c.execute("SELECT * FROM smtp_profiles WHERE id=?",(sid,)).fetchone() if sid else None; c.close()
        provider=esc(r["provider"]) if r else "Gmail"; preset=SMTP_PROVIDERS.get(provider,SMTP_PROVIDERS["Custom SMTP"])
        host=esc(r["host"]) if r else esc(preset["host"]); port=esc(r["port"]) if r else str(preset["port"]); security=esc(r["security"]) if r else preset["security"]
        name=esc(r["name"]) if r else ""; username=esc(r["username"]) if r else ""; from_name=esc(r["from_name"]) if r else ""; from_email=esc(r["from_email"]) if r else ""; reply_to=esc(r["reply_to"]) if r else ""
        opts="".join('<option value="%s" %s>%s</option>'%(esc(k),"selected" if k==provider else "",esc(k)) for k in SMTP_PROVIDERS)
        secs="".join('<option value="%s" %s>%s</option>'%(x,"selected" if x==security else "",x) for x in ("STARTTLS","SSL/TLS","NONE"))
        return self.admin_shell("SMTP Provider",'<h1>%s SMTP Provider</h1><div class="card"><form class="form" method="post" action="/admin/smtp/save"><input type="hidden" name="id" value="%s"><label>Profile Name<input name="name" value="%s" required></label><label>Provider<select id="provider" name="provider" onchange="presetProvider()">%s</select></label><label>SMTP Host<input id="host" name="host" value="%s" required></label><label>Port<input id="port" type="number" min="1" max="65535" name="port" value="%s" required></label><label>Security<select id="security" name="security">%s</select></label><label>Username / SMTP account<input name="username" value="%s" autocomplete="username"></label><label>Password<input type="password" name="password" value="" autocomplete="new-password" placeholder="%s"></label><label>From Name<input name="from_name" value="%s"></label><label>From Email<input type="email" name="from_email" value="%s" required></label><label>Reply-To<input type="email" name="reply_to" value="%s"></label><div style="padding:12px;background:#f4f7f6;border-radius:8px;font-size:12px;color:#60716a">Password is write-only. Leave it blank when editing to keep the existing encrypted secret.</div><button class="btn primary">Save Provider</button></form></div><script>const presets=%s;function presetProvider(){const p=presets[document.getElementById("provider").value];if(p){document.getElementById("host").value=p.host;document.getElementById("port").value=p.port;document.getElementById("security").value=p.security}}</script>'%( "Edit" if r else "Add",sid or "",name,opts,host,port,secs,username,"unchanged" if r else "enter SMTP password",from_name,from_email,reply_to,html.escape(str(SMTP_PROVIDERS).replace("'",'"'))),"SMTP Providers")
    def campaign_form(self,cid=None):
        c=db(); r=c.execute("SELECT * FROM campaigns WHERE id=?",(cid,)).fetchone() if cid else None; c.close()
        name=esc(r["name"]) if r else ""; template=esc(r["template"]) if r else "1"; status=esc(r["status"]) if r else "Draft"
        opts="".join('<option value="%s" %s>Template %s</option>'%(i,"selected" if str(i)==template else "",i) for i in range(1,11))
        stats="".join('<option %s>%s</option>'%("selected" if x==status else "",x) for x in ("Draft","Active","Paused","Completed"))
        return self.admin_shell("Campaign",'<h1>%s Campaign</h1><div class="card"><form class="form" method="post" action="/admin/campaigns/save"><input type="hidden" name="id" value="%s"><label>Name<input name="name" value="%s" required></label><label>Template<select name="template">%s</select></label><label>Status<select name="status">%s</select></label><button class="btn primary">Save Campaign</button></form></div>'%("Edit" if r else "New",cid or "",name,opts,stats),"Campaigns")

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        p=urlparse(self.path); path=p.path; ip=self.client_address[0]; ua=self.headers.get("User-Agent","")
        if path=="/admin":
            if not self.auth(): return self.sendbody(200,self.login_page())
            return self.sendbody(200,self.dashboard())
        if path=="/admin/logout":
            c=cookies.SimpleCookie(self.headers.get("Cookie","")); s=c.get("admin_session")
            if s: SESSIONS.discard(s.value)
            return self.sendbody(302,b"",extra={"Location":"/admin","Set-Cookie":"admin_session=; Max-Age=0; HttpOnly; SameSite=Strict"})
        if path=="/admin.csv":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            c=db(); rows=c.execute("SELECT ts,event,template,ip,name,employee_id,email,mobile,card_type,user_agent FROM events ORDER BY id DESC").fetchall(); c.close()
            out=io.StringIO(); w=csv.writer(out)
            w.writerow(["timestamp","event","template","local_ip","name","employee_id","email","mobile","card_type","user_agent"])
            for r in rows:
                w.writerow([r["ts"],r["event"],r["template"],r["ip"],r["name"] or "",r["employee_id"] or "",r["email"] or "",r["mobile"] or "",r["card_type"] or "",r["user_agent"] or ""])
            return self.sendbody(200,out.getvalue(),"text/csv",{"Content-Disposition":"attachment; filename=phish-simulation.csv"})
        if path in ("/admin/campaigns","/admin/templates","/admin/landing-pages","/admin/smtp","/admin/users","/admin/reports","/admin/risk","/admin/exports","/admin/settings","/admin/audit"):
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            if path=="/admin/campaigns" and parse_qs(p.query).get("id",[None])[0]:
                return self.sendbody(200,self.campaign_form(parse_qs(p.query).get("id",[None])[0]))
            if path=="/admin/smtp" and parse_qs(p.query).get("id",[None])[0]:
                return self.sendbody(200,self.smtp_form(parse_qs(p.query).get("id",[None])[0]))
            return self.sendbody(200,self.feature_page(path))
        if path=="/admin/smtp/new":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            return self.sendbody(200,self.smtp_form())
        if path=="/admin/campaigns/new":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            return self.sendbody(200,self.campaign_form())
        if path.startswith("/") and path.endswith(".html") and path[1:-5].isdigit():
            t=path[1:]; fn=os.path.join(TEMPLATES,t)
            if os.path.isfile(fn):
                record(ip,t,"click",ua=ua); access(ip,path,200)
                with open(fn,"rb") as f: return self.sendbody(200,f.read())
        access(ip,path,404); return self.sendbody(404,"404 File not found","text/plain")

    def do_POST(self):
        p=urlparse(self.path); ip=self.client_address[0]
        n=int(self.headers.get("Content-Length","0"))
        form=parse_qs(self.rfile.read(n).decode("utf-8","replace"))
        if p.path=="/admin/login":
            username=form.get("username",[""])[0]
            password=form.get("password",[""])[0]
            if secrets.compare_digest(username,ADMIN_USERNAME) and secrets.compare_digest(password,ADMIN_PASSWORD):
                sid=secrets.token_urlsafe(32); SESSIONS.add(sid)
                ck=cookies.SimpleCookie(); ck["admin_session"]=sid; ck["admin_session"]["HttpOnly"]=True; ck["admin_session"]["SameSite"]="Strict"
                return self.sendbody(302,b"",extra={"Location":"/admin","Set-Cookie":ck["admin_session"].OutputString()})
            return self.sendbody(401,self.login_page("Invalid username or password"))
        if p.path=="/admin/smtp/save":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            sid=form.get("id",[""])[0]; name=form.get("name",[""])[0][:100]; provider=form.get("provider",["Custom SMTP"])[0]
            host=form.get("host",[""])[0][:255]; port=int(form.get("port",["587"])[0]); security=form.get("security",["STARTTLS"])[0]
            username=form.get("username",[""])[0][:255]; password=form.get("password",[""])[0]; from_name=form.get("from_name",[""])[0][:150]
            from_email=form.get("from_email",[""])[0][:255]; reply_to=form.get("reply_to",[""])[0][:255]
            if provider not in SMTP_PROVIDERS or security not in ("STARTTLS","SSL/TLS","NONE") or not host or not from_email or port<1 or port>65535:
                return self.sendbody(400,"Invalid SMTP profile","text/plain")
            c=db()
            if sid:
                old=c.execute("SELECT password_enc FROM smtp_profiles WHERE id=?",(sid,)).fetchone()
                enc=encrypt_secret(password) if password else (old["password_enc"] if old else "")
                c.execute("UPDATE smtp_profiles SET name=?,provider=?,host=?,port=?,security=?,username=?,password_enc=?,from_name=?,from_email=?,reply_to=?,updated_at=? WHERE id=?",(name,provider,host,port,security,username,enc,from_name,from_email,reply_to,now(),sid)); action="SMTP_PROFILE_UPDATE"
            else:
                enc=encrypt_secret(password) if password else ""
                c.execute("INSERT INTO smtp_profiles(name,provider,host,port,security,username,password_enc,from_name,from_email,reply_to,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(name,provider,host,port,security,username,enc,from_name,from_email,reply_to,1,now(),now())); action="SMTP_PROFILE_CREATE"
            c.commit(); c.close(); audit(ADMIN_USERNAME,action,name,ip)
            return self.sendbody(302,b"",extra={"Location":"/admin/smtp"})
        if p.path=="/admin/smtp/test":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            sid=form.get("id",[""])[0]; to_email=form.get("to_email",[""])[0][:255]
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",to_email):
                return self.sendbody(400,"Invalid test email","text/plain")
            c=db(); profile=c.execute("SELECT * FROM smtp_profiles WHERE id=?",(sid,)).fetchone(); c.close()
            if not profile: return self.sendbody(404,"SMTP profile not found","text/plain")
            try:
                smtp_send_test(profile,to_email)
                audit(ADMIN_USERNAME,"SMTP_TEST",f"profile={profile['name']} recipient={to_email}",ip)
                return self.sendbody(200,page("SMTP Test","<div style='max-width:700px;margin:70px auto;background:#fff;padding:30px;border-radius:16px;border:1px solid #dce7e2'><h2>SMTP test sent</h2><p>The test message was accepted by the configured SMTP server.</p><p><a href='/admin/smtp'>Back to SMTP Providers</a></p></div>"))
            except Exception as e:
                audit(ADMIN_USERNAME,"SMTP_TEST_FAILED",f"profile={profile['name']}",ip)
                return self.sendbody(502,page("SMTP Test Failed","<div style='max-width:700px;margin:70px auto;background:#fff;padding:30px;border-radius:16px;border:1px solid #dce7e2'><h2>SMTP test failed</h2><p>The SMTP connection or authentication failed. Check host, port, TLS mode and provider credentials.</p><p style='color:#a12d2d;font-size:12px'>No SMTP password is shown here.</p><p><a href='/admin/smtp'>Back to SMTP Providers</a></p></div>"))
        if p.path=="/admin/campaigns/save":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            cid=form.get("id",[""])[0]; name=form.get("name",[""])[0][:150]; template=form.get("template",["1"])[0]; status=form.get("status",["Draft"])[0]
            c=db()
            if cid:
                c.execute("UPDATE campaigns SET name=?,template=?,status=?,updated_at=? WHERE id=?",(name,template,status,now(),cid)); action="CAMPAIGN_UPDATE"
            else:
                c.execute("INSERT INTO campaigns(name,template,status,targeted,created_at,updated_at) VALUES(?,?,?,?,?,?)",(name,template,status,0,now(),now())); action="CAMPAIGN_CREATE"
            c.commit(); c.close(); audit(ADMIN_USERNAME,action,name,ip)
            return self.sendbody(302,b"",extra={"Location":"/admin/campaigns"})
        if p.path=="/submit":
            t=form.get("template",["unknown"])[0][:50]
            name=form.get("name",[""])[0][:150]; employee_id=form.get("employee_id",[""])[0][:100]
            email=form.get("email",[""])[0][:200]; mobile=form.get("mobile",[""])[0][:50]
            card_type=form.get("card_type",[""])[0][:100]
            record(ip,t,"submitted",name,email,mobile,self.headers.get("User-Agent",""),employee_id,card_type)
            access(ip,p.path,200)
            return self.sendbody(200,page("Simulation Complete","<div style='max-width:760px;margin:80px auto;background:#fff;padding:35px;border-radius:18px;border:1px solid #dce7e2'><h1>Security Awareness Simulation</h1><p>Simulation complete. No password, OTP, PIN, CVV or card information was requested or stored.</p></div>"))
        return self.sendbody(404,"Not found","text/plain")

if __name__=="__main__":
    db().close()
    ThreadingHTTPServer(("0.0.0.0",PORT),Handler).serve_forever()
