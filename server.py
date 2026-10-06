#!/usr/bin/env python3
import os, sqlite3, csv, io, secrets, html, smtplib, ssl, subprocess, tempfile, re, threading, time, hashlib, hmac, base64, socket
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, urlencode
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
PUBLIC_BASE_URL=os.environ.get("PUBLIC_BASE_URL","").rstrip("/")
SEND_DELAY=float(os.environ.get("SEND_DELAY_SECONDS","0.2"))
ADMIN_USERNAME=os.environ.get("ADMIN_USERNAME","admin")
ADMIN_PASSWORD=os.environ.get("ADMIN_PASSWORD","CHANGE_ME")
SESSIONS={}
LOGIN_ATTEMPTS={}
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

def password_hash(password):
    salt=secrets.token_bytes(16)
    digest=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,150000)
    return "pbkdf2_sha256$150000$%s$%s"%(base64.urlsafe_b64encode(salt).decode(),base64.urlsafe_b64encode(digest).decode())

def password_verify(password,stored):
    try:
        algo,iterations,salt_b64,digest_b64=stored.split("$",3)
        if algo!="pbkdf2_sha256": return False
        salt=base64.urlsafe_b64decode(salt_b64.encode())
        expected=base64.urlsafe_b64decode(digest_b64.encode())
        actual=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,int(iterations))
        return hmac.compare_digest(actual,expected)
    except Exception:
        return False

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
    for col in ("employee_id","card_type","campaign_id","recipient_id"):
        if col not in cols:
            c.execute(f"ALTER TABLE events ADD COLUMN {col} TEXT")
    c.executescript("""
    CREATE TABLE IF NOT EXISTS tracking_tokens(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT UNIQUE NOT NULL,
        campaign_id INTEGER NOT NULL,
        recipient_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT
    );
    CREATE TABLE IF NOT EXISTS event_dedup(
        token TEXT NOT NULL,
        event TEXT NOT NULL,
        first_seen_at TEXT NOT NULL,
        PRIMARY KEY(token,event)
    );
    CREATE INDEX IF NOT EXISTS idx_events_campaign_event ON events(campaign_id,event);
    CREATE INDEX IF NOT EXISTS idx_events_recipient_event ON events(recipient_id,event);
    """)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS rbac_roles(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        slug TEXT NOT NULL UNIQUE,
        description TEXT,
        built_in INTEGER NOT NULL DEFAULT 0,
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS rbac_permissions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        resource TEXT NOT NULL,
        action TEXT NOT NULL,
        label TEXT NOT NULL,
        description TEXT,
        risk_level TEXT NOT NULL DEFAULT 'normal' CHECK(risk_level IN ('normal','elevated','privileged')),
        active INTEGER NOT NULL DEFAULT 1,
        UNIQUE(resource,action)
    );
    CREATE TABLE IF NOT EXISTS rbac_role_permissions(
        role_id INTEGER NOT NULL,
        permission_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY(role_id,permission_id),
        FOREIGN KEY(role_id) REFERENCES rbac_roles(id) ON DELETE CASCADE,
        FOREIGN KEY(permission_id) REFERENCES rbac_permissions(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_rbac_role_permissions_role
    ON rbac_role_permissions(role_id);
    CREATE INDEX IF NOT EXISTS idx_rbac_role_permissions_permission
    ON rbac_role_permissions(permission_id);
    CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, role TEXT DEFAULT "Administrator", password_hash TEXT, created_at TEXT);
    CREATE TABLE IF NOT EXISTS campaigns(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,template TEXT,status TEXT NOT NULL DEFAULT 'Draft',targeted INTEGER DEFAULT 0,created_at TEXT,updated_at TEXT);
    CREATE TABLE IF NOT EXISTS recipients(id INTEGER PRIMARY KEY AUTOINCREMENT,campaign_id INTEGER,email TEXT,name TEXT,employee_id TEXT,department TEXT,group_name TEXT,status TEXT DEFAULT 'Pending',created_at TEXT);
    CREATE TABLE IF NOT EXISTS groups_tbl(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT UNIQUE,department TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS landing_pages(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT UNIQUE,template TEXT,status TEXT DEFAULT 'Enabled',created_at TEXT);
    CREATE TABLE IF NOT EXISTS risk_scores(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE,score REAL DEFAULT 0,level TEXT DEFAULT 'Low',failures INTEGER DEFAULT 0,last_event TEXT,updated_at TEXT);
    CREATE TABLE IF NOT EXISTS risk_history(id INTEGER PRIMARY KEY AUTOINCREMENT,scope TEXT NOT NULL,subject TEXT NOT NULL,score REAL DEFAULT 0,level TEXT DEFAULT 'Low',failures INTEGER DEFAULT 0,recorded_at TEXT NOT NULL,factors TEXT);
    CREATE INDEX IF NOT EXISTS idx_risk_history_scope_subject_time ON risk_history(scope,subject,recorded_at);
    CREATE TABLE IF NOT EXISTS risk_settings(key TEXT PRIMARY KEY,value TEXT);
    INSERT OR IGNORE INTO risk_settings(key,value) VALUES('click_weight','20'),('form_action_weight','35'),('report_bonus','-10'),('repeat_bonus','15'),('lookback_days','180'),('high_threshold','70'),('medium_threshold','40');
    CREATE TABLE IF NOT EXISTS training_records(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE,completion REAL DEFAULT 0,course TEXT,updated_at TEXT);
    CREATE TABLE IF NOT EXISTS training_courses(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        description TEXT,
        duration_minutes INTEGER DEFAULT 15,
        passing_score REAL DEFAULT 80,
        status TEXT DEFAULT 'Active',
        created_at TEXT,
        updated_at TEXT
    );
    CREATE TABLE IF NOT EXISTS training_assignments(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        course_id INTEGER NOT NULL,
        recipient_id INTEGER NOT NULL,
        assigned_at TEXT,
        due_at TEXT,
        status TEXT DEFAULT 'Assigned',
        completion REAL DEFAULT 0,
        score REAL,
        completed_at TEXT,
        UNIQUE(course_id,recipient_id)
    );
    CREATE INDEX IF NOT EXISTS idx_training_assignments_recipient ON training_assignments(recipient_id,status);
    CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY AUTOINCREMENT,ts TEXT,admin TEXT,action TEXT,details TEXT,ip TEXT);
    CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT);
    CREATE TABLE IF NOT EXISTS campaign_deliveries(id INTEGER PRIMARY KEY AUTOINCREMENT,campaign_id INTEGER,recipient_id INTEGER,status TEXT,attempted_at TEXT,sent_at TEXT,error TEXT);
    CREATE TABLE IF NOT EXISTS campaign_queue(
        id INTEGER PRIMARY KEY AUTOINCREMENT,campaign_id INTEGER NOT NULL,recipient_id INTEGER NOT NULL,status TEXT DEFAULT 'Pending',
        attempts INTEGER DEFAULT 0,next_attempt_at TEXT,last_error TEXT,queued_at TEXT,updated_at TEXT,
        UNIQUE(campaign_id,recipient_id)
    );
    CREATE INDEX IF NOT EXISTS idx_campaign_queue_due ON campaign_queue(campaign_id,status,next_attempt_at);
    CREATE TABLE IF NOT EXISTS scheduled_reports(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        frequency TEXT NOT NULL DEFAULT 'Weekly',
        report_view TEXT NOT NULL DEFAULT 'executive',
        smtp_profile_id INTEGER NOT NULL,
        recipients TEXT NOT NULL,
        next_run_at TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        last_run_at TEXT,
        last_status TEXT,
        created_at TEXT,
        updated_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_scheduled_reports_due ON scheduled_reports(enabled,next_run_at);
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
        auth_method TEXT DEFAULT 'password',
        oauth_token_enc TEXT,
        oauth_refresh_token_enc TEXT,
        oauth_token_url TEXT,
        oauth_client_id TEXT,
        oauth_scopes TEXT,
        enabled INTEGER DEFAULT 1,
        created_at TEXT,
        updated_at TEXT
    );
    CREATE TABLE IF NOT EXISTS template_library(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        template TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        subject TEXT,
        preheader TEXT,
        category TEXT DEFAULT 'General',
        difficulty TEXT DEFAULT 'Medium',
        language TEXT DEFAULT 'English',
        brand TEXT,
        industry TEXT,
        tags TEXT,
        html_body TEXT,
        text_body TEXT,
        version INTEGER DEFAULT 1,
        from_name TEXT,
        from_email TEXT,
        reply_to TEXT,
        owner TEXT,
        status TEXT DEFAULT "Active",
        updated_at TEXT
    );
    CREATE TABLE IF NOT EXISTS template_versions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        template TEXT NOT NULL,
        version INTEGER NOT NULL,
        name TEXT,
        subject TEXT,
        preheader TEXT,
        category TEXT,
        difficulty TEXT,
        language TEXT,
        brand TEXT,
        industry TEXT,
        tags TEXT,
        html_body TEXT,
        text_body TEXT,
        created_at TEXT,
        created_by TEXT,
        UNIQUE(template,version)
    );
    CREATE INDEX IF NOT EXISTS idx_template_versions_template
    ON template_versions(template,version);
    CREATE TABLE IF NOT EXISTS landing_page_versions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        landing_page_id INTEGER NOT NULL,
        version INTEGER NOT NULL,
        html_body TEXT,
        text_body TEXT,
        created_at TEXT,
        created_by TEXT,
        UNIQUE(landing_page_id,version)
    );
    CREATE INDEX IF NOT EXISTS idx_landing_page_versions_page
    ON landing_page_versions(landing_page_id,version);

    """)

    cols_admin={row[1] for row in c.execute("PRAGMA table_info(admins)").fetchall()}
    if "role" not in cols_admin: c.execute('ALTER TABLE admins ADD COLUMN role TEXT DEFAULT "Administrator"')
    if "password_hash" not in cols_admin: c.execute("ALTER TABLE admins ADD COLUMN password_hash TEXT")
    if "active" not in cols_admin: c.execute("ALTER TABLE admins ADD COLUMN active INTEGER DEFAULT 1")
    c.execute("INSERT OR IGNORE INTO admins(username,role,password_hash,active,created_at) VALUES(?,?,?,?,?)",(ADMIN_USERNAME,"Administrator",password_hash(ADMIN_PASSWORD),1,now()))
    c.execute("UPDATE admins SET password_hash=? WHERE username=? AND (password_hash IS NULL OR password_hash='')",(password_hash(ADMIN_PASSWORD),ADMIN_USERNAME))
    c.execute("UPDATE admins SET active=1 WHERE username=? AND active IS NULL",(ADMIN_USERNAME,))
    cols_smtp={row[1] for row in c.execute("PRAGMA table_info(smtp_profiles)").fetchall()}
    for col,definition in (("auth_method","TEXT DEFAULT 'password'"),("oauth_token_enc","TEXT"),("oauth_refresh_token_enc","TEXT"),("oauth_token_url","TEXT"),("oauth_client_id","TEXT"),("oauth_scopes","TEXT")):
        if col not in cols_smtp: c.execute("ALTER TABLE smtp_profiles ADD COLUMN %s %s"%(col,definition))

    cols_template={row[1] for row in c.execute("PRAGMA table_info(template_library)").fetchall()}
    if "version" not in cols_template: c.execute("ALTER TABLE template_library ADD COLUMN version INTEGER DEFAULT 1")

    cols_template={row[1] for row in c.execute("PRAGMA table_info(template_library)").fetchall()}
    for col,definition in (("from_name","TEXT"),("from_email","TEXT"),("reply_to","TEXT"),("owner","TEXT"),("status","TEXT DEFAULT 'Active'")):
        if col not in cols_template: c.execute("ALTER TABLE template_library ADD COLUMN %s %s"%(col,definition))

    cols_risk={row[1] for row in c.execute("PRAGMA table_info(risk_scores)").fetchall()}
    for col,definition in (("repeat_offender","INTEGER DEFAULT 0"),("remediation_status","TEXT DEFAULT 'None'"),("remediation_due_at","TEXT"),("factor_summary","TEXT")):
        if col not in cols_risk:
            c.execute("ALTER TABLE risk_scores ADD COLUMN %s %s"%(col,definition))
    cols_training={row[1] for row in c.execute("PRAGMA table_info(training_assignments)").fetchall()}
    for col,definition in (("result","TEXT"),("trigger_campaign_id","INTEGER"),("remediation_campaign_id","INTEGER"),("result_at","TEXT")):
        if col not in cols_training:
            c.execute("ALTER TABLE training_assignments ADD COLUMN %s %s"%(col,definition))
    cols_landing={row[1] for row in c.execute("PRAGMA table_info(landing_pages)").fetchall()}
    for col,definition in (("html_body","TEXT"),("text_body","TEXT"),("version","INTEGER DEFAULT 1"),("updated_at","TEXT")):
        if col not in cols_landing:
            c.execute("ALTER TABLE landing_pages ADD COLUMN %s %s"%(col,definition))
    c.execute("""UPDATE landing_pages
                 SET html_body=COALESCE(html_body,''),
                     text_body=COALESCE(text_body,''),
                     version=COALESCE(version,1),
                     updated_at=COALESCE(updated_at,created_at)
                 WHERE html_body IS NULL OR text_body IS NULL OR version IS NULL OR updated_at IS NULL""")
    for lp in c.execute("SELECT id,template,html_body,text_body FROM landing_pages").fetchall():
        if not (lp["html_body"] or "").strip():
            fn=os.path.join(TEMPLATES,str(lp["template"])+".html")
            try:
                with open(fn,"r",encoding="utf-8") as tf:
                    seed_html=tf.read()
                c.execute("UPDATE landing_pages SET html_body=?,text_body=?,updated_at=? WHERE id=?",(seed_html,"Authorized security-awareness simulation landing page.",now(),lp["id"]))
            except Exception:
                pass
    cols_recipient={row[1] for row in c.execute("PRAGMA table_info(recipients)").fetchall()}
    for col,definition in (("designation","TEXT"),("location","TEXT"),("manager","TEXT"),("language","TEXT DEFAULT 'English'"),("timezone","TEXT DEFAULT 'Asia/Dhaka'")):
        if col not in cols_recipient:
            c.execute("ALTER TABLE recipients ADD COLUMN %s %s"%(col,definition))
    c.execute("""CREATE TABLE IF NOT EXISTS recipient_import_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_name TEXT,
        processed INTEGER DEFAULT 0,
        created INTEGER DEFAULT 0,
        updated INTEGER DEFAULT 0,
        skipped INTEGER DEFAULT 0,
        errors TEXT,
        created_at TEXT
    )""")
    cols_campaign={row[1] for row in c.execute("PRAGMA table_info(campaigns)").fetchall()}
    for col,definition in (("smtp_profile_id","INTEGER"),("landing_page_id","INTEGER"),("subject","TEXT"),("launch_at","TEXT"),("send_by","TEXT"),("group_name","TEXT"),("timezone","TEXT DEFAULT 'Asia/Dhaka'"),("business_days","TEXT DEFAULT 'Sun,Mon,Tue,Wed,Thu'"),("window_start","TEXT DEFAULT '09:00'"),("window_end","TEXT DEFAULT '17:00'"),("batch_size","INTEGER DEFAULT 50"),("rate_per_minute","INTEGER DEFAULT 60"),("retry_max","INTEGER DEFAULT 2"),("retry_backoff_seconds","INTEGER DEFAULT 5"),("cancel_requested","INTEGER DEFAULT 0")):
        if col not in cols_campaign:
            c.execute("ALTER TABLE campaigns ADD COLUMN %s %s"%(col,definition))
    if not c.execute("SELECT 1 FROM admins WHERE username=?",(ADMIN_USERNAME,)).fetchone():
        c.execute("INSERT INTO admins(username,created_at) VALUES(?,?)",(ADMIN_USERNAME,datetime.now(timezone.utc).isoformat()))
    c.execute("""INSERT OR IGNORE INTO training_courses(name,description,duration_minutes,passing_score,status,created_at,updated_at)
                 VALUES(?,?,?,?,?,?,?)""",
              ("Security Awareness Fundamentals","Core security-awareness training following a phishing simulation.",15,80,"Active",now(),now()))
    for i in range(1,11):
        c.execute("INSERT OR IGNORE INTO landing_pages(name,template,status,created_at) VALUES(?,?,?,?)",(f"Landing Page {i}",str(i),"Enabled",datetime.now(timezone.utc).isoformat()))
        fn=os.path.join(TEMPLATES,str(i)+".html")
        existing=c.execute("SELECT id FROM template_library WHERE template=?",(str(i),)).fetchone()
        if not existing:
            body=""
            try:
                with open(fn,"r",encoding="utf-8") as tf: body=tf.read()
            except Exception:
                pass
            c.execute("""INSERT INTO template_library(template,name,subject,preheader,category,difficulty,language,brand,industry,tags,html_body,text_body,updated_at)
                         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (str(i),f"Template {i}","Security Awareness Simulation","Authorized security-awareness simulation",
                       "General","Medium","English","Trust PhishGuard","Banking","simulation,awareness",body,
                       "This is an authorized security-awareness simulation.",now()))
    c.commit()
    return c

EVENT_TAXONOMY={"delivered","open","click","form_action","report","QR_scan","training_assigned","training_completed","bot_detected"}
BOT_UA_RE=re.compile(r"(bot|crawler|spider|scanner|proofpoint|mimecast|barracuda|safelinks|urlscan|security|linkcheck|headless|phantom|selenium|playwright)",re.I)

def is_bot_user_agent(ua):
    return bool(BOT_UA_RE.search(ua or ""))

LANDING_BLOCKED_PATTERNS=(
    r'(?is)<input[^>]+(?:type\s*=\s*["\\\']?password|name\s*=\s*["\\\']?(?:password|passwd|passcode))',
    r'(?is)(?:name|id)\s*=\s*["\\\']?(?:otp|one[-_ ]?time[-_ ]?password|pin|cvv|cvc|card[-_ ]?number)',
    r'(?is)(?:otp|one[-_ ]?time[-_ ]?password|cvv|cvc|card[-_ ]?number)\s*[:=]'
)
TEMPLATE_BLOCKED_PATTERNS=(
    r'(?is)<input[^>]+(?:type\s*=\s*["\\\']?password|name\s*=\s*["\\\']?(?:password|passwd|passcode))',
    r'(?is)(?:name|id)\s*=\s*["\\\']?(?:otp|one[-_ ]?time[-_ ]?password|pin|cvv|cvc|card[-_ ]?number)',
    r'(?is)(?:otp|one[-_ ]?time[-_ ]?password|cvv|cvc|card[-_ ]?number)\s*[:=]'
)

def validate_template_html(body):
    if len(body or "")>500000:
        return False,"Template HTML exceeds the 500 KB limit."
    for pattern in TEMPLATE_BLOCKED_PATTERNS:
        if re.search(pattern,body or ""):
            return False,"Blocked field policy: passwords, OTPs, PINs, CVV/CVC or card-number collection is not allowed."
    return True,""

def validate_landing_html(body):
    if len(body)>500000:
        return False,"Landing page HTML exceeds the 500 KB limit."
    for pattern in LANDING_BLOCKED_PATTERNS:
        if re.search(pattern,body or ""):
            return False,"Blocked field policy: passwords, OTPs, PINs, CVV/CVC or card-number collection is not allowed."
    return True,""

def create_tracking_token(campaign_id,recipient_id):
    token=secrets.token_urlsafe(32)
    c=db()
    c.execute("INSERT INTO tracking_tokens(token,campaign_id,recipient_id,created_at) VALUES(?,?,?,?)",(token,campaign_id,recipient_id,now()))
    c.commit(); c.close()
    return token

def resolve_tracking_token(token):
    if not token: return None
    c=db(); row=c.execute("SELECT * FROM tracking_tokens WHERE token=?",(token,)).fetchone(); c.close()
    return row

def risk_settings(c=None):
    own=False
    if c is None: c=db(); own=True
    rows=c.execute("SELECT key,value FROM risk_settings").fetchall()
    vals={r["key"]:r["value"] for r in rows}
    if own: c.close()
    def num(k,d):
        try: return float(vals.get(k,d))
        except: return float(d)
    return {"click_weight":num("click_weight",20),"form_action_weight":num("form_action_weight",35),"report_bonus":num("report_bonus",-10),"repeat_bonus":num("repeat_bonus",15),"lookback_days":max(1,int(num("lookback_days",180))),"high_threshold":num("high_threshold",70),"medium_threshold":num("medium_threshold",40)}

def risk_recalculate(email=""):
    c=db(); cfg=risk_settings(c)
    cutoff=(datetime.now(timezone.utc)-timedelta(days=cfg["lookback_days"])).isoformat()
    rows=c.execute("SELECT email,event,campaign_id,ts FROM events WHERE email!='' AND ts>=?"+(" AND email=?" if email else ""), (cutoff,email) if email else (cutoff,)).fetchall()
    grouped={}
    for r in rows: grouped.setdefault(r["email"],[]).append(r)
    if email and email not in grouped: grouped[email]=[]
    for addr,evs in grouped.items():
        clicks=sum(r["event"]=="click" for r in evs); actions=sum(r["event"]=="form_action" for r in evs); reports=sum(r["event"]=="report" for r in evs)
        failures=clicks+actions; campaigns={str(r["campaign_id"]) for r in evs if r["campaign_id"] not in (None,"")}
        repeat=int(failures>=2 and len(campaigns)>=2)
        score=max(0,min(100,clicks*cfg["click_weight"]+actions*cfg["form_action_weight"]+reports*cfg["report_bonus"]+repeat*cfg["repeat_bonus"]))
        level="High" if score>=cfg["high_threshold"] else ("Medium" if score>=cfg["medium_threshold"] else "Low")
        factors="clicks=%d;form_actions=%d;reports=%d;campaigns=%d;repeat_offender=%s;lookback_days=%d"%(clicks,actions,reports,len(campaigns),"yes" if repeat else "no",cfg["lookback_days"])
        cur=c.execute("SELECT remediation_status,remediation_due_at FROM risk_scores WHERE email=?",(addr,)).fetchone()
        rem=(cur["remediation_status"] if cur else "") or ("Required" if level=="High" else ("Recommended" if level=="Medium" else "None"))
        due=cur["remediation_due_at"] if cur else ""
        c.execute("""INSERT INTO risk_scores(email,score,level,failures,last_event,updated_at,repeat_offender,remediation_status,remediation_due_at,factor_summary)
        VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(email) DO UPDATE SET score=excluded.score,level=excluded.level,failures=excluded.failures,last_event=excluded.last_event,updated_at=excluded.updated_at,repeat_offender=excluded.repeat_offender,remediation_status=excluded.remediation_status,remediation_due_at=excluded.remediation_due_at,factor_summary=excluded.factor_summary""",(addr,score,level,failures,evs[-1]["event"] if evs else "",now(),repeat,rem,due,factors))
    c.commit(); c.close()

def snapshot_risk_history():
    risk_recalculate()
    c=db(); ts=now(); day=ts[:10]
    user_rows=c.execute("SELECT email,score,level,failures,factor_summary FROM risk_scores").fetchall()
    for r in user_rows:
        if not c.execute("SELECT 1 FROM risk_history WHERE scope='user' AND subject=? AND substr(recorded_at,1,10)=?",(r["email"],day)).fetchone():
            c.execute("INSERT INTO risk_history(scope,subject,score,level,failures,recorded_at,factors) VALUES(?,?,?,?,?,?,?)",("user",r["email"],r["score"],r["level"],r["failures"],ts,r["factor_summary"] or ""))
    dept_rows=c.execute("""SELECT r.department,AVG(rs.score) score,SUM(rs.failures) failures,COUNT(*) members
                           FROM recipients r JOIN risk_scores rs ON lower(r.email)=lower(rs.email)
                           WHERE r.department!='' GROUP BY r.department""").fetchall()
    for r in dept_rows:
        score=float(r["score"] or 0); level="High" if score>=70 else ("Medium" if score>=40 else "Low")
        if not c.execute("SELECT 1 FROM risk_history WHERE scope='department' AND subject=? AND substr(recorded_at,1,10)=?",(r["department"],day)).fetchone():
            c.execute("INSERT INTO risk_history(scope,subject,score,level,failures,recorded_at,factors) VALUES(?,?,?,?,?,?,?)",("department",r["department"],score,level,int(r["failures"] or 0),ts,"members=%s"%r["members"]))
    campaign_rows=c.execute("""SELECT c.id,c.name,COALESCE(SUM(CASE WHEN e.event='click' THEN 1 ELSE 0 END),0) clicks,
                               COALESCE(SUM(CASE WHEN e.event='form_action' THEN 1 ELSE 0 END),0) actions,
                               COALESCE(SUM(CASE WHEN e.event='report' THEN 1 ELSE 0 END),0) reports,
                               COALESCE((SELECT COUNT(*) FROM campaign_deliveries d WHERE d.campaign_id=c.id AND d.status='Sent'),0) sent
                               FROM campaigns c LEFT JOIN events e ON e.campaign_id=c.id GROUP BY c.id,c.name""").fetchall()
    for r in campaign_rows:
        sent=max(int(r["sent"] or 0),1)
        score=max(0,min(100,(r["clicks"]*100.0/sent*0.6)+(r["actions"]*100.0/sent*0.4)-(r["reports"]*5)))
        level="High" if score>=70 else ("Medium" if score>=40 else "Low")
        if not c.execute("SELECT 1 FROM risk_history WHERE scope='campaign' AND subject=? AND substr(recorded_at,1,10)=?",(str(r["id"]),day)).fetchone():
            c.execute("INSERT INTO risk_history(scope,subject,score,level,failures,recorded_at,factors) VALUES(?,?,?,?,?,?,?)",("campaign",str(r["id"]),score,level,int(r["clicks"]+r["actions"]),ts,"campaign=%s;sent=%s;clicks=%s;actions=%s;reports=%s"%(r["name"],r["sent"],r["clicks"],r["actions"],r["reports"])))
    c.commit(); c.close()
def record(ip,t,event,name="",email="",mobile="",ua="",employee_id="",card_type="",campaign_id="",recipient_id="",token=""):
    if event not in EVENT_TAXONOMY: raise ValueError("Unsupported event taxonomy: %s" % event)
    c=db()
    if token and event in ("click","form_action","report","QR_scan","open"):
        try: c.execute("INSERT INTO event_dedup(token,event,first_seen_at) VALUES(?,?,?)",(token,event,now()))
        except sqlite3.IntegrityError: c.close(); return False
    c.execute("INSERT INTO events(ts,ip,template,event,name,email,mobile,user_agent,employee_id,card_type,campaign_id,recipient_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(datetime.now(timezone.utc).isoformat(),ip,t,event,name,email,mobile,ua,employee_id,card_type,campaign_id,recipient_id))
    c.commit(); c.close()
    if email and event in ("click","form_action","report"): risk_recalculate(email)
    return True

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

def smtp_diagnostics(profile,to_email=""):
    result=[]
    host=profile["host"]; port=int(profile["port"]); security=profile["security"]
    if not host:
        return [{"stage":"DNS","status":"FAIL","detail":"SMTP host is empty."}]
    try:
        addresses=socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)
        result.append({"stage":"DNS","status":"PASS","detail":"Resolved %d address(es)."%len(addresses)})
    except Exception as e:
        return result+[{"stage":"DNS","status":"FAIL","detail":"DNS resolution failed."}]
    try:
        raw=socket.create_connection((host,port),timeout=10)
        raw.close()
        result.append({"stage":"TCP","status":"PASS","detail":"TCP connection established."})
    except Exception:
        return result+[{"stage":"TCP","status":"FAIL","detail":"TCP connection failed."}]
    smtp=None
    try:
        if security=="SSL/TLS":
            smtp=smtplib.SMTP_SSL(host,port,context=ssl.create_default_context(),timeout=15)
            smtp.ehlo()
        else:
            smtp=smtplib.SMTP(host,port,timeout=15)
            smtp.ehlo()
            if security=="STARTTLS":
                smtp.starttls(context=ssl.create_default_context()); smtp.ehlo()
        result.append({"stage":"TLS","status":"PASS","detail":"SMTP TLS/session negotiation succeeded."})
        if profile["username"] or (profile["auth_method"] or "password").lower()=="oauth2":
            smtp_authenticate(smtp,profile)
            result.append({"stage":"AUTH","status":"PASS","detail":"SMTP authentication succeeded."})
        else:
            result.append({"stage":"AUTH","status":"SKIP","detail":"No SMTP authentication configured; relay may use IP or other policy."})
        if to_email:
            msg=EmailMessage()
            msg["Subject"]="[TEST] Trust PhishGuard SMTP diagnostics"
            msg["From"]=formataddr((profile["from_name"] or "Trust PhishGuard",profile["from_email"]))
            msg["To"]=to_email
            if profile["reply_to"]: msg["Reply-To"]=profile["reply_to"]
            msg.set_content("This is an authorized Trust PhishGuard SMTP connectivity diagnostic.")
            smtp.send_message(msg)
            result.append({"stage":"SEND","status":"PASS","detail":"Diagnostic test message accepted by SMTP server."})
        else:
            result.append({"stage":"SEND","status":"SKIP","detail":"No test recipient supplied."})
    except smtplib.SMTPAuthenticationError:
        result.append({"stage":"AUTH","status":"FAIL","detail":"SMTP authentication failed."})
    except ssl.SSLError:
        result.append({"stage":"TLS","status":"FAIL","detail":"TLS negotiation failed."})
    except Exception:
        result.append({"stage":"SEND" if to_email else "TLS","status":"FAIL","detail":"SMTP session operation failed."})
    finally:
        if smtp:
            try: smtp.quit()
            except Exception: pass
    return result

def smtp_authenticate(smtp,profile):
    method=(profile["auth_method"] or "password").lower()
    if method=="oauth2":
        token=decrypt_secret(profile["oauth_token_enc"]) if profile["oauth_token_enc"] else ""
        if not token:
            raise RuntimeError("SMTP OAuth2 access token is not configured")
        auth_string=lambda challenge=None: "\x00%s\x00%s"%(profile["username"] or "",token)
        smtp.auth("XOAUTH2",auth_string,initial_response_ok=True)
        return
    if profile["username"]:
        smtp.login(profile["username"],decrypt_secret(profile["password_enc"]))

def smtp_connect(profile):
    host=profile["host"]; port=int(profile["port"]); security=profile["security"]
    if security=="SSL/TLS":
        smtp=smtplib.SMTP_SSL(host,port,context=ssl.create_default_context(),timeout=20)
    else:
        smtp=smtplib.SMTP(host,port,timeout=20)
        smtp.ehlo()
        if security=="STARTTLS":
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
    smtp_authenticate(smtp,profile)
    return smtp

def campaign_zone(campaign):
    try:
        return ZoneInfo(campaign["timezone"] or "Asia/Dhaka")
    except Exception:
        raise ValueError("Invalid campaign timezone")

def campaign_dt(value, zone):
    if not value:
        return None
    dt=datetime.fromisoformat(value)
    return dt.replace(tzinfo=zone) if dt.tzinfo is None else dt.astimezone(zone)

def campaign_window_open(campaign, when=None):
    zone=campaign_zone(campaign)
    local=(when or datetime.now(timezone.utc)).astimezone(zone)
    days={x.strip() for x in (campaign["business_days"] or "Sun,Mon,Tue,Wed,Thu").split(",") if x.strip()}
    if days and local.strftime("%a") not in days:
        return False
    start=datetime.strptime(campaign["window_start"] or "09:00","%H:%M").time()
    end=datetime.strptime(campaign["window_end"] or "17:00","%H:%M").time()
    return start <= local.time() <= end

def campaign_validation(campaign):
    zone=campaign_zone(campaign)
    launch=campaign_dt(campaign["launch_at"],zone)
    deadline=campaign_dt(campaign["send_by"],zone)
    if launch and deadline and deadline < launch:
        raise ValueError("Send-by deadline must be after launch time")
    start=datetime.strptime(campaign["window_start"] or "09:00","%H:%M")
    end=datetime.strptime(campaign["window_end"] or "17:00","%H:%M")
    if end <= start:
        raise ValueError("Sending window end must be after start")
    days={x.strip() for x in (campaign["business_days"] or "").split(",") if x.strip()}
    if not days or not days.issubset({"Mon","Tue","Wed","Thu","Fri","Sat","Sun"}):
        raise ValueError("Business days are invalid")
    return launch,deadline

def queue_campaign(campaign_id):
    c=db()
    campaign=c.execute("SELECT * FROM campaigns WHERE id=?",(campaign_id,)).fetchone()
    if not campaign:
        c.close()
        raise ValueError("Campaign not found")
    if campaign["group_name"]:
        recipients=c.execute("SELECT id FROM recipients WHERE status!='Suppressed' AND group_name=? ORDER BY id",(campaign["group_name"],)).fetchall()
    else:
        recipients=c.execute("SELECT id FROM recipients WHERE status!='Suppressed' ORDER BY id").fetchall()
    for rec in recipients:
        c.execute("""INSERT OR IGNORE INTO campaign_queue
                     (campaign_id,recipient_id,status,attempts,next_attempt_at,queued_at,updated_at)
                     VALUES(?,?,?,?,?,?,?)""",(campaign_id,rec["id"],"Pending",0,now(),now(),now()))
    c.execute("UPDATE campaigns SET targeted=?,updated_at=? WHERE id=?",(len(recipients),now(),campaign_id))
    c.commit()
    c.close()
    return len(recipients)

SAFE_TEMPLATE_VARIABLES=("name","email","employee_id","department","designation","location","manager","language","timezone","campaign_name","tracking_link","report_link","qr_link")

def render_template_variables(body,recipient,campaign,links):
    values={
        "name":recipient["name"] or "",
        "email":recipient["email"] or "",
        "employee_id":recipient["employee_id"] or "",
        "department":recipient["department"] or "",
        "designation":recipient["designation"] or "",
        "location":recipient["location"] or "",
        "manager":recipient["manager"] or "",
        "language":recipient["language"] or "",
        "timezone":recipient["timezone"] or "",
        "campaign_name":campaign["name"] or "",
        "tracking_link":links["tracking_link"],
        "report_link":links["report_link"],
        "qr_link":links["qr_link"]
    }
    return re.sub(r"\{\{\s*([a-z_]+)\s*\}\}",lambda m:esc(str(values.get(m.group(1),m.group(0)))),body or "")

def _send_campaign_recipient(campaign,rec,queue_id):
    c=db()
    c.execute("UPDATE campaign_queue SET status='Sending',attempts=attempts+1,updated_at=? WHERE id=?",(now(),queue_id))
    c.execute("INSERT INTO campaign_deliveries(campaign_id,recipient_id,status,attempted_at) VALUES(?,?,?,?)",(campaign["id"],rec["id"],"Attempted",now()))
    delivery_id=c.execute("SELECT last_insert_rowid() id").fetchone()["id"]
    c.commit()
    c.close()
    token=create_tracking_token(campaign["id"],rec["id"])
    link=PUBLIC_BASE_URL+"/"+str(campaign["template"])+".html?"+urlencode({"t":token})
    msg=EmailMessage()
    msg["From"]=formataddr((campaign["template_from_name"] or campaign["from_name"] or "Trust PhishGuard",campaign["template_from_email"] or campaign["from_email"]))
    if campaign["template_reply_to"] or campaign["reply_to"]:
        msg["Reply-To"]=campaign["template_reply_to"] or campaign["reply_to"]
    msg["To"]=rec["email"]
    msg["Subject"]=campaign["subject"] or "Security Awareness Simulation"
    links={"tracking_link":link,"report_link":PUBLIC_BASE_URL+"/report?t="+token,"qr_link":PUBLIC_BASE_URL+"/qr?t="+token}
    if campaign["template_status"] and campaign["template_status"]!="Active":
        raise RuntimeError("Selected template is archived")
    html_body=render_template_variables(campaign["template_html"],rec,campaign,links)
    text_body=render_template_variables(campaign["template_text"],rec,campaign,links)
    if not html_body:
        html_body="<p>Hello %s,</p><p>%s</p><p><a href=\"%s\">Review the message</a></p><p><a href=\"%s\">Report this simulation</a></p>"%(esc(rec["name"] or "Colleague"),esc(campaign["subject"] or "Security Awareness Simulation"),esc(link),esc(links["report_link"]))
    if not text_body:
        text_body="Hello %s,\n\n%s\n\nReview the message here:\n%s\n\nReport this simulation:\n%s\n\nQR scan tracking endpoint:\n%s"%(rec["name"] or "Colleague",campaign["subject"] or "Security Awareness Simulation",link,links["report_link"],links["qr_link"])
    msg.set_content(text_body+"\n\nThis email is part of an authorized internal security-awareness simulation. No password, OTP, PIN, CVV or full card number is requested.")
    msg.add_alternative(html_body,subtype="html")
    smtp=None
    try:
        smtp=smtp_connect(campaign)
        smtp.send_message(msg)
        c=db()
        c.execute("UPDATE campaign_deliveries SET status='Sent',sent_at=?,error=NULL WHERE id=?",(now(),delivery_id))
        c.execute("UPDATE campaign_queue SET status='Sent',next_attempt_at=NULL,last_error=NULL,updated_at=? WHERE id=?",(now(),queue_id))
        c.execute("UPDATE recipients SET status='Sent' WHERE id=?",(rec["id"],))
        c.commit()
        c.close()
        record("smtp",str(campaign["template"]),"delivered",rec["name"] or "",rec["email"] or "",rec["mobile"] or "","campaign-delivery",rec["employee_id"] or "","",campaign["id"],rec["id"],token)
        return True
    except Exception as e:
        err=str(e)[:500]
        retry_at=(datetime.now(timezone.utc)+timedelta(seconds=max(1,int(campaign["retry_backoff_seconds"] or 5)))).isoformat()
        c=db()
        c.execute("UPDATE campaign_deliveries SET status='Failed',error=? WHERE id=?",(err,delivery_id))
        c.execute("UPDATE campaign_queue SET status='Failed',last_error=?,next_attempt_at=?,updated_at=? WHERE id=?",(err,retry_at,now(),queue_id))
        c.commit()
        c.close()
        return False
    finally:
        if smtp:
            try: smtp.quit()
            except Exception: pass

def campaign_prelaunch_validation(campaign):
    errors=[]
    if not campaign: return ["Campaign not found."]
    if not os.environ.get("PUBLIC_BASE_URL","").strip(): errors.append("PUBLIC_BASE_URL is not configured.")
    c=db()
    smtp=c.execute("SELECT * FROM smtp_profiles WHERE id=? AND enabled=1",(campaign["smtp_profile_id"],)).fetchone() if campaign["smtp_profile_id"] else None
    landing=c.execute("SELECT * FROM landing_pages WHERE id=? AND status='Enabled'",(campaign["landing_page_id"],)).fetchone() if campaign["landing_page_id"] else None
    template=c.execute("SELECT status,html_body FROM template_library WHERE template=?",(campaign["template"],)).fetchone()
    group=campaign["group_name"] or ""
    recipient_count=c.execute("SELECT COUNT(*) n FROM recipients WHERE status!='Suppressed' AND (group_name=? OR ?='')",(group,group)).fetchone()["n"]
    c.close()
    if not smtp: errors.append("Enabled SMTP provider is required.")
    if not landing: errors.append("Enabled landing page is required.")
    if template and (template["status"] or "Active")!="Active": errors.append("Selected template is archived.")
    if template:
        ok,msg=validate_template_html(template["html_body"] or "")
        if not ok: errors.append(msg)
    if not recipient_count: errors.append("No eligible recipients are available.")
    if not (campaign["subject"] or "").strip(): errors.append("Campaign subject is required.")
    if not re.fullmatch(r"\d+",str(campaign["template"] or "")): errors.append("Template selection is invalid.")
    ok,msg=validate_landing_html(landing["html_body"] if landing else "")
    if landing and not ok: errors.append(msg)
    try:
        zone=ZoneInfo(campaign["timezone"] or "Asia/Dhaka")
        if campaign["launch_at"] and campaign["send_by"] and campaign_dt(campaign["send_by"],zone)<campaign_dt(campaign["launch_at"],zone):
            errors.append("Send-by deadline must be on or after launch time.")
        datetime.strptime(campaign["window_start"],"%H:%M")
        datetime.strptime(campaign["window_end"],"%H:%M")
        if datetime.strptime(campaign["window_end"],"%H:%M")<=datetime.strptime(campaign["window_start"],"%H:%M"): errors.append("Sending window end must be later than start.")
    except Exception:
        errors.append("Campaign timezone or sending-window settings are invalid.")
    return errors

def send_campaign(campaign_id,scheduled=False):
    if not PUBLIC_BASE_URL:
        raise RuntimeError("PUBLIC_BASE_URL is not configured")
    c=db()
    campaign=c.execute("""SELECT c.*,s.host,s.port,s.security,s.username,s.password_enc,s.from_name,s.from_email,s.reply_to,
                          t.html_body template_html,t.text_body template_text,t.from_name template_from_name,t.from_email template_from_email,t.reply_to template_reply_to,t.status template_status
                          FROM campaigns c JOIN smtp_profiles s ON s.id=c.smtp_profile_id
                          LEFT JOIN template_library t ON t.template=c.template
                          WHERE c.id=? AND s.enabled=1""",(campaign_id,)).fetchone()
    c.close()
    if not campaign:
        raise RuntimeError("Campaign or SMTP profile not found")
    campaign_validation(campaign)
    queued=queue_campaign(campaign_id)
    if campaign["cancel_requested"] or campaign["status"] in ("Cancelled","Paused"):
        return 0,0,queued
    if scheduled and not campaign_window_open(campaign):
        return 0,0,queued
    c=db()
    c.execute("UPDATE campaigns SET status='Active',updated_at=? WHERE id=?",(now(),campaign_id))
    c.commit()
    limit=max(1,int(campaign["batch_size"] or 50)) if scheduled else -1
    qrows=c.execute("""SELECT q.*,r.* FROM campaign_queue q JOIN recipients r ON r.id=q.recipient_id
                       WHERE q.campaign_id=? AND q.status IN ('Pending','Failed')
                       AND (q.next_attempt_at IS NULL OR q.next_attempt_at<=?)
                       AND r.status!='Suppressed' ORDER BY q.id LIMIT ?""",(campaign_id,now(),limit)).fetchall()
    c.close()
    sent=failed=0
    interval=60.0/max(1,int(campaign["rate_per_minute"] or 60))
    for idx,q in enumerate(qrows):
        c=db()
        current=c.execute("SELECT status,cancel_requested FROM campaigns WHERE id=?",(campaign_id,)).fetchone()
        c.close()
        if not current or current["cancel_requested"] or current["status"] in ("Cancelled","Paused"):
            break
        if not campaign_window_open(campaign):
            break
        if campaign["send_by"]:
            deadline=campaign_dt(campaign["send_by"],campaign_zone(campaign))
            if deadline and datetime.now(timezone.utc)>deadline.astimezone(timezone.utc):
                c=db()
                c.execute("UPDATE campaigns SET status='Expired',updated_at=? WHERE id=?",(now(),campaign_id))
                c.execute("UPDATE campaign_queue SET status='Cancelled',updated_at=? WHERE campaign_id=? AND status IN ('Pending','Failed')",(now(),campaign_id))
                c.commit()
                c.close()
                break
        attempts=max(1,int(campaign["retry_max"] or 2)+1)
        ok=False
        for attempt in range(attempts):
            ok=_send_campaign_recipient(campaign,q,q["id"])
            if ok:
                break
            if attempt < attempts-1:
                time.sleep(max(1,int(campaign["retry_backoff_seconds"] or 5))*(attempt+1))
        if ok:
            sent+=1
        else:
            failed+=1
        if idx < len(qrows)-1:
            time.sleep(interval)
    c=db()
    pending=c.execute("SELECT COUNT(*) n FROM campaign_queue WHERE campaign_id=? AND status IN ('Pending','Failed')",(campaign_id,)).fetchone()["n"]
    current=c.execute("SELECT status,cancel_requested FROM campaigns WHERE id=?",(campaign_id,)).fetchone()
    if current and current["cancel_requested"]:
        c.execute("UPDATE campaign_queue SET status='Cancelled',updated_at=? WHERE campaign_id=? AND status IN ('Pending','Failed')",(now(),campaign_id))
        c.execute("UPDATE campaigns SET status='Cancelled',updated_at=? WHERE id=?",(now(),campaign_id))
    elif pending==0:
        c.execute("UPDATE campaigns SET status='Completed',updated_at=? WHERE id=?",(now(),campaign_id))
    else:
        c.execute("UPDATE campaigns SET status='Active',updated_at=? WHERE id=?",(now(),campaign_id))
    c.commit()
    c.close()
    return sent,failed,queued

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

def report_window(query):
    end_s=(query.get("end",[""])[0] or "").strip()
    start_s=(query.get("start",[""])[0] or "").strip()
    now_utc=datetime.now(timezone.utc)
    end_dt=datetime.fromisoformat(end_s).replace(tzinfo=timezone.utc)+timedelta(days=1) if end_s else now_utc+timedelta(days=1)
    start_dt=datetime.fromisoformat(start_s).replace(tzinfo=timezone.utc) if start_s else end_dt-timedelta(days=30)
    if start_dt>=end_dt:
        raise ValueError("Start date must be before end date.")
    return start_dt.isoformat(),end_dt.isoformat(),start_dt.date().isoformat(),(end_dt-timedelta(days=1)).date().isoformat()

def pdf_escape(value):
    text_value=str(value or "").replace("\\","\\\\").replace("(","\\(").replace(")","\\)")
    return text_value.encode("latin-1","replace").decode("latin-1")

def build_pdf(lines,title="Trust PhishGuard Report"):
    # Minimal dependency-free PDF writer for RHEL/python-stdlib deployments.
    page_lines=[]; current=[]
    for line in lines:
        if len(current)>=48:
            page_lines.append(current); current=[]
        current.append(str(line)[:105])
    if current or not page_lines: page_lines.append(current)
    objects=[]
    page_ids=[]; content_ids=[]
    for page in page_lines:
        content="BT /F1 10 Tf 42 750 Td 14 TL "
        first=True
        for line in page:
            if not first: content+="T* "
            content+="("+pdf_escape(line)+") Tj "
            first=False
        content+="ET"
        cb=content.encode("latin-1","replace")
        content_ids.append(len(objects)+4)
        objects.extend([None,None,None])
        page_ids.append(len(objects)+4)
        objects.append(None)
    # Rebuild deterministic object list: catalog, pages, font, then content/page pairs.
    objs=[None,None,None]
    kids=[]
    for page in page_lines:
        content="BT /F1 10 Tf 42 750 Td 14 TL "
        for n,line in enumerate(page):
            if n: content+="T* "
            content+="("+pdf_escape(line)+") Tj "
        content+=" ET"
        stream=content.encode("latin-1","replace")
        content_obj=len(objs)+1; objs.append(("stream",stream))
        page_obj=len(objs)+1; objs.append(("page",content_obj))
        kids.append(page_obj)
    objs[0]=("catalog",None); objs[1]=("pages",kids); objs[2]=("font",None)
    out=bytearray(b"%PDF-1.4\n%\xe2\xe3\\xcf\xd3\n"); offsets=[0]
    for num,obj in enumerate(objs,1):
        offsets.append(len(out)); out.extend(("%d 0 obj\n"%num).encode())
        if obj[0]=="catalog": out.extend(b"<< /Type /Catalog /Pages 2 0 R >>\n")
        elif obj[0]=="pages": out.extend(("<< /Type /Pages /Kids [%s] /Count %d >>\n"%(" ".join("%d 0 R"%x for x in obj[1]),len(obj[1]))).encode())
        elif obj[0]=="font": out.extend(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\n")
        elif obj[0]=="stream": out.extend(("<< /Length %d >>\nstream\n"%len(obj[1])).encode()); out.extend(obj[1]); out.extend(b"\nendstream\n")
        elif obj[0]=="page": out.extend(("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>\n"%obj[1]).encode())
        out.extend(b"endobj\n")
    xref=len(out); out.extend(("xref\n0 %d\n"%(len(objs)+1)).encode()); out.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]: out.extend(("%010d 00000 n \n"%off).encode())
    out.extend(("trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n"%(len(objs)+1,xref)).encode())
    return bytes(out)

def report_metric_sql(alias="e"):
    return """COALESCE(SUM(CASE WHEN %s.event='click' THEN 1 ELSE 0 END),0) clicks,
COALESCE(SUM(CASE WHEN %s.event='form_action' THEN 1 ELSE 0 END),0) actions,
COALESCE(SUM(CASE WHEN %s.event='report' THEN 1 ELSE 0 END),0) reports"""%(alias,alias,alias)

class Handler(BaseHTTPRequestHandler):
    def sendbody(self,code,body,ctype="text/html; charset=utf-8",extra=None):
        b=body.encode() if isinstance(body,str) else body
        self.send_response(code)
        self.send_header("Content-Type",ctype)
        self.send_header("Content-Length",str(len(b)))
        self.send_header("X-Content-Type-Options","nosniff")
        self.send_header("X-Frame-Options","DENY")
        self.send_header("Referrer-Policy","same-origin")
        self.send_header("Permissions-Policy","camera=(),microphone=(),geolocation=()")
        if extra:
            for k,v in extra.items(): self.send_header(k,v)
        self.end_headers()
        if self.command!="HEAD": self.wfile.write(b)

    def auth(self):
        c=cookies.SimpleCookie(self.headers.get("Cookie",""))
        s=c.get("admin_session")
        session=SESSIONS.get(s.value) if s else None
        if not session: return False
        now_ts=time.time()
        if now_ts-session["created_at"]>28800 or now_ts-session.get("last_seen",session["created_at"])>1800:
            SESSIONS.pop(s.value,None)
            return False
        session["last_seen"]=now_ts
        return True

    def current_admin(self):
        c=cookies.SimpleCookie(self.headers.get("Cookie",""))
        s=c.get("admin_session")
        return SESSIONS.get(s.value) if s else None

    def csrf_origin_ok(self):
        origin=self.headers.get("Origin","").strip()
        referer=self.headers.get("Referer","").strip()
        source=origin or referer
        if not source:
            return False
        try:
            return urlparse(source).netloc==self.headers.get("Host","")
        except Exception:
            return False

    def login_allowed(self):
        now_ts=time.time()
        bucket=LOGIN_ATTEMPTS.get(self.client_address[0],[])
        bucket=[x for x in bucket if now_ts-x<300]
        LOGIN_ATTEMPTS[self.client_address[0]]=bucket
        return len(bucket)<5

    def login_failed(self):
        LOGIN_ATTEMPTS.setdefault(self.client_address[0],[]).append(time.time())

    def role_allowed(self,path):
        admin=self.current_admin()
        if not admin: return False
        role=admin.get("role","Administrator")
        if role=="Administrator": return True
        permissions={
            "Campaign Manager":("/admin/campaigns","/admin/templates","/admin/landing-pages","/admin/recipients","/admin/groups","/admin/training"),
            "Reporting Analyst":("/admin/reports","/admin/risk","/admin/exports"),
            "SMTP Manager":("/admin/smtp",),
            "Security Auditor":("/admin/audit",)
        }
        return any(path==prefix or path.startswith(prefix+"/") for prefix in permissions.get(role,()))

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
        nav=[("Overview","/admin"),("Campaigns","/admin/campaigns"),("Templates","/admin/templates"),("Landing Pages","/admin/landing-pages"),("SMTP Providers","/admin/smtp"),("Training","/admin/training"),("Recipients","/admin/recipients"),("Groups & Departments","/admin/groups"),("Users & Groups","/admin/users"),("Reports","/admin/reports"),("Risk & Trends","/admin/risk"),("Exports","/admin/exports"),("Settings","/admin/settings"),("Audit Log","/admin/audit"),("Admin Users","/admin/admins")]
        links="".join('<a href="%s" class="%s">%s</a>'%(u,"active" if n==active else "",n) for n,u in nav)
        css=DASH_CSS+".layout{display:grid;grid-template-columns:220px 1fr;min-height:calc(100vh - 68px)}.side{background:#0b241c;color:#b8d1c8;padding:16px}.side a{display:block;padding:9px;border-radius:8px;text-decoration:none;font-size:12px;margin:2px 0}.side a:hover,.side a.active{background:#164536;color:#fff}.main{padding:26px;max-width:1500px}.card{background:#fff;border:1px solid #e0e9e5;border-radius:14px;padding:18px}.table{width:100%;border-collapse:collapse;font-size:12px}.table th,.table td{padding:10px;border-bottom:1px solid #edf1ef;text-align:left}.table th{background:#f7faf8}.btn{display:inline-block;padding:9px 12px;border-radius:8px;border:1px solid #d5e0dc;text-decoration:none;font-size:12px;font-weight:700}.primary{background:#087b59;color:#fff}.form{display:grid;gap:12px;max-width:700px}.form input,.form select{padding:10px;border:1px solid #ccd9d4;border-radius:8px}.pill{padding:4px 8px;border-radius:999px;background:#eaf6f1;color:#087b59;font-size:10px;font-weight:800}@media(max-width:800px){.layout{grid-template-columns:1fr}.side{display:flex;overflow:auto}.side a{white-space:nowrap}}";
        body='<header style="height:68px;background:#071b15;color:#fff;display:flex;align-items:center;justify-content:space-between;padding:0 25px"><b>✓ Trust PhishGuard</b><span><a style="color:#fff;margin-right:15px" href="/admin.csv">CSV</a><a style="color:#fff" href="/admin/logout">Logout</a></span></header><div class="layout"><aside class="side">'+links+'</aside><main class="main">'+content+'</main></div>';
        return page(title,body,css)

    def feature_page(self,path,query=""):
        c=db()
        if path=="/admin/campaigns":
            rows=c.execute("SELECT * FROM campaigns ORDER BY id DESC").fetchall(); c.close()
            table="".join('<tr><td>%s</td><td>%s</td><td>Template %s</td><td>%s</td><td><span class="pill">%s</span></td><td><a class="btn" href="/admin/campaigns?id=%s">Edit</a></td></tr>'%(r["id"],esc(r["name"]),esc(r["template"]),r["targeted"],esc(r["status"]),r["id"]) for r in rows) or '<tr><td colspan="6">No campaigns yet.</td></tr>'
            return self.admin_shell("Campaigns",'<h1>Campaigns</h1><p>Create, pause and complete simulation campaigns.</p><p><a class="btn primary" href="/admin/campaigns/new">+ New Campaign</a></p><div class="card"><table class="table"><tr><th>ID</th><th>Name</th><th>Template</th><th>Targeted</th><th>Status</th><th></th></tr>'+table+'</table></div>',"Campaigns")
        if path=="/admin/templates":
            rows=c.execute("SELECT * FROM template_library ORDER BY CAST(template AS INTEGER)").fetchall()
            c.close()
            table="".join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><span class="pill">%s</span></td><td><a class="btn" href="/admin/templates?id=%s">Edit</a> <a class="btn" target="_blank" href="/%s.html">Preview</a></td></tr>'%
                         (esc(r["template"]),esc(r["name"]),esc(r["category"]),esc(r["difficulty"]),esc(r["language"]), "Enabled",esc(r["template"]),esc(r["template"])) for r in rows)
            return self.admin_shell("Templates",'<h1>Email Templates & Payloads</h1><p>Enterprise-style simulation payload metadata, HTML/plain-text content and preview.</p><p><a class="btn primary" href="/admin/templates?id=1">Open Template Builder</a></p><div class="card"><table class="table"><tr><th>ID</th><th>Name</th><th>Category</th><th>Difficulty</th><th>Language</th><th>Status</th><th></th></tr>'+table+'</table></div>',"Templates")
        if path=="/admin/landing-pages":
            rows=c.execute("SELECT * FROM landing_pages ORDER BY id").fetchall(); c.close()
            table="".join('<tr><td>%s</td><td>%s</td><td>%s</td><td>v%s</td><td><a class="btn" href="/admin/landing-pages?id=%s">Edit</a> <a class="btn" target="_blank" href="/admin/landing-pages/preview?id=%s">Preview</a></td></tr>'%(r["id"],esc(r["name"]),esc(r["status"]),r["version"] or 1,r["id"],r["id"]) for r in rows)
            return self.admin_shell("Landing Pages",'<h1>Landing Pages</h1><p>Simulation-safe landing page editor with version history and field-policy validation.</p><div class="card"><table class="table"><tr><th>ID</th><th>Name</th><th>Status</th><th>Version</th><th></th></tr>'+table+'</table></div>',"Landing Pages")
        if path=="/admin/smtp":
            rows=c.execute("SELECT id,name,provider,host,port,security,username,from_name,from_email,reply_to,enabled,updated_at FROM smtp_profiles ORDER BY id DESC").fetchall(); c.close()
            table="".join('<tr><td>%s</td><td>%s</td><td>%s:%s</td><td>%s</td><td>%s</td><td><span class="pill">%s</span></td><td><a class="btn" href="/admin/smtp?id=%s">Edit</a></td></tr>'%(r["id"],esc(r["name"]),esc(r["host"]),r["port"],esc(r["security"]),esc(r["from_email"]),"Enabled" if r["enabled"] else "Disabled",r["id"]) for r in rows) or '<tr><td colspan="7">No SMTP profiles configured.</td></tr>'
            note='<div style="margin:12px 0;padding:12px;background:#edf8f4;border-radius:9px;font-size:12px;color:#2b6554">SMTP passwords are encrypted at rest with a server-local 0600 key. They are never displayed, exported or committed to Git.</div>'
            return self.admin_shell("SMTP Providers",'<h1>SMTP Providers</h1><p>Enterprise mail-delivery profiles for simulation campaigns and test messages.</p>'+note+'<p><a class="btn primary" href="/admin/smtp/new">+ Add SMTP Provider</a></p><div class="card"><table class="table"><tr><th>ID</th><th>Name</th><th>Server</th><th>Security</th><th>From</th><th>Status</th><th></th></tr>'+table+'</table></div>',"SMTP Providers")
        if path=="/admin/training":
            courses=c.execute("SELECT * FROM training_courses ORDER BY id DESC").fetchall()
            assigned=c.execute("""SELECT a.id,a.status,a.result,a.completion,a.score,a.due_at,a.trigger_campaign_id,a.remediation_campaign_id,c.name course,c.passing_score,r.email,r.name,r.department,
                                  tc.name trigger_name,rc.name remediation_name
                                  FROM training_assignments a JOIN training_courses c ON c.id=a.course_id
                                  JOIN recipients r ON r.id=a.recipient_id
                                  LEFT JOIN campaigns tc ON tc.id=a.trigger_campaign_id
                                  LEFT JOIN campaigns rc ON rc.id=a.remediation_campaign_id
                                  ORDER BY a.id DESC LIMIT 1000""").fetchall()
            total=len(assigned); completed=sum(1 for x in assigned if x["status"]=="Completed"); passed=sum(1 for x in assigned if x["result"]=="Passed"); failed=sum(1 for x in assigned if x["result"]=="Failed")
            overdue=sum(1 for x in assigned if x["status"] not in ("Completed","Cancelled","Failed") and x["due_at"] and x["due_at"] < now())
            course_rows="".join('<tr><td>%s</td><td>%s</td><td>%s min</td><td>%s%%</td><td><span class="pill">%s</span></td></tr>'%(x["id"],esc(x["name"]),x["duration_minutes"],x["passing_score"],esc(x["status"])) for x in courses) or '<tr><td colspan="5">No training courses.</td></tr>'
            assignment_rows="".join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%.0f%%</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><form method="post" action="/admin/training/update" style="display:flex;gap:4px"><input type="hidden" name="id" value="%s"><input name="completion" type="number" min="0" max="100" step="1" value="%s" style="width:65px"><input name="score" type="number" min="0" max="100" step="1" value="%s" placeholder="score" style="width:65px"><button class="btn">Update</button></form></td></tr>'%(esc(x["email"]),esc(x["name"]),esc(x["department"]),esc(x["course"]),x["completion"] or 0,esc(x["status"]),esc(x["result"] or "Pending"),esc(x["trigger_name"] or "—"),esc(x["remediation_name"] or "—"),x["id"],x["completion"] or 0,"" if x["score"] is None else x["score"]) for x in assigned) or '<tr><td colspan="10">No assignments yet.</td></tr>'
            c.close()
            body=('<h1>Training</h1><p>Assign security-awareness courses after simulations and track completion, pass/fail and remediation linkage without collecting credentials.</p><div class="stats" style="margin:16px 0"><div class="stat"><div class="stat-label">ASSIGNMENTS</div><div class="num">%s</div></div><div class="stat"><div class="stat-label">PASSED</div><div class="num">%s</div></div><div class="stat"><div class="stat-label">FAILED</div><div class="num">%s</div></div><div class="stat"><div class="stat-label">OVERDUE</div><div class="num">%s</div></div></div><p><a class="btn primary" href="/admin/training/new">+ Create Assignment</a> <a class="btn" href="/admin/training/course/new">+ New Course</a></p><div class="card"><h3>Course Catalog</h3><table class="table"><tr><th>ID</th><th>Course</th><th>Duration</th><th>Pass Score</th><th>Status</th></tr>%s</table></div><div class="card" style="margin-top:15px"><h3>Assignments & Results</h3><div class="table-wrap"><table class="table"><tr><th>Email</th><th>Name</th><th>Department</th><th>Course</th><th>Completion</th><th>Status</th><th>Result</th><th>Trigger Campaign</th><th>Remediation Campaign</th><th>Update</th></tr>%s</table></div></div>'%(total,passed,failed,overdue,course_rows,assignment_rows))
            return self.admin_shell("Training",body,"Training")
        if path=="/admin/recipients":
            rows=c.execute("SELECT id,email,name,employee_id,department,designation,location,manager,language,timezone,group_name,status,created_at FROM recipients ORDER BY id DESC LIMIT 1000").fetchall()
            total=c.execute("SELECT COUNT(*) n FROM recipients").fetchone()["n"]
            suppressed=c.execute("SELECT COUNT(*) n FROM recipients WHERE status='Suppressed'").fetchone()["n"]
            imports=c.execute("SELECT id,source_name,processed,created,updated,skipped,errors,created_at FROM recipient_import_history ORDER BY id DESC LIMIT 20").fetchall()
            c.close()
            table="".join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><span class="pill">%s</span></td><td><a class="btn" href="/admin/recipients?id=%s">Profile</a></td></tr>'%(r["id"],esc(r["email"]),esc(r["name"]),esc(r["employee_id"]),esc(r["department"]),esc(r["designation"]),esc(r["location"]),esc(r["status"]),r["id"]) for r in rows) or '<tr><td colspan="9">No recipients imported.</td></tr>'
            ih="".join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>'%(r["id"],esc(r["source_name"] or "Manual/CSV"),r["processed"],r["created"],r["updated"],r["skipped"],esc(r["errors"] or ""),esc(r["created_at"])) for r in imports) or '<tr><td colspan="8">No import history.</td></tr>'
            body='<h1>Recipients</h1><p>Enterprise recipient profiles for authorized simulation targeting. Suppressed recipients are excluded from campaign delivery.</p><div class="stats" style="margin:16px 0"><div class="stat"><div class="stat-label">RECIPIENTS</div><div class="num">%s</div></div><div class="stat"><div class="stat-label">SUPPRESSED</div><div class="num">%s</div></div></div><p><a class="btn primary" href="/admin/recipients/import">+ Import CSV</a></p><div class="card"><div class="table-wrap"><table class="table"><tr><th>ID</th><th>Email</th><th>Name</th><th>Employee ID</th><th>Department</th><th>Designation</th><th>Location</th><th>Status</th><th></th></tr>%s</table></div></div><div class="card" style="margin-top:15px"><h3>Import History</h3><div class="table-wrap"><table class="table"><tr><th>ID</th><th>Source</th><th>Processed</th><th>Created</th><th>Updated</th><th>Skipped</th><th>Errors</th><th>Time</th></tr>%s</table></div></div>'%(total,suppressed,table,ih)
            return self.admin_shell("Recipients",body,"Recipients")
        if path=="/admin/groups":
            rows=c.execute("SELECT g.id,g.name,g.department,COUNT(r.id) members FROM groups_tbl g LEFT JOIN recipients r ON r.group_name=g.name GROUP BY g.id ORDER BY g.id DESC").fetchall(); c.close()
            table="".join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>'%(r["id"],esc(r["name"]),esc(r["department"]),r["members"]) for r in rows) or '<tr><td colspan="4">No groups yet.</td></tr>'
            return self.admin_shell("Groups",'<h1>Groups & Departments</h1><p>Reusable recipient groups for campaign targeting.</p><p><a class="btn primary" href="/admin/groups/new">+ New Group</a></p><div class="card"><table class="table"><tr><th>ID</th><th>Group</th><th>Department</th><th>Members</th></tr>'+table+'</table></div>',"Groups & Departments")
        if path=="/admin/users":
            rows=c.execute("SELECT email,MAX(name) name,MAX(employee_id) employee_id,COUNT(*) events,SUM(event='click') clicks,SUM(event='submitted') submissions FROM events WHERE email!='' GROUP BY email ORDER BY events DESC").fetchall(); c.close()
            table="".join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>'%(esc(r["email"]),esc(r["name"]),esc(r["employee_id"]),r["events"],r["clicks"] or 0,r["submissions"] or 0) for r in rows) or '<tr><td colspan="6">No users recorded yet.</td></tr>'
            return self.admin_shell("Users",'<h1>Users & Groups</h1><p>Observed simulation users and engagement.</p><div class="card"><table class="table"><tr><th>Email</th><th>Name</th><th>Employee ID</th><th>Events</th><th>Clicks</th><th>Submissions</th></tr>'+table+'</table></div>',"Users & Groups")
        if path=="/admin/risk":
            snapshot_risk_history()
            c=db()
            rows=c.execute("SELECT * FROM risk_scores ORDER BY score DESC,email").fetchall()
            departments=c.execute("""SELECT r.department,ROUND(AVG(rs.score),1) score,COUNT(*) members,SUM(rs.failures) failures
                                     FROM recipients r JOIN risk_scores rs ON lower(r.email)=lower(rs.email)
                                     WHERE r.department!='' GROUP BY r.department ORDER BY score DESC""").fetchall()
            campaigns=c.execute("""SELECT c.id,c.name,COALESCE((SELECT COUNT(*) FROM campaign_deliveries d WHERE d.campaign_id=c.id AND d.status='Sent'),0) sent,
                                   COALESCE((SELECT COUNT(*) FROM events e WHERE e.campaign_id=c.id AND e.event='click'),0) clicks,
                                   COALESCE((SELECT COUNT(*) FROM events e WHERE e.campaign_id=c.id AND e.event='form_action'),0) actions,
                                   COALESCE((SELECT COUNT(*) FROM events e WHERE e.campaign_id=c.id AND e.event='report'),0) reports FROM campaigns c ORDER BY c.id DESC LIMIT 100""").fetchall()
            history=c.execute("SELECT * FROM risk_history WHERE scope='user' ORDER BY id DESC LIMIT 50").fetchall(); c.close()
            table="".join('<tr><td>%s</td><td>%s</td><td>%.0f</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>'%(esc(r["email"]),r["failures"],r["score"],esc(r["level"]),"Yes" if r["repeat_offender"] else "No",esc(r["remediation_status"] or "None"),esc(r["factor_summary"] or "")) for r in rows) or '<tr><td colspan="7">No risk data yet.</td></tr>'
            dept="".join('<tr><td>%s</td><td>%s</td><td>%.1f</td><td>%s</td></tr>'%(esc(r["department"]),r["members"],r["score"],r["failures"]) for r in departments) or '<tr><td colspan="4">No department risk data.</td></tr>'
            camp="".join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%.1f%%</td><td>%.1f%%</td><td>%s</td></tr>'%(r["id"],esc(r["name"]),r["sent"],(r["clicks"] or 0)/max(r["sent"],1)*100,(r["actions"] or 0)/max(r["sent"],1)*100,r["reports"] or 0) for r in campaigns) or '<tr><td colspan="6">No campaign risk data.</td></tr>'
            hist="".join('<tr><td>%s</td><td>%s</td><td>%.0f</td><td>%s</td><td>%s</td></tr>'%(esc(r["subject"]),esc(r["recorded_at"]),r["score"],esc(r["level"]),esc(r["factors"] or "")) for r in history) or '<tr><td colspan="5">No risk history yet.</td></tr>'
            body='<h1>Risk & Trends</h1><p>Explainable risk based only on measured click, form-action and report telemetry.</p><div class="card"><h3>User Risk</h3><div class="table-wrap"><table class="table"><tr><th>User</th><th>Failures</th><th>Score</th><th>Risk</th><th>Repeat</th><th>Remediation</th><th>Factors</th></tr>%s</table></div></div><div class="card" style="margin-top:15px"><h3>Department Risk</h3><table class="table"><tr><th>Department</th><th>Members</th><th>Avg Score</th><th>Failures</th></tr>%s</table></div><div class="card" style="margin-top:15px"><h3>Campaign Risk</h3><table class="table"><tr><th>ID</th><th>Campaign</th><th>Sent</th><th>Click Rate</th><th>Action Rate</th><th>Reports</th></tr>%s</table></div><div class="card" style="margin-top:15px"><h3>User Risk History</h3><div class="table-wrap"><table class="table"><tr><th>User</th><th>Recorded</th><th>Score</th><th>Risk</th><th>Factors</th></tr>%s</table></div></div>'%(table,dept,camp,hist)
            return self.admin_shell("Risk",body,"Risk & Trends")
        if path=="/admin/audit":
            rows=c.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200").fetchall(); c.close()
            table="".join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>'%(esc(format_datetime(r["ts"])[0]),esc(format_datetime(r["ts"])[1]),esc(r["action"]),esc(r["details"])) for r in rows) or '<tr><td colspan="4">No audit records.</td></tr>'
            return self.admin_shell("Audit",'<h1>Audit Log</h1><p>Administrative actions and exports.</p><div class="card"><table class="table"><tr><th>Date</th><th>Time</th><th>Action</th><th>Details</th></tr>'+table+'</table></div>',"Audit Log")
        if path=="/admin/reports.pdf":
            try: start_iso,end_iso,start_day,end_day=report_window(parse_qs(query))
            except ValueError as e: return self.sendbody(400,esc(str(e)),"text/plain")
            c=db()
            total=c.execute("SELECT COUNT(*) n FROM events WHERE ts>=? AND ts<?",(start_iso,end_iso)).fetchone()["n"]
            clicks=c.execute("SELECT COUNT(*) n FROM events WHERE ts>=? AND ts<? AND event='click'",(start_iso,end_iso)).fetchone()["n"]
            actions=c.execute("SELECT COUNT(*) n FROM events WHERE ts>=? AND ts<? AND event='form_action'",(start_iso,end_iso)).fetchone()["n"]
            reports=c.execute("SELECT COUNT(*) n FROM events WHERE ts>=? AND ts<? AND event='report'",(start_iso,end_iso)).fetchone()["n"]
            delivered=c.execute("SELECT COUNT(*) n FROM campaign_deliveries WHERE sent_at>=? AND sent_at<? AND status='Sent'",(start_iso,end_iso)).fetchone()["n"]
            training_assigned=c.execute("SELECT COUNT(*) n FROM training_assignments WHERE assigned_at>=? AND assigned_at<?",(start_iso,end_iso)).fetchone()["n"]
            training_completed=c.execute("SELECT COUNT(*) n FROM training_assignments WHERE completed_at>=? AND completed_at<?",(start_iso,end_iso)).fetchone()["n"]
            risk_rows=c.execute("SELECT level,COUNT(*) n FROM risk_scores GROUP BY level").fetchall()
            campaign_rows=c.execute("""SELECT c.name,c.status,c.targeted,
                COALESCE((SELECT COUNT(*) FROM campaign_deliveries d WHERE d.campaign_id=c.id AND d.sent_at>=? AND d.sent_at<? AND d.status='Sent'),0) sent,
                COALESCE((SELECT COUNT(*) FROM events e WHERE e.campaign_id=c.id AND e.ts>=? AND e.ts<? AND e.event='click'),0) clicks,
                COALESCE((SELECT COUNT(*) FROM events e WHERE e.campaign_id=c.id AND e.ts>=? AND e.ts<? AND e.event='form_action'),0) actions,
                COALESCE((SELECT COUNT(*) FROM events e WHERE e.campaign_id=c.id AND e.ts>=? AND e.ts<? AND e.event='report'),0) reports
                FROM campaigns c ORDER BY c.id DESC LIMIT 25""",(start_iso,end_iso,start_iso,end_iso,start_iso,end_iso,start_iso,end_iso)).fetchall()
            c.close()
            lines=["Trust PhishGuard — Executive Report","Period: %s to %s"%(start_day,end_day),"","Measured activity","Total events: %s"%total,"Delivered: %s"%delivered,"Clicks: %s"%clicks,"Actions: %s"%actions,"Reports: %s"%reports,"Click rate: %.1f%%"%((clicks/max(delivered,1))*100),"Action rate: %.1f%%"%((actions/max(clicks,1))*100),"Report rate: %.1f%%"%((reports/max(clicks,1))*100),"","Training","Assigned: %s"%training_assigned,"Completed: %s"%training_completed,"Completion: %.1f%%"%((training_completed/max(training_assigned,1))*100),"","Current risk mix"]
            lines.extend("%s: %s"%(r["level"],r["n"]) for r in risk_rows)
            lines.extend(["","","Campaign summary"])
            for r in campaign_rows:
                lines.append("%s | %s | targeted=%s sent=%s clicks=%s actions=%s reports=%s"%(r["name"],r["status"],r["targeted"],r["sent"],r["clicks"],r["actions"],r["reports"]))
            lines.append("")
            lines.append("Metrics reflect measured simulation telemetry only; unmeasured opens are not inferred.")
            audit(ADMIN_USERNAME,"report_pdf_export","Period %s to %s"%(start_day,end_day),self.client_address[0])
            pdf=build_pdf(lines)
            return self.sendbody(200,pdf,"application/pdf",{"Content-Disposition":'attachment; filename="phishguard-report-%s-to-%s.pdf"'%(start_day,end_day)})
        if path=="/admin/reports" and not parse_qs(query).get("view",[""])[0]:
            try: start_iso,end_iso,start_day,end_day=report_window(parse_qs(query))
            except ValueError as e: return self.sendbody(400,esc(str(e)),"text/plain")
            c=db()
            total=c.execute("SELECT COUNT(*) n FROM events WHERE ts>=? AND ts<?",(start_iso,end_iso)).fetchone()["n"]
            clicks=c.execute("SELECT COUNT(*) n FROM events WHERE ts>=? AND ts<? AND event='click'",(start_iso,end_iso)).fetchone()["n"]
            subs=c.execute("SELECT COUNT(*) n FROM events WHERE ts>=? AND ts<? AND event='form_action'",(start_iso,end_iso)).fetchone()["n"]
            reports=c.execute("SELECT COUNT(*) n FROM events WHERE ts>=? AND ts<? AND event='report'",(start_iso,end_iso)).fetchone()["n"]
            campaigns=c.execute("""SELECT c.id,c.name,c.status,c.targeted,
                COALESCE((SELECT COUNT(*) FROM campaign_deliveries d WHERE d.campaign_id=c.id AND d.status='Sent' AND d.sent_at>=? AND d.sent_at<?),0) sent,
                COALESCE((SELECT COUNT(*) FROM campaign_deliveries d WHERE d.campaign_id=c.id AND d.status='Failed' AND d.attempted_at>=? AND d.attempted_at<?),0) failed,
                COALESCE((SELECT COUNT(*) FROM events e WHERE e.campaign_id=c.id AND e.event='click' AND e.ts>=? AND e.ts<?),0) clicks,
                COALESCE((SELECT COUNT(*) FROM events e WHERE e.campaign_id=c.id AND e.event='form_action' AND e.ts>=? AND e.ts<?),0) actions,
                COALESCE((SELECT COUNT(*) FROM events e WHERE e.campaign_id=c.id AND e.event='report' AND e.ts>=? AND e.ts<?),0) reports
                FROM campaigns c ORDER BY c.id DESC""",(start_iso,end_iso,start_iso,end_iso,start_iso,end_iso,start_iso,end_iso,start_iso,end_iso)).fetchall(); c.close()
            rate=subs/clicks*100 if clicks else 0; report_rate=reports/clicks*100 if clicks else 0
            rows="".join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%.1f%%</td><td>%.1f%%</td><td><a class="btn" href="/admin/reports?campaign_id=%s">Details</a></td></tr>'%(r["id"],esc(r["name"]),esc(r["status"]),r["targeted"],r["sent"],r["failed"],r["clicks"],(r["actions"] or 0)/(r["clicks"] or 1)*100,(r["reports"] or 0)/(r["clicks"] or 1)*100,r["id"]) for r in campaigns) or '<tr><td colspan="10">No campaign telemetry in this period.</td></tr>'
            controls='<div class="card"><form method="get" class="filter"><label>Start <input type="date" name="start" value="%s"></label><label>End <input type="date" name="end" value="%s"></label><button class="btn primary">Apply</button><a class="btn" href="/admin/reports">Last 30 Days</a><a class="btn" href="/admin/reports.pdf?start=%s&end=%s">PDF Report</a></form></div>'%(esc(start_day),esc(end_day),esc(start_day),esc(end_day))
            return self.admin_shell("Reports",'<h1>Campaign Reports</h1><p>Measured telemetry · %s to %s.</p>%s<div class="card"><h3>Overall</h3><p>Events: %s · Clicks: %s · Actions: %s · Reports: %s · Action rate: %.1f%% · Report rate: %.1f%%</p></div><div class="card"><p><a class="btn" href="/admin/reports?view=compare">Campaign Comparison</a> <a class="btn" href="/admin/reports?view=department">Department Report</a> <a class="btn" href="/admin/reports?view=monthly">Monthly Report</a> <a class="btn" href="/admin/reports?view=executive">Executive Dashboard</a> <a class="btn" href="/admin/reports?view=trend">Risk & Resilience Trends</a> <a class="btn" href="/admin/reports/scheduled">Scheduled Reports</a></p><table class="table"><tr><th>ID</th><th>Campaign</th><th>Status</th><th>Targeted</th><th>Sent</th><th>Failed</th><th>Clicks</th><th>Action Rate</th><th>Report Rate</th><th></th></tr>%s</table></div>'%(esc(start_day),esc(end_day),controls,total,clicks,subs,reports,rate,report_rate,rows),"Reports")
        if path=="/admin/reports" and parse_qs(query).get("view",[""])[0]=="department":
            try: start_iso,end_iso,start_day,end_day=report_window(parse_qs(query))
            except ValueError as e: return self.sendbody(400,esc(str(e)),"text/plain")
            c=db(); rows=c.execute("""SELECT COALESCE(r.department,'Unassigned') department,
                COUNT(DISTINCT r.id) users,
                COUNT(DISTINCT CASE WHEN e.event='click' THEN r.id END) clicked_users,
                COUNT(DISTINCT CASE WHEN e.event='form_action' THEN r.id END) action_users,
                COUNT(DISTINCT CASE WHEN e.event='report' THEN r.id END) report_users,
                COUNT(e.id) events
                FROM recipients r LEFT JOIN events e ON lower(e.email)=lower(r.email) AND e.ts>=? AND e.ts<?
                GROUP BY COALESCE(r.department,'Unassigned') ORDER BY action_users DESC,clicked_users DESC""",(start_iso,end_iso)).fetchall(); c.close()
            table="".join("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"%(esc(x["department"]),x["users"],x["clicked_users"],x["action_users"],x["report_users"],x["events"]) for x in rows) or "<tr><td colspan='6'>No department telemetry.</td></tr>"
            return self.admin_shell("Department Report",'<h1>Department Report</h1><p>Unique users with measured simulation events · %s to %s.</p><div class="card"><form method="get" class="filter"><input type="hidden" name="view" value="department"><label>Start <input type="date" name="start" value="%s"></label><label>End <input type="date" name="end" value="%s"></label><button class="btn primary">Apply</button><a class="btn" href="/admin/reports">Campaign Reports</a></form></div><div class="card"><table class="table"><tr><th>Department</th><th>Users</th><th>Clicked Users</th><th>Action Users</th><th>Reported Users</th><th>Events</th></tr>%s</table></div>'%(esc(start_day),esc(end_day),table),"Reports")
        if path=="/admin/reports" and parse_qs(query).get("view",[""])[0]=="monthly":
            try: start_iso,end_iso,start_day,end_day=report_window(parse_qs(query))
            except ValueError as e: return self.sendbody(400,esc(str(e)),"text/plain")
            c=db(); rows=c.execute("""SELECT substr(ts,1,7) month,
                COUNT(*) events,
                SUM(event='click') clicks,
                SUM(event='form_action') actions,
                SUM(event='report') reports
                FROM events WHERE ts>=? AND ts<? GROUP BY substr(ts,1,7) ORDER BY month DESC""",(start_iso,end_iso)).fetchall(); c.close()
            table="".join("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%.1f%%</td><td>%.1f%%</td></tr>"%(esc(x["month"]),x["events"],x["clicks"] or 0,x["actions"] or 0,x["reports"] or 0,(x["actions"] or 0)/max(x["clicks"] or 0,1)*100,(x["reports"] or 0)/max(x["clicks"] or 0,1)*100) for x in rows) or "<tr><td colspan='7'>No monthly telemetry.</td></tr>"
            return self.admin_shell("Monthly Report",'<h1>Monthly Report</h1><p>Measured telemetry by calendar month · %s to %s.</p><div class="card"><form method="get" class="filter"><input type="hidden" name="view" value="monthly"><label>Start <input type="date" name="start" value="%s"></label><label>End <input type="date" name="end" value="%s"></label><button class="btn primary">Apply</button><a class="btn" href="/admin/reports">Campaign Reports</a></form></div><div class="card"><table class="table"><tr><th>Month</th><th>Events</th><th>Clicks</th><th>Actions</th><th>Reports</th><th>Action Rate</th><th>Report Rate</th></tr>%s</table></div>'%(esc(start_day),esc(end_day),table),"Reports")
        if path=="/admin/reports" and parse_qs(query).get("view",[""])[0]=="compare":
            ids=[x for x in parse_qs(query).get("campaign_id",[]) if x.isdigit()][:10]
            c=db(); campaigns=c.execute("SELECT id,name,status,targeted FROM campaigns ORDER BY id DESC LIMIT 100").fetchall()
            selected=[x for x in campaigns if str(x["id"]) in ids]
            rows=[]
            if selected:
                placeholders=",".join("?"*len(selected))
                rows=c.execute("""SELECT c.id,c.name,c.targeted,
                    COALESCE((SELECT COUNT(*) FROM campaign_deliveries d WHERE d.campaign_id=c.id AND d.status='Sent'),0) sent,
                    COALESCE((SELECT COUNT(*) FROM events e WHERE e.campaign_id=c.id AND e.event='click'),0) clicks,
                    COALESCE((SELECT COUNT(*) FROM events e WHERE e.campaign_id=c.id AND e.event='form_action'),0) actions,
                    COALESCE((SELECT COUNT(*) FROM events e WHERE e.campaign_id=c.id AND e.event='report'),0) reports
                    FROM campaigns c WHERE c.id IN (""" + placeholders + ") ORDER BY c.id DESC",tuple(x["id"] for x in selected)).fetchall()
            c.close()
            table="".join("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%.1f%%</td><td>%.1f%%</td><td>%.1f%%</td></tr>"%(x["id"],esc(x["name"]),x["targeted"],x["sent"],x["clicks"],x["clicks"]/max(x["sent"],1)*100,x["actions"]/max(x["sent"],1)*100,x["reports"]/max(x["sent"],1)*100) for x in rows) or "<tr><td colspan='8'>Select campaigns to compare.</td></tr>"
            opts="".join("<option value='%s' %s>%s</option>"%(x["id"],"selected" if str(x["id"]) in ids else "",esc(x["name"])) for x in campaigns)
            return self.admin_shell("Campaign Comparison",'<h1>Campaign Comparison</h1><p>Compare measured campaign outcomes. Select up to 10 campaigns.</p><div class="card"><form method="get"><input type="hidden" name="view" value="compare"><select name="campaign_id" multiple size="8" style="width:100%%;padding:10px;border:1px solid #ccd9d4;border-radius:8px">%s</select><p><button class="btn primary">Compare Selected</button></p></form></div><div class="card"><table class="table"><tr><th>ID</th><th>Campaign</th><th>Targeted</th><th>Sent</th><th>Clicks</th><th>Click Rate</th><th>Action Rate</th><th>Report Rate</th></tr>%s</table></div>'%(opts,table),"Reports")
        if path=="/admin/reports" and parse_qs(query).get("view",[""])[0]=="executive":
            try: start_iso,end_iso,start_day,end_day=report_window(parse_qs(query))
            except ValueError as e: return self.sendbody(400,esc(str(e)),"text/plain")
            c=db()
            targeted=c.execute("SELECT COALESCE(SUM(targeted),0) n FROM campaigns WHERE created_at>=? AND created_at<?",(start_iso,end_iso)).fetchone()["n"]
            sent=c.execute("SELECT COUNT(*) n FROM campaign_deliveries WHERE status='Sent' AND sent_at>=? AND sent_at<?",(start_iso,end_iso)).fetchone()["n"]
            clicks=c.execute("SELECT COUNT(*) n FROM events WHERE event='click' AND ts>=? AND ts<?",(start_iso,end_iso)).fetchone()["n"]
            actions=c.execute("SELECT COUNT(*) n FROM events WHERE event='form_action' AND ts>=? AND ts<?",(start_iso,end_iso)).fetchone()["n"]
            reports=c.execute("SELECT COUNT(*) n FROM events WHERE event='report' AND ts>=? AND ts<?",(start_iso,end_iso)).fetchone()["n"]
            training_assigned=c.execute("SELECT COUNT(*) n FROM events WHERE event='training_assigned' AND ts>=? AND ts<?",(start_iso,end_iso)).fetchone()["n"]
            training_completed=c.execute("SELECT COUNT(*) n FROM events WHERE event='training_completed' AND ts>=? AND ts<?",(start_iso,end_iso)).fetchone()["n"]
            risk=c.execute("SELECT level,COUNT(*) n FROM risk_scores GROUP BY level").fetchall()
            c.close()
            click_rate=clicks/max(sent,1)*100; action_rate=actions/max(sent,1)*100; report_rate=reports/max(sent,1)*100; training_rate=training_completed/max(training_assigned,1)*100
            risk_html="".join("<span class='pill'>%s: %s</span> "%(esc(x["level"]),x["n"]) for x in risk) or "No risk data"
            cards='<section class="stats"><div class="stat"><div class="stat-label">TARGETED</div><div class="num">%s</div></div><div class="stat"><div class="stat-label">DELIVERED</div><div class="num">%s</div></div><div class="stat"><div class="stat-label">CLICK RATE</div><div class="num">%.1f%%</div></div><div class="stat"><div class="stat-label">ACTION RATE</div><div class="num">%.1f%%</div></div></section>'%(targeted,sent,click_rate,action_rate)
            return self.admin_shell("Executive Dashboard",'<h1>Executive Dashboard</h1><p>Measured security-awareness outcomes · %s to %s.</p><div class="card"><form method="get" class="filter"><input type="hidden" name="view" value="executive"><label>Start <input type="date" name="start" value="%s"></label><label>End <input type="date" name="end" value="%s"></label><button class="btn primary">Apply</button></form></div>%s<div class="grid"><div class="card"><h3>Reporting & Training</h3><p>Report rate: <b>%.1f%%</b> · Training assigned: <b>%s</b> · Training completed: <b>%s</b> · Training completion: <b>%.1f%%</b></p></div><div class="card"><h3>Current Risk Mix</h3><p>%s</p></div></div><div class="card"><h3>Executive Interpretation</h3><p>Metrics shown here are calculated only from recorded delivery, click, form-action, report and training telemetry. Open rates are not shown unless genuinely measured.</p></div>'%(esc(start_day),esc(end_day),cards,report_rate,training_assigned,training_completed,training_rate,risk_html),"Reports")
        if path=="/admin/reports" and parse_qs(query).get("view",[""])[0]=="trend":
            c=db()
            rows=c.execute("""SELECT substr(ts,1,7) month,
                SUM(event='click') clicks,SUM(event='form_action') actions,SUM(event='report') reports
                FROM events WHERE ts>=? GROUP BY substr(ts,1,7) ORDER BY month""",((datetime.now(timezone.utc)-timedelta(days=183)).isoformat(),)).fetchall()
            c.close()
            table="".join("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%.1f%%</td><td>%.1f%%</td></tr>"%(esc(x["month"]),x["clicks"] or 0,x["actions"] or 0,x["reports"] or 0,(x["actions"] or 0)/max(x["clicks"] or 0,1)*100,(x["reports"] or 0)/max(x["clicks"] or 0,1)*100) for x in rows) or "<tr><td colspan='6'>No resilience telemetry yet.</td></tr>"
            return self.admin_shell("Risk & Resilience Trends",'<h1>Risk & Resilience Trends</h1><p>Six-month measured trend. Lower click/action rates and higher reporting behavior can indicate improving resilience, but this view does not infer unmeasured behavior.</p><div class="card"><table class="table"><tr><th>Month</th><th>Clicks</th><th>Actions</th><th>Reports</th><th>Action/Click</th><th>Report/Click</th></tr>%s</table></div>'%table,"Reports")
        if path=="/admin/exports":
            total=c.execute("SELECT COUNT(*) n FROM events").fetchone()["n"]; clicks=c.execute("SELECT COUNT(*) n FROM events WHERE event='click'").fetchone()["n"]; subs=c.execute("SELECT COUNT(*) n FROM events WHERE event='submitted'").fetchone()["n"]; c.close(); rate=subs/clicks*100 if clicks else 0
            return self.admin_shell("Exports",'<h1>Exports</h1><p>Download measured simulation telemetry. SMTP passwords and encrypted secrets are excluded.</p><div class="card"><h3>Events</h3><p>Total: %s · Clicks: %s · Actions: %s · Action rate: %.1f%%</p><a class="btn primary" href="/admin.csv">Export Event CSV</a></div>'%(total,clicks,subs,rate),"Exports")
        if path=="/admin/reports/scheduled":
            rows=c.execute("""SELECT sr.*,sp.name smtp_name FROM scheduled_reports sr LEFT JOIN smtp_profiles sp ON sp.id=sr.smtp_profile_id ORDER BY sr.id DESC""").fetchall()
            profiles=c.execute("SELECT id,name FROM smtp_profiles WHERE enabled=1 ORDER BY name").fetchall()
            c.close()
            table="".join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>'%(r["id"],esc(r["name"]),esc(r["frequency"]),esc(r["smtp_name"] or "Unavailable"),esc(r["recipients"]),esc(r["next_run_at"]),esc(r["last_status"] or "Never")) for r in rows) or '<tr><td colspan="7">No scheduled reports.</td></tr>'
            opts="".join('<option value="%s">%s</option>'%(p["id"],esc(p["name"])) for p in profiles) or '<option value="">No enabled SMTP profile</option>'
            body='<h1>Scheduled Reports</h1><p>Automatically email measured executive PDF reports using an enabled SMTP profile.</p><div class="card"><form class="form" method="post" action="/admin/reports/scheduled/save"><label>Name<input name="name" maxlength="120" required></label><label>Frequency<select name="frequency"><option>Daily</option><option selected>Weekly</option><option>Monthly</option></select></label><label>SMTP Profile<select name="smtp_profile_id" required>%s</select></label><label>Recipients (comma-separated)<input name="recipients" placeholder="security@example.com, ciso@example.com" required></label><label>First Run (Asia/Dhaka)<input type="datetime-local" name="next_run_at" required></label><button class="btn primary">Create Schedule</button></form></div><div class="card" style="margin-top:15px"><table class="table"><tr><th>ID</th><th>Name</th><th>Frequency</th><th>SMTP</th><th>Recipients</th><th>Next Run UTC</th><th>Status</th></tr>%s</table></div>'%(opts,table)
            return self.admin_shell("Scheduled Reports",body,"Reports")
        if path=="/admin/admins":
            if not self.current_admin() or self.current_admin().get("role")!="Administrator":
                return self.sendbody(403,"Administrator role required","text/plain")
            tab=parse_qs(query).get("tab",["administrators"])[0]
            if tab=="roles":
                built_in_roles=[
                    ("Administrator","Full administrative control","Protected built-in role"),
                    ("Campaign Manager","Campaigns, templates, landing pages, recipients, groups and training","Built-in role"),
                    ("Reporting Analyst","Reports, risk analytics and exports","Built-in role"),
                    ("SMTP Manager","SMTP provider profiles, diagnostics and delivery settings","Built-in role"),
                    ("Security Auditor","Audit log and security activity review","Built-in role")
                ]
                role_cards="".join('<div class="card"><div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start"><div><h3>%s</h3><p class="sub">%s</p></div><span class="sub">%s</span></div></div>'%(esc(name),esc(desc),esc(kind)) for name,desc,kind in built_in_roles)
                custom_rows=c=db()
                custom_roles=c.execute("SELECT name,description,active,created_at FROM rbac_roles WHERE built_in=0 ORDER BY name").fetchall()
                c.close()
                custom_cards="".join('<div class="card"><div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start"><div><h3>%s</h3><p class="sub">%s</p></div><span class="sub">%s</span></div></div>'%(esc(r["name"]),esc(r["description"] or "No description"),"Active" if r["active"] else "Disabled") for r in custom_roles) or '<div class="card"><p class="sub">No custom roles created yet.</p></div>'
                body='<h1>Admin Users & Roles</h1><p>Manage administrator accounts, roles and access policies.</p><div style="display:flex;gap:8px;margin:15px 0"><a class="btn" href="/admin/admins">Administrators</a><a class="btn primary" href="/admin/admins?tab=roles">Roles</a></div><div class="card"><h3>Create Custom Role</h3><p class="sub">Create a named custom role for future granular permission assignment.</p><form class="form" method="post" action="/admin/roles/create"><label>Role name<input name="name" maxlength="80" placeholder="e.g. Training Coordinator" required></label><label>Description<textarea name="description" maxlength="500" rows="3" placeholder="Describe the intended access scope"></textarea></label><button class="btn primary" type="submit">Create Custom Role</button></form></div><div class="card" style="margin-top:15px"><h3>Built-in Roles</h3><p class="sub">Protected roles currently supported by the administration model.</p></div><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:15px;margin-top:15px">%s</div><div class="card" style="margin-top:15px"><h3>Custom Roles</h3><p class="sub">Custom roles are persisted independently from the protected built-in roles. Permission assignment will be added in the permission phase.</p></div><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:15px;margin-top:15px">%s</div>'%(role_cards,custom_cards)
                return self.admin_shell("Admin Users",body,"Admin Users")
            rows=c.execute("SELECT id,username,role,active,created_at FROM admins ORDER BY id").fetchall()
            c.close()
            roles=["Administrator","Campaign Manager","Reporting Analyst","SMTP Manager","Security Auditor"]
            role_opts=lambda selected:"".join('<option value="%s"%s>%s</option>'%(esc(x),' selected' if x==selected else '',esc(x)) for x in roles)
            table="".join('<tr><td>%s</td><td><b>%s</b><div class="sub">Administrator account</div><a class="btn" style="margin-top:6px" href="/admin/admins?id=%s">View access</a></td><td><form method="post" action="/admin/admins/save" style="display:flex;gap:6px;align-items:center;flex-wrap:wrap"><input type="hidden" name="id" value="%s"><select name="role">%s</select><select name="active"><option value="1"%s>Active</option><option value="0"%s>Disabled</option></select><button class="btn primary">Save</button></form></td></tr>'%(r["id"],esc(r["username"]),r["id"],r["id"],role_opts(r["role"] or "Administrator")," selected" if r["active"] else ""," selected" if not r["active"] else "") for r in rows) or '<tr><td colspan="3">No administrator accounts found.</td></tr>'
            selected_id=parse_qs(query).get("id",[""])[0]
            selected=None
            if selected_id.isdigit():
                c=db()
                selected=c.execute("SELECT id,username,role,active,created_at FROM admins WHERE id=?",(int(selected_id),)).fetchone()
                c.close()
            access={
                "Administrator":["Full administration access","Campaigns, templates, landing pages, recipients and groups","Training, reports, risk and exports","SMTP and audit administration"],
                "Campaign Manager":["Campaigns and campaign delivery","Templates and landing pages","Recipients and groups","Training workflows"],
                "Reporting Analyst":["Reports and executive views","Risk and trend analytics","Report exports"],
                "SMTP Manager":["SMTP provider profiles","SMTP diagnostics and delivery settings"],
                "Security Auditor":["Audit log and security activity review"]
            }
            preview=""
            if selected:
                perms="".join("<li>%s</li>"%esc(x) for x in access.get(selected["role"],[]))
                status="Active" if selected["active"] else "Disabled"
                preview='<div class="card" style="margin-top:15px"><div style="display:flex;justify-content:space-between;align-items:flex-start;gap:15px"><div><h3>Access Preview</h3><p class="sub">%s · %s</p></div><a class="btn" href="/admin/admins">Close</a></div><div style="margin-top:12px;padding:14px;background:#f7faf8;border-radius:10px"><b>%s</b><div class="sub" style="margin-top:5px">Account ID %s · Status: %s</div><ul style="margin:12px 0 0 18px;line-height:1.8;font-size:12px">%s</ul></div><p class="sub" style="margin-top:12px">Preview reflects the current built-in role model. Granular custom permissions will be introduced in the RBAC permission phase.</p></div>'%(esc(selected["username"]),esc(selected["role"]),esc(selected["role"]),selected["id"],status,perms)
            elif selected_id:
                preview='<div class="card" style="margin-top:15px"><h3>Administrator not found</h3><p class="sub">The requested administrator account does not exist.</p></div>'
            body='<h1>Admin Users & Roles</h1><p>Manage administrator accounts and assign the existing least-privilege roles. Passwords are hashed and never displayed.</p><p><a class="btn primary" href="#add-admin">+ Add Administrator</a></p><div style="display:grid;grid-template-columns:minmax(0,1.55fr) minmax(300px,.85fr);gap:15px;align-items:start"><div class="card"><h3>Administrators</h3><p class="sub">Create, assign and disable administrative access.</p><div class="table-wrap"><table class="table" style="min-width:760px"><tr><th>ID</th><th>Administrator</th><th>Role / Status</th></tr>%s</table></div></div><div class="card" id="add-admin"><h3>Add Administrator</h3><p class="sub">Create an active administrator account using the existing RBAC role set.</p><form class="form" method="post" action="/admin/admins/create"><label>Email / Username<input type="email" name="username" autocomplete="username" maxlength="254" placeholder="admin@example.com" required></label><label>Temporary password<input type="password" name="password" autocomplete="new-password" minlength="12" maxlength="256" placeholder="Minimum 12 characters" required></label><label>Role<select name="role" required>%s</select></label><button class="btn primary" type="submit">Create Administrator</button></form><div style="margin-top:12px;padding:11px 12px;background:#edf8f4;border-radius:9px;font-size:11px;color:#2b6554;line-height:1.5">Password policy: 12–256 characters. Do not use line breaks. The password is stored only as a secure hash and is never shown in the administrator list or audit log.</div></div></div><div class="card" style="margin-top:15px"><h3>Current role access</h3><p><b>Administrator:</b> full control · <b>Campaign Manager:</b> campaigns, templates, landing pages, recipients, groups, training · <b>Reporting Analyst:</b> reports, risk, exports · <b>SMTP Manager:</b> SMTP profiles · <b>Security Auditor:</b> audit log.</p><p class="sub">Custom roles and granular permission assignment are planned for the next RBAC phase.</p></div>'+preview%(table,role_opts("Campaign Manager"))
            return self.admin_shell("Admin Users",body,"Admin Users")
        if path=="/admin/settings":
            cfg=risk_settings(c); c.close()
            body='<h1>Settings</h1><div class="card"><p>Admin credentials are environment variables. Database: SQLite. Timezone: Asia/Dhaka.</p><p>Simulation policy: never request or store passwords, OTPs, PINs, CVV or full card numbers.</p></div><div class="card" style="margin-top:15px"><h3>Risk Scoring Configuration</h3><p>Weights apply only to measured telemetry inside the configured lookback window.</p><form class="form" method="post" action="/admin/risk/settings"><label>Click weight<input type="number" min="0" max="100" name="click_weight" value="%s"></label><label>Form-action weight<input type="number" min="0" max="100" name="form_action_weight" value="%s"></label><label>Report bonus<input type="number" min="-100" max="0" name="report_bonus" value="%s"></label><label>Repeat-offender bonus<input type="number" min="0" max="100" name="repeat_bonus" value="%s"></label><label>Lookback days<input type="number" min="1" max="3650" name="lookback_days" value="%s"></label><label>High threshold<input type="number" min="1" max="100" name="high_threshold" value="%s"></label><label>Medium threshold<input type="number" min="1" max="100" name="medium_threshold" value="%s"></label><button class="btn primary">Save Risk Settings</button></form></div>'%(cfg["click_weight"],cfg["form_action_weight"],cfg["report_bonus"],cfg["repeat_bonus"],cfg["lookback_days"],cfg["high_threshold"],cfg["medium_threshold"])
            return self.admin_shell("Settings",body,"Settings")
        c.close(); return None

    def campaign_report(self,cid):
        c=db()
        camp=c.execute("SELECT c.*,s.name smtp_name,l.name landing_name FROM campaigns c LEFT JOIN smtp_profiles s ON s.id=c.smtp_profile_id LEFT JOIN landing_pages l ON l.id=c.landing_page_id WHERE c.id=?",(cid,)).fetchone()
        deliveries=c.execute("SELECT d.status,d.sent_at,r.email,r.name,r.department FROM campaign_deliveries d JOIN recipients r ON r.id=d.recipient_id WHERE d.campaign_id=? ORDER BY d.id DESC",(cid,)).fetchall()
        events=c.execute("SELECT event,COUNT(*) n FROM events WHERE campaign_id=? GROUP BY event",(cid,)).fetchall()
        c.close()
        if not camp: return self.sendbody(404,"Campaign not found","text/plain")
        counts={x["event"]:x["n"] for x in events}
        sent=sum(1 for x in deliveries if x["status"]=="Sent"); failed=sum(1 for x in deliveries if x["status"]=="Failed")
        rows="".join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>'%(esc(x["email"]),esc(x["name"]),esc(x["department"]),esc(x["status"]),esc(x["sent_at"] or "")) for x in deliveries) or '<tr><td colspan="5">No delivery records.</td></tr>'
        body='<h1>%s</h1><p>SMTP: %s · Landing Page: %s · Targeted: %s</p><div class="card"><b>Sent</b> %s &nbsp; <b>Failed</b> %s &nbsp; <b>Clicks</b> %s &nbsp; <b>Actions</b> %s</div><div class="card"><table class="table"><tr><th>Email</th><th>Name</th><th>Department</th><th>Delivery</th><th>Sent At</th></tr>%s</table></div><p><a class="btn" href="/admin/reports">Back to Reports</a></p>'%(esc(camp["name"]),esc(camp["smtp_name"] or "Not set"),esc(camp["landing_name"] or "Not set"),camp["targeted"],sent,failed,counts.get("click",0),counts.get("submitted",0),rows)
        return self.admin_shell("Campaign Report",body,"Reports")

    def recipient_profile_form(self,rid):
        c=db(); r=c.execute("SELECT * FROM recipients WHERE id=?",(rid,)).fetchone(); c.close()
        if not r:
            return self.admin_shell("Recipient Profile","<h1>Recipient not found</h1><p><a class='btn' href='/admin/recipients'>Back</a></p>","Recipients")
        def v(k): return esc(r[k] or "")
        langs=["English","Bangla","Bengali-English","Arabic","Hindi"]
        langopts="".join('<option value="%s" %s>%s</option>'%(esc(x),"selected" if r["language"]==x else "",esc(x)) for x in langs)
        statusopts="".join('<option value="%s" %s>%s</option>'%(x,"selected" if r["status"]==x else "",x) for x in ("Active","Suppressed"))
        body='<h1>Recipient Profile</h1><p>Edit identity, organizational and targeting metadata. No credential fields are supported.</p><div class="card"><form class="form" method="post" action="/admin/recipients/save"><input type="hidden" name="id" value="%s"><div style="display:grid;grid-template-columns:1fr 1fr;gap:12px"><label>Email<input type="email" name="email" value="%s" required maxlength="255"></label><label>Employee ID<input name="employee_id" value="%s" maxlength="100"></label><label>Name<input name="name" value="%s" maxlength="150"></label><label>Designation<input name="designation" value="%s" maxlength="150"></label><label>Department<input name="department" value="%s" maxlength="100"></label><label>Location<input name="location" value="%s" maxlength="150"></label><label>Manager<input name="manager" value="%s" maxlength="150"></label><label>Group<input name="group_name" value="%s" maxlength="100"></label><label>Language<select name="language">%s</select></label><label>Timezone<input name="timezone" value="%s" maxlength="80" placeholder="Asia/Dhaka"></label><label>Status<select name="status">%s</select></label></div><button class="btn primary">Save Profile</button> <a class="btn" href="/admin/recipients">Cancel</a></form></div>'%(r["id"],v("email"),v("employee_id"),v("name"),v("designation"),v("department"),v("location"),v("manager"),v("group_name"),langopts,v("timezone"),statusopts)
        return self.admin_shell("Recipient Profile",body,"Recipients")

    def recipient_import_form(self):
        return self.admin_shell("Import Recipients",'<h1>Import Recipients</h1><div class="card"><form class="form" method="post" action="/admin/recipients/import"><label>Source Name<input name="source_name" maxlength="150" placeholder="HR recipient export - October 2026"></label><label>CSV data<textarea name="csv_data" rows="16" style="width:100%;padding:10px;border:1px solid #ccd9d4;border-radius:8px" placeholder="email,name,employee_id,department,designation,location,manager,language,timezone,group_name"></textarea></label><button class="btn primary">Validate & Import</button></form><p style="font-size:12px;color:#71817b">Supported metadata: email, name, employee_id, department, designation, location, manager, language, timezone, group_name. Duplicate emails are updated; conflicting employee IDs are skipped. Never place passwords, OTPs, PINs, CVVs or card data here.</p></div>',"Recipients")

    def group_form(self):
        return self.admin_shell("New Group",'<h1>New Group</h1><div class="card"><form class="form" method="post" action="/admin/groups/save"><label>Group Name<input name="name" required maxlength="100"></label><label>Department<input name="department" maxlength="100"></label><button class="btn primary">Save Group</button></form></div>',"Groups & Departments")

    def smtp_form(self,sid=None):
        c=db(); r=c.execute("SELECT * FROM smtp_profiles WHERE id=?",(sid,)).fetchone() if sid else None; c.close()
        provider=esc(r["provider"]) if r else "Gmail"; preset=SMTP_PROVIDERS.get(provider,SMTP_PROVIDERS["Custom SMTP"])
        host=esc(r["host"]) if r else esc(preset["host"]); port=esc(r["port"]) if r else str(preset["port"]); security=esc(r["security"]) if r else preset["security"]
        name=esc(r["name"]) if r else ""; username=esc(r["username"]) if r else ""; from_name=esc(r["from_name"]) if r else ""; from_email=esc(r["from_email"]) if r else ""; reply_to=esc(r["reply_to"]) if r else ""; auth_method=esc(r["auth_method"]) if r and r["auth_method"] else "password"; oauth_url=esc(r["oauth_token_url"]) if r else ""; oauth_client=esc(r["oauth_client_id"]) if r else ""; oauth_scopes=esc(r["oauth_scopes"]) if r else ""
        opts="".join('<option value="%s" %s>%s</option>'%(esc(k),"selected" if k==provider else "",esc(k)) for k in SMTP_PROVIDERS)
        secs="".join('<option value="%s" %s>%s</option>'%(x,"selected" if x==security else "",x) for x in ("STARTTLS","SSL/TLS","NONE"))
        return self.admin_shell("SMTP Provider",'<h1>%s SMTP Provider</h1><div class="card"><form class="form" method="post" action="/admin/smtp/save"><input type="hidden" name="id" value="%s"><label>Profile Name<input name="name" value="%s" required></label><label>Provider<select id="provider" name="provider" onchange="presetProvider()">%s</select></label><label>SMTP Host<input id="host" name="host" value="%s" required></label><label>Port<input id="port" type="number" min="1" max="65535" name="port" value="%s" required></label><label>Security<select id="security" name="security">%s</select></label><label>Authentication<select name="auth_method"><option value="password" %s>Password / SMTP AUTH</option><option value="oauth2" %s>OAuth 2.0 / XOAUTH2</option></select></label><label>Username / SMTP account<input name="username" value="%s" autocomplete="username"></label><label>Password<input type="password" name="password" value="" autocomplete="new-password" placeholder="%s"></label><label>OAuth Token URL<input name="oauth_token_url" value="%s" maxlength="500"></label><label>OAuth Access Token<input type="password" name="oauth_token" value="" autocomplete="new-password" placeholder="%s"></label><label>OAuth Client ID<input name="oauth_client_id" value="%s" maxlength="255"></label><label>OAuth Scopes<input name="oauth_scopes" value="%s" maxlength="1000"></label><label>From Name<input name="from_name" value="%s"></label><label>From Email<input type="email" name="from_email" value="%s" required></label><label>Reply-To<input type="email" name="reply_to" value="%s"></label><div style="padding:12px;background:#f4f7f6;border-radius:8px;font-size:12px;color:#60716a">Password is write-only. Leave it blank when editing to keep the existing encrypted secret.</div><button class="btn primary">Save Provider</button>%s</form></div><script>const presets=%s;function presetProvider(){const p=presets[document.getElementById("provider").value];if(p){document.getElementById("host").value=p.host;document.getElementById("port").value=p.port;document.getElementById("security").value=p.security}}</script>'%( "Edit" if r else "Add",sid or "",name,opts,host,port,secs,username,"unchanged" if r else "enter SMTP password",from_name,from_email,reply_to,auth_method=="password" and "selected" or "",auth_method=="oauth2" and "selected" or "",oauth_url,oauth_client,oauth_scopes,"unchanged" if r else "enter OAuth access token",html.escape(str(SMTP_PROVIDERS).replace("'",'"')),(('<a class="btn" href="/admin/smtp/diagnostics?id=%s">Run Diagnostics</a>'%sid) if r else "")),"SMTP Providers")
    def landing_page_form(self,lid=None):
        c=db()
        r=c.execute("SELECT * FROM landing_pages WHERE id=?",(lid,)).fetchone() if lid else None
        versions=c.execute("SELECT version,created_at,created_by FROM landing_page_versions WHERE landing_page_id=? ORDER BY version DESC LIMIT 20",(lid,)).fetchall() if lid else []
        c.close()
        if not r:
            return self.admin_shell("Landing Page","<h1>Landing page not found</h1><p><a class='btn' href='/admin/landing-pages'>Back</a></p>","Landing Pages")
        body=esc(r["html_body"] or "")
        text_body=esc(r["text_body"] or "")
        versions_html="".join("<tr><td>v%s</td><td>%s</td><td>%s</td></tr>"%(v["version"],esc(v["created_at"] or ""),esc(v["created_by"] or "system")) for v in versions) or "<tr><td colspan='3'>No saved versions yet.</td></tr>"
        form="<h1>Edit Landing Page</h1><p>Edit simulation-safe landing content. Credential collection fields are blocked by policy.</p><div class='card'><form class='form' method='post' action='/admin/landing-pages/save'><input type='hidden' name='id' value='%s'><label>Name<input name='name' value='%s' maxlength='150' required></label><label>Status<select name='status'><option %s>Enabled</option><option %s>Disabled</option></select></label><label>HTML Body<textarea name='html_body' rows='24' style='width:100%%;padding:10px;border:1px solid #ccd9d4;border-radius:8px;font-family:monospace;font-size:12px' required>%s</textarea></label><label>Plain Text Body<textarea name='text_body' rows='8' style='width:100%%;padding:10px;border:1px solid #ccd9d4;border-radius:8px'>%s</textarea></label><p style='font-size:12px;color:#71817b'>Maximum HTML size: 500 KB. Password, OTP, PIN, CVV/CVC and full-card-number collection fields are not permitted.</p><button class='btn primary'>Save New Version</button> <a class='btn' href='/admin/landing-pages'>Cancel</a></form></div><div class='card' style='margin-top:15px'><h3>Version History</h3><table class='table'><tr><th>Version</th><th>Created</th><th>By</th></tr>%s</table></div>"%(r["id"],esc(r["name"]), "selected" if r["status"]=="Enabled" else "", "selected" if r["status"]=="Disabled" else "",body,text_body,versions_html)
        return self.admin_shell("Landing Page Editor",form,"Landing Pages")

    def template_form(self,tid=None):
        c=db()
        r=c.execute("SELECT * FROM template_library WHERE template=?",(str(tid),)).fetchone() if tid else None
        if not r and tid:
            fn=os.path.join(TEMPLATES,str(tid)+".html")
            if os.path.isfile(fn):
                with open(fn,"r",encoding="utf-8") as f: body=f.read()
                c.execute("""INSERT OR IGNORE INTO template_library(template,name,subject,preheader,category,difficulty,language,brand,industry,tags,html_body,text_body,updated_at)
                             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",(str(tid),f"Template {tid}","Security Awareness Simulation","Authorized security-awareness simulation","General","Medium","English","Trust PhishGuard","Banking","simulation,awareness",body,"This is an authorized security-awareness simulation.",now()))
                c.commit()
                r=c.execute("SELECT * FROM template_library WHERE template=?",(str(tid),)).fetchone()
        versions=c.execute("SELECT version,created_at,created_by FROM template_versions WHERE template=? ORDER BY version DESC LIMIT 20",(str(tid),)).fetchall() if r else []
        c.close()
        if not r:
            return self.admin_shell("Template","<h1>Template not found</h1><p><a class='btn' href='/admin/templates'>Back</a></p>","Templates")
        def val(k): return esc(r[k] or "")
        version_rows="".join("<tr><td>v%s</td><td>%s</td><td>%s</td></tr>"%(v["version"],esc(v["created_at"]),esc(v["created_by"])) for v in versions) or "<tr><td colspan='3'>No saved versions yet.</td></tr>"
        cats=["General","Credential Awareness","Malware Awareness","QR Awareness","Finance","HR","IT","Executive","Seasonal"]
        diffs=["Easy","Medium","Hard"]
        langs=["English","Bangla","Bengali-English","Arabic","Hindi"]
        catopts="".join('<option %s>%s</option>'%("selected" if r["category"]==x else "",x) for x in cats)
        diffopts="".join('<option %s>%s</option>'%("selected" if r["difficulty"]==x else "",x) for x in diffs)
        langopts="".join('<option %s>%s</option>'%("selected" if r["language"]==x else "",x) for x in langs)
        body="""<h1>Edit Simulation Template %s</h1>
<p>Build the message metadata and HTML body used by an authorized awareness campaign. Never add password, OTP, PIN, CVV or full-card-number collection fields.</p>
<div class="card"><form class="form" method="post" action="/admin/templates/save">
<input type="hidden" name="template" value="%s">
<label>Template Name<input name="name" value="%s" required maxlength="150"></label>
<label>Subject<input name="subject" value="%s" maxlength="250"></label>
<label>Preheader<input name="preheader" value="%s" maxlength="250"></label>
<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px">
<label>Category<select name="category">%s</select></label>
<label>Difficulty<select name="difficulty">%s</select></label>
<label>Language<select name="language">%s</select></label>
</div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
<label>Brand<input name="brand" value="%s" maxlength="100"></label>
<label>Industry<input name="industry" value="%s" maxlength="100"></label>
</div>
<label>Tags<input name="tags" value="%s" placeholder="finance, employee, urgent" maxlength="500"></label>
<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px">
<label>From Name<input name="from_name" value="%s" maxlength="150"></label>
<label>From Email<input name="from_email" value="%s" maxlength="254"></label>
<label>Reply-To<input name="reply_to" value="%s" maxlength="254"></label>
</div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
<label>Owner<input name="owner" value="%s" maxlength="150"></label>
<label>Status<select name="status"><option %s>Active</option><option %s>Archived</option></select></label>
</div>
<p style="font-size:12px;color:#71817b">Safe variables: {{name}}, {{email}}, {{employee_id}}, {{department}}, {{designation}}, {{location}}, {{manager}}, {{language}}, {{timezone}}, {{campaign_name}}, {{tracking_link}}, {{report_link}}, {{qr_link}}. Unknown variables remain unchanged.</p><label>HTML Body<textarea name="html_body" rows="22" style="width:100%%;font-family:Consolas,monospace;padding:12px;border:1px solid #ccd9d4;border-radius:8px" required>%s</textarea></label>
<label>Plain Text Body<textarea name="text_body" rows="8" style="width:100%%;padding:12px;border:1px solid #ccd9d4;border-radius:8px">%s</textarea></label>
<div style="display:flex;gap:8px"><button class="btn primary">Save Template</button><a class="btn" href="/admin/templates/test-send?id=%s">Test Send</a><a class="btn" target="_blank" href="/%s.html">Preview</a><a class="btn" href="/admin/templates">Cancel</a></div>
</form></div><div class="card" style="margin-top:15px"><h3>Version History</h3><table class="table"><tr><th>Version</th><th>Created</th><th>Created By</th></tr>%s</table></div>"""%(val("template"),val("template"),val("name"),val("subject"),val("preheader"),catopts,diffopts,langopts,val("brand"),val("industry"),val("tags"),val("from_name"),val("from_email"),val("reply_to"),val("owner"),"selected" if (r["status"] or "Active")=="Active" else "","selected" if (r["status"] or "Active")=="Archived" else "",val("html_body"),val("text_body"),val("template"),val("template"),version_rows)
        return self.admin_shell("Template Builder",body,"Templates")

    def campaign_form(self,cid=None):
        c=db()
        r=c.execute("SELECT * FROM campaigns WHERE id=?",(cid,)).fetchone() if cid else None
        smtps=c.execute("SELECT id,name,provider,from_email FROM smtp_profiles WHERE enabled=1 ORDER BY name").fetchall()
        lands=c.execute("SELECT id,name,template FROM landing_pages WHERE status='Enabled' ORDER BY id").fetchall()
        groups=c.execute("SELECT g.name,COUNT(r.id) members FROM groups_tbl g LEFT JOIN recipients r ON r.group_name=g.name GROUP BY g.name ORDER BY g.name").fetchall()
        c.close()
        name=esc(r["name"]) if r else ""
        template=esc(r["template"]) if r else "1"
        status=esc(r["status"]) if r else "Draft"
        subject=esc(r["subject"]) if r else "Security Awareness Simulation"
        smtp_id=str(r["smtp_profile_id"]) if r and r["smtp_profile_id"] else ""
        landing_id=str(r["landing_page_id"]) if r and r["landing_page_id"] else ""
        saved_group=str(r["group_name"]) if r and r["group_name"] else ""
        launch=esc(r["launch_at"]) if r else ""
        send_by=esc(r["send_by"]) if r else ""
        opts="".join('<option value="%s" %s>Template %s</option>'%(i,"selected" if str(i)==template else "",i) for i in range(1,11))
        smtp_opts='<option value="">-- Select SMTP provider --</option>'+"".join('<option value="%s" %s>%s · %s</option>'%(x["id"],"selected" if str(x["id"])==smtp_id else "",esc(x["name"]),esc(x["from_email"])) for x in smtps)
        land_opts='<option value="">-- Select landing page --</option>'+"".join('<option value="%s" %s>%s · Template %s</option>'%(x["id"],"selected" if str(x["id"])==landing_id else "",esc(x["name"]),esc(x["template"])) for x in lands)
        group_opts='<option value="">All imported recipients</option>'+"".join('<option value="%s" %s>%s · %s members</option>'%(esc(x["name"]),"selected" if x["name"]==saved_group else "",esc(x["name"]),x["members"]) for x in groups)
        timezone=esc(r["timezone"]) if r and r["timezone"] else "Asia/Dhaka"
        business_days=esc(r["business_days"]) if r and r["business_days"] else "Sun,Mon,Tue,Wed,Thu"
        window_start=esc(r["window_start"]) if r and r["window_start"] else "09:00"
        window_end=esc(r["window_end"]) if r and r["window_end"] else "17:00"
        batch_size=str(r["batch_size"] or 50) if r else "50"
        rate=str(r["rate_per_minute"] or 60) if r else "60"
        retry_max=str(r["retry_max"] if r and r["retry_max"] is not None else 2)
        retry_backoff=str(r["retry_backoff_seconds"] if r and r["retry_backoff_seconds"] is not None else 5)
        tz_opts="".join('<option value="%s" %s>%s</option>'%(z,"selected" if z==timezone else "",z) for z in ("Asia/Dhaka","UTC","Asia/Kolkata","Asia/Singapore","Asia/Dubai","Europe/London","America/New_York","America/Los_Angeles"))
        stats="".join('<option %s>%s</option>'%("selected" if x==status else "",x) for x in ("Draft","Scheduled","Active","Paused","Completed","Cancelled","Expired"))
        launch_link='<p><a class="btn primary" href="/admin/campaigns/launch?id=%s">Launch / Queue Campaign</a></p>'%cid if cid else ""
        control_link=('<div style="display:flex;gap:8px;margin:12px 0"><form method="post" action="/admin/campaigns/control"><input type="hidden" name="id" value="%s"><button class="btn" name="action" value="pause">Pause</button><button class="btn" name="action" value="resume">Resume</button><button class="btn" name="action" value="cancel">Cancel</button></form></div>'%cid) if cid else ""
        body='<h1>%s Campaign</h1>%s%s<div class="card"><form class="form" method="post" action="/admin/campaigns/save"><input type="hidden" name="id" value="%s"><label>Name<input name="name" value="%s" required maxlength="150"></label><label>Template<select name="template">%s</select></label><label>SMTP Provider<select name="smtp_profile_id" required>%s</select></label><label>Landing Page<select name="landing_page_id" required>%s</select></label><label>Recipient Group<select name="group_name">%s</select></label><label>Subject<input name="subject" value="%s" maxlength="250" required></label><label>Launch At<input type="datetime-local" name="launch_at" value="%s"></label><label>Send By<input type="datetime-local" name="send_by" value="%s"></label><label>Timezone<select name="timezone">%s</select></label><label>Business Days<input name="business_days" value="%s"></label><label>Sending Window<input name="window_start" type="time" value="%s"> — <input name="window_end" type="time" value="%s"></label><label>Batch Size<input name="batch_size" type="number" min="1" max="1000" value="%s"></label><label>Rate Limit<input name="rate_per_minute" type="number" min="1" max="1000" value="%s"></label><label>Retry Attempts<input name="retry_max" type="number" min="0" max="5" value="%s"></label><label>Retry Backoff Seconds<input name="retry_backoff_seconds" type="number" min="1" max="300" value="%s"></label><label>Status<select name="status">%s</select></label><button class="btn primary">Save Campaign</button></form></div>'%("Edit" if r else "New",launch_link,control_link,cid or "",name,opts,smtp_opts,land_opts,group_opts,subject,launch,send_by,tz_opts,business_days,window_start,window_end,batch_size,rate,retry_max,retry_backoff,stats)
        return self.admin_shell("Campaign",body,"Campaigns")

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        p=urlparse(self.path); path=p.path; ip=self.client_address[0]; ua=self.headers.get("User-Agent","")
        if path.startswith("/admin/") and path not in ("/admin/login",):
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            if path!="/admin/logout" and not self.role_allowed(path): return self.sendbody(403,"Insufficient role permission","text/plain")
        if path=="/admin":
            if not self.auth(): return self.sendbody(200,self.login_page())
            return self.sendbody(200,self.dashboard())
        if path=="/admin/logout":
            c=cookies.SimpleCookie(self.headers.get("Cookie","")); s=c.get("admin_session")
            if s: SESSIONS.pop(s.value,None)
            return self.sendbody(302,b"",extra={"Location":"/admin","Set-Cookie":"admin_session=; Max-Age=0; HttpOnly; SameSite=Strict"})
        if path=="/admin.csv":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            c=db(); rows=c.execute("SELECT ts,event,template,ip,name,employee_id,email,mobile,card_type,user_agent FROM events ORDER BY id DESC").fetchall(); c.close()
            out=io.StringIO(); w=csv.writer(out)
            w.writerow(["timestamp","event","template","local_ip","name","employee_id","email","mobile","card_type","user_agent"])
            for r in rows:
                w.writerow([r["ts"],r["event"],r["template"],r["ip"],r["name"] or "",r["employee_id"] or "",r["email"] or "",r["mobile"] or "",r["card_type"] or "",r["user_agent"] or ""])
            return self.sendbody(200,out.getvalue(),"text/csv",{"Content-Disposition":"attachment; filename=phish-simulation.csv"})
        if path in ("/admin/campaigns","/admin/templates","/admin/landing-pages","/admin/smtp","/admin/training","/admin/recipients","/admin/groups","/admin/users","/admin/reports","/admin/reports.pdf","/admin/risk","/admin/exports","/admin/settings","/admin/audit","/admin/admins"):
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            if not self.role_allowed(path): return self.sendbody(403,"Insufficient role permission","text/plain")
            if path=="/admin/campaigns" and parse_qs(p.query).get("id",[None])[0]:
                return self.sendbody(200,self.campaign_form(parse_qs(p.query).get("id",[None])[0]))
            if path=="/admin/reports" and parse_qs(p.query).get("campaign_id",[None])[0]:
                return self.sendbody(200,self.campaign_report(parse_qs(p.query).get("campaign_id",[None])[0]))
            if path=="/admin/smtp" and parse_qs(p.query).get("id",[None])[0]:
                return self.sendbody(200,self.smtp_form(parse_qs(p.query).get("id",[None])[0]))
            if path=="/admin/templates" and parse_qs(p.query).get("id",[None])[0]:
                return self.sendbody(200,self.template_form(parse_qs(p.query).get("id",[None])[0]))
            if path=="/admin/landing-pages" and parse_qs(p.query).get("id",[None])[0]:
                return self.sendbody(200,self.landing_page_form(parse_qs(p.query).get("id",[None])[0]))
        if path=="/admin/landing-pages/preview":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            lid=parse_qs(p.query).get("id",[""])[0]
            c=db(); row=c.execute("SELECT * FROM landing_pages WHERE id=?",(lid,)).fetchone(); c.close()
            if not row: return self.sendbody(404,"Landing page not found","text/plain")
            ok,msg=validate_landing_html(row["html_body"] or "")
            if not ok: return self.sendbody(400,msg,"text/plain")
            return self.sendbody(200,row["html_body"] or "<h1>Empty landing page</h1>")
        if path in ("/admin/campaigns","/admin/templates","/admin/landing-pages","/admin/smtp","/admin/training","/admin/recipients","/admin/groups","/admin/users","/admin/reports","/admin/reports.pdf","/admin/risk","/admin/exports","/admin/settings","/admin/audit","/admin/admins"):
            return self.sendbody(200,self.feature_page(path,p.query))
        if path=="/admin/smtp/diagnostics":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            sid=parse_qs(p.query).get("id",[""])[0]
            c=db(); profile=c.execute("SELECT id,name,provider,host,port,security,from_name,from_email FROM smtp_profiles WHERE id=?",(sid,)).fetchone(); c.close()
            if not profile: return self.sendbody(404,"SMTP profile not found","text/plain")
            body='<h1>SMTP Connectivity Diagnostics</h1><div class="card"><p><b>%s</b> · %s · %s:%s · %s</p><p>Runs DNS → TCP → TLS → AUTH and optionally sends one diagnostic message. Secrets are never displayed.</p><form class="form" method="post" action="/admin/smtp/diagnostics"><input type="hidden" name="id" value="%s"><label>Diagnostic recipient email<input type="email" name="to_email" maxlength="254" placeholder="security@example.com"></label><button class="btn primary">Run Diagnostics</button></form></div>'%(esc(profile["name"]),esc(profile["provider"]),esc(profile["host"]),profile["port"],esc(profile["security"]),profile["id"])
            return self.admin_shell("SMTP Diagnostics",body,"SMTP")
        if path=="/admin/smtp/new":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            return self.sendbody(200,self.smtp_form())
        if path=="/admin/training/new":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            c=db(); courses=c.execute("SELECT id,name FROM training_courses WHERE status='Active' ORDER BY name").fetchall(); recipients=c.execute("SELECT id,email,name,department FROM recipients WHERE status!='Suppressed' ORDER BY email").fetchall(); campaigns=c.execute("SELECT id,name FROM campaigns ORDER BY id DESC").fetchall(); c.close()
            co="".join('<option value="%s">%s</option>'%(x["id"],esc(x["name"])) for x in courses); ro="".join('<option value="%s">%s · %s</option>'%(x["id"],esc(x["email"]),esc(x["department"] or "")) for x in recipients)
            ca='<option value="">None</option>'+"".join('<option value="%s">%s</option>'%(x["id"],esc(x["name"])) for x in campaigns)
            body='<h1>Assign Training</h1><div class="card"><form class="form" method="post" action="/admin/training/assign"><label>Course<select name="course_id" required>%s</select></label><label>Recipient<select name="recipient_id" required>%s</select></label><label>Due Date<input type="datetime-local" name="due_at" required></label><label>Trigger Campaign<select name="trigger_campaign_id">%s</select></label><label>Remediation Campaign<select name="remediation_campaign_id">%s</select></label><p style="font-size:12px;color:#71817b">Trigger campaign identifies the simulation that led to training. Remediation campaign identifies the follow-up simulation.</p><button class="btn primary">Assign Training</button></form></div>'%(co,ro,ca,ca)
            return self.sendbody(200,self.admin_shell("Assign Training",body,"Training"))
        if path=="/admin/training/course/new":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            body='<h1>New Training Course</h1><div class="card"><form class="form" method="post" action="/admin/training/course/save"><label>Course Name<input name="name" required maxlength="150"></label><label>Description<textarea name="description" rows="5" style="width:100%;padding:10px;border:1px solid #ccd9d4;border-radius:8px"></textarea></label><label>Duration (minutes)<input type="number" name="duration_minutes" value="15" min="1" max="480"></label><label>Passing Score %<input type="number" name="passing_score" value="80" min="0" max="100"></label><button class="btn primary">Save Course</button></form></div>'
            return self.sendbody(200,self.admin_shell("New Training Course",body,"Training"))
        if path=="/admin/recipients" and parse_qs(p.query).get("id",[None])[0]:
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            return self.sendbody(200,self.recipient_profile_form(parse_qs(p.query).get("id",[None])[0]))
        if path=="/admin/recipients/import":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            return self.sendbody(200,self.recipient_import_form())
        if path=="/admin/groups/new":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            return self.sendbody(200,self.group_form())
        if path=="/admin/templates/test-send":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            tid=parse_qs(p.query).get("id",[""])[0]
            c=db(); tpl=c.execute("SELECT * FROM template_library WHERE template=?",(tid,)).fetchone(); profiles=c.execute("SELECT id,name FROM smtp_profiles WHERE enabled=1 ORDER BY name").fetchall(); c.close()
            if not tpl: return self.sendbody(404,"Template not found","text/plain")
            opts="".join('<option value="%s">%s</option>'%(x["id"],esc(x["name"])) for x in profiles)
            body='<h1>Template Test Send</h1><div class="card"><p>Template: <b>%s</b> · Version %s</p><p>This sends a single non-tracked test message. No campaign recipient or tracking event is created.</p><form class="form" method="post" action="/admin/templates/test-send"><input type="hidden" name="template" value="%s"><label>Test recipient email<input type="email" name="to_email" required maxlength="254"></label><label>SMTP Profile<select name="smtp_profile_id" required>%s</select></label><button class="btn primary">Send Test Message</button></form></div>'%(esc(tpl["name"]),tpl["version"] or 1,esc(tid),opts)
            return self.admin_shell("Template Test Send",body,"Templates")
        if path=="/admin/campaigns/test-send":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            cid=parse_qs(p.query).get("id",[""])[0]
            c=db(); campaign=c.execute("SELECT c.*,s.name smtp_name,s.from_email,s.from_name,s.reply_to,s.username,s.password_enc,s.host,s.port,s.security FROM campaigns c JOIN smtp_profiles s ON s.id=c.smtp_profile_id WHERE c.id=?",(cid,)).fetchone(); c.close()
            if not campaign: return self.sendbody(404,"Campaign not found","text/plain")
            body="<h1>Test Send</h1><div class='card'><p>Campaign: <b>%s</b></p><p>This sends one non-tracked test message using the configured SMTP profile. It does not target campaign recipients.</p><form class='form' method='post' action='/admin/campaigns/test-send'><input type='hidden' name='id' value='%s'><label>Test recipient email<input type='email' name='to_email' required maxlength='255'></label><button class='btn primary'>Send Test Message</button></form></div>"%(esc(campaign["name"]),cid)
            return self.sendbody(200,self.admin_shell("Campaign Test Send",body,"Campaigns"))
        if path=="/admin/campaigns/launch":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            cid=parse_qs(p.query).get("id",[""])[0]
            c=db(); campaign=c.execute("SELECT * FROM campaigns WHERE id=?",(cid,)).fetchone()
            count=c.execute("SELECT COUNT(*) n FROM recipients WHERE status!='Suppressed' AND (group_name=? OR ?='')",(campaign["group_name"] if campaign else "",campaign["group_name"] if campaign else "")).fetchone()["n"] if campaign else 0
            c.close()
            if not campaign: return self.sendbody(404,"Campaign not found","text/plain")
            errors=campaign_prelaunch_validation(campaign)
            checks="".join("<li style='color:%s'>%s</li>"%("#a12d2d" if e else "#087b59",esc(e or "Ready")) for e in errors) if errors else "<li style='color:#087b59'>All pre-launch checks passed.</li>"
            disabled=" disabled" if errors else ""
            body='<h1>Launch Campaign</h1><div class="card"><h3>%s</h3><p>Eligible recipients: <b>%s</b></p><h3>Pre-launch validation</h3><ul>%s</ul><p>This action sends only to the configured authorized target scope.</p><p><a class="btn" href="/admin/campaigns/test-send?id=%s">Send Test Message</a></p><form class="form" method="post" action="/admin/campaigns/launch"><input type="hidden" name="id" value="%s"><label><input type="checkbox" name="confirm" value="YES" required%s> I confirm this campaign is authorized and the target list is approved.</label><button class="btn primary"%s>Launch Now</button></form></div>'%(esc(campaign["name"]),count,checks,cid,cid,disabled,disabled)
            return self.sendbody(200,self.admin_shell("Launch Campaign",body,"Campaigns"))
        if path=="/admin/campaigns/new":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            return self.sendbody(200,self.campaign_form())
        if path in ("/report","/qr"):
            token=parse_qs(p.query).get("t",[""])[0]
            tr=resolve_tracking_token(token)
            if not tr: return self.sendbody(404,"Invalid tracking token","text/plain")
            event="report" if path=="/report" else "QR_scan"
            c=db(); recrow=c.execute("SELECT * FROM recipients WHERE id=?",(tr["recipient_id"],)).fetchone(); c.close()
            record(ip,str(tr["campaign_id"]),event,recrow["name"] if recrow else "",recrow["email"] if recrow else "", "",ua,recrow["employee_id"] if recrow else "", "",str(tr["campaign_id"]),str(tr["recipient_id"]),token)
            return self.sendbody(200,page("PhishGuard","<div style='max-width:700px;margin:80px auto;background:#fff;padding:35px;border-radius:18px;border:1px solid #dce7e2'><h1>Thank you</h1><p>Your report has been recorded as part of the authorized security-awareness simulation.</p></div>"))
        if path.startswith("/") and path.endswith(".html") and path[1:-5].isdigit():
            t=path[1:]; fn=os.path.join(TEMPLATES,t)
            if os.path.isfile(fn):
                q=parse_qs(p.query); token=q.get("t",[""])[0]; tr=resolve_tracking_token(token)
                campaign_id=str(tr["campaign_id"]) if tr else ""; recipient_id=str(tr["recipient_id"]) if tr else ""
                if tr:
                    c=db(); recrow=c.execute("SELECT * FROM recipients WHERE id=?",(recipient_id,)).fetchone(); c.close()
                    if is_bot_user_agent(ua):
                        record(ip,t,"bot_detected",ua=ua,campaign_id=campaign_id,recipient_id=recipient_id,token=token,email=recrow["email"] if recrow else "",name=recrow["name"] if recrow else "",employee_id=recrow["employee_id"] if recrow else "")
                    else:
                        record(ip,t,"click",ua=ua,campaign_id=campaign_id,recipient_id=recipient_id,token=token,email=recrow["email"] if recrow else "",name=recrow["name"] if recrow else "",employee_id=recrow["employee_id"] if recrow else "")
                access(ip,path,200)
                with open(fn,"rb") as f: body=f.read().decode("utf-8","replace")
                if token:
                    action="/submit?"+urlencode({"t":token})
                    body=body.replace('action="/submit"','action="'+action+'"').replace("action='/submit'","action='"+action+"'")
                return self.sendbody(200,body)
        access(ip,path,404); return self.sendbody(404,"404 File not found","text/plain")

    def do_POST(self):
        p=urlparse(self.path); ip=self.client_address[0]
        n=int(self.headers.get("Content-Length","0"))
        form=parse_qs(self.rfile.read(n).decode("utf-8","replace"))
        if p.path=="/admin/login":
            username=form.get("username",[""])[0]
            password=form.get("password",[""])[0]
            if not self.login_allowed():
                return self.sendbody(429,"Too many login attempts. Try again later.","text/plain",{"Retry-After":"300"})
            c=db()
            admin=c.execute("SELECT username,role,password_hash,active FROM admins WHERE username=?",(username,)).fetchone()
            c.close()
            valid=False
            if admin and admin["active"] and admin["password_hash"]:
                valid=password_verify(password,admin["password_hash"])
            elif secrets.compare_digest(username,ADMIN_USERNAME) and secrets.compare_digest(password,ADMIN_PASSWORD):
                valid=True
            if valid:
                LOGIN_ATTEMPTS.pop(self.client_address[0],None)
                sid=secrets.token_urlsafe(32); SESSIONS[sid]={"username":username,"role":admin["role"] if admin else "Administrator","created_at":time.time(),"last_seen":time.time()}
                ck=cookies.SimpleCookie(); ck["admin_session"]=sid; ck["admin_session"]["HttpOnly"]=True; ck["admin_session"]["SameSite"]="Strict"; ck["admin_session"]["Max-Age"]="28800"
                if self.headers.get("X-Forwarded-Proto","").lower()=="https": ck["admin_session"]["Secure"]=True
                return self.sendbody(302,b"",extra={"Location":"/admin","Set-Cookie":ck["admin_session"].OutputString()})
            self.login_failed()
            return self.sendbody(401,self.login_page("Invalid username or password"))
        if p.path.startswith("/admin/") and p.path!="/admin/login" and not self.csrf_origin_ok():
            return self.sendbody(403,"CSRF validation failed","text/plain")
        if p.path.startswith("/admin/") and p.path!="/admin/login" and not self.role_allowed(p.path):
            return self.sendbody(403,"Insufficient role permission","text/plain")
        if p.path=="/admin/landing-pages/save":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            lid=form.get("id",[""])[0]
            name=form.get("name",[""])[0].strip()[:150]
            status=form.get("status",["Enabled"])[0]
            html_body=form.get("html_body",[""])[0]
            text_body=form.get("text_body",[""])[0][:200000]
            if status not in ("Enabled","Disabled"): status="Enabled"
            if not name: return self.sendbody(400,"Landing page name is required","text/plain")
            ok,msg=validate_landing_html(html_body)
            if not ok: return self.sendbody(400,msg,"text/plain")
            c=db(); row=c.execute("SELECT * FROM landing_pages WHERE id=?",(lid,)).fetchone()
            if not row: c.close(); return self.sendbody(404,"Landing page not found","text/plain")
            next_version=(c.execute("SELECT COALESCE(MAX(version),0)+1 n FROM landing_page_versions WHERE landing_page_id=?",(lid,)).fetchone()["n"])
            c.execute("UPDATE landing_pages SET name=?,status=?,html_body=?,text_body=?,version=?,updated_at=? WHERE id=?",(name,status,html_body,text_body,next_version,now(),lid))
            c.execute("INSERT INTO landing_page_versions(landing_page_id,version,html_body,text_body,created_at,created_by) VALUES(?,?,?,?,?,?)",(lid,next_version,html_body,text_body,now(),ADMIN_USERNAME))
            c.commit(); c.close()
            audit(ADMIN_USERNAME,"LANDING_PAGE_UPDATE",f"landing_page={lid} version={next_version}",ip)
            return self.sendbody(302,b"",extra={"Location":"/admin/landing-pages?id="+str(lid)})
        if p.path=="/admin/templates/save":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            tid=form.get("template",[""])[0][:20]
            if not re.fullmatch(r"\d{1,3}",tid) or not (1 <= int(tid) <= 999):
                return self.sendbody(400,"Invalid template id","text/plain")
            name=form.get("name",[""])[0][:150]
            subject=form.get("subject",[""])[0][:250]
            preheader=form.get("preheader",[""])[0][:250]
            category=form.get("category",["General"])[0][:80]
            difficulty=form.get("difficulty",["Medium"])[0][:30]
            language=form.get("language",["English"])[0][:50]
            brand=form.get("brand",[""])[0][:100]
            industry=form.get("industry",[""])[0][:100]
            tags=form.get("tags",[""])[0][:500]
            from_name=form.get("from_name",[""])[0][:150]
            from_email=form.get("from_email",[""])[0][:254]
            reply_to=form.get("reply_to",[""])[0][:254]
            owner=form.get("owner",[""])[0][:150]
            status=form.get("status",["Active"])[0]
            html_body=form.get("html_body",[""])[0]
            text_body=form.get("text_body",[""])[0][:10000]
            if not name or not html_body:
                return self.sendbody(400,"Template name and HTML body are required","text/plain")
            if status not in ("Active","Archived"): status="Active"
            if from_email and not re.fullmatch(r"[^@\\s]+@[^@\\s]+\\.[^@\\s]+",from_email):
                return self.sendbody(400,"Invalid From email","text/plain")
            if reply_to and not re.fullmatch(r"[^@\\s]+@[^@\\s]+\\.[^@\\s]+",reply_to):
                return self.sendbody(400,"Invalid Reply-To email","text/plain")
            ok,msg=validate_template_html(html_body)
            if not ok: return self.sendbody(400,msg,"text/plain")
            fn=os.path.join(TEMPLATES,tid+".html")
            with open(fn,"w",encoding="utf-8") as tf: tf.write(html_body)
            c=db()
            existing=c.execute("SELECT version FROM template_library WHERE template=?",(tid,)).fetchone()
            next_version=(int(existing["version"]) if existing and existing["version"] else 0)+1
            c.execute("""INSERT INTO template_library(template,name,subject,preheader,category,difficulty,language,brand,industry,tags,html_body,text_body,version,from_name,from_email,reply_to,owner,status,updated_at)
                         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                         ON CONFLICT(template) DO UPDATE SET name=excluded.name,subject=excluded.subject,preheader=excluded.preheader,
                         category=excluded.category,difficulty=excluded.difficulty,language=excluded.language,brand=excluded.brand,
                         industry=excluded.industry,tags=excluded.tags,html_body=excluded.html_body,text_body=excluded.text_body,version=excluded.version,
                         from_name=excluded.from_name,from_email=excluded.from_email,reply_to=excluded.reply_to,owner=excluded.owner,status=excluded.status,updated_at=excluded.updated_at""",
                      (tid,name,subject,preheader,category,difficulty,language,brand,industry,tags,html_body,text_body,next_version,from_name,from_email,reply_to,owner,status,now()))
            c.execute("""INSERT INTO template_versions(template,version,name,subject,preheader,category,difficulty,language,brand,industry,tags,html_body,text_body,created_at,created_by)
                         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (tid,next_version,name,subject,preheader,category,difficulty,language,brand,industry,tags,html_body,text_body,now(),ADMIN_USERNAME))
            c.commit(); c.close()
            audit(ADMIN_USERNAME,"TEMPLATE_UPDATE","template=%s name=%s"%(tid,name),ip)
            return self.sendbody(302,b"",extra={"Location":"/admin/templates"})
        if p.path=="/admin/templates/test-send":
            admin=self.current_admin()
            if not admin: return self.sendbody(403,"Forbidden","text/plain")
            tid=form.get("template",[""])[0]
            to_email=form.get("to_email",[""])[0].strip()
            smtp_id=form.get("smtp_profile_id",[""])[0]
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",to_email) or not smtp_id.isdigit():
                return self.sendbody(400,"Invalid test-send parameters","text/plain")
            c=db()
            tpl=c.execute("SELECT * FROM template_library WHERE template=?",(tid,)).fetchone()
            profile=c.execute("SELECT * FROM smtp_profiles WHERE id=? AND enabled=1",(int(smtp_id),)).fetchone()
            c.close()
            if not tpl: return self.sendbody(404,"Template not found","text/plain")
            if not profile: return self.sendbody(400,"SMTP profile is unavailable","text/plain")
            if (tpl["status"] or "Active")!="Active": return self.sendbody(400,"Archived templates cannot be test-sent","text/plain")
            ok,msg=validate_template_html(tpl["html_body"] or "")
            if not ok: return self.sendbody(400,msg,"text/plain")
            smtp=smtp_connect(profile)
            try:
                msg_obj=EmailMessage()
                msg_obj["Subject"]="[TEST] "+(tpl["subject"] or tpl["name"])
                sender_email=tpl["from_email"] or profile["from_email"]
                sender_name=tpl["from_name"] or profile["from_name"] or "Trust PhishGuard"
                msg_obj["From"]=formataddr((sender_name,sender_email))
                msg_obj["To"]=to_email
                if tpl["reply_to"] or profile["reply_to"]: msg_obj["Reply-To"]=tpl["reply_to"] or profile["reply_to"]
                msg_obj.set_content(tpl["text_body"] or "Trust PhishGuard authorized security-awareness simulation test message.")
                msg_obj.add_alternative(tpl["html_body"],subtype="html")
                smtp.send_message(msg_obj)
            finally:
                smtp.quit()
            audit(admin["username"],"TEMPLATE_TEST_SEND","template=%s to=%s smtp_profile=%s"%(tid,to_email,smtp_id),ip)
            return self.sendbody(302,b"",extra={"Location":"/admin/templates?id="+tid})
        if p.path=="/admin/reports/scheduled/save":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            name=form.get("name",[""])[0].strip()[:120]
            frequency=form.get("frequency",["Weekly"])[0]
            smtp_id=form.get("smtp_profile_id",[""])[0]
            recipients=form.get("recipients",[""])[0].strip()[:3000]
            next_run=form.get("next_run_at",[""])[0].strip()
            if not name or frequency not in ("Daily","Weekly","Monthly") or not smtp_id.isdigit() or not recipients or not next_run:
                return self.sendbody(400,"Invalid scheduled report configuration","text/plain")
            try:
                dt=datetime.fromisoformat(next_run).replace(tzinfo=TZ)
                if dt.astimezone(timezone.utc)<=datetime.now(timezone.utc):
                    return self.sendbody(400,"First run must be in the future","text/plain")
            except Exception:
                return self.sendbody(400,"Invalid first-run date/time","text/plain")
            emails=[x.strip() for x in recipients.split(",") if x.strip()]
            if not emails or any("@" not in x or len(x)>254 for x in emails[:50]):
                return self.sendbody(400,"Enter valid recipient email addresses","text/plain")
            c=db()
            if not c.execute("SELECT 1 FROM smtp_profiles WHERE id=? AND enabled=1",(int(smtp_id),)).fetchone():
                c.close(); return self.sendbody(400,"SMTP profile is unavailable","text/plain")
            try:
                c.execute("INSERT INTO scheduled_reports(name,frequency,report_view,smtp_profile_id,recipients,next_run_at,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",(name,frequency,"executive",int(smtp_id),", ".join(emails[:50]),dt.astimezone(timezone.utc).isoformat(),1,now(),now()))
                c.commit()
            except sqlite3.IntegrityError:
                c.close(); return self.sendbody(409,"Scheduled report name already exists","text/plain")
            c.close()
            audit(ADMIN_USERNAME,"SCHEDULED_REPORT_CREATE","name=%s frequency=%s"%(name,frequency),ip)
            return self.sendbody(302,b"",extra={"Location":"/admin/reports/scheduled"})
        if p.path=="/admin/admins/create":
            admin=self.current_admin()
            if not admin or admin.get("role")!="Administrator":
                return self.sendbody(403,"Administrator role required","text/plain")
            username=form.get("username",[""])[0].strip().lower()[:254]
            password=form.get("password",[""])[0]
            role=form.get("role",[""])[0].strip()
            allowed_roles=("Administrator","Campaign Manager","Reporting Analyst","SMTP Manager","Security Auditor")
            if not re.fullmatch(r"[^@\\s]+@[^@\\s]+\\.[^@\\s]+",username):
                return self.sendbody(400,"A valid administrator email is required","text/plain")
            if len(password)<12 or len(password)>256 or "\\r" in password or "\\n" in password:
                return self.sendbody(400,"Temporary password must be 12-256 characters and must not contain line breaks","text/plain")
            if role not in allowed_roles:
                return self.sendbody(400,"Invalid administrator role","text/plain")
            c=db()
            existing=c.execute("SELECT id FROM admins WHERE lower(username)=lower(?)",(username,)).fetchone()
            if existing:
                c.close()
                return self.sendbody(409,"An administrator with this email already exists","text/plain")
            c.execute("INSERT INTO admins(username,role,password_hash,active,created_at) VALUES(?,?,?,?,?)",
                      (username,role,password_hash(password),1,now()))
            c.commit()
            c.close()
            audit(admin["username"],"ADMIN_CREATE","username=%s role=%s"%(username,role),ip)
            return self.sendbody(302,b"",extra={"Location":"/admin/admins"})

        if p.path=="/admin/roles/create":
            admin=self.current_admin()
            if not admin or admin.get("role")!="Administrator":
                return self.sendbody(403,"Administrator role required","text/plain")
            name=form.get("name",[""])[0].strip()
            description=form.get("description",[""])[0].strip()
            if not name or len(name)>80 or "\r" in name or "\n" in name:
                return self.sendbody(400,"Custom role name must be 1-80 characters and must not contain line breaks","text/plain")
            if len(description)>500 or "\r" in description or "\n" in description:
                return self.sendbody(400,"Role description must be 500 characters or fewer and must not contain line breaks","text/plain")
            slug=re.sub(r"[^a-z0-9]+","-",name.lower()).strip("-")
            if not slug or len(slug)>80:
                return self.sendbody(400,"Invalid custom role name","text/plain")
            built_in_roles=("Administrator","Campaign Manager","Reporting Analyst","SMTP Manager","Security Auditor")
            if name in built_in_roles:
                return self.sendbody(400,"Built-in role names are protected","text/plain")
            c=db()
            existing=c.execute("SELECT id FROM rbac_roles WHERE lower(name)=lower(?) OR slug=?",(name,slug)).fetchone()
            if existing:
                c.close()
                return self.sendbody(409,"A custom role with this name already exists","text/plain")
            ts=now()
            c.execute("INSERT INTO rbac_roles(name,slug,description,built_in,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                      (name,slug,description,0,1,ts,ts))
            c.commit()
            c.close()
            audit(admin["username"],"ROLE_CREATE","name=%s slug=%s"%(name,slug),ip)
            return self.sendbody(302,b"",extra={"Location":"/admin/admins?tab=roles"})

        if p.path=="/admin/admins/save":
            admin=self.current_admin()
            if not admin or admin.get("role")!="Administrator": return self.sendbody(403,"Administrator role required","text/plain")
            aid=form.get("id",[""])[0]
            role=form.get("role",[""])[0]
            active=form.get("active",["1"])[0]
            if not aid.isdigit() or role not in ("Administrator","Campaign Manager","Reporting Analyst","SMTP Manager","Security Auditor") or active not in ("0","1"):
                return self.sendbody(400,"Invalid administrator settings","text/plain")
            c=db(); row=c.execute("SELECT username,role,active FROM admins WHERE id=?",(int(aid),)).fetchone()
            if not row: c.close(); return self.sendbody(404,"Administrator not found","text/plain")
            if row["username"]==admin["username"] and (active=="0" or role!="Administrator"):
                c.close(); return self.sendbody(400,"You cannot disable or demote your current administrator account","text/plain")
            old_role=row["role"] or "Administrator"
            old_active=bool(row["active"])
            new_active=(active=="1")
            if old_role=="Administrator" and old_active and (role!="Administrator" or not new_active):
                remaining=c.execute("SELECT COUNT(*) AS n FROM admins WHERE id<>? AND role=? AND active=1",(int(aid),"Administrator")).fetchone()["n"]
                if remaining==0:
                    c.close(); return self.sendbody(400,"You cannot disable or demote the last active administrator account","text/plain")
            c.execute("UPDATE admins SET role=?,active=? WHERE id=?",(role,int(new_active),int(aid))); c.commit(); c.close()
            if role!=old_role:
                audit(admin["username"],"ADMIN_ROLE_UPDATE","username=%s role=%s"%(row["username"],role),ip)
            if new_active!=old_active:
                audit(admin["username"],"ADMIN_ENABLE" if new_active else "ADMIN_DISABLE","username=%s"%(row["username"]),ip)
            return self.sendbody(302,b"",extra={"Location":"/admin/admins"})
        if p.path=="/admin/risk/settings":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            try:
                vals={"click_weight":max(0,min(100,float(form.get("click_weight",["20"])[0]))),"form_action_weight":max(0,min(100,float(form.get("form_action_weight",["35"])[0]))),"report_bonus":max(-100,min(0,float(form.get("report_bonus",["-10"])[0]))),"repeat_bonus":max(0,min(100,float(form.get("repeat_bonus",["15"])[0]))),"lookback_days":max(1,min(3650,int(form.get("lookback_days",["180"])[0]))),"high_threshold":max(1,min(100,float(form.get("high_threshold",["70"])[0]))),"medium_threshold":max(1,min(100,float(form.get("medium_threshold",["40"])[0])))}
            except (ValueError,TypeError): return self.sendbody(400,"Invalid risk settings","text/plain")
            if vals["medium_threshold"]>=vals["high_threshold"]: return self.sendbody(400,"Medium threshold must be lower than High threshold","text/plain")
            c=db()
            for k,v in vals.items(): c.execute("INSERT INTO risk_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(k,str(v)))
            c.commit(); c.close(); risk_recalculate(); audit(ADMIN_USERNAME,"RISK_SETTINGS_UPDATE","risk scoring configuration updated",ip)
            return self.sendbody(302,b"",extra={"Location":"/admin/settings"})
        if p.path=="/admin/smtp/save":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            sid=form.get("id",[""])[0]; name=form.get("name",[""])[0][:100]; provider=form.get("provider",["Custom SMTP"])[0]
            host=form.get("host",[""])[0][:255]; port=int(form.get("port",["587"])[0]); security=form.get("security",["STARTTLS"])[0]
            username=form.get("username",[""])[0][:255]; password=form.get("password",[""])[0]; from_name=form.get("from_name",[""])[0][:150]
            from_email=form.get("from_email",[""])[0][:255]; reply_to=form.get("reply_to",[""])[0][:255]; auth_method=form.get("auth_method",["password"])[0]; oauth_url=form.get("oauth_token_url",[""])[0][:500]; oauth_client=form.get("oauth_client_id",[""])[0][:255]; oauth_scopes=form.get("oauth_scopes",[""])[0][:1000]; oauth_token=form.get("oauth_token",[""])[0]
            if provider not in SMTP_PROVIDERS or security not in ("STARTTLS","SSL/TLS","NONE") or auth_method not in ("password","oauth2") or not host or not from_email or port<1 or port>65535:
                return self.sendbody(400,"Invalid SMTP profile","text/plain")
            c=db()
            if sid:
                old=c.execute("SELECT password_enc,oauth_token_enc FROM smtp_profiles WHERE id=?",(sid,)).fetchone()
                enc=encrypt_secret(password) if password else (old["password_enc"] if old else ""); oauth_enc=encrypt_secret(oauth_token) if oauth_token else (old["oauth_token_enc"] if old else "")
                c.execute("UPDATE smtp_profiles SET name=?,provider=?,host=?,port=?,security=?,username=?,password_enc=?,from_name=?,from_email=?,reply_to=?,auth_method=?,oauth_token_enc=?,oauth_token_url=?,oauth_client_id=?,oauth_scopes=?,updated_at=? WHERE id=?",(name,provider,host,port,security,username,enc,from_name,from_email,reply_to,auth_method,oauth_enc,oauth_url,oauth_client,oauth_scopes,now(),sid)); action="SMTP_PROFILE_UPDATE"
            else:
                enc=encrypt_secret(password) if password else ""
                c.execute("INSERT INTO smtp_profiles(name,provider,host,port,security,username,password_enc,from_name,from_email,reply_to,auth_method,oauth_token_url,oauth_client_id,oauth_scopes,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(name,provider,host,port,security,username,enc,from_name,from_email,reply_to,auth_method,oauth_enc,oauth_url,oauth_client,oauth_scopes,1,now(),now())); action="SMTP_PROFILE_CREATE"
            c.commit(); c.close(); audit(ADMIN_USERNAME,action,name,ip)
            return self.sendbody(302,b"",extra={"Location":"/admin/smtp"})
        if p.path=="/admin/smtp/diagnostics":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            sid=form.get("id",[""])[0]; to_email=form.get("to_email",[""])[0].strip()[:254]
            if not sid.isdigit(): return self.sendbody(400,"Invalid SMTP profile","text/plain")
            if to_email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",to_email):
                return self.sendbody(400,"Invalid diagnostic recipient email","text/plain")
            c=db(); profile=c.execute("SELECT * FROM smtp_profiles WHERE id=?",(int(sid),)).fetchone(); c.close()
            if not profile: return self.sendbody(404,"SMTP profile not found","text/plain")
            results=smtp_diagnostics(profile,to_email)
            rows="".join("<tr><td>%s</td><td><b>%s</b></td><td>%s</td></tr>"%(esc(x["stage"]),esc(x["status"]),esc(x["detail"])) for x in results)
            audit(ADMIN_USERNAME,"SMTP_DIAGNOSTICS","profile=%s result=%s"%(profile["name"],",".join(x["status"] for x in results)),ip)
            body='<h1>SMTP Connectivity Diagnostics</h1><div class="card"><table class="table"><tr><th>Stage</th><th>Status</th><th>Detail</th></tr>%s</table><p><a class="btn" href="/admin/smtp">Back to SMTP Providers</a></p></div>'%rows
            return self.sendbody(200,self.admin_shell("SMTP Diagnostics",body,"SMTP"))
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
        if p.path=="/admin/training/update":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            aid=form.get("id",[""])[0]
            try:
                completion=max(0,min(100,float(form.get("completion",["0"])[0]))); raw=form.get("score",[""])[0].strip(); score=None if raw=="" else max(0,min(100,float(raw)))
            except (ValueError,TypeError): return self.sendbody(400,"Invalid completion or score","text/plain")
            c=db(); a=c.execute("""SELECT a.*,c.passing_score,c.name course,r.email FROM training_assignments a JOIN training_courses c ON c.id=a.course_id JOIN recipients r ON r.id=a.recipient_id WHERE a.id=?""",(aid,)).fetchone()
            if not a: c.close(); return self.sendbody(404,"Training assignment not found","text/plain")
            result="In Progress"; status="In Progress"; completed_at=None
            if completion>=100:
                completed_at=now()
                if score is not None and score>=a["passing_score"]: result="Passed"; status="Completed"
                elif score is not None: result="Failed"; status="Failed"
                else: result="Completed - Score Pending"; status="Completed"
            c.execute("UPDATE training_assignments SET completion=?,score=?,result=?,status=?,completed_at=?,result_at=? WHERE id=?",(completion,score,result,status,completed_at,now(),aid))
            c.execute("""INSERT INTO training_records(email,completion,course,updated_at) VALUES(?,?,?,?) ON CONFLICT(email) DO UPDATE SET completion=excluded.completion,course=excluded.course,updated_at=excluded.updated_at""",(a["email"],completion,a["course"],now())); c.commit(); c.close()
            if result=="Passed":
                record(ip,"training","training_completed","",a["email"] or "","","", "", "",a["trigger_campaign_id"] or "",a["recipient_id"],"")
            audit(ADMIN_USERNAME,"TRAINING_RESULT_UPDATE",f"assignment={aid} result={result} score={score if score is not None else ''}",ip)
            return self.sendbody(302,b"",extra={"Location":"/admin/training"})
        if p.path=="/admin/training/course/save":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            name=form.get("name",[""])[0][:150]; description=form.get("description",[""])[0][:1000]
            try: duration=max(1,min(480,int(form.get("duration_minutes",["15"])[0]))); passing=max(0,min(100,float(form.get("passing_score",["80"])[0])))
            except ValueError: return self.sendbody(400,"Invalid course values","text/plain")
            if not name: return self.sendbody(400,"Course name required","text/plain")
            c=db(); c.execute("""INSERT INTO training_courses(name,description,duration_minutes,passing_score,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)""",(name,description,duration,passing,"Active",now(),now())); c.commit(); c.close()
            audit(ADMIN_USERNAME,"TRAINING_COURSE_CREATE",name,ip)
            return self.sendbody(302,b"",extra={"Location":"/admin/training"})
        if p.path=="/admin/training/assign":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            course_id=form.get("course_id",[""])[0]; recipient_id=form.get("recipient_id",[""])[0]; due_at=form.get("due_at",[""])[0][:40]
            remediation_campaign_id=form.get("remediation_campaign_id",[""])[0]; trigger_campaign_id=form.get("trigger_campaign_id",[""])[0]
            c=db(); course=c.execute("SELECT * FROM training_courses WHERE id=? AND status='Active'",(course_id,)).fetchone(); recipient=c.execute("SELECT * FROM recipients WHERE id=? AND status!='Suppressed'",(recipient_id,)).fetchone()
            if not course or not recipient: c.close(); return self.sendbody(400,"Invalid course or recipient","text/plain")
            if remediation_campaign_id and not c.execute("SELECT 1 FROM campaigns WHERE id=?",(remediation_campaign_id,)).fetchone(): c.close(); return self.sendbody(400,"Invalid remediation campaign","text/plain")
            if trigger_campaign_id and not c.execute("SELECT 1 FROM campaigns WHERE id=?",(trigger_campaign_id,)).fetchone(): c.close(); return self.sendbody(400,"Invalid trigger campaign","text/plain")
            try:
                c.execute("""INSERT INTO training_assignments(course_id,recipient_id,assigned_at,due_at,status,completion,score,result,trigger_campaign_id,remediation_campaign_id)
                             VALUES(?,?,?,?,?,?,?,?,?,?)""",(course_id,recipient_id,now(),due_at,"Assigned",0,None,"Pending",trigger_campaign_id or None,remediation_campaign_id or None)); c.commit()
            except sqlite3.IntegrityError: c.close(); return self.sendbody(409,"Training is already assigned to this recipient","text/plain")
            c.close()
            record(ip,"training","training_assigned",recipient["name"] or "",recipient["email"] or "","","",recipient["employee_id"] or "","",trigger_campaign_id or "",recipient_id,"")
            audit(ADMIN_USERNAME,"TRAINING_ASSIGN",f"course={course_id} recipient={recipient_id} trigger_campaign={trigger_campaign_id or ''} remediation_campaign={remediation_campaign_id or ''}",ip)
            return self.sendbody(302,b"",extra={"Location":"/admin/training"})
        if p.path=="/admin/recipients/save":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            rid=form.get("id",[""])[0]; email=form.get("email",[""])[0].strip().lower()
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",email): return self.sendbody(400,"Invalid email address","text/plain")
            c=db()
            existing=c.execute("SELECT id FROM recipients WHERE email=? AND id!=?",(email,rid)).fetchone()
            employee=form.get("employee_id",[""])[0].strip()[:100]
            employee_conflict=c.execute("SELECT id FROM recipients WHERE employee_id=? AND id!=? AND employee_id!=''",(employee,rid)).fetchone() if employee else None
            if existing: c.close(); return self.sendbody(409,"A recipient with this email already exists","text/plain")
            if employee_conflict: c.close(); return self.sendbody(409,"Employee ID is already assigned to another recipient","text/plain")
            c.execute("UPDATE recipients SET email=?,name=?,employee_id=?,department=?,designation=?,location=?,manager=?,language=?,timezone=?,group_name=?,status=? WHERE id=?",(email,form.get("name",[""])[0][:150],employee,form.get("department",[""])[0][:100],form.get("designation",[""])[0][:150],form.get("location",[""])[0][:150],form.get("manager",[""])[0][:150],form.get("language",["English"])[0][:50],form.get("timezone",["Asia/Dhaka"])[0][:80],form.get("group_name",[""])[0][:100],form.get("status",["Active"])[0] if form.get("status",["Active"])[0] in ("Active","Suppressed") else "Active",rid))
            c.commit(); c.close(); audit(ADMIN_USERNAME,"RECIPIENT_PROFILE_UPDATE","recipient=%s email=%s"%(rid,email),ip)
            return self.sendbody(302,b"",extra={"Location":"/admin/recipients"})
        if p.path=="/admin/recipients/import":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            raw=form.get("csv_data",[""])[0]; source=form.get("source_name",["CSV import"])[0][:150]
            reader=csv.DictReader(io.StringIO(raw)); c=db(); processed=created=updated=skipped=0; errors=[]; seen_emails=set(); seen_employees=set()
            for rownum,row in enumerate(reader,start=2):
                processed+=1; email=(row.get("email") or "").strip().lower()
                if not email or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",email): skipped+=1; errors.append("row %s: invalid email"%rownum); continue
                if email in seen_emails: skipped+=1; errors.append("row %s: duplicate email in file"%rownum); continue
                seen_emails.add(email); employee=(row.get("employee_id") or "").strip()[:100]
                if employee:
                    if employee in seen_employees: skipped+=1; errors.append("row %s: duplicate employee_id in file"%rownum); continue
                    seen_employees.add(employee)
                    conflict=c.execute("SELECT id,email FROM recipients WHERE employee_id=? AND employee_id!='' AND email!=?",(employee,email)).fetchone()
                    if conflict: skipped+=1; errors.append("row %s: employee_id already belongs to another email"%rownum); continue
                vals=((row.get("name") or "").strip()[:150],employee,(row.get("department") or "").strip()[:100],(row.get("designation") or "").strip()[:150],(row.get("location") or "").strip()[:150],(row.get("manager") or "").strip()[:150],(row.get("language") or "English").strip()[:50],(row.get("timezone") or "Asia/Dhaka").strip()[:80],(row.get("group_name") or "").strip()[:100])
                existing=c.execute("SELECT id FROM recipients WHERE email=?",(email,)).fetchone()
                if existing:
                    c.execute("UPDATE recipients SET name=?,employee_id=?,department=?,designation=?,location=?,manager=?,language=?,timezone=?,group_name=? WHERE id=?",(vals[0],vals[1],vals[2],vals[3],vals[4],vals[5],vals[6],vals[7],vals[8],existing["id"])); updated+=1
                else:
                    c.execute("INSERT INTO recipients(email,name,employee_id,department,designation,location,manager,language,timezone,group_name,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(email,*vals,"Active",now())); created+=1
            errtxt="; ".join(errors[:20])
            c.execute("INSERT INTO recipient_import_history(source_name,processed,created,updated,skipped,errors,created_at) VALUES(?,?,?,?,?,?,?)",(source,processed,created,updated,skipped,errtxt,now()))
            c.commit(); c.close(); audit(ADMIN_USERNAME,"RECIPIENT_IMPORT","source=%s processed=%s created=%s updated=%s skipped=%s"%(source,processed,created,updated,skipped),ip)
            return self.sendbody(200,page("Recipients Imported","<div style='max-width:760px;margin:70px auto;background:#fff;padding:30px;border-radius:16px;border:1px solid #dce7e2'><h2>Recipient import complete</h2><p>Processed: <b>%s</b> · Created: <b>%s</b> · Updated: <b>%s</b> · Skipped: <b>%s</b></p><p>%s</p><p><a href='/admin/recipients'>Back to Recipients</a></p></div>"%(processed,created,updated,skipped,esc(errtxt or "No validation errors."))))
        if p.path=="/admin/groups/save":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            name=form.get("name",[""])[0][:100]; department=form.get("department",[""])[0][:100]
            if not name: return self.sendbody(400,"Group name required","text/plain")
            c=db(); c.execute("INSERT OR IGNORE INTO groups_tbl(name,department,created_at) VALUES(?,?,?)",(name,department,now())); c.commit(); c.close(); audit(ADMIN_USERNAME,"GROUP_CREATE",name,ip)
            return self.sendbody(302,b"",extra={"Location":"/admin/groups"})
        if p.path=="/admin/campaigns/control":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            cid=form.get("id",[""])[0]
            action=form.get("action",[""])[0]
            if action not in ("pause","resume","cancel"): return self.sendbody(400,"Invalid campaign action","text/plain")
            c=db()
            campaign=c.execute("SELECT id,status FROM campaigns WHERE id=?",(cid,)).fetchone()
            if not campaign:
                c.close()
                return self.sendbody(404,"Campaign not found","text/plain")
            if action=="pause":
                c.execute("UPDATE campaigns SET status='Paused',updated_at=? WHERE id=? AND status IN ('Scheduled','Active')",(now(),cid))
            elif action=="resume":
                c.execute("UPDATE campaigns SET status='Active',cancel_requested=0,updated_at=? WHERE id=? AND status='Paused'",(now(),cid))
            else:
                c.execute("UPDATE campaigns SET status='Cancelled',cancel_requested=1,updated_at=? WHERE id=? AND status NOT IN ('Completed','Cancelled','Expired')",(now(),cid))
                c.execute("UPDATE campaign_queue SET status='Cancelled',updated_at=? WHERE campaign_id=? AND status IN ('Pending','Failed')",(now(),cid))
            c.commit()
            c.close()
            audit(ADMIN_USERNAME,"CAMPAIGN_CONTROL","campaign=%s action=%s"%(cid,action),ip)
            return self.sendbody(302,b"",extra={"Location":"/admin/campaigns?id="+str(cid)})
        if p.path=="/admin/campaigns/test-send":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            cid=form.get("id",[""])[0]
            to_email=form.get("to_email",[""])[0].strip().lower()
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",to_email): return self.sendbody(400,"Invalid test recipient email","text/plain")
            c=db(); campaign=c.execute("SELECT c.*,s.* FROM campaigns c JOIN smtp_profiles s ON s.id=c.smtp_profile_id WHERE c.id=?",(cid,)).fetchone(); c.close()
            if not campaign: return self.sendbody(404,"Campaign not found","text/plain")
            errors=campaign_prelaunch_validation(campaign)
            if errors: return self.sendbody(409,"Test-send blocked by pre-launch validation: "+" ".join(errors),"text/plain")
            try:
                msg=EmailMessage()
                msg["From"]=formataddr((campaign["from_name"] or "Trust PhishGuard",campaign["from_email"]))
                msg["To"]=to_email
                msg["Subject"]="[TEST] "+(campaign["subject"] or "Trust PhishGuard Simulation")
                if campaign["reply_to"]: msg["Reply-To"]=campaign["reply_to"]
                msg.set_content("This is a pre-launch test message for an authorized Trust PhishGuard security-awareness simulation. No credentials are requested or collected.")
                smtp=smtp_connect(campaign); smtp.send_message(msg); smtp.quit()
                audit(ADMIN_USERNAME,"CAMPAIGN_TEST_SEND","campaign=%s recipient=%s"%(cid,to_email),ip)
                return self.sendbody(200,page("Campaign Test Send","<div style='max-width:760px;margin:70px auto;background:#fff;padding:30px;border-radius:16px;border:1px solid #dce7e2'><h2>Test message sent</h2><p>The pre-launch test message was accepted by the configured SMTP server.</p><p>No campaign recipient was contacted or tracked.</p><p><a href='/admin/campaigns?id=%s'>Back to Campaign</a></p></div>"%cid))
            except Exception:
                audit(ADMIN_USERNAME,"CAMPAIGN_TEST_SEND_FAILED","campaign=%s recipient=%s"%(cid,to_email),ip)
                return self.sendbody(502,page("Campaign Test Send Failed","<div style='max-width:760px;margin:70px auto;background:#fff;padding:30px;border-radius:16px;border:1px solid #dce7e2'><h2>Test message failed</h2><p>SMTP connection or authentication failed. No SMTP secret is displayed.</p></div>"))
        if p.path=="/admin/campaigns/launch":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            cid=form.get("id",[""])[0]
            if form.get("confirm",[""])[0]!="YES": return self.sendbody(400,"Launch confirmation required","text/plain")
            c=db(); campaign=c.execute("SELECT * FROM campaigns WHERE id=?",(cid,)).fetchone(); c.close()
            if not campaign: return self.sendbody(404,"Campaign not found","text/plain")
            if campaign["status"]=="Completed": return self.sendbody(409,"Campaign already completed","text/plain")
            errors=campaign_prelaunch_validation(campaign)
            if errors:
                return self.sendbody(409,"Pre-launch validation failed: "+" ".join(errors),"text/plain")
            try:
                sent,failed,total=send_campaign(cid)
                audit(ADMIN_USERNAME,"CAMPAIGN_LAUNCH","campaign=%s sent=%s failed=%s total=%s"%(cid,sent,failed,total),ip)
                return self.sendbody(200,page("Campaign Launch","<div style='max-width:760px;margin:70px auto;background:#fff;padding:30px;border-radius:16px;border:1px solid #dce7e2'><h2>Campaign launch complete</h2><p>Attempted: %s · Sent: %s · Failed: %s</p><p><a href='/admin/campaigns'>Back to Campaigns</a></p></div>"%(total,sent,failed)))
            except Exception:
                audit(ADMIN_USERNAME,"CAMPAIGN_LAUNCH_FAILED","campaign=%s"%cid,ip)
                return self.sendbody(502,page("Campaign Launch Failed","<div style='max-width:760px;margin:70px auto;background:#fff;padding:30px;border-radius:16px'><h2>Campaign launch failed</h2><p>Check PUBLIC_BASE_URL, SMTP configuration, target recipients and server logs. SMTP credentials are not displayed.</p><p><a href='/admin/campaigns'>Back to Campaigns</a></p></div>"))
        if p.path=="/admin/campaigns/save":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            cid=form.get("id",[""])[0]
            name=form.get("name",[""])[0][:150]
            template=form.get("template",["1"])[0]
            status=form.get("status",["Draft"])[0]
            smtp_id=form.get("smtp_profile_id",[""])[0]
            landing_id=form.get("landing_page_id",[""])[0]
            group_name=form.get("group_name",[""])[0][:100]
            subject=form.get("subject",["Security Awareness Simulation"])[0][:250]
            launch_at=form.get("launch_at",[""])[0][:40]
            send_by=form.get("send_by",[""])[0][:40]
            timezone=form.get("timezone",["Asia/Dhaka"])[0][:80]
            business_days=form.get("business_days",["Sun,Mon,Tue,Wed,Thu"])[0][:100]
            window_start=form.get("window_start",["09:00"])[0][:5]
            window_end=form.get("window_end",["17:00"])[0][:5]
            try:
                batch_size=max(1,min(1000,int(form.get("batch_size",["50"])[0])))
                rate_per_minute=max(1,min(1000,int(form.get("rate_per_minute",["60"])[0])))
                retry_max=max(0,min(5,int(form.get("retry_max",["2"])[0])))
                retry_backoff=max(1,min(300,int(form.get("retry_backoff_seconds",["5"])[0])))
                zone=ZoneInfo(timezone)
                if datetime.strptime(window_end,"%H:%M") <= datetime.strptime(window_start,"%H:%M"): raise ValueError()
                days={x.strip() for x in business_days.split(",") if x.strip()}
                if not days or not days.issubset({"Mon","Tue","Wed","Thu","Fri","Sat","Sun"}): raise ValueError()
                if launch_at and send_by and campaign_dt(send_by,zone) < campaign_dt(launch_at,zone): raise ValueError()
            except Exception:
                return self.sendbody(400,"Invalid scheduler settings or send-by deadline","text/plain")
            c=db()
            if not smtp_id or not c.execute("SELECT 1 FROM smtp_profiles WHERE id=? AND enabled=1",(smtp_id,)).fetchone():
                c.close(); return self.sendbody(400,"A valid SMTP provider is required","text/plain")
            if not landing_id or not c.execute("SELECT 1 FROM landing_pages WHERE id=? AND status='Enabled'",(landing_id,)).fetchone():
                c.close(); return self.sendbody(400,"A valid landing page is required","text/plain")
            if group_name:
                targeted=c.execute("SELECT COUNT(*) n FROM recipients WHERE group_name=?",(group_name,)).fetchone()["n"]
            else:
                targeted=c.execute("SELECT COUNT(*) n FROM recipients").fetchone()["n"]
            if cid:
                c.execute("UPDATE campaigns SET name=?,template=?,status=?,targeted=?,smtp_profile_id=?,landing_page_id=?,subject=?,launch_at=?,send_by=?,group_name=?,timezone=?,business_days=?,window_start=?,window_end=?,batch_size=?,rate_per_minute=?,retry_max=?,retry_backoff_seconds=?,cancel_requested=?,updated_at=? WHERE id=?",(name,template,status,targeted,smtp_id,landing_id,subject,launch_at,send_by,group_name,timezone,business_days,window_start,window_end,batch_size,rate_per_minute,retry_max,retry_backoff,0,now(),cid))
                action="CAMPAIGN_UPDATE"
            else:
                c.execute("INSERT INTO campaigns(name,template,status,targeted,smtp_profile_id,landing_page_id,subject,launch_at,send_by,group_name,timezone,business_days,window_start,window_end,batch_size,rate_per_minute,retry_max,retry_backoff_seconds,cancel_requested,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(name,template,status,targeted,smtp_id,landing_id,subject,launch_at,send_by,group_name,timezone,business_days,window_start,window_end,batch_size,rate_per_minute,retry_max,retry_backoff,0,now(),now()))
                action="CAMPAIGN_CREATE"
            c.commit(); c.close()
            audit(ADMIN_USERNAME,action,"%s targeted=%s group=%s"%(name,targeted,group_name or "all"),ip)
            return self.sendbody(302,b"",extra={"Location":"/admin/campaigns"})

        if p.path=="/submit":
            t=form.get("template",["unknown"])[0][:50]
            name=form.get("name",[""])[0][:150]; employee_id=form.get("employee_id",[""])[0][:100]
            email=form.get("email",[""])[0][:200]; mobile=form.get("mobile",[""])[0][:50]
            card_type=form.get("card_type",[""])[0][:100]
            qs=parse_qs(p.query); token=qs.get("t",[""])[0]; tr=resolve_tracking_token(token)
            campaign_id=str(tr["campaign_id"]) if tr else ""; recipient_id=str(tr["recipient_id"]) if tr else ""
            record(ip,t,"form_action",name,email,mobile,self.headers.get("User-Agent",""),employee_id,card_type,campaign_id,recipient_id,token)
            access(ip,p.path,200)
            return self.sendbody(200,page("Simulation Complete","<div style='max-width:760px;margin:80px auto;background:#fff;padding:35px;border-radius:18px;border:1px solid #dce7e2'><h1>Security Awareness Simulation</h1><p>Simulation complete. No password, OTP, PIN, CVV or card information was requested or stored.</p></div>"))
        return self.sendbody(404,"Not found","text/plain")

def scheduled_report_next_run(frequency, current):
    if frequency=="Daily": return current+timedelta(days=1)
    if frequency=="Weekly": return current+timedelta(days=7)
    local=current.astimezone(TZ)
    first=datetime(local.year + (1 if local.month==12 else 0), 1 if local.month==12 else local.month+1, 1, 9, 0, tzinfo=TZ)
    return first.astimezone(timezone.utc)

def send_scheduled_report(row):
    c=db()
    profile=c.execute("SELECT * FROM smtp_profiles WHERE id=? AND enabled=1",(row["smtp_profile_id"],)).fetchone()
    if not profile: raise RuntimeError("Scheduled report SMTP profile is unavailable")
    now_utc=datetime.now(timezone.utc)
    if row["frequency"]=="Daily": start=now_utc-timedelta(days=1)
    elif row["frequency"]=="Weekly": start=now_utc-timedelta(days=7)
    else:
        local=now_utc.astimezone(TZ)
        first_this=datetime(local.year,local.month,1,tzinfo=TZ)
        prev_end=first_this
        prev_start=(datetime(local.year-1,12,1,tzinfo=TZ) if local.month==1 else datetime(local.year,local.month-1,1,tzinfo=TZ))
        start=prev_start.astimezone(timezone.utc); now_utc=prev_end.astimezone(timezone.utc)
    end=now_utc
    start_day=start.astimezone(TZ).date().isoformat(); end_day=(end-timedelta(seconds=1)).astimezone(TZ).date().isoformat()
    total=c.execute("SELECT COUNT(*) n FROM events WHERE ts>=? AND ts<?",(start.isoformat(),end.isoformat())).fetchone()["n"]
    clicks=c.execute("SELECT COUNT(*) n FROM events WHERE ts>=? AND ts<? AND event='click'",(start.isoformat(),end.isoformat())).fetchone()["n"]
    actions=c.execute("SELECT COUNT(*) n FROM events WHERE ts>=? AND ts<? AND event='form_action'",(start.isoformat(),end.isoformat())).fetchone()["n"]
    reports=c.execute("SELECT COUNT(*) n FROM events WHERE ts>=? AND ts<? AND event='report'",(start.isoformat(),end.isoformat())).fetchone()["n"]
    lines=["Trust PhishGuard — Scheduled Executive Report","Period: %s to %s"%(start_day,end_day),"","Total events: %s"%total,"Clicks: %s"%clicks,"Actions: %s"%actions,"Reports: %s"%reports,"Action rate: %.1f%%"%((actions/max(clicks,1))*100),"Report rate: %.1f%%"%((reports/max(clicks,1))*100),"","Metrics reflect measured simulation telemetry only; unmeasured opens are not inferred."]
    c.close()
    pdf=build_pdf(lines)
    recipients=[x.strip() for x in (row["recipients"] or "").split(",") if "@" in x.strip()][:50]
    if not recipients: raise RuntimeError("Scheduled report has no valid recipient addresses")
    smtp=smtp_connect(profile)
    try:
        msg=EmailMessage()
        msg["Subject"]="Trust PhishGuard — %s report (%s to %s)"%(row["frequency"],start_day,end_day)
        msg["From"]=formataddr((profile["from_name"] or "Trust PhishGuard",profile["from_email"]))
        msg["To"]=", ".join(recipients)
        if profile["reply_to"]: msg["Reply-To"]=profile["reply_to"]
        msg.set_content("Attached is the Trust PhishGuard scheduled executive report for %s to %s."%(start_day,end_day))
        msg.add_attachment(pdf,maintype="application",subtype="pdf",filename="phishguard-report-%s-to-%s.pdf"%(start_day,end_day))
        smtp.send_message(msg)
    finally:
        smtp.quit()
    c=db(); c.execute("UPDATE scheduled_reports SET last_run_at=?,last_status=?,next_run_at=?,updated_at=? WHERE id=?",(now(),"Sent",scheduled_report_next_run(row["frequency"],datetime.now(timezone.utc)).isoformat(),now(),row["id"])); c.commit(); c.close()

def scheduler_loop():
    while True:
        try:
            c=db()
            scheduled=c.execute("SELECT id,launch_at,timezone FROM campaigns WHERE status='Scheduled' AND launch_at IS NOT NULL AND launch_at!=''").fetchall()
            active=c.execute("SELECT id FROM campaigns WHERE status='Active' AND cancel_requested=0").fetchall()
            c.close()
            now_utc=datetime.now(timezone.utc)
            for row in scheduled:
                try:
                    zone=ZoneInfo(row["timezone"] or "Asia/Dhaka")
                    dt=campaign_dt(row["launch_at"],zone)
                    if dt and dt.astimezone(timezone.utc) <= now_utc:
                        send_campaign(row["id"],scheduled=True)
                except Exception:
                    pass
            c=db()
            due_reports=c.execute("SELECT * FROM scheduled_reports WHERE enabled=1 AND next_run_at<=?",(now_utc.isoformat(),)).fetchall()
            c.close()
            for report in due_reports:
                try:
                    send_scheduled_report(report)
                except Exception as exc:
                    c=db()
                    c.execute("UPDATE scheduled_reports SET last_run_at=?,last_status=?,next_run_at=?,updated_at=? WHERE id=?",(now(),"Failed: %s"%str(exc)[:180],scheduled_report_next_run(report["frequency"],now_utc).isoformat(),now(),report["id"]))
                    c.commit(); c.close()
            for row in active:
                try:
                    send_campaign(row["id"],scheduled=True)
                except Exception:
                    pass
        except Exception:
            pass
        time.sleep(30)

if __name__=="__main__":
    db().close()
    threading.Thread(target=scheduler_loop,daemon=True,name="campaign-scheduler").start()
    ThreadingHTTPServer(("0.0.0.0",PORT),Handler).serve_forever()