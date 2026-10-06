#!/usr/bin/env python3
import os, sqlite3, csv, io, secrets, html, smtplib, ssl, subprocess, tempfile, re, threading, time
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
    CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, created_at TEXT);
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
        updated_at TEXT
    );
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
    if profile["username"]:
        smtp.login(profile["username"],decrypt_secret(profile["password_enc"]))
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
    msg["From"]=formataddr((campaign["from_name"] or "Trust PhishGuard",campaign["from_email"]))
    if campaign["reply_to"]:
        msg["Reply-To"]=campaign["reply_to"]
    msg["To"]=rec["email"]
    msg["Subject"]=campaign["subject"] or "Security Awareness Simulation"
    msg.set_content("Hello %s,\n\n%s\n\nReview the message here:\n%s\n\nReport this simulation:\n%s\n\nQR scan tracking endpoint:\n%s\n\nThis email is part of an authorized internal security-awareness simulation. No password, OTP, PIN, CVV or full card number is requested."%(rec["name"] or "Colleague",campaign["subject"] or "Security Awareness Simulation",link,PUBLIC_BASE_URL+"/report?t="+token,PUBLIC_BASE_URL+"/qr?t="+token))
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
    group=campaign["group_name"] or ""
    recipient_count=c.execute("SELECT COUNT(*) n FROM recipients WHERE status!='Suppressed' AND (group_name=? OR ?='')",(group,group)).fetchone()["n"]
    c.close()
    if not smtp: errors.append("Enabled SMTP provider is required.")
    if not landing: errors.append("Enabled landing page is required.")
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
    campaign=c.execute("""SELECT c.*,s.host,s.port,s.security,s.username,s.password_enc,s.from_name,s.from_email,s.reply_to
                          FROM campaigns c JOIN smtp_profiles s ON s.id=c.smtp_profile_id
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
        nav=[("Overview","/admin"),("Campaigns","/admin/campaigns"),("Templates","/admin/templates"),("Landing Pages","/admin/landing-pages"),("SMTP Providers","/admin/smtp"),("Training","/admin/training"),("Recipients","/admin/recipients"),("Groups & Departments","/admin/groups"),("Users & Groups","/admin/users"),("Reports","/admin/reports"),("Risk & Trends","/admin/risk"),("Exports","/admin/exports"),("Settings","/admin/settings"),("Audit Log","/admin/audit")]
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
        if path=="/admin/reports":
            total=c.execute("SELECT COUNT(*) n FROM events").fetchone()["n"]; clicks=c.execute("SELECT COUNT(*) n FROM events WHERE event='click'").fetchone()["n"]; subs=c.execute("SELECT COUNT(*) n FROM events WHERE event='submitted'").fetchone()["n"]
            campaigns=c.execute("""SELECT c.id,c.name,c.status,c.targeted,COALESCE((SELECT COUNT(*) FROM campaign_deliveries d WHERE d.campaign_id=c.id AND d.status='Sent'),0) sent,COALESCE((SELECT COUNT(*) FROM campaign_deliveries d WHERE d.campaign_id=c.id AND d.status='Failed'),0) failed,COALESCE((SELECT COUNT(*) FROM events e WHERE e.campaign_id=c.id AND e.event='click'),0) clicks,COALESCE((SELECT COUNT(*) FROM events e WHERE e.campaign_id=c.id AND e.event='form_action'),0) submissions,COALESCE((SELECT COUNT(*) FROM events e WHERE e.campaign_id=c.id AND e.event='report'),0) reports FROM campaigns c ORDER BY c.id DESC""").fetchall(); c.close()
            rate=subs/clicks*100 if clicks else 0
            rows="".join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><a class="btn" href="/admin/reports?campaign_id=%s">Details</a></td></tr>'%(r["id"],esc(r["name"]),esc(r["status"]),r["targeted"],r["sent"],r["failed"],r["clicks"],r["id"]) for r in campaigns) or '<tr><td colspan="8">No campaign telemetry yet.</td></tr>'
            return self.admin_shell("Reports",'<h1>Campaign Reports</h1><p>Measured delivery and simulation telemetry.</p><div class="card"><h3>Overall</h3><p>Total events: %s · Clicks: %s · Simulation actions: %s · Action rate: %.1f%%</p></div><div class="card"><table class="table"><tr><th>ID</th><th>Campaign</th><th>Status</th><th>Targeted</th><th>Sent</th><th>Failed</th><th>Clicks</th><th></th></tr>%s</table></div>'%(total,clicks,subs,rate,rows),"Reports")
        if path=="/admin/exports":
            total=c.execute("SELECT COUNT(*) n FROM events").fetchone()["n"]; clicks=c.execute("SELECT COUNT(*) n FROM events WHERE event='click'").fetchone()["n"]; subs=c.execute("SELECT COUNT(*) n FROM events WHERE event='submitted'").fetchone()["n"]; c.close(); rate=subs/clicks*100 if clicks else 0
            return self.admin_shell("Exports",'<h1>Exports</h1><p>Download measured simulation telemetry. SMTP passwords and encrypted secrets are excluded.</p><div class="card"><h3>Events</h3><p>Total: %s · Clicks: %s · Actions: %s · Action rate: %.1f%%</p><a class="btn primary" href="/admin.csv">Export Event CSV</a></div>'%(total,clicks,subs,rate),"Exports")
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
        name=esc(r["name"]) if r else ""; username=esc(r["username"]) if r else ""; from_name=esc(r["from_name"]) if r else ""; from_email=esc(r["from_email"]) if r else ""; reply_to=esc(r["reply_to"]) if r else ""
        opts="".join('<option value="%s" %s>%s</option>'%(esc(k),"selected" if k==provider else "",esc(k)) for k in SMTP_PROVIDERS)
        secs="".join('<option value="%s" %s>%s</option>'%(x,"selected" if x==security else "",x) for x in ("STARTTLS","SSL/TLS","NONE"))
        return self.admin_shell("SMTP Provider",'<h1>%s SMTP Provider</h1><div class="card"><form class="form" method="post" action="/admin/smtp/save"><input type="hidden" name="id" value="%s"><label>Profile Name<input name="name" value="%s" required></label><label>Provider<select id="provider" name="provider" onchange="presetProvider()">%s</select></label><label>SMTP Host<input id="host" name="host" value="%s" required></label><label>Port<input id="port" type="number" min="1" max="65535" name="port" value="%s" required></label><label>Security<select id="security" name="security">%s</select></label><label>Username / SMTP account<input name="username" value="%s" autocomplete="username"></label><label>Password<input type="password" name="password" value="" autocomplete="new-password" placeholder="%s"></label><label>From Name<input name="from_name" value="%s"></label><label>From Email<input type="email" name="from_email" value="%s" required></label><label>Reply-To<input type="email" name="reply_to" value="%s"></label><div style="padding:12px;background:#f4f7f6;border-radius:8px;font-size:12px;color:#60716a">Password is write-only. Leave it blank when editing to keep the existing encrypted secret.</div><button class="btn primary">Save Provider</button></form></div><script>const presets=%s;function presetProvider(){const p=presets[document.getElementById("provider").value];if(p){document.getElementById("host").value=p.host;document.getElementById("port").value=p.port;document.getElementById("security").value=p.security}}</script>'%( "Edit" if r else "Add",sid or "",name,opts,host,port,secs,username,"unchanged" if r else "enter SMTP password",from_name,from_email,reply_to,html.escape(str(SMTP_PROVIDERS).replace("'",'"'))),"SMTP Providers")
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
        c.close()
        if not r:
            return self.admin_shell("Template","<h1>Template not found</h1><p><a class='btn' href='/admin/templates'>Back</a></p>","Templates")
        def val(k): return esc(r[k] or "")
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
<label>HTML Body<textarea name="html_body" rows="22" style="width:100%%;font-family:Consolas,monospace;padding:12px;border:1px solid #ccd9d4;border-radius:8px" required>%s</textarea></label>
<label>Plain Text Body<textarea name="text_body" rows="8" style="width:100%%;padding:12px;border:1px solid #ccd9d4;border-radius:8px">%s</textarea></label>
<div style="display:flex;gap:8px"><button class="btn primary">Save Template</button><a class="btn" target="_blank" href="/%s.html">Preview</a><a class="btn" href="/admin/templates">Cancel</a></div>
</form></div>"""%(val("template"),val("template"),val("name"),val("subject"),val("preheader"),catopts,diffopts,langopts,val("brand"),val("industry"),val("tags"),val("html_body"),val("text_body"),val("template"))
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
        if path in ("/admin/campaigns","/admin/templates","/admin/landing-pages","/admin/smtp","/admin/training","/admin/recipients","/admin/groups","/admin/users","/admin/reports","/admin/risk","/admin/exports","/admin/settings","/admin/audit"):
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
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
            return self.sendbody(200,self.feature_page(path))
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
            if secrets.compare_digest(username,ADMIN_USERNAME) and secrets.compare_digest(password,ADMIN_PASSWORD):
                sid=secrets.token_urlsafe(32); SESSIONS.add(sid)
                ck=cookies.SimpleCookie(); ck["admin_session"]=sid; ck["admin_session"]["HttpOnly"]=True; ck["admin_session"]["SameSite"]="Strict"
                return self.sendbody(302,b"",extra={"Location":"/admin","Set-Cookie":ck["admin_session"].OutputString()})
            return self.sendbody(401,self.login_page("Invalid username or password"))
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
            html_body=form.get("html_body",[""])[0]
            text_body=form.get("text_body",[""])[0][:10000]
            if not name or not html_body:
                return self.sendbody(400,"Template name and HTML body are required","text/plain")
            fn=os.path.join(TEMPLATES,tid+".html")
            with open(fn,"w",encoding="utf-8") as tf: tf.write(html_body)
            c=db()
            c.execute("""INSERT INTO template_library(template,name,subject,preheader,category,difficulty,language,brand,industry,tags,html_body,text_body,updated_at)
                         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                         ON CONFLICT(template) DO UPDATE SET name=excluded.name,subject=excluded.subject,preheader=excluded.preheader,
                         category=excluded.category,difficulty=excluded.difficulty,language=excluded.language,brand=excluded.brand,
                         industry=excluded.industry,tags=excluded.tags,html_body=excluded.html_body,text_body=excluded.text_body,updated_at=excluded.updated_at""",
                      (tid,name,subject,preheader,category,difficulty,language,brand,industry,tags,html_body,text_body,now()))
            c.commit(); c.close()
            audit(ADMIN_USERNAME,"TEMPLATE_UPDATE","template=%s name=%s"%(tid,name),ip)
            return self.sendbody(302,b"",extra={"Location":"/admin/templates"})
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
        if p.path=="/admin/campaigns/launch":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            cid=form.get("id",[""])[0]
            if form.get("confirm",[""])[0]!="YES": return self.sendbody(400,"Launch confirmation required","text/plain")
            c=db(); campaign=c.execute("SELECT * FROM campaigns WHERE id=?",(cid,)).fetchone(); c.close()
            if not campaign: return self.sendbody(404,"Campaign not found","text/plain")
            if campaign["status"]=="Completed": return self.sendbody(409,"Campaign already completed","text/plain")
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
