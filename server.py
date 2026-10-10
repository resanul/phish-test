#!/usr/bin/env python3
import os, sqlite3, csv, io, secrets, html, smtplib, ssl, subprocess, tempfile, re, threading, time, hashlib, hmac, base64, socket, json
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, urlencode, quote_plus
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
PORT=int(os.environ.get("PORT","8899"))
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

LINKSEC_BRAND_MAP = {
    "amazon-web-services-aws": ("Amazon Web Services (AWS)", "Cloud Services & Infrastructure", "AWS Security Team", "aws-alerts@amazon-security.com", "Medium"),
    "bluejeans": ("BlueJeans", "Communication & Collaboration", "BlueJeans Support", "support@bluejeans-meetings.com", "Easy"),
    "cisco": ("Cisco Webex", "Communication & Collaboration", "Cisco Webex Team", "messenger@cisco-webex.com", "Medium"),
    "google-cloud-platform-gcp": ("Google Cloud Platform (GCP)", "Cloud Services & Infrastructure", "Google Cloud Security", "cloud-security@google-alerts.com", "Hard"),
    "google-workspace": ("Google Workspace", "Communication & Collaboration", "Google Workspace Team", "no-reply@workspace-google.com", "Medium"),
    "gotomeeting": ("GoToMeeting", "Communication & Collaboration", "GoToMeeting Alerts", "notifications@gotomeeting-secure.com", "Easy"),
    "ibm-cloud": ("IBM Cloud", "Cloud Services & Infrastructure", "IBM Cloud Operations", "support@ibmcloud-security.com", "Medium"),
    "microsoft-azure": ("Microsoft Azure", "Cloud Services & Infrastructure", "Microsoft Azure Security", "azure-alerts@microsoft-security.com", "Hard"),
    "microsoft-office-365": ("Microsoft Office 365", "Communication & Collaboration", "Microsoft 365 Security", "security@office365-verify.com", "Medium"),
    "microsoft-teams": ("Microsoft Teams", "Communication & Collaboration", "Microsoft Teams Alerts", "alerts@teams-notifications.com", "Medium"),
    "oracle-cloud": ("Oracle Cloud", "Cloud Services & Infrastructure", "Oracle Cloud Identity", "oraclecloud@oracle-identity.com", "Hard"),
    "ringcentral": ("RingCentral", "Communication & Collaboration", "RingCentral Service", "service@ringcentral-messaging.com", "Easy"),
    "skype-for-business": ("Skype for Business", "Communication & Collaboration", "Skype Security Team", "security@skype-connect.com", "Easy"),
    "slack": ("Slack", "Communication & Collaboration", "Slack Technologies", "notification@slack-workspaces.com", "Medium"),
    "zoom": ("Zoom", "Communication & Collaboration", "Zoom Security", "noreply@zoomsecurity.com", "Medium"),
}

LINKSEC_KNOWN_TITLES = {
    "zoom-urgent-account-update-required": ("Zoom - Urgent Account Update Required", "Urgent: Immediate Action Required to Prevent Zoom Account Suspension", "Hard"),
    "zoom-urgent-zoom-account-security-alert": ("Zoom - Urgent Security Alert", "Zoom - Urgent Security Alert: Unusual Login Detected", "Medium"),
    "zoom-zoom-pro-subscription-offer": ("Zoom - Free Pro Subscription Offer", "Congratulations: Claim Your Complimentary 1-Year Zoom Pro Plan", "Easy"),
    "amazon-web-services-aws-aws-account-verification-request": ("AWS - Account Verification Request", "Action Required: Verify Your Amazon Web Services Account", "Medium"),
    "bluejeans-free-bluejeans-premium-subscription-offer": ("BlueJeans - Free Premium Subscription", "Claim Your Free BlueJeans Premium Subscription", "Easy"),
    "bluejeans-urgent-account-verification-request": ("BlueJeans - Urgent Account Verification", "Urgent: BlueJeans Account Verification Required", "Medium"),
    "microsoft-teams-exclusive-microsoft-365-upgrade-offer": ("Microsoft Teams - Exclusive 365 Upgrade Offer", "Special Invitation: Claim Your Microsoft 365 Premium Upgrade", "Easy"),
    "microsoft-teams-microsoft-teams-free-upgrade-offer": ("Microsoft Teams - Free Feature Upgrade Alert", "New Features Available: Free Microsoft Teams Upgrade", "Easy"),
    "oracle-cloud-urgent-account-update-request": ("Oracle Cloud - Urgent Account Update Request", "Urgent: Immediate Oracle Cloud Account Verification", "Hard"),
    "skype-for-business-urgent-password-reset-reminder": ("Skype - Password Reset Reminder", "Security Notice: Reset Your Skype for Business Password", "Medium"),
    "slack-enticing-gift-card-phishing-template": ("Slack - Employee Reward Gift Card", "Special Gift: You have Received a Slack Community Gift Card", "Easy"),
}

_LINKSEC_CATALOG_CACHE = None

def get_linksec_catalog():
    global _LINKSEC_CATALOG_CACHE
    if _LINKSEC_CATALOG_CACHE is not None:
        return _LINKSEC_CATALOG_CACHE

    candidates = [
        os.path.join(TEMPLATES, "email"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "email"),
        r"C:\opt\phish-simulation\templates\email"
    ]
    email_dir = next((d for d in candidates if os.path.isdir(d)), None)
    if not email_dir:
        _LINKSEC_CATALOG_CACHE = []
        return []

    items = []
    for brand_dir in sorted(os.listdir(email_dir)):
        b_path = os.path.join(email_dir, brand_dir)
        if not os.path.isdir(b_path): continue
        for f in sorted(os.listdir(b_path)):
            if not f.endswith(".html"): continue
            p = os.path.join(b_path, f)
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as fp:
                    html_content = fp.read()
            except Exception:
                continue
            slug = f.replace("-modified.html", "").replace(".html", "")
            b_meta = LINKSEC_BRAND_MAP.get(brand_dir, (brand_dir.replace("-", " ").title(), "General", "Security Team", "noreply@security.local", "Medium"))
            
            m_t = re.search(r"<title>(.*?)</title>", html_content, re.I)
            raw_title = m_t.group(1).strip() if m_t else ""
            
            if slug in LINKSEC_KNOWN_TITLES:
                name, subject, diff = LINKSEC_KNOWN_TITLES[slug]
            else:
                diff = b_meta[4]
                name = raw_title or slug.replace("-", " ").title()
                subject = raw_title or f"Important Notice regarding your {b_meta[0]} account"
            
            tags = list(set(re.findall(r'data-name=[\'"]([^\'"]+)[\'"]', html_content)))
            tag_str = ", ".join(tags) if tags else "Call to action, Visual Imitation"
            reply_to = b_meta[3].replace("@", "@reply.")
            
            items.append({
                "template": slug,
                "name": name,
                "subject": subject,
                "preheader": f"Security notification regarding your {b_meta[0]} account.",
                "category": b_meta[1],
                "difficulty": diff,
                "language": "English",
                "brand": b_meta[0],
                "industry": "Cloud & Enterprise",
                "tags": tag_str,
                "html_body": html_content,
                "text_body": f"Hello {{name}},\n\n{subject}\n\nPlease review this notification:\n{{tracking_link}}\n\nThis is an authorized security-awareness simulation.",
                "from_name": b_meta[2],
                "from_email": b_meta[3],
                "reply_to": reply_to,
                "owner": "LinkSec Awareness Library",
                "status": "Active"
            })
    _LINKSEC_CATALOG_CACHE = items
    return items

def seed_linksec_templates(c):
    catalog = get_linksec_catalog()
    for item in catalog:
        existing = c.execute("SELECT id FROM template_library WHERE template=?", (item["template"],)).fetchone()
        if not existing:
            c.execute("""INSERT INTO template_library(template,name,subject,preheader,category,difficulty,language,brand,industry,tags,html_body,text_body,from_name,from_email,reply_to,owner,status,updated_at)
                         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (item["template"], item["name"], item["subject"], item["preheader"],
                       item["category"], item["difficulty"], item["language"], item["brand"],
                       item["industry"], item["tags"], item["html_body"], item["text_body"],
                       item["from_name"], item["from_email"], item["reply_to"], item["owner"],
                       item["status"], now()))
            c.execute("""INSERT OR IGNORE INTO template_versions(template,version,name,subject,preheader,category,difficulty,language,brand,industry,tags,html_body,text_body,created_at,created_by)
                         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (item["template"], 1, item["name"], item["subject"], item["preheader"],
                       item["category"], item["difficulty"], item["language"], item["brand"],
                       item["industry"], item["tags"], item["html_body"], item["text_body"],
                       now(), ADMIN_USERNAME))

LANDING_PAGE_SEEDS = [
    {
        "template": "1",
        "name": "Apex Rewards — Employee Gift Voucher & Benefits Portal",
        "brand": "Apex",
        "scenario": "Retail & Rewards Claim",
        "file": "1.html"
    },
    {
        "template": "2",
        "name": "Trust Bank PLC — Exclusive Employee Card Portal",
        "brand": "Trust Bank",
        "scenario": "Corporate Banking & Card Privileges",
        "file": "2.html"
    },
    {
        "template": "3",
        "name": "Microsoft 365 — Corporate Outlook & OneDrive Sign-In",
        "brand": "Microsoft 365",
        "scenario": "Cloud SSO & Mail Authentication",
        "file": "3.html"
    },
    {
        "template": "4",
        "name": "Google Workspace — Enterprise SSO Authentication Portal",
        "brand": "Google Workspace",
        "scenario": "Identity & Drive Verification",
        "file": "4.html"
    },
    {
        "template": "5",
        "name": "HR Employee Portal — Annual Appraisal & Benefits Statement",
        "brand": "HR Portal",
        "scenario": "Human Resources & Payroll Review",
        "file": "5.html"
    },
    {
        "template": "6",
        "name": "GlobalProtect — IT Security Gateway & Remote VPN Login",
        "brand": "GlobalProtect",
        "scenario": "IT Infrastructure & Network Gateway",
        "file": "6.html"
    },
    {
        "template": "7",
        "name": "bKash & Banking Alert — Suspicious Transaction Verification",
        "brand": "bKash / Bank",
        "scenario": "Financial Security & Fraud Alert",
        "file": "7.html"
    },
    {
        "template": "8",
        "name": "Zoom Meeting — Security Verification & Meeting Access",
        "brand": "Zoom",
        "scenario": "Video Collaboration Security Update",
        "file": "8.html"
    },
    {
        "template": "9",
        "name": "Amazon Web Services (AWS) — Cloud IAM Console Sign-In",
        "brand": "AWS",
        "scenario": "DevOps & Cloud Management Access",
        "file": "9.html"
    },
    {
        "template": "10",
        "name": "Teachable Moment — Instant Awareness Training & Feedback",
        "brand": "Security Awareness",
        "scenario": "Educational Incident Drill",
        "file": "10.html"
    }
]

def seed_landing_pages(c):
    for item in LANDING_PAGE_SEEDS:
        html_body = ""
        for cand in (os.path.join(TEMPLATES, item["file"]), os.path.join(os.path.dirname(__file__), "templates", item["file"])):
            if os.path.isfile(cand):
                try:
                    with open(cand, "r", encoding="utf-8") as tf:
                        html_body = tf.read()
                    break
                except Exception:
                    pass

        row = c.execute("SELECT id, name, html_body, version FROM landing_pages WHERE template=?", (item["template"],)).fetchone()
        if row:
            is_placeholder = row["name"].startswith("Landing Page ") or len(row["html_body"] or "") < 1200
            if is_placeholder and html_body:
                c.execute("UPDATE landing_pages SET name=?, html_body=?, text_body=?, updated_at=? WHERE id=?",
                          (item["name"], html_body, "Authorized security-awareness simulation landing page.", now(), row["id"]))
                c.execute("INSERT OR IGNORE INTO landing_page_versions(landing_page_id,version,html_body,text_body,created_at,created_by) VALUES(?,?,?,?,?,?)",
                          (row["id"], row["version"] or 1, html_body, "Authorized security-awareness simulation landing page.", now(), ADMIN_USERNAME))
        else:
            c.execute("INSERT INTO landing_pages(name,template,status,html_body,text_body,version,created_at,updated_at) VALUES(?,?,'Enabled',?,?,1,?,?)",
                      (item["name"], item["template"], html_body, "Authorized security-awareness simulation landing page.", now(), now()))
            new_id = c.execute("SELECT last_insert_rowid() id").fetchone()["id"]
            c.execute("INSERT OR IGNORE INTO landing_page_versions(landing_page_id,version,html_body,text_body,created_at,created_by) VALUES(?,1,?,?,?,?)",
                      (new_id, html_body, "Authorized security-awareness simulation landing page.", now(), ADMIN_USERNAME))

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
    CREATE TABLE IF NOT EXISTS system_settings(
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
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
    CREATE TABLE IF NOT EXISTS rbac_resource_scopes(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        role_id INTEGER NOT NULL,
        permission_id INTEGER NOT NULL,
        scope_kind TEXT NOT NULL,
        scope_value TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(role_id,permission_id,scope_kind,scope_value),
        FOREIGN KEY(role_id) REFERENCES rbac_roles(id) ON DELETE CASCADE,
        FOREIGN KEY(permission_id) REFERENCES rbac_permissions(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_rbac_resource_scopes_role
    ON rbac_resource_scopes(role_id);
    CREATE INDEX IF NOT EXISTS idx_rbac_resource_scopes_permission
    ON rbac_resource_scopes(permission_id);
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
    CREATE TABLE IF NOT EXISTS access_reviews(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_admin_id INTEGER NOT NULL,
        target_username TEXT NOT NULL,
        target_role TEXT NOT NULL,
        target_active INTEGER NOT NULL,
        permission_count INTEGER NOT NULL,
        normal_count INTEGER NOT NULL,
        elevated_count INTEGER NOT NULL,
        privileged_count INTEGER NOT NULL,
        reviewed_by TEXT NOT NULL,
        reviewed_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_access_reviews_target_time ON access_reviews(target_admin_id,reviewed_at);
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

    permission_seed=[
        ("campaign","view","View campaigns","View campaign configuration and status."),("campaign","create","Create campaigns","Create new simulation campaigns."),("campaign","edit","Edit campaigns","Modify campaign configuration before launch."),("campaign","launch","Launch campaigns","Start an authorized simulation campaign."),("campaign","delete","Delete campaigns","Delete campaigns when allowed by lifecycle rules."),
        ("template","view","View templates","View reusable email template definitions."),("template","create","Create templates","Create reusable simulation email templates."),("template","edit","Edit templates","Modify reusable simulation email templates."),("template","archive","Archive templates","Archive reusable email templates."),
        ("landing_page","view","View landing pages","View simulation landing-page definitions."),("landing_page","create","Create landing pages","Create authorized simulation landing pages."),("landing_page","edit","Edit landing pages","Modify authorized simulation landing pages."),
        ("recipient","view","View recipients","View recipient and organizational metadata."),("recipient","create","Create recipients","Create recipient records for simulations."),("recipient","edit","Edit recipients","Modify recipient metadata."),("recipient","delete","Delete recipients","Delete recipient records from directory."),("recipient","import","Import recipients","Import recipient metadata from approved sources."),
        ("group","view","View groups","View recipient groups and departments."),("group","manage","Manage groups","Create, update, and organize recipient groups."),
        ("training","view","View training","View training courses and assignments."),("training","manage","Manage training","Create and manage awareness training content."),("training","assign","Assign training","Assign approved training to recipients."),
        ("report","view","View reports","View campaign, risk, and training reports."),("report","export","Export reports","Export authorized reporting data."),("report","schedule","Schedule reports","Create and manage scheduled reports."),
        ("risk","view","View risk","View risk scores, trends, and history."),("risk","manage","Manage risk","Modify risk settings and remediation controls."),
        ("smtp","view","View SMTP","View SMTP provider configuration metadata."),("smtp","manage","Manage SMTP","Create and modify SMTP provider profiles."),("smtp","diagnostics","Run SMTP diagnostics","Run SMTP connectivity diagnostics."),
        ("audit","view","View audit log","View administrative audit events."),
        ("admin","view","View administrators","View administrator accounts and access status."),("admin","create","Create administrators","Create administrator accounts."),("admin","edit","Edit administrators","Modify administrator roles and account settings."),("admin","disable","Disable administrators","Disable administrator accounts."),
        ("role","view","View roles","View built-in and custom roles."),("role","create","Create roles","Create custom administrative roles."),("role","edit","Edit roles","Modify custom role definitions."),("role","delete","Delete roles","Delete custom roles when no longer referenced."),
    ]
    risk_levels={
        ("campaign","launch"):"elevated",
        ("campaign","delete"):"elevated",
        ("template","archive"):"elevated",
        ("recipient","import"):"elevated",
        ("recipient","delete"):"elevated",
        ("group","manage"):"elevated",
        ("training","manage"):"elevated",
        ("training","assign"):"elevated",
        ("report","schedule"):"elevated",
        ("smtp","diagnostics"):"elevated",
        ("report","export"):"privileged",
        ("risk","manage"):"privileged",
        ("smtp","manage"):"privileged",
        ("admin","create"):"privileged",
        ("admin","edit"):"privileged",
        ("admin","disable"):"privileged",
        ("role","create"):"privileged",
        ("role","edit"):"privileged",
        ("role","delete"):"privileged",
    }
    c.executemany("INSERT OR IGNORE INTO rbac_permissions(resource,action,label,description,risk_level,active) VALUES(?,?,?,?,?,1)",[(resource,action,label,description,risk_levels.get((resource,action),"normal")) for resource,action,label,description in permission_seed])
    for (resource,action),risk in risk_levels.items():
        c.execute("UPDATE rbac_permissions SET risk_level=? WHERE resource=? AND action=?",(risk,resource,action))
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
    for col,definition in (("designation","TEXT"),("location","TEXT"),("manager","TEXT"),("language","TEXT DEFAULT 'English'"),("timezone","TEXT DEFAULT 'Asia/Dhaka'"),("mobile","TEXT")):
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
    seed_linksec_templates(c)
    seed_landing_pages(c)
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

def get_public_base_url(fallback_host=None):
    global PUBLIC_BASE_URL
    env_val = os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/")
    if env_val:
        PUBLIC_BASE_URL = env_val
        return env_val
    try:
        c = db()
        r = c.execute("SELECT value FROM system_settings WHERE key='public_base_url'").fetchone()
        c.close()
        if r and r["value"] and r["value"].strip():
            val = r["value"].strip().rstrip("/")
            PUBLIC_BASE_URL = val
            return val
    except Exception:
        pass
    if fallback_host:
        proto = "https" if str(fallback_host).endswith(":443") else "http"
        detected = f"{proto}://{fallback_host}".rstrip("/")
        try:
            c = db()
            c.execute("INSERT OR REPLACE INTO system_settings(key,value,updated_at) VALUES('public_base_url',?,?)", (detected, now()))
            c.commit()
            c.close()
        except Exception:
            pass
        PUBLIC_BASE_URL = detected
        return detected
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL
    return f"http://127.0.0.1:{PORT}"

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
        try:
            c.execute("INSERT OR IGNORE INTO event_dedup(token,event,first_seen_at) VALUES(?,?,?)",(token,event,now()))
        except Exception:
            pass
    c.execute("INSERT INTO events(ts,ip,template,event,name,email,mobile,user_agent,employee_id,card_type,campaign_id,recipient_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(datetime.now(timezone.utc).isoformat(),ip,t,event,name,email,mobile,ua,employee_id,card_type,campaign_id,recipient_id))
    c.commit(); c.close()
    if email and event in ("click","form_action","report"): risk_recalculate(email)
    return True

def ensure_smtp_key():
    os.makedirs(DATA,exist_ok=True)
    if not os.path.exists(SMTP_KEY):
        try:
            with open(SMTP_KEY,"w") as f:
                subprocess.run(["openssl","rand","-base64","48"],check=True,stdout=f,stderr=subprocess.DEVNULL)
        except Exception:
            with open(SMTP_KEY,"w") as f:
                f.write(secrets.token_urlsafe(48))
        try: os.chmod(SMTP_KEY,0o600)
        except Exception: pass
    else:
        try: os.chmod(SMTP_KEY,0o600)
        except Exception: pass
    return SMTP_KEY

def encrypt_secret(value):
    if not value:
        return ""
    key=ensure_smtp_key()
    try:
        p=subprocess.run(
            ["openssl","enc","-aes-256-cbc","-pbkdf2","-salt","-a","-A","-pass",f"file:{key}"],
            input=value.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
        return p.stdout.decode().strip()
    except Exception:
        with open(key,"rb") as f:
            k=f.read()
        derived=hashlib.sha256(k).digest()
        raw=value.encode("utf-8")
        xor_bytes=bytes(b ^ derived[i % len(derived)] for i, b in enumerate(raw))
        return "FALLBACK:" + base64.b64encode(xor_bytes).decode("ascii")

def decrypt_secret(value):
    if not value:
        return ""
    if value.startswith("FALLBACK:"):
        key=ensure_smtp_key()
        with open(key,"rb") as f:
            k=f.read()
        derived=hashlib.sha256(k).digest()
        raw=base64.b64decode(value[9:].encode("ascii"))
        return bytes(b ^ derived[i % len(derived)] for i, b in enumerate(raw)).decode("utf-8",errors="replace")
    key=ensure_smtp_key()
    try:
        p=subprocess.run(
            ["openssl","enc","-d","-aes-256-cbc","-pbkdf2","-a","-A","-pass",f"file:{key}"],
            input=value.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
        return p.stdout.decode()
    except Exception:
        return ""

def smtp_send_test(profile,to_email):
    msg=EmailMessage()
    from_name=profile["from_name"] if "from_name" in profile.keys() and profile["from_name"] else "Trust PhishGuard"
    msg["From"]=formataddr((from_name,profile["from_email"]))
    msg["To"]=to_email
    if "reply_to" in profile.keys() and profile["reply_to"]:
        msg["Reply-To"]=profile["reply_to"]
    msg["Subject"]="Trust PhishGuard SMTP test"
    msg.set_content("This is an SMTP connectivity test from Trust PhishGuard. No credentials are requested or collected.")
    smtp=smtp_connect(profile)
    try:
        smtp.send_message(msg)
    finally:
        try: smtp.quit()
        except Exception: pass

def sanitize_audit_details(details):
    """Redact authentication secrets if a caller accidentally includes them."""
    text=str(details or "")
    secret_key=r"(?:password(?:_hash|_enc)?|otp|pin|cvv|card(?:_number)?|token|secret|authorization|api[_ -]?key|client[_ -]?secret)"
    pattern=re.compile(r"(?i)\b("+secret_key+r")\s*([=:])\s*(\"[^\"]*\"|'[^']*'|[^\s,;&]+)")
    return pattern.sub(lambda match: match.group(1)+match.group(2)+"[REDACTED]",text)

def audit(admin,action,details,ip):
    c=db()
    safe_details=sanitize_audit_details(details)
    c.execute("INSERT INTO audit_logs(ts,admin,action,details,ip) VALUES(?,?,?,?,?)",(now(),admin,action,safe_details,ip))
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
    current_stage="TLS"
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
        current_stage="AUTH"
        username=profile["username"] if "username" in profile.keys() and profile["username"] else ""
        auth_method=profile["auth_method"] if "auth_method" in profile.keys() and profile["auth_method"] else "password"
        if username or auth_method.lower()=="oauth2":
            smtp_authenticate(smtp,profile)
            result.append({"stage":"AUTH","status":"PASS","detail":"SMTP authentication succeeded."})
        else:
            result.append({"stage":"AUTH","status":"SKIP","detail":"No SMTP authentication configured; relay may use IP or other policy."})
        if to_email:
            current_stage="SEND"
            msg=EmailMessage()
            msg["Subject"]="[TEST] Trust PhishGuard SMTP diagnostics"
            from_name=profile["from_name"] if "from_name" in profile.keys() and profile["from_name"] else "Trust PhishGuard"
            msg["From"]=formataddr((from_name,profile["from_email"]))
            msg["To"]=to_email
            if "reply_to" in profile.keys() and profile["reply_to"]: msg["Reply-To"]=profile["reply_to"]
            msg.set_content("This is an authorized Trust PhishGuard SMTP connectivity diagnostic.")
            smtp.send_message(msg)
            result.append({"stage":"SEND","status":"PASS","detail":"Diagnostic test message accepted by SMTP server."})
        else:
            result.append({"stage":"SEND","status":"SKIP","detail":"No test recipient supplied."})
    except smtplib.SMTPAuthenticationError:
        result.append({"stage":"AUTH","status":"FAIL","detail":"SMTP authentication failed."})
    except ssl.SSLError:
        result.append({"stage":"TLS","status":"FAIL","detail":"TLS negotiation failed."})
    except Exception as e:
        stage_fail=current_stage if current_stage in ("TLS","AUTH","SEND") else ("SEND" if to_email else "TLS")
        result.append({"stage":stage_fail,"status":"FAIL","detail":"SMTP session operation failed: %s"%esc(sanitize_audit_details(str(e)[:120]))})
    finally:
        if smtp:
            try: smtp.quit()
            except Exception: pass
    return result

def smtp_authenticate(smtp,profile):
    auth_method=profile["auth_method"] if "auth_method" in profile.keys() and profile["auth_method"] else "password"
    method=auth_method.lower()
    if method=="oauth2":
        token_enc=profile["oauth_token_enc"] if "oauth_token_enc" in profile.keys() else ""
        token=decrypt_secret(token_enc) if token_enc else ""
        if not token:
            raise RuntimeError("SMTP OAuth2 access token is not configured")
        username=profile["username"] if "username" in profile.keys() and profile["username"] else ""
        auth_string=lambda challenge=None: "\x00%s\x00%s"%(username,token)
        smtp.auth("XOAUTH2",auth_string,initial_response_ok=True)
        return
    username=profile["username"] if "username" in profile.keys() and profile["username"] else ""
    if username:
        password_enc=profile["password_enc"] if "password_enc" in profile.keys() else ""
        smtp.login(username,decrypt_secret(password_enc or ""))

def smtp_connect(profile):
    host=profile["host"]; port=int(profile["port"]); security=profile["security"]
    if security=="SSL/TLS":
        smtp=smtplib.SMTP_SSL(host,port,context=ssl.create_default_context(),timeout=20)
        smtp.ehlo()
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
    rec=recipient or {}
    name=(rec.get("name") if isinstance(rec,dict) else getattr(rec,"name","")) or ""
    first_name=name.split()[0] if name else "Colleague"
    last_name=name.split()[-1] if len(name.split())>1 else ""
    email=(rec.get("email") if isinstance(rec,dict) else getattr(rec,"email","")) or ""
    cname=(campaign.get("name") if isinstance(campaign,dict) else getattr(campaign,"name","")) or "Security Awareness Simulation"
    cbrand=(campaign.get("brand") if isinstance(campaign,dict) else getattr(campaign,"brand","")) or "Trust PhishGuard"
    trk=links.get("tracking_link","") if links else ""
    rep=links.get("report_link","") if links else ""
    qr=links.get("qr_link","") if links else ""

    values={
        "name":name or "Colleague",
        "first_name":first_name,
        "last_name":last_name,
        "FirstName":first_name,
        "LastName":last_name,
        "email":email,
        "Email":email,
        "URL":trk,
        "url":trk,
        "tracking_link":trk,
        "report_link":rep,
        "qr_link":qr,
        "company_name":cbrand,
        "campaign_name":cname,
        "employee_id":(rec.get("employee_id") if isinstance(rec,dict) else getattr(rec,"employee_id","")) or "",
        "department":(rec.get("department") if isinstance(rec,dict) else getattr(rec,"department","")) or "",
        "designation":(rec.get("designation") if isinstance(rec,dict) else getattr(rec,"designation","")) or "",
        "location":(rec.get("location") if isinstance(rec,dict) else getattr(rec,"location","")) or "",
        "manager":(rec.get("manager") if isinstance(rec,dict) else getattr(rec,"manager","")) or "",
        "language":(rec.get("language") if isinstance(rec,dict) else getattr(rec,"language","")) or "",
        "timezone":(rec.get("timezone") if isinstance(rec,dict) else getattr(rec,"timezone","")) or "",
    }
    return re.sub(r"\{\{\s*\.?([a-zA-Z0-9_]+)\s*\}\}",lambda m:esc(str(values.get(m.group(1),m.group(0)))),body or "")

def _send_campaign_recipient(campaign,rec,queue_id):
    rec_id = rec["recipient_id"] if ("recipient_id" in rec.keys()) else rec["id"]
    c=db()
    c.execute("UPDATE campaign_queue SET status='Sending',attempts=attempts+1,updated_at=? WHERE id=?",(now(),queue_id))
    c.execute("INSERT INTO campaign_deliveries(campaign_id,recipient_id,status,attempted_at) VALUES(?,?,?,?)",(campaign["id"],rec_id,"Attempted",now()))
    delivery_id=c.execute("SELECT last_insert_rowid() id").fetchone()["id"]
    c.commit()
    c.close()
    token=create_tracking_token(campaign["id"],rec_id)
    target_page=None
    if campaign["landing_page_id"]:
        c=db(); lrow=c.execute("SELECT template FROM landing_pages WHERE id=?",(campaign["landing_page_id"],)).fetchone(); c.close()
        if lrow and lrow["template"]: target_page=str(lrow["template"])
    if not target_page: target_page=str(campaign["template"] or "1")
    pub_url = get_public_base_url()
    link=pub_url+"/"+target_page+".html?"+urlencode({"t":token})
    msg=EmailMessage()
    msg["From"]=formataddr((campaign["template_from_name"] or campaign["from_name"] or "Trust PhishGuard",campaign["template_from_email"] or campaign["from_email"]))
    if campaign["template_reply_to"] or campaign["reply_to"]:
        msg["Reply-To"]=campaign["template_reply_to"] or campaign["reply_to"]
    msg["To"]=rec["email"]
    msg["Subject"]=campaign["subject"] or "Security Awareness Simulation"
    links={"tracking_link":link,"report_link":pub_url+"/report?t="+token,"qr_link":pub_url+"/qr?t="+token}
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
        c.execute("UPDATE recipients SET status='Sent' WHERE id=?",(rec_id,))
        c.commit()
        c.close()
        mobile_val=(rec["mobile"] if ("mobile" in rec.keys() and rec["mobile"]) else "") or ""
        record("smtp",str(campaign["template"]),"delivered",rec["name"] or "",rec["email"] or "",mobile_val,"campaign-delivery",rec["employee_id"] or "","",campaign["id"],rec_id,token)
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

def campaign_prelaunch_validation(campaign, req_host=None):
    errors=[]
    if not campaign: return ["Campaign not found."]
    if not get_public_base_url(req_host): errors.append("PUBLIC_BASE_URL is not configured.")
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
    if not re.fullmatch(r"[a-zA-Z0-9_\-]+",str(campaign["template"] or "")): errors.append("Template selection is invalid.")
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

def send_campaign(campaign_id,scheduled=False,req_host=None):
    if not get_public_base_url(req_host):
        raise RuntimeError("PUBLIC_BASE_URL is not configured")
    c=db()
    campaign=c.execute("""SELECT c.*,s.host,s.port,s.security,s.username,s.password_enc,s.from_name,s.from_email,s.reply_to,s.auth_method,s.oauth_token_enc,
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
    qrows=c.execute("""SELECT q.id AS queue_id, q.attempts, q.next_attempt_at, q.campaign_id,
                              r.id AS recipient_id, r.*
                       FROM campaign_queue q JOIN recipients r ON r.id=q.recipient_id
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
        if scheduled and not campaign_window_open(campaign):
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
            ok=_send_campaign_recipient(campaign,q,q["queue_id"])
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
:root{--primary:#087b59;--primary-hover:#066347;--bg:#051b14;--card:#ffffff;--text:#10221a}
*{box-sizing:border-box}body{margin:0;background:#051b14;color:#10221a;font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
.login-shell{min-height:100vh;display:grid;grid-template-columns:1.15fr .85fr;background:#051b14}
.login-left{padding:60px 8vw;color:#fff;display:flex;flex-direction:column;justify-content:center;background:radial-gradient(circle at 20% 30%,#0f4735 0%,#051b14 70%);border-right:1px solid #0e3729;position:relative}
.brand{display:flex;gap:12px;align-items:center;font-weight:800;font-size:24px;letter-spacing:-0.5px}
.brand-mark{width:44px;height:44px;border-radius:12px;background:linear-gradient(135deg,#10b981,#059669);display:grid;place-items:center;color:#fff;font-size:22px;box-shadow:0 4px 14px rgba(16,185,129,0.35)}
.login-left h1{font-size:clamp(36px,4.5vw,56px);line-height:1.06;margin:46px 0 18px;letter-spacing:-1.5px;font-weight:850}
.login-left p{max-width:540px;color:#a3c7bb;font-size:16px;line-height:1.7;margin:0 0 28px}
.feature-row{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
.feature{border:1px solid #1c523f;background:rgba(20,68,52,0.45);backdrop-filter:blur(8px);border-radius:999px;padding:8px 14px;font-size:12px;font-weight:600;color:#cde5dc}
.login-right{background:#f2f5f3;display:grid;place-items:center;padding:36px}
.login-card{width:min(440px,100%);background:#ffffff;border:1px solid #dce8e2;border-radius:20px;padding:38px;box-shadow:0 20px 60px rgba(5,27,20,0.08)}
.login-card-head{margin-bottom:22px}
.login-card h2{margin:0 0 6px;font-size:26px;font-weight:800;color:#10221a;letter-spacing:-0.5px}
.muted{color:#647d72;font-size:13.5px;line-height:1.5}
.field{margin-top:18px}
.field label{display:block;font-size:12.5px;font-weight:700;color:#1a3127;margin-bottom:7px}
.field input{width:100%;padding:12px 14px;border:1.5px solid #cbdad2;border-radius:10px;font-size:14px;outline:none;transition:all 0.15s ease}
.field input:focus{border-color:#087b59;box-shadow:0 0 0 3px rgba(8,123,89,0.12)}
.login-btn{width:100%;border:0;border-radius:10px;padding:13px;background:#087b59;color:#fff;font-size:14px;font-weight:750;cursor:pointer;margin-top:24px;transition:all 0.15s ease;box-shadow:0 3px 10px rgba(8,123,89,0.25)}
.login-btn:hover{background:#066347;transform:translateY(-1px);box-shadow:0 5px 14px rgba(8,123,89,0.3)}
.login-alert{margin-top:14px;padding:11px 14px;border-radius:9px;background:#fee2e2;color:#991b1b;border:1px solid #fecaca;font-size:13px;font-weight:600}
.notice{margin-top:22px;padding:12px 14px;border-radius:10px;background:#e8f4ef;color:#1e4d3c;font-size:12px;line-height:1.5;border:1px solid #c8e4d8}
.trust{margin-top:24px;text-align:center;color:#789186;font-size:12px;font-weight:600}
@media(max-width:850px){.login-shell{grid-template-columns:1fr}.login-left{padding:40px 24px}.login-right{padding:24px}}
"""

DASH_CSS="""
:root{--primary:#087b59;--primary-hover:#066347;--bg:#f2f5f3;--card:#ffffff;--border:#e1ece6;--text:#10221a;--text-muted:#5e776d}
*{box-sizing:border-box}body{margin:0;background:#f2f5f3;color:#10221a;font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
a{color:inherit}button,input,select,textarea{font:inherit}
.topbar{height:68px;background:#051b14;color:#fff;display:flex;align-items:center;justify-content:space-between;padding:0 28px;border-bottom:1px solid #0f382a;position:sticky;top:0;z-index:90}
.topbrand{display:flex;align-items:center;gap:12px;font-weight:800;font-size:16px;color:#fff;text-decoration:none}
.mark{width:36px;height:36px;border-radius:10px;background:linear-gradient(135deg,#10b981,#059669);color:#fff;display:grid;place-items:center;font-weight:900;font-size:18px;box-shadow:0 2px 8px rgba(16,185,129,0.3)}
.live-status-pill{display:inline-flex;align-items:center;gap:7px;background:rgba(16,185,129,0.12);color:#34d399;border:1px solid rgba(16,185,129,0.25);padding:5px 12px;border-radius:999px;font-size:11.5px;font-weight:600}
.pulse-dot{width:7px;height:7px;border-radius:50%;background:#10b981;box-shadow:0 0 8px #10b981;display:inline-block}
.top-actions{display:flex;gap:10px;align-items:center}
.top-actions a{padding:7px 13px;border:1px solid #1c4b3a;background:rgba(255,255,255,0.05);border-radius:8px;text-decoration:none;font-size:12px;color:#d7ebe3;font-weight:600;transition:all 0.15s ease}
.top-actions a:hover{background:#123e2f;border-color:#2a6952;color:#fff}
.top-role-badge{font-size:11px;font-weight:750;background:rgba(255,255,255,0.08);color:#a8c7bc;padding:5px 9px;border-radius:6px;border:1px solid #1b4536;letter-spacing:0.5px}
.layout{display:grid;grid-template-columns:240px 1fr;min-height:calc(100vh - 68px)}
.side{background:#071c15;color:#b8d1c8;padding:18px 14px;border-right:1px solid #0f3327;overflow-y:auto;display:flex;flex-direction:column;gap:3px}
.side-group-title{font-size:10.5px;font-weight:800;text-transform:uppercase;letter-spacing:0.8px;color:#497563;padding:12px 10px 4px;margin-top:4px}
.side a{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:9px;text-decoration:none;font-size:12.5px;font-weight:550;color:#a8c4b9;margin:1px 0;transition:all 0.15s ease}
.side a:hover{background:#103528;color:#fff;transform:translateX(3px)}
.side a.active{background:#164536;color:#ffffff;font-weight:700;box-shadow:inset 3px 0 0 #10b981}
.side-ico{font-size:14px;width:18px;display:inline-block;text-align:center}
.main{padding:28px 36px;max-width:1560px}
.wrap{max-width:1440px;margin:auto;padding:28px}
.hero{display:flex;justify-content:space-between;align-items:flex-end;margin-bottom:22px;flex-wrap:wrap;gap:14px}
.hero h1{margin:0;font-size:28px;font-weight:850;color:#10221a;letter-spacing:-0.7px}
.hero p{margin:6px 0 0;color:#5e776d;font-size:13.5px}
.camp-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:22px;gap:16px;flex-wrap:wrap}
.camp-crumb{font-size:12px;color:#5e776d;margin-bottom:6px;display:flex;gap:6px;align-items:center}
.camp-crumb a{color:#087b59;text-decoration:none;font-weight:600}
.camp-crumb a:hover{text-decoration:underline}
.camp-title-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.camp-title-row h1{margin:0;font-size:24px;font-weight:850;color:#10221a;letter-spacing:-0.5px}
.camp-status-badge{font-size:11px;font-weight:750;padding:4px 10px;border-radius:999px;text-transform:uppercase;letter-spacing:0.5px}
.status-active{background:#e6f7f0;color:#087b59;border:1px solid #b7e8d3}
.status-draft{background:#fef3c7;color:#92400e;border:1px solid #fde68a}
.status-completed{background:#e0f2fe;color:#0284c7;border:1px solid #bae6fd}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:22px}
.stat{background:#fff;border:1px solid #e0ece6;border-radius:14px;padding:20px;box-shadow:0 1px 3px rgba(0,0,0,0.02);transition:all 0.15s ease}
.stat:hover{transform:translateY(-2px);box-shadow:0 6px 18px rgba(8,123,89,0.06);border-color:#b8dad0}
.stat-label{font-size:11px;color:#5e776d;font-weight:750;text-transform:uppercase;letter-spacing:0.6px}
.num{font-size:30px;font-weight:850;color:#10221a;margin-top:8px;letter-spacing:-0.5px}
.delta{font-size:11.5px;color:#087b59;margin-top:8px;font-weight:600}
.grid{display:grid;grid-template-columns:1.35fr .65fr;gap:16px;margin-top:16px}
.card{background:#ffffff;border:1px solid #e1ece6;border-radius:14px;padding:22px;box-shadow:0 1px 3px rgba(0,0,0,0.02),0 4px 14px rgba(7,28,21,0.02);margin-bottom:20px}
.card h3{margin:0 0 6px;font-size:16px;font-weight:750;color:#10221a}
.sub{color:#647d72;font-size:12px;line-height:1.5}
.bars{margin-top:18px;display:grid;gap:13px}
.bar-row{display:grid;grid-template-columns:110px 1fr 45px;gap:12px;align-items:center;font-size:12.5px}
.bar{height:10px;background:#edf3f0;border-radius:20px;overflow:hidden}
.bar>i{display:block;height:100%;background:linear-gradient(90deg,#087b59,#10b981);border-radius:20px}
.trend{height:185px;display:flex;align-items:end;gap:8px;margin-top:20px;padding:0 3px}
.day{flex:1;display:flex;flex-direction:column;justify-content:end;align-items:center;height:100%;gap:7px}
.daybar{width:100%;max-width:42px;background:linear-gradient(180deg,#10b981,#087b59);border-radius:6px 6px 2px 2px;min-height:3px;box-shadow:0 2px 6px rgba(8,123,89,0.15)}
.day small{font-size:10.5px;color:#647d72;font-weight:600}
.day b{font-size:11px;color:#10221a;font-weight:750}
.table-wrap{overflow-x:auto;border-radius:12px;border:1px solid #e1ece6;background:#fff;margin-top:14px}
.table{width:100%;border-collapse:collapse;font-size:12.5px;text-align:left}
.table th{background:#f7faf8;color:#496559;font-size:11px;font-weight:750;text-transform:uppercase;letter-spacing:0.5px;padding:12px 14px;border-bottom:1.5px solid #e1ece6;white-space:nowrap}
.table td{padding:12px 14px;border-bottom:1px solid #edf3f0;color:#1a3127;vertical-align:middle}
.table tbody tr:hover{background:#f8fbf9}
.table tbody tr:last-child td{border-bottom:none}
.pill{display:inline-flex;align-items:center;gap:4px;padding:4px 9px;border-radius:999px;font-size:11px;font-weight:750}
.pill.click{background:#e6f7f0;color:#087b59;border:1px solid #c2ebd9}
.pill.submitted,.pill.form_action{background:#edf3ff;color:#2563eb;border:1px solid #c7dcfe}
.pill.report{background:#fdf4ff;color:#9333ea;border:1px solid #f5d0fe}
.pill.bot_detected{background:#fef2f2;color:#b91c1c;border:1px solid #fecaca}
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 14px;border-radius:8px;border:1.5px solid #d0e0d8;background:#fff;color:#193026;text-decoration:none;font-size:12px;font-weight:650;cursor:pointer;transition:all 0.15s ease}
.btn:hover{border-color:#087b59;background:#f5faf7;color:#087b59;transform:translateY(-1px)}
.btn.primary{background:#087b59;border-color:#087b59;color:#fff;box-shadow:0 2px 6px rgba(8,123,89,0.2)}
.btn.primary:hover{background:#066347;border-color:#066347;color:#fff;box-shadow:0 4px 10px rgba(8,123,89,0.25)}
.filter{display:flex;gap:9px;align-items:center;margin-top:14px;flex-wrap:wrap}
.filter input{border:1.5px solid #ccdcd5;border-radius:8px;padding:9px 12px;font-size:12.5px;outline:none;background:#fff;color:#10221a;transition:all 0.15s ease}
.filter input:focus{border-color:#087b59;box-shadow:0 0 0 3px rgba(8,123,89,0.12)}
.filter button{border:0;background:#e3ede8;color:#1a3328;padding:9px 13px;border-radius:8px;cursor:pointer;font-size:12px;font-weight:650;transition:all 0.15s ease}
.filter button:hover{background:#d5e5dd}
.form{display:grid;gap:14px;max-width:850px}
.form label{display:flex;flex-direction:column;gap:6px;font-size:12.5px;font-weight:650;color:#1a3127}
.form input,.form select,.form textarea{padding:10px 13px;border:1.5px solid #ccdcd5;border-radius:9px;font-size:13px;background:#fff;color:#10221a;outline:none;transition:all 0.15s ease}
.form input:focus,.form select:focus,.form textarea:focus{border-color:#087b59;box-shadow:0 0 0 3px rgba(8,123,89,0.12)}
@media(max-width:960px){.stats{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}.layout{grid-template-columns:1fr}.side{display:flex;flex-direction:row;overflow-x:auto;padding:10px}.side-group-title{display:none}.side a{white-space:nowrap}}
@media(max-width:540px){.stats{grid-template-columns:1fr}.main{padding:18px}.topbar{padding:0 16px}.top-role-badge{display:none}}
/* LinkSec Modern 3-Column Email Template Catalog & Live Preview */
.ls-browser{display:grid;grid-template-columns:230px 370px 1fr;background:#ffffff;border:1px solid #e1ece6;border-radius:14px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.02),0 4px 18px rgba(7,28,21,0.04);min-height:740px;height:calc(100vh - 210px);margin-top:14px}
.ls-sidebar{background:#f9fbf9;border-right:1px solid #e6f0eb;padding:14px 10px;overflow-y:auto;display:flex;flex-direction:column;gap:14px}
.ls-group-title{font-size:10.5px;font-weight:800;text-transform:uppercase;letter-spacing:0.7px;color:#527365;padding:4px 8px;margin-bottom:2px}
.ls-nav-item{display:flex;align-items:center;justify-content:space-between;padding:7px 10px;border-radius:8px;font-size:12px;font-weight:600;color:#243e32;cursor:pointer;transition:all 0.15s ease;user-select:none}
.ls-nav-item:hover{background:#edf5f0;color:#087b59}
.ls-nav-item.active{background:#e6f7f0;color:#087b59;font-weight:750}
.ls-badge-count{font-size:10.5px;background:#e1ece6;color:#3b5a4d;padding:2px 7px;border-radius:999px;font-weight:700}
.ls-nav-item.active .ls-badge-count{background:#087b59;color:#fff}
.ls-catalog{background:#ffffff;border-right:1px solid #e6f0eb;display:flex;flex-direction:column;height:100%;overflow:hidden}
.ls-catalog-header{padding:12px 14px;border-bottom:1px solid #e6f0eb;background:#fbfdfc;display:flex;flex-direction:column;gap:8px}
.ls-search-wrap{position:relative;display:flex;align-items:center}
.ls-search-icon{position:absolute;left:10px;font-size:12px;color:#8da49a;pointer-events:none}
.ls-search-input{width:100%;padding:8px 10px 8px 30px;border:1.5px solid #d5e5dc;border-radius:8px;font-size:12px;outline:none;background:#fff;transition:border-color 0.15s ease}
.ls-search-input:focus{border-color:#087b59;box-shadow:0 0 0 3px rgba(8,123,89,0.1)}
.ls-tags-bar{display:flex;gap:5px;overflow-x:auto;padding-bottom:3px;scrollbar-width:thin}
.ls-tag-pill{font-size:10.5px;font-weight:650;padding:3px 9px;border-radius:999px;background:#edf4f0;color:#3b5a4d;white-space:nowrap;cursor:pointer;border:1px solid #d8e8df;transition:all 0.15s ease;user-select:none}
.ls-tag-pill:hover{background:#e1efe8;color:#087b59}
.ls-tag-pill.active{background:#087b59;color:#fff;border-color:#087b59}
.ls-cards-list{flex:1;overflow-y:auto;padding:8px 10px;display:flex;flex-direction:column;gap:8px}
.ls-card{padding:11px 12px;border-radius:10px;border:1.5px solid #e5ede8;background:#fbfdfc;cursor:pointer;transition:all 0.15s ease;display:flex;flex-direction:column;gap:5px}
.ls-card:hover{border-color:#b7d6c6;background:#ffffff;box-shadow:0 2px 8px rgba(7,28,21,0.03)}
.ls-card.active{border-color:#087b59;background:#f4faf7;box-shadow:0 3px 12px rgba(8,123,89,0.08)}
.ls-card-top{display:flex;justify-content:space-between;align-items:center;font-size:11px}
.ls-card-sender{font-weight:700;color:#12281e;display:flex;align-items:center;gap:6px}
.ls-dot{width:6px;height:6px;border-radius:50%;background:#2563eb;display:inline-block}
.ls-card-time{font-size:10px;color:#6d887d}
.ls-card-subject{font-size:12px;font-weight:700;color:#0d1e16;line-height:1.35;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.ls-card-name{font-size:11px;color:#557265;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ls-card-badges{display:flex;gap:4px;flex-wrap:wrap;margin-top:2px}
.ls-chip{font-size:9.5px;font-weight:700;padding:2px 6px;border-radius:4px;background:#eef5f1;color:#3b5a4d}
.ls-chip.brand{background:#e0f2fe;color:#0369a1}
.ls-chip.diff-Easy{background:#dcfce7;color:#15803d}
.ls-chip.diff-Medium{background:#fef3c7;color:#b45309}
.ls-chip.diff-Hard{background:#fee2e2;color:#b91c1c}
.ls-chip.technique{background:#f3e8ff;color:#7e22ce}
.ls-preview-pane{background:#f4f7f5;display:flex;flex-direction:column;height:100%;overflow:hidden}
.ls-preview-toolbar{padding:10px 16px;background:#ffffff;border-bottom:1px solid #e3ede7;display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
.ls-toolbar-left{display:flex;align-items:center;gap:8px}
.ls-toolbar-right{display:flex;align-items:center;gap:6px}
.ls-toggle-mode{display:inline-flex;align-items:center;background:#edf5f1;border:1px solid #d4e6dc;border-radius:7px;padding:2px;gap:2px}
.ls-toggle-btn{padding:4px 9px;border-radius:5px;border:none;background:transparent;font-size:11px;font-weight:700;color:#557265;cursor:pointer;transition:all 0.15s ease}
.ls-toggle-btn.active{background:#087b59;color:#ffffff;box-shadow:0 1px 3px rgba(8,123,89,0.2)}
.ls-envelope{padding:14px 18px;background:#ffffff;border-bottom:1px solid #e7eee9;display:flex;align-items:flex-start;gap:12px}
.ls-avatar{width:38px;height:38px;border-radius:50%;background:linear-gradient(135deg,#087b59,#10b981);color:#fff;display:grid;place-items:center;font-weight:850;font-size:15px;text-transform:uppercase;flex-shrink:0;box-shadow:0 2px 6px rgba(8,123,89,0.15)}
.ls-envelope-meta{flex:1;min-width:0;display:flex;flex-direction:column;gap:3px}
.ls-meta-row-from{display:flex;justify-content:space-between;align-items:center;gap:8px}
.ls-sender-name{font-size:13px;font-weight:800;color:#10241b}
.ls-sender-email{font-size:11.5px;color:#60796f;margin-left:4px;font-family:monospace}
.ls-meta-date{font-size:11px;color:#7b968b;flex-shrink:0}
.ls-meta-subject{font-size:13.5px;font-weight:800;color:#0b1a13;margin-top:2px}
.ls-meta-subline{font-size:11px;color:#648074;display:flex;gap:10px;flex-wrap:wrap}
.ls-frame-container{flex:1;padding:14px 18px;overflow-y:auto;display:flex;justify-content:center;background:#edf3f0}
.ls-frame-card{width:100%;max-width:820px;background:#ffffff;border-radius:10px;border:1px solid #dce8e1;box-shadow:0 3px 14px rgba(7,28,21,0.04);overflow:hidden;display:flex;flex-direction:column}
.ls-iframe{width:100%;height:680px;border:none;background:#ffffff}
@media(max-width:1200px){.ls-browser{grid-template-columns:200px 320px 1fr}}
@media(max-width:960px){.ls-browser{grid-template-columns:1fr;height:auto;min-height:0}.ls-sidebar{display:none}}
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

RBAC_ROUTE_PERMISSION_MAP={
    "GET":{
        "/admin/campaigns":"campaign.view",
        "/admin/templates":"template.view",
        "/admin/landing-pages":"landing_page.view",
        "/admin/smtp":"smtp.view",
        "/admin/training":"training.view",
        "/admin/recipients":"recipient.view",
        "/admin/groups":"group.view",
        "/admin/users":"admin.view",
        "/admin/reports":"report.view",
        "/admin/reports.pdf":"report.export",
        "/admin/risk":"risk.view",
        "/admin/settings":"risk.manage",
        "/admin.csv":"report.export",
        "/admin/exports":"report.export",
        "/admin/audit":"audit.view",
        "/admin/admins":"admin.view",
        "/admin/landing-pages/preview":"landing_page.view",
        "/admin/templates/preview":"template.view",
        "/admin/landing-pages/new":"landing_page.create",
        "/admin/smtp/diagnostics":"smtp.diagnostics",
        "/admin/smtp/new":"smtp.manage",
        "/admin/training/new":"training.assign",
        "/admin/training/course/new":"training.manage",
        "/admin/recipients/import":"recipient.import",
        "/admin/recipients/new":"recipient.create",
        "/admin/groups/new":"group.manage",
        "/admin/templates/test-send":"template.edit",
        "/admin/campaigns/test-send":"campaign.launch",
        "/admin/campaigns/launch":"campaign.launch",
        "/admin/campaigns/new":"campaign.create",
        "/admin/reports/scheduled":"report.schedule",
    },
    "POST":{
        "/admin/admins/review":"admin.view",
        "/admin/landing-pages/save":{"create":"landing_page.create","edit":"landing_page.edit"},
        "/admin/templates/save":{"create":"template.create","edit":"template.edit"},
        "/admin/templates/test-send":"template.edit",
        "/admin/reports/scheduled/save":"report.schedule",
        "/admin/admins/create":"admin.create",
        "/admin/roles/permissions":"role.edit",
        "/admin/roles/create":"role.create",
        "/admin/roles/duplicate":"role.create",
        "/admin/roles/delete":"role.delete",
        "/admin/roles/save":{"create":"role.create","edit":"role.edit"},
        "/admin/admins/save":"admin.edit",
        "/admin/risk/settings":"risk.manage",
        "/admin/smtp/save":"smtp.manage",
        "/admin/smtp/delete":"smtp.manage",
        "/admin/smtp/diagnostics":"smtp.diagnostics",
        "/admin/smtp/test":"smtp.diagnostics",
        "/admin/training/update":"training.manage",
        "/admin/training/course/save":"training.manage",
        "/admin/training/assign":"training.assign",
        "/admin/recipients/save":{"create":"recipient.create","edit":"recipient.edit"},
        "/admin/recipients/delete":"recipient.delete",
        "/admin/recipients/import":"recipient.import",
        "/admin/groups/save":"group.manage",
        "/admin/campaigns/control":"campaign.edit",
        "/admin/campaigns/test-send":"campaign.launch",
        "/admin/campaigns/launch":"campaign.launch",
        "/admin/campaigns/save":{"create":"campaign.create","edit":"campaign.edit"},
        "/admin/campaigns/quick":"campaign.launch",
        "/admin/settings/base-url":"risk.manage",
    },
}

def route_permission(path,method,form=None):
    mapping=RBAC_ROUTE_PERMISSION_MAP.get((method or "").upper(),{})
    value=mapping.get(path)
    if isinstance(value,dict):
        record_id=(form or {}).get("id",[""])[0].strip()
        return value["edit"] if (record_id and record_id!="new") else value["create"]
    return value

class Handler(BaseHTTPRequestHandler):
    def sendbody(self,code,body,ctype="text/html; charset=utf-8",extra=None):
        b=body.encode() if isinstance(body,str) else body
        self.send_response(code)
        self.send_header("Content-Type",ctype)
        self.send_header("Content-Length",str(len(b)))
        self.send_header("X-Content-Type-Options","nosniff")
        x_frame = "DENY"
        if extra and "X-Frame-Options" in extra:
            x_frame = extra.pop("X-Frame-Options")
        if x_frame:
            self.send_header("X-Frame-Options", x_frame)
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

    def resolve_role_permissions(self, role_name=None):
        """
        Resolve the effective permission keys for the current role model.

        Custom roles use persisted rbac_role_permissions assignments.
        Built-in roles use a compatibility mapping that mirrors the existing
        module-level role_allowed() behavior. This resolver does not enforce
        access; enforcement remains a separate Phase D task.
        """
        admin=self.current_admin()
        role=role_name or (admin.get("role") if admin else None)
        if not role:
            return set()

        c=db()
        row=c.execute("SELECT id,built_in,active FROM rbac_roles WHERE name=?",(role,)).fetchone()
        # Inactive roles must fail closed, including built-in roles that use
        # the compatibility mapping below rather than persisted assignments.
        if row and not row["active"]:
            c.close()
            return set()
        if row and row["built_in"]==0:
            rows=c.execute("""SELECT p.resource,p.action
                              FROM rbac_role_permissions rp
                              JOIN rbac_permissions p ON p.id=rp.permission_id
                              WHERE rp.role_id=? AND p.active=1
                              ORDER BY p.resource,p.action""",(row["id"],)).fetchall()
            c.close()
            return {"%s.%s"%(x["resource"],x["action"]) for x in rows}

        if role=="Administrator":
            rows=c.execute("SELECT resource,action FROM rbac_permissions WHERE active=1 ORDER BY resource,action").fetchall()
            c.close()
            return {"%s.%s"%(x["resource"],x["action"]) for x in rows}

        compatibility_resources={
            "Campaign Manager":{"campaign","template","landing_page","recipient","group","training"},
            "Reporting Analyst":{"report","risk"},
            "SMTP Manager":{"smtp"},
            "Security Auditor":{"audit"},
        }
        resources=compatibility_resources.get(role,set())
        if not resources:
            c.close()
            return set()
        placeholders=",".join("?" for _ in resources)
        rows=c.execute("SELECT resource,action FROM rbac_permissions WHERE active=1 AND resource IN (%s) ORDER BY resource,action"%placeholders,tuple(sorted(resources))).fetchall()
        c.close()
        return {"%s.%s"%(x["resource"],x["action"]) for x in rows}

    def resolve_role_access_preview(self, role_name=None):
        """
        Return a structured, non-secret preview of effective RBAC access.

        The preview is derived from the same permission resolver used for
        enforcement. It is read-only and intentionally excludes credentials,
        secrets and mutable account data so it can be reused by future admin
        UI flows without creating a second authorization model.
        """
        admin=self.current_admin()
        role=role_name or (admin.get("role") if admin else None)
        if not role:
            return {"role":None,"permission_count":0,"modules":[],"permissions":[],"high_risk_permissions":[],"risk_counts":{"normal":0,"elevated":0,"privileged":0},"scopes":[]}

        keys=self.resolve_role_permissions(role)
        c=db()
        rows=[]
        if keys:
            pairs=[key.split(".",1) for key in keys if "." in key]
            clauses=[]
            params=[]
            for resource,action in pairs:
                clauses.append("(resource=? AND action=?)")
                params.extend((resource,action))
            rows=c.execute(
                "SELECT resource,action,label,description,risk_level FROM rbac_permissions WHERE active=1 AND ("+" OR ".join(clauses)+") ORDER BY resource,action",
                tuple(params)
            ).fetchall()
        scope_rows=c.execute(
            """SELECT p.resource,p.action,s.scope_kind,s.scope_value
               FROM rbac_resource_scopes s
               JOIN rbac_permissions p ON p.id=s.permission_id
               JOIN rbac_roles r ON r.id=s.role_id
               JOIN rbac_role_permissions rp ON rp.role_id=r.id AND rp.permission_id=p.id
               WHERE r.name=? AND r.built_in=0 AND r.active=1 AND s.active=1 AND p.active=1
               ORDER BY p.resource,p.action,s.scope_kind,s.scope_value""",
            (role,)
        ).fetchall()
        c.close()

        scopes=[
            {
                "permission":"%s.%s"%(row["resource"],row["action"]),
                "scope_kind":row["scope_kind"],
                "scope_value":row["scope_value"]
            }
            for row in scope_rows
        ]
        permissions=[            {
                "key":"%s.%s"%(row["resource"],row["action"]),
                "resource":row["resource"],
                "action":row["action"],
                "label":row["label"],
                "description":row["description"] or "",
                "risk_level":row["risk_level"]
            }
            for row in rows
        ]
        risk_counts={"normal":0,"elevated":0,"privileged":0}
        for item in permissions:
            risk_counts[item["risk_level"]]=risk_counts.get(item["risk_level"],0)+1
        high_risk=[item for item in permissions if item["risk_level"] in ("elevated","privileged")]
        modules=sorted({item["resource"] for item in permissions})
        return {
            "role":role,
            "permission_count":len(permissions),
            "modules":modules,
            "permissions":permissions,
            "high_risk_permissions":high_risk,
            "risk_counts":risk_counts,
            "scopes":scopes
        }

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

    def scope_context(self,path,method,form=None,query=""):
        """Return request values used by resource-scope evaluation.

        Scope values are intentionally derived from explicit request context;
        no credential or secret fields are considered.
        """
        form=form or {}
        params=parse_qs(query or "")
        def first(*names):
            # Scope context must be unambiguous across aliases, repeated query
            # parameters, and form/query sources. Conflicts fail closed.
            candidates=[]
            for name in names:
                for source in (form,params):
                    raw=source.get(name,[])
                    if isinstance(raw,str):
                        raw=[raw]
                    candidates.extend(value.strip() for value in raw if isinstance(value,str) and value.strip())
            distinct=set(candidates)
            return next(iter(distinct)) if len(distinct)==1 else ""
        if path.startswith("/admin/campaigns"):
            return {
                "campaign": first("id","campaign_id"),
                "campaign_group": first("group_name","group_id"),
                "campaign_type": first("campaign_type","type"),
            }
        if path.startswith("/admin/recipients"):
            return {
                "department": first("department"),
                "organizational_unit": first("organizational_unit","org_unit"),
            }
        if path.startswith("/admin/groups"):
            return {
                "campaign_group": first("name","group_name","id","group_id"),
                "department": first("department"),
                "organizational_unit": first("organizational_unit","org_unit"),
            }
        if path.startswith("/admin/templates"):
            return {"campaign_type": first("campaign_type","type","category")}
        return {
            "department": first("department"),
            "organizational_unit": first("organizational_unit","org_unit"),
            "campaign_type": first("campaign_type","type"),
            "campaign_group": first("group_name","group_id"),
            "campaign": first("campaign_id"),
        }

    def scoped_permission_allowed(self,role_name,permission_key,path,method,form=None,query=""):
        """Evaluate assigned resource scopes for one permission.

        No scope rows preserve legacy permission behavior. Once a permission
        has active scopes, every assigned scope kind must match the request;
        multiple values within the same kind are alternatives. Wildcard '*'
        matches any non-empty request value.
        """
        if role_name=="Administrator":
            return True
        c=db()
        row=c.execute("SELECT id,built_in,active FROM rbac_roles WHERE name=?",(role_name,)).fetchone()
        if not row or row["built_in"] or not row["active"]:
            c.close()
            return False
        try:
            resource,action=permission_key.split(".",1)
        except ValueError:
            c.close()
            return False
        permission=c.execute(
            "SELECT id FROM rbac_permissions WHERE resource=? AND action=? AND active=1",
            (resource,action)
        ).fetchone()
        if not permission:
            c.close()
            return False
        rows=c.execute(
            """SELECT scope_kind,scope_value
               FROM rbac_resource_scopes
               WHERE role_id=? AND permission_id=? AND active=1
               ORDER BY scope_kind,scope_value""",
            (row["id"],permission["id"])
        ).fetchall()
        c.close()
        if not rows:
            return True
        context=self.scope_context(path,method,form,query)
        grouped={}
        for item in rows:
            grouped.setdefault(item["scope_kind"],set()).add(item["scope_value"])
        for kind,values in grouped.items():
            actual=context.get(kind,"")
            if not actual or (actual not in values and "*" not in values):
                audit(
                    self.current_admin().get("username"),
                    "RBAC_SCOPE_ACCESS_DENIED",
                    "role=%s permission=%s path=%s method=%s scope_kind=%s actual=%s allowed=%s"
                    %(role_name,permission_key,path,method,kind,actual,",".join(sorted(values))),
                    self.client_address[0]
                )
                return False
        return True

    def permission_allowed(self,path,method,form=None,query=""):
        """Evaluate route permission and any assigned resource scope."""
        if not self.current_admin():
            return False
        required=route_permission(path,method,form)
        if not required:
            # Unknown or unmapped admin routes must fail closed. Public login,
            # session logout, and the authenticated dashboard are handled by
            # their explicit control flow outside this permission check.
            return False
        permissions=self.resolve_role_permissions()
        if required not in permissions:
            return False
        return self.scoped_permission_allowed(
            self.current_admin().get("role"),required,path,method,form,query
        )

    def login_page(self,error=""):
        err=f'<div class="login-alert">{esc(error)}</div>' if error else ""
        body=f"""<div class="login-shell"><section class="login-left">
<div class="brand"><div class="brand-mark">🛡️</div><div>Trust PhishGuard</div></div>
<h1>Security awareness, measured.</h1>
<p>Enterprise phishing simulation and behavioral human-risk telemetry control center. Measure employee awareness, schedule automated drills, and track resilience without capturing credentials.</p>
<div class="feature-row">
  <span class="feature">🎯 Multi-Vector Drills</span>
  <span class="feature">📊 Real-Time Telemetry</span>
  <span class="feature">🛡️ Zero-Credential Policy</span>
  <span class="feature">⚡ Asia/Dhaka Synchronized</span>
</div>
</section><section class="login-right"><div class="login-card">
<div class="login-card-head">
  <h2>Admin Sign In</h2>
  <div class="muted">Access the Trust PhishGuard security operations console.</div>
</div>
{err}<form method="post" action="/admin/login">
<div class="field"><label>Admin Username</label><input name="username" autocomplete="username" placeholder="admin@trustbank.com.bd" required autofocus></div>
<div class="field"><label>Password</label><input type="password" name="password" autocomplete="current-password" placeholder="••••••••••••" required></div>
<button class="login-btn" type="submit">Sign in securely ➔</button></form>
<div class="notice"><b>🛡️ Strict Simulation Policy:</b> This portal monitors awareness telemetry only. Passwords, OTPs, PINs, CVVs, and payment credentials are never requested or stored.</div>
<div class="trust">Trust Bank PLC · Information Security Division</div>
</div></section></div>"""
        return page("Admin Sign In",body,LOGIN_CSS)

    def dashboard(self):
        c=db()
        total=c.execute("SELECT COUNT(*) n FROM events").fetchone()["n"]
        clicks=c.execute("SELECT COUNT(*) n FROM events WHERE event='click'").fetchone()["n"]
        subs=c.execute("SELECT COUNT(*) n FROM events WHERE event IN ('submitted','form_action')").fetchone()["n"]
        ips=c.execute("SELECT COUNT(DISTINCT ip) n FROM events").fetchone()["n"]
        templates=c.execute("SELECT template, COUNT(*) n FROM events GROUP BY template ORDER BY n DESC").fetchall()
        recent=c.execute("SELECT * FROM events ORDER BY id DESC LIMIT 80").fetchall()
        since=(datetime.now(timezone.utc)-timedelta(days=6)).isoformat()
        trend=c.execute("SELECT substr(ts,1,10) d, COUNT(*) n FROM events WHERE ts>=? GROUP BY d ORDER BY d", (since,)).fetchall()
        c.close()

        tpl_labels = {
            "1": "1 (Apex Rewards)", "1.html": "1 (Apex Rewards)",
            "2": "2 (Trust Bank PLC)", "2.html": "2 (Trust Bank PLC)",
            "3": "3 (Microsoft 365)", "3.html": "3 (Microsoft 365)",
            "4": "4 (Google Workspace)", "4.html": "4 (Google Workspace)",
            "5": "5 (HR Portal)", "5.html": "5 (HR Portal)",
            "6": "6 (GlobalProtect IT)", "6.html": "6 (GlobalProtect IT)",
            "7": "7 (bKash & Banking)", "7.html": "7 (bKash & Banking)",
            "8": "8 (Zoom Meetings)", "8.html": "8 (Zoom Meetings)",
            "9": "9 (AWS IAM Console)", "9.html": "9 (AWS IAM Console)",
            "10": "10 (Awareness Drill)", "10.html": "10 (Awareness Drill)",
        }

        rate=(subs/clicks*100) if clicks else 0
        max_t=max([r["n"] for r in templates],default=1) or 1
        bars="".join(f'<div class="bar-row"><span>{esc(tpl_labels.get(str(r["template"]), "Template " + str(r["template"])))}</span><div class="bar"><i style="width:{r["n"]/max_t*100:.0f}%"></i></div><b>{r["n"]}</b></div>' for r in templates[:8]) or '<div class="sub">No template activity yet.</div>'

        byday={r["d"]:r["n"] for r in trend}
        days=[]
        now=datetime.now(timezone.utc)
        for i in range(6,-1,-1):
            d=(now-timedelta(days=i)).date().isoformat()
            days.append((d,byday.get(d,0)))
        max_d=max([x[1] for x in days],default=1) or 1
        trend_html="".join(f'<div class="day"><b>{n}</b><div class="daybar" style="height:{max(3,n/max_d*135):.0f}px"></div><small>{d[5:]}</small></div>' for d,n in days)

        rows=[]
        for r in recent:
            d,t=format_datetime(r["ts"])
            display_tpl = tpl_labels.get(str(r["template"]), "Template " + str(r["template"]))
            name_val = esc(r["name"]) if r["name"] else '<span style="color:#8ba59b">—</span>'
            email_val = esc(r["email"]) if r["email"] else '<span style="color:#8ba59b">—</span>'
            mobile_val = esc(r["mobile"]) if r["mobile"] else '<span style="color:#8ba59b">—</span>'
            rows.append(f'<tr><td>{esc(d)}</td><td>{esc(t)}</td><td><span class="pill {esc(r["event"])}">{esc(r["event"])}</span></td><td><b>{esc(display_tpl)}</b></td><td><code>{esc(r["ip"])}</code></td><td>{name_val}</td><td>{email_val}</td><td>{mobile_val}</td></tr>')
        table="".join(rows) or '<tr><td colspan="8">No activity yet.</td></tr>'

        body=f"""<header class="topbar"><div class="topbrand"><div class="mark">🛡️</div>Trust PhishGuard</div><div class="top-actions"><span class="top-role-badge">ADMIN CONTROL CENTER</span><a href="/admin.csv">📥 Export CSV</a><a href="/admin/logout">🚪 Logout</a></div></header>
<main class="wrap"><div class="hero"><div><h1>Dashboard</h1><p>Simulation telemetry and engagement overview · Asia/Dhaka</p></div><div style="display:flex;gap:10px;align-items:center"><a class="btn primary" href="/admin/campaigns/new">+ New Campaign</a><a class="btn" href="/admin/landing-pages/new">+ New Landing Page</a><a class="btn" href="/admin.csv">📥 Export CSV</a></div></div>
<section class="stats">
  <div class="stat"><div class="stat-label">TOTAL EVENTS</div><div class="num">{total}</div><div class="delta">All recorded activity</div></div>
  <div class="stat"><div class="stat-label">CLICKS</div><div class="num">{clicks}</div><div class="delta">Simulation page visits</div></div>
  <div class="stat"><div class="stat-label">SUBMISSIONS</div><div class="num">{subs}</div><div class="delta">Form actions recorded</div></div>
  <div class="stat"><div class="stat-label">ACTION RATE</div><div class="num">{rate:.1f}%</div><div class="delta">{ips} unique source IPs</div></div>
</section>
<section class="grid">
  <div class="card"><h3>7-Day Activity</h3><div class="sub">Recorded simulation events by UTC day</div><div class="trend">{trend_html}</div></div>
  <div class="card"><h3>Template Performance</h3><div class="sub">Total events by template</div><div class="bars">{bars}</div></div>
</section>
<section class="card activity" style="margin-top:20px">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:12px">
    <div><h3 style="margin:0">Recent Activity</h3><div class="sub" style="margin-top:4px">Latest simulation events · dates and times shown in Bangladesh Standard Time</div></div>
    <div class="filter" style="margin:0"><input id="q" oninput="filterRows()" placeholder="Filter IP, template, email..."><button onclick="document.getElementById('q').value='';filterRows()">Clear</button></div>
  </div>
  <div class="table-wrap">
    <table class="table"><thead><tr><th>Date</th><th>Time</th><th>Event</th><th>Template</th><th>Source IP</th><th>Name</th><th>Email</th><th>Mobile</th></tr></thead><tbody id="rows">{table}</tbody></table>
  </div>
</section></main>
<script>
function filterRows(){{const q=document.getElementById('q').value.toLowerCase();document.querySelectorAll('#rows tr').forEach(r=>r.style.display=r.innerText.toLowerCase().includes(q)?'':'none')}}
</script>"""
        dashboard_main=body[body.index("<main"):body.rindex("</main>")+7]
        return self.admin_shell("Overview",dashboard_main,"Overview")

    def admin_shell(self,title,content,active):
        nav_groups=[
            ("Simulation Suite",[
                ("Overview","/admin","📊"),
                ("Campaigns","/admin/campaigns","🎯"),
                ("Email Templates","/admin/templates","✉️"),
                ("Landing Pages","/admin/landing-pages","🌐"),
            ]),
            ("Audience & Relay",[
                ("Recipients","/admin/recipients","👥"),
                ("Groups & Departments","/admin/groups","🏢"),
                ("SMTP Providers","/admin/smtp","⚡"),
            ]),
            ("Analytics & Risk",[
                ("Reports","/admin/reports","📈"),
                ("Risk & Trends","/admin/risk","🛡️"),
                ("Users & Groups","/admin/users","👤"),
            ]),
            ("Governance",[
                ("Training","/admin/training","🎓"),
                ("Exports","/admin/exports","💾"),
                ("Settings","/admin/settings","⚙️"),
                ("Audit Log","/admin/audit","📋"),
                ("Admin Users","/admin/admins","🔐"),
            ]),
        ]
        links_parts=[]
        for gname,items in nav_groups:
            links_parts.append(f'<div class="side-group-title">{gname}</div>')
            for n,u,ico in items:
                act="active" if (n==active or (active in ("Templates","Email Templates") and n=="Email Templates") or (active=="Overview" and n=="Overview") or (active=="Dashboard" and n=="Overview")) else ""
                links_parts.append(f'<a href="{u}" class="{act}"><span class="side-ico">{ico}</span><span>{n}</span></a>')
        links="".join(links_parts)
        css=DASH_CSS
        body=f'''<header class="topbar">
  <a class="topbrand" href="/admin">
    <div class="mark">🛡️</div>
    <div>Trust PhishGuard</div>
  </a>
  <div class="live-status-pill">
    <span class="pulse-dot"></span> Simulation Engine Online · Asia/Dhaka
  </div>
  <div class="top-actions">
    <span class="top-role-badge">ADMINISTRATOR</span>
    <a href="/admin.csv">📥 Export CSV</a>
    <a href="/admin/logout">🚪 Logout</a>
  </div>
</header>
<div class="layout">
  <aside class="side">{links}</aside>
  <main class="main">{content}</main>
</div>'''
        return page(title,body,css)

    def feature_page(self,path,query=""):
        c=db()
        if path=="/admin/campaigns":
            q_params=parse_qs(query) if query else {}
            quick_launched_id=q_params.get("quick_launched",[""])[0]
            quick_error=q_params.get("quick_error",[""])[0]
            sent_n=q_params.get("sent",["0"])[0]
            failed_n=q_params.get("failed",["0"])[0]
            total_n=q_params.get("total",["0"])[0]
            quick_banner=""
            if quick_launched_id:
                ql_camp=c.execute("SELECT name,targeted FROM campaigns WHERE id=?",(quick_launched_id,)).fetchone()
                c_name=esc(ql_camp["name"]) if ql_camp else f"Campaign #{quick_launched_id}"
                if quick_error:
                    quick_banner=f'''<div style="background:#fff3f3;border:1.5px solid #dc3545;color:#842029;padding:14px 18px;border-radius:12px;margin-bottom:20px;display:flex;align-items:center;justify-content:space-between;box-shadow:0 2px 8px rgba(220,53,69,0.1)">
                      <div style="display:flex;align-items:center;gap:12px">
                        <span style="font-size:24px">⚠️</span>
                        <div><b style="font-size:14px">Quick Campaign Created with Dispatch Notice</b><div style="font-size:12.5px;margin-top:3px;opacity:0.95">{esc(quick_error)}</div></div>
                      </div>
                      <a href="/admin/campaigns?id={quick_launched_id}" class="btn" style="background:#fff;color:#842029;border:1px solid #f5c2c7;font-size:12px;font-weight:600">Review Campaign</a>
                    </div>'''
                else:
                    quick_banner=f'''<div style="background:#e8f8f0;border:1.5px solid #28a745;color:#155724;padding:14px 18px;border-radius:12px;margin-bottom:20px;display:flex;align-items:center;justify-content:space-between;box-shadow:0 2px 8px rgba(40,167,69,0.1)">
                      <div style="display:flex;align-items:center;gap:12px">
                        <span style="font-size:24px">⚡</span>
                        <div><b style="font-size:14px">Quick Campaign Dispatched Successfully!</b><div style="font-size:12.5px;margin-top:3px;opacity:0.95">"{c_name}" is active. <b>Attempted:</b> {total_n} · <b style="color:#198754">Sent:</b> {sent_n} · <b>Failed:</b> {failed_n}</div></div>
                      </div>
                      <div style="display:flex;gap:8px">
                        <a href="/admin/campaigns?id={quick_launched_id}" class="btn" style="background:#fff;color:#155724;border:1px solid #c3e6cb;font-size:12px;font-weight:600">View Campaign</a>
                        <a href="/admin/reports?campaign_id={quick_launched_id}" class="btn primary" style="font-size:12px;font-weight:600">Live Analytics</a>
                      </div>
                    </div>'''

            rows=c.execute("SELECT * FROM campaigns ORDER BY id DESC").fetchall()
            templates_rows=c.execute("SELECT template, name, subject, brand FROM template_library WHERE status='Active' ORDER BY CASE WHEN brand='Zoom' THEN 0 WHEN brand='Microsoft Office 365' THEN 1 WHEN brand='Google Workspace' THEN 2 ELSE 3 END, brand, name").fetchall()
            groups_rows=c.execute("SELECT name FROM groups_tbl ORDER BY name").fetchall()
            active_recipients_cnt=c.execute("SELECT COUNT(*) n FROM recipients WHERE status!='Suppressed'").fetchone()["n"]
            smtp_rows=c.execute("SELECT id, name, from_email FROM smtp_profiles WHERE enabled=1 ORDER BY id").fetchall()
            landing_rows=c.execute("SELECT id, name, template FROM landing_pages WHERE status='Enabled' ORDER BY id").fetchall()
            c.close()

            template_options="".join(f'<option value="{esc(t["template"])}">[{esc(t["brand"] or "General")}] {esc(t["name"])}</option>' for t in templates_rows)
            group_options="".join(f'<option value="{esc(g["name"])}">👥 Group: {esc(g["name"])}</option>' for g in groups_rows)
            landing_options="".join(f'<option value="{l["id"]}" data-tpl="{esc(l["template"] or "")}">{esc(l["name"])} (Template {esc(l["template"] or "Default")})</option>' for l in landing_rows)
            smtp_options="".join(f'<option value="{s["id"]}">{esc(s["name"])} &lt;{esc(s["from_email"])}&gt;</option>' for s in smtp_rows) or '<option value="">⚠️ No enabled SMTP profile (Configure in SMTP Providers)</option>'

            tpl_dict={str(t["template"]): {"name": t["name"], "subject": t["subject"] or "Security Awareness Simulation", "brand": t["brand"] or ""} for t in templates_rows}
            tpl_json_raw=json.dumps(tpl_dict).replace("'", "\\'")

            total_c=len(rows)
            active_c=sum(1 for r in rows if r["status"]=="Active")
            completed_c=sum(1 for r in rows if r["status"]=="Completed")
            targeted_sum=sum(r["targeted"] or 0 for r in rows)
            table="".join('<tr><td><b>#%s</b></td><td><div style="font-weight:700;color:#10221a">%s</div></td><td><span class="pill" style="background:#f4f7f5;color:#1e352b">Template %s</span></td><td><b>%s</b></td><td><span class="camp-status-badge %s">%s</span></td><td style="text-align:right"><a class="btn primary" href="/admin/campaigns?id=%s">✏️ Edit</a> <a class="btn" href="/admin/reports?campaign_id=%s">📊 Analytics</a></td></tr>'%(r["id"],esc(r["name"]),esc(r["template"]),r["targeted"],"status-active" if r["status"]=="Active" else ("status-completed" if r["status"]=="Completed" else "status-draft"),esc(r["status"]),r["id"],r["id"]) for r in rows) or '<tr><td colspan="6">No campaigns yet.</td></tr>'
            body=f'''{quick_banner}
<div class="camp-header">
  <div>
    <div class="camp-crumb"><a href="/admin">Dashboard</a> <span>/</span> <span>Campaigns</span></div>
    <div class="camp-title-row">
      <h1>Simulation Campaigns</h1>
      <span class="camp-status-badge status-active">{active_c} Active</span>
    </div>
  </div>
  <div class="camp-actions" style="display:flex;gap:10px;align-items:center">
    <button class="btn" type="button" onclick="openQuickModal()" style="background:linear-gradient(135deg,#ff9800,#f57c00);color:#fff;border:none;font-weight:700;display:inline-flex;align-items:center;gap:7px;box-shadow:0 3px 10px rgba(245,124,0,0.3);padding:9px 18px;border-radius:8px;cursor:pointer;font-size:13px">⚡ Quick Campaign</button>
    <a class="btn primary" href="/admin/campaigns/new">+ New Campaign</a>
  </div>
</div>

<div class="stats">
  <div class="stat"><div class="stat-label">TOTAL CAMPAIGNS</div><div class="num">{total_c}</div><div class="delta">All scheduled drills</div></div>
  <div class="stat"><div class="stat-label">ACTIVE DRILLS</div><div class="num">{active_c}</div><div class="delta">Currently dispatching</div></div>
  <div class="stat"><div class="stat-label">COMPLETED</div><div class="num">{completed_c}</div><div class="delta">Archived simulations</div></div>
  <div class="stat"><div class="stat-label">TARGETED EMPLOYEES</div><div class="num">{targeted_sum}</div><div class="delta">Cumulative recipients</div></div>
</div>

<div class="card">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:12px">
    <h3 style="margin:0">Configured Campaigns</h3>
    <input id="qCamp" oninput="filterCampTable()" placeholder="Filter by name, template or status..." style="padding:8px 12px;border:1.5px solid #cbdad2;border-radius:8px;font-size:12px;width:280px">
  </div>
  <div class="table-wrap">
    <table class="table" style="width:100%">
      <thead><tr><th>ID</th><th>Campaign Name</th><th>Payload</th><th>Targeted</th><th>Status</th><th style="text-align:right">Actions</th></tr></thead>
      <tbody id="campRows">{table}</tbody>
    </table>
  </div>
</div>

<!-- Quick Campaign Modal -->
<div id="quickCampModal" style="display:none;position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(10,25,20,0.65);z-index:99999;backdrop-filter:blur(4px);align-items:center;justify-content:center;padding:20px;box-sizing:border-box">
  <div style="background:#ffffff;border-radius:18px;width:100%;max-width:620px;box-shadow:0 25px 60px rgba(0,0,0,0.3);overflow:hidden;animation:popIn 0.22s cubic-bezier(0.16,1,0.3,1)">
    <div style="background:linear-gradient(135deg,#0d3829,#15543e);color:#fff;padding:20px 24px;display:flex;align-items:center;justify-content:space-between">
      <div style="display:flex;align-items:center;gap:12px">
        <div style="background:linear-gradient(135deg,#ffb74d,#ff9800);width:42px;height:42px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:22px;box-shadow:0 4px 10px rgba(0,0,0,0.25)">⚡</div>
        <div>
          <h2 style="margin:0;font-size:18px;font-weight:700;color:#fff">Quick Campaign Launch</h2>
          <p style="margin:3px 0 0;font-size:12px;opacity:0.85;color:#d8efe5">Deploy instant simulation drills with 1-click execution</p>
        </div>
      </div>
      <button type="button" onclick="closeQuickModal()" style="background:none;border:none;color:#fff;font-size:26px;cursor:pointer;opacity:0.8;line-height:1">&times;</button>
    </div>

    <form class="form" method="post" action="/admin/campaigns/quick" style="padding:24px;display:flex;flex-direction:column;gap:14px;margin:0">
      <div>
        <label style="font-weight:600;font-size:12.5px;color:#203a30;margin-bottom:5px;display:block">Campaign Name</label>
        <input type="text" id="qcName" name="name" required maxlength="150" style="width:100%;box-sizing:border-box;padding:9px 12px;border:1.5px solid #cbdad2;border-radius:8px;font-size:13px" placeholder="e.g. Quick Drill - Zoom Meeting (Instant)">
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
        <div>
          <label style="font-weight:600;font-size:12.5px;color:#203a30;margin-bottom:5px;display:block">Email Template (Payload)</label>
          <select id="qcTemplate" name="template" required onchange="onTemplateChange()" style="width:100%;box-sizing:border-box;padding:9px 12px;border:1.5px solid #cbdad2;border-radius:8px;font-size:13px">
            {template_options}
          </select>
        </div>
        <div>
          <label style="font-weight:600;font-size:12.5px;color:#203a30;margin-bottom:5px;display:block">Target Audience</label>
          <select name="group_name" id="qcAudience" style="width:100%;box-sizing:border-box;padding:9px 12px;border:1.5px solid #cbdad2;border-radius:8px;font-size:13px">
            <option value="">🎯 All Active Recipients ({active_recipients_cnt} targets)</option>
            {group_options}
          </select>
        </div>
      </div>

      <div>
        <label style="font-weight:600;font-size:12.5px;color:#203a30;margin-bottom:5px;display:block">Email Subject Line</label>
        <input type="text" id="qcSubject" name="subject" required maxlength="250" style="width:100%;box-sizing:border-box;padding:9px 12px;border:1.5px solid #cbdad2;border-radius:8px;font-size:13px">
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
        <div>
          <label style="font-weight:600;font-size:12.5px;color:#203a30;margin-bottom:5px;display:block">Landing Page</label>
          <select id="qcLanding" name="landing_page_id" required style="width:100%;box-sizing:border-box;padding:9px 12px;border:1.5px solid #cbdad2;border-radius:8px;font-size:13px">
            {landing_options}
          </select>
        </div>
        <div>
          <label style="font-weight:600;font-size:12.5px;color:#203a30;margin-bottom:5px;display:block">SMTP Profile</label>
          <select id="qcSmtp" name="smtp_profile_id" required style="width:100%;box-sizing:border-box;padding:9px 12px;border:1.5px solid #cbdad2;border-radius:8px;font-size:13px">
            {smtp_options}
          </select>
        </div>
      </div>

      <div style="background:#f4fbf7;border:1px solid #d4ece1;border-radius:10px;padding:11px 14px;font-size:11.5px;color:#225c46;line-height:1.5;display:flex;align-items:flex-start;gap:8px">
        <span style="font-size:16px">⚡</span>
        <div><b>Instant Dispatch Policy:</b> Quick campaigns bypass sending window restrictions and weekend blocks to immediately deliver test simulation emails to targets.</div>
      </div>

      <div style="display:flex;justify-content:flex-end;align-items:center;gap:10px;margin-top:6px">
        <button type="button" class="btn" onclick="closeQuickModal()" style="cursor:pointer">Cancel</button>
        <button type="submit" name="action_mode" value="draft" class="btn" style="background:#eef4f1;color:#1e3d31;font-weight:600;cursor:pointer">💾 Save as Draft</button>
        <button type="submit" name="action_mode" value="launch" class="btn primary" style="background:linear-gradient(135deg,#ff9800,#f57c00);border:none;color:#fff;font-weight:700;box-shadow:0 3px 8px rgba(245,124,0,0.3);cursor:pointer">⚡ Instant Launch Now</button>
      </div>
    </form>
  </div>
</div>

<style>
@keyframes popIn {{
  from {{ transform: scale(0.94); opacity: 0; }}
  to {{ transform: scale(1); opacity: 1; }}
}}
</style>

<script>
const qcTemplates = {tpl_json_raw};
function filterCampTable(){{const q=document.getElementById('qCamp').value.toLowerCase();document.querySelectorAll('#campRows tr').forEach(r=>r.style.display=r.innerText.toLowerCase().includes(q)?'':'none')}}

function openQuickModal() {{
  document.getElementById('quickCampModal').style.display = 'flex';
  onTemplateChange();
}}
function closeQuickModal() {{
  document.getElementById('quickCampModal').style.display = 'none';
}}
function onTemplateChange() {{
  const selTpl = document.getElementById('qcTemplate').value;
  const tInfo = qcTemplates[selTpl];
  if (tInfo) {{
    document.getElementById('qcSubject').value = tInfo.subject || 'Security Awareness Simulation';
    const now = new Date();
    const dStr = now.toLocaleDateString('en-GB', {{day:'2-digit', month:'short'}});
    const tStr = now.toLocaleTimeString('en-GB', {{hour:'2-digit', minute:'2-digit'}});
    document.getElementById('qcName').value = 'Quick Drill - ' + (tInfo.name || 'Template ' + selTpl) + ' (' + dStr + ' ' + tStr + ')';
    const lpSel = document.getElementById('qcLanding');
    for (let opt of lpSel.options) {{
      if (opt.getAttribute('data-tpl') === selTpl) {{
        lpSel.value = opt.value;
        break;
      }}
    }}
  }}
}}
document.getElementById('quickCampModal').addEventListener('click', function(e) {{
  if (e.target === this) closeQuickModal();
}});
</script>'''
            return self.admin_shell("Campaigns",body,"Campaigns")
        if path=="/admin/templates":
            rows=c.execute("""SELECT * FROM template_library
                              ORDER BY CASE
                                WHEN brand='Zoom' THEN 0
                                WHEN brand='Microsoft Office 365' THEN 1
                                WHEN brand='Google Workspace' THEN 2
                                WHEN brand='Amazon Web Services (AWS)' THEN 3
                                WHEN brand='Slack' THEN 4
                                ELSE 5 END, brand, name""").fetchall()
            c.close()
            total_t=len(rows)
            categories_map={}
            brands_map={}
            for r in rows:
                cat=r["category"] or "General"
                categories_map[cat]=categories_map.get(cat,0)+1
                b=r["brand"] or "General"
                brands_map[b]=brands_map.get(b,0)+1

            cat_keys=sorted(categories_map.keys())
            brand_keys=sorted(brands_map.keys(), key=lambda x: (0 if x=="Zoom" else 1 if x=="Microsoft Office 365" else 2 if x=="Google Workspace" else 3 if x=="Amazon Web Services (AWS)" else 4, x))

            sel_param=parse_qs(query).get("select",[""])[0] if query else ""
            default_row=next((r for r in rows if r["template"]==sel_param), rows[0] if rows else None)
            default_id=default_row["template"] if default_row else "1"

            cat_items='<div class="ls-nav-item active" data-cat="" onclick="lsFilterCat(\'\')"><span>📁 All Categories</span><span class="ls-badge-count">%d</span></div>'%total_t
            for k in cat_keys:
                cat_items+='<div class="ls-nav-item" data-cat="%s" onclick="lsFilterCat(\'%s\')"><span>📁 %s</span><span class="ls-badge-count">%d</span></div>'%(esc(k),esc(k),esc(k),categories_map[k])

            brand_items='<div class="ls-nav-item active" data-brand="" onclick="lsFilterBrand(\'\')"><span>✉️ All Brands</span><span class="ls-badge-count">%d</span></div>'%total_t
            for b in brand_keys:
                brand_items+='<div class="ls-nav-item" data-brand="%s" onclick="lsFilterBrand(\'%s\')"><span>✉️ %s</span><span class="ls-badge-count">%d</span></div>'%(esc(b),esc(b),esc(b),brands_map[b])

            techniques=["All","Call to action","Visual Imitation","Generic details","Personalized Information","Urgency","FOMO","Emotional Appeal","Authority Figures","Technical Jargon"]
            tech_pills="".join('<span class="ls-tag-pill%s" data-tech="%s" onclick="lsFilterTech(\'%s\')">%s</span>'%(" active" if t=="All" else "",esc(t),esc(t),esc(t)) for t in techniques)

            cards_list=[]
            tpl_json_map={}
            for r in rows:
                tid=esc(r["template"])
                tname=esc(r["name"])
                tsubj=esc(r["subject"] or "")
                tbrand=esc(r["brand"] or "General")
                tcat=esc(r["category"] or "General")
                tdiff=esc(r["difficulty"] or "Medium")
                tfrom_email=esc(r["from_email"] or "noreply@security.local")
                tfrom_name=esc(r["from_name"] or "Security Team")
                treply_to=esc(r["reply_to"] or tfrom_email)
                ttags=esc(r["tags"] or "")
                is_active=" active" if tid==default_id else ""

                raw_tags=[x.strip() for x in (r["tags"] or "").split(",") if x.strip()]
                badge_tags="".join('<span class="ls-chip technique">%s</span>'%esc(x) for x in raw_tags[:3])

                cards_list.append(f'''<div class="ls-card{is_active}" id="card-{tid}" data-id="{tid}" data-brand="{tbrand}" data-cat="{tcat}" data-tags="{ttags}" onclick="selectTemplate('{tid}')">
  <div class="ls-card-top">
    <div class="ls-card-sender"><span class="ls-dot"></span> {tfrom_email}</div>
    <div class="ls-card-time"><span class="ls-chip diff-{tdiff}">{tdiff}</span></div>
  </div>
  <div class="ls-card-subject">{tsubj}</div>
  <div class="ls-card-name">{tname}</div>
  <div class="ls-card-badges">
    <span class="ls-chip brand">{tbrand}</span>
    {badge_tags}
  </div>
</div>''')

                tpl_json_map[r["template"]]={
                    "id":r["template"],
                    "name":r["name"],
                    "subject":r["subject"] or "",
                    "brand":r["brand"] or "General",
                    "category":r["category"] or "General",
                    "from_name":r["from_name"] or "Security Team",
                    "from_email":r["from_email"] or "noreply@security.local",
                    "reply_to":r["reply_to"] or "noreply@security.local",
                    "difficulty":r["difficulty"] or "Medium",
                    "tags":r["tags"] or "",
                }

            cards_html="".join(cards_list) or '<div style="padding:20px;text-align:center;color:#6d887d">No templates found.</div>'
            json_blob=json.dumps(tpl_json_map)

            def_from_name=esc(default_row["from_name"] if default_row else "Zoom Security")
            def_from_email=esc(default_row["from_email"] if default_row else "noreply@zoomsecurity.com")
            def_subject=esc(default_row["subject"] if default_row else "Urgent: Security Verification Required")
            def_reply_to=esc(default_row["reply_to"] if default_row else "noreplyzoomsecurity-com@linksec.io")
            def_brand=esc(default_row["brand"] if default_row else "Zoom")
            def_initial=def_from_name[:1].upper() if def_from_name else "Z"

            body=f'''<div class="camp-header">
  <div>
    <div class="camp-crumb"><a href="/admin">Dashboard</a> <span>/</span> <span>Email Templates</span></div>
    <div class="camp-title-row">
      <h1>Email Templates &amp; Payloads</h1>
      <span class="camp-status-badge status-active">{total_t} Authentic Lures</span>
    </div>
  </div>
  <div class="camp-actions">
    <a class="btn primary" href="/admin/templates?id=new">+ Create Custom Template</a>
    <a class="btn" href="/admin/campaigns/new?template={default_id}" id="hdrUseBtn">🚀 Use in Campaign</a>
  </div>
</div>

<div class="stats">
  <div class="stat"><div class="stat-label">TOTAL EMAIL TEMPLATES</div><div class="num">{total_t}</div><div class="delta">Pre-configured lures</div></div>
  <div class="stat"><div class="stat-label">AUTHENTIC BRANDS</div><div class="num">{len(brands_map)}</div><div class="delta">Zoom, M365, AWS, GCP, Slack...</div></div>
  <div class="stat"><div class="stat-label">CATEGORIES</div><div class="num">{len(categories_map)}</div><div class="delta">Cloud, Collab, Security, Finance</div></div>
  <div class="stat"><div class="stat-label">COMPLIANCE POLICY</div><div class="num" style="font-size:20px;color:#087b59;margin-top:14px">✓ Verified Safe</div><div class="delta">Zero-credential harvest</div></div>
</div>

<div class="ls-browser">
  <!-- Column 1: Categories & Brands Sidebar -->
  <div class="ls-sidebar">
    <div>
      <div class="ls-group-title">Categories</div>
      <div id="lsCatList">{cat_items}</div>
    </div>
    <div>
      <div class="ls-group-title">Brands</div>
      <div id="lsBrandList" style="max-height:360px;overflow-y:auto">{brand_items}</div>
    </div>
  </div>

  <!-- Column 2: Template Catalog List -->
  <div class="ls-catalog">
    <div class="ls-catalog-header">
      <div class="ls-search-wrap">
        <span class="ls-search-icon">🔍</span>
        <input class="ls-search-input" id="lsSearch" placeholder="Search templates, subjects, brands, techniques..." oninput="lsSearchFilter()">
      </div>
      <div class="ls-tags-bar" id="lsTechBar">{tech_pills}</div>
    </div>
    <div class="ls-cards-list" id="lsCardsList">
      {cards_html}
    </div>
  </div>

  <!-- Column 3: Live Interactive Email Client -->
  <div class="ls-preview-pane">
    <div class="ls-preview-toolbar">
      <div class="ls-toolbar-left">
        <span style="font-size:12px;font-weight:750;color:#203c30">📧 Client Preview:</span>
        <div class="ls-toggle-mode">
          <button type="button" class="ls-toggle-btn active" id="btnModeReal" onclick="setPreviewMode('realistic')">Realistic View (Victim)</button>
          <button type="button" class="ls-toggle-btn" id="btnModeTech" onclick="setPreviewMode('indicators')">Phish Indicators (Trainee)</button>
        </div>
      </div>
      <div class="ls-toolbar-right">
        <a class="btn primary" id="btnUseCamp" href="/admin/campaigns/new?template={default_id}">🚀 Use in Campaign</a>
        <a class="btn" id="btnEditTpl" href="/admin/templates?id={default_id}">✏️ Edit HTML</a>
        <a class="btn" id="btnTestSend" href="/admin/templates/test-send?id={default_id}">✉️ Send Test</a>
      </div>
    </div>

    <!-- Envelope Header -->
    <div class="ls-envelope">
      <div class="ls-avatar" id="prevAvatar">{def_initial}</div>
      <div class="ls-envelope-meta">
        <div class="ls-meta-row-from">
          <div>
            <span class="ls-sender-name" id="prevFromName">{def_from_name}</span>
            <span class="ls-sender-email" id="prevFromEmail">&lt;{def_from_email}&gt;</span>
          </div>
          <div class="ls-meta-date">Today, 10:42 AM (Simulation)</div>
        </div>
        <div class="ls-meta-subject" id="prevSubject">{def_subject}</div>
        <div class="ls-meta-subline">
          <span>To: <b>Target Employee &lt;employee@company.com&gt;</b></span>
          <span>Reply-To: <span class="mono" id="prevReplyTo">{def_reply_to}</span></span>
        </div>
      </div>
    </div>

    <!-- Email Rendered Frame Container -->
    <div class="ls-frame-container">
      <div class="ls-frame-card">
        <iframe class="ls-iframe" id="lsIframe" src="/admin/templates/preview?id={default_id}&mode=realistic"></iframe>
      </div>
    </div>
  </div>
</div>

<script>
const TPL_MAP = {json_blob};
let currentTplId = "{default_id}";
let currentMode = "realistic";
let filterCatVal = "";
let filterBrandVal = "";
let filterTechVal = "All";

function selectTemplate(tid) {{
  if(!TPL_MAP[tid]) return;
  currentTplId = tid;
  const d = TPL_MAP[tid];

  document.querySelectorAll('.ls-card').forEach(c => c.classList.remove('active'));
  const activeCard = document.getElementById('card-' + tid);
  if(activeCard) activeCard.classList.add('active');

  document.getElementById('btnUseCamp').href = '/admin/campaigns/new?template=' + encodeURIComponent(tid);
  document.getElementById('hdrUseBtn').href = '/admin/campaigns/new?template=' + encodeURIComponent(tid);
  document.getElementById('btnEditTpl').href = '/admin/templates?id=' + encodeURIComponent(tid);
  document.getElementById('btnTestSend').href = '/admin/templates/test-send?id=' + encodeURIComponent(tid);

  document.getElementById('prevFromName').innerText = d.from_name;
  document.getElementById('prevFromEmail').innerText = '<' + d.from_email + '>';
  document.getElementById('prevSubject').innerText = d.subject;
  document.getElementById('prevReplyTo').innerText = d.reply_to;
  document.getElementById('prevAvatar').innerText = (d.from_name || d.brand || 'P').charAt(0).toUpperCase();

  refreshIframe();
}}

function setPreviewMode(mode) {{
  currentMode = mode;
  document.getElementById('btnModeReal').classList.toggle('active', mode === 'realistic');
  document.getElementById('btnModeTech').classList.toggle('active', mode === 'indicators');
  refreshIframe();
}}

function refreshIframe() {{
  const ifr = document.getElementById('lsIframe');
  if(!ifr) return;
  const targetUrl = '/admin/templates/preview?id=' + encodeURIComponent(currentTplId) + '&mode=' + encodeURIComponent(currentMode);
  fetch(targetUrl)
    .then(r => {{
      if(!r.ok) throw new Error('HTTP ' + r.status);
      return r.text();
    }})
    .then(html => {{
      ifr.srcdoc = html;
    }})
    .catch(err => {{
      console.warn('Preview fallback to src', err);
      ifr.src = targetUrl;
    }});
}}

if(document.readyState === 'loading') {{
  document.addEventListener('DOMContentLoaded', refreshIframe);
}} else {{
  refreshIframe();
}}

function lsFilterCat(cat) {{
  filterCatVal = cat;
  document.querySelectorAll('#lsCatList .ls-nav-item').forEach(el => {{
    el.classList.toggle('active', el.getAttribute('data-cat') === cat);
  }});
  applyFilters();
}}

function lsFilterBrand(brand) {{
  filterBrandVal = brand;
  document.querySelectorAll('#lsBrandList .ls-nav-item').forEach(el => {{
    el.classList.toggle('active', el.getAttribute('data-brand') === brand);
  }});
  applyFilters();
}}

function lsFilterTech(tech) {{
  filterTechVal = tech;
  document.querySelectorAll('#lsTechBar .ls-tag-pill').forEach(el => {{
    el.classList.toggle('active', el.getAttribute('data-tech') === tech);
  }});
  applyFilters();
}}

function lsSearchFilter() {{
  applyFilters();
}}

function applyFilters() {{
  const q = document.getElementById('lsSearch').value.toLowerCase().trim();
  const cards = document.querySelectorAll('.ls-card');
  let firstVisible = null;
  cards.forEach(card => {{
    const id = card.getAttribute('data-id');
    const brand = (card.getAttribute('data-brand') || '').toLowerCase();
    const cat = (card.getAttribute('data-cat') || '').toLowerCase();
    const tags = (card.getAttribute('data-tags') || '').toLowerCase();
    const text = card.innerText.toLowerCase();

    let show = true;
    if(filterCatVal && cat !== filterCatVal.toLowerCase()) show = false;
    if(filterBrandVal && brand !== filterBrandVal.toLowerCase()) show = false;
    if(filterTechVal && filterTechVal !== 'All' && !tags.includes(filterTechVal.toLowerCase())) show = false;
    if(q && !text.includes(q)) show = false;

    card.style.display = show ? '' : 'none';
    if(show && !firstVisible) firstVisible = id;
  }});
}}
</script>'''
            return self.admin_shell("Email Templates",body,"Email Templates")
        if path=="/admin/landing-pages":
            rows=c.execute("SELECT * FROM landing_pages ORDER BY id").fetchall(); c.close()
            total_lp=len(rows)
            active_lp=sum(1 for r in rows if r["status"]=="Enabled")
            brand_map={"1":"Apex","2":"Trust Bank","3":"Microsoft 365","4":"Google Workspace","5":"HR Portal","6":"GlobalProtect","7":"bKash / Bank","8":"Zoom","9":"AWS","10":"Awareness Training"}
            table_rows=[]
            for r in rows:
                tpl_str=str(r["template"] or "")
                b_name=brand_map.get(tpl_str,"Enterprise Portal")
                test_link=f'/{tpl_str}.html' if tpl_str.isdigit() else f'/admin/landing-pages/preview?id={r["id"]}'
                table_rows.append(f'''<tr>
                  <td><b>#{r["id"]}</b></td>
                  <td>
                    <div style="display:flex;align-items:center;gap:8px">
                      <span style="font-weight:700;color:#12251e">{esc(r["name"])}</span>
                      <span class="pill" style="font-size:10.5px;padding:2px 7px;background:#f0f5f2;color:#355346;border:1px solid #d9e6e0">{b_name}</span>
                    </div>
                  </td>
                  <td><span class="pill" style="background:#eef5f8;color:#0369a1;font-weight:600">Template {esc(r["template"])}</span></td>
                  <td><span class="pill" style="background:#e8f4ef;color:#087b59">v{r["version"] or 1}</span></td>
                  <td><span class="camp-status-badge {'status-active' if r['status']=='Enabled' else 'status-draft'}">{esc(r['status'])}</span></td>
                  <td style="text-align:right">
                    <a class="btn" target="_blank" href="/admin/landing-pages/preview?id={r['id']}" style="display:inline-flex;align-items:center;gap:4px">👁️ Preview</a>
                    <a class="btn primary" href="/admin/landing-pages?id={r['id']}" style="display:inline-flex;align-items:center;gap:4px">✏️ Edit</a>
                    <a class="btn" target="_blank" href="{test_link}" title="Direct Simulation URL" style="font-size:11.5px">🔗 Test URL</a>
                  </td>
                </tr>''')
            table="".join(table_rows) or '<tr><td colspan="6">No landing pages found.</td></tr>'
            body=f'''<div class="lp-list-page">
<div class="camp-header">
  <div>
    <div class="camp-crumb"><a href="/admin">Dashboard</a> <span>/</span> <span>Landing Pages</span></div>
    <div class="camp-title-row">
      <h1>Simulation Landing Pages</h1>
      <span class="camp-status-badge status-active">{active_lp} Active</span>
    </div>
  </div>
  <div class="camp-actions">
    <a class="btn primary" href="/admin/landing-pages/new">+ Create Landing Page</a>
  </div>
</div>

<div class="stats">
  <div class="stat"><div class="stat-label">TOTAL PORTALS</div><div class="num">{total_lp}</div><div class="delta">Configured drill pages</div></div>
  <div class="stat"><div class="stat-label">ENABLED &amp; READY</div><div class="num">{active_lp}</div><div class="delta">Active for campaigns</div></div>
  <div class="stat"><div class="stat-label">MARKET PRESETS</div><div class="num">10 Included</div><div class="delta">Apex, Trust Bank, M365, Google...</div></div>
  <div class="stat"><div class="stat-label">SAFETY GUARD</div><div class="num" style="font-size:20px;color:#087b59;margin-top:14px">✓ Policy Active</div><div class="delta">Credentials blocked</div></div>
</div>

<div class="card" style="margin-bottom:20px;padding:16px 20px;background:#f8faf9;border:1px solid #dbe7e1;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px">
  <div style="display:flex;align-items:center;gap:10px">
    <span style="font-size:18px">🛡️</span>
    <span style="font-size:12.5px;color:#2b4539"><b>Simulation Safety Policy Active:</b> Password, OTP, PIN, and CVV/Card collection is strictly blocked by platform validation. All telemetry records safe engagement without credential theft.</span>
  </div>
  <a class="btn" href="/admin/landing-pages/new" style="background:#fff">Explore Preset Library ↗</a>
</div>

<div class="card">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:12px">
    <h3 style="margin:0;font-size:16px;color:#12251e">Configured Landing Pages</h3>
    <input id="qLp" oninput="filterLpTable()" placeholder="Filter by name, version or status..." style="padding:8px 12px;border:1.5px solid #cbdad2;border-radius:8px;font-size:12px;width:280px">
  </div>
  <div class="table-wrap">
    <table class="table" style="width:100%">
      <thead>
        <tr>
          <th style="width:70px">ID</th>
          <th>Portal Name &amp; Brand</th>
          <th style="width:120px">Template Lure</th>
          <th style="width:90px">Version</th>
          <th style="width:110px">Status</th>
          <th style="text-align:right;width:240px">Actions</th>
        </tr>
      </thead>
      <tbody id="lpRows">{table}</tbody>
    </table>
  </div>
</div>
<script>
function filterLpTable(){{const q=document.getElementById('qLp').value.toLowerCase();document.querySelectorAll('#lpRows tr').forEach(r=>r.style.display=r.innerText.toLowerCase().includes(q)?'':'none')}}
</script>'''
            return self.admin_shell("Landing Pages",body,"Landing Pages")
        if path=="/admin/smtp":
            rows=c.execute("SELECT id,name,provider,host,port,security,username,from_name,from_email,reply_to,enabled,updated_at FROM smtp_profiles ORDER BY id DESC").fetchall(); c.close()
            total_smtp=len(rows)
            active_smtp=sum(1 for r in rows if r["enabled"])
            table="".join('<tr><td><b>#%s</b></td><td><div style="font-weight:700;color:#10221a">%s</div><div class="sub" style="font-size:11px">%s</div></td><td><code>%s:%s</code></td><td><span class="pill" style="background:#eaf4ef;color:#087b59">%s</span></td><td>%s</td><td><span class="camp-status-badge %s">%s</span></td><td style="text-align:right"><a class="btn primary" href="/admin/smtp?id=%s">✏️ Edit</a> <a class="btn" href="/admin/smtp/diagnostics?id=%s">🩺 Diagnostics</a></td></tr>'%(r["id"],esc(r["name"]),esc(r["provider"]),esc(r["host"]),r["port"],esc(r["security"]),esc(r["from_email"]),"status-active" if r["enabled"] else "status-draft","Enabled" if r["enabled"] else "Disabled",r["id"],r["id"]) for r in rows) or '<tr><td colspan="7">No SMTP profiles configured.</td></tr>'
            note='<div class="card" style="margin-bottom:20px;padding:16px 20px;background:#f8faf9;border:1px solid #dbe7e1;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px"><div style="display:flex;align-items:center;gap:10px"><span style="font-size:18px">🛡️</span><span style="font-size:12.5px;color:#2b4539"><b>Zero-Exposure Credential Encryption:</b> SMTP passwords and OAuth tokens are AES-encrypted at rest using a server-local 0600 key file. Secrets are never displayed, exported, or committed to Git.</span></div></div>'
            body=f'''<div class="camp-header">
  <div>
    <div class="camp-crumb"><a href="/admin">Dashboard</a> <span>/</span> <span>SMTP Providers</span></div>
    <div class="camp-title-row">
      <h1>SMTP Mail Delivery Providers</h1>
      <span class="camp-status-badge status-active">{active_smtp} Enabled</span>
    </div>
  </div>
  <div class="camp-actions">
    <a class="btn primary" href="/admin/smtp/new">+ Add SMTP Provider</a>
  </div>
</div>

<div class="stats">
  <div class="stat"><div class="stat-label">CONFIGURED PROFILES</div><div class="num">{total_smtp}</div><div class="delta">Mail relay servers</div></div>
  <div class="stat"><div class="stat-label">ACTIVE &amp; READY</div><div class="num">{active_smtp}</div><div class="delta">Available for drills</div></div>
  <div class="stat"><div class="stat-label">AUTHENTICATION</div><div class="num" style="font-size:20px;color:#087b59;margin-top:14px">OAuth 2.0 &amp; Password</div><div class="delta">XOAUTH2 supported</div></div>
  <div class="stat"><div class="stat-label">ENCRYPTION</div><div class="num" style="font-size:20px;color:#087b59;margin-top:14px">AES-256 Rest</div><div class="delta">Local keystore (0600)</div></div>
</div>

{note}

<div class="card">
  <h3 style="margin-bottom:14px">Configured Relay Profiles</h3>
  <div class="table-wrap">
    <table class="table" style="width:100%">
      <thead><tr><th>ID</th><th>Profile &amp; Provider</th><th>Host : Port</th><th>Security</th><th>From Address</th><th>Status</th><th style="text-align:right">Actions</th></tr></thead>
      <tbody>{table}</tbody>
    </table>
  </div>
</div>'''
            return self.admin_shell("SMTP Providers",body,"SMTP Providers")
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
            course_rows="".join('<tr><td><b>#%s</b></td><td><b>%s</b></td><td>%s min</td><td>%s%%</td><td><span class="camp-status-badge status-active">%s</span></td></tr>'%(x["id"],esc(x["name"]),x["duration_minutes"],x["passing_score"],esc(x["status"])) for x in courses) or '<tr><td colspan="5">No training courses.</td></tr>'
            assignment_rows="".join('<tr><td>%s</td><td><b>%s</b></td><td>%s</td><td>%s</td><td><b>%.0f%%</b></td><td><span class="pill %s">%s</span></td><td><span class="pill %s">%s</span></td><td>%s</td><td>%s</td><td><form method="post" action="/admin/training/update" style="display:flex;gap:4px"><input type="hidden" name="id" value="%s"><input name="completion" type="number" min="0" max="100" step="1" value="%s" style="width:65px;padding:6px;border:1.5px solid #ccdcd5;border-radius:6px"><input name="score" type="number" min="0" max="100" step="1" value="%s" placeholder="score" style="width:65px;padding:6px;border:1.5px solid #ccdcd5;border-radius:6px"><button class="btn primary" style="padding:6px 10px">Update</button></form></td></tr>'%(esc(x["email"]),esc(x["name"]),esc(x["department"]),esc(x["course"]),x["completion"] or 0,"click" if x["status"]=="Completed" else "submitted",esc(x["status"]),"click" if x["result"]=="Passed" else ("submitted" if x["result"]=="Failed" else "report"),esc(x["result"] or "Pending"),esc(x["trigger_name"] or "—"),esc(x["remediation_name"] or "—"),x["id"],x["completion"] or 0,"" if x["score"] is None else x["score"]) for x in assigned) or '<tr><td colspan="10">No assignments yet.</td></tr>'
            c.close()
            body=f'''<div class="camp-header">
  <div>
    <div class="camp-crumb"><a href="/admin">Dashboard</a> <span>/</span> <span>Training</span></div>
    <div class="camp-title-row">
      <h1>Security Awareness Training</h1>
      <span class="camp-status-badge status-active">{total} Assignments</span>
    </div>
  </div>
  <div class="camp-actions">
    <a class="btn primary" href="/admin/training/new">+ Create Assignment</a>
    <a class="btn" href="/admin/training/course/new">+ New Course</a>
  </div>
</div>

<div class="stats">
  <div class="stat"><div class="stat-label">ASSIGNMENTS</div><div class="num">{total}</div><div class="delta">Enrolled users</div></div>
  <div class="stat"><div class="stat-label">PASSED</div><div class="num">{passed}</div><div class="delta">Successful completion</div></div>
  <div class="stat"><div class="stat-label">FAILED</div><div class="num">{failed}</div><div class="delta">Needs retake</div></div>
  <div class="stat"><div class="stat-label">OVERDUE</div><div class="num">{overdue}</div><div class="delta">Past deadline</div></div>
</div>

<div class="card">
  <h3 style="margin-bottom:14px">Course Catalog</h3>
  <div class="table-wrap">
    <table class="table" style="width:100%">
      <thead><tr><th>ID</th><th>Course</th><th>Duration</th><th>Pass Score</th><th>Status</th></tr></thead>
      <tbody>{course_rows}</tbody>
    </table>
  </div>
</div>

<div class="card" style="margin-top:20px">
  <h3 style="margin-bottom:14px">Assignments &amp; Results</h3>
  <div class="table-wrap">
    <table class="table" style="width:100%">
      <thead><tr><th>Email</th><th>Name</th><th>Department</th><th>Course</th><th>Completion</th><th>Status</th><th>Result</th><th>Trigger Drill</th><th>Remediation Drill</th><th>Quick Update</th></tr></thead>
      <tbody>{assignment_rows}</tbody>
    </table>
  </div>
</div>'''
            return self.admin_shell("Training",body,"Training")
        if path=="/admin/recipients":
            rows=c.execute("SELECT id,email,name,employee_id,department,designation,location,manager,language,timezone,group_name,status,created_at FROM recipients ORDER BY id DESC LIMIT 1000").fetchall()
            total=c.execute("SELECT COUNT(*) n FROM recipients").fetchone()["n"]
            suppressed=c.execute("SELECT COUNT(*) n FROM recipients WHERE status='Suppressed'").fetchone()["n"]
            active_rec=total - suppressed
            imports=c.execute("SELECT id,source_name,processed,created,updated,skipped,errors,created_at FROM recipient_import_history ORDER BY id DESC LIMIT 20").fetchall()
            c.close()
            table="".join('<tr><td><b>#%s</b></td><td><b>%s</b></td><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td><span class="camp-status-badge %s">%s</span></td><td style="text-align:right;white-space:nowrap"><a class="btn" style="padding:4px 9px;font-size:11.5px;margin-right:4px" href="/admin/recipients?id=%s">✏️ Edit</a><form method="post" action="/admin/recipients/delete" style="display:inline" onsubmit="return confirm(\'Delete recipient #%s (%s)?\');"><input type="hidden" name="id" value="%s"><button class="btn" style="color:#b91c1c;border-color:#fca5a5;background:#fef2f2;padding:4px 8px;font-size:11px" type="submit" title="Delete Recipient">🗑️</button></form></td></tr>'%(r["id"],esc(r["email"]),esc(r["name"]),esc(r["employee_id"]),esc(r["department"]),esc(r["designation"]),esc(r["location"]),"status-draft" if r["status"]=="Suppressed" else "status-active",esc(r["status"]),r["id"],r["id"],esc(r["email"]),r["id"]) for r in rows) or '<tr><td colspan="9">No recipients in directory yet. <a href="/admin/recipients?id=new">Add single recipient</a> or <a href="/admin/recipients/import">import CSV</a>.</td></tr>'
            ih="".join('<tr><td><b>#%s</b></td><td>%s</td><td><b>%s</b></td><td>%s</td><td>%s</td><td>%s</td><td><span style="color:#a12d2d">%s</span></td><td>%s</td></tr>'%(r["id"],esc(r["source_name"] or "Manual/CSV"),r["processed"],r["created"],r["updated"],r["skipped"],esc(r["errors"] or ""),esc(r["created_at"])) for r in imports) or '<tr><td colspan="8">No import history.</td></tr>'
            body=f'''<div class="camp-header">
  <div>
    <div class="camp-crumb"><a href="/admin">Dashboard</a> <span>/</span> <span>Recipients</span></div>
    <div class="camp-title-row">
      <h1>Employee Target Directory</h1>
      <span class="camp-status-badge status-active">{active_rec} Active</span>
    </div>
  </div>
  <div class="camp-actions" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
    <a class="btn primary" href="/admin/recipients?id=new" style="display:inline-flex;align-items:center;gap:6px">➕ Add Recipient</a>
    <button class="btn" type="button" onclick="openQuickAddModal()" style="display:inline-flex;align-items:center;gap:6px">⚡ Quick Add</button>
    <a class="btn" href="/admin/recipients/import" style="display:inline-flex;align-items:center;gap:6px">📥 Import CSV</a>
  </div>
</div>

<div class="stats">
  <div class="stat"><div class="stat-label">TOTAL RECIPIENTS</div><div class="num">{total}</div><div class="delta">Imported employee profiles</div></div>
  <div class="stat"><div class="stat-label">ACTIVE TARGETS</div><div class="num">{active_rec}</div><div class="delta">Eligible for simulations</div></div>
  <div class="stat"><div class="stat-label">SUPPRESSED</div><div class="num">{suppressed}</div><div class="delta">Excluded from delivery</div></div>
  <div class="stat"><div class="stat-label">COMPLIANCE POLICY</div><div class="num" style="font-size:20px;color:#087b59;margin-top:14px">✓ Zero-Secret Policy</div><div class="delta">No credential storage</div></div>
</div>

<div class="card">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:12px">
    <div style="display:flex;align-items:center;gap:10px">
      <h3 style="margin:0">Active Recipients</h3>
      <span style="font-size:12px;color:#59776b">({active_rec} targets)</span>
    </div>
    <div style="display:flex;gap:10px;align-items:center">
      <input id="qRec" oninput="filterRecTable()" placeholder="Filter by email, name, dept, id..." style="padding:8px 12px;border:1.5px solid #cbdad2;border-radius:8px;font-size:12px;width:280px">
      <a class="btn" href="/admin/recipients?id=new" style="font-size:12px;padding:7px 11px">+ Add Single</a>
    </div>
  </div>
  <div class="table-wrap">
    <table class="table" style="width:100%">
      <thead><tr><th>ID</th><th>Email</th><th>Name</th><th>Employee ID</th><th>Department</th><th>Designation</th><th>Location</th><th>Status</th><th style="text-align:right">Actions</th></tr></thead>
      <tbody id="recRows">{table}</tbody>
    </table>
  </div>
</div>

<div class="card" style="margin-top:20px">
  <h3 style="margin-bottom:14px">Import History</h3>
  <div class="table-wrap">
    <table class="table" style="width:100%">
      <thead><tr><th>ID</th><th>Source</th><th>Processed</th><th>Created</th><th>Updated</th><th>Skipped</th><th>Errors</th><th>Timestamp</th></tr></thead>
      <tbody>{ih}</tbody>
    </table>
  </div>
</div>

<!-- Quick Add Modal -->
<div id="quickAddModal" style="display:none;position:fixed;inset:0;background:rgba(8,30,22,0.5);backdrop-filter:blur(3px);z-index:9999;align-items:center;justify-content:center;padding:16px">
  <div style="background:#ffffff;border-radius:12px;max-width:520px;width:100%;box-shadow:0 12px 40px rgba(0,0,0,0.2);border:1px solid #d3e4dc;overflow:hidden">
    <div style="padding:15px 20px;background:#f3f8f5;border-bottom:1px solid #deebe3;display:flex;justify-content:space-between;align-items:center">
      <div style="display:flex;align-items:center;gap:8px">
        <span style="font-size:17px">⚡</span>
        <h3 style="margin:0;font-size:15px;color:#102b20">Quick Add Target Employee</h3>
      </div>
      <button type="button" onclick="closeQuickAddModal()" style="border:none;background:none;font-size:22px;cursor:pointer;color:#658274;line-height:1">&times;</button>
    </div>
    <form method="post" action="/admin/recipients/save" style="padding:18px 20px">
      <input type="hidden" name="id" value="">
      <div style="display:flex;flex-direction:column;gap:12px">
        <label style="display:flex;flex-direction:column;gap:5px;font-size:12px;font-weight:700;color:#1a3528">
          <span>Email Address <span style="color:#dc2626">*</span></span>
          <input type="email" name="email" required placeholder="target.user@company.com" style="padding:8px 12px;border:1.5px solid #cbdad2;border-radius:7px;font-size:13px">
        </label>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
          <label style="display:flex;flex-direction:column;gap:5px;font-size:12px;font-weight:700;color:#1a3528">
            Full Name
            <input name="name" placeholder="Target User" style="padding:8px 12px;border:1.5px solid #cbdad2;border-radius:7px;font-size:13px">
          </label>
          <label style="display:flex;flex-direction:column;gap:5px;font-size:12px;font-weight:700;color:#1a3528">
            Employee ID
            <input name="employee_id" placeholder="EMP-1001" style="padding:8px 12px;border:1.5px solid #cbdad2;border-radius:7px;font-size:13px">
          </label>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
          <label style="display:flex;flex-direction:column;gap:5px;font-size:12px;font-weight:700;color:#1a3528">
            Department
            <input name="department" placeholder="Finance / IT / HR" style="padding:8px 12px;border:1.5px solid #cbdad2;border-radius:7px;font-size:13px">
          </label>
          <label style="display:flex;flex-direction:column;gap:5px;font-size:12px;font-weight:700;color:#1a3528">
            Designation
            <input name="designation" placeholder="Officer / Analyst" style="padding:8px 12px;border:1.5px solid #cbdad2;border-radius:7px;font-size:13px">
          </label>
        </div>
        <div style="font-size:11px;color:#678275;background:#f5faf7;padding:8px 10px;border-radius:6px;border:1px solid #e1eee7">
          ✓ Target will be saved with default Active status and eligible for assigned simulation drills.
        </div>
      </div>
      <div style="margin-top:16px;padding-top:12px;border-top:1px solid #e7eee9;display:flex;justify-content:space-between;align-items:center">
        <a href="/admin/recipients?id=new" style="font-size:12px;color:#087b59;font-weight:700;text-decoration:none">Open full form →</a>
        <div style="display:flex;gap:8px">
          <button type="button" class="btn" onclick="closeQuickAddModal()">Cancel</button>
          <button type="submit" class="btn primary">Save Target</button>
        </div>
      </div>
    </form>
  </div>
</div>

<script>
function filterRecTable(){{const q=document.getElementById('qRec').value.toLowerCase();document.querySelectorAll('#recRows tr').forEach(r=>r.style.display=r.innerText.toLowerCase().includes(q)?'':'none')}}
function openQuickAddModal(){{document.getElementById('quickAddModal').style.display='flex'}}
function closeQuickAddModal(){{document.getElementById('quickAddModal').style.display='none'}}
</script>'''
            return self.admin_shell("Recipients",body,"Recipients")
        if path=="/admin/groups":
            rows=c.execute("SELECT g.id,g.name,g.department,COUNT(r.id) members FROM groups_tbl g LEFT JOIN recipients r ON r.group_name=g.name GROUP BY g.id ORDER BY g.id DESC").fetchall(); c.close()
            total_g=len(rows)
            total_members=sum(r["members"] or 0 for r in rows)
            table="".join('<tr><td><b>#%s</b></td><td><b>%s</b></td><td>%s</td><td><span class="pill" style="background:#eaf4ef;color:#087b59">%s Members</span></td></tr>'%(r["id"],esc(r["name"]),esc(r["department"]),r["members"]) for r in rows) or '<tr><td colspan="4">No groups yet.</td></tr>'
            body=f'''<div class="camp-header">
  <div>
    <div class="camp-crumb"><a href="/admin">Dashboard</a> <span>/</span> <span>Groups</span></div>
    <div class="camp-title-row">
      <h1>Groups &amp; Departments</h1>
      <span class="camp-status-badge status-active">{total_g} Groups</span>
    </div>
  </div>
  <div class="camp-actions">
    <a class="btn primary" href="/admin/groups/new">+ New Group</a>
  </div>
</div>

<div class="stats">
  <div class="stat"><div class="stat-label">RECIPIENT GROUPS</div><div class="num">{total_g}</div><div class="delta">Targeting groups</div></div>
  <div class="stat"><div class="stat-label">ASSIGNED MEMBERS</div><div class="num">{total_members}</div><div class="delta">Total group assignments</div></div>
</div>

<div class="card">
  <h3 style="margin-bottom:14px">Configured Target Groups</h3>
  <div class="table-wrap">
    <table class="table" style="width:100%">
      <thead><tr><th>ID</th><th>Group Name</th><th>Department</th><th>Members</th></tr></thead>
      <tbody>{table}</tbody>
    </table>
  </div>
</div>'''
            return self.admin_shell("Groups",body,"Groups & Departments")
        if path=="/admin/users":
            rows=c.execute("SELECT email,MAX(name) name,MAX(employee_id) employee_id,COUNT(*) events,SUM(event='click') clicks,SUM(event='submitted') submissions FROM events WHERE email!='' GROUP BY email ORDER BY events DESC").fetchall(); c.close()
            total_u=len(rows)
            total_clicks=sum(r["clicks"] or 0 for r in rows)
            total_subs=sum(r["submissions"] or 0 for r in rows)
            table="".join('<tr><td><b>%s</b></td><td>%s</td><td><code>%s</code></td><td><b>%s</b></td><td><span class="pill click">%s</span></td><td><span class="pill submitted">%s</span></td></tr>'%(esc(r["email"]),esc(r["name"]),esc(r["employee_id"]),r["events"],r["clicks"] or 0,r["submissions"] or 0) for r in rows) or '<tr><td colspan="6">No users recorded yet.</td></tr>'
            body=f'''<div class="camp-header">
  <div>
    <div class="camp-crumb"><a href="/admin">Dashboard</a> <span>/</span> <span>Users</span></div>
    <div class="camp-title-row">
      <h1>Observed Users &amp; Engagement</h1>
      <span class="camp-status-badge status-active">{total_u} Monitored</span>
    </div>
  </div>
</div>

<div class="stats">
  <div class="stat"><div class="stat-label">MONITORED USERS</div><div class="num">{total_u}</div><div class="delta">With recorded telemetry</div></div>
  <div class="stat"><div class="stat-label">TOTAL CLICKS</div><div class="num">{total_clicks}</div><div class="delta">Link visit events</div></div>
  <div class="stat"><div class="stat-label">FORM SUBMISSIONS</div><div class="num">{total_subs}</div><div class="delta">Action drill failures</div></div>
</div>

<div class="card">
  <h3 style="margin-bottom:14px">User Engagement Telemetry</h3>
  <div class="table-wrap">
    <table class="table" style="width:100%">
      <thead><tr><th>Email</th><th>Name</th><th>Employee ID</th><th>Events</th><th>Clicks</th><th>Submissions</th></tr></thead>
      <tbody>{table}</tbody>
    </table>
  </div>
</div>'''
            return self.admin_shell("Users",body,"Users & Groups")
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
            total_r=len(rows)
            high_r=sum(1 for r in rows if r["level"] in ("High","Critical"))
            repeats=sum(1 for r in rows if r["repeat_offender"])
            table="".join('<tr><td><b>%s</b></td><td><b>%s</b></td><td><b>%.0f</b></td><td><span class="pill %s">%s</span></td><td>%s</td><td>%s</td><td><div class="sub" style="font-size:11px">%s</div></td></tr>'%(esc(r["email"]),r["failures"],r["score"],"submitted" if r["level"] in ("High","Critical") else ("click" if r["level"]=="Low" else "report"),esc(r["level"]),'<span class="pill submitted">Repeat</span>' if r["repeat_offender"] else "No",esc(r["remediation_status"] or "None"),esc(r["factor_summary"] or "")) for r in rows) or '<tr><td colspan="7">No risk data yet.</td></tr>'
            dept="".join('<tr><td><b>%s</b></td><td>%s</td><td><b>%.1f</b></td><td>%s</td></tr>'%(esc(r["department"]),r["members"],r["score"],r["failures"]) for r in departments) or '<tr><td colspan="4">No department risk data.</td></tr>'
            camp="".join('<tr><td><b>#%s</b></td><td>%s</td><td>%s</td><td>%.1f%%</td><td>%.1f%%</td><td>%s</td></tr>'%(r["id"],esc(r["name"]),r["sent"],(r["clicks"] or 0)/max(r["sent"],1)*100,(r["actions"] or 0)/max(r["sent"],1)*100,r["reports"] or 0) for r in campaigns) or '<tr><td colspan="6">No campaign risk data.</td></tr>'
            hist="".join('<tr><td><b>%s</b></td><td>%s</td><td>%.0f</td><td><span class="pill %s">%s</span></td><td>%s</td></tr>'%(esc(r["subject"]),esc(r["recorded_at"]),r["score"],"submitted" if r["level"] in ("High","Critical") else "click",esc(r["level"]),esc(r["factors"] or "")) for r in history) or '<tr><td colspan="5">No risk history yet.</td></tr>'
            body=f'''<div class="camp-header">
  <div>
    <div class="camp-crumb"><a href="/admin">Dashboard</a> <span>/</span> <span>Risk</span></div>
    <div class="camp-title-row">
      <h1>Risk &amp; Trends Analytics</h1>
      <span class="camp-status-badge status-active">{total_r} Scored</span>
    </div>
  </div>
</div>

<div class="stats">
  <div class="stat"><div class="stat-label">SCORED PROFILES</div><div class="num">{total_r}</div><div class="delta">Telemetry-based scores</div></div>
  <div class="stat"><div class="stat-label">ELEVATED RISK</div><div class="num" style="color:#b91c1c">{high_r}</div><div class="delta">High / Critical risk</div></div>
  <div class="stat"><div class="stat-label">REPEAT OFFENDERS</div><div class="num" style="color:#b45309">{repeats}</div><div class="delta">Multiple drill failures</div></div>
  <div class="stat"><div class="stat-label">MODEL AUDIT</div><div class="num" style="font-size:20px;color:#087b59;margin-top:14px">Explainable AI</div><div class="delta">Zero synthetic bias</div></div>
</div>

<div class="card">
  <h3 style="margin-bottom:14px">User Risk Leaderboard</h3>
  <div class="table-wrap">
    <table class="table" style="width:100%">
      <thead><tr><th>User Email</th><th>Failures</th><th>Score</th><th>Risk Level</th><th>Repeat Offender</th><th>Remediation Status</th><th>Risk Factor Breakdown</th></tr></thead>
      <tbody>{table}</tbody>
    </table>
  </div>
</div>

<div class="grid">
  <div class="card">
    <h3 style="margin-bottom:14px">Department Risk Summary</h3>
    <div class="table-wrap">
      <table class="table"><thead><tr><th>Department</th><th>Members</th><th>Avg Score</th><th>Failures</th></tr></thead><tbody>{dept}</tbody></table>
    </div>
  </div>
  <div class="card">
    <h3 style="margin-bottom:14px">Campaign Drill Outcomes</h3>
    <div class="table-wrap">
      <table class="table"><thead><tr><th>ID</th><th>Campaign</th><th>Sent</th><th>Click Rate</th><th>Action Rate</th><th>Reports</th></tr></thead><tbody>{camp}</tbody></table>
    </div>
  </div>
</div>

<div class="card" style="margin-top:20px">
  <h3 style="margin-bottom:14px">Historical Risk Snapshots</h3>
  <div class="table-wrap">
    <table class="table" style="width:100%">
      <thead><tr><th>Subject</th><th>Recorded At</th><th>Score</th><th>Risk Level</th><th>Factors</th></tr></thead>
      <tbody>{hist}</tbody>
    </table>
  </div>
</div>'''
            return self.admin_shell("Risk",body,"Risk & Trends")
        if path=="/admin/audit":
            rows=c.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200").fetchall(); c.close()
            table="".join('<tr><td><b>%s</b></td><td><code>%s</code></td><td><span class="pill click">%s</span></td><td>%s</td></tr>'%(esc(format_datetime(r["ts"])[0]),esc(format_datetime(r["ts"])[1]),esc(r["action"]),esc(r["details"])) for r in rows) or '<tr><td colspan="4">No audit records.</td></tr>'
            body=f'''<div class="camp-header">
  <div>
    <div class="camp-crumb"><a href="/admin">Dashboard</a> <span>/</span> <span>Audit Log</span></div>
    <div class="camp-title-row">
      <h1>Administrative Audit Trail</h1>
      <span class="camp-status-badge status-active">Immutable Log</span>
    </div>
  </div>
</div>
<div class="card">
  <h3 style="margin-bottom:14px">Recent Audit Events</h3>
  <div class="table-wrap">
    <table class="table" style="width:100%">
      <thead><tr><th>Date</th><th>Time</th><th>Action</th><th>Details &amp; Parameters</th></tr></thead>
      <tbody>{table}</tbody>
    </table>
  </div>
</div>'''
            return self.admin_shell("Audit",body,"Audit Log")
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
            if tab=="permissions":
                c=db()
                permission_rows=c.execute("SELECT resource,action,label,description,risk_level,active FROM rbac_permissions ORDER BY resource,action").fetchall()
                c.close()
                resources=sorted({r["resource"] for r in permission_rows})
                resource_opts=''.join('<option value="%s">%s</option>'%(esc(x),esc(x.replace("_"," ").title())) for x in resources)
                permission_cards="".join('<tr data-search="%s"><td><code>%s.%s</code></td><td><b>%s</b><div class="sub">%s</div></td><td>%s</td><td>%s</td></tr>'%(esc((" ".join([r["resource"],r["action"],r["label"],r["description"] or ""])).lower()),esc(r["resource"]),esc(r["action"]),esc(r["label"]),esc(r["description"] or ""),esc(r["risk_level"]),("Active" if r["active"] else "Disabled")) for r in permission_rows) or '<tr><td colspan="4">No permission definitions found.</td></tr>'
                actions=sorted({r["action"] for r in permission_rows})
                permission_map={(r["resource"],r["action"]):r for r in permission_rows}
                matrix_head="".join("<th>%s</th>"%esc(x.replace("_"," ").title()) for x in actions)
                matrix_rows="".join('<tr data-resource="%s">'%(esc(resource))+"".join(('<td class="permission-cell" data-search="%s" title="%s">✓</td>'%(esc((" ".join([r["resource"],r["action"],r["label"],r["description"] or ""])).lower()),esc(r["label"]))) if (r:=permission_map.get((resource,action))) else '<td class="permission-cell empty">—</td>' for action in actions)+"</tr>" for resource in resources)
                body='<h1>Permission Catalog</h1><p>Search and filter the seeded permission definitions used by the future granular RBAC model.</p><div style="display:flex;gap:8px;margin:15px 0;flex-wrap:wrap"><a class="btn" href="/admin/admins">Administrators</a><a class="btn" href="/admin/admins?tab=roles">Roles</a><a class="btn primary" href="/admin/admins?tab=permissions">Permissions</a></div><div class="card"><div style="display:grid;grid-template-columns:minmax(240px,1fr) 180px;gap:10px"><label>Search permissions<input id="permissionSearch" type="search" placeholder="resource.action, label or description" autocomplete="off"></label><label>Resource<select id="permissionResource"><option value="">All resources</option>%s</select></label></div><p class="sub" id="permissionCount" style="margin-top:10px"></p></div><div class="card" style="margin-top:15px"><h3>Permission Matrix</h3><p class="sub">Read-only catalog view. Role-permission assignment will be introduced in the RBAC enforcement phase.</p><div class="table-wrap"><table class="table permission-matrix" style="min-width:980px"><thead><tr><th>Resource</th>%s</tr></thead><tbody id="permissionMatrix">%s</tbody></table></div></div><div class="card" style="margin-top:15px"><h3>Permission Definitions</h3><div class="table-wrap"><table class="table" style="min-width:760px"><thead><tr><th>Permission</th><th>Definition</th><th>Risk</th><th>Status</th></tr></thead><tbody id="permissionRows">%s</tbody></table></div></div><script>(function(){const input=document.getElementById("permissionSearch"),resource=document.getElementById("permissionResource"),rows=[...document.querySelectorAll("#permissionRows tr")],matrixRows=[...document.querySelectorAll("#permissionMatrix tr")],count=document.getElementById("permissionCount");function apply(){const q=(input.value||"").trim().toLowerCase(),r=resource.value;let visible=0;rows.forEach(function(row){const ok=(!q||(row.dataset.search||"").includes(q))&&(!r||row.querySelector("td code")?.textContent.startsWith(r+"."));row.style.display=ok?"":"none";if(ok)visible++;});matrixRows.forEach(function(row){const resourceOk=!r||row.dataset.resource===r;let cellVisible=0;row.querySelectorAll(".permission-cell").forEach(function(cell){const ok=resourceOk&&!cell.classList.contains("empty")&&(!q||(cell.dataset.search||"").includes(q));cell.style.display=ok?"":"none";if(ok)cellVisible++;});row.style.display=resourceOk&&(cellVisible||!q)?"":"none";});count.textContent=visible+" permission definition"+(visible===1?"":"s")+" shown";}input.addEventListener("input",apply);resource.addEventListener("change",apply);apply();})();</script>'%(resource_opts,matrix_head,matrix_rows,permission_cards)
                return self.admin_shell("Permission Catalog",body,"Admin Users")
            if tab=="roles":
                built_in_roles=[
                    ("Administrator","Full administrative control","Protected built-in role"),
                    ("Campaign Manager","Campaigns, templates, landing pages, recipients, groups and training","Built-in role"),
                    ("Reporting Analyst","Reports, risk analytics and exports","Built-in role"),
                    ("SMTP Manager","SMTP provider profiles, diagnostics and delivery settings","Built-in role"),
                    ("Security Auditor","Audit log and security activity review","Built-in role")
                ]
                c=db()
                admin_counts={r["role"]:r["n"] for r in c.execute("SELECT role,COUNT(*) AS n FROM admins GROUP BY role").fetchall()}
                role_cards="".join('<div class="card"><div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start"><div><h3>%s</h3><p class="sub">%s</p></div><span class="sub">Administrators: %s · %s</span></div></div>'%(esc(name),esc(desc),admin_counts.get(name,0),esc(kind)) for name,desc,kind in built_in_roles)
                custom_roles=c.execute("SELECT r.id,r.name,r.description,r.active,r.created_at,COUNT(a.id) AS admin_count FROM rbac_roles r LEFT JOIN admins a ON a.role=r.name WHERE r.built_in=0 GROUP BY r.id,r.name,r.description,r.active,r.created_at ORDER BY r.name").fetchall()
                permission_rows=c.execute("SELECT id,resource,action,label,risk_level FROM rbac_permissions WHERE active=1 ORDER BY resource,action").fetchall()
                assigned_rows=c.execute("SELECT role_id,permission_id FROM rbac_role_permissions").fetchall()
                assigned_by_role={}
                for ar in assigned_rows:
                    assigned_by_role.setdefault(ar["role_id"],set()).add(ar["permission_id"])
                c.close()
                scope_rows=c.execute("SELECT role_id,permission_id,scope_kind,scope_value FROM rbac_resource_scopes WHERE active=1 ORDER BY role_id,permission_id,scope_kind,scope_value").fetchall()
                scopes_by_role={}
                for sr in scope_rows:
                    scopes_by_role.setdefault((sr["role_id"],sr["permission_id"]),[]).append("%s=%s"%(sr["scope_kind"],sr["scope_value"]))
                c.close()
                permission_controls={}
                scope_kinds=("campaign","campaign_group","campaign_type","department","organizational_unit")
                for role in custom_roles:
                    checked=assigned_by_role.get(role["id"],set())
                    def permission_control(p):
                        existing_scopes="\n".join(scopes_by_role.get((role["id"],p["id"]),[]))
                        return '<div style="margin:4px 0 8px"><label style="display:flex;gap:8px;align-items:center;font-size:12px"><input type="checkbox" name="permission_ids" value="%s"%s> %s <span class="sub">(%s · %s)</span></label><label style="display:block;margin-left:24px;font-size:11px;color:#71817b">Optional scopes (one per line: kind=value)<textarea name="scope_assignments_%s" rows="2" maxlength="2000" placeholder="campaign=123&#10;department=Finance" style="width:100%%;margin-top:4px;padding:7px;border:1px solid #ccd9d4;border-radius:7px;font-size:11px">%s</textarea></label></div>'%(p["id"]," checked" if p["id"] in checked else "",esc(p["label"]),esc(p["resource"]+"."+p["action"]),esc(p["risk_level"]),p["id"],esc(existing_scopes))
                    controls="".join(permission_control(p) for p in permission_rows)
                    permission_controls[role["id"]]=controls or '<p class="sub">No active permissions are available.</p>'
                custom_cards="".join('<div class="card"><form class="form" method="post" action="/admin/roles/save"><input type="hidden" name="id" value="%s"><div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start"><div><h3>Custom Role</h3><span class="sub">%s</span></div><span class="sub">Administrators: %s · %s</span></div><label>Role name<input name="name" maxlength="80" value="%s" required></label><label>Description<textarea name="description" maxlength="500" rows="3">%s</textarea></label><div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn primary" type="submit">Save Changes</button><button class="btn" type="submit" formaction="/admin/roles/duplicate">Duplicate</button><button class="btn" type="submit" formaction="/admin/roles/delete" formmethod="post" onclick="return confirm(&quot;Delete this custom role? This cannot be undone.&quot;)">Delete</button></div></form><div style="margin-top:14px;padding-top:12px;border-top:1px solid #e2ebe7"><h4>Permissions</h4><p class="sub">Persist the permissions assigned to this custom role. Authorization enforcement is a separate Phase D task.</p><form class="form" method="post" action="/admin/roles/permissions"><input type="hidden" name="role_id" value="%s"><div style="max-height:360px;overflow:auto;padding:8px 4px">%s</div><label style="display:flex;gap:8px;align-items:flex-start;font-size:12px;margin-top:10px"><input type="checkbox" name="confirm_privileged" value="1"> I understand that selecting any <b>privileged</b> permission grants elevated administrative capability and I explicitly approve this assignment.</label><button class="btn primary" type="submit">Save Permissions</button></form></div></div>'%(r["id"],esc(r["name"]),r["admin_count"],("Active" if r["active"] else "Disabled"),esc(r["name"]),esc(r["description"] or ""),r["id"],permission_controls.get(r["id"],"")) for r in custom_roles) or '<div class="card"><p class="sub">No custom roles created yet.</p></div>'
                body='<h1>Admin Users & Roles</h1><p>Manage administrator accounts, roles and access policies.</p><div style="display:flex;gap:8px;margin:15px 0"><a class="btn" href="/admin/admins">Administrators</a><a class="btn primary" href="/admin/admins?tab=roles">Roles</a></div><div class="card"><h3>Create Custom Role</h3><p class="sub">Create a named custom role for granular permission assignment.</p><form class="form" method="post" action="/admin/roles/create"><label>Role name<input name="name" maxlength="80" placeholder="e.g. Training Coordinator" required></label><label>Description<textarea name="description" maxlength="500" rows="3" placeholder="Describe the intended access scope"></textarea></label><button class="btn primary" type="submit">Create Custom Role</button></form></div><div class="card" style="margin-top:15px"><h3>Built-in Roles</h3><p class="sub">Protected roles currently supported by the administration model.</p></div><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:15px;margin-top:15px">%s</div><div class="card" style="margin-top:15px"><h3>Custom Roles</h3><p class="sub">Custom roles can now persist granular permission assignments. Enforcement remains a separate Phase D task.</p></div><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:15px;margin-top:15px">%s</div>'%(role_cards,custom_cards)
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
            preview=""
            if selected:
                access_preview=self.resolve_role_access_preview(selected["role"])
                review_db=db()
                latest_review=review_db.execute(
                    "SELECT reviewed_by,reviewed_at,permission_count,normal_count,elevated_count,privileged_count,target_role,target_active FROM access_reviews WHERE target_admin_id=? ORDER BY id DESC LIMIT 1",
                    (int(selected["id"]),)
                ).fetchone()
                review_db.close()
                status="Active" if selected["active"] else "Disabled"
                permission_rows="".join(
                    "<li><b>%s</b> <span class=\"sub\">(%s · %s)</span><br><span class=\"sub\">%s</span></li>"%
                    (esc(item["label"]),esc(item["key"]),esc(item["risk_level"]),esc(item["description"]))
                    for item in access_preview["permissions"]
                ) or "<li>No active permissions resolved.</li>"
                high_risk="".join(
                    "<li><b>%s</b> <span class=\"sub\">(%s)</span></li>"%
                    (esc(item["label"]),esc(item["risk_level"]))
                    for item in access_preview["high_risk_permissions"]
                ) or "<li>None</li>"
                scope_rows="".join(
                    '<li><b>%s</b> <span class="sub">(%s=%s)</span></li>'%
                    (esc(item["permission"]),esc(item["scope_kind"]),esc(item["scope_value"]))
                    for item in access_preview["scopes"]
                ) or "<li>No active resource scopes assigned.</li>"
                risk_counts=access_preview["risk_counts"]
                modules=", ".join(esc(module) for module in access_preview["modules"]) or "None"
                preview='<div class="card" style="margin-top:15px"><div style="display:flex;justify-content:space-between;align-items:flex-start;gap:15px"><div><h3>Access Preview</h3><p class="sub">%s · %s</p></div><a class="btn" href="/admin/admins">Close</a></div><div style="margin-top:12px;padding:14px;background:#f7faf8;border-radius:10px"><b>%s</b><div class="sub" style="margin-top:5px">Account ID %s · Status: %s</div><div class="sub" style="margin-top:8px">Modules: %s · Permissions: %s</div><div class="sub" style="margin-top:5px">Risk: %s normal · %s elevated · %s privileged</div><div style="margin-top:12px"><b>Permissions</b><ul style="margin:8px 0 0 18px;line-height:1.7;font-size:12px">%s</ul></div><div style="margin-top:12px"><b>Elevated / privileged</b><ul style="margin:8px 0 0 18px;line-height:1.7;font-size:12px">%s</ul></div><div style="margin-top:12px"><b>Resource scopes</b><ul style="margin:8px 0 0 18px;line-height:1.7;font-size:12px">%s</ul></div></div><p class="sub" style="margin-top:12px">Preview is derived from the same effective-permission resolver used by RBAC enforcement. No credentials, secrets, or mutable account state are exposed.</p><div style="margin-top:14px;padding-top:12px;border-top:1px solid #e2ebe7"><b>Access review</b><p class="sub">Record a non-secret review acknowledgment for this current access snapshot.</p><form method="post" action="/admin/admins/review" style="margin-top:8px"><input type="hidden" name="id" value="%s"><button class="btn primary" type="submit">Mark access reviewed</button></form>%s</div></div>'%(esc(selected["username"]),esc(selected["role"]),esc(selected["role"]),selected["id"],status,modules,access_preview["permission_count"],risk_counts["normal"],risk_counts["elevated"],risk_counts["privileged"],permission_rows,high_risk,scope_rows,selected["id"],(
                    '<p class="sub" style="margin-top:8px">Last reviewed by <b>%s</b> at %s · snapshot: %s permissions (%s normal / %s elevated / %s privileged).</p>'%
                    (esc(latest_review["reviewed_by"]),esc(latest_review["reviewed_at"]),latest_review["permission_count"],latest_review["normal_count"],latest_review["elevated_count"],latest_review["privileged_count"])
                    if latest_review else '<p class="sub" style="margin-top:8px">No access review recorded yet.</p>'
                ))
            elif selected_id:
                preview='<div class="card" style="margin-top:15px"><h3>Administrator not found</h3><p class="sub">The requested administrator account does not exist.</p></div>'
            body='<h1>Admin Users & Roles</h1><p>Manage administrator accounts and assign the existing least-privilege roles. Passwords are hashed and never displayed.</p><p><a class="btn primary" href="#add-admin">+ Add Administrator</a></p><div style="display:grid;grid-template-columns:minmax(0,1.55fr) minmax(300px,.85fr);gap:15px;align-items:start"><div class="card"><h3>Administrators</h3><p class="sub">Create, assign and disable administrative access.</p><div class="table-wrap"><table class="table" style="min-width:760px"><tr><th>ID</th><th>Administrator</th><th>Role / Status</th></tr>%s</table></div></div><div class="card" id="add-admin"><h3>Add Administrator</h3><p class="sub">Create an active administrator account using the existing RBAC role set.</p><form class="form" method="post" action="/admin/admins/create"><label>Email / Username<input type="email" name="username" autocomplete="username" maxlength="254" placeholder="admin@example.com" required></label><label>Temporary password<input type="password" name="password" autocomplete="new-password" minlength="12" maxlength="256" placeholder="Minimum 12 characters" required></label><label>Role<select name="role" required>%s</select></label><button class="btn primary" type="submit">Create Administrator</button></form><div style="margin-top:12px;padding:11px 12px;background:#edf8f4;border-radius:9px;font-size:11px;color:#2b6554;line-height:1.5">Password policy: 12–256 characters. Do not use line breaks. The password is stored only as a secure hash and is never shown in the administrator list or audit log.</div></div></div><div class="card" style="margin-top:15px"><h3>Current role access</h3><p><b>Administrator:</b> full control · <b>Campaign Manager:</b> campaigns, templates, landing pages, recipients, groups, training · <b>Reporting Analyst:</b> reports, risk, exports · <b>SMTP Manager:</b> SMTP profiles · <b>Security Auditor:</b> audit log.</p><p class="sub">Custom roles and granular permission assignment are planned for the next RBAC phase.</p></div>'%(table,role_opts("Campaign Manager"))+preview
            return self.admin_shell("Admin Users",body,"Admin Users")
        if path=="/admin/settings":
            cfg=risk_settings(c); c.close()
            cur_base_url = get_public_base_url(self.headers.get("Host"))
            body='''<h1>Settings</h1><div class="card"><h3>Public Simulation Base URL</h3><p>The public base URL used for email tracking links, landing pages, and QR codes sent to target users.</p><form class="form" method="post" action="/admin/settings/base-url"><label>Base URL (e.g., http://192.168.10.242:8899 or https://phish.example.com)<input type="text" name="public_base_url" value="%s" required maxlength="255"></label><button class="btn primary" type="submit">Save Base URL</button></form><p class="sub" style="margin-top:8px">Currently active: <code>%s</code></p></div><div class="card" style="margin-top:15px"><h3>System Environment</h3><p>Admin credentials are environment variables. Database: SQLite. Timezone: Asia/Dhaka.</p><p>Simulation policy: never request or store passwords, OTPs, PINs, CVV or full card numbers.</p></div><div class="card" style="margin-top:15px"><h3>Risk Scoring Configuration</h3><p>Weights apply only to measured telemetry inside the configured lookback window.</p><form class="form" method="post" action="/admin/risk/settings"><label>Click weight<input type="number" min="0" max="100" name="click_weight" value="%s"></label><label>Form-action weight<input type="number" min="0" max="100" name="form_action_weight" value="%s"></label><label>Report bonus<input type="number" min="-100" max="0" name="report_bonus" value="%s"></label><label>Repeat-offender bonus<input type="number" min="0" max="100" name="repeat_bonus" value="%s"></label><label>Lookback days<input type="number" min="1" max="3650" name="lookback_days" value="%s"></label><label>High threshold<input type="number" min="1" max="100" name="high_threshold" value="%s"></label><label>Medium threshold<input type="number" min="1" max="100" name="medium_threshold" value="%s"></label><button class="btn primary">Save Risk Settings</button></form></div>'''%(esc(cur_base_url),esc(cur_base_url),cfg["click_weight"],cfg["form_action_weight"],cfg["report_bonus"],cfg["repeat_bonus"],cfg["lookback_days"],cfg["high_threshold"],cfg["medium_threshold"])
            return self.admin_shell("Settings",body,"Settings")
        c.close(); return None

    def campaign_report(self,cid):
        c=db()
        camp=c.execute("SELECT c.*,s.name smtp_name,l.name landing_name FROM campaigns c LEFT JOIN smtp_profiles s ON s.id=c.smtp_profile_id LEFT JOIN landing_pages l ON l.id=c.landing_page_id WHERE c.id=?",(cid,)).fetchone()
        deliveries=c.execute("""SELECT d.status,d.sent_at,r.email,r.name,r.department,
                                       (SELECT COUNT(*) FROM events e WHERE e.campaign_id=? AND e.email=r.email AND e.event='click') as click_count,
                                       (SELECT COUNT(*) FROM events e WHERE e.campaign_id=? AND e.email=r.email AND e.event in ('form_action','submitted')) as action_count
                                FROM campaign_deliveries d JOIN recipients r ON r.id=d.recipient_id WHERE d.campaign_id=? ORDER BY d.id DESC""",(cid,cid,cid)).fetchall()
        events=c.execute("SELECT event,COUNT(*) n FROM events WHERE campaign_id=? GROUP BY event",(cid,)).fetchall()
        c.close()
        if not camp: return self.sendbody(404,"Campaign not found","text/plain")
        counts={x["event"]:x["n"] for x in events}
        sent=sum(1 for x in deliveries if x["status"]=="Sent"); failed=sum(1 for x in deliveries if x["status"]=="Failed")
        rows=[]
        for x in deliveries:
            ck_badge = f'<span class="pill click" style="background:#fff3cd;color:#856404;font-weight:700">⚠️ Clicked ({x["click_count"]})</span>' if x["click_count"] > 0 else '<span style="color:#8ba59b">—</span>'
            act_badge = f'<span class="pill form_action" style="background:#f8d7da;color:#721c24;font-weight:700">🚨 Action ({x["action_count"]})</span>' if x["action_count"] > 0 else '<span style="color:#8ba59b">—</span>'
            rows.append('<tr><td><b>%s</b></td><td>%s</td><td>%s</td><td><span class="pill %s">%s</span></td><td>%s</td><td>%s</td><td>%s</td></tr>'%(
                esc(x["email"]),esc(x["name"]),esc(x["department"]),
                "delivered" if x["status"]=="Sent" else "failed",esc(x["status"]),
                ck_badge,act_badge,esc(x["sent_at"] or "")
            ))
        rows_html="".join(rows) or '<tr><td colspan="7">No delivery records.</td></tr>'
        total_actions=counts.get("form_action",0) + counts.get("submitted",0)
        body='<h1>%s</h1><p>SMTP: %s · Landing Page: %s · Targeted: %s</p><div class="card" style="display:flex;gap:20px;flex-wrap:wrap"><div><b>Sent:</b> %s</div> <div><b>Failed:</b> %s</div> <div><b style="color:#b37400">Clicks:</b> %s</div> <div><b style="color:#c82333">Form Actions:</b> %s</div></div><div class="card"><table class="table"><tr><th>Email</th><th>Name</th><th>Department</th><th>Delivery</th><th>Clicked</th><th>Form Action</th><th>Sent At</th></tr>%s</table></div><p><a class="btn" href="/admin/reports">Back to Reports</a></p>'%(esc(camp["name"]),esc(camp["smtp_name"] or "Not set"),esc(camp["landing_name"] or "Not set"),camp["targeted"],sent,failed,counts.get("click",0),total_actions,rows_html)
        return self.admin_shell("Campaign Report",body,"Reports")

    def recipient_profile_form(self,rid=None):
        c=db()
        r=c.execute("SELECT * FROM recipients WHERE id=?",(rid,)).fetchone() if (rid and str(rid).lower()!="new") else None
        depts=[row[0] for row in c.execute("SELECT DISTINCT department FROM recipients WHERE department!='' UNION SELECT department FROM groups_tbl WHERE department!=''").fetchall()]
        groups=[row[0] for row in c.execute("SELECT name FROM groups_tbl ORDER BY name").fetchall()]
        c.close()

        is_new=(r is None)
        if not is_new:
            page_title=f"Edit Recipient: {esc(r['name'] or r['email'])}"
            form_title=f"Edit Target Profile #{r['id']}"
            crumb_sub="Edit Profile"
            submit_lbl="💾 Save Changes"
        else:
            page_title="Add Single Recipient"
            form_title="➕ Add Target Employee"
            crumb_sub="New Recipient"
            submit_lbl="➕ Add Recipient to Directory"

        def v(k, default=""):
            if is_new: return default
            return esc(r[k] or "")

        langs=["English","Bangla","Bengali-English","Arabic","Hindi","Spanish","French"]
        curr_lang=v("language","English")
        langopts="".join('<option value="%s" %s>%s</option>'%(esc(x),"selected" if curr_lang==x else "",esc(x)) for x in langs)
        curr_status=v("status","Active")
        statusopts="".join('<option value="%s" %s>%s</option>'%(x,"selected" if curr_status==x else "",x) for x in ("Active","Suppressed"))

        dept_datalist="".join('<option value="%s">'%esc(d) for d in depts)
        group_datalist="".join('<option value="%s">'%esc(g) for g in groups)

        delete_btn=""
        if not is_new:
            delete_btn=f'''<button class="btn" style="color:#b91c1c;border-color:#fca5a5;background:#fef2f2" type="submit" formaction="/admin/recipients/delete" onclick="return confirm('Are you sure you want to delete this recipient profile?');">🗑️ Delete Recipient</button>'''

        body=f'''<div class="camp-header">
  <div>
    <div class="camp-crumb"><a href="/admin/recipients">Recipients</a> <span>/</span> <span>{crumb_sub}</span></div>
    <div class="camp-title-row">
      <h1>{form_title}</h1>
      <span class="camp-status-badge status-active">{'Active Target' if curr_status=='Active' else 'Suppressed'}</span>
    </div>
  </div>
  <div class="camp-actions">
    <a class="btn" href="/admin/recipients">← Back to Directory</a>
  </div>
</div>

<div class="card" style="max-width:920px;margin:0 auto">
  <div style="margin-bottom:18px;border-bottom:1px solid #e2ede7;padding-bottom:14px">
    <h3 style="margin:0 0 6px 0">{form_title}</h3>
    <p style="margin:0;font-size:12.5px;color:#5c786c">Enter employee organizational and simulation targeting metadata. <b>Compliance guarantee:</b> Zero credential storage policy strictly enforced.</p>
  </div>

  <form class="form" method="post" action="/admin/recipients/save">
    <input type="hidden" name="id" value="{'' if is_new else r['id']}">
    
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px 20px">
      <label>
        <span style="font-weight:700;color:#183227;display:flex;align-items:center;gap:4px">Corporate Email Address <span style="color:#dc2626">*</span></span>
        <input type="email" name="email" value="{v('email')}" required maxlength="255" placeholder="alex.morgan@company.com" style="margin-top:6px;width:100%;padding:10px 12px;border:1.5px solid #cbdad2;border-radius:8px">
      </label>

      <label>
        <span style="font-weight:700;color:#183227">Full Name</span>
        <input name="name" value="{v('name')}" maxlength="150" placeholder="Alex Morgan" style="margin-top:6px;width:100%;padding:10px 12px;border:1.5px solid #cbdad2;border-radius:8px">
      </label>

      <label>
        <span style="font-weight:700;color:#183227">Employee ID</span>
        <input name="employee_id" value="{v('employee_id')}" maxlength="100" placeholder="EMP-5082" style="margin-top:6px;width:100%;padding:10px 12px;border:1.5px solid #cbdad2;border-radius:8px">
      </label>

      <label>
        <span style="font-weight:700;color:#183227">Designation / Role</span>
        <input name="designation" value="{v('designation')}" maxlength="150" placeholder="Senior Financial Analyst" style="margin-top:6px;width:100%;padding:10px 12px;border:1.5px solid #cbdad2;border-radius:8px">
      </label>

      <label>
        <span style="font-weight:700;color:#183227">Department</span>
        <input name="department" value="{v('department')}" list="deptList" maxlength="100" placeholder="Finance & Operations" style="margin-top:6px;width:100%;padding:10px 12px;border:1.5px solid #cbdad2;border-radius:8px">
        <datalist id="deptList">{dept_datalist}</datalist>
      </label>

      <label>
        <span style="font-weight:700;color:#183227">Group / Segment</span>
        <input name="group_name" value="{v('group_name')}" list="grpList" maxlength="100" placeholder="Finance Dept Drill" style="margin-top:6px;width:100%;padding:10px 12px;border:1.5px solid #cbdad2;border-radius:8px">
        <datalist id="grpList">{group_datalist}</datalist>
      </label>

      <label>
        <span style="font-weight:700;color:#183227">Office Location</span>
        <input name="location" value="{v('location')}" maxlength="150" placeholder="Dhaka HQ / Floor 7" style="margin-top:6px;width:100%;padding:10px 12px;border:1.5px solid #cbdad2;border-radius:8px">
      </label>

      <label>
        <span style="font-weight:700;color:#183227">Reporting Manager</span>
        <input name="manager" value="{v('manager')}" maxlength="150" placeholder="Sarah Jenkins" style="margin-top:6px;width:100%;padding:10px 12px;border:1.5px solid #cbdad2;border-radius:8px">
      </label>

      <label>
        <span style="font-weight:700;color:#183227">Preferred Language</span>
        <select name="language" style="margin-top:6px;width:100%;padding:10px 12px;border:1.5px solid #cbdad2;border-radius:8px;background:#fff">{langopts}</select>
      </label>

      <label>
        <span style="font-weight:700;color:#183227">Local Timezone</span>
        <input name="timezone" value="{v('timezone', 'Asia/Dhaka')}" maxlength="80" placeholder="Asia/Dhaka" style="margin-top:6px;width:100%;padding:10px 12px;border:1.5px solid #cbdad2;border-radius:8px">
      </label>

      <label style="grid-column:span 2">
        <span style="font-weight:700;color:#183227">Simulation Targeting Status</span>
        <select name="status" style="margin-top:6px;width:100%;padding:10px 12px;border:1.5px solid #cbdad2;border-radius:8px;background:#fff">{statusopts}</select>
        <span style="font-size:11.5px;color:#678275;margin-top:4px;display:block">Active targets will receive assigned campaign drills. Suppressed profiles are excluded from delivery.</span>
      </label>
    </div>

    <div style="display:flex;justify-content:space-between;align-items:center;margin-top:24px;border-top:1px solid #e2ede7;padding-top:18px;gap:10px;flex-wrap:wrap">
      <div style="display:flex;gap:10px;align-items:center">
        <button class="btn primary" type="submit" style="padding:9px 20px;font-weight:700">{submit_lbl}</button>
        <a class="btn" href="/admin/recipients">Cancel</a>
      </div>
      {delete_btn}
    </div>
  </form>
</div>'''
        return self.admin_shell(page_title,body,"Recipients")

    def recipient_import_form(self):
        return self.admin_shell("Import Recipients",'<h1>Import Recipients</h1><div class="card"><form class="form" method="post" action="/admin/recipients/import"><label>Source Name<input name="source_name" maxlength="150" placeholder="HR recipient export - October 2026"></label><label>CSV data<textarea name="csv_data" rows="16" style="width:100%;padding:10px;border:1px solid #ccd9d4;border-radius:8px" placeholder="email,name,employee_id,department,designation,location,manager,language,timezone,group_name"></textarea></label><button class="btn primary">Validate & Import</button></form><p style="font-size:12px;color:#71817b">Supported metadata: email, name, employee_id, department, designation, location, manager, language, timezone, group_name. Duplicate emails are updated; conflicting employee IDs are skipped. Never place passwords, OTPs, PINs, CVVs or card data here.</p></div>',"Recipients")

    def group_form(self):
        return self.admin_shell("New Group",'<h1>New Group</h1><div class="card"><form class="form" method="post" action="/admin/groups/save"><label>Group Name<input name="name" required maxlength="100"></label><label>Department<input name="department" maxlength="100"></label><button class="btn primary">Save Group</button></form></div>',"Groups & Departments")

    def smtp_form(self,sid=None):
        c=db(); r=c.execute("SELECT * FROM smtp_profiles WHERE id=?",(sid,)).fetchone() if sid else None; c.close()
        provider=esc(r["provider"]) if r else "Gmail"; preset=SMTP_PROVIDERS.get(provider,SMTP_PROVIDERS["Custom SMTP"])
        host=esc(r["host"]) if r else esc(preset["host"]); port=esc(r["port"]) if r else str(preset["port"]); security=esc(r["security"]) if r else preset["security"]
        name=esc(r["name"]) if r else ""; username=esc(r["username"]) if r else ""; from_name=esc(r["from_name"]) if r else ""; from_email=esc(r["from_email"]) if r else ""; reply_to=esc(r["reply_to"]) if r else ""; auth_method=esc(r["auth_method"]) if r and r["auth_method"] else "password"; oauth_url=esc(r["oauth_token_url"]) if r else ""; oauth_client=esc(r["oauth_client_id"]) if r else ""; oauth_scopes=esc(r["oauth_scopes"]) if r else ""
        enabled=r["enabled"] if r and "enabled" in r.keys() else 1
        opts="".join('<option value="%s" %s>%s</option>'%(esc(k),"selected" if k==provider else "",esc(k)) for k in SMTP_PROVIDERS)
        secs="".join('<option value="%s" %s>%s</option>'%(x,"selected" if x==security else "",x) for x in ("STARTTLS","SSL/TLS","NONE"))
        status_opts='<option value="1" %s>Enabled</option><option value="0" %s>Disabled</option>'%("selected" if enabled else "","selected" if not enabled else "")
        diagnostics=('<a class="btn" href="/admin/smtp/diagnostics?id=%s">Open Diagnostics</a>'%sid) if r else ""
        delete_btn=('<button class="btn" style="color:#a12d2d;border-color:#f0c0c0" type="submit" formaction="/admin/smtp/delete" onclick="return confirm(\'Delete this SMTP profile?\');">Delete Provider</button>') if r else ""
        body='<div class="smtp-editor"><div class="smtp-heading"><h1>%s SMTP Provider</h1><p>Configure email delivery for your campaigns.</p></div><div class="card smtp-card"><form method="post" action="/admin/smtp/save"><input type="hidden" name="id" value="%s"><div class="smtp-fields"><label>Profile Name<input name="name" value="%s" placeholder="Corporate Mail - Primary" maxlength="100" required></label><label>Email Provider<select id="provider" name="provider" onchange="presetProvider()">%s</select></label><label>Sender Email<input type="email" name="from_email" value="%s" placeholder="security@example.com" maxlength="255" required></label><label>Sender Name<input name="from_name" value="%s" maxlength="150" placeholder="Trust PhishGuard"></label><label>Authentication<select id="auth_method" name="auth_method" onchange="authFields()"><option value="password" %s>SMTP Username &amp; Password</option><option value="oauth2" %s>OAuth 2.0 / XOAUTH2</option></select></label><label>Status<select name="enabled">%s</select></label><label>SMTP Username<input name="username" value="%s" autocomplete="username" placeholder="security@example.com" maxlength="255"></label><label id="password-label">SMTP Password / App Password<input type="password" name="password" value="" autocomplete="new-password" placeholder="%s"></label></div><details class="smtp-advanced" %s><summary>Advanced Settings &amp; Server Connection</summary><div class="smtp-fields"><label>SMTP Host<input id="host" name="host" value="%s" maxlength="255" required></label><label>Port<input id="port" type="number" min="1" max="65535" name="port" value="%s" required></label><label>Connection Security<select id="security" name="security">%s</select></label><label>Reply-To Email<input type="email" name="reply_to" value="%s" maxlength="255"></label><label>OAuth Token URL<input name="oauth_token_url" value="%s" maxlength="500"></label><label>OAuth Access Token<input type="password" name="oauth_token" value="" autocomplete="new-password" placeholder="%s"></label><label>OAuth Client ID<input name="oauth_client_id" value="%s" maxlength="255"></label><label>OAuth Scopes<input name="oauth_scopes" value="%s" maxlength="1000"></label></div><p class="smtp-secret-note">Credentials are stored encrypted and never displayed. When editing, leave secret fields blank to retain the existing secret.</p></details><div class="smtp-actions">%s<button class="btn" type="submit" name="test_after_save" value="1">Test Connection</button><button class="btn primary" type="submit">Save Provider</button>%s<a class="btn" href="/admin/smtp">Cancel</a></div></form></div></div><style>.smtp-editor{max-width:980px;margin:0 auto}.smtp-heading{margin:8px 0 22px}.smtp-heading h1{margin-bottom:8px}.smtp-heading p{color:#60716a;margin-top:0}.smtp-card{padding:24px}.smtp-fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px 22px}.smtp-fields label{display:flex;flex-direction:column;gap:8px;font-weight:650;color:#233b32}.smtp-fields input,.smtp-fields select{width:100%%;min-height:44px;border:1px solid #cbd9d2;border-radius:9px;padding:10px 12px;background:#fff;color:#12231d}.smtp-advanced{margin-top:22px;border-top:1px solid #e0e9e4;padding-top:18px}.smtp-advanced summary{cursor:pointer;font-weight:700;color:#145c45;padding:4px 0 14px}.smtp-secret-note{font-size:12px;color:#60716a;background:#f4f7f6;border-radius:8px;padding:12px}.smtp-actions{display:flex;justify-content:flex-end;align-items:center;gap:10px;flex-wrap:wrap;margin-top:22px;padding-top:18px;border-top:1px solid #e0e9e4}@media(max-width:680px){.smtp-fields{grid-template-columns:1fr}.smtp-card{padding:16px}}</style><script>const presets=%s;function presetProvider(){const p=presets[document.getElementById("provider").value];if(p){if(p.host)document.getElementById("host").value=p.host;if(p.port)document.getElementById("port").value=p.port;if(p.security)document.getElementById("security").value=p.security}}function authFields(){const oauth=document.getElementById("auth_method").value==="oauth2";const pwd=document.getElementById("password-label");if(pwd){pwd.style.opacity=oauth?".55":"1"}const adv=document.querySelector(".smtp-advanced");if(oauth&&adv){adv.open=true}}authFields();</script>'%("Edit" if r else "Add",sid or "",name,opts,from_email,from_name,auth_method=="password" and "selected" or "",auth_method=="oauth2" and "selected" or "",status_opts,username,"unchanged" if r else "Enter SMTP password or app password","open" if auth_method=="oauth2" else "",host,port,secs,reply_to,oauth_url,"unchanged" if r else "Enter OAuth access token",oauth_client,oauth_scopes,delete_btn,diagnostics,json.dumps(SMTP_PROVIDERS))
        return self.admin_shell("SMTP Provider",body,"SMTP Providers")
    def landing_page_form(self,lid=None):
        c=db()
        r=c.execute("SELECT * FROM landing_pages WHERE id=?",(lid,)).fetchone() if lid else None
        versions=c.execute("SELECT version,created_at,created_by FROM landing_page_versions WHERE landing_page_id=? ORDER BY version DESC LIMIT 20",(lid,)).fetchall() if lid else []
        c.close()
        if not r and lid:
            return self.admin_shell("Landing Page","<h1>Landing page not found</h1><p><a class='btn' href='/admin/landing-pages'>Back to Landing Pages</a></p>","Landing Pages")

        presets_dict = {}
        for s in LANDING_PAGE_SEEDS:
            t_num = s["template"]
            h_body = ""
            for cand in (os.path.join(TEMPLATES, s["file"]), os.path.join(os.path.dirname(__file__), "templates", s["file"])):
                if os.path.isfile(cand):
                    try:
                        with open(cand, "r", encoding="utf-8") as f:
                            h_body = f.read()
                        break
                    except Exception:
                        pass
            presets_dict[t_num] = {
                "name": s["name"],
                "brand": s["brand"],
                "scenario": s["scenario"],
                "html": h_body
            }
        aliases = {"m365": "3", "google": "4", "hr_portal": "5", "it_sso": "6", "fin_bkash": "7", "awareness": "10"}
        for alias, target in aliases.items():
            if target in presets_dict:
                presets_dict[alias] = presets_dict[target]
        presets_json = json.dumps(presets_dict)

        name=esc(r["name"]) if r else "New Simulation Portal"
        status=esc(r["status"]) if r else "Enabled"
        html_body=r["html_body"] if (r and r["html_body"]) else presets_dict.get("1", {}).get("html", "")
        text_body=esc(r["text_body"]) if (r and r["text_body"]) else "Authorized security-awareness simulation landing page."
        versions_html="".join("<tr><td><b>v%s</b></td><td>%s</td><td>%s</td></tr>"%(v["version"],esc(v["created_at"] or ""),esc(v["created_by"] or "system")) for v in versions) or "<tr><td colspan='3'>No saved versions yet.</td></tr>"

        preview_header=f'<a class="btn" target="_blank" href="/admin/landing-pages/preview?id={lid}">👁️ Live Preview Tab</a>' if lid else ""

        body=f"""<div class="camp-editor lp-editor">
<div class="camp-header">
  <div>
    <div class="camp-crumb"><a href="/admin/landing-pages">Landing Pages</a> <span>/</span> <span>{"Edit Portal #"+str(lid) if lid else "Create New Portal"}</span></div>
    <div class="camp-title-row">
      <h1>{"Edit" if r else "Create"} Simulation Landing Page</h1>
      <span class="camp-status-badge {'status-active' if status=='Enabled' else 'status-draft'}" id="lpStatusBadge">{status}</span>
    </div>
  </div>
  <div class="camp-actions">
    {preview_header}
    <a class="btn" href="/admin/landing-pages">Cancel</a>
    <button class="btn primary" type="submit" form="lpForm">Save Landing Page</button>
  </div>
</div>

<form id="lpForm" method="post" action="/admin/landing-pages/save">
<input type="hidden" name="id" value="{lid or ''}">

<div class="camp-grid" style="grid-template-columns: minmax(0, 1.15fr) minmax(360px, 0.85fr);">
  <!-- Left Side: Configuration, Presets, HTML Editor -->
  <div class="camp-main">

    <!-- Card 1: Portal Settings -->
    <div class="camp-card">
      <div class="camp-card-header">
        <div class="camp-icon">🌐</div>
        <div class="camp-card-title">
          <h3>Portal Settings &amp; Metadata</h3>
          <p>Define portal name, visibility, and version information.</p>
        </div>
      </div>
      <div class="camp-fields">
        <div class="camp-label col-full">
          <span>Portal Name <b style="color:#a12d2d">*</b></span>
          <input name="name" id="lpName" value="{name}" required maxlength="150" placeholder="e.g. Microsoft 365 Enterprise Sign-In Portal">
          <div class="field-hint">A clear scenario title shown in campaign selectors and audit logs.</div>
        </div>
        <div class="camp-label">
          <span>Status</span>
          <select name="status" id="lpStatus" onchange="syncStatusBadge()">
            <option value="Enabled" {"selected" if status=="Enabled" else ""}>Enabled</option>
            <option value="Disabled" {"selected" if status=="Disabled" else ""}>Disabled</option>
          </select>
          <div class="field-hint">Enabled portals are selectable in campaigns.</div>
        </div>
        <div class="camp-label">
          <span>Active Version</span>
          <input value="v{r['version'] if r else '1'}" disabled style="background:#f5f8f6;color:#556c62">
          <div class="field-hint">Every save automatically archives a new version snapshot.</div>
        </div>
      </div>
    </div>

    <!-- Card 2: Market Presets Library -->
    <div class="camp-card">
      <div class="camp-card-header">
        <div class="camp-icon">⚡</div>
        <div class="camp-card-title">
          <h3>One-Click Authentic Market Presets (10 Enterprise Portals)</h3>
          <p>Load battle-tested, high-converting corporate phishing simulation portals with authentic layouts and compliant fields.</p>
        </div>
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px">
        <div class="preset-card" onclick="loadPreset('1')">
          <div style="display:flex;align-items:center;gap:8px;font-weight:700;font-size:13px;color:#12251e">
            <span>🎁</span> Apex Rewards Voucher
          </div>
          <p style="font-size:11.5px;color:#556c62;margin:5px 0 0">Exclusive employee gift voucher &amp; discount claim portal.</p>
        </div>
        <div class="preset-card" onclick="loadPreset('2')">
          <div style="display:flex;align-items:center;gap:8px;font-weight:700;font-size:13px;color:#12251e">
            <span>🏛️</span> Trust Bank Corporate
          </div>
          <p style="font-size:11.5px;color:#556c62;margin:5px 0 0">Corporate banking privileges &amp; employee card claim.</p>
        </div>
        <div class="preset-card" onclick="loadPreset('m365')">
          <div style="display:flex;align-items:center;gap:8px;font-weight:700;font-size:13px;color:#12251e">
            <span>🏢</span> Microsoft 365 Sign-In
          </div>
          <p style="font-size:11.5px;color:#556c62;margin:5px 0 0">Entra ID / Outlook corporate sign-in simulation.</p>
        </div>
        <div class="preset-card" onclick="loadPreset('4')">
          <div style="display:flex;align-items:center;gap:8px;font-weight:700;font-size:13px;color:#12251e">
            <span>🌐</span> Google Workspace SSO
          </div>
          <p style="font-size:11.5px;color:#556c62;margin:5px 0 0">Google Drive &amp; Workspace account verification.</p>
        </div>
        <div class="preset-card" onclick="loadPreset('5')">
          <div style="display:flex;align-items:center;gap:8px;font-weight:700;font-size:13px;color:#12251e">
            <span>👥</span> HR Benefits &amp; Appraisal
          </div>
          <p style="font-size:11.5px;color:#556c62;margin:5px 0 0">Employee portal compensation statement review.</p>
        </div>
        <div class="preset-card" onclick="loadPreset('6')">
          <div style="display:flex;align-items:center;gap:8px;font-weight:700;font-size:13px;color:#12251e">
            <span>💻</span> GlobalProtect IT Gateway
          </div>
          <p style="font-size:11.5px;color:#556c62;margin:5px 0 0">Enterprise remote VPN &amp; identity gate verification.</p>
        </div>
        <div class="preset-card" onclick="loadPreset('7')">
          <div style="display:flex;align-items:center;gap:8px;font-weight:700;font-size:13px;color:#12251e">
            <span>💳</span> bKash / Financial Alert
          </div>
          <p style="font-size:11.5px;color:#556c62;margin:5px 0 0">Suspicious transaction halt &amp; verify alert (bKash/Bank).</p>
        </div>
        <div class="preset-card" onclick="loadPreset('8')">
          <div style="display:flex;align-items:center;gap:8px;font-weight:700;font-size:13px;color:#12251e">
            <span>📹</span> Zoom Meeting Gateway
          </div>
          <p style="font-size:11.5px;color:#556c62;margin:5px 0 0">Executive conference pre-call check &amp; verification.</p>
        </div>
        <div class="preset-card" onclick="loadPreset('9')">
          <div style="display:flex;align-items:center;gap:8px;font-weight:700;font-size:13px;color:#12251e">
            <span>☁️</span> AWS Cloud Console IAM
          </div>
          <p style="font-size:11.5px;color:#556c62;margin:5px 0 0">Cloud infrastructure identity &amp; root device verification.</p>
        </div>
        <div class="preset-card" onclick="loadPreset('10')">
          <div style="display:flex;align-items:center;gap:8px;font-weight:700;font-size:13px;color:#12251e">
            <span>🎓</span> Teachable Moment (Awareness)
          </div>
          <p style="font-size:11.5px;color:#556c62;margin:5px 0 0">Instant interactive drill with phishing red flag breakdown.</p>
        </div>
      </div>
    </div>

    <!-- Card 3: Code Editor -->
    <div class="camp-card">
      <div class="camp-card-header" style="justify-content:space-between">
        <div style="display:flex;align-items:flex-start;gap:14px">
          <div class="camp-icon">💻</div>
          <div class="camp-card-title">
            <h3>HTML Source Code Editor</h3>
            <p>Customize portal branding and input fields. Form must submit to <code>/submit</code>.</p>
          </div>
        </div>
        <div style="font-size:11.5px;color:#087b59;background:#e8f4ef;padding:5px 10px;border-radius:6px;font-weight:700;display:flex;align-items:center;gap:5px">
          <span>🔒</span> Safety Policy Guard Active
        </div>
      </div>

      <div class="token-row" style="margin-bottom:12px">
        <small style="color:#556c62;font-weight:600">Quick Insert:</small>
        <button type="button" class="token-chip" onclick="insertField('&lt;input type=&quot;text&quot; name=&quot;name&quot; placeholder=&quot;Full Legal Name&quot; required&gt;')">+ Name Field</button>
        <button type="button" class="token-chip" onclick="insertField('&lt;input type=&quot;email&quot; name=&quot;email&quot; placeholder=&quot;Work Email&quot; required&gt;')">+ Email Field</button>
        <button type="button" class="token-chip" onclick="insertField('&lt;input type=&quot;text&quot; name=&quot;employee_id&quot; placeholder=&quot;Employee ID (e.g. EMP-9021)&quot; required&gt;')">+ Employee ID</button>
        <button type="button" class="token-chip" onclick="insertField('&lt;input type=&quot;text&quot; name=&quot;mobile&quot; placeholder=&quot;Mobile Number&quot; required&gt;')">+ Mobile Number</button>
        <button type="button" class="token-chip" onclick="insertField('&lt;button type=&quot;submit&quot;&gt;Continue&lt;/button&gt;')">+ Submit Button</button>
      </div>

      <div class="camp-label">
        <textarea id="htmlEditor" name="html_body" rows="22" style="font-family:'SF Mono',Consolas,Menlo,monospace;font-size:12px;line-height:1.55;background:#0d1814;color:#d5ede2;border:1px solid #1a382c;border-radius:10px;padding:16px;box-sizing:border-box" oninput="updateLivePreview()" required>{esc(html_body)}</textarea>
      </div>
      <div style="display:flex;justify-content:space-between;margin-top:8px;font-size:11.5px;color:#556c62">
        <span>Blocked by policy: <code>password</code>, <code>otp</code>, <code>pin</code>, <code>cvv</code> (prevents accidental credential theft).</span>
        <span id="charCount">0 characters</span>
      </div>
    </div>

    <!-- Card 4: Plain Text Fallback -->
    <div class="camp-card">
      <div class="camp-card-header">
        <div class="camp-icon">📝</div>
        <div class="camp-card-title">
          <h3>Plain Text Fallback</h3>
          <p>Alternative message rendered for non-HTML environments and accessibility readers.</p>
        </div>
      </div>
      <div class="camp-label">
        <textarea name="text_body" rows="4" style="font-size:13px">{text_body}</textarea>
      </div>
    </div>

    <!-- Card 5: Version History -->
    {f'''<div class="camp-card">
      <div class="camp-card-header">
        <div class="camp-icon">📜</div>
        <div class="camp-card-title">
          <h3>Version Revision History</h3>
          <p>Audit trail of all previous revisions saved for this landing page.</p>
        </div>
      </div>
      <div class="table-wrap">
        <table class="table" style="width:100%">
          <thead><tr><th>Version</th><th>Saved At</th><th>Author</th></tr></thead>
          <tbody>{versions_html}</tbody>
        </table>
      </div>
    </div>''' if lid else ''}

    <div class="camp-bottom-bar">
      <a class="btn" href="/admin/landing-pages">Cancel</a>
      <button class="btn primary" type="submit">Save Landing Page</button>
    </div>

  </div>

  <!-- Right Side: Live Interactive Device Preview -->
  <div class="camp-sidebar">
    <div class="camp-sidebar-sticky" style="top:20px">
      <div class="camp-card" style="padding:16px;margin-bottom:0">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
          <div style="display:flex;align-items:center;gap:8px">
            <span style="font-size:16px">👁️</span>
            <span style="font-weight:700;font-size:13.5px;color:#12251e">Live Real-time Preview</span>
          </div>
          <div style="display:flex;gap:4px;background:#edf3f0;padding:3px;border-radius:8px">
            <button type="button" id="btnDesk" class="preset-btn active" style="font-size:11px;padding:3px 8px;border:none" onclick="setDevice('desktop')">💻 Desktop</button>
            <button type="button" id="btnMob" class="preset-btn" style="font-size:11px;padding:3px 8px;border:none" onclick="setDevice('mobile')">📱 Mobile</button>
          </div>
        </div>

        <!-- Fake Browser Navigation Bar -->
        <div style="background:#edf3f0;border:1px solid #dbe7e1;border-radius:8px 8px 0 0;padding:8px 12px;display:flex;align-items:center;gap:8px">
          <div style="display:flex;gap:5px">
            <span style="width:8px;height:8px;border-radius:50%;background:#f87171;display:inline-block"></span>
            <span style="width:8px;height:8px;border-radius:50%;background:#fbbf24;display:inline-block"></span>
            <span style="width:8px;height:8px;border-radius:50%;background:#34d399;display:inline-block"></span>
          </div>
          <div style="flex:1;background:#fff;border-radius:6px;padding:3px 10px;font-size:11px;color:#445b51;font-family:monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
            🔒 https://secure-login.portal-verify.local/auth
          </div>
        </div>

        <!-- Iframe Sandbox Container -->
        <div id="previewContainer" style="border:1px solid #dbe7e1;border-top:none;border-radius:0 0 8px 8px;overflow:hidden;background:#fff;display:flex;justify-content:center;transition:all 0.2s">
          <iframe id="previewFrame" style="width:100%;height:580px;border:none;background:#fff" sandbox="allow-same-origin allow-forms allow-scripts"></iframe>
        </div>

        <div style="margin-top:10px;display:flex;justify-content:space-between;align-items:center;font-size:11px;color:#647b71">
          <span>Updates immediately as you edit code</span>
          <span id="viewportSizeLabel">Desktop (100%)</span>
        </div>
      </div>
    </div>
  </div>

</div>
</form>
</div>

<style>
.preset-card {{ background:#ffffff; border:1.5px solid #dce8e2; border-radius:10px; padding:12px 14px; cursor:pointer; transition:all 0.15s ease; }}
.preset-card:hover {{ border-color:#087b59; background:#f4faf7; transform:translateY(-1px); box-shadow:0 3px 8px rgba(8,123,89,0.08); }}
.preset-btn.active {{ background:#087b59; color:#fff; }}
</style>

<script>
const PRESETS = {presets_json};
function loadPreset(key) {{
  const p = PRESETS[key];
  if (!p) return;
  const ed = document.getElementById('htmlEditor');
  const nameInput = document.getElementById('lpName');
  if (confirm("Load " + p.name + " preset? This will replace the editor content.")) {{
    ed.value = p.html;
    if (nameInput && (!nameInput.value || nameInput.value === 'New Simulation Portal')) {{
      nameInput.value = p.name;
    }}
    updateLivePreview();
  }}
}}

function insertField(fieldHtml) {{
  const ed = document.getElementById('htmlEditor');
  const pos = ed.selectionStart || ed.value.length;
  ed.value = ed.value.slice(0, pos) + fieldHtml + ed.value.slice(pos);
  ed.focus();
  updateLivePreview();
}}

function updateLivePreview() {{
  const ed = document.getElementById('htmlEditor');
  const val = ed ? ed.value : '';
  const frame = document.getElementById('previewFrame');
  if (frame) {{
    frame.srcdoc = val;
  }}
  const countEl = document.getElementById('charCount');
  if (countEl) {{
    countEl.textContent = val.length.toLocaleString() + ' characters';
  }}
}}

function setDevice(mode) {{
  const container = document.getElementById('previewContainer');
  const btnDesk = document.getElementById('btnDesk');
  const btnMob = document.getElementById('btnMob');
  const sizeLabel = document.getElementById('viewportSizeLabel');
  if (mode === 'mobile') {{
    container.style.maxWidth = '375px';
    container.style.margin = '0 auto';
    btnMob.classList.add('active');
    btnDesk.classList.remove('active');
    sizeLabel.textContent = 'Mobile (375px)';
  }} else {{
    container.style.maxWidth = '100%';
    container.style.margin = '0';
    btnDesk.classList.add('active');
    btnMob.classList.remove('active');
    sizeLabel.textContent = 'Desktop (100%)';
  }}
}}

function syncStatusBadge() {{
  const sel = document.getElementById('lpStatus');
  const badge = document.getElementById('lpStatusBadge');
  if (badge && sel) {{
    badge.textContent = sel.value;
    badge.className = 'camp-status-badge ' + (sel.value === 'Enabled' ? 'status-active' : 'status-draft');
  }}
}}

document.addEventListener('DOMContentLoaded', function() {{
  updateLivePreview();
}});
updateLivePreview();
</script>"""
        return self.admin_shell("Landing Page Editor",body,"Landing Pages")

    def template_form(self,tid=None):
        c=db()
        r=c.execute("SELECT * FROM template_library WHERE template=?",(str(tid),)).fetchone() if tid else None
        if not r and tid and tid=="new":
            r={
                "template":"custom-"+secrets.token_hex(3),
                "name":"New Custom Email Template",
                "subject":"Important Security Notification",
                "preheader":"Action required within 24 hours",
                "category":"General",
                "difficulty":"Medium",
                "language":"English",
                "brand":"Internal IT",
                "industry":"Corporate",
                "tags":"Call to action, Visual Imitation",
                "html_body":"<!DOCTYPE html>\n<html>\n<head><meta charset=\"UTF-8\"><title>Security Notification</title></head>\n<body style=\"font-family:sans-serif;padding:20px;background:#f9f9f9\">\n  <div style=\"max-width:600px;margin:auto;background:#fff;padding:24px;border-radius:8px\">\n    <h2>Security Notice</h2>\n    <p>Dear {{name}},</p>\n    <p>Please review your account credentials to ensure access remains active.</p>\n    <p><a href=\"{{tracking_link}}\" style=\"display:inline-block;padding:10px 18px;background:#087b59;color:#fff;text-decoration:none;border-radius:5px\">Review Account Now</a></p>\n  </div>\n</body>\n</html>",
                "text_body":"Hello {{name}},\n\nPlease review your account notification:\n{{tracking_link}}\n\nThis is an authorized security-awareness simulation.",
                "from_name":"IT Support",
                "from_email":"it-support@security.local",
                "reply_to":"it-support@security.local",
                "owner":ADMIN_USERNAME,
                "status":"Active",
                "version":1
            }
        elif not r and tid:
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
            return self.admin_shell("Email Template","<h1>Email Template not found</h1><p><a class='btn' href='/admin/templates'>Back to Email Templates</a></p>","Email Templates")
        def val(k): return esc(r[k] or "")
        version_rows="".join("<tr><td>v%s</td><td>%s</td><td>%s</td></tr>"%(v["version"],esc(v["created_at"]),esc(v["created_by"])) for v in versions) or "<tr><td colspan='3'>No saved versions yet.</td></tr>"
        cats=["General","Credential Awareness","Malware Awareness","QR Awareness","Finance","HR","IT","Executive","Seasonal"]
        diffs=["Easy","Medium","Hard"]
        langs=["English","Bangla","Bengali-English","Arabic","Hindi"]
        catopts="".join('<option %s>%s</option>'%("selected" if r["category"]==x else "",x) for x in cats)
        diffopts="".join('<option %s>%s</option>'%("selected" if r["difficulty"]==x else "",x) for x in diffs)
        langopts="".join('<option %s>%s</option>'%("selected" if r["language"]==x else "",x) for x in langs)
        body=f"""<div class="camp-editor">
<div class="camp-header">
  <div>
    <div class="camp-crumb"><a href="/admin/templates">Email Templates</a> <span>/</span> <span>Edit Template #{val('template')}</span></div>
    <div class="camp-title-row">
      <h1>Edit Email Template #{val('template')}</h1>
      <span class="camp-status-badge status-active">{r['status'] or 'Active'}</span>
    </div>
  </div>
  <div class="camp-actions">
    <a class="btn" target="_blank" href="/admin/templates/preview?id={val('template')}">👁️ Preview Tab</a>
    <a class="btn" href="/admin/templates/test-send?id={val('template')}">✉️ Test Send</a>
    <a class="btn" href="/admin/templates">Cancel</a>
    <button class="btn primary" type="submit" form="tplForm">Save Template</button>
  </div>
</div>

<form id="tplForm" method="post" action="/admin/templates/save">
<input type="hidden" name="template" value="{val('template')}">

<div class="camp-card">
  <div class="camp-card-header">
    <div class="camp-icon">📝</div>
    <div class="camp-card-title">
      <h3>Template Metadata &amp; Targeting</h3>
      <p>Configure subject line, lure category, difficulty rating, and brand identifiers.</p>
    </div>
  </div>
  <div class="camp-fields">
    <div class="camp-label col-full">
      <span>Template Title <b style="color:#a12d2d">*</b></span>
      <input name="name" value="{val('name')}" required maxlength="150" placeholder="e.g. Microsoft 365 Account Expiry Drill">
      <div class="field-hint">A clear name shown in campaign setup and administrative audit logs.</div>
    </div>
    <div class="camp-label">
      <span>Subject Line</span>
      <input name="subject" value="{val('subject')}" maxlength="250" placeholder="e.g. Urgent: Verify Your Security Credentials">
    </div>
    <div class="camp-label">
      <span>Preheader / Preview Text</span>
      <input name="preheader" value="{val('preheader')}" maxlength="250" placeholder="e.g. Action required within 24 hours">
    </div>
    <div class="camp-label">
      <span>Category</span>
      <select name="category">{catopts}</select>
    </div>
    <div class="camp-label">
      <span>Difficulty</span>
      <select name="difficulty">{diffopts}</select>
    </div>
    <div class="camp-label">
      <span>Language</span>
      <select name="language">{langopts}</select>
    </div>
    <div class="camp-label">
      <span>Brand</span>
      <input name="brand" value="{val('brand')}" maxlength="100" placeholder="e.g. Microsoft, Google, HR Dept">
    </div>
    <div class="camp-label">
      <span>Industry</span>
      <input name="industry" value="{val('industry')}" maxlength="100" placeholder="e.g. Banking, Corporate, Tech">
    </div>
    <div class="camp-label">
      <span>Tags (comma-separated)</span>
      <input name="tags" value="{val('tags')}" placeholder="finance, employee, urgent" maxlength="500">
    </div>
  </div>
</div>

<div class="camp-card">
  <div class="camp-card-header">
    <div class="camp-icon">✉️</div>
    <div class="camp-card-title">
      <h3>Sender &amp; Header Identity</h3>
      <p>Configure the simulated sender profile and return addresses.</p>
    </div>
  </div>
  <div class="camp-fields">
    <div class="camp-label">
      <span>From Name</span>
      <input name="from_name" value="{val('from_name')}" maxlength="150" placeholder="e.g. Trust PhishGuard Alert">
    </div>
    <div class="camp-label">
      <span>From Email</span>
      <input name="from_email" value="{val('from_email')}" maxlength="254" placeholder="e.g. no-reply@security-notice.net">
    </div>
    <div class="camp-label">
      <span>Reply-To Email</span>
      <input name="reply_to" value="{val('reply_to')}" maxlength="254" placeholder="e.g. security-audit@notice.local">
    </div>
    <div class="camp-label">
      <span>Template Owner</span>
      <input name="owner" value="{val('owner')}" maxlength="150" placeholder="e.g. SecOps Lead">
    </div>
    <div class="camp-label">
      <span>Status</span>
      <select name="status">
        <option {"selected" if (r["status"] or "Active")=="Active" else ""}>Active</option>
        <option {"selected" if (r["status"] or "Active")=="Archived" else ""}>Archived</option>
      </select>
    </div>
  </div>
</div>

<div class="camp-card">
  <div class="camp-card-header">
    <div class="camp-icon">⚡</div>
    <div class="camp-card-title">
      <h3>Dynamic Variables Insertion</h3>
      <p>Click any variable below to insert it at cursor position in the HTML editor.</p>
    </div>
  </div>
  <div style="display:flex;gap:8px;flex-wrap:wrap">
    <button type="button" class="btn" onclick="insertTplVar('{{name}}')">+ Employee Name</button>
    <button type="button" class="btn" onclick="insertTplVar('{{email}}')">+ Email</button>
    <button type="button" class="btn" onclick="insertTplVar('{{employee_id}}')">+ Employee ID</button>
    <button type="button" class="btn" onclick="insertTplVar('{{department}}')">+ Department</button>
    <button type="button" class="btn" onclick="insertTplVar('{{tracking_link}}')">+ Phish Tracking Link</button>
    <button type="button" class="btn" onclick="insertTplVar('{{report_link}}')">+ Report Phish Link</button>
    <button type="button" class="btn" onclick="insertTplVar('{{qr_link}}')">+ QR Code Link</button>
  </div>
</div>

<div class="camp-card">
  <div class="camp-card-header">
    <div class="camp-icon">💻</div>
    <div class="camp-card-title">
      <h3>HTML Email Body &amp; Plain Text</h3>
      <p>Write the responsive email layout. Simulation safety policy blocks any password input tags.</p>
    </div>
  </div>
  <div style="display:grid;gap:14px">
    <label style="font-weight:700;font-size:12.5px;color:#10221a">HTML Source Code
      <textarea id="tplHtml" name="html_body" rows="22" style="width:100%;font-family:Consolas,monospace;padding:12px;border:1.5px solid #cbdad2;border-radius:8px;background:#0d1c16;color:#e8f4ef;font-size:13px;line-height:1.5;margin-top:6px" required>{val('html_body')}</textarea>
    </label>
    <label style="font-weight:700;font-size:12.5px;color:#10221a">Plain Text Fallback
      <textarea name="text_body" rows="6" style="width:100%;padding:10px 12px;border:1.5px solid #cbdad2;border-radius:8px;font-size:13px;margin-top:6px">{val('text_body')}</textarea>
    </label>
  </div>
</div>

<div class="camp-bottom-bar">
  <a class="btn" href="/admin/templates">Cancel</a>
  <button class="btn primary" type="submit">Save Template</button>
</div>
</form>

<div class="camp-card" style="margin-top:20px">
  <h3 style="margin-bottom:12px">Version Revision History</h3>
  <div class="table-wrap">
    <table class="table" style="width:100%">
      <thead><tr><th>Version</th><th>Created At</th><th>Created By</th></tr></thead>
      <tbody>{version_rows}</tbody>
    </table>
  </div>
</div>

<script>
function insertTplVar(v) {{
  const ed = document.getElementById('tplHtml');
  if (!ed) return;
  const pos = ed.selectionStart || ed.value.length;
  ed.value = ed.value.slice(0, pos) + v + ed.value.slice(pos);
  ed.focus();
}}
</script>"""
        return self.admin_shell("Email Template Editor",body,"Email Templates")


    def campaign_form(self,cid=None):
        c=db()
        r=c.execute("SELECT * FROM campaigns WHERE id=?",(cid,)).fetchone() if cid else None
        smtps=c.execute("SELECT id,name,provider,from_email,host,port,security FROM smtp_profiles WHERE enabled=1 ORDER BY name").fetchall()
        lands=c.execute("SELECT id,name,template,version FROM landing_pages WHERE status='Enabled' ORDER BY id").fetchall()
        groups=c.execute("SELECT g.name,COUNT(r.id) members FROM groups_tbl g LEFT JOIN recipients r ON r.group_name=g.name GROUP BY g.name ORDER BY g.name").fetchall()
        total_recipients=c.execute("SELECT COUNT(*) n FROM recipients WHERE status!='Suppressed'").fetchone()["n"]
        templates=c.execute("SELECT template,name,category,difficulty,subject,brand FROM template_library ORDER BY CASE WHEN brand='Zoom' THEN 0 WHEN brand='Microsoft Office 365' THEN 1 WHEN brand='Google Workspace' THEN 2 WHEN brand='Amazon Web Services (AWS)' THEN 3 ELSE 4 END, brand, name").fetchall()
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
        timezone=esc(r["timezone"]) if r and r["timezone"] else "Asia/Dhaka"
        business_days=esc(r["business_days"]) if r and r["business_days"] else "Sun,Mon,Tue,Wed,Thu"
        window_start=esc(r["window_start"]) if r and r["window_start"] else "09:00"
        window_end=esc(r["window_end"]) if r and r["window_end"] else "17:00"
        batch_size=str(r["batch_size"] or 50) if r else "50"
        rate=str(r["rate_per_minute"] or 60) if r else "60"
        retry_max=str(r["retry_max"] if r and r["retry_max"] is not None else 2)
        retry_backoff=str(r["retry_backoff_seconds"] if r and r["retry_backoff_seconds"] is not None else 5)

        if templates:
            by_brand={}
            for t in templates:
                b=t["brand"] or "General"
                by_brand.setdefault(b,[]).append(t)
            opts_parts=[]
            for bname,tlist in by_brand.items():
                opts_parts.append('<optgroup label="%s">'%esc(bname))
                for t in tlist:
                    sel="selected" if str(t["template"])==template else ""
                    opts_parts.append('<option value="%s" data-name="%s" data-diff="%s" data-subject="%s" %s>%s · %s (%s)</option>'%(
                        esc(t["template"]),esc(t["name"]),esc(t["difficulty"]),esc(t["subject"] or ""),sel,
                        esc(t["brand"] or "General"),esc(t["name"]),esc(t["difficulty"])
                    ))
                opts_parts.append('</optgroup>')
            opts="".join(opts_parts)
        else:
            opts="".join('<option value="%s" data-name="Template %s" data-diff="Medium" %s>Template %s</option>'%(i,i,"selected" if str(i)==template else "",i) for i in range(1,11))

        smtp_opts='<option value="">-- Select SMTP provider --</option>'+"".join('<option value="%s" %s>%s (%s · %s)</option>'%(x["id"],"selected" if str(x["id"])==smtp_id else "",esc(x["name"]),esc(x["provider"]),esc(x["from_email"])) for x in smtps)
        land_opts='<option value="">-- Select landing page --</option>'+"".join('<option value="%s" data-template="%s" %s>%s (Template %s · v%s)</option>'%(x["id"],esc(x["template"]),"selected" if str(x["id"])==landing_id else "",esc(x["name"]),esc(x["template"]),x["version"] or 1) for x in lands)
        group_opts='<option value="" data-count="%s" %s>All Active Recipients (%s members)</option>'%(total_recipients,"selected" if not saved_group else "",total_recipients)+"".join('<option value="%s" data-count="%s" %s>%s (%s members)</option>'%(esc(x["name"]),x["members"],"selected" if x["name"]==saved_group else "",esc(x["name"]),x["members"]) for x in groups)
        tz_opts="".join('<option value="%s" %s>%s</option>'%(z,"selected" if z==timezone else "",z) for z in ("Asia/Dhaka","UTC","Asia/Kolkata","Asia/Singapore","Asia/Dubai","Europe/London","America/New_York","America/Los_Angeles","Europe/Berlin","Asia/Tokyo"))
        stats="".join('<option value="%s" %s>%s</option>'%(x,"selected" if x==status else "",x) for x in ("Draft","Scheduled","Active","Paused","Completed","Cancelled","Expired"))

        cur_days=set(d.strip() for d in business_days.split(",") if d.strip())
        day_chips="".join('<button type="button" class="day-chip%s" data-day="%s" onclick="toggleDay(\'%s\')">%s</button>'%(" active" if d in cur_days else "",d,d,d) for d in ("Sun","Mon","Tue","Wed","Thu","Fri","Sat"))

        status_class={"Draft":"status-draft","Active":"status-active","Scheduled":"status-scheduled","Paused":"status-paused","Completed":"status-completed","Cancelled":"status-cancelled","Expired":"status-expired"}.get(status,"status-draft")

        top_actions='<a class="btn" href="/admin/campaigns">Cancel</a> '
        top_actions+='<button class="btn" type="submit" form="campForm" name="action_mode" value="draft" style="display:inline-flex;align-items:center;gap:6px;font-weight:700;background:#ffffff;border:1.5px solid #cbdad2;color:#183227">📝 Save as Draft</button> '
        top_actions+='<button class="btn primary" type="submit" form="campForm" name="action_mode" value="save" style="display:inline-flex;align-items:center;gap:6px;font-weight:700">💾 %s</button> '%("Save Changes" if cid else "Save Campaign")
        if cid:
            top_actions+='<a class="btn" href="/admin/campaigns/test-send?id=%s">✉️ Test Send</a> '%cid
            top_actions+='<form method="post" action="/admin/campaigns/control" style="display:inline-flex;gap:6px"><input type="hidden" name="id" value="%s"><button class="btn" name="action" value="pause">⏸ Pause</button><button class="btn" name="action" value="resume">▶ Resume</button></form> '%cid
            top_actions+='<a class="btn primary" href="/admin/campaigns/launch?id=%s" style="background:#10b981;border-color:#10b981">🚀 Launch Campaign</a> '%cid
        else:
            top_actions+='<button class="btn primary" type="submit" form="campForm" name="action_mode" value="launch" style="background:#10b981;border-color:#10b981;display:inline-flex;align-items:center;gap:6px;font-weight:700">🚀 Save &amp; Launch</button>'

        body=f"""<div class="camp-editor">
<div class="camp-header">
  <div>
    <div class="camp-crumb"><a href="/admin/campaigns">Campaigns</a> <span>/</span> <span>{"Edit Campaign #"+str(cid) if cid else "New Campaign"}</span></div>
    <div class="camp-title-row">
      <h1>{"Edit" if r else "New"} Simulation Campaign</h1>
      <span class="camp-status-badge {status_class}" id="statusBadge">{status}</span>
    </div>
  </div>
  <div class="camp-actions" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
    {top_actions}
  </div>
</div>

<form id="campForm" method="post" action="/admin/campaigns/save">
<input type="hidden" name="id" value="{cid or ''}">
<input type="hidden" name="business_days" id="business_days_input" value="{business_days}">

<div class="camp-grid">
  <div class="camp-main">

    <!-- Card 1: Identity & Target Audience -->
    <div class="camp-card">
      <div class="camp-card-header">
        <div class="camp-icon">👥</div>
        <div class="camp-card-title">
          <h3>Campaign Identity &amp; Target Audience</h3>
          <p>Define the core simulation metadata, target group, and lifecycle status.</p>
        </div>
      </div>
      <div class="camp-fields">
        <div class="camp-label col-full">
          <span>Campaign Name <b style="color:#a12d2d">*</b></span>
          <input name="name" value="{name}" placeholder="e.g. Q4 2026 Enterprise Phishing Simulation Drill" required maxlength="150" autocomplete="off">
          <div class="field-hint">A clear, descriptive title visible in administrative reporting and audit logs.</div>
        </div>
        <div class="camp-label col-full">
          <span>Target Recipient Group</span>
          <select name="group_name" id="groupSelect" onchange="syncAudience()">
            {group_opts}
          </select>
          <div class="field-hint">Select a departmental employee group or target all active recipients.</div>
        </div>
        <div class="camp-label col-full">
          <span>Simulation Lifecycle Status</span>
          <div class="status-segmented-control" style="display:grid;grid-template-columns:repeat(auto-fit, minmax(210px, 1fr));gap:12px;margin-top:6px">
            <div class="status-card" id="cardDraft" onclick="selectStatus('Draft')" style="cursor:pointer;border:2px solid {'#087b59' if status=='Draft' else '#d9e7e0'};border-radius:10px;padding:12px 14px;background:{'#f0f8f4' if status=='Draft' else '#ffffff'};display:flex;flex-direction:column;gap:5px;transition:all 0.15s ease">
              <div style="display:flex;justify-content:space-between;align-items:center">
                <span style="font-weight:800;font-size:13px;color:#122b20">📝 Draft (Safe Mode)</span>
                <span class="camp-status-badge status-draft" style="font-size:10px">Draft</span>
              </div>
              <span style="font-size:11.5px;color:#557265;line-height:1.4">Safe to configure &amp; test. No simulated emails are sent to targets.</span>
            </div>

            <div class="status-card" id="cardActive" onclick="selectStatus('Active')" style="cursor:pointer;border:2px solid {'#087b59' if status=='Active' else '#d9e7e0'};border-radius:10px;padding:12px 14px;background:{'#f0f8f4' if status=='Active' else '#ffffff'};display:flex;flex-direction:column;gap:5px;transition:all 0.15s ease">
              <div style="display:flex;justify-content:space-between;align-items:center">
                <span style="font-weight:800;font-size:13px;color:#122b20">⚡ Active (Live Simulation)</span>
                <span class="camp-status-badge status-active" style="font-size:10px">Active</span>
              </div>
              <span style="font-size:11.5px;color:#557265;line-height:1.4">Ready for deployment. Dispatches drills according to sending window.</span>
            </div>

            <div class="status-card" id="cardScheduled" onclick="selectStatus('Scheduled')" style="cursor:pointer;border:2px solid {'#087b59' if status=='Scheduled' else '#d9e7e0'};border-radius:10px;padding:12px 14px;background:{'#f0f8f4' if status=='Scheduled' else '#ffffff'};display:flex;flex-direction:column;gap:5px;transition:all 0.15s ease">
              <div style="display:flex;justify-content:space-between;align-items:center">
                <span style="font-weight:800;font-size:13px;color:#122b20">⏰ Scheduled (Future)</span>
                <span class="camp-status-badge status-scheduled" style="font-size:10px">Scheduled</span>
              </div>
              <span style="font-size:11.5px;color:#557265;line-height:1.4">Waits until the specified Launch Date &amp; Time before sending.</span>
            </div>
          </div>
          <select name="status" id="statusSelect" onchange="syncStatusBadge()" style="display:none">
            {stats}
          </select>
          <div class="field-hint" style="margin-top:6px">Select how you want this simulation staged. You can also click <b>Save as Draft</b> directly from the top or bottom action buttons.</div>
        </div>
      </div>
    </div>

    <!-- Card 2: Attack Vector & Simulation Payload -->
    <div class="camp-card">
      <div class="camp-card-header">
        <div class="camp-icon">🎯</div>
        <div class="camp-card-title">
          <h3>Simulation Scenario &amp; Attack Vector</h3>
          <p>Select the simulated email template, customize the subject line, and attach the educational landing page.</p>
        </div>
      </div>
      <div class="camp-fields">
        <div class="camp-label col-full">
          <span>Email Template (Phishing Scenario) <b style="color:#a12d2d">*</b></span>
          <select name="template" id="templateSelect" onchange="syncTemplatePreview()">
            {opts}
          </select>
          <div class="preview-link-wrap">
            <a id="templatePreviewBtn" class="preview-link" target="_blank" href="/admin/templates/preview?id={template}">
              <span>👁️</span> Preview Template in New Tab
            </a>
          </div>
        </div>
        <div class="camp-label col-full">
          <span>Email Subject Line <b style="color:#a12d2d">*</b></span>
          <input name="subject" id="subjectInput" value="{subject}" maxlength="250" required placeholder="e.g. Urgent: Account Verification Required">
          <div class="token-row">
            <small>Insert personalization tags:</small>
            <button type="button" class="token-chip" onclick="insertToken('{{{{name}}}}')">{{name}}</button>
            <button type="button" class="token-chip" onclick="insertToken('{{{{email}}}}')">{{email}}</button>
            <button type="button" class="token-chip" onclick="insertToken('{{{{employee_id}}}}')">{{employee_id}}</button>
            <button type="button" class="token-chip" onclick="insertToken('{{{{department}}}}')">{{department}}</button>
          </div>
        </div>
        <div class="camp-label col-full">
          <span>Landing Page (Simulation / Training Page) <b style="color:#a12d2d">*</b></span>
          <select name="landing_page_id" id="landingSelect" required onchange="syncLandingPreview()">
            {land_opts}
          </select>
          <div class="preview-link-wrap">
            <a id="landingPreviewBtn" class="preview-link" target="_blank" href="/admin/landing-pages/preview?id={landing_id or '1'}">
              <span>🔗</span> Preview Landing Page in New Tab
            </a>
          </div>
        </div>
      </div>
    </div>

    <!-- Card 3: Mail Delivery Infrastructure -->
    <div class="camp-card">
      <div class="camp-card-header">
        <div class="camp-icon">📨</div>
        <div class="camp-card-title">
          <h3>Mail Delivery Infrastructure (SMTP Provider)</h3>
          <p>The authorized corporate SMTP relay or external provider used to deliver simulation emails.</p>
        </div>
      </div>
      <div class="camp-fields">
        <div class="camp-label col-full">
          <span>SMTP Provider Profile <b style="color:#a12d2d">*</b></span>
          <select name="smtp_profile_id" id="smtpSelect" required onchange="syncSmtpInfo()">
            {smtp_opts}
          </select>
          <div class="preview-link-wrap" style="display:flex;gap:12px;align-items:center;margin-top:8px;">
            <a class="preview-link" href="/admin/smtp" target="_blank">⚙️ Manage SMTP Providers ↗</a>
            <span style="font-size:11.5px;color:#556c62">Credentials are stored encrypted at rest.</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Card 4: Schedule & Smart Sending Window -->
    <div class="camp-card">
      <div class="camp-card-header">
        <div class="camp-icon">⏰</div>
        <div class="camp-card-title">
          <h3>Schedule &amp; Smart Delivery Window</h3>
          <p>Align simulation email delivery with actual business hours to ensure maximum realism and avoid after-hours disruption.</p>
        </div>
      </div>
      <div class="camp-fields">
        <div class="camp-label">
          <span>Launch Date &amp; Time</span>
          <input type="datetime-local" name="launch_at" id="launchAt" value="{launch}">
          <div class="field-hint">Leave blank to begin sending immediately once the campaign is launched.</div>
        </div>
        <div class="camp-label">
          <span>Send-By Deadline</span>
          <input type="datetime-local" name="send_by" id="sendBy" value="{send_by}">
          <div class="field-hint">Pending emails will not be dispatched after this date and time.</div>
        </div>
        <div class="camp-label col-full">
          <span>Delivery Timezone</span>
          <select name="timezone" id="tzSelect" onchange="syncSummary()">
            {tz_opts}
          </select>
          <div class="field-hint">Business days and sending hours are evaluated according to this timezone.</div>
        </div>
        <div class="camp-label col-full">
          <span>Allowed Delivery Days</span>
          <div class="day-chips" id="dayChips">
            {day_chips}
          </div>
          <div class="preset-btns">
            <small style="color:#556c62;align-self:center;font-size:11px">Presets:</small>
            <button type="button" class="preset-btn" onclick="setPresetDays(['Sun','Mon','Tue','Wed','Thu'])">Workdays (Sun–Thu)</button>
            <button type="button" class="preset-btn" onclick="setPresetDays(['Mon','Tue','Wed','Thu','Fri'])">Workdays (Mon–Fri)</button>
            <button type="button" class="preset-btn" onclick="setPresetDays(['Sun','Mon','Tue','Wed','Thu','Fri','Sat'])">All 7 Days</button>
          </div>
        </div>
        <div class="camp-label col-full">
          <span>Sending Window (Working Hours)</span>
          <div class="time-range-wrap">
            <div style="flex:1">
              <input type="time" name="window_start" id="windowStart" value="{window_start}" required>
              <div class="field-hint">Window Start</div>
            </div>
            <span class="time-range-sep">—</span>
            <div style="flex:1">
              <input type="time" name="window_end" id="windowEnd" value="{window_end}" required>
              <div class="field-hint">Window End</div>
            </div>
          </div>
          <div class="field-hint" style="margin-top:6px">Emails will pause automatically outside this time window. Window End must be after Window Start.</div>
        </div>
      </div>
    </div>

    <!-- Card 5: Throttling & Anti-Spam Safeguards -->
    <div class="camp-card">
      <div class="camp-card-header">
        <div class="camp-icon">🛡️</div>
        <div class="camp-card-title">
          <h3>Throttling &amp; Anti-Spam Safeguards</h3>
          <p>Rate limiting protects your mail server from hitting spam traps or outbound relay throttling.</p>
        </div>
      </div>
      <div class="camp-fields">
        <div class="camp-label">
          <span>Batch Size (Emails per Cycle)</span>
          <input type="number" min="1" max="1000" name="batch_size" id="batchSize" value="{batch_size}" required>
          <div class="field-hint">Number of emails picked up and processed in each queue worker run.</div>
        </div>
        <div class="camp-label">
          <span>Rate Limit (Emails / Minute)</span>
          <input type="number" min="1" max="1000" name="rate_per_minute" id="rateLimit" value="{rate}" required oninput="syncSummary()">
          <div class="field-hint">Paces outbound traffic to avoid triggering tenant spam rate limits.</div>
        </div>
        <div class="camp-label">
          <span>Max Retry Attempts</span>
          <input type="number" min="0" max="5" name="retry_max" value="{retry_max}" required>
          <div class="field-hint">Retries for transient SMTP connection errors (4xx codes).</div>
        </div>
        <div class="camp-label">
          <span>Retry Backoff (Seconds)</span>
          <input type="number" min="1" max="300" name="retry_backoff_seconds" value="{retry_backoff}" required>
          <div class="field-hint">Delay before retrying a temporarily deferred delivery.</div>
        </div>
      </div>
    </div>

    <!-- Bottom Actions -->
    <div class="camp-bottom-bar" style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;background:#ffffff;padding:16px 20px;border-radius:12px;border:1px solid #dce7e2;margin-top:20px">
      <div style="font-size:12.5px;color:#557265;display:flex;align-items:center;gap:6px">
        <span>💡</span> <span><b>Pro-Tip:</b> Use <b>Save as Draft</b> to stage and verify recipients safely before triggering live simulation delivery.</span>
      </div>
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <a class="btn" href="/admin/campaigns">Cancel</a>
        <button class="btn" type="submit" form="campForm" name="action_mode" value="draft" style="font-weight:700;background:#ffffff;border:1.5px solid #cbdad2;color:#183227">📝 Save as Draft</button>
        <button class="btn primary" type="submit" form="campForm" name="action_mode" value="save" style="font-weight:700">💾 {"Save Changes" if cid else "Save Campaign"}</button>
        {('<button class="btn primary" type="submit" form="campForm" name="action_mode" value="launch" style="background:#10b981;border-color:#10b981;font-weight:700">🚀 Save &amp; Launch</button>') if not cid else ('<a class="btn primary" href="/admin/campaigns/launch?id='+str(cid)+'" style="background:#10b981;border-color:#10b981;font-weight:700">🚀 Launch Campaign</a>')}
      </div>
    </div>

  </div>

  <!-- Sidebar -->
  <div class="camp-sidebar">
    <div class="camp-sidebar-sticky">

      <!-- Summary Widget -->
      <div class="camp-card" style="margin-bottom:0">
        <div class="camp-card-header" style="margin-bottom:14px;padding-bottom:12px">
          <div class="camp-icon" style="background:#e8f4ef;color:#087b59">📊</div>
          <div class="camp-card-title">
            <h3>Simulation Summary</h3>
            <p>Live calculated metrics for this campaign.</p>
          </div>
        </div>
        <div class="summary-stat">
          <span>Target Audience</span>
          <b id="sumAudience">0 recipients</b>
        </div>
        <div class="summary-stat">
          <span>Delivery Rate</span>
          <b id="sumPace">{rate} emails/min</b>
        </div>
        <div class="summary-stat">
          <span>Est. Delivery Duration</span>
          <b id="sumEstTime">~1 min</b>
        </div>
        <div class="summary-stat">
          <span>Selected Timezone</span>
          <b id="sumTz" style="font-size:11.5px">{timezone}</b>
        </div>

        <div style="margin-top:16px;padding-top:14px;border-top:1px solid #edf3f0">
          <div style="font-size:12px;font-weight:700;color:#12251e;margin-bottom:8px">Campaign Readiness</div>
          <ul class="checklist">
            <li><span class="checklist-icon">✓</span> <span>Profile &amp; Audience defined</span></li>
            <li><span class="checklist-icon">✓</span> <span>Simulation template matched</span></li>
            <li><span class="checklist-icon">✓</span> <span>Encrypted SMTP profile attached</span></li>
            <li><span class="checklist-icon">✓</span> <span>Safe sending window active</span></li>
          </ul>
        </div>
      </div>

      <!-- Enterprise Best Practices -->
      <div class="camp-card" style="background:#f9fbf9;border-color:#d7e7df;margin-bottom:0">
        <div style="display:flex;align-items:center;gap:8px;font-size:13px;font-weight:700;color:#184a36;margin-bottom:8px">
          <span>💡</span> Enterprise Best Practices
        </div>
        <p style="font-size:12px;color:#496155;line-height:1.55;margin:0 0 10px 0">
          For Microsoft 365 and Google Workspace, maintain a rate limit under <b>60 emails/min</b> to avoid tenant-level outbound throttling.
        </p>
        <p style="font-size:12px;color:#496155;line-height:1.55;margin:0">
          Ensure sending hours match employee working hours so click-through and reporting metrics represent realistic engagement.
        </p>
      </div>

    </div>
  </div>
</div>
</form>
</div>

<style>
.camp-editor {{ max-width: 1400px; margin: 0 auto; }}
.camp-header {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px; margin-bottom: 24px; padding-bottom: 18px; border-bottom: 1px solid #e0e9e4; }}
.camp-crumb {{ display: flex; align-items: center; gap: 8px; font-size: 13px; color: #556c62; margin-bottom: 6px; }}
.camp-crumb a {{ color: #087b59; text-decoration: none; font-weight: 600; }}
.camp-title-row {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
.camp-title-row h1 {{ margin: 0; font-size: 26px; font-weight: 800; color: #12251e; letter-spacing: -0.02em; }}
.camp-status-badge {{ padding: 4px 10px; border-radius: 999px; font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.04em; }}
.status-draft {{ background: #eef2f0; color: #4b6157; border: 1px solid #d4ded9; }}
.status-active {{ background: #dff6ec; color: #087b59; border: 1px solid #a3e4cb; }}
.status-scheduled {{ background: #e0f2fe; color: #0369a1; border: 1px solid #bae6fd; }}
.status-paused {{ background: #fef3c7; color: #92400e; border: 1px solid #fde68a; }}
.status-completed {{ background: #f3e8ff; color: #6b21a8; border: 1px solid #e9d5ff; }}
.status-cancelled {{ background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }}
.status-expired {{ background: #f1f5f9; color: #475569; border: 1px solid #cbd5e1; }}
.camp-actions {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}

.camp-grid {{ display: grid; grid-template-columns: minmax(0, 1fr) 340px; gap: 24px; align-items: start; }}
@media (max-width: 1040px) {{ .camp-grid {{ grid-template-columns: 1fr; }} }}

.camp-card {{ background: #ffffff; border: 1px solid #e2ebe6; border-radius: 14px; padding: 22px 24px; margin-bottom: 22px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04); }}
.camp-card-header {{ display: flex; align-items: flex-start; gap: 14px; margin-bottom: 20px; padding-bottom: 14px; border-bottom: 1px solid #edf3f0; }}
.camp-icon {{ width: 38px; height: 38px; border-radius: 10px; background: #edf7f3; color: #087b59; display: flex; align-items: center; justify-content: center; font-size: 18px; flex-shrink: 0; }}
.camp-card-title h3 {{ margin: 0 0 3px 0; font-size: 16px; font-weight: 700; color: #12251e; }}
.camp-card-title p {{ margin: 0; font-size: 12.5px; color: #556c62; }}

.camp-fields {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 18px 22px; }}
.col-full {{ grid-column: span 2; }}
@media (max-width: 640px) {{ .camp-fields {{ grid-template-columns: 1fr; }} .col-full {{ grid-column: span 1; }} }}

.camp-label {{ display: flex; flex-direction: column; gap: 7px; font-size: 13px; font-weight: 650; color: #1a3328; }}
.camp-label input, .camp-label select {{ width: 100%; min-height: 44px; border: 1.5px solid #cbdad2; border-radius: 9px; padding: 10px 13px; background: #ffffff; color: #12251e; font-size: 13.5px; transition: all 0.15s ease; box-sizing: border-box; }}
.camp-label input:focus, .camp-label select:focus {{ outline: none; border-color: #087b59; box-shadow: 0 0 0 3px rgba(8, 123, 89, 0.15); }}
.field-hint {{ font-size: 11.5px; color: #5c746a; font-weight: 400; margin-top: 2px; }}

.token-row {{ display: flex; align-items: center; gap: 6px; flex-wrap: wrap; margin-top: 5px; }}
.token-chip {{ padding: 3px 8px; border-radius: 6px; background: #edf6f2; border: 1px solid #cfe0d8; color: #087b59; font-size: 11px; font-weight: 600; cursor: pointer; transition: background 0.15s; }}
.token-chip:hover {{ background: #ddf0e8; }}

.preview-link-wrap {{ margin-top: 6px; }}
.preview-link {{ display: inline-flex; align-items: center; gap: 5px; font-size: 12px; font-weight: 650; color: #087b59; text-decoration: none; padding: 4px 8px; background: #f0f7f4; border-radius: 6px; transition: background 0.15s; }}
.preview-link:hover {{ background: #e2f1eb; }}

.day-chips {{ display: flex; gap: 8px; flex-wrap: wrap; margin-top: 8px; }}
.day-chip {{ flex: 1; min-width: 44px; padding: 10px 6px; text-align: center; border-radius: 8px; border: 1.5px solid #cfe0d8; background: #f8faf9; color: #2b4539; font-size: 12.5px; font-weight: 700; cursor: pointer; transition: all 0.15s ease; user-select: none; }}
.day-chip:hover {{ border-color: #087b59; background: #edf7f3; }}
.day-chip.active {{ background: #087b59; color: #ffffff; border-color: #087b59; box-shadow: 0 2px 6px rgba(8, 123, 89, 0.25); }}

.preset-btns {{ display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; }}
.preset-btn {{ font-size: 11px; padding: 4px 9px; border-radius: 6px; border: 1px dashed #b7cec4; background: #ffffff; color: #204c3b; cursor: pointer; font-weight: 600; transition: background 0.15s; }}
.preset-btn:hover {{ background: #f0f7f4; border-color: #087b59; }}

.time-range-wrap {{ display: flex; align-items: center; gap: 12px; }}
.time-range-sep {{ font-size: 14px; font-weight: 700; color: #6a8277; margin-top: -12px; }}

.camp-sidebar-sticky {{ position: sticky; top: 24px; display: flex; flex-direction: column; gap: 20px; }}
.summary-stat {{ display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid #edf3f0; font-size: 13px; }}
.summary-stat:last-child {{ border-bottom: none; }}
.summary-stat span {{ color: #556c62; }}
.summary-stat b {{ color: #12251e; font-weight: 700; }}

.checklist {{ list-style: none; padding: 0; margin: 14px 0 0 0; font-size: 12.5px; }}
.checklist li {{ display: flex; align-items: center; gap: 8px; margin-bottom: 9px; color: #3b5247; }}
.checklist-icon {{ width: 18px; height: 18px; border-radius: 50%; background: #dff6ec; color: #087b59; display: inline-flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 800; }}

.camp-bottom-bar {{ display: flex; justify-content: flex-end; align-items: center; gap: 12px; padding: 20px 24px; background: #ffffff; border: 1px solid #e2ebe6; border-radius: 14px; box-shadow: 0 2px 8px rgba(0,0,0,0.04); margin-top: 24px; }}
</style>

<script>
const ALL_DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
function toggleDay(d) {{
  const chip = document.querySelector(`.day-chip[data-day="${{d}}"]`);
  if (chip) chip.classList.toggle('active');
  updateDaysInput();
}}

function setPresetDays(days) {{
  document.querySelectorAll('.day-chip').forEach(c => {{
    c.classList.toggle('active', days.includes(c.getAttribute('data-day')));
  }});
  updateDaysInput();
}}

function updateDaysInput() {{
  const activeDays = [];
  ALL_DAYS.forEach(d => {{
    const c = document.querySelector(`.day-chip[data-day="${{d}}"]`);
    if (c && c.classList.contains('active')) activeDays.push(d);
  }});
  document.getElementById('business_days_input').value = activeDays.join(',');
}}

function insertToken(token) {{
  const input = document.getElementById('subjectInput');
  const pos = input.selectionStart || input.value.length;
  input.value = input.value.slice(0, pos) + token + input.value.slice(pos);
  input.focus();
}}

function syncTemplatePreview() {{
  const sel = document.getElementById('templateSelect');
  const val = sel.value;
  const opt = sel.options[sel.selectedIndex];
  const btn = document.getElementById('templatePreviewBtn');
  if (btn && val) btn.href = '/admin/templates/preview?id=' + encodeURIComponent(val);
  const subjInput = document.getElementById('subjectInput');
  if (opt && opt.dataset.subject && (!subjInput.value || subjInput.value === 'Security Awareness Simulation')) {{
    subjInput.value = opt.dataset.subject;
  }}
  syncSummary();
}}

function syncLandingPreview() {{
  const sel = document.getElementById('landingSelect');
  const val = sel.value;
  const btn = document.getElementById('landingPreviewBtn');
  if (btn) btn.href = '/admin/landing-pages/preview?id=' + (val || '1');
}}

function selectStatus(st) {{
  const sel = document.getElementById('statusSelect');
  if (sel) {{
    sel.value = st;
    syncStatusBadge();
  }}
}}

function syncStatusBadge() {{
  const sel = document.getElementById('statusSelect');
  const badge = document.getElementById('statusBadge');
  if (badge && sel) {{
    badge.textContent = sel.value;
    badge.className = 'camp-status-badge status-' + sel.value.toLowerCase();
  }}
  const curVal = sel ? sel.value : 'Draft';
  ['Draft', 'Active', 'Scheduled'].forEach(function(s) {{
    const card = document.getElementById('card' + s);
    if (card) {{
      if (curVal === s) {{
        card.style.border = '2px solid #087b59';
        card.style.background = '#f0f8f4';
      }} else {{
        card.style.border = '2px solid #d9e7e0';
        card.style.background = '#ffffff';
      }}
    }}
  }});
}}

function syncAudience() {{
  const sel = document.getElementById('groupSelect');
  const opt = sel.options[sel.selectedIndex];
  const count = parseInt(opt ? opt.getAttribute('data-count') : 0) || 0;
  const targetEl = document.getElementById('sumAudience');
  if (targetEl) targetEl.textContent = count + ' recipients';
  syncSummary();
}}

function syncSummary() {{
  const groupSel = document.getElementById('groupSelect');
  const opt = groupSel ? groupSel.options[groupSel.selectedIndex] : null;
  const count = parseInt(opt ? opt.getAttribute('data-count') : 0) || 0;

  const rateInput = document.getElementById('rateLimit');
  const rate = Math.max(1, parseInt(rateInput ? rateInput.value : 60) || 60);

  const durationMin = Math.max(1, Math.ceil(count / rate));
  const durEl = document.getElementById('sumEstTime');
  if (durEl) durEl.textContent = '~' + durationMin + ' min' + (durationMin > 1 ? 's' : '');

  const paceEl = document.getElementById('sumPace');
  if (paceEl) paceEl.textContent = rate + ' emails/min';

  const tzSel = document.getElementById('tzSelect');
  const tzEl = document.getElementById('sumTz');
  if (tzEl && tzSel) tzEl.textContent = tzSel.value;
}}

document.addEventListener('DOMContentLoaded', function() {{
  syncAudience();
  syncTemplatePreview();
  syncLandingPreview();
  syncStatusBadge();
}});
syncAudience();
</script>"""
        return self.admin_shell("Campaign",body,"Campaigns")

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        p=urlparse(self.path); path=p.path; ip=self.client_address[0]; ua=self.headers.get("User-Agent","")
        if path.startswith("/admin/") and path not in ("/admin/login",):
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            if path!="/admin/logout" and not self.permission_allowed(path,"GET",query=p.query): return self.sendbody(403,"Insufficient role permission","text/plain")
        if path=="/admin":
            if not self.auth(): return self.sendbody(200,self.login_page())
            return self.sendbody(302,b"",extra={"Location":"/"})
        if path=="/":
            if not self.auth(): return self.sendbody(200,self.login_page())
            return self.sendbody(200,self.dashboard())
        if path=="/dashboard":
            if not self.auth(): return self.sendbody(302,b"",extra={"Location":"/admin"})
            return self.sendbody(302,b"",extra={"Location":"/"})
        if path=="/admin/logout":
            c=cookies.SimpleCookie(self.headers.get("Cookie","")); s=c.get("admin_session")
            if s: SESSIONS.pop(s.value,None)
            return self.sendbody(302,b"",extra={"Location":"/admin","Set-Cookie":"admin_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"})
        if path=="/admin.csv":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            if not self.permission_allowed(path,"GET",query=p.query): return self.sendbody(403,"Insufficient role permission","text/plain")
            c=db(); rows=c.execute("SELECT ts,event,template,ip,name,employee_id,email,mobile,card_type,user_agent FROM events ORDER BY id DESC").fetchall(); c.close()
            out=io.StringIO(); w=csv.writer(out)
            w.writerow(["timestamp","event","template","local_ip","name","employee_id","email","mobile","card_type","user_agent"])
            for r in rows:
                w.writerow([r["ts"],r["event"],r["template"],r["ip"],r["name"] or "",r["employee_id"] or "",r["email"] or "",r["mobile"] or "",r["card_type"] or "",r["user_agent"] or ""])
            return self.sendbody(200,out.getvalue(),"text/csv",{"Content-Disposition":"attachment; filename=phish-simulation.csv"})
        if path in ("/admin/campaigns","/admin/templates","/admin/landing-pages","/admin/smtp","/admin/training","/admin/recipients","/admin/recipients/new","/admin/groups","/admin/users","/admin/reports","/admin/reports.pdf","/admin/risk","/admin/exports","/admin/settings","/admin/audit","/admin/admins"):
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            if not self.permission_allowed(path,"GET",query=p.query): return self.sendbody(403,"Insufficient role permission","text/plain")
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
            if path=="/admin/recipients" and parse_qs(p.query).get("id",[None])[0]:
                return self.sendbody(200,self.recipient_profile_form(parse_qs(p.query).get("id",[None])[0]))
            if path=="/admin/recipients/new":
                return self.sendbody(200,self.recipient_profile_form("new"))
        if path=="/admin/landing-pages/preview":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            lid=parse_qs(p.query).get("id",[""])[0]
            c=db(); row=c.execute("SELECT * FROM landing_pages WHERE id=?",(lid,)).fetchone(); c.close()
            if not row: return self.sendbody(404,"Landing page not found","text/plain")
            ok,msg=validate_landing_html(row["html_body"] or "")
            if not ok: return self.sendbody(400,msg,"text/plain")
            return self.sendbody(200,row["html_body"] or "<h1>Empty landing page</h1>",extra={"X-Frame-Options":"SAMEORIGIN"})
        if path=="/admin/templates/preview":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            tid=parse_qs(p.query).get("id",[""])[0]
            mode=parse_qs(p.query).get("mode",["realistic"])[0]
            c=db(); row=c.execute("SELECT * FROM template_library WHERE template=?",(tid,)).fetchone(); c.close()
            if not row:
                for cand in (os.path.join(TEMPLATES,tid+".html"), os.path.join(TEMPLATES,"email",tid+".html")):
                    if os.path.isfile(cand):
                        with open(cand,"r",encoding="utf-8",errors="ignore") as f:
                            html_content=f.read()
                        break
                else:
                    return self.sendbody(404,"Template not found","text/plain")
                brand="Security Awareness"
            else:
                html_content=row["html_body"] or ""
                brand=row["brand"] or "Security Awareness"
            mock_recipient={
                "name":"John Doe",
                "first_name":"John",
                "last_name":"Doe",
                "email":"john.doe@enterprise.com",
                "employee_id":"EMP-1042",
                "department":"Finance & Operations",
                "designation":"Lead Security Analyst",
                "location":"Dhaka HQ",
                "manager":"Jane Smith",
                "language":"English",
                "timezone":"Asia/Dhaka"
            }
            mock_campaign={"name":"Security Awareness Simulation Drill","brand":brand}
            mock_links={
                "tracking_link":"#preview-clicked-tracking-link",
                "report_link":"#preview-report-phish",
                "qr_link":"#preview-qr-scan"
            }
            rendered=render_template_variables(html_content,mock_recipient,mock_campaign,mock_links)
            if mode=="realistic":
                rendered=re.sub(r'style="background-color:\s*#[a-fA-F0-9]+;\s*outline:\s*3px solid\s*#[a-fA-F0-9]+"', 'style="background-color:transparent;outline:none"', rendered)
            return self.sendbody(200,rendered,"text/html; charset=utf-8",extra={"X-Frame-Options":"SAMEORIGIN"})
        if path in ("/admin/campaigns","/admin/templates","/admin/landing-pages","/admin/smtp","/admin/training","/admin/recipients","/admin/recipients/new","/admin/groups","/admin/users","/admin/reports","/admin/reports.pdf","/admin/risk","/admin/exports","/admin/settings","/admin/audit","/admin/admins"):
            return self.sendbody(200,self.feature_page(path,p.query))
        if path=="/admin/smtp/diagnostics":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            sid=parse_qs(p.query).get("id",[""])[0]
            c=db(); profile=c.execute("SELECT id,name,provider,host,port,security,from_name,from_email FROM smtp_profiles WHERE id=?",(sid,)).fetchone(); c.close()
            if not profile: return self.sendbody(404,"SMTP profile not found","text/plain")
            body='<h1>SMTP Connectivity Diagnostics</h1><div class="card"><p><b>%s</b> · %s · %s:%s · %s</p><p>Runs DNS → TCP → TLS → AUTH and optionally sends one diagnostic message. Secrets are never displayed.</p><form class="form" method="post" action="/admin/smtp/diagnostics"><input type="hidden" name="id" value="%s"><label>Diagnostic recipient email<input type="email" name="to_email" maxlength="254" placeholder="security@example.com"></label><div style="margin-top:14px;display:flex;gap:10px;align-items:center"><button class="btn primary">Run Diagnostics</button><a class="btn" href="/admin/smtp?id=%s">Edit Provider</a><a class="btn" href="/admin/smtp">Back to Providers</a></div></form></div>'%(esc(profile["name"]),esc(profile["provider"]),esc(profile["host"]),profile["port"],esc(profile["security"]),profile["id"],profile["id"])
            return self.sendbody(200,self.admin_shell("SMTP Diagnostics",body,"SMTP Providers"))
        if path=="/admin/landing-pages/new":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            return self.sendbody(200,self.landing_page_form(None))
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
        if path=="/admin/recipients/new":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            return self.sendbody(200,self.recipient_profile_form("new"))
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
            return self.sendbody(200,self.admin_shell("Template Test Send",body,"Email Templates"))
        if path=="/admin/campaigns/test-send":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            cid=parse_qs(p.query).get("id",[""])[0]
            c=db(); campaign=c.execute("SELECT c.*,s.name smtp_name,s.from_email,s.from_name,s.reply_to,s.username,s.password_enc,s.host,s.port,s.security,s.auth_method,s.oauth_token_enc FROM campaigns c JOIN smtp_profiles s ON s.id=c.smtp_profile_id WHERE c.id=?",(cid,)).fetchone(); c.close()
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
            req_host=self.headers.get("Host")
            errors=campaign_prelaunch_validation(campaign, req_host)
            current_base_url=get_public_base_url(req_host)
            checks="".join("<li style='color:%s'>%s</li>"%("#a12d2d" if e else "#087b59",esc(e or "Ready")) for e in errors) if errors else "<li style='color:#087b59'>All pre-launch checks passed.</li>"
            in_window=campaign_window_open(campaign)
            window_info='<p style="color:#087b59;font-size:12px;margin:5px 0">✓ Within configured sending window (%s, %s–%s %s)</p>'%(esc(campaign["business_days"] or "Sun,Mon,Tue,Wed,Thu"),esc(campaign["window_start"] or "09:00"),esc(campaign["window_end"] or "17:00"),esc(campaign["timezone"] or "Asia/Dhaka")) if in_window else '<p style="color:#b37400;font-size:12px;margin:5px 0">ℹ Currently outside configured sending window (%s, %s–%s %s). <b>Manual launch will dispatch immediately.</b></p>'%(esc(campaign["business_days"] or "Sun,Mon,Tue,Wed,Thu"),esc(campaign["window_start"] or "09:00"),esc(campaign["window_end"] or "17:00"),esc(campaign["timezone"] or "Asia/Dhaka"))
            body='<h1>Launch Campaign</h1><div class="card"><h3>%s</h3><p>Eligible recipients: <b>%s</b></p><p>Simulation Base URL: <code>%s</code> (<a href="/admin/settings">Change in Settings</a>)</p>%s<h3>Pre-launch validation</h3><ul>%s</ul><p>This action sends only to the configured authorized target scope.</p><p><a class="btn" href="/admin/campaigns/test-send?id=%s">Send Test Message</a></p><form class="form" method="post" action="/admin/campaigns/launch"><input type="hidden" name="id" value="%s"><label><input type="checkbox" name="confirm" value="YES" required%s> I confirm this campaign is authorized and the target list is approved.</label><button class="btn primary"%s>Launch Now</button></form></div>'%(esc(campaign["name"]),count,esc(current_base_url),window_info,checks,cid,cid,disabled,disabled)
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
        is_html_tpl = path.startswith("/") and path.endswith(".html") and path[1:-5].isdigit()
        is_landing_path = path in ("/landing", "/landing.html")
        if is_html_tpl or is_landing_path:
            q=parse_qs(p.query); token=q.get("t",[""])[0]; tr=resolve_tracking_token(token)
            campaign_id=str(tr["campaign_id"]) if tr else ""; recipient_id=str(tr["recipient_id"]) if tr else ""
            t=path[1:] if is_html_tpl else ""
            t_num=path[1:-5] if is_html_tpl else ""
            if not t_num and tr:
                c=db()
                crow=c.execute("SELECT c.template, c.landing_page_id, lp.template as lp_template FROM campaigns c LEFT JOIN landing_pages lp ON lp.id=c.landing_page_id WHERE c.id=?",(tr["campaign_id"],)).fetchone()
                c.close()
                if crow:
                    t_num=str(crow["lp_template"] or crow["template"] or "1")
                    t=f"{t_num}.html"
            if not t_num:
                t_num=q.get("id",["1"])[0]
                t=f"{t_num}.html"

            body=None
            c=db()
            lp_row=c.execute("SELECT html_body FROM landing_pages WHERE (template=? OR id=?) AND html_body IS NOT NULL AND length(html_body)>0",(t_num,t_num)).fetchone()
            c.close()
            if lp_row and lp_row["html_body"]:
                body=lp_row["html_body"]
            else:
                for cand in (os.path.join(TEMPLATES,t), os.path.join(os.path.dirname(__file__),"templates",t), os.path.join(TEMPLATES,f"{t_num}.html"), os.path.join(os.path.dirname(__file__),"templates",f"{t_num}.html")):
                    if os.path.isfile(cand):
                        try:
                            with open(cand,"rb") as f: body=f.read().decode("utf-8","replace")
                            break
                        except Exception:
                            pass

            if body is not None:
                tpl_key = str(t_num or t or "1")
                if tr:
                    c=db(); recrow=c.execute("SELECT * FROM recipients WHERE id=?",(recipient_id,)).fetchone(); c.close()
                    if is_bot_user_agent(ua):
                        record(ip,tpl_key,"bot_detected",ua=ua,campaign_id=campaign_id,recipient_id=recipient_id,token=token,email=recrow["email"] if recrow else "",name=recrow["name"] if recrow else "",employee_id=recrow["employee_id"] if recrow else "")
                    else:
                        record(ip,tpl_key,"click",ua=ua,campaign_id=campaign_id,recipient_id=recipient_id,token=token,email=recrow["email"] if recrow else "",name=recrow["name"] if recrow else "",employee_id=recrow["employee_id"] if recrow else "")
                else:
                    if is_bot_user_agent(ua):
                        record(ip,tpl_key,"bot_detected",ua=ua)
                    else:
                        record(ip,tpl_key,"click",ua=ua)
                access(ip,path,200)
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
                ck=cookies.SimpleCookie(); ck["admin_session"]=sid; ck["admin_session"]["HttpOnly"]=True; ck["admin_session"]["SameSite"]="Strict"; ck["admin_session"]["Max-Age"]="28800"; ck["admin_session"]["Path"]="/"
                if self.headers.get("X-Forwarded-Proto","").lower()=="https": ck["admin_session"]["Secure"]=True
                return self.sendbody(302,b"",extra={"Location":"/","Set-Cookie":ck["admin_session"].OutputString()})
            self.login_failed()
            return self.sendbody(401,self.login_page("Invalid username or password"))
        if p.path.startswith("/admin/") and p.path!="/admin/login" and not self.csrf_origin_ok():
            return self.sendbody(403,"CSRF validation failed","text/plain")
        if p.path.startswith("/admin/") and p.path!="/admin/login" and not self.permission_allowed(p.path,"POST",form,p.query):
            return self.sendbody(403,"Insufficient role permission","text/plain")
        if p.path=="/admin/landing-pages/save":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            lid=form.get("id",[""])[0].strip()
            name=form.get("name",[""])[0].strip()[:150]
            status=form.get("status",["Enabled"])[0]
            html_body=form.get("html_body",[""])[0]
            text_body=form.get("text_body",[""])[0][:200000]
            if status not in ("Enabled","Disabled"): status="Enabled"
            if not name: return self.sendbody(400,"Landing page name is required","text/plain")
            ok,msg=validate_landing_html(html_body)
            if not ok: return self.sendbody(400,msg,"text/plain")
            c=db()
            if lid:
                row=c.execute("SELECT * FROM landing_pages WHERE id=?",(lid,)).fetchone()
                if not row: c.close(); return self.sendbody(404,"Landing page not found","text/plain")
                next_version=(c.execute("SELECT COALESCE(MAX(version),0)+1 n FROM landing_page_versions WHERE landing_page_id=?",(lid,)).fetchone()["n"])
                c.execute("UPDATE landing_pages SET name=?,status=?,html_body=?,text_body=?,version=?,updated_at=? WHERE id=?",(name,status,html_body,text_body,next_version,now(),lid))
                c.execute("INSERT INTO landing_page_versions(landing_page_id,version,html_body,text_body,created_at,created_by) VALUES(?,?,?,?,?,?)",(lid,next_version,html_body,text_body,now(),ADMIN_USERNAME))
                c.commit(); c.close()
                audit(ADMIN_USERNAME,"LANDING_PAGE_UPDATE",f"landing_page={lid} version={next_version}",ip)
                return self.sendbody(302,b"",extra={"Location":"/admin/landing-pages?id="+str(lid)})
            else:
                c.execute("INSERT INTO landing_pages(name,template,status,html_body,text_body,version,created_at,updated_at) VALUES(?,?,'Enabled',?,?,1,?,?)",(name,"custom",html_body,text_body,now(),now()))
                new_id=c.execute("SELECT last_insert_rowid() id").fetchone()["id"]
                c.execute("INSERT INTO landing_page_versions(landing_page_id,version,html_body,text_body,created_at,created_by) VALUES(?,1,?,?,?,?)",(new_id,html_body,text_body,now(),ADMIN_USERNAME))
                c.commit(); c.close()
                audit(ADMIN_USERNAME,"LANDING_PAGE_CREATE",f"landing_page={new_id} name={name}",ip)
                return self.sendbody(302,b"",extra={"Location":"/admin/landing-pages?id="+str(new_id)})
        if p.path=="/admin/templates/save":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            tid=form.get("template",[""])[0][:64].strip()
            if not re.fullmatch(r"[a-zA-Z0-9_\-]{1,64}",tid):
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
        if p.path=="/admin/admins/review":
            admin=self.current_admin()
            if not admin or admin.get("role")!="Administrator":
                return self.sendbody(403,"Administrator role required","text/plain")
            aid=form.get("id",[""])[0]
            if not aid.isdigit():
                return self.sendbody(400,"Invalid administrator account","text/plain")
            c=db()
            target=c.execute("SELECT id,username,role,active FROM admins WHERE id=?",(int(aid),)).fetchone()
            if not target:
                c.close()
                return self.sendbody(404,"Administrator not found","text/plain")
            access_preview=self.resolve_role_access_preview(target["role"])
            counts=access_preview["risk_counts"]
            c.execute(
                """INSERT INTO access_reviews(
                    target_admin_id,target_username,target_role,target_active,
                    permission_count,normal_count,elevated_count,privileged_count,
                    reviewed_by,reviewed_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    target["id"],target["username"],target["role"],int(target["active"]),
                    access_preview["permission_count"],counts["normal"],counts["elevated"],counts["privileged"],
                    admin["username"],now()
                )
            )
            c.commit()
            c.close()
            audit(admin["username"],"ADMIN_ACCESS_REVIEW","target_username=%s target_role=%s target_active=%s permission_count=%s normal=%s elevated=%s privileged=%s"%
                  (target["username"],target["role"],bool(target["active"]),access_preview["permission_count"],counts["normal"],counts["elevated"],counts["privileged"]),ip)
            return self.sendbody(302,b"",extra={"Location":"/admin/admins?id=%s"%aid})

        if p.path=="/admin/admins/create":
            admin=self.current_admin()
            if not admin or admin.get("role")!="Administrator":
                return self.sendbody(403,"Administrator role required","text/plain")
            username=form.get("username",[""])[0].strip().lower()[:254]
            password=form.get("password",[""])[0]
            role=form.get("role",[""])[0].strip()
            allowed_roles=("Administrator","Campaign Manager","Reporting Analyst","SMTP Manager","Security Auditor")
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",username):
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

        if p.path=="/admin/roles/permissions":
            admin=self.current_admin()
            if not admin or admin.get("role")!="Administrator":
                return self.sendbody(403,"Administrator role required","text/plain")
            role_id=form.get("role_id",[""])[0]
            if not role_id.isdigit():
                return self.sendbody(400,"Invalid custom role","text/plain")
            permission_ids=sorted({int(value) for value in form.get("permission_ids",[]) if value.isdigit()})
            c=db()
            role=c.execute("SELECT id,name,built_in,active FROM rbac_roles WHERE id=?",(int(role_id),)).fetchone()
            if not role:
                c.close()
                return self.sendbody(404,"Custom role not found","text/plain")
            if role["built_in"]:
                c.close()
                return self.sendbody(400,"Built-in roles cannot be modified","text/plain")
            if not role["active"]:
                c.close()
                return self.sendbody(400,"Inactive custom roles cannot receive permissions","text/plain")
            valid=[]
            if permission_ids:
                placeholders=",".join("?" for _ in permission_ids)
                valid=c.execute("SELECT id FROM rbac_permissions WHERE active=1 AND id IN (%s)"%placeholders,tuple(permission_ids)).fetchall()
            if {int(x["id"]) for x in valid} != set(permission_ids):
                c.close()
                return self.sendbody(400,"One or more selected permissions are invalid or inactive","text/plain")
            selected_privileged=c.execute(
                "SELECT COUNT(*) AS n FROM rbac_permissions WHERE active=1 AND risk_level='privileged' AND id IN (%s)"%
                (",".join("?" for _ in permission_ids) or "NULL"),tuple(permission_ids)
            ).fetchone()["n"] if permission_ids else 0
            scope_kinds={"campaign","campaign_group","campaign_type","department","organizational_unit"}
            scope_assignments=[]
            for permission_id in permission_ids:
                raw_scope=form.get("scope_assignments_%s"%permission_id,[""])[0]
                for line in raw_scope.splitlines():
                    line=line.strip()
                    if not line: continue
                    if "=" not in line:
                        c.close()
                        return self.sendbody(400,"Invalid scope entry. Use kind=value.","text/plain")
                    scope_kind,scope_value=line.split("=",1)
                    scope_kind=scope_kind.strip()
                    scope_value=scope_value.strip()
                    if scope_kind not in scope_kinds or not scope_value or len(scope_value)>200 or "\r" in scope_value or "\n" in scope_value:
                        c.close()
                        return self.sendbody(400,"Invalid scope entry. Allowed kinds: campaign, campaign_group, campaign_type, department, organizational_unit.","text/plain")
                    scope_assignments.append((int(role_id),permission_id,scope_kind,scope_value))
            privileged_confirmed=form.get("confirm_privileged",[""])[0]=="1"
            if selected_privileged and not privileged_confirmed:
                c.close()
                return self.sendbody(400,"Privileged permissions require explicit confirmation","text/plain")
            old_privileged=c.execute(
                """SELECT COUNT(*) AS n
                   FROM rbac_role_permissions rp
                   JOIN rbac_permissions p ON p.id=rp.permission_id
                   WHERE rp.role_id=? AND p.active=1 AND p.risk_level='privileged'""",(int(role_id),)
            ).fetchone()["n"]
            try:
                c.execute("BEGIN")
                c.execute("DELETE FROM rbac_role_permissions WHERE role_id=?",(int(role_id),))
                c.execute("DELETE FROM rbac_resource_scopes WHERE role_id=?",(int(role_id),))
                if permission_ids:
                    c.executemany("INSERT INTO rbac_role_permissions(role_id,permission_id,created_at) VALUES(?,?,?)",[(int(role_id),pid,now()) for pid in permission_ids])
                if scope_assignments:
                    c.executemany("INSERT INTO rbac_resource_scopes(role_id,permission_id,scope_kind,scope_value,active,created_at,updated_at) VALUES(?,?,?,?,1,?,?)",
                                  [(rid,pid,kind,value,now(),now()) for rid,pid,kind,value in scope_assignments])
                c.commit()
            except Exception:
                c.rollback()
                c.close()
                return self.sendbody(500,"Unable to save role permissions","text/plain")
            c.close()
            audit(admin["username"],"ROLE_PERMISSION_UPDATE","role_id=%s permission_count=%s"%(role_id,len(permission_ids)),ip)
            if scope_assignments:
                scope_summary=";".join("%s=%s"%(kind,value) for _,_,kind,value in sorted(scope_assignments,key=lambda item:(item[2],item[3])))
                audit(
                    admin["username"],
                    "RBAC_SCOPE_ASSIGNMENT_UPDATE",
                    "role_id=%s scope_count=%s scopes=%s"%(role_id,len(scope_assignments),scope_summary[:2000]),
                    ip
                )
            if selected_privileged and not old_privileged:
                audit(admin["username"],"PRIVILEGED_PERMISSION_GRANT","role_id=%s privileged_permission_count=%s"%(role_id,selected_privileged),ip)
            return self.sendbody(302,b"",extra={"Location":"/admin/admins?tab=roles"})
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

        if p.path=="/admin/roles/duplicate":
            admin=self.current_admin()
            if not admin or admin.get("role")!="Administrator":
                return self.sendbody(403,"Administrator role required","text/plain")
            rid=form.get("id",[""])[0]
            if not rid.isdigit():
                return self.sendbody(400,"Invalid custom role","text/plain")
            c=db()
            row=c.execute("SELECT id,name,description,active,built_in FROM rbac_roles WHERE id=?",(int(rid),)).fetchone()
            if not row:
                c.close()
                return self.sendbody(404,"Custom role not found","text/plain")
            if row["built_in"]:
                c.close()
                return self.sendbody(400,"Built-in roles are protected","text/plain")
            base_name="Copy of "+row["name"]
            if len(base_name)>80:
                base_name=base_name[:80].rstrip()
            name=base_name
            suffix=2
            while c.execute("SELECT 1 FROM rbac_roles WHERE lower(name)=lower(?) OR slug=?",(name,re.sub(r"[^a-z0-9]+","-",name.lower()).strip("-"))).fetchone():
                suffix_text=" (%s)"%suffix
                name=base_name[:80-len(suffix_text)].rstrip()+suffix_text
                suffix+=1
                if suffix>9999:
                    c.close()
                    return self.sendbody(409,"Unable to generate a unique custom role name","text/plain")
            slug=re.sub(r"[^a-z0-9]+","-",name.lower()).strip("-")
            if not slug or len(slug)>80:
                c.close()
                return self.sendbody(400,"Invalid duplicated role name","text/plain")
            ts=now()
            c.execute("INSERT INTO rbac_roles(name,slug,description,built_in,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                      (name,slug,row["description"] or "",0,int(row["active"]),ts,ts))
            new_id=c.execute("SELECT last_insert_rowid()").fetchone()[0]
            c.commit()
            c.close()
            audit(admin["username"],"ROLE_CREATE","source_role_id=%s duplicated_role_id=%s name=%s slug=%s"%(rid,new_id,name,slug),ip)
            return self.sendbody(302,b"",extra={"Location":"/admin/admins?tab=roles"})

        if p.path=="/admin/roles/delete":
            admin=self.current_admin()
            if not admin or admin.get("role")!="Administrator":
                return self.sendbody(403,"Administrator role required","text/plain")
            rid=form.get("id",[""])[0]
            if not rid.isdigit():
                return self.sendbody(400,"Invalid custom role","text/plain")
            c=db()
            row=c.execute("SELECT id,name,built_in FROM rbac_roles WHERE id=?",(int(rid),)).fetchone()
            if not row:
                c.close()
                return self.sendbody(404,"Custom role not found","text/plain")
            if row["built_in"]:
                c.close()
                return self.sendbody(400,"Built-in roles are protected","text/plain")
            admin_use=c.execute("SELECT COUNT(*) AS n FROM admins WHERE role=?",(row["name"],)).fetchone()["n"]
            permission_use=c.execute("SELECT COUNT(*) AS n FROM rbac_role_permissions WHERE role_id=?",(int(rid),)).fetchone()["n"]
            if admin_use or permission_use:
                c.close()
                return self.sendbody(409,"Custom role is still referenced and cannot be deleted","text/plain")
            c.execute("DELETE FROM rbac_roles WHERE id=?",(int(rid),))
            c.commit()
            c.close()
            audit(admin["username"],"ROLE_DELETE","role_id=%s name=%s"%(rid,row["name"]),ip)
            return self.sendbody(302,b"",extra={"Location":"/admin/admins?tab=roles"})

        if p.path=="/admin/roles/save":
            admin=self.current_admin()
            if not admin or admin.get("role")!="Administrator":
                return self.sendbody(403,"Administrator role required","text/plain")
            rid=form.get("id",[""])[0]
            name=form.get("name",[""])[0].strip()
            description=form.get("description",[""])[0].strip()
            if not rid.isdigit():
                return self.sendbody(400,"Invalid custom role","text/plain")
            if not name or len(name)>80 or "\r" in name or "\n" in name:
                return self.sendbody(400,"Custom role name must be 1-80 characters and must not contain line breaks","text/plain")
            if len(description)>500 or "\r" in description or "\n" in description:
                return self.sendbody(400,"Role description must be 500 characters or fewer and must not contain line breaks","text/plain")
            slug=re.sub(r"[^a-z0-9]+","-",name.lower()).strip("-")
            if not slug or len(slug)>80:
                return self.sendbody(400,"Invalid custom role name","text/plain")
            c=db()
            row=c.execute("SELECT name,slug,built_in FROM rbac_roles WHERE id=?",(int(rid),)).fetchone()
            if not row:
                c.close()
                return self.sendbody(404,"Custom role not found","text/plain")
            if row["built_in"]:
                c.close()
                return self.sendbody(400,"Built-in roles are protected","text/plain")
            existing=c.execute("SELECT id FROM rbac_roles WHERE id<>? AND (lower(name)=lower(?) OR slug=?)",(int(rid),name,slug)).fetchone()
            if existing:
                c.close()
                return self.sendbody(409,"A role with this name already exists","text/plain")
            ts=now()
            c.execute("UPDATE rbac_roles SET name=?,slug=?,description=?,updated_at=? WHERE id=?",
                      (name,slug,description,ts,int(rid)))
            c.commit()
            c.close()
            audit(admin["username"],"ROLE_UPDATE","role_id=%s name=%s slug=%s"%(rid,name,slug),ip)
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
                    c.close()
                    audit(admin["username"],"ADMIN_LAST_SUPERADMIN_BLOCKED","username=%s attempted_role=%s attempted_active=%s reason=last_active_administrator"%(row["username"],role,new_active),ip)
                    return self.sendbody(400,"You cannot disable or demote the last active administrator account","text/plain")
            c.execute("UPDATE admins SET role=?,active=? WHERE id=?",(role,int(new_active),int(aid))); c.commit(); c.close()
            if role!=old_role:
                audit(admin["username"],"ADMIN_ROLE_UPDATE","username=%s old_role=%s new_role=%s"%(row["username"],old_role,role),ip)
            if new_active!=old_active:
                audit(admin["username"],"ADMIN_ENABLE" if new_active else "ADMIN_DISABLE","username=%s old_active=%s new_active=%s"%(row["username"],old_active,new_active),ip)
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
        if p.path=="/admin/settings/base-url":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            base_url=form.get("public_base_url",[""])[0].strip().rstrip("/")
            if not base_url or not (base_url.startswith("http://") or base_url.startswith("https://")):
                return self.sendbody(400,"Base URL must begin with http:// or https://","text/plain")
            c=db()
            c.execute("INSERT OR REPLACE INTO system_settings(key,value,updated_at) VALUES('public_base_url',?,?)",(base_url,now()))
            c.commit(); c.close()
            global PUBLIC_BASE_URL
            PUBLIC_BASE_URL=base_url
            audit(ADMIN_USERNAME,"SETTINGS_UPDATE","public_base_url updated to %s"%base_url,ip)
            return self.sendbody(302,b"",extra={"Location":"/admin/settings"})
        if p.path=="/admin/smtp/save":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            sid=form.get("id",[""])[0]; name=form.get("name",[""])[0][:100]; provider=form.get("provider",["Custom SMTP"])[0]
            host=form.get("host",[""])[0][:255]; port=int(form.get("port",["587"])[0]); security=form.get("security",["STARTTLS"])[0]
            username=form.get("username",[""])[0][:255]; password=form.get("password",[""])[0]; from_name=form.get("from_name",[""])[0][:150]
            from_email=form.get("from_email",[""])[0][:255]; reply_to=form.get("reply_to",[""])[0][:255]; auth_method=form.get("auth_method",["password"])[0]; oauth_url=form.get("oauth_token_url",[""])[0][:500]; oauth_client=form.get("oauth_client_id",[""])[0][:255]; oauth_scopes=form.get("oauth_scopes",[""])[0][:1000]; oauth_token=form.get("oauth_token",[""])[0]
            enabled=1 if form.get("enabled",["1"])[0] in ("1","Enabled","true") else 0
            if provider not in SMTP_PROVIDERS or security not in ("STARTTLS","SSL/TLS","NONE") or auth_method not in ("password","oauth2") or not host or not from_email or port<1 or port>65535:
                return self.sendbody(400,"Invalid SMTP profile","text/plain")
            c=db()
            existing=c.execute("SELECT id FROM smtp_profiles WHERE name=? AND id<>?",(name,int(sid) if sid else -1)).fetchone()
            if existing:
                c.close()
                return self.sendbody(409,"A provider with this profile name already exists. Open SMTP Providers and edit the existing profile, or choose a different Profile Name.","text/plain")
            profile_id=None
            if sid:
                profile_id=int(sid)
                old=c.execute("SELECT password_enc,oauth_token_enc FROM smtp_profiles WHERE id=?",(sid,)).fetchone()
                enc=encrypt_secret(password) if password else (old["password_enc"] if old else ""); oauth_enc=encrypt_secret(oauth_token) if oauth_token else (old["oauth_token_enc"] if old else "")
                c.execute("UPDATE smtp_profiles SET name=?,provider=?,host=?,port=?,security=?,username=?,password_enc=?,from_name=?,from_email=?,reply_to=?,auth_method=?,oauth_token_enc=?,oauth_token_url=?,oauth_client_id=?,oauth_scopes=?,enabled=?,updated_at=? WHERE id=?",(name,provider,host,port,security,username,enc,from_name,from_email,reply_to,auth_method,oauth_enc,oauth_url,oauth_client,oauth_scopes,enabled,now(),sid)); action="SMTP_PROFILE_UPDATE"
            else:
                enc=encrypt_secret(password) if password else ""; oauth_enc=encrypt_secret(oauth_token) if oauth_token else ""
                cur=c.execute("INSERT INTO smtp_profiles(name,provider,host,port,security,username,password_enc,from_name,from_email,reply_to,auth_method,oauth_token_enc,oauth_token_url,oauth_client_id,oauth_scopes,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(name,provider,host,port,security,username,enc,from_name,from_email,reply_to,auth_method,oauth_enc,oauth_url,oauth_client,oauth_scopes,enabled,now(),now())); profile_id=cur.lastrowid; action="SMTP_PROFILE_CREATE"
            c.commit(); c.close(); audit(ADMIN_USERNAME,action,name,ip)
            destination=("/admin/smtp/diagnostics?id="+str(profile_id)) if form.get("test_after_save",[""])[0]=="1" else "/admin/smtp"
            return self.sendbody(302,b"",extra={"Location":destination})
        if p.path=="/admin/smtp/delete":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            sid=form.get("id",[""])[0]
            if not sid.isdigit(): return self.sendbody(400,"Invalid SMTP profile","text/plain")
            c=db()
            profile=c.execute("SELECT id,name FROM smtp_profiles WHERE id=?",(int(sid),)).fetchone()
            if not profile:
                c.close()
                return self.sendbody(404,"SMTP profile not found","text/plain")
            in_camp=c.execute("SELECT COUNT(*) n FROM campaigns WHERE smtp_profile_id=?",(int(sid),)).fetchone()["n"]
            in_rep=c.execute("SELECT COUNT(*) n FROM scheduled_reports WHERE smtp_profile_id=?",(int(sid),)).fetchone()["n"]
            if in_camp > 0 or in_rep > 0:
                c.close()
                return self.sendbody(400,page("Cannot Delete SMTP Provider","<div style='max-width:700px;margin:70px auto;background:#fff;padding:30px;border-radius:16px;border:1px solid #dce7e2'><h2>Cannot Delete SMTP Provider</h2><p>This SMTP provider is currently in use by %d campaign(s) and %d scheduled report(s). To discontinue its use, disable the profile instead.</p><p><a class='btn' href='/admin/smtp?id=%s'>Back to Profile</a> <a class='btn' href='/admin/smtp'>Back to SMTP Providers</a></p></div>"%(in_camp,in_rep,sid)))
            c.execute("DELETE FROM smtp_profiles WHERE id=?",(int(sid),))
            c.commit(); c.close()
            audit(ADMIN_USERNAME,"SMTP_PROFILE_DELETE","profile=%s"%profile["name"],ip)
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
            body='<h1>SMTP Connectivity Diagnostics</h1><div class="card"><table class="table"><tr><th>Stage</th><th>Status</th><th>Detail</th></tr>%s</table><p><a class="btn" href="/admin/smtp?id=%s">Edit Provider</a> <a class="btn" href="/admin/smtp">Back to SMTP Providers</a></p></div>'%(rows,sid)
            return self.sendbody(200,self.admin_shell("SMTP Diagnostics",body,"SMTP Providers"))
        if p.path=="/admin/smtp/test":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            sid=form.get("id",[""])[0]; to_email=form.get("to_email",[""])[0][:255]
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",to_email):
                return self.sendbody(400,"Invalid test email","text/plain")
            c=db(); profile=c.execute("SELECT * FROM smtp_profiles WHERE id=?",(int(sid) if sid.isdigit() else sid,)).fetchone(); c.close()
            if not profile: return self.sendbody(404,"SMTP profile not found","text/plain")
            try:
                smtp_send_test(profile,to_email)
                audit(ADMIN_USERNAME,"SMTP_TEST",f"profile={profile['name']} recipient={to_email}",ip)
                return self.sendbody(200,page("SMTP Test","<div style='max-width:700px;margin:70px auto;background:#fff;padding:30px;border-radius:16px;border:1px solid #dce7e2'><h2>SMTP test sent</h2><p>The test message was accepted by the configured SMTP server.</p><p><a class='btn' href='/admin/smtp?id=%s'>Back to Profile</a> <a class='btn' href='/admin/smtp'>Back to SMTP Providers</a></p></div>"%profile["id"]))
            except Exception as e:
                audit(ADMIN_USERNAME,"SMTP_TEST_FAILED",f"profile={profile['name']}",ip)
                return self.sendbody(502,page("SMTP Test Failed","<div style='max-width:700px;margin:70px auto;background:#fff;padding:30px;border-radius:16px;border:1px solid #dce7e2'><h2>SMTP test failed</h2><p>The SMTP connection or authentication failed. Check host, port, TLS mode and provider credentials.</p><p style='color:#a12d2d;font-size:12px'>Error details: %s</p><p style='color:#a12d2d;font-size:12px'>No SMTP password is shown here.</p><p><a class='btn' href='/admin/smtp?id=%s'>Back to Profile</a> <a class='btn' href='/admin/smtp'>Back to SMTP Providers</a></p></div>"%(esc(sanitize_audit_details(str(e)[:150])),profile["id"])))
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
            if not self.permission_allowed(p.path,"POST",form=form): return self.sendbody(403,"Insufficient role permission","text/plain")
            rid=form.get("id",[""])[0].strip()
            email=form.get("email",[""])[0].strip().lower()
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",email): return self.sendbody(400,"Invalid email address","text/plain")
            c=db()
            employee=form.get("employee_id",[""])[0].strip()[:100]
            name=form.get("name",[""])[0].strip()[:150]
            department=form.get("department",[""])[0].strip()[:100]
            designation=form.get("designation",[""])[0].strip()[:150]
            location=form.get("location",[""])[0].strip()[:150]
            manager=form.get("manager",[""])[0].strip()[:150]
            group_name=form.get("group_name",[""])[0].strip()[:100]
            language=form.get("language",["English"])[0].strip()[:50]
            timezone_val=form.get("timezone",["Asia/Dhaka"])[0].strip()[:80] or "Asia/Dhaka"
            status_val=form.get("status",["Active"])[0] if form.get("status",["Active"])[0] in ("Active","Suppressed") else "Active"

            if not rid or rid=="new":
                existing=c.execute("SELECT id FROM recipients WHERE lower(email)=?",(email,)).fetchone()
                if existing: c.close(); return self.sendbody(409,"A recipient with this email already exists","text/plain")
                if employee:
                    emp_conflict=c.execute("SELECT id FROM recipients WHERE employee_id=? AND employee_id!=''",(employee,)).fetchone()
                    if emp_conflict: c.close(); return self.sendbody(409,"Employee ID is already assigned to another recipient","text/plain")
                c.execute("""INSERT INTO recipients(email,name,employee_id,department,designation,location,manager,language,timezone,group_name,status,created_at)
                             VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                          (email,name,employee,department,designation,location,manager,language,timezone_val,group_name,status_val,now()))
                new_id=c.execute("SELECT last_insert_rowid() id").fetchone()["id"]
                c.commit(); c.close(); audit(ADMIN_USERNAME,"RECIPIENT_CREATE",f"recipient={new_id} email={email}",ip)
                return self.sendbody(302,b"",extra={"Location":"/admin/recipients"})
            else:
                existing=c.execute("SELECT id FROM recipients WHERE lower(email)=? AND id!=?",(email,rid)).fetchone()
                if existing: c.close(); return self.sendbody(409,"A recipient with this email already exists","text/plain")
                if employee:
                    emp_conflict=c.execute("SELECT id FROM recipients WHERE employee_id=? AND employee_id!=''",(employee,rid)).fetchone()
                    if emp_conflict: c.close(); return self.sendbody(409,"Employee ID is already assigned to another recipient","text/plain")
                c.execute("UPDATE recipients SET email=?,name=?,employee_id=?,department=?,designation=?,location=?,manager=?,language=?,timezone=?,group_name=?,status=? WHERE id=?",
                          (email,name,employee,department,designation,location,manager,language,timezone_val,group_name,status_val,rid))
                c.commit(); c.close(); audit(ADMIN_USERNAME,"RECIPIENT_PROFILE_UPDATE","recipient=%s email=%s"%(rid,email),ip)
                return self.sendbody(302,b"",extra={"Location":"/admin/recipients"})
        if p.path=="/admin/recipients/delete":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            if not self.permission_allowed(p.path,"POST",form=form): return self.sendbody(403,"Insufficient role permission","text/plain")
            rid=form.get("id",[""])[0].strip()
            c=db()
            rec=c.execute("SELECT email FROM recipients WHERE id=?",(rid,)).fetchone()
            if rec:
                c.execute("DELETE FROM recipients WHERE id=?",(rid,))
                c.commit()
                audit(ADMIN_USERNAME,"RECIPIENT_DELETE","recipient=%s email=%s"%(rid,rec["email"]),ip)
            c.close()
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
            errors=campaign_prelaunch_validation(campaign, self.headers.get("Host"))
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
            errors=campaign_prelaunch_validation(campaign, self.headers.get("Host"))
            if errors:
                return self.sendbody(409,"Pre-launch validation failed: "+" ".join(errors),"text/plain")
            try:
                sent,failed,total=send_campaign(cid, req_host=self.headers.get("Host"))
                audit(ADMIN_USERNAME,"CAMPAIGN_LAUNCH","campaign=%s sent=%s failed=%s total=%s"%(cid,sent,failed,total),ip)
                fail_notice = "<p style='color:#a12d2d;margin-top:10px'>⚠️ %s delivery attempts failed. Check SMTP configuration and delivery logs.</p>"%failed if failed else ""
                return self.sendbody(200,page("Campaign Launch","<div style='max-width:760px;margin:70px auto;background:#fff;padding:30px;border-radius:16px;border:1px solid #dce7e2'><h2>Campaign launch complete</h2><p>Attempted: %s · Sent: %s · Failed: %s</p>%s<p style='margin-top:15px'><a class='btn primary' href='/admin/campaigns'>Back to Campaigns</a></p></div>"%(total,sent,failed,fail_notice)))
            except Exception as e:
                audit(ADMIN_USERNAME,"CAMPAIGN_LAUNCH_FAILED","campaign=%s error=%s"%(cid,str(e)[:200]),ip)
                return self.sendbody(502,page("Campaign Launch Failed","<div style='max-width:760px;margin:70px auto;background:#fff;padding:30px;border-radius:16px'><h2>Campaign launch failed</h2><p style='color:#a12d2d'><b>Error:</b> %s</p><p>Check PUBLIC_BASE_URL, SMTP configuration, target recipients and server logs. SMTP credentials are not displayed.</p><p><a class='btn' href='/admin/campaigns'>Back to Campaigns</a></p></div>"%esc(str(e))))
        if p.path=="/admin/campaigns/save":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            action_mode=form.get("action_mode",[""])[0].strip().lower()
            cid=form.get("id",[""])[0]
            name=form.get("name",[""])[0][:150]
            template=form.get("template",["1"])[0]
            status=form.get("status",["Draft"])[0]
            if action_mode=="draft":
                status="Draft"
            elif action_mode=="launch":
                status="Active"
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
            if status!="Draft":
                if not smtp_id or not c.execute("SELECT 1 FROM smtp_profiles WHERE id=? AND enabled=1",(smtp_id,)).fetchone():
                    c.close(); return self.sendbody(400,"A valid SMTP provider is required","text/plain")
                if not landing_id or not c.execute("SELECT 1 FROM landing_pages WHERE id=? AND status='Enabled'",(landing_id,)).fetchone():
                    c.close(); return self.sendbody(400,"A valid landing page is required","text/plain")
            else:
                if smtp_id and not c.execute("SELECT 1 FROM smtp_profiles WHERE id=? AND enabled=1",(smtp_id,)).fetchone():
                    c.close(); return self.sendbody(400,"Invalid SMTP provider selected","text/plain")
                if landing_id and not c.execute("SELECT 1 FROM landing_pages WHERE id=? AND status='Enabled'",(landing_id,)).fetchone():
                    c.close(); return self.sendbody(400,"Invalid landing page selected","text/plain")
            if group_name:
                targeted=c.execute("SELECT COUNT(*) n FROM recipients WHERE group_name=?",(group_name,)).fetchone()["n"]
            else:
                targeted=c.execute("SELECT COUNT(*) n FROM recipients").fetchone()["n"]
            smtp_val=int(smtp_id) if smtp_id and smtp_id.isdigit() else None
            landing_val=int(landing_id) if landing_id and landing_id.isdigit() else None
            if cid:
                c.execute("UPDATE campaigns SET name=?,template=?,status=?,targeted=?,smtp_profile_id=?,landing_page_id=?,subject=?,launch_at=?,send_by=?,group_name=?,timezone=?,business_days=?,window_start=?,window_end=?,batch_size=?,rate_per_minute=?,retry_max=?,retry_backoff_seconds=?,cancel_requested=?,updated_at=? WHERE id=?",(name,template,status,targeted,smtp_val,landing_val,subject,launch_at,send_by,group_name,timezone,business_days,window_start,window_end,batch_size,rate_per_minute,retry_max,retry_backoff,0,now(),cid))
                action="CAMPAIGN_UPDATE"
            else:
                cur=c.execute("INSERT INTO campaigns(name,template,status,targeted,smtp_profile_id,landing_page_id,subject,launch_at,send_by,group_name,timezone,business_days,window_start,window_end,batch_size,rate_per_minute,retry_max,retry_backoff_seconds,cancel_requested,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(name,template,status,targeted,smtp_val,landing_val,subject,launch_at,send_by,group_name,timezone,business_days,window_start,window_end,batch_size,rate_per_minute,retry_max,retry_backoff,0,now(),now()))
                cid=str(cur.lastrowid)
                action="CAMPAIGN_CREATE"
            c.commit(); c.close()
            audit(ADMIN_USERNAME,action,"%s status=%s targeted=%s group=%s"%(name,status,targeted,group_name or "all"),ip)
            if action_mode=="launch":
                return self.sendbody(302,b"",extra={"Location":"/admin/campaigns/launch?id="+cid})
            return self.sendbody(302,b"",extra={"Location":"/admin/campaigns"})

        if p.path=="/admin/campaigns/quick":
            if not self.auth(): return self.sendbody(403,"Forbidden","text/plain")
            name=form.get("name",[""])[0].strip()[:150]
            template=form.get("template",["1"])[0]
            landing_id=form.get("landing_page_id",[""])[0]
            smtp_id=form.get("smtp_profile_id",[""])[0]
            group_name=form.get("group_name",[""])[0].strip()[:100]
            subject=form.get("subject",[""])[0].strip()[:250]
            action_mode=form.get("action_mode",["launch"])[0].strip().lower()

            c=db()
            if not subject:
                t_row=c.execute("SELECT subject, name FROM template_library WHERE template=?",(template,)).fetchone()
                subject=(t_row["subject"] if t_row and t_row["subject"] else "") or "Security Awareness Simulation"
            if not name:
                name=f"Quick Drill - Template {template} ({datetime.now(TZ).strftime('%d %b %H:%M')})"

            if not smtp_id:
                s_row=c.execute("SELECT id FROM smtp_profiles WHERE enabled=1 ORDER BY id LIMIT 1").fetchone()
                if s_row: smtp_id=str(s_row["id"])

            if not landing_id:
                l_row=c.execute("SELECT id FROM landing_pages WHERE template=? AND status='Enabled' LIMIT 1",(template,)).fetchone()
                if not l_row:
                    l_row=c.execute("SELECT id FROM landing_pages WHERE status='Enabled' ORDER BY id LIMIT 1").fetchone()
                if l_row: landing_id=str(l_row["id"])

            if not smtp_id or not c.execute("SELECT 1 FROM smtp_profiles WHERE id=? AND enabled=1",(smtp_id,)).fetchone():
                c.close()
                return self.sendbody(400,"A valid enabled SMTP profile is required for Quick Campaign","text/plain")
            if not landing_id or not c.execute("SELECT 1 FROM landing_pages WHERE id=? AND status='Enabled'",(landing_id,)).fetchone():
                c.close()
                return self.sendbody(400,"A valid enabled landing page is required for Quick Campaign","text/plain")

            smtp_val=int(smtp_id)
            landing_val=int(landing_id)

            if group_name:
                targeted=c.execute("SELECT COUNT(*) n FROM recipients WHERE status!='Suppressed' AND group_name=?",(group_name,)).fetchone()["n"]
            else:
                targeted=c.execute("SELECT COUNT(*) n FROM recipients WHERE status!='Suppressed'").fetchone()["n"]

            if targeted==0:
                c.close()
                return self.sendbody(400,"No eligible recipients found in selected target audience.","text/plain")

            status="Active" if action_mode=="launch" else "Draft"
            business_days="Mon,Tue,Wed,Thu,Fri,Sat,Sun"
            window_start="00:00"
            window_end="23:59"
            timezone="Asia/Dhaka"

            cur=c.execute("""INSERT INTO campaigns(name,template,status,targeted,smtp_profile_id,landing_page_id,subject,
                             launch_at,send_by,group_name,timezone,business_days,window_start,window_end,batch_size,
                             rate_per_minute,retry_max,retry_backoff_seconds,cancel_requested,created_at,updated_at)
                             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                          (name,template,status,targeted,smtp_val,landing_val,subject,"","",group_name,
                           timezone,business_days,window_start,window_end,50,60,2,5,0,now(),now()))
            cid=str(cur.lastrowid)
            c.commit(); c.close()
            audit(ADMIN_USERNAME,"QUICK_CAMPAIGN_CREATE","name=%s status=%s targeted=%s"%(name,status,targeted),ip)

            if action_mode=="launch":
                try:
                    sent,failed,total=send_campaign(cid, scheduled=False, req_host=self.headers.get("Host"))
                    audit(ADMIN_USERNAME,"CAMPAIGN_LAUNCH","campaign=%s sent=%s failed=%s total=%s"%(cid,sent,failed,total),ip)
                    return self.sendbody(302,b"",extra={"Location":f"/admin/campaigns?quick_launched={cid}&sent={sent}&failed={failed}&total={total}"})
                except Exception as e:
                    audit(ADMIN_USERNAME,"CAMPAIGN_LAUNCH_FAILED","campaign=%s error=%s"%(cid,str(e)[:200]),ip)
                    err_msg=quote_plus(str(e)[:150])
                    return self.sendbody(302,b"",extra={"Location":f"/admin/campaigns?quick_launched={cid}&quick_error={err_msg}"})
            else:
                return self.sendbody(302,b"",extra={"Location":f"/admin/campaigns?id={cid}"})

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