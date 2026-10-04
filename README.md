# Phishing Simulation
Authorized internal security-awareness simulation server.

Features:
- /1.html through /10.html
- /admin dashboard
- SQLite: /opt/phish-simulation/data/phish.db
- Access log: /opt/phish-simulation/logs/access.log
- CSV export
- Records source/local IP, timestamp, template, event, name, email, mobile and user-agent
- Does NOT request/store passwords, OTPs, PINs, CVVs or card numbers
- Python standard library only

Install: ./install.sh
Set ADMIN_PASSWORD in /etc/systemd/system/phish-simulation.service, then systemctl daemon-reload && systemctl restart phish-simulation
Update: ./update.sh
