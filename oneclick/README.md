# Phish — Internal Security Awareness Simulation

One-click Linux deployment for an authorised internal security-awareness simulation.

## Install
```bash
sudo ./install.sh
```

The installer creates `phish-test.service`, installs Flask in a virtual environment, generates an admin token, and stores event data locally.

## Service
```bash
sudo systemctl status phish-test
sudo systemctl restart phish-test
sudo journalctl -u phish-test -f
```

Default URL: `http://SERVER-IP:8080/`

Admin events:
```bash
curl -H "X-Admin-Token: YOUR_TOKEN" http://SERVER-IP:8080/admin/events
```

Collected simulation data stays under `/opt/phish-test/backend/data/` and is excluded from Git.

The application intentionally rejects password, OTP/PIN, card and CVV/payment credential fields.