# Phish — Internal Security Awareness Simulation

One-click Linux deployment for an authorised internal security-awareness simulation.

## Install
```bash
sudo ./install.sh
```

The installer creates `phish-simulation.service`, installs Flask in a virtual environment, generates an admin token, and stores event data locally.

## Service
```bash
sudo systemctl status phish-simulation
sudo systemctl restart phish-simulation
sudo journalctl -u phish-simulation -f
```

Default URL: `http://SERVER-IP:8080/`

Admin events:
```bash
curl -H "X-Admin-Token: YOUR_TOKEN" http://SERVER-IP:8080/admin/events
```

Collected simulation data stays under `/opt/phish-simulation/backend/data/` and is excluded from Git.

The application intentionally rejects password, OTP/PIN, card and CVV/payment credential fields.