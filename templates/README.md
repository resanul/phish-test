# Internal Phishing Simulation Template Server

Lightweight authorised security-awareness simulation server.

## Requirements

- Linux server
- Python 3
- systemd

No Flask, pip, Docker, or additional package is required.

## Install

From this directory:

```bash
chmod +x install.sh
./install.sh
```

Default port: 8080.

## URLs

```
http://abcd.com:8080/1.html
http://abcd.com:8080/2.html
...
http://abcd.com:8080/10.html
```

If the DNS name is mapped to the server and port 80 is used by your environment, the same templates can be exposed as:

```
http://abcd.com/1.html
```

## Logs

Requests are written locally to:

```
/opt/phish-simulation/logs/access.log
```

Each entry records timestamp, source IP, requested path and HTTP status.

## Service

```bash
systemctl status phish-simulation
systemctl restart phish-simulation
journalctl -u phish-simulation -f
```

This project is intended for authorised internal security-awareness exercises. Do not use it to collect passwords, OTPs, PINs, card data, or other authentication/payment credentials.
