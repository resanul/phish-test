# Phishing Simulation Template Server

Private internal security-awareness simulation server.

## Deployment model

The server is deployed directly from this Git repository.

Runtime data is intentionally kept outside Git:
- `data/` — SQLite database
- `logs/` — access logs
- `.deploy-state` — deployment metadata

## One-time server setup

The server must have Git access to this private repository.

Recommended SSH remote:

```bash
cd /opt
git clone git@github.com:resanul/phish.git phish-simulation
cd /opt/phish-simulation
chmod +x install.sh update.sh rollback.sh
./install.sh
```

If the application already exists from the older copy-based installer, back it up first and migrate the existing `data/` and `logs/` directories before using the Git workflow.

## Normal update

```bash
cd /opt/phish-simulation
./update.sh
```

The script:
1. Fetches `origin/main`
2. Resets the application code to the latest commit
3. Preserves ignored runtime directories
4. Validates `server.py`
5. Restarts systemd
6. Checks `/1.html`
7. Automatically rolls back if the health check fails

For a simple HTML-only change, restart is harmless and keeps the workflow consistent.

## Rollback

Rollback to the previous deployment:

```bash
cd /opt/phish-simulation
./rollback.sh
```

Rollback to a specific commit:

```bash
./rollback.sh <commit-sha>
```

Useful history:

```git log --oneline --decorate -10```

## Important

Do not commit:
- admin passwords
- SQLite database
- access logs
- production secrets

Set the admin password only in:

`/etc/systemd/system/phish-simulation.service`

After changing it:

```bash
systemctl daemon-reload
systemctl restart phish-simulation
```
