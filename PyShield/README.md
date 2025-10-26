# PyShield -   Python Firewall

PyShield is a production-ready Python firewall with advanced threat protection and a real-time web dashboard. It protects against DDoS, blocks malicious URLs, controls ports, monitors browser requests via an optional HTTP proxy, and supports alerting.

## Core Features

- DDoS protection (sliding window rate limiting, optional IP auto-ban)
- URL/domain blocking with large threat feeds and custom blacklists
- Optional HTTP proxy to monitor and filter browser traffic in real time
- Intrusion detection (failed login/brute-force tracking with bans)
- Port management (Windows netsh / Linux iptables; dry-run by default)
- Web dashboard (FastAPI) with live stats and activity
- Alerting integrations (Email, Discord, Slack)

## Requirements

- Python 3.8+ (3.11 recommended)
- Windows, Linux, or macOS
- For port rule enforcement: admin/root privileges (dry-run is safe by default)

## Quick Start (Windows PowerShell)

1. Create venv and install dependencies

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

2. Create config from example and edit if needed

   ```powershell
   Copy-Item config\config.example.yaml config\config.yaml
   ```

3. Run PyShield

   ```powershell
   python run.py
   ```

4. Open the dashboard

   - URL: http://127.0.0.1:8000
   - Username: admin
   - Password: admin

5. Optional: monitor your browser traffic (proxy)

   - Set your system/browser HTTP proxy to 127.0.0.1:8888

   - Open the "Browser Traffic" tab in the dashboard to see requests

## Configuration (excerpt)

Edit `config/config.yaml` to tune behavior:

```yaml
ddos:
  enabled: true
  request_limit: 200
  window_seconds: 60
  ban_seconds: 900

url_blocking:
  enabled: true
  feeds:
    - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
  custom_blacklist: []

dashboard:
  enabled: true
  host: 127.0.0.1
  port: 8000
  username: admin
  password: admin
  enable_proxy: true
  proxy_port: 8888

alerts:
  email_enabled: false
  discord_webhook_url: null
  slack_webhook_url: null
```

## Dashboard

- Overview: live stats and charts
- Browser Traffic: recent HTTP/HTTPS requests via the proxy (allowed vs blocked)
- Activity Log: chronological security events
- Settings: DDoS, URL list, port controls, alert tests

## Logs

- `logs/pyshield.log`: main application logs (rotating)
- Console output with timestamp and severity
- Configurable log levels

## Notes

- Change default credentials in `config/config.yaml` before production use
- Put HTTPS in front of the dashboard if exposed publicly
- Enforcing port rules (not dry-run) requires elevated privileges

---

PyShield —  -grade network security for Python environments.