# PyShield - Professional Python Firewall# PyShield — Advanced Python Firewall



A production-ready firewall system with advanced threat protection and real-time browser traffic monitoring.PyShield is a modular Python firewall toolkit that helps protect servers from DDoS attacks, malicious URLs, unauthorized port access, and other intrusions. It includes logging, analytics, optional geo-blocking, and an admin API.



## 🛡️ Core Features## Features



- **DDoS Protection**: Intelligent rate limiting with automatic IP banning- DDoS protection with sliding window rate limiting (optional Redis backend)

- **URL Blocking**: Real-time malicious URL detection with 100K+ threat feeds- Malicious URL/domain blocking with local blacklist and feed updater

- **HTTP Proxy**: Monitor and protect all browser traffic in real-time- Port blocking via iptables (Linux) or Windows Firewall (netsh)

- **Intrusion Detection**: Failed login monitoring and brute-force protection- Intrusion detection for repeated failed login attempts with auto-bans

- **Port Management**: Dynamic port blocking and access control- Optional geo-blocking using a GeoIP database

- **Web Dashboard**: Professional monitoring interface with real-time analytics- Structured logging and simple analytics

- **Alert System**: Multi-channel notifications (Email, Discord, Slack)- Admin API (FastAPI) with basic auth to view stats and manage rules

- Real-time alerts via Email, Discord, and Slack (optional)

## 🚀 Quick Start

## Quick start

1. **Install dependencies**:

   ```bash1. Create a virtual environment and install dependencies

   pip install -r requirements.txt

   ``````bash

python -m venv .venv

2. **Run PyShield**:. .venv/Scripts/activate  # Windows: .venv\Scripts\activate

   ```bashpip install -r requirements.txt

   python run.py```

   ```

2. Copy the example config

3. **Access Dashboard**:

   - URL: http://127.0.0.1:8000```bash

   - Username: `admin`mkdir -p config

   - Password: `admin`copy config\config.example.yaml config\config.yaml  # Windows

```

4. **Configure Browser Proxy** (optional):

   - Set HTTP proxy to: `127.0.0.1:8888`3. Run PyShield (dashboard enabled by default on 127.0.0.1:8000)

   - Monitor all web traffic in "Browser Traffic" tab

```bash

## ⚙️ Configurationpython -m src.main --config config\config.yaml

```

Edit `config/config.yaml`:

Notes:

```yaml- Port operations run in `dry_run` by default for safety. Set `port_blocking.dry_run: false` to apply real rules (requires admin/root privileges).

ddos:- Geo-blocking requires a local MaxMind GeoLite2 Country DB (`data/GeoLite2-Country.mmdb`).

  enabled: true- Alert channels (email/Discord/Slack) require credentials/webhooks in config.

  request_limit: 200

  window_seconds: 60## Admin API

  ban_seconds: 900

- GET /stats — basic stats

url_blocking:- POST /ports/block {"ports": [80, 443]}

  enabled: true- POST /ports/unblock {"ports": [80, 443]}

  feeds:- POST /urls/add {"items": ["bad.example"]}

    - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts- POST /urls/remove {"items": ["bad.example"]}



dashboard:Authenticate with basic auth using the `dashboard.username` and `dashboard.password` from the config.

  enabled: true

  host: 127.0.0.1## Design

  port: 8000

  enable_proxy: trueCore modules:

  proxy_port: 8888- `src/core/config.py` — YAML config loader with dataclasses

- `src/core/logging_system.py` — rotating file + console logging

alerts:- `src/core/alerts.py` — email/Discord/Slack alerts

  email_enabled: false- `src/core/rate_limiter.py` — in-memory sliding window and optional Redis counter

  discord_webhook_url: null- `src/core/firewall.py` — orchestrator and stats

  slack_webhook_url: null

```Feature modules:

- `src/modules/ddos_protection.py` — per-IP request tracking with ban logic

## 📊 Dashboard Features- `src/modules/url_blocking.py` — blacklist management and feed updater

- `src/modules/port_blocking.py` — cross-platform port rule management

### Overview Tab- `src/modules/intrusion_detection.py` — failed login detection with auto-bans

- Real-time statistics and charts- `src/modules/geo_blocking.py` — country-based blocking

- Attack type breakdown

- Timeline analysisDashboard:

- System status indicators- `src/dashboard/api.py` — FastAPI app factory exposing admin endpoints



### Browser Traffic TabMain:

- Live web request monitoring- `src/main.py` — process bootstrap, dashboard, lifecycle

- Blocked vs allowed traffic

- Request details and analysis## Security and OS notes

- Proxy configuration guide

- Windows: port rules use `netsh advfirewall` and require an elevated PowerShell/Command Prompt when `dry_run` is false.

### Activity Log- Linux: port rules use `iptables` and require sudo privileges.

- Real-time security events- Packet sniffing (scapy) is not enabled by default; you can extend `src/main.py` to start sniffers if needed.

- Detailed attack information

- Historical activity tracking## Testing



### SettingsUnit tests are in `tests/`. You can run them with pytest:

- DDoS protection configuration

- URL blacklist management```bash

- Port blocking controlspytest -q

- Alert system testing```



## 🔒 Security Features## License



### DDoS ProtectionMIT

- Per-IP rate limiting
- Sliding window detection
- Automatic ban management
- Redis support for scaling

### URL Blocking
- 100K+ malicious URLs blocked
- Real-time threat feed updates
- Custom blacklist support
- Domain and path filtering

### Proxy Protection
- HTTP/HTTPS traffic filtering
- Real-time malware blocking
- Geographic restrictions
- Request/response analysis

## 🚦 Production Deployment

1. **Security Hardening**:
   - Change default credentials
   - Configure HTTPS
   - Set up proper logging
   - Enable all protection modules

2. **Performance Tuning**:
   ```yaml
   ddos:
     request_limit: 100  # Stricter limits
     use_redis: true     # For load balancing
   
   url_blocking:
     auto_update_minutes: 30  # Frequent updates
   ```

3. **Monitoring Setup**:
   ```yaml
   alerts:
     email_enabled: true
     smtp_host: your-smtp-server
     to_emails: [admin@yourcompany.com]
     discord_webhook_url: your-webhook-url
   ```

## 📝 Logs

- `logs/pyshield.log`: Main application logs
- Console output with timestamp and severity
- Configurable log levels and rotation

## ⚠️ Important Notes

- **Admin Privileges**: Some features require elevated permissions
- **Network Configuration**: Ensure firewall ports are properly configured  
- **Resource Usage**: Monitor CPU/memory usage under high load
- **Legal Compliance**: Use only for legitimate security purposes

## 🛠️ System Requirements

- Python 3.8+
- 512MB RAM minimum (1GB+ recommended)
- Network interface access
- Optional: Redis for distributed deployments

---

**PyShield**: Professional-grade network security for Python environments.