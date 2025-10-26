from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

import yaml


@dataclass
class RedisConfig:
    enabled: bool = False
    url: str = "redis://localhost:6379/0"


@dataclass
class DDoSConfig:
    enabled: bool = True
    request_limit: int = 200
    window_seconds: int = 60
    ban_seconds: int = 900
    use_redis: bool = False


@dataclass
class URLBlockingConfig:
    enabled: bool = True
    blacklist: List[str] = field(default_factory=list)
    feeds: List[str] = field(default_factory=list)
    virustotal_api_key: Optional[str] = None
    auto_update_minutes: int = 60


@dataclass
class PortBlockingConfig:
    enabled: bool = True
    blocked_ports: List[int] = field(default_factory=list)
    dry_run: bool = True  # Safe default for development/testing


@dataclass
class IDSConfig:
    enabled: bool = True
    failed_login_threshold: int = 5
    window_seconds: int = 300
    auto_ban_seconds: int = 1800


@dataclass
class GeoBlockingConfig:
    enabled: bool = False
    blacklist_countries: List[str] = field(default_factory=list)
    whitelist_countries: List[str] = field(default_factory=list)
    # Path to MaxMind DB or similar (optional)
    geoip_db_path: Optional[str] = None


@dataclass
class InspectionConfig:
    enabled: bool = False
    interface: Optional[str] = None
    bpf_filter: Optional[str] = None
    portscan_threshold: int = 20
    window_seconds: int = 60


@dataclass
class AlertConfig:
    email_enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    from_email: str = ""
    to_emails: List[str] = field(default_factory=list)

    discord_webhook_url: Optional[str] = None
    slack_webhook_url: Optional[str] = None


@dataclass
class DashboardConfig:
    enabled: bool = False
    host: str = "0.0.0.0"
    port: int = 8000
    username: str = "admin"
    password: str = "admin"
    enable_proxy: bool = False
    proxy_port: int = 8888


@dataclass
class LoggingConfig:
    level: str = "INFO"
    json: bool = False
    log_dir: str = "logs"
    file_name: str = "pyshield.log"
    max_mb: int = 10
    backups: int = 5


@dataclass
class PyShieldConfig:
    ddos: DDoSConfig = field(default_factory=DDoSConfig)
    url_blocking: URLBlockingConfig = field(default_factory=URLBlockingConfig)
    port_blocking: PortBlockingConfig = field(default_factory=PortBlockingConfig)
    ids: IDSConfig = field(default_factory=IDSConfig)
    geo: GeoBlockingConfig = field(default_factory=GeoBlockingConfig)
    inspection: InspectionConfig = field(default_factory=InspectionConfig)
    alerts: AlertConfig = field(default_factory=AlertConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    redis: RedisConfig = field(default_factory=RedisConfig)


class ConfigLoader:
    @staticmethod
    def from_yaml(path: str) -> PyShieldConfig:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return ConfigLoader.from_dict(data)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> PyShieldConfig:
        # Helper to deep read dicts with defaults
        def get(d: Dict[str, Any], key: str, default: Any) -> Any:
            val = d.get(key, {})
            return val if isinstance(val, dict) else ({} if val is None else val)

        ddos = get(data, "ddos", {})
        urlb = get(data, "url_blocking", {})
        ports = get(data, "port_blocking", {})
        ids = get(data, "ids", {})
        geo = get(data, "geo", {})
        inspection = get(data, "inspection", {})
        alerts = get(data, "alerts", {})
        dashboard = get(data, "dashboard", {})
        logging = get(data, "logging", {})
        redis = get(data, "redis", {})

        cfg = PyShieldConfig(
            ddos=DDoSConfig(
                enabled=ddos.get("enabled", True),
                request_limit=ddos.get("request_limit", 200),
                window_seconds=ddos.get("window_seconds", 60),
                ban_seconds=ddos.get("ban_seconds", 900),
                use_redis=ddos.get("use_redis", False),
            ),
            url_blocking=URLBlockingConfig(
                enabled=urlb.get("enabled", True),
                blacklist=list(urlb.get("blacklist", []) or []),
                feeds=list(urlb.get("feeds", []) or []),
                virustotal_api_key=urlb.get("virustotal_api_key"),
                auto_update_minutes=urlb.get("auto_update_minutes", 60),
            ),
            port_blocking=PortBlockingConfig(
                enabled=ports.get("enabled", True),
                blocked_ports=list(ports.get("blocked_ports", []) or []),
                dry_run=ports.get("dry_run", True),
            ),
            ids=IDSConfig(
                enabled=ids.get("enabled", True),
                failed_login_threshold=ids.get("failed_login_threshold", 5),
                window_seconds=ids.get("window_seconds", 300),
                auto_ban_seconds=ids.get("auto_ban_seconds", 1800),
            ),
            geo=GeoBlockingConfig(
                enabled=geo.get("enabled", False),
                blacklist_countries=list(geo.get("blacklist_countries", []) or []),
                whitelist_countries=list(geo.get("whitelist_countries", []) or []),
                geoip_db_path=geo.get("geoip_db_path"),
            ),
            inspection=InspectionConfig(
                enabled=inspection.get("enabled", False),
                interface=inspection.get("interface"),
                bpf_filter=inspection.get("bpf_filter"),
                portscan_threshold=inspection.get("portscan_threshold", 20),
                window_seconds=inspection.get("window_seconds", 60),
            ),
            alerts=AlertConfig(
                email_enabled=alerts.get("email_enabled", False),
                smtp_host=alerts.get("smtp_host", ""),
                smtp_port=alerts.get("smtp_port", 587),
                smtp_username=alerts.get("smtp_username", ""),
                smtp_password=alerts.get("smtp_password", ""),
                from_email=alerts.get("from_email", ""),
                to_emails=list(alerts.get("to_emails", []) or []),
                discord_webhook_url=alerts.get("discord_webhook_url"),
                slack_webhook_url=alerts.get("slack_webhook_url"),
            ),
            dashboard=DashboardConfig(
                enabled=dashboard.get("enabled", False),
                host=dashboard.get("host", "0.0.0.0"),
                port=dashboard.get("port", 8000),
                username=dashboard.get("username", "admin"),
                password=dashboard.get("password", "admin"),
                enable_proxy=dashboard.get("enable_proxy", False),
                proxy_port=dashboard.get("proxy_port", 8888),
            ),
            logging=LoggingConfig(
                level=logging.get("level", "INFO"),
                json=logging.get("json", False),
                log_dir=logging.get("log_dir", "logs"),
                file_name=logging.get("file_name", "pyshield.log"),
                max_mb=logging.get("max_mb", 10),
                backups=logging.get("backups", 5),
            ),
            redis=RedisConfig(
                enabled=redis.get("enabled", False),
                url=redis.get("url", "redis://localhost:6379/0"),
            ),
        )

        # Environment overrides (simple pattern: PYSHIELD_SECTION_KEY)
        def env_bool(name: str, default: bool) -> bool:
            v = os.getenv(name)
            if v is None:
                return default
            return v.lower() in {"1", "true", "yes", "on"}

        cfg.ddos.enabled = env_bool("PYSHIELD_DDOS_ENABLED", cfg.ddos.enabled)
        cfg.port_blocking.dry_run = env_bool("PYSHIELD_PORTS_DRY_RUN", cfg.port_blocking.dry_run)
        cfg.dashboard.enabled = env_bool("PYSHIELD_DASHBOARD_ENABLED", cfg.dashboard.enabled)

        return cfg
