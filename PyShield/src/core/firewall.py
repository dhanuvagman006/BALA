from __future__ import annotations

import platform
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Set, Optional

from .config import PyShieldConfig
from .logging_system import LoggerFactory
from .alerts import AlertSender


@dataclass
class Stats:
    blocked_ips: Dict[str, int] = field(default_factory=dict)
    blocked_urls: Dict[str, int] = field(default_factory=dict)
    blocked_ports: Set[int] = field(default_factory=set)
    active_attacks: Dict[str, int] = field(default_factory=dict)


class PyShield:
    def __init__(self, config: PyShieldConfig) -> None:
        self.cfg = config
        self.logger = LoggerFactory.get_logger(
            "pyshield",
            level=self.cfg.logging.level,
            json_mode=self.cfg.logging.json,
            log_dir=self.cfg.logging.log_dir,
            file_name=self.cfg.logging.file_name,
            max_mb=self.cfg.logging.max_mb,
            backups=self.cfg.logging.backups,
        )
        self.alerts = AlertSender(
            smtp_host=self.cfg.alerts.smtp_host,
            smtp_port=self.cfg.alerts.smtp_port,
            smtp_username=self.cfg.alerts.smtp_username,
            smtp_password=self.cfg.alerts.smtp_password,
            from_email=self.cfg.alerts.from_email,
            to_emails=self.cfg.alerts.to_emails,
            discord_webhook_url=self.cfg.alerts.discord_webhook_url,
            slack_webhook_url=self.cfg.alerts.slack_webhook_url,
        )
        self.stats = Stats()
        self._threads: list[threading.Thread] = []
        self._stopping = threading.Event()

    def start(self) -> None:
        self.logger.info("Starting PyShield on %s", platform.system())
        # In a fuller implementation, we'd launch background workers (sniffers, updaters)
        # Here we keep it synchronous unless dashboard/sniffer is enabled externally.

    def stop(self, timeout: float = 3.0) -> None:
        self._stopping.set()
        for t in self._threads:
            t.join(timeout=timeout)
        self.logger.info("PyShield stopped")

    # Example event ingestion APIs other modules can call
    def on_ddos_block(self, ip: str, count: int) -> None:
        self.stats.blocked_ips[ip] = self.stats.blocked_ips.get(ip, 0) + 1
        self.logger.warning("DDoS blocked IP %s (reqs=%s)", ip, count)
        self.alerts.alert("DDoS Blocked", f"Blocked IP {ip}", {"requests": count})

    def on_url_block(self, url: str) -> None:
        self.stats.blocked_urls[url] = self.stats.blocked_urls.get(url, 0) + 1
        self.logger.warning("Blocked malicious URL: %s", url)
        self.alerts.alert("Malicious URL Blocked", url)

    def on_port_block(self, port: int) -> None:
        self.stats.blocked_ports.add(port)
        self.logger.info("Port blocked: %s", port)

    def on_attack_detected(self, kind: str, info: Optional[dict] = None) -> None:
        self.stats.active_attacks[kind] = self.stats.active_attacks.get(kind, 0) + 1
        self.logger.error("Attack detected: %s %s", kind, info or {})
        self.alerts.alert("Attack detected", kind, info)
