from __future__ import annotations

import re
import threading
import time
from typing import Iterable, List, Optional, Set

import requests

from core.config import URLBlockingConfig
from core.logging_system import LoggerFactory


DOMAIN_RE = re.compile(r"https?://([^/]+)")


class URLBlocker:
    def __init__(self, cfg: URLBlockingConfig):
        self.cfg = cfg
        self.logger = LoggerFactory.get_logger("pyshield.url")
        self._blacklist: Set[str] = set(map(self._normalize, cfg.blacklist or []))
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._bg: Optional[threading.Thread] = None

    def start(self) -> None:
        if self.cfg.feeds and self.cfg.auto_update_minutes > 0 and self._bg is None:
            self._bg = threading.Thread(target=self._auto_update_loop, daemon=True)
            self._bg.start()

    def stop(self) -> None:
        self._stop.set()
        if self._bg:
            self._bg.join(timeout=2)

    def _auto_update_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.update_from_feeds(self.cfg.feeds)
            except Exception as e:  # pragma: no cover
                self.logger.exception("Feed update failed: %s", e)
            self._stop.wait(self.cfg.auto_update_minutes * 60)

    def _normalize(self, item: str) -> str:
        item = item.strip().lower()
        item = item.rstrip('/')
        # domain only
        m = DOMAIN_RE.match(item)
        if m:
            item = m.group(1)
        return item

    def add(self, items: Iterable[str]) -> None:
        with self._lock:
            for it in items:
                self._blacklist.add(self._normalize(it))

    def remove(self, items: Iterable[str]) -> None:
        with self._lock:
            for it in items:
                self._blacklist.discard(self._normalize(it))

    def is_malicious(self, url: str) -> bool:
        host = self._normalize(url)
        with self._lock:
            if host in self._blacklist:
                return True
            # subdomain match
            parts = host.split('.')
            for i in range(1, len(parts)):
                if '.'.join(parts[i:]) in self._blacklist:
                    return True
        return False

    def update_from_feeds(self, feeds: List[str]) -> int:
        added = 0
        new_items: Set[str] = set()
        for url in feeds:
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code == 200:
                    lines = [line.strip() for line in resp.text.splitlines() if line.strip() and not line.startswith('#')]
                    new_items.update(lines)
            except Exception as e:  # pragma: no cover
                self.logger.warning("Feed fetch failed %s: %s", url, e)
        before = len(self._blacklist)
        self.add(new_items)
        added = len(self._blacklist) - before
        if added:
            self.logger.info("Blacklist updated: +%s entries (total=%s)", added, len(self._blacklist))
        return added

    def virustotal_check(self, url: str, api_key: Optional[str]) -> Optional[bool]:  # pragma: no cover (network)
        if not api_key:
            return None
        try:
            # Simple URL scanning endpoint (v3) placeholder
            headers = {"x-apikey": api_key}
            resp = requests.get("https://www.virustotal.com/api/v3/urls", headers=headers, timeout=10)
            return None if resp.status_code >= 400 else None
        except Exception:
            return None
