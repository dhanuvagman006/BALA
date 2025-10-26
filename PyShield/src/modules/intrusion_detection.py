from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional

from core.config import IDSConfig
from core.logging_system import LoggerFactory


class IntrusionDetector:
    def __init__(self, cfg: IDSConfig):
        self.cfg = cfg
        self.logger = LoggerFactory.get_logger("pyshield.ids")
        self.failed_logins: Dict[str, Deque[float]] = defaultdict(deque)
        self.banned_until: Dict[str, float] = {}

    def _purge_window(self, q: Deque[float], now: float) -> None:
        cutoff = now - self.cfg.window_seconds
        while q and q[0] < cutoff:
            q.popleft()

    def is_banned(self, ip: str, now: Optional[float] = None) -> bool:
        t = now if now is not None else time.time()
        until = self.banned_until.get(ip, 0)
        if until and until > t:
            return True
        if until and until <= t:
            self.banned_until.pop(ip, None)
        return False

    def register_failed_login(self, ip: str, now: Optional[float] = None) -> bool:
        if not self.cfg.enabled:
            return False
        t = now if now is not None else time.time()
        q = self.failed_logins[ip]
        q.append(t)
        self._purge_window(q, t)
        if len(q) >= self.cfg.failed_login_threshold:
            self.banned_until[ip] = t + self.cfg.auto_ban_seconds
            self.logger.warning("IDS ban applied to %s for %ss (failed_logins=%s)", ip, self.cfg.auto_ban_seconds, len(q))
            return True
        return False
