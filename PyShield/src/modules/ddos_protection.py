from __future__ import annotations

import time
from typing import Dict, Optional

from core.config import DDoSConfig
from core.rate_limiter import SlidingWindowRateLimiter, RedisCounter
from core.logging_system import LoggerFactory

try:
    import redis  # type: ignore
except Exception:  # pragma: no cover
    redis = None  # type: ignore


class DDoSProtector:
    def __init__(self, cfg: DDoSConfig):
        self.cfg = cfg
        self.logger = LoggerFactory.get_logger("pyshield.ddos")
        self.banned_until: Dict[str, float] = {}
        if self.cfg.use_redis and redis is not None and self._can_use_redis():
            self._backend = RedisCounter(self._redis_client(), window_seconds=self.cfg.window_seconds)
            self._use_redis = True
        else:
            self._backend = SlidingWindowRateLimiter(limit=self.cfg.request_limit, window_seconds=self.cfg.window_seconds)
            self._use_redis = False

    def _can_use_redis(self) -> bool:
        return True  # Attempt; connection errors handled at runtime

    def _redis_client(self):  # pragma: no cover
        assert redis is not None
        return redis.from_url("redis://localhost:6379/0", decode_responses=True)

    def is_banned(self, ip: str, now: Optional[float] = None) -> bool:
        t = now if now is not None else time.time()
        until = self.banned_until.get(ip, 0)
        if until and until > t:
            return True
        if until and until <= t:
            self.banned_until.pop(ip, None)
        return False

    def register_request(self, ip: str, now: Optional[float] = None) -> Optional[int]:
        """
        Returns current request count in window if limit exceeded, else None.
        """
        if self.is_banned(ip, now=now):
            return self.cfg.request_limit + 1
        allowed, count = self._backend.hit(ip, now=now)
        # With RedisCounter, allowed is always True; enforce policy here
        if count > self.cfg.request_limit:
            t = now if now is not None else time.time()
            self.banned_until[ip] = t + self.cfg.ban_seconds
            self.logger.warning("DDoS ban applied to %s for %ss (count=%s)", ip, self.cfg.ban_seconds, count)
            return count
        return None
