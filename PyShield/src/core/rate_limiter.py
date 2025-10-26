from __future__ import annotations

import time
from collections import deque
from typing import Deque, Dict, Tuple, Optional, Any

try:
    import redis  # type: ignore
except Exception:  # pragma: no cover
    redis = None  # type: ignore


class SlidingWindowRateLimiter:
    def __init__(self, *, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window = window_seconds
        self.events: Dict[str, Deque[float]] = {}

    def hit(self, key: str, now: Optional[float] = None) -> Tuple[bool, int]:
        t = now if now is not None else time.time()
        q = self.events.setdefault(key, deque())
        q.append(t)
        # Evict old
        cutoff = t - self.window
        while q and q[0] < cutoff:
            q.popleft()
        allowed = len(q) <= self.limit
        return allowed, len(q)


class RedisCounter:
    def __init__(self, client: Any, *, window_seconds: int) -> None:
        self.client = client
        self.window = window_seconds

    def hit(self, key: str, now: Optional[float] = None) -> Tuple[bool, int]:  # pragma: no cover (requires redis)
        t = int(now if now is not None else time.time())
        pipe = self.client.pipeline(True)
        redis_key = f"rl:{key}:{t // self.window}"
        pipe.incr(redis_key, 1)
        pipe.expire(redis_key, self.window + 1)
        count, _ = pipe.execute()
        return True, int(count)  # Policy enforcement based on count is done by the caller
