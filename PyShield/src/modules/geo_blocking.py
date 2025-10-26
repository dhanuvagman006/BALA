from __future__ import annotations

from typing import Optional

from core.config import GeoBlockingConfig
from core.logging_system import LoggerFactory

try:
    import geoip2.database  # type: ignore
except Exception:  # pragma: no cover
    geoip2 = None  # type: ignore


class GeoBlocker:
    def __init__(self, cfg: GeoBlockingConfig):
        self.cfg = cfg
        self.logger = LoggerFactory.get_logger("pyshield.geo")
        self._reader = None
        if self.cfg.enabled and self.cfg.geoip_db_path and geoip2 is not None:
            try:  # pragma: no cover (requires DB file)
                self._reader = geoip2.Reader(self.cfg.geoip_db_path)
            except Exception as e:
                self.logger.error("GeoIP DB load failed: %s", e)

    def country_code(self, ip: str) -> Optional[str]:
        if not self._reader:
            return None
        try:  # pragma: no cover (requires DB file)
            r = self._reader.country(ip)
            return r.country.iso_code
        except Exception:
            return None

    def is_blocked(self, ip: str) -> Optional[bool]:
        if not self.cfg.enabled:
            return None
        code = self.country_code(ip)
        if code is None:
            return None
        if self.cfg.whitelist_countries and code in self.cfg.whitelist_countries:
            return False
        if self.cfg.blacklist_countries and code in self.cfg.blacklist_countries:
            return True
        return None
