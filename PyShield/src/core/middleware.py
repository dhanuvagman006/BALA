from __future__ import annotations

import time
from typing import Callable, Optional
from fastapi import Request, Response, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from core.firewall import PyShield
from modules.ddos_protection import DDoSProtector
from modules.url_blocking import URLBlocker
from modules.intrusion_detection import IntrusionDetector
from modules.geo_blocking import GeoBlocker


class FirewallMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, pyshield: PyShield, ddos: DDoSProtector, 
                 url_blocker: URLBlocker, ids: IntrusionDetector, 
                 geo_blocker: GeoBlocker = None):
        super().__init__(app)
        self.pyshield = pyshield
        self.ddos = ddos
        self.url_blocker = url_blocker
        self.ids = ids
        self.geo_blocker = geo_blocker
    
    def get_client_ip(self, request: Request) -> str:
        """Extract client IP from request headers"""
        # Check X-Forwarded-For (from load balancers/proxies)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        # Check X-Real-IP
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fall back to direct connection IP
        return request.client.host if request.client else "unknown"
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = self.get_client_ip(request)
        request_time = time.time()
        
        try:
            # 1. Check DDoS protection
            if self.ddos and self.ddos.cfg.enabled:
                if self.ddos.is_banned(client_ip):
                    self.pyshield.on_ddos_block(client_ip, self.ddos.cfg.request_limit + 1)
                    return JSONResponse(
                        status_code=429,
                        content={"error": "Too Many Requests", "message": "IP temporarily banned"}
                    )
                
                # Register request and check if it exceeds limit
                exceeded_count = self.ddos.register_request(client_ip)
                if exceeded_count is not None:
                    self.pyshield.on_ddos_block(client_ip, exceeded_count)
                    return JSONResponse(
                        status_code=429,
                        content={"error": "Too Many Requests", "message": f"Rate limit exceeded: {exceeded_count} requests"}
                    )
            
            # 2. Check geo-blocking
            if self.geo_blocker and self.geo_blocker.cfg.enabled:
                is_blocked = self.geo_blocker.is_blocked(client_ip)
                if is_blocked:
                    return JSONResponse(
                        status_code=403,
                        content={"error": "Forbidden", "message": "Access denied from your location"}
                    )
            
            # 3. Check URL blocking
            if self.url_blocker and self.url_blocker.cfg.enabled:
                url = str(request.url)
                if self.url_blocker.is_malicious(url):
                    self.pyshield.on_url_block(url)
                    return JSONResponse(
                        status_code=403,
                        content={"error": "Forbidden", "message": "Access to malicious URL blocked"}
                    )
            
            # 4. Process the request
            response = await call_next(request)
            
            # 5. Check for authentication failures (for IDS)
            if response.status_code == 401 and self.ids and self.ids.cfg.enabled:
                # Register failed login attempt
                is_banned = self.ids.register_failed_login(client_ip)
                if is_banned:
                    self.pyshield.on_attack_detected("brute-force", {"ip": client_ip, "failed_attempts": self.ids.cfg.failed_login_threshold})
            
            return response
            
        except Exception as e:
            # Log the error but don't block the request
            self.pyshield.logger.error(f"Firewall middleware error: {e}")
            return await call_next(request)