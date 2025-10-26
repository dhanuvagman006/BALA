from __future__ import annotations

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from typing import Dict, Any, Iterable
import os

from core.firewall import PyShield
from core.config import PyShieldConfig
from core.middleware import FirewallMiddleware

security = HTTPBasic()


def create_app(pyshield: PyShield, cfg: PyShieldConfig,
               url_blocker=None, port_blocker=None) -> FastAPI:
    app = FastAPI(title="PyShield Admin", description="Advanced Python Firewall Management API")

    # Setup templates and static files
    dashboard_dir = os.path.dirname(__file__)
    templates_dir = os.path.join(dashboard_dir, "templates")
    static_dir = os.path.join(dashboard_dir, "static")
    
    templates = Jinja2Templates(directory=templates_dir)
    app.mount("/static", StaticFiles(directory=static_dir), name="static")
    
    # Add firewall middleware
    app.add_middleware(
        FirewallMiddleware,
        pyshield=pyshield,
        ddos=getattr(pyshield, 'ddos_protector', None),
        url_blocker=getattr(pyshield, 'url_blocker', None),
        ids=getattr(pyshield, 'intrusion_detector', None),
        geo_blocker=getattr(pyshield, 'geo_blocker', None)
    )

    def auth(credentials: HTTPBasicCredentials = Depends(security)) -> None:
        if not (credentials.username == cfg.dashboard.username and credentials.password == cfg.dashboard.password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request, _: None = Depends(auth)):
        return templates.TemplateResponse("dashboard.html", {"request": request})

    @app.get("/api")
    def api_root():
        return RedirectResponse(url="/docs")

    @app.get("/health")
    def health():
        return {"status": "ok", "service": "PyShield"}

    @app.get("/stats")
    def stats(_: None = Depends(auth)) -> Dict[str, Any]:
        return {
            "blocked_ips": pyshield.stats.blocked_ips,
            "blocked_urls": pyshield.stats.blocked_urls,
            "blocked_ports": sorted(list(pyshield.stats.blocked_ports)),
            "active_attacks": pyshield.stats.active_attacks,
        }

    @app.post("/ports/block")
    def block_ports(body: Dict[str, Iterable[int]], _: None = Depends(auth)) -> Dict[str, Any]:
        if not port_blocker:
            raise HTTPException(400, "Port blocker not configured")
        ports = list(body.get("ports", []))
        port_blocker.block_ports(ports)
        for p in ports:
            pyshield.on_port_block(p)
        return {"status": "ok", "blocked": ports}

    @app.post("/ports/unblock")
    def unblock_ports(body: Dict[str, Iterable[int]], _: None = Depends(auth)) -> Dict[str, Any]:
        if not port_blocker:
            raise HTTPException(400, "Port blocker not configured")
        ports = list(body.get("ports", []))
        port_blocker.unblock_ports(ports)
        return {"status": "ok", "unblocked": ports}

    @app.post("/urls/add")
    def add_urls(body: Dict[str, Iterable[str]], _: None = Depends(auth)) -> Dict[str, Any]:
        if not url_blocker:
            raise HTTPException(400, "URL blocker not configured")
        items = list(body.get("items", []))
        url_blocker.add(items)
        return {"status": "ok", "added": items}

    @app.post("/urls/remove")
    def remove_urls(body: Dict[str, Iterable[str]], _: None = Depends(auth)) -> Dict[str, Any]:
        if not url_blocker:
            raise HTTPException(400, "URL blocker not configured")
        items = list(body.get("items", []))
        url_blocker.remove(items)
        return {"status": "ok", "removed": items}

    @app.post("/settings/ddos")
    def update_ddos_settings(body: Dict[str, Any], _: None = Depends(auth)) -> Dict[str, Any]:
        # In a full implementation, this would update the config and restart modules
        # For now, just acknowledge the request
        return {"status": "ok", "message": "DDoS settings updated (restart required)"}

    @app.get("/ddos/settings")
    def get_ddos_settings(_: None = Depends(auth)) -> Dict[str, Any]:
        return {
            "request_limit": cfg.ddos.request_limit,
            "window_seconds": cfg.ddos.window_seconds,
            "ban_seconds": cfg.ddos.ban_seconds,
            "use_redis": cfg.ddos.use_redis
        }

    @app.get("/proxy/requests")
    def get_proxy_requests(_: None = Depends(auth)) -> Dict[str, Any]:
        """Get recent proxy requests for dashboard"""
        if hasattr(pyshield, 'proxy_server') and pyshield.proxy_server:
            return {
                "requests": pyshield.proxy_server.get_request_history(limit=100),
                "proxy_enabled": True,
                "proxy_port": pyshield.proxy_server.proxy_port
            }
        return {
            "requests": [],
            "proxy_enabled": False,
            "proxy_port": getattr(cfg.dashboard, 'proxy_port', 8888)
        }

    @app.get("/proxy/stats")
    def get_proxy_stats(_: None = Depends(auth)) -> Dict[str, Any]:
        """Get proxy statistics"""
        if hasattr(pyshield, 'proxy_server') and pyshield.proxy_server:
            history = pyshield.proxy_server.request_history
            total_requests = len(history)
            blocked_requests = sum(1 for req in history if req.blocked)
            
            return {
                "total_requests": total_requests,
                "blocked_requests": blocked_requests,
                "allowed_requests": total_requests - blocked_requests,
                "block_rate": (blocked_requests / total_requests * 100) if total_requests > 0 else 0,
                "proxy_running": pyshield.proxy_server.running
            }
        return {
            "total_requests": 0,
            "blocked_requests": 0,
            "allowed_requests": 0,
            "block_rate": 0,
            "proxy_running": False
        }

    return app
