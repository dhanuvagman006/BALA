from __future__ import annotations

import argparse
import os
import signal
import sys
import threading

import uvicorn

from core.config import ConfigLoader
from core.firewall import PyShield
from core.logging_system import LoggerFactory
from modules.ddos_protection import DDoSProtector
from modules.url_blocking import URLBlocker
from modules.port_blocking import PortBlocker
from modules.intrusion_detection import IntrusionDetector
from modules.inspection import PacketInspector
from dashboard.api import create_app
from core.proxy_server import HTTPProxyServer


def run_dashboard(pyshield: PyShield, cfg, url_blocker, port_blocker):
    app = create_app(pyshield, cfg, url_blocker=url_blocker, port_blocker=port_blocker)
    uvicorn.run(app, host=cfg.dashboard.host, port=cfg.dashboard.port, log_level="info")


def main(argv=None):
    argv = argv or sys.argv[1:]
    parser = argparse.ArgumentParser(description="PyShield - Advanced Python Firewall")
    # Get the directory of this script, then go up one level to find config
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_config = os.path.join(script_dir, "config", "config.yaml")
    parser.add_argument("--config", "-c", default=default_config, help="Path to YAML config")
    args = parser.parse_args(argv)

    # Load config (fall back to example if not present)
    cfg_path = args.config
    if not os.path.exists(cfg_path):
        example = os.path.join(os.getcwd(), "config", "config.example.yaml")
        cfg_path = example if os.path.exists(example) else args.config

    cfg = ConfigLoader.from_yaml(cfg_path)
    logger = LoggerFactory.get_logger("pyshield.boot", level=cfg.logging.level, json_mode=cfg.logging.json,
                                     log_dir=cfg.logging.log_dir, file_name=cfg.logging.file_name,
                                     max_mb=cfg.logging.max_mb, backups=cfg.logging.backups)

    # Initialize all modules
    url_blocker = URLBlocker(cfg.url_blocking)
    port_blocker = PortBlocker(cfg.port_blocking)
    ids = IntrusionDetector(cfg.ids)
    ddos = DDoSProtector(cfg.ddos)
    
    # Initialize PyShield with references to modules
    pyshield = PyShield(cfg)
    pyshield.url_blocker = url_blocker
    pyshield.port_blocker = port_blocker
    pyshield.intrusion_detector = ids
    pyshield.ddos_protector = ddos
    pyshield.geo_blocker = None  # Optional module
    
    # Initialize proxy server
    proxy_server = HTTPProxyServer(cfg, pyshield)
    pyshield.proxy_server = proxy_server
    
    inspector = PacketInspector(cfg.inspection, on_portscan_detected=lambda kind, info: pyshield.on_attack_detected(kind, info))

    pyshield.start()
    url_blocker.start()
    inspector.start()

    # Start proxy server in background
    proxy_thread = None
    if hasattr(cfg.dashboard, 'enable_proxy') and cfg.dashboard.enable_proxy:
        def run_proxy():
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(proxy_server.start())
                loop.run_forever()
            except Exception as e:
                logger.error(f"Proxy server error: {e}")
            finally:
                loop.close()
        
        proxy_thread = threading.Thread(target=run_proxy, daemon=True)
        proxy_thread.start()
        logger.info("Proxy server started on port 8888")

    dash_thread = None
    stop_event = threading.Event()

    def shutdown(*_):
        logger.info("Shutting down...")
        stop_event.set()
        url_blocker.stop()
        inspector.stop()
        pyshield.stop()
        if proxy_thread:
            try:
                import asyncio
                asyncio.run(proxy_server.stop())
            except:
                pass
        if dash_thread:
            # uvicorn will stop on signal
            pass

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    if cfg.dashboard.enabled:
        dash_thread = threading.Thread(target=run_dashboard, args=(pyshield, cfg, url_blocker, port_blocker), daemon=True)
        dash_thread.start()
        logger.info("Dashboard running at http://%s:%s", cfg.dashboard.host, cfg.dashboard.port)

    # Idle loop to keep process alive when no other background work is enabled
    try:
        while not stop_event.is_set():
            stop_event.wait(0.5)
    finally:
        shutdown()


if __name__ == "__main__":
    main()
