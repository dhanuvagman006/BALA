from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional

from core.config import InspectionConfig
from core.logging_system import LoggerFactory

try:
    from scapy.all import sniff  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover
    SCAPY_AVAILABLE = False


class PortScanDetector:
    def __init__(self, threshold: int, window_seconds: int):
        self.threshold = threshold
        self.window = window_seconds
        self._by_ip: Dict[str, Deque[tuple[float, int]]] = defaultdict(deque)

    def _purge(self, q: Deque[tuple[float, int]], now: float) -> None:
        cutoff = now - self.window
        while q and q[0][0] < cutoff:
            q.popleft()

    def observe(self, src_ip: str, dst_port: int, now: Optional[float] = None) -> bool:
        t = now if now is not None else time.time()
        q = self._by_ip[src_ip]
        q.append((t, dst_port))
        self._purge(q, t)
        unique_ports = {p for _, p in q}
        return len(unique_ports) >= self.threshold


class PacketInspector:
    def __init__(self, cfg: InspectionConfig, on_portscan_detected):
        self.cfg = cfg
        self.logger = LoggerFactory.get_logger("pyshield.inspect")
        self.detector = PortScanDetector(cfg.portscan_threshold, cfg.window_seconds)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._callback = on_portscan_detected

    def start(self) -> None:
        if not self.cfg.enabled:
            return
        if not SCAPY_AVAILABLE:
            self.logger.warning("Scapy not available; inspection disabled")
            return
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self.logger.info("Packet inspector started")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self) -> None:  # pragma: no cover (requires scapy & privileges)
        def on_pkt(pkt):
            try:
                if not pkt.haslayer('IP'):
                    return
                ip = pkt['IP']
                src = ip.src
                dst_port = None
                if pkt.haslayer('TCP'):
                    dst_port = int(pkt['TCP'].dport)
                elif pkt.haslayer('UDP'):
                    dst_port = int(pkt['UDP'].dport)
                if dst_port is None:
                    return
                if self.detector.observe(src, dst_port):
                    self._callback("port-scan", {"src_ip": src, "unique_ports": self.cfg.portscan_threshold})
            except Exception as e:
                self.logger.debug("Inspection error: %s", e)

        sniff_kwargs = {}
        if self.cfg.interface:
            sniff_kwargs['iface'] = self.cfg.interface
        if self.cfg.bpf_filter:
            sniff_kwargs['filter'] = self.cfg.bpf_filter
        sniff(store=False, prn=on_pkt, stop_filter=lambda _: self._stop.is_set(), **sniff_kwargs)
