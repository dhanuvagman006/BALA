from __future__ import annotations

import platform
import subprocess
from typing import Iterable, List, Tuple

from core.config import PortBlockingConfig
from core.logging_system import LoggerFactory


class PortBlocker:
    def __init__(self, cfg: PortBlockingConfig):
        self.cfg = cfg
        self.logger = LoggerFactory.get_logger("pyshield.ports")

    def _run(self, cmd: List[str]) -> Tuple[int, str, str]:
        if self.cfg.dry_run:
            self.logger.info("[dry-run] %s", " ".join(cmd))
            return 0, "", ""
        proc = subprocess.run(cmd, capture_output=True, text=True)
        return proc.returncode, proc.stdout, proc.stderr

    def block_ports(self, ports: Iterable[int]) -> None:
        os_name = platform.system()
        for port in ports:
            if os_name == "Windows":
                # netsh advfirewall firewall add rule name=... dir=in action=block protocol=TCP localport=PORT
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=PyShield_Block_{port}", "dir=in", "action=block",
                    "protocol=TCP", f"localport={port}",
                ]
            else:
                cmd = [
                    "sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"
                ]
            rc, out, err = self._run(cmd)
            if rc == 0:
                self.logger.info("Port %s blocked", port)
            else:
                self.logger.error("Failed to block port %s: %s %s", port, out, err)

    def unblock_ports(self, ports: Iterable[int]) -> None:
        os_name = platform.system()
        for port in ports:
            if os_name == "Windows":
                cmd = [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name=PyShield_Block_{port}", "protocol=TCP", f"localport={port}",
                ]
            else:
                cmd = [
                    "sudo", "iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"
                ]
            rc, out, err = self._run(cmd)
            if rc == 0:
                self.logger.info("Port %s unblocked", port)
            else:
                self.logger.error("Failed to unblock port %s: %s %s", port, out, err)
