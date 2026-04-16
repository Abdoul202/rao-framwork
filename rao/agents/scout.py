"""
Scout Agent - Reconnaissance & Enumeration

Responsibilities:
    - Port scanning via nmap
    - Service/version detection
    - OS fingerprinting
    - Populating HostInfo into MissionState
"""

from __future__ import annotations

import logging

from rao.core.state import HostInfo, MissionState, PortInfo
from rao.tools.nmap_wrapper import NmapScanner

logger = logging.getLogger(__name__)


class ScoutAgent:
    """Performs automated reconnaissance on target hosts."""

    def __init__(self) -> None:
        self.scanner = NmapScanner()

    def run(self, mission: MissionState) -> MissionState:
        """Scan all targets in scope and populate hosts."""
        logger.info("Scout starting reconnaissance on %s", mission.target)

        for target in mission.scope:
            try:
                host = self._scan_target(target)
                if host:
                    mission.hosts.append(host)
                    logger.info(
                        "Found %d open ports on %s", len(host.ports), host.ip
                    )
            except Exception as e:
                error_msg = f"Scout scan failed for {target}: {e}"
                logger.error(error_msg)
                mission.errors.append(error_msg)

        logger.info(
            "Scout completed: %d hosts discovered", len(mission.hosts)
        )
        return mission

    def _scan_target(self, target: str) -> HostInfo | None:
        """Run nmap scan and parse results into HostInfo."""
        scan_result = self.scanner.scan(target, arguments="-sV -sC --top-ports 1000")

        if not scan_result:
            return None

        host = scan_result[0]
        ports = [
            PortInfo(
                port=p["port"],
                protocol=p["protocol"],
                state=p["state"],
                service=p["service"],
                version=p.get("version", ""),
            )
            for p in host.get("ports", [])
            if p["state"] == "open"
        ]

        return HostInfo(
            ip=host["ip"],
            hostname=host.get("hostname", ""),
            os_guess=host.get("os_guess", ""),
            ports=ports,
        )
