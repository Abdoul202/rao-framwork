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

logger = logging.getLogger(__name__)


class ScoutAgent:
    """Performs automated reconnaissance on target hosts.

    N26 fix: NmapScanner is lazy-initialized. If nmap is not installed on
    the system, the error is caught at first use and logged clearly rather
    than crashing on import/init.
    """

    def __init__(self) -> None:
        self._scanner = None  # N26: lazy init

    @property
    def scanner(self):
        """Lazy-load NmapScanner to handle missing system nmap gracefully."""
        if self._scanner is None:
            try:
                from rao.tools.nmap_wrapper import NmapScanner
                self._scanner = NmapScanner()
            except Exception as e:
                logger.error(
                    "Scout: cannot initialize nmap scanner. "
                    "Is nmap installed? (sudo apt-get install nmap). Error: %s", e
                )
                raise RuntimeError(
                    f"nmap is required for the Scout agent. Install it first: {e}"
                ) from e
        return self._scanner

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
            except RuntimeError as e:
                # nmap not installed — abort all scans, no point continuing
                error_msg = f"Scout aborted: {e}"
                logger.error(error_msg)
                mission.errors.append(error_msg)
                break
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
