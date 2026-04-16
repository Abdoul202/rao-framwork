"""Nmap wrapper for Scout agent reconnaissance."""

from __future__ import annotations

import logging

import nmap

logger = logging.getLogger(__name__)


class NmapScanner:
    """Wrapper around python-nmap for structured scan results."""

    def __init__(self) -> None:
        self.nm = nmap.PortScanner()

    def scan(
        self, target: str, arguments: str = "-sV --top-ports 1000"
    ) -> list[dict]:
        """
        Run an nmap scan and return structured results.

        Returns a list of host dicts with keys: ip, hostname, os_guess, ports.
        Each port dict has: port, protocol, state, service, version.
        """
        logger.info("Scanning %s with args: %s", target, arguments)

        try:
            self.nm.scan(hosts=target, arguments=arguments)
        except nmap.PortScannerError as e:
            logger.error("Nmap scan error: %s", e)
            raise
        except Exception as e:
            logger.error("Unexpected scan error: %s", e)
            raise

        results = []
        for host in self.nm.all_hosts():
            host_data = {
                "ip": host,
                "hostname": self.nm[host].hostname(),
                "os_guess": self._get_os_guess(host),
                "ports": [],
            }

            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                for port in sorted(ports):
                    port_info = self.nm[host][proto][port]
                    host_data["ports"].append(
                        {
                            "port": port,
                            "protocol": proto,
                            "state": port_info["state"],
                            "service": port_info.get("name", "unknown"),
                            "version": self._build_version_string(port_info),
                        }
                    )

            results.append(host_data)

        logger.info("Scan complete: %d hosts found", len(results))
        return results

    def _get_os_guess(self, host: str) -> str:
        """Extract best OS guess if available."""
        try:
            os_matches = self.nm[host].get("osmatch", [])
            if os_matches:
                return os_matches[0].get("name", "")
        except (KeyError, IndexError):
            pass
        return ""

    @staticmethod
    def _build_version_string(port_info: dict) -> str:
        """Build a version string from nmap port info fields."""
        parts = [
            port_info.get("product", ""),
            port_info.get("version", ""),
            port_info.get("extrainfo", ""),
        ]
        return " ".join(p for p in parts if p).strip()
