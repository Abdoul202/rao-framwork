"""Nmap wrapper for Scout agent reconnaissance.

Scan profiles
-------------
quick   : -sV --top-ports 1000 -T4          (default, fast)
full    : -sV -p- -T4                        (all 65535 TCP ports)
stealth : -sS -sV -p- -T2                   (SYN stealth, slow/quiet)
udp     : -sU --top-ports 200 -T4           (top 200 UDP ports, requires root)
vuln    : -sV --script vuln -T4             (NSE vulnerability scripts)
smb     : -p 139,445 --script smb-security-mode,smb-vuln-*  (SMB/Windows checks)
web     : -p 80,443,8080,8443,8000,3000,5000 --script http-headers,http-title
"""

from __future__ import annotations

import logging
from typing import Literal

import nmap

logger = logging.getLogger(__name__)

ScanProfile = Literal["quick", "full", "stealth", "udp", "vuln", "smb", "web", "custom"]

SCAN_PROFILES: dict[str, str] = {
    "quick":   "-sV --top-ports 1000 -T4",
    "full":    "-sV -p- -T4",
    "stealth": "-sS -sV -p- -T2",
    "udp":     "-sU --top-ports 200 -T4",
    "vuln":    "-sV --script vuln -T4",
    "smb":     "-p 139,445 --script smb-security-mode,smb-vuln-ms17-010,smb-vuln-ms08-067 -T4",
    "web":     "-p 80,443,8080,8443,8000,3000,5000,8888 --script http-headers,http-title,http-methods -T4",
}


class NmapScanner:
    """Wrapper around python-nmap for structured scan results."""

    def __init__(self) -> None:
        self.nm = nmap.PortScanner()

    def scan(
        self,
        target: str,
        arguments: str | None = None,
        profile: ScanProfile = "quick",
    ) -> list[dict]:
        """Run an nmap scan and return structured results.

        Parameters
        ----------
        target:
            IP address, hostname, or CIDR range.
        arguments:
            Raw nmap arguments string. Overrides ``profile`` if provided.
        profile:
            Named scan profile (quick/full/stealth/udp/vuln/smb/web).
            Ignored when ``arguments`` is set explicitly.

        Returns
        -------
        list[dict]
            List of host dicts: {ip, hostname, os_guess, ports, scripts}.
            Each port dict: {port, protocol, state, service, version, scripts}.
        """
        args = arguments if arguments is not None else SCAN_PROFILES.get(profile, SCAN_PROFILES["quick"])
        logger.info("Scanning %s | profile=%s | args: %s", target, profile, args)

        try:
            self.nm.scan(hosts=target, arguments=args)
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
                "scripts": self._get_host_scripts(host),  # host-level NSE output
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
                            "scripts": port_info.get("script", {}),  # per-port NSE output
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

    def _get_host_scripts(self, host: str) -> dict:
        """Extract host-level NSE script output (e.g. from --script vuln)."""
        try:
            return self.nm[host].get("hostscript", {})
        except Exception:
            return {}

    @staticmethod
    def _build_version_string(port_info: dict) -> str:
        """Build a version string from nmap port info fields."""
        parts = [
            port_info.get("product", ""),
            port_info.get("version", ""),
            port_info.get("extrainfo", ""),
        ]
        return " ".join(p for p in parts if p).strip()

    @staticmethod
    def list_profiles() -> dict[str, str]:
        """Return all available scan profiles and their nmap arguments."""
        return dict(SCAN_PROFILES)
