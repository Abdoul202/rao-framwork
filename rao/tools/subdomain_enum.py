"""
Subdomain Enumerator - Passive subdomain discovery.

Sources:
    - crt.sh (Certificate Transparency logs)
    - DNS brute-force with common subdomain wordlist
"""

from __future__ import annotations

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

logger = logging.getLogger(__name__)

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "admin", "api",
    "dev", "staging", "test", "beta", "demo", "app", "portal",
    "vpn", "remote", "git", "gitlab", "jenkins", "ci", "cd",
    "monitor", "grafana", "kibana", "elastic", "db", "database",
    "mysql", "postgres", "redis", "mongo", "backup", "old",
    "new", "v2", "internal", "intranet", "owa", "exchange",
    "autodiscover", "sso", "auth", "login", "cdn", "static",
    "assets", "img", "images", "media", "docs", "wiki", "blog",
    "shop", "store", "pay", "billing", "support", "help", "status",
    "health", "metrics", "prometheus", "traefik", "proxy", "lb",
    "gateway", "edge", "mobile", "m", "graphql", "ws", "socket",
    "chat", "slack", "jira", "confluence", "bitbucket",
]


class SubdomainEnumerator:
    """Discover subdomains through passive and active methods."""

    def __init__(self, timeout: int = 5, max_workers: int = 20) -> None:
        self.timeout = timeout
        self.max_workers = max_workers

    def enumerate(self, domain: str) -> list[dict]:
        """
        Discover subdomains for a domain.

        Returns list of dicts: {subdomain, ip, source}
        """
        logger.info("Enumerating subdomains for %s", domain)
        found: dict[str, dict] = {}

        # Passive: Certificate Transparency
        ct_subs = self._query_crtsh(domain)
        for sub in ct_subs:
            if sub not in found:
                ip = self._resolve(sub)
                if ip:
                    found[sub] = {"subdomain": sub, "ip": ip, "source": "crt.sh"}

        # Active: DNS brute-force
        dns_subs = self._dns_bruteforce(domain)
        for sub, ip in dns_subs:
            if sub not in found:
                found[sub] = {"subdomain": sub, "ip": ip, "source": "dns-brute"}

        results = list(found.values())
        logger.info("Found %d subdomains for %s", len(results), domain)
        return results

    def _query_crtsh(self, domain: str) -> list[str]:
        """Query crt.sh Certificate Transparency logs."""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            resp = requests.get(url, timeout=15)
            resp.raise_for_status()
            entries = resp.json()

            subdomains = set()
            for entry in entries:
                name = entry.get("name_value", "")
                for line in name.split("\n"):
                    line = line.strip().lower()
                    if line.endswith(f".{domain}") or line == domain:
                        # Skip wildcards
                        if not line.startswith("*"):
                            subdomains.add(line)

            logger.info("crt.sh returned %d unique subdomains", len(subdomains))
            return list(subdomains)

        except Exception as e:
            logger.warning("crt.sh query failed: %s", e)
            return []

    def _dns_bruteforce(self, domain: str) -> list[tuple[str, str]]:
        """Resolve common subdomain names via DNS."""
        results = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for prefix in COMMON_SUBDOMAINS:
                fqdn = f"{prefix}.{domain}"
                futures[executor.submit(self._resolve, fqdn)] = fqdn

            for future in as_completed(futures):
                fqdn = futures[future]
                try:
                    ip = future.result()
                    if ip:
                        results.append((fqdn, ip))
                except Exception:
                    continue

        return results

    def _resolve(self, hostname: str) -> str | None:
        """Resolve hostname to IP address."""
        try:
            ip = socket.gethostbyname(hostname)
            return ip
        except socket.gaierror:
            return None
