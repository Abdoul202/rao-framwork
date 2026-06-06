"""
OSINT Collector — Passive open-source intelligence gathering.

Collects intelligence about a target from public sources without
sending any requests to the target itself.

Sources
-------
- WHOIS         : Domain registration info (python-whois or stdlib)
- Shodan        : Internet-connected device data (requires SHODAN_API_KEY)
- AlienVault OTX: Threat intelligence, malware reports, passive DNS
- Hunter.io     : Email addresses associated with the domain (requires HUNTER_API_KEY)
- GitHub Search : Potential secrets or config files leaked in public repos
- Google Dorks  : Informational dork queries (passive — not executed, just generated)

All sources that require API keys fail gracefully and are simply skipped.
"""

from __future__ import annotations

import logging
import os
import socket
from dataclasses import dataclass, field
from typing import Any

import requests

logger = logging.getLogger(__name__)


@dataclass
class OSINTResult:
    target: str

    # WHOIS
    whois: dict[str, Any] = field(default_factory=dict)

    # Shodan
    shodan_info: dict[str, Any] = field(default_factory=dict)

    # AlienVault OTX
    otx_pulses: list[dict] = field(default_factory=list)    # threat intel reports
    otx_malware: list[str] = field(default_factory=list)    # malware families

    # Hunter.io emails
    emails: list[dict] = field(default_factory=list)        # {email, first_name, last_name, position}

    # GitHub leaks
    github_results: list[dict] = field(default_factory=list)  # {name, url, description}

    # Google dorks (generated queries, not executed)
    google_dorks: list[str] = field(default_factory=list)

    # Consolidated findings
    findings: list[dict] = field(default_factory=list)      # {severity, title, detail}

    errors: list[str] = field(default_factory=list)


class OSINTCollector:
    """Gather passive OSINT on a domain or IP target.

    Parameters
    ----------
    timeout:
        HTTP request timeout in seconds.
    """

    REQUEST_TIMEOUT = 15

    def __init__(self, timeout: int = 15) -> None:
        self.timeout = timeout
        self._shodan_key     = os.getenv("SHODAN_API_KEY", "")
        self._hunter_key     = os.getenv("HUNTER_API_KEY", "")
        self._github_token   = os.getenv("GITHUB_TOKEN", "")

    def collect(self, target: str) -> OSINTResult:
        """Run all available OSINT sources against the target.

        Parameters
        ----------
        target:
            Domain name or IP address.

        Returns
        -------
        OSINTResult
            Aggregated OSINT data with structured findings.
        """
        result = OSINTResult(target=target)
        logger.info("OSINT collection starting for %s", target)

        is_ip = self._is_ip(target)

        # WHOIS — always attempt (stdlib fallback)
        self._collect_whois(target, result)

        # Shodan — requires API key
        if self._shodan_key:
            self._collect_shodan(target, result, is_ip)
        else:
            logger.info("OSINT: Shodan skipped (SHODAN_API_KEY not set)")

        # AlienVault OTX — free, no key required
        self._collect_otx(target, result)

        # Hunter.io emails — requires API key (only for domains)
        if self._hunter_key and not is_ip:
            self._collect_hunter(target, result)
        elif not is_ip:
            logger.info("OSINT: Hunter.io skipped (HUNTER_API_KEY not set)")

        # GitHub — free with or without token (token increases rate limits)
        if not is_ip:
            self._collect_github(target, result)

        # Google dorks — always generated (not executed)
        if not is_ip:
            result.google_dorks = self._generate_google_dorks(target)

        # Compile all findings
        self._compile_findings(result)

        logger.info(
            "OSINT complete for %s: %d findings, %d emails, %d OTX pulses",
            target, len(result.findings), len(result.emails), len(result.otx_pulses),
        )
        return result

    # ── WHOIS ─────────────────────────────────────────────────────────────────

    def _collect_whois(self, target: str, result: OSINTResult) -> None:
        """Domain/IP WHOIS lookup."""
        try:
            import whois as python_whois  # python-whois library
            w = python_whois.whois(target)
            result.whois = {
                "registrar":       str(w.registrar or ""),
                "creation_date":   str(w.creation_date or ""),
                "expiration_date": str(w.expiration_date or ""),
                "name_servers":    w.name_servers or [],
                "emails":          w.emails or [],
                "org":             str(w.org or ""),
                "country":         str(w.country or ""),
            }
            logger.info("WHOIS: registrar=%s", result.whois.get("registrar", ""))
        except ImportError:
            # Fallback: use socket for basic info
            try:
                ip = socket.gethostbyname(target)
                result.whois = {"resolved_ip": ip}
            except Exception:
                pass
            result.errors.append("python-whois not installed — pip install python-whois")
        except Exception as e:
            logger.debug("WHOIS failed: %s", e)
            result.errors.append(f"WHOIS error: {e}")

    # ── Shodan ────────────────────────────────────────────────────────────────

    def _collect_shodan(self, target: str, result: OSINTResult, is_ip: bool) -> None:
        """Query Shodan for exposed services."""
        try:
            if is_ip:
                url = f"https://api.shodan.io/shodan/host/{target}?key={self._shodan_key}"
            else:
                # Resolve domain to IP first
                ip = socket.gethostbyname(target)
                url = f"https://api.shodan.io/shodan/host/{ip}?key={self._shodan_key}"

            resp = requests.get(url, timeout=self.REQUEST_TIMEOUT)
            if resp.status_code == 404:
                logger.info("Shodan: no data for %s", target)
                return
            resp.raise_for_status()
            data = resp.json()

            result.shodan_info = {
                "ip":           data.get("ip_str", ""),
                "org":          data.get("org", ""),
                "isp":          data.get("isp", ""),
                "country":      data.get("country_name", ""),
                "open_ports":   data.get("ports", []),
                "hostnames":    data.get("hostnames", []),
                "vulns":        list(data.get("vulns", {}).keys()),
                "os":           data.get("os", ""),
                "last_update":  data.get("last_update", ""),
                "tags":         data.get("tags", []),
            }
            logger.info(
                "Shodan: %d open ports, %d vulns on %s",
                len(result.shodan_info["open_ports"]),
                len(result.shodan_info["vulns"]),
                target,
            )
        except Exception as e:
            logger.debug("Shodan query failed: %s", e)
            result.errors.append(f"Shodan error: {e}")

    # ── AlienVault OTX ────────────────────────────────────────────────────────

    def _collect_otx(self, target: str, result: OSINTResult) -> None:
        """Query AlienVault OTX for threat intelligence pulses and malware."""
        try:
            indicator_type = "IPv4" if self._is_ip(target) else "domain"
            base = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{target}"

            # General info
            resp = requests.get(f"{base}/general", timeout=self.REQUEST_TIMEOUT)
            if resp.ok:
                data = resp.json()
                pulse_info = data.get("pulse_info", {})
                pulses = pulse_info.get("pulses", [])
                result.otx_pulses = [
                    {
                        "name":        p.get("name", ""),
                        "description": p.get("description", "")[:200],
                        "tags":        p.get("tags", []),
                        "created":     p.get("created", ""),
                    }
                    for p in pulses[:10]  # cap at 10 pulses
                ]

            # Malware info
            resp = requests.get(f"{base}/malware", timeout=self.REQUEST_TIMEOUT)
            if resp.ok:
                data = resp.json()
                families: set[str] = set()
                for sample in data.get("data", []):
                    for detection in sample.get("detections", {}).values():
                        if detection:
                            families.add(str(detection))
                result.otx_malware = list(families)[:20]

            logger.info("OTX: %d pulses, %d malware families for %s",
                        len(result.otx_pulses), len(result.otx_malware), target)
        except Exception as e:
            logger.debug("OTX OSINT failed: %s", e)

    # ── Hunter.io ─────────────────────────────────────────────────────────────

    def _collect_hunter(self, target: str, result: OSINTResult) -> None:
        """Collect email addresses via Hunter.io (requires HUNTER_API_KEY)."""
        try:
            resp = requests.get(
                "https://api.hunter.io/v2/domain-search",
                params={"domain": target, "api_key": self._hunter_key, "limit": 20},
                timeout=self.REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            result.emails = [
                {
                    "email":      e.get("value", ""),
                    "first_name": e.get("first_name", ""),
                    "last_name":  e.get("last_name", ""),
                    "position":   e.get("position", ""),
                    "confidence": e.get("confidence", 0),
                }
                for e in data.get("emails", [])
            ]
            logger.info("Hunter.io: %d emails for %s", len(result.emails), target)
        except Exception as e:
            logger.debug("Hunter.io failed: %s", e)
            result.errors.append(f"Hunter.io error: {e}")

    # ── GitHub ────────────────────────────────────────────────────────────────

    def _collect_github(self, target: str, result: OSINTResult) -> None:
        """Search GitHub for potential secrets or config files mentioning the domain."""
        try:
            headers = {"Accept": "application/vnd.github.v3+json"}
            if self._github_token:
                headers["Authorization"] = f"Bearer {self._github_token}"

            queries = [
                f'"{target}" password',
                f'"{target}" api_key',
                f'"{target}" secret',
            ]

            found: list[dict] = []
            for query in queries:
                resp = requests.get(
                    "https://api.github.com/search/code",
                    params={"q": query, "per_page": 5},
                    headers=headers,
                    timeout=self.REQUEST_TIMEOUT,
                )
                if not resp.ok:
                    break  # Rate limited or auth error
                items = resp.json().get("items", [])
                for item in items:
                    found.append({
                        "name":        item.get("name", ""),
                        "path":        item.get("path", ""),
                        "url":         item.get("html_url", ""),
                        "repository":  item.get("repository", {}).get("full_name", ""),
                        "query":       query,
                    })

            result.github_results = found[:15]  # cap at 15
            if found:
                logger.warning("GitHub: %d potential leak results for %s", len(found), target)
        except Exception as e:
            logger.debug("GitHub search failed: %s", e)

    # ── Google Dorks ─────────────────────────────────────────────────────────

    def _generate_google_dorks(self, domain: str) -> list[str]:
        """Generate Google dork queries for manual investigation.

        These are NOT executed — they are provided for the analyst to run
        manually in a browser to avoid detection and legal issues.
        """
        return [
            f'site:{domain} filetype:env',
            f'site:{domain} filetype:sql',
            f'site:{domain} filetype:log',
            f'site:{domain} inurl:admin',
            f'site:{domain} inurl:login',
            f'site:{domain} inurl:api',
            f'site:{domain} intitle:"Index of"',
            f'site:{domain} "error" OR "exception" OR "traceback"',
            f'site:{domain} "DB_PASSWORD" OR "DB_USER" OR "DATABASE_URL"',
            f'site:{domain} "AWS_SECRET_ACCESS_KEY" OR "AWS_ACCESS_KEY_ID"',
            f'inurl:github.com "{domain}" password',
            f'inurl:pastebin.com "{domain}"',
            f'inurl:trello.com "{domain}"',
        ]

    # ── Finding compilation ───────────────────────────────────────────────────

    def _compile_findings(self, result: OSINTResult) -> None:
        """Convert raw OSINT data into structured findings."""

        def add(severity: str, title: str, detail: str) -> None:
            result.findings.append({"severity": severity, "title": title, "detail": detail})

        # Shodan vulnerabilities
        if result.shodan_info.get("vulns"):
            for cve in result.shodan_info["vulns"]:
                add("high", f"Shodan reports vulnerability: {cve}",
                    f"Shodan has indexed this CVE on {result.target}. Verify and patch.")

        if result.shodan_info.get("open_ports"):
            ports = result.shodan_info["open_ports"]
            risky = [p for p in ports if p in (21, 23, 3389, 5900, 6379, 27017, 9200)]
            for p in risky:
                port_names = {21: "FTP", 23: "Telnet", 3389: "RDP", 5900: "VNC",
                              6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch"}
                add("high", f"Risky service exposed on port {p} ({port_names.get(p, '')})",
                    f"Shodan sees port {p} open on {result.target}.")

        # OTX threat intel
        if result.otx_pulses:
            add("medium",
                f"Target flagged in {len(result.otx_pulses)} AlienVault OTX threat report(s)",
                f"Pulses: {', '.join(p['name'] for p in result.otx_pulses[:3])}")

        if result.otx_malware:
            add("high",
                f"Target associated with malware families: {', '.join(result.otx_malware[:5])}",
                "OTX reports malware activity originating from this target.")

        # GitHub leaks
        if result.github_results:
            add("high",
                f"{len(result.github_results)} potential credential leak(s) found on GitHub",
                f"URLs: {', '.join(r['url'] for r in result.github_results[:3])}")

        # WHOIS: check for expiring domain (hijacking risk)
        exp = result.whois.get("expiration_date", "")
        if exp and isinstance(exp, str) and exp:
            try:
                from datetime import datetime, timezone
                exp_dt = datetime.fromisoformat(exp.split("T")[0]).replace(tzinfo=timezone.utc)
                from datetime import datetime
                now = datetime.now(tz=timezone.utc)
                days = (exp_dt - now).days
                if 0 < days < 30:
                    add("high", f"Domain expiring in {days} days — hijacking risk",
                        f"Domain {result.target} expires {exp}. Renewal required.")
            except Exception:
                pass

        # Emails discovered → social engineering surface
        if result.emails:
            email_list = [e["email"] for e in result.emails[:5]]
            add("info",
                f"{len(result.emails)} email address(es) discovered via Hunter.io",
                f"Emails: {', '.join(email_list)}")

    @staticmethod
    def _is_ip(target: str) -> bool:
        """Return True if target is a bare IP address."""
        import ipaddress
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
