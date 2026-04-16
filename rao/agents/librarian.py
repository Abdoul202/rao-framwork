"""
Librarian Agent - Knowledge Management & CVE Correlation

Responsibilities:
    - Correlate discovered services with known CVEs (NVD API)
    - Store and retrieve knowledge from ChromaDB and Neo4j
    - Use LLM to assess relevance of CVEs to the target context
    - Generate initial findings from correlated data
"""

from __future__ import annotations

import logging

from rao.core.llm import get_llm
from rao.core.state import Finding, MissionState, Severity
from rao.tools.cve_lookup import CVELookup

logger = logging.getLogger(__name__)

ANALYSIS_PROMPT = """You are a cybersecurity analyst. Given a service and its known CVEs,
assess which vulnerabilities are most likely exploitable in this context.

Service: {service} {version}
Host: {host}:{port}

Known CVEs:
{cves}

For each relevant CVE, respond in this exact format (one per line):
CVE_ID | SEVERITY | DESCRIPTION | WHY_RELEVANT

Only include CVEs that are realistically exploitable given the service version.
If none are relevant, respond with: NONE
"""


class LibrarianAgent:
    """Correlates scan results with vulnerability databases."""

    def __init__(self) -> None:
        self.cve_lookup = CVELookup()
        self.llm = None  # Lazy init to avoid import cost if not needed

    def _get_llm(self):
        if self.llm is None:
            self.llm = get_llm()
        return self.llm

    def run(self, mission: MissionState) -> MissionState:
        """Analyze all discovered hosts and generate findings."""
        logger.info("Librarian analyzing %d hosts", len(mission.hosts))

        for host in mission.hosts:
            for port_info in host.ports:
                findings = self._analyze_service(host.ip, port_info)
                mission.findings.extend(findings)

        logger.info(
            "Librarian completed: %d potential findings", len(mission.findings)
        )
        return mission

    def _analyze_service(self, host_ip: str, port_info) -> list[Finding]:
        """Look up CVEs for a service and assess relevance with LLM."""
        search_term = f"{port_info.service} {port_info.version}".strip()
        if not search_term or search_term == port_info.service:
            return []

        cves = self.cve_lookup.search(search_term)
        if not cves:
            return []

        cve_text = "\n".join(
            f"- {c['id']}: {c['description'][:200]}" for c in cves[:15]
        )

        prompt = ANALYSIS_PROMPT.format(
            service=port_info.service,
            version=port_info.version,
            host=host_ip,
            port=port_info.port,
            cves=cve_text,
        )

        try:
            llm = self._get_llm()
            response = llm.invoke(prompt)
            return self._parse_llm_findings(
                response.content, host_ip, port_info.port
            )
        except Exception as e:
            logger.warning("LLM analysis failed for %s: %s", search_term, e)
            return self._fallback_findings(cves[:3], host_ip, port_info.port)

    def _parse_llm_findings(
        self, response: str, host: str, port: int
    ) -> list[Finding]:
        """Parse the structured LLM response into Finding objects."""
        findings = []
        if "NONE" in response.strip():
            return findings

        for line in response.strip().split("\n"):
            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 4:
                continue

            cve_id, severity_str, description, evidence = parts[:4]
            severity = self._parse_severity(severity_str)

            findings.append(
                Finding(
                    title=f"{cve_id} - {description[:80]}",
                    severity=severity,
                    description=description,
                    evidence=evidence,
                    host=host,
                    port=port,
                    cve_ids=[cve_id],
                )
            )
        return findings

    def _fallback_findings(
        self, cves: list[dict], host: str, port: int
    ) -> list[Finding]:
        """Create findings directly from CVE data when LLM is unavailable."""
        return [
            Finding(
                title=f"{c['id']} - {c['description'][:80]}",
                severity=self._parse_severity(c.get("severity", "medium")),
                description=c["description"],
                evidence="Matched by service version (LLM analysis unavailable)",
                host=host,
                port=port,
                cve_ids=[c["id"]],
            )
            for c in cves
        ]

    @staticmethod
    def _parse_severity(raw: str) -> Severity:
        raw_lower = raw.lower().strip()
        for sev in Severity:
            if sev.value in raw_lower:
                return sev
        return Severity.MEDIUM
