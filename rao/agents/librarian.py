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
import re

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
If none are relevant, respond with exactly: NONE
"""

# Regex patterns that suggest prompt injection attempts in CVE descriptions
_INJECTION_PATTERNS = re.compile(
    r"^\s*(VERDICT|FINDING|TOOL|APPROACH|EXAMPLE|PREREQUISITE|RISK"
    r"|CVE_ID|SEVERITY|EXPLOITABILITY|REASONING|VERIFICATION)\s*:",
    re.IGNORECASE | re.MULTILINE,
)


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
        # BUG #12 fix: search even when version is unknown — just use service name.
        # Previously, services without a detected version returned [] silently,
        # missing 30-50% of CVE lookup opportunities.
        service_name = port_info.service.strip()
        version = port_info.version.strip()
        search_term = f"{service_name} {version}".strip() if version else service_name

        if not search_term:
            return []

        cves = self.cve_lookup.search(search_term)
        if not cves:
            return []

        # BUG #14 fix: sanitize CVE descriptions before injecting into LLM prompt
        cve_text = "\n".join(
            f"- {c['id']}: {self._sanitize_for_prompt(c['description'])}"
            for c in cves[:15]
        )

        prompt = ANALYSIS_PROMPT.format(
            service=service_name,
            version=version or "unknown",
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

    @staticmethod
    def _sanitize_for_prompt(text: str) -> str:
        """BUG #14 fix: strip prompt-injection patterns from CVE descriptions.

        CVE descriptions come from the NVD API (external, untrusted data).
        They could theoretically contain lines that manipulate the LLM prompt
        (e.g. 'VERDICT: TRUE_POSITIVE'). We remove those patterns.
        """
        # Remove lines that match known prompt keyword patterns
        sanitized = _INJECTION_PATTERNS.sub("", text)
        # Remove control characters except newlines
        sanitized = "".join(c for c in sanitized if ord(c) >= 32 or c == "\n")
        return sanitized.strip()[:200]

    def _parse_llm_findings(
        self, response: str, host: str, port: int
    ) -> list[Finding]:
        """Parse the structured LLM response into Finding objects.

        BUG #11 fix: now uses LibrarianFinding structured model.
        BUG #13 fix: NONE check is exact-match only (was substring match,
        which could match CVE IDs containing 'none').
        """
        from rao.core.structured_output import LibrarianFinding

        # BUG #13 fix: exact match, case-insensitive
        if response.strip().upper() == "NONE":
            return []

        findings = []
        for line in response.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            lf = LibrarianFinding.parse_llm_line(line)
            if lf is None:
                continue

            severity = self._parse_severity(lf.severity)
            findings.append(
                Finding(
                    title=f"{lf.cve_id} - {lf.description[:80]}",
                    severity=severity,
                    description=lf.description,
                    evidence=lf.why_relevant,
                    host=host,
                    port=port,
                    cve_ids=[lf.cve_id],
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
