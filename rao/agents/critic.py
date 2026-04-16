"""
Critic Agent - Validation & False Positive Filtering

Responsibilities:
    - Review findings from the Librarian
    - Use LLM reasoning to assess exploitability
    - Filter out false positives
    - Assign confidence scores
    - Produce validated findings list
"""

from __future__ import annotations

import logging

from rao.core.llm import get_llm
from rao.core.state import Finding, MissionState

logger = logging.getLogger(__name__)

VALIDATION_PROMPT = """You are a senior penetration tester reviewing automated scan findings.
Your job is to filter false positives and assess real exploitability.

Finding: {title}
Severity: {severity}
Host: {host}:{port}
Description: {description}
Evidence: {evidence}
CVEs: {cves}

Assess this finding:
1. Is this likely a TRUE POSITIVE or FALSE POSITIVE?
2. What is the realistic exploitability? (HIGH / MEDIUM / LOW / NONE)
3. What additional verification would confirm this?

Respond in this exact format:
VERDICT: TRUE_POSITIVE or FALSE_POSITIVE
EXPLOITABILITY: HIGH or MEDIUM or LOW or NONE
REASONING: <one paragraph>
VERIFICATION: <suggested next step>
"""


class CriticAgent:
    """Validates findings and filters false positives using LLM reasoning."""

    def __init__(self) -> None:
        self.llm = None

    def _get_llm(self):
        if self.llm is None:
            self.llm = get_llm()
        return self.llm

    def run(self, mission: MissionState) -> MissionState:
        """Review all findings and separate validated from false positives."""
        logger.info("Critic reviewing %d findings", len(mission.findings))

        for finding in mission.findings:
            validated = self._validate_finding(finding)
            if validated:
                mission.validated_findings.append(finding)

        logger.info(
            "Critic completed: %d/%d findings validated",
            len(mission.validated_findings),
            len(mission.findings),
        )
        return mission

    def _validate_finding(self, finding: Finding) -> bool:
        """Use LLM to determine if a finding is a true positive."""
        prompt = VALIDATION_PROMPT.format(
            title=finding.title,
            severity=finding.severity.value,
            host=finding.host,
            port=finding.port or "N/A",
            description=finding.description,
            evidence=finding.evidence,
            cves=", ".join(finding.cve_ids) if finding.cve_ids else "None",
        )

        try:
            llm = self._get_llm()
            response = llm.invoke(prompt)
            return self._parse_verdict(response.content, finding)
        except Exception as e:
            logger.warning("Critic validation failed for %s: %s", finding.title, e)
            # Conservative: keep finding if we can't validate
            finding.validated = False
            return True

    def _parse_verdict(self, response: str, finding: Finding) -> bool:
        """Parse the LLM verdict and update the finding."""
        lines = response.strip().split("\n")

        is_true_positive = True
        for line in lines:
            if line.startswith("VERDICT:"):
                verdict = line.split(":", 1)[1].strip().upper()
                is_true_positive = "TRUE" in verdict
            elif line.startswith("EXPLOITABILITY:"):
                exploitability = line.split(":", 1)[1].strip().upper()
                if exploitability == "NONE":
                    is_true_positive = False

        if is_true_positive:
            finding.validated = True
            finding.false_positive = False
        else:
            finding.validated = True
            finding.false_positive = True

        return is_true_positive
