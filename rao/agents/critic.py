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
        # BUG #9 fix: do NOT init LLM at construction time.
        # Lazy init avoids RuntimeError on startup when no provider is available,
        # and allows re-initialization if the token expires mid-mission.
        self._llm = None

    def _get_llm(self):
        """Lazy-load LLM. Returns None if no provider is reachable."""
        if self._llm is None:
            # BUG #9 fix: use get_llm_or_none — never raises, returns None on failure
            from rao.core.llm import get_llm_or_none
            self._llm = get_llm_or_none()
        return self._llm

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

        llm = self._get_llm()
        if llm is None:
            # No LLM available — use safe offline fallback immediately
            return self._offline_fallback(finding)

        try:
            response = llm.invoke(prompt)
            return self._parse_verdict(response.content, finding)
        except Exception as e:
            logger.warning("Critic LLM call failed for '%s': %s", finding.title, e)
            # BUG #9 fix: reset cached LLM so the next finding retries fresh
            # (handles token expiry, quota exceeded, transient API errors)
            self._llm = None
            return self._offline_fallback(finding)

    def _parse_verdict(self, response: str, finding: Finding) -> bool:
        """Parse the structured LLM verdict using CriticVerdict model."""
        from rao.core.structured_output import CriticVerdict, Exploitability, Verdict

        verdict = CriticVerdict.parse_llm_response(response)

        is_true_positive = (
            verdict.verdict == Verdict.TRUE_POSITIVE
            and verdict.exploitability != Exploitability.NONE
        )

        finding.validated = True
        finding.false_positive = not is_true_positive
        return is_true_positive

    def _offline_fallback(self, finding: Finding) -> bool:
        """Safe fallback when LLM is unavailable.

        Conservative policy: only keep CRITICAL and HIGH findings
        without LLM validation. Mark them clearly as unvalidated.
        Medium/Low/Info findings are dropped to avoid report noise.
        """
        from rao.core.state import Severity

        finding.validated = False   # Explicitly not validated by LLM
        finding.false_positive = False

        keep = finding.severity in (Severity.CRITICAL, Severity.HIGH)
        if keep:
            logger.info(
                "Offline fallback: keeping unvalidated finding '%s' (severity=%s)",
                finding.title,
                finding.severity.value,
            )
        return keep
