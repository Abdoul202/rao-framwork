"""
Operator Agent - Exploitation Planning (v0.2)

Generates actionable, tool-specific attack strategies from validated findings.
All plans are for AUTHORIZED penetration testing only.
"""

from __future__ import annotations

import logging

from rao.core.state import MissionState, Severity

logger = logging.getLogger(__name__)

OPERATOR_PROMPT = """You are an expert penetration tester creating a structured attack plan.
All actions below are for AUTHORIZED testing only on systems you have permission to test.

Validated findings (HIGH/CRITICAL only):
{findings}

For each finding, provide a concise exploitation strategy:

FINDING: <exact title>
TOOL: <recommended tool, e.g. metasploit, sqlmap, curl, nuclei, manual>
APPROACH: <1-2 sentence description of the exploitation technique>
EXAMPLE: <example command or payload — use placeholders like TARGET_IP>
PREREQUISITE: <what must be confirmed before attempting this>
RISK: <LOW | MEDIUM | HIGH — risk of detection/system impact>
---
"""

# Maximum findings to include to avoid exceeding LLM context limits
MAX_FINDINGS = 10


class OperatorAgent:
    """Generates exploitation plans from validated HIGH/CRITICAL findings."""

    def __init__(self) -> None:
        # BUG #15 fix: lazy init — do NOT connect to LLM at construction time.
        # Reasons:
        # 1. OCC creates all agents at startup; missions that skip the operator
        #    (no CRITICAL/HIGH findings) would waste a connection attempt.
        # 2. If the Groq token expires between init and first use, the stored
        #    client would be stale.
        self._llm = None

    @property
    def llm(self):
        """Lazy-loaded LLM: initialized on first actual use."""
        if self._llm is None:
            from rao.core.llm import get_llm_or_none
            self._llm = get_llm_or_none()
        return self._llm

    def run(self, mission: MissionState) -> MissionState:
        """Generate attack plan for critical validated findings."""
        if not mission.validated_findings:
            logger.info("Operator: no validated findings — skipping planning phase.")
            return mission

        if self.llm is None:
            logger.warning(
                "Operator: no LLM available — skipping exploitation planning. "
                "Configure GROQ_API_KEY or start Ollama to enable this phase."
            )
            return mission

        # Only plan for HIGH and CRITICAL — keep signal-to-noise ratio high
        critical_findings = [
            f for f in mission.validated_findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]

        if not critical_findings:
            logger.info(
                "Operator: %d validated findings but none are HIGH/CRITICAL — skipping.",
                len(mission.validated_findings),
            )
            return mission

        logger.info(
            "Operator: generating attack plan for %d critical findings.",
            len(critical_findings),
        )

        findings_text = "\n".join(
            f"- [{f.severity.value.upper()}] {f.title}\n"
            f"  Host: {f.host}:{f.port or 'N/A'}\n"
            f"  CVEs: {', '.join(f.cve_ids) if f.cve_ids else 'None'}"
            for f in critical_findings[:MAX_FINDINGS]
        )

        try:
            mission.current_phase = "exploitation_planning"
            response = self.llm.invoke(OPERATOR_PROMPT.format(findings=findings_text))
            raw_plan: str = response.content
            mission.attack_plan = raw_plan

            # Parse raw text into structured AttackStep objects
            from rao.core.structured_output import AttackStep
            mission.attack_steps = AttackStep.parse_llm_response(raw_plan)
            logger.info(
                "Operator: attack plan generated (%d characters, %d steps).",
                len(raw_plan),
                len(mission.attack_steps),
            )
        except Exception as e:
            logger.warning("Operator: attack plan generation failed: %s", e)
            # BUG #15 fix: reset so next mission attempt retries fresh
            self._llm = None
            mission.errors.append(f"Operator planning failed: {e}")

        return mission
