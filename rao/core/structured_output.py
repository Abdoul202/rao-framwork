"""Structured Pydantic models for LLM outputs.

Replaces fragile string-split parsing with validated, typed models.
Models: CriticVerdict, LibrarianFinding, AttackStep.
"""

from __future__ import annotations

import logging
from enum import Enum

from pydantic import BaseModel, field_validator

logger = logging.getLogger(__name__)


class Verdict(str, Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class Exploitability(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class CriticVerdict(BaseModel):
    """Structured output for the CriticAgent validation prompt."""

    verdict: Verdict
    exploitability: Exploitability
    reasoning: str = ""
    verification: str = ""

    @field_validator("verdict", mode="before")
    @classmethod
    def normalize_verdict(cls, v: str) -> str:
        v_upper = v.upper().strip()
        if "TRUE" in v_upper:
            return Verdict.TRUE_POSITIVE
        return Verdict.FALSE_POSITIVE

    @field_validator("exploitability", mode="before")
    @classmethod
    def normalize_exploitability(cls, v: str) -> str:
        v_upper = v.upper().strip()
        for member in Exploitability:
            if member.value in v_upper:
                return member
        return Exploitability.MEDIUM

    @classmethod
    def parse_llm_response(cls, response: str) -> CriticVerdict:
        """Parse the structured LLM text response into a CriticVerdict.

        BUG #10 fix: default is now FALSE_POSITIVE + NONE exploitability
        (conservative). A warning is logged when the VERDICT line is missing,
        which indicates a malformed/hallucinated LLM response.
        """
        # BUG #10 fix: conservative defaults — treat unknown as false positive
        verdict: Verdict = Verdict.FALSE_POSITIVE
        exploitability: Exploitability = Exploitability.NONE
        reasoning = ""
        verification = ""
        verdict_found = False

        for line in response.strip().splitlines():
            line = line.strip()
            if line.startswith("VERDICT:"):
                raw = line.split(":", 1)[1].strip()
                verdict = cls.normalize_verdict(raw)
                verdict_found = True
            elif line.startswith("EXPLOITABILITY:"):
                raw = line.split(":", 1)[1].strip()
                exploitability = cls.normalize_exploitability(raw)
            elif line.startswith("REASONING:"):
                reasoning = line.split(":", 1)[1].strip()
            elif line.startswith("VERIFICATION:"):
                verification = line.split(":", 1)[1].strip()

        # BUG #10 fix: warn on malformed response — helps detect hallucinations
        if not verdict_found:
            logger.warning(
                "CriticVerdict: no VERDICT line in LLM response — "
                "defaulting to FALSE_POSITIVE (conservative). "
                "Response preview: %.120s",
                response,
            )

        return cls(
            verdict=verdict,
            exploitability=exploitability,
            reasoning=reasoning,
            verification=verification,
        )


class LibrarianFinding(BaseModel):
    """One CVE finding as parsed from the LibrarianAgent response."""

    cve_id: str
    severity: str
    description: str
    why_relevant: str

    @classmethod
    def parse_llm_line(cls, line: str) -> LibrarianFinding | None:
        """Parse a pipe-delimited LLM response line."""
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 4:
            return None
        # Validate it looks like a CVE ID (starts with CVE-)
        if not parts[0].upper().startswith("CVE-"):
            return None
        return cls(
            cve_id=parts[0],
            severity=parts[1],
            description=parts[2],
            why_relevant=parts[3],
        )


class AttackRisk(str, Enum):
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"


class AttackStep(BaseModel):
    """One structured exploitation step from the OperatorAgent LLM response.

    The Operator prompt instructs the LLM to emit blocks separated by '---'
    with labelled fields. This model parses each block into a typed object.
    """

    finding:      str = ""
    tool:         str = "manual"
    approach:     str = ""
    example:      str = ""
    prerequisite: str = ""
    risk:         AttackRisk = AttackRisk.MEDIUM

    @field_validator("risk", mode="before")
    @classmethod
    def normalize_risk(cls, v: str) -> str:
        v_upper = v.upper().strip()
        for member in AttackRisk:
            if member.value in v_upper:
                return member
        return AttackRisk.MEDIUM

    @classmethod
    def parse_llm_block(cls, block: str) -> AttackStep | None:
        """Parse one '---' delimited block from the Operator LLM response.

        Expected format (each field on its own line)::

            FINDING: <title>
            TOOL: <tool name>
            APPROACH: <description>
            EXAMPLE: <command or payload>
            PREREQUISITE: <precondition>
            RISK: LOW | MEDIUM | HIGH
        """
        data: dict[str, str] = {}
        for line in block.strip().splitlines():
            line = line.strip()
            for key in ("FINDING", "TOOL", "APPROACH", "EXAMPLE", "PREREQUISITE", "RISK"):
                if line.upper().startswith(f"{key}:"):
                    data[key.lower()] = line.split(":", 1)[1].strip()
                    break

        if not data.get("finding") and not data.get("approach"):
            return None  # empty or noise block

        try:
            return cls(**{k: v for k, v in data.items() if v})
        except Exception as exc:
            logger.debug("AttackStep.parse_llm_block failed: %s", exc)
            return None

    @classmethod
    def parse_llm_response(cls, response: str) -> list[AttackStep]:
        """Split the full Operator response into individual AttackStep objects.

        Blocks are separated by '---' lines.
        """
        blocks = response.split("---")
        steps = []
        for block in blocks:
            step = cls.parse_llm_block(block)
            if step:
                steps.append(step)
        return steps
