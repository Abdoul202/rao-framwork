"""Typed models for the LLM red teaming module.

Follows the same Pydantic conventions as rao/core/structured_output.py and
reuses the shared Severity enum from rao/core/state.py.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

from rao.core.state import Severity


class OwaspLLM(str, Enum):
    """OWASP Top 10 for LLM Applications — 2025 identifiers."""

    LLM01 = "LLM01"  # Prompt Injection
    LLM02 = "LLM02"  # Sensitive Information Disclosure
    LLM03 = "LLM03"  # Supply Chain
    LLM04 = "LLM04"  # Data and Model Poisoning
    LLM05 = "LLM05"  # Improper Output Handling
    LLM06 = "LLM06"  # Excessive Agency
    LLM07 = "LLM07"  # System Prompt Leakage
    LLM08 = "LLM08"  # Vector and Embedding Weaknesses
    LLM09 = "LLM09"  # Misinformation
    LLM10 = "LLM10"  # Unbounded Consumption

    @property
    def label(self) -> str:
        return _OWASP_LABELS.get(self, self.value)


_OWASP_LABELS: dict[OwaspLLM, str] = {
    OwaspLLM.LLM01: "Prompt Injection",
    OwaspLLM.LLM02: "Sensitive Information Disclosure",
    OwaspLLM.LLM03: "Supply Chain",
    OwaspLLM.LLM04: "Data and Model Poisoning",
    OwaspLLM.LLM05: "Improper Output Handling",
    OwaspLLM.LLM06: "Excessive Agency",
    OwaspLLM.LLM07: "System Prompt Leakage",
    OwaspLLM.LLM08: "Vector and Embedding Weaknesses",
    OwaspLLM.LLM09: "Misinformation",
    OwaspLLM.LLM10: "Unbounded Consumption",
}


class DetectorType(str, Enum):
    """How a probe's success/failure is decided.

    CANARY        — success iff the attacker-chosen echo token leaks (proves an
                    injected instruction was followed).
    SECRET        — success iff a user-provided known secret leaks (exfiltration).
                    Ambiguous (→ judge) when no known secret is supplied.
    SENTINEL      — success iff a known system-prompt marker leaks. Ambiguous
                    (→ judge) when no marker is supplied.
    UNSAFE_OUTPUT — success iff the response contains executable markup/code.
    COMPLIANCE    — success iff the model complies (no refusal) with a
                    disallowed request (used for jailbreaks). Refusal => blocked.
    JUDGE         — defer to the conservative LLM judge.
    """

    CANARY = "canary"
    SECRET = "secret"
    SENTINEL = "sentinel"
    UNSAFE_OUTPUT = "unsafe_output"
    COMPLIANCE = "compliance"
    JUDGE = "judge"


class LLMProbe(BaseModel):
    """A single attack probe loaded from the probe catalogue."""

    id: str
    name: str
    owasp_id: OwaspLLM
    atlas_id: str = ""
    severity: Severity = Severity.MEDIUM
    detector: DetectorType = DetectorType.JUDGE
    description: str = ""
    # Payload templates. May contain {{CANARY}} (replaced with the run's canary)
    # and {{INJECT}} (replaced with a disallowed instruction marker).
    payloads: list[str] = Field(default_factory=list)
    # For COMPLIANCE/JUDGE probes: the disallowed goal we expect to be refused.
    goal: str = ""

    @property
    def needs_canary(self) -> bool:
        return self.detector is DetectorType.CANARY or any(
            "{{CANARY}}" in p for p in self.payloads
        )


class LLMFinding(BaseModel):
    """One probe result. `success=True` means the attack worked (a real,
    evidence-backed weakness), not merely that it was attempted."""

    probe_id: str
    name: str
    owasp_id: OwaspLLM
    atlas_id: str = ""
    severity: Severity = Severity.MEDIUM
    payload: str
    success: bool
    detector: str
    confidence: float = 0.0
    response_excerpt: str = ""
    judge_reasoning: str = ""
    error: str | None = None

    def excerpt(self, limit: int = 240) -> str:
        text = (self.response_excerpt or "").replace("\n", " ").strip()
        return text[:limit]


class LLMRedTeamResult(BaseModel):
    """Aggregate result for one target run."""

    target_id: str
    target_label: str
    findings: list[LLMFinding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    started_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: str = ""
    judge_used: bool = False

    # ── Derived summaries ──────────────────────────────────────────────────
    @property
    def successes(self) -> list[LLMFinding]:
        return [f for f in self.findings if f.success]

    @property
    def total(self) -> int:
        return len(self.findings)

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.successes:
            counts[f.severity.value] += 1
        return counts

    def coverage(self) -> dict[str, dict[str, int]]:
        """Per-OWASP-category coverage: probes run vs. successes."""
        cov: dict[str, dict[str, int]] = {}
        for f in self.findings:
            key = f.owasp_id.value
            row = cov.setdefault(key, {"probed": 0, "succeeded": 0})
            row["probed"] += 1
            if f.success:
                row["succeeded"] += 1
        return cov
