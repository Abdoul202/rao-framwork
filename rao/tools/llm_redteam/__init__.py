"""LLM Red Teaming module for RAO-Framework.

Continuous, evidence-based red teaming of LLM targets. Attacks a victim LLM
with a catalogue of probes mapped to the OWASP LLM Top 10 (2025) and MITRE
ATLAS, then *proves* each success with deterministic detectors first and a
conservative LLM judge only for ambiguous cases (0-false-positive bias).

Public API
----------
    from rao.tools.llm_redteam import LLMRedTeamScanner, build_target

The scanner is also registered as a ToolPlugin under the name "llm_redteam".
"""

from __future__ import annotations

from rao.tools.llm_redteam.models import (
    DetectorType,
    LLMFinding,
    LLMProbe,
    LLMRedTeamResult,
    OwaspLLM,
)
from rao.tools.llm_redteam.scanner import LLMRedTeamScanner, new_canary
from rao.tools.llm_redteam.target import (
    HTTPTarget,
    LLMTarget,
    OpenAITarget,
    build_target,
)

__all__ = [
    "DetectorType",
    "LLMFinding",
    "LLMProbe",
    "LLMRedTeamResult",
    "OwaspLLM",
    "HTTPTarget",
    "LLMTarget",
    "OpenAITarget",
    "build_target",
    "LLMRedTeamScanner",
    "new_canary",
]
