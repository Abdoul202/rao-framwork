"""Tests for the Critic agent's parsing and offline fallback logic."""

from rao.agents.critic import CriticAgent
from rao.core.state import Finding, Severity


def _make_finding(severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        title="Test finding",
        severity=severity,
        description="desc",
        evidence="evidence",
        host="10.0.0.1",
    )


def test_parse_verdict_true_positive():
    critic = CriticAgent()
    finding = _make_finding(Severity.HIGH)

    response = """VERDICT: TRUE_POSITIVE
EXPLOITABILITY: HIGH
REASONING: The service version is known vulnerable.
VERIFICATION: Attempt authenticated access."""

    result = critic._parse_verdict(response, finding)
    assert result is True
    assert finding.validated is True
    assert finding.false_positive is False


def test_parse_verdict_false_positive():
    critic = CriticAgent()
    finding = _make_finding(Severity.MEDIUM)

    response = """VERDICT: FALSE_POSITIVE
EXPLOITABILITY: NONE
REASONING: Version not actually affected.
VERIFICATION: N/A"""

    result = critic._parse_verdict(response, finding)
    assert result is False
    assert finding.false_positive is True


# N18 fix: new tests for updated conservative defaults and offline behavior

def test_parse_verdict_no_verdict_line_defaults_false_positive():
    """N18: When LLM returns no VERDICT line, conservative default is FALSE_POSITIVE."""
    critic = CriticAgent()
    finding = _make_finding(Severity.MEDIUM)

    # Malformed response — no VERDICT: line
    response = "This looks potentially exploitable but I am not sure."

    result = critic._parse_verdict(response, finding)
    # Conservative default: no VERDICT → FALSE_POSITIVE
    assert result is False


def test_offline_fallback_keeps_critical():
    """N18: Offline fallback must keep CRITICAL findings."""
    critic = CriticAgent()
    finding = _make_finding(Severity.CRITICAL)

    result = critic._offline_fallback(finding)
    assert result is True
    assert finding.validated is False  # Not validated by LLM


def test_offline_fallback_keeps_high():
    """N18: Offline fallback must keep HIGH findings."""
    critic = CriticAgent()
    finding = _make_finding(Severity.HIGH)

    result = critic._offline_fallback(finding)
    assert result is True


def test_offline_fallback_drops_medium():
    """N18: Offline fallback must DROP MEDIUM findings (reduce noise)."""
    critic = CriticAgent()
    finding = _make_finding(Severity.MEDIUM)

    result = critic._offline_fallback(finding)
    assert result is False


def test_offline_fallback_drops_low():
    """N18: Offline fallback must DROP LOW findings."""
    critic = CriticAgent()
    finding = _make_finding(Severity.LOW)

    result = critic._offline_fallback(finding)
    assert result is False


def test_llm_error_resets_cached_llm():
    """N18: After an LLM API error, self._llm must be reset to None for retry."""
    from unittest.mock import MagicMock

    critic = CriticAgent()
    fake_llm = MagicMock()
    fake_llm.invoke.side_effect = Exception("API quota exceeded")
    critic._llm = fake_llm  # Inject a broken LLM

    finding = _make_finding(Severity.HIGH)
    # Should not raise — should degrade to offline fallback
    result = critic._validate_finding(finding)

    # After failure, _llm must be reset to allow retry
    assert critic._llm is None
    # HIGH finding kept by offline fallback
    assert result is True
