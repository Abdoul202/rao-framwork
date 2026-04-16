"""Tests for the Critic agent's parsing logic."""

from rao.agents.critic import CriticAgent
from rao.core.state import Finding, Severity


def test_parse_verdict_true_positive():
    critic = CriticAgent()
    finding = Finding(
        title="Test finding",
        severity=Severity.HIGH,
        description="desc",
        evidence="evidence",
        host="10.0.0.1",
    )

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
    finding = Finding(
        title="Test finding",
        severity=Severity.MEDIUM,
        description="desc",
        evidence="evidence",
        host="10.0.0.1",
    )

    response = """VERDICT: FALSE_POSITIVE
EXPLOITABILITY: NONE
REASONING: Version not actually affected.
VERIFICATION: N/A"""

    result = critic._parse_verdict(response, finding)
    assert result is False
    assert finding.false_positive is True
