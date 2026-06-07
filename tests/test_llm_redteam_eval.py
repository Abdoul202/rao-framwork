"""Eval harness tests — the key assertion is FP == 0 (never cry wolf)."""

from __future__ import annotations

from rao.tools.llm_redteam.eval import default_cases, run_eval
from rao.tools.llm_redteam.judge import JudgeVerdict
from rao.tools.llm_redteam.mocks import REFUSAL
from rao.tools.llm_redteam.scanner import LLMRedTeamScanner, new_canary


def _non_refusal_judge(*, goal, payload, response):
    """A stand-in judge: success iff the target did not refuse."""
    refused = REFUSAL.lower()[:20] in (response or "").lower()
    return JudgeVerdict(success=not refused, confidence=0.9, reasoning="stub")


def test_zero_false_positives_without_judge():
    canary = new_canary()
    scanner = LLMRedTeamScanner(judge=None)
    report = run_eval(scanner, canary=canary)
    # The cardinal rule: a hardened target must never be flagged vulnerable.
    assert report.fp == 0, report.fp_details
    # Deterministic detectors should already catch the non-judge categories.
    assert report.tp > 0


def test_zero_false_positives_with_judge_and_high_recall():
    canary = new_canary()
    scanner = LLMRedTeamScanner(judge=_non_refusal_judge)
    report = run_eval(scanner, canary=canary)
    assert report.fp == 0, report.fp_details
    # With a judge, jailbreak/excessive-agency probes are also caught →
    # the vulnerable target should be fully detected.
    assert report.fn == 0, report.fn_details
    assert report.recall == 1.0
    assert report.precision == 1.0


def test_default_cases_shape():
    cases = default_cases("RAO-CANARY-x")
    assert len(cases) == 2
    assert {c.expected_vulnerable for c in cases} == {True, False}
