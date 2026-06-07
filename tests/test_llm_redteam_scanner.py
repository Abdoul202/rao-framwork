"""Scanner integration tests using an in-memory fake target (no network)."""

from __future__ import annotations

import httpx
import pytest

from rao.tools.llm_redteam.judge import JudgeVerdict
from rao.tools.llm_redteam.models import DetectorType, LLMProbe, OwaspLLM
from rao.tools.llm_redteam.scanner import LLMRedTeamScanner, new_canary
from rao.tools.llm_redteam.target import LLMTarget


class FakeTarget(LLMTarget):
    """Returns a canned response chosen by a function of the payload."""

    def __init__(self, responder):
        self._responder = responder
        self.label = "fake"
        self.target_id = "faketarget000000"

    async def query(self, prompt: str, client: httpx.AsyncClient) -> str:
        return self._responder(prompt)


def _probe(detector: DetectorType, **kw) -> LLMProbe:
    base = {
        "id": "p1", "name": "probe", "owasp_id": OwaspLLM.LLM01,
        "detector": detector, "payloads": ["do {{CANARY}}"],
    }
    base.update(kw)
    return LLMProbe(**base)


@pytest.mark.asyncio
async def test_canary_echo_is_marked_vulnerable():
    canary = new_canary()
    # The target obediently echoes whatever it's told (echoes the canary).
    target = FakeTarget(lambda p: f"ok: {p}")
    scanner = LLMRedTeamScanner(judge=None)
    result = await scanner.scan_async(
        target, [_probe(DetectorType.CANARY)], canary=canary
    )
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.success is True
    assert f.detector == "canary"
    assert canary in f.response_excerpt


@pytest.mark.asyncio
async def test_refusal_is_blocked_without_judge():
    target = FakeTarget(lambda p: "I'm sorry, but I can't help with that.")
    scanner = LLMRedTeamScanner(judge=None)
    result = await scanner.scan_async(
        target, [_probe(DetectorType.COMPLIANCE, payloads=["jailbreak me"])]
    )
    assert result.findings[0].success is False
    assert result.judge_used is False


@pytest.mark.asyncio
async def test_ambiguous_without_judge_is_conservative_blocked():
    # Non-refusal, non-canary => ambiguous; no judge => must stay blocked.
    target = FakeTarget(lambda p: "Sure, here is a detailed answer ...")
    scanner = LLMRedTeamScanner(judge=None)
    result = await scanner.scan_async(
        target, [_probe(DetectorType.COMPLIANCE, payloads=["jailbreak me"])]
    )
    f = result.findings[0]
    assert f.success is False
    assert f.detector.endswith("/no-judge")


@pytest.mark.asyncio
async def test_ambiguous_with_judge_success():
    target = FakeTarget(lambda p: "Sure: step 1 ... step 2 ...")

    def fake_judge(*, goal, payload, response):
        return JudgeVerdict(success=True, confidence=0.9, reasoning="complied")

    scanner = LLMRedTeamScanner(judge=fake_judge)
    result = await scanner.scan_async(
        target, [_probe(DetectorType.JUDGE, payloads=["do bad thing"], goal="bad")]
    )
    f = result.findings[0]
    assert f.success is True
    assert f.detector == "judge"
    assert f.judge_reasoning == "complied"
    assert result.judge_used is True


@pytest.mark.asyncio
async def test_unsafe_output_detected():
    target = FakeTarget(lambda p: "<script>alert('rao')</script>")
    scanner = LLMRedTeamScanner(judge=None)
    result = await scanner.scan_async(
        target, [_probe(DetectorType.UNSAFE_OUTPUT, owasp_id=OwaspLLM.LLM05, payloads=["echo xss"])]
    )
    assert result.findings[0].success is True
    assert result.findings[0].detector == "unsafe_output"


@pytest.mark.asyncio
async def test_query_error_recorded_not_raised():
    def boom(p):
        raise httpx.ConnectError("refused")

    target = FakeTarget(boom)
    scanner = LLMRedTeamScanner(judge=None)
    result = await scanner.scan_async(target, [_probe(DetectorType.CANARY)])
    f = result.findings[0]
    assert f.success is False
    assert f.error is not None
    assert "ConnectError" in f.error
    assert result.errors


@pytest.mark.asyncio
async def test_multiple_payloads_yield_multiple_findings():
    target = FakeTarget(lambda p: "blocked: I cannot help")
    scanner = LLMRedTeamScanner(judge=None)
    probe = _probe(DetectorType.COMPLIANCE, payloads=["a", "b", "c"])
    result = await scanner.scan_async(target, [probe])
    assert result.total == 3


def test_coverage_and_severity_summary():
    target = FakeTarget(lambda p: f"echo {p}")
    canary = new_canary()
    scanner = LLMRedTeamScanner(judge=None)
    result = scanner.scan(
        target,
        [_probe(DetectorType.CANARY, severity="high")],
        canary=canary,
    )
    cov = result.coverage()
    assert cov["LLM01"]["succeeded"] == 1
    assert result.by_severity()["high"] == 1
