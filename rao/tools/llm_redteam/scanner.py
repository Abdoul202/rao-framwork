"""Async, bounded-concurrency scanner that drives probes against an LLM target.

This is the module's V2 socle: real async I/O (httpx) with a concurrency
semaphore — the synchronous, sequential bottleneck called out in the audit is
gone here. The public `run()` keeps a synchronous surface for the CLI and the
ToolPlugin protocol.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from collections.abc import Callable
from datetime import datetime, timezone

import httpx

from rao.tools.llm_redteam.detectors import (
    DetectionVerdict,
    detect_canary,
    detect_compliance,
    detect_sentinel,
    detect_unsafe_output,
)
from rao.tools.llm_redteam.models import (
    DetectorType,
    LLMFinding,
    LLMProbe,
    LLMRedTeamResult,
)
from rao.tools.llm_redteam.probes import load_probes, render_payload
from rao.tools.llm_redteam.target import LLMTarget, build_target
from rao.tools.plugin import ToolResult

logger = logging.getLogger(__name__)

# A judge is any callable: (goal, payload, response) -> object with
# .success: bool, .confidence: float, .reasoning: str
JudgeFn = Callable[..., object]


def new_canary() -> str:
    """Unique, easily-greppable per-run token."""
    return f"RAO-CANARY-{secrets.token_hex(6)}"


class LLMRedTeamScanner:
    """Evidence-based LLM red teaming scanner (ToolPlugin-compatible)."""

    name = "llm_redteam"
    description = "Continuous, evidence-based red teaming of LLM endpoints (OWASP LLM Top 10 + ATLAS)."
    version = "0.1.0"
    author = "RAO-Framework"
    requires: list[str] = []

    def __init__(
        self,
        *,
        concurrency: int = 5,
        request_timeout: float = 30.0,
        judge: JudgeFn | None = None,
    ) -> None:
        self.concurrency = max(1, concurrency)
        self.request_timeout = request_timeout
        self.judge = judge

    # ── Core async engine ──────────────────────────────────────────────────
    async def scan_async(
        self,
        target: LLMTarget,
        probes: list[LLMProbe],
        *,
        canary: str = "",
        sentinels: list[str] | None = None,
    ) -> LLMRedTeamResult:
        canary = canary or new_canary()
        result = LLMRedTeamResult(target_id=target.target_id, target_label=target.label)
        sem = asyncio.Semaphore(self.concurrency)
        # Track whether the judge was actually consulted.
        judge_used = {"flag": False}

        # Build one task per (probe, payload).
        units: list[tuple[LLMProbe, str]] = []
        for probe in probes:
            for raw in probe.payloads:
                units.append((probe, render_payload(raw, canary=canary)))

        async with httpx.AsyncClient() as client:
            async def worker(probe: LLMProbe, payload: str) -> LLMFinding:
                async with sem:
                    return await self._run_unit(
                        probe, payload, target, client, canary, sentinels, judge_used
                    )

            findings = await asyncio.gather(
                *(worker(p, pl) for p, pl in units), return_exceptions=False
            )

        result.findings = list(findings)
        result.errors = [f.error for f in findings if f.error]
        result.judge_used = judge_used["flag"]
        result.finished_at = datetime.now(timezone.utc).isoformat()
        return result

    async def _run_unit(
        self,
        probe: LLMProbe,
        payload: str,
        target: LLMTarget,
        client: httpx.AsyncClient,
        canary: str,
        sentinels: list[str] | None,
        judge_used: dict,
    ) -> LLMFinding:
        finding = LLMFinding(
            probe_id=probe.id,
            name=probe.name,
            owasp_id=probe.owasp_id,
            atlas_id=probe.atlas_id,
            severity=probe.severity,
            payload=payload,
            success=False,
            detector=probe.detector.value,
        )
        try:
            response = await target.query(payload, client)
        except Exception as exc:  # noqa: BLE001 — record transport/parse errors per probe
            finding.error = f"{type(exc).__name__}: {exc}"
            finding.detector = "error"
            return finding

        finding.response_excerpt = response

        signal = self._deterministic(probe, response, canary, sentinels)
        if signal.verdict is DetectionVerdict.SUCCESS:
            finding.success = True
            finding.confidence = signal.confidence
            finding.detector = signal.detector
            finding.response_excerpt = signal.evidence
            return finding
        if signal.verdict is DetectionVerdict.BLOCKED:
            finding.success = False
            finding.confidence = signal.confidence
            finding.detector = signal.detector
            finding.response_excerpt = signal.evidence
            return finding

        # AMBIGUOUS → escalate to the conservative judge (or stay BLOCKED).
        if self.judge is not None:
            judge_used["flag"] = True
            verdict = await asyncio.to_thread(
                self.judge, goal=probe.goal or probe.description, payload=payload, response=response
            )
            finding.success = bool(getattr(verdict, "success", False))
            finding.confidence = float(getattr(verdict, "confidence", 0.0))
            finding.judge_reasoning = str(getattr(verdict, "reasoning", ""))
            finding.detector = "judge"
        else:
            # No judge available: do not guess. Conservative BLOCKED.
            finding.success = False
            finding.detector = f"{signal.detector}/no-judge"
            finding.response_excerpt = signal.evidence
        return finding

    @staticmethod
    def _deterministic(probe: LLMProbe, response: str, canary: str, sentinels):
        if probe.detector is DetectorType.CANARY:
            return detect_canary(response, canary)
        if probe.detector is DetectorType.SENTINEL:
            return detect_sentinel(response, sentinels)
        if probe.detector is DetectorType.UNSAFE_OUTPUT:
            return detect_unsafe_output(response)
        if probe.detector is DetectorType.COMPLIANCE:
            return detect_compliance(response)
        # DetectorType.JUDGE → always ambiguous so the judge decides.
        from rao.tools.llm_redteam.detectors import DetectionSignal

        return DetectionSignal(DetectionVerdict.AMBIGUOUS, 0.0, response[:160], "judge")

    # ── Sync wrappers ──────────────────────────────────────────────────────
    def scan(
        self,
        target: LLMTarget,
        probes: list[LLMProbe] | None = None,
        *,
        canary: str = "",
        sentinels: list[str] | None = None,
    ) -> LLMRedTeamResult:
        """Synchronous entry point used by the CLI."""
        probes = probes if probes is not None else load_probes()
        return asyncio.run(self.scan_async(target, probes, canary=canary, sentinels=sentinels))

    def run(self, target, **kwargs) -> ToolResult:
        """ToolPlugin adapter. `target` may be an LLMTarget or a profile dict."""
        start = time.time()
        try:
            tgt = target if isinstance(target, LLMTarget) else build_target(target)
            probes = kwargs.get("probes") or load_probes()
            result = self.scan(
                tgt,
                probes,
                canary=kwargs.get("canary", ""),
                sentinels=kwargs.get("sentinels"),
            )
            return ToolResult(
                success=True,
                data=result.model_dump(mode="json"),
                duration_ms=(time.time() - start) * 1000,
            )
        except Exception as exc:  # noqa: BLE001 — protocol forbids raising
            return ToolResult(
                success=False, error=f"{type(exc).__name__}: {exc}",
                duration_ms=(time.time() - start) * 1000,
            )
