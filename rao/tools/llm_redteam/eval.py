"""Evaluation harness — measures the scanner's false-positive / false-negative
rate against ground-truth targets. The headline metric is FP = 0: the scanner
must never flag a hardened target as vulnerable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from rao.tools.llm_redteam.baseline import probe_status
from rao.tools.llm_redteam.mocks import (
    SENTINEL,
    HardenedMockTarget,
    VulnerableMockTarget,
)
from rao.tools.llm_redteam.models import LLMProbe
from rao.tools.llm_redteam.probes import load_probes
from rao.tools.llm_redteam.scanner import LLMRedTeamScanner, new_canary
from rao.tools.llm_redteam.target import LLMTarget


@dataclass
class EvalCase:
    target: LLMTarget
    # True  => every probe is EXPECTED to succeed (target is vulnerable to all)
    # False => every probe is EXPECTED to be blocked (target is hardened)
    expected_vulnerable: bool


@dataclass
class EvalReport:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    fp_details: list[dict] = field(default_factory=list)
    fn_details: list[dict] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 1.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 1.0

    def confusion_str(self) -> str:
        return (
            "                 predicted-vuln  predicted-blocked\n"
            f"  actual-vuln          TP={self.tp:<4}        FN={self.fn:<4}\n"
            f"  actual-hardened      FP={self.fp:<4}        TN={self.tn:<4}\n"
            f"  precision={self.precision:.2f}  recall={self.recall:.2f}  "
            f"accuracy={self.accuracy:.2f}"
        )


def default_cases(canary: str, sentinel: str = SENTINEL) -> list[EvalCase]:
    """The standard ground-truth suite: one all-vulnerable, one all-hardened."""
    return [
        EvalCase(VulnerableMockTarget(secret=canary, sentinel=sentinel), expected_vulnerable=True),
        EvalCase(HardenedMockTarget(), expected_vulnerable=False),
    ]


def run_eval(
    scanner: LLMRedTeamScanner,
    probes: list[LLMProbe] | None = None,
    cases: list[EvalCase] | None = None,
    *,
    canary: str = "",
    sentinel: str = SENTINEL,
) -> EvalReport:
    canary = canary or new_canary()
    probes = probes if probes is not None else load_probes()
    cases = cases if cases is not None else default_cases(canary, sentinel)
    report = EvalReport()

    for case in cases:
        result = scanner.scan(case.target, probes, canary=canary, sentinels=[sentinel])
        statuses = probe_status(result)
        for pid, row in statuses.items():
            predicted = bool(row["vulnerable"])
            expected = case.expected_vulnerable
            detail = {
                "probe_id": pid,
                "target": case.target.label,
                "expected": "vulnerable" if expected else "hardened",
            }
            if expected and predicted:
                report.tp += 1
            elif expected and not predicted:
                report.fn += 1
                report.fn_details.append(detail)
            elif not expected and predicted:
                report.fp += 1
                report.fp_details.append(detail)
            else:
                report.tn += 1
    return report
