"""Tests for the baseline store and regression diff."""

from __future__ import annotations

from rao.tools.llm_redteam.baseline import (
    diff_baseline,
    load_baseline,
    probe_status,
    save_baseline,
)
from rao.tools.llm_redteam.models import (
    LLMFinding,
    LLMRedTeamResult,
    OwaspLLM,
    Severity,
)


def _result(target_id="t1", **probe_success) -> LLMRedTeamResult:
    findings = []
    for pid, ok in probe_success.items():
        findings.append(
            LLMFinding(
                probe_id=pid,
                name=pid.upper(),
                owasp_id=OwaspLLM.LLM01,
                severity=Severity.HIGH,
                payload="p",
                success=ok,
                detector="canary",
            )
        )
    return LLMRedTeamResult(target_id=target_id, target_label="t", findings=findings)


def test_probe_status_any_payload_success():
    r = LLMRedTeamResult(
        target_id="t",
        target_label="t",
        findings=[
            LLMFinding(probe_id="a", name="a", owasp_id=OwaspLLM.LLM01, payload="1", success=False, detector="d"),
            LLMFinding(probe_id="a", name="a", owasp_id=OwaspLLM.LLM01, payload="2", success=True, detector="d"),
        ],
    )
    st = probe_status(r)
    assert st["a"]["vulnerable"] is True


def test_diff_new_fixed_persistent():
    prior = {
        "a": {"vulnerable": True},
        "b": {"vulnerable": True},
        "c": {"vulnerable": False},
    }
    current = probe_status(_result(a=True, b=False, c=True, d=True))
    diff = diff_baseline(prior, current)
    new_ids = {e["probe_id"] for e in diff.new}
    fixed_ids = {e["probe_id"] for e in diff.fixed}
    persist_ids = {e["probe_id"] for e in diff.persistent}
    assert new_ids == {"c", "d"}      # c was blocked->vuln, d is brand new
    assert fixed_ids == {"b"}          # b was vuln->blocked
    assert persist_ids == {"a"}        # a stayed vuln
    assert diff.has_regressions is True


def test_no_regressions_when_only_fixed():
    prior = {"a": {"vulnerable": True}}
    current = probe_status(_result(a=False))
    diff = diff_baseline(prior, current)
    assert diff.has_regressions is False
    assert {e["probe_id"] for e in diff.fixed} == {"a"}


def test_save_and_load_roundtrip_preserves_first_seen(tmp_path):
    base = str(tmp_path)
    st1 = probe_status(_result(target_id="tid", a=True))
    save_baseline("tid", st1, base)
    loaded1 = load_baseline("tid", base)
    first_seen = loaded1["a"]["first_seen"]
    assert loaded1["a"]["vulnerable"] is True

    # Second run: first_seen must be preserved, last_seen refreshed.
    st2 = probe_status(_result(target_id="tid", a=False))
    save_baseline("tid", st2, base)
    loaded2 = load_baseline("tid", base)
    assert loaded2["a"]["first_seen"] == first_seen
    assert loaded2["a"]["vulnerable"] is False


def test_load_missing_baseline_is_empty(tmp_path):
    assert load_baseline("nope", str(tmp_path)) == {}
