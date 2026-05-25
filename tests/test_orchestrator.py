"""Tests for the OCC orchestrator pipeline."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from rao.core.state import Finding, HostInfo, MissionState, PortInfo, Severity


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_host() -> HostInfo:
    return HostInfo(
        ip="192.168.1.1",
        ports=[
            PortInfo(port=80, protocol="tcp", state="open", service="http", version="Apache/2.4")
        ],
    )


def _make_mission_with_hosts() -> MissionState:
    m = MissionState(target="192.168.1.1", scope=["192.168.1.1"])
    m.hosts.append(_make_host())
    return m


def _make_mission_with_findings() -> MissionState:
    m = _make_mission_with_hosts()
    m.findings.append(
        Finding(
            title="CVE-2024-0001 - Test finding",
            severity=Severity.HIGH,
            description="Test description",
            evidence="Test evidence",
            host="192.168.1.1",
            port=80,
            cve_ids=["CVE-2024-0001"],
        )
    )
    return m


def _make_mission_validated() -> MissionState:
    m = _make_mission_with_findings()
    m.validated_findings.extend(m.findings)
    return m


# ── Pipeline routing tests ─────────────────────────────────────────────────────

@patch("rao.agents.scout.ScoutAgent.run")
@patch("rao.agents.librarian.LibrarianAgent.run")
@patch("rao.agents.critic.CriticAgent.run")
@patch("rao.agents.operator.OperatorAgent.run")
def test_full_pipeline_executes_all_agents(mock_op, mock_critic, mock_lib, mock_scout):
    """When Scout finds hosts with findings, all 4 agents must run."""
    validated = _make_mission_validated()
    mock_scout.return_value = _make_mission_with_findings()
    mock_lib.return_value = _make_mission_with_findings()
    mock_critic.return_value = validated
    mock_op.return_value = validated

    from rao.core.orchestrator import OCC

    occ = OCC()
    occ.execute(target="192.168.1.1")

    mock_scout.assert_called_once()
    mock_lib.assert_called_once()
    mock_critic.assert_called_once()
    mock_op.assert_called_once()


@patch("rao.agents.scout.ScoutAgent.run")
def test_pipeline_skips_librarian_when_no_hosts(mock_scout):
    """If Scout finds no hosts, Librarian, Critic and Operator must be skipped."""
    mock_scout.return_value = MissionState(target="192.168.1.1")

    with (
        patch("rao.agents.librarian.LibrarianAgent.run") as mock_lib,
        patch("rao.agents.critic.CriticAgent.run") as mock_critic,
        patch("rao.agents.operator.OperatorAgent.run") as mock_op,
    ):
        from rao.core.orchestrator import OCC

        OCC().execute(target="192.168.1.1")

        mock_lib.assert_not_called()
        mock_critic.assert_not_called()
        mock_op.assert_not_called()


@patch("rao.agents.scout.ScoutAgent.run")
@patch("rao.agents.librarian.LibrarianAgent.run")
def test_pipeline_skips_critic_when_no_findings(mock_lib, mock_scout):
    """If Librarian produces no findings, Critic and Operator must be skipped."""
    mock_scout.return_value = _make_mission_with_hosts()
    mock_lib.return_value = _make_mission_with_hosts()  # no findings

    with (
        patch("rao.agents.critic.CriticAgent.run") as mock_critic,
        patch("rao.agents.operator.OperatorAgent.run") as mock_op,
    ):
        from rao.core.orchestrator import OCC

        OCC().execute(target="192.168.1.1")

        mock_critic.assert_not_called()
        mock_op.assert_not_called()


@patch("rao.agents.scout.ScoutAgent.run")
@patch("rao.agents.librarian.LibrarianAgent.run")
@patch("rao.agents.critic.CriticAgent.run")
def test_pipeline_skips_operator_when_no_validated_findings(mock_critic, mock_lib, mock_scout):
    """If Critic validates nothing, Operator must be skipped."""
    mission_no_validated = _make_mission_with_findings()
    # validated_findings remains empty
    mock_scout.return_value = mission_no_validated
    mock_lib.return_value = mission_no_validated
    mock_critic.return_value = mission_no_validated

    with patch("rao.agents.operator.OperatorAgent.run") as mock_op:
        from rao.core.orchestrator import OCC

        OCC().execute(target="192.168.1.1")
        mock_op.assert_not_called()


# ── Result integrity tests ─────────────────────────────────────────────────────

@patch("rao.agents.scout.ScoutAgent.run")
def test_execute_returns_mission_state(mock_scout):
    """execute() must always return a MissionState object."""
    mock_scout.return_value = MissionState(target="10.0.0.1")

    from rao.core.orchestrator import OCC

    result = OCC().execute(target="10.0.0.1")
    assert isinstance(result, MissionState)
    assert result.target == "10.0.0.1"
