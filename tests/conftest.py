"""Shared pytest configuration, fixtures, and global mocks.

N20 fix: conftest.py created to:
  - Suppress the NEO4J_PASSWORD warning in every test (config import side-effect)
  - Provide shared fixtures to avoid code duplication across test files
  - Ensure clean isolation between tests
"""

from __future__ import annotations

import logging

import pytest

from rao.core.state import Finding, HostInfo, MissionState, PortInfo, Severity

# ── Suppress expected config warnings in test output ──────────────────────────

@pytest.fixture(autouse=True)
def suppress_config_warnings(caplog):
    """N20 fix: NEO4J_PASSWORD warning is expected in CI — suppress it from test logs."""
    with caplog.at_level(logging.ERROR, logger="rao.config"):
        yield


# ── Shared state fixtures ──────────────────────────────────────────────────────

@pytest.fixture
def basic_port() -> PortInfo:
    return PortInfo(port=80, protocol="tcp", state="open", service="http", version="nginx 1.18")


@pytest.fixture
def basic_host(basic_port) -> HostInfo:
    return HostInfo(ip="192.168.1.1", hostname="test.local", ports=[basic_port])


@pytest.fixture
def empty_mission() -> MissionState:
    return MissionState(target="192.168.1.1", scope=["192.168.1.1"])


@pytest.fixture
def mission_with_hosts(basic_host) -> MissionState:
    m = MissionState(target="192.168.1.1", scope=["192.168.1.1"])
    m.hosts.append(basic_host)
    return m


@pytest.fixture
def high_finding() -> Finding:
    return Finding(
        title="CVE-2024-0001 - Test finding",
        severity=Severity.HIGH,
        description="A test vulnerability",
        evidence="Version match",
        host="192.168.1.1",
        port=80,
        cve_ids=["CVE-2024-0001"],
    )


@pytest.fixture
def mission_with_findings(mission_with_hosts, high_finding) -> MissionState:
    mission_with_hosts.findings.append(high_finding)
    return mission_with_hosts


@pytest.fixture
def mission_validated(mission_with_findings) -> MissionState:
    mission_with_findings.validated_findings.extend(mission_with_findings.findings)
    return mission_with_findings
