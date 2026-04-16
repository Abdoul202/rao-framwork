"""Tests for core state objects."""

from rao.core.state import Finding, HostInfo, MissionState, PortInfo, Severity


def test_mission_state_defaults():
    mission = MissionState(target="192.168.1.1")
    assert mission.target == "192.168.1.1"
    assert mission.scope == []
    assert mission.hosts == []
    assert mission.findings == []
    assert mission.current_phase == "reconnaissance"


def test_host_info_with_ports():
    port = PortInfo(
        port=80, protocol="tcp", state="open", service="http", version="nginx 1.18"
    )
    host = HostInfo(ip="10.0.0.1", hostname="web.local", ports=[port])
    assert len(host.ports) == 1
    assert host.ports[0].service == "http"


def test_finding_creation():
    finding = Finding(
        title="CVE-2024-1234 - Test vuln",
        severity=Severity.HIGH,
        description="A test vulnerability",
        evidence="Version match",
        host="10.0.0.1",
        port=443,
        cve_ids=["CVE-2024-1234"],
    )
    assert finding.severity == Severity.HIGH
    assert not finding.validated
    assert not finding.false_positive


def test_severity_ordering():
    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    severities = [Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]
    sorted_sevs = sorted(severities, key=lambda s: list(Severity).index(s))
    assert sorted_sevs[0] == Severity.CRITICAL
