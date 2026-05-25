"""Tests for session save/load — including attack_plan serialization."""

from rao.core.session import _deserialize_mission, _serialize_mission
from rao.core.state import (
    Finding,
    HostInfo,
    MissionState,
    PortInfo,
    Severity,
)


def test_serialize_roundtrip():
    mission = MissionState(
        target="10.0.0.1",
        scope=["10.0.0.0/24"],
        current_phase="validation",
    )
    mission.hosts.append(
        HostInfo(
            ip="10.0.0.1",
            hostname="web.local",
            ports=[
                PortInfo(port=80, protocol="tcp", state="open", service="http", version="nginx 1.18")
            ],
        )
    )
    mission.findings.append(
        Finding(
            title="Test vuln",
            severity=Severity.HIGH,
            description="desc",
            evidence="evidence",
            host="10.0.0.1",
            port=80,
            cve_ids=["CVE-2024-0001"],
        )
    )

    data = _serialize_mission(mission)
    restored = _deserialize_mission(data)

    assert restored.target == "10.0.0.1"
    assert restored.current_phase == "validation"
    assert len(restored.hosts) == 1
    assert restored.hosts[0].ports[0].service == "http"
    assert len(restored.findings) == 1
    assert restored.findings[0].severity == Severity.HIGH
    assert restored.findings[0].cve_ids == ["CVE-2024-0001"]


def test_serialize_empty_mission():
    mission = MissionState(target="192.168.1.1")
    data = _serialize_mission(mission)
    restored = _deserialize_mission(data)

    assert restored.target == "192.168.1.1"
    assert restored.hosts == []
    assert restored.findings == []


# N17 fix: attack_plan serialization tests
def test_serialize_attack_plan():
    """attack_plan must survive a serialize/deserialize roundtrip."""
    mission = MissionState(target="10.0.0.1")
    mission.attack_plan = "FINDING: SSH brute-force\nTOOL: hydra\nAPPROACH: Test credentials"

    data = _serialize_mission(mission)
    assert "attack_plan" in data, "attack_plan key must be present in serialized data"

    restored = _deserialize_mission(data)
    assert restored.attack_plan == mission.attack_plan


def test_serialize_empty_attack_plan():
    """Empty attack_plan must deserialize to empty string, not None."""
    mission = MissionState(target="10.0.0.1")
    assert mission.attack_plan == ""

    data = _serialize_mission(mission)
    restored = _deserialize_mission(data)
    assert restored.attack_plan == ""


def test_deserialize_legacy_session_without_attack_plan():
    """Sessions saved before attack_plan was added must deserialize without error."""
    legacy_data = {
        "target": "10.0.0.1",
        "scope": ["10.0.0.0/24"],
        "current_phase": "validation",
        "errors": [],
        # Deliberately omit "attack_plan" — simulates a legacy session file
        "hosts": [],
        "findings": [],
        "validated_findings": [],
    }
    restored = _deserialize_mission(legacy_data)
    assert restored.attack_plan == ""  # Should default to "" via .get("attack_plan", "")
