"""Tests for session save/load."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

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
    mission = MissionState(target="127.0.0.1")
    data = _serialize_mission(mission)
    restored = _deserialize_mission(data)

    assert restored.target == "127.0.0.1"
    assert restored.hosts == []
    assert restored.findings == []
