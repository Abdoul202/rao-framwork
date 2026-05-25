"""
Session Manager - Save, resume, and manage missions.

Missions are serialized to JSON so they can be paused and resumed later.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from rao.config import settings
from rao.core.state import (
    Finding,
    HostInfo,
    MissionState,
    PortInfo,
    Severity,
)

logger = logging.getLogger(__name__)

SESSIONS_DIR = Path(settings.report_output_dir) / "sessions"


def save_session(mission: MissionState, session_name: str | None = None) -> Path:
    """Serialize a MissionState to JSON on disk."""
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)

    if not session_name:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_target = mission.target.replace(".", "_").replace("/", "_")
        session_name = f"session_{safe_target}_{timestamp}"

    filepath = SESSIONS_DIR / f"{session_name}.json"
    data = _serialize_mission(mission)
    data["_session"] = {
        "name": session_name,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "phase": mission.current_phase,
    }

    filepath.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    logger.info("Session saved: %s", filepath)
    return filepath


def load_session(session_path: str | Path) -> MissionState:
    """Deserialize a MissionState from JSON."""
    path = Path(session_path)
    if not path.exists():
        # Try looking in the sessions directory
        path = SESSIONS_DIR / f"{session_path}.json"

    if not path.exists():
        raise FileNotFoundError(f"Session not found: {session_path}")

    data = json.loads(path.read_text())
    mission = _deserialize_mission(data)
    logger.info(
        "Session loaded: target=%s, phase=%s, hosts=%d, findings=%d",
        mission.target,
        mission.current_phase,
        len(mission.hosts),
        len(mission.findings),
    )
    return mission


def list_sessions() -> list[dict]:
    """List all saved sessions."""
    if not SESSIONS_DIR.exists():
        return []

    sessions = []
    for f in sorted(SESSIONS_DIR.glob("*.json"), reverse=True):
        try:
            data = json.loads(f.read_text())
            meta = data.get("_session", {})
            sessions.append(
                {
                    "name": meta.get("name", f.stem),
                    "file": str(f),
                    "target": data.get("target", "unknown"),
                    "phase": meta.get("phase", "unknown"),
                    "saved_at": meta.get("saved_at", "unknown"),
                    "hosts": len(data.get("hosts", [])),
                    "findings": len(data.get("findings", [])),
                }
            )
        except Exception as e:
            logger.warning("Cannot read session %s: %s", f, e)

    return sessions


def _serialize_mission(mission: MissionState) -> dict:
    return {
        "target": mission.target,
        "scope": mission.scope,
        "current_phase": mission.current_phase,
        "errors": mission.errors,
        # BUG #16 fix: attack_plan is now persisted in sessions
        "attack_plan": mission.attack_plan,
        "hosts": [
            {
                "ip": h.ip,
                "hostname": h.hostname,
                "os_guess": h.os_guess,
                "ports": [
                    {
                        "port": p.port,
                        "protocol": p.protocol,
                        "state": p.state,
                        "service": p.service,
                        "version": p.version,
                    }
                    for p in h.ports
                ],
            }
            for h in mission.hosts
        ],
        "findings": [_serialize_finding(f) for f in mission.findings],
        "validated_findings": [
            _serialize_finding(f) for f in mission.validated_findings
        ],
    }


def _serialize_finding(f: Finding) -> dict:
    return {
        "title": f.title,
        "severity": f.severity.value,
        "description": f.description,
        "evidence": f.evidence,
        "host": f.host,
        "port": f.port,
        "cve_ids": f.cve_ids,
        "validated": f.validated,
        "false_positive": f.false_positive,
    }


def _deserialize_mission(data: dict) -> MissionState:
    mission = MissionState(
        target=data["target"],
        scope=data.get("scope", [data["target"]]),
        current_phase=data.get("current_phase", "reconnaissance"),
        errors=data.get("errors", []),
        # BUG #16 fix: restore attack_plan from session file
        attack_plan=data.get("attack_plan", ""),
    )

    for h in data.get("hosts", []):
        ports = [
            PortInfo(
                port=p["port"],
                protocol=p["protocol"],
                state=p["state"],
                service=p["service"],
                version=p.get("version", ""),
            )
            for p in h.get("ports", [])
        ]
        mission.hosts.append(
            HostInfo(
                ip=h["ip"],
                hostname=h.get("hostname", ""),
                os_guess=h.get("os_guess", ""),
                ports=ports,
            )
        )

    for f in data.get("findings", []):
        mission.findings.append(_deserialize_finding(f))
    for f in data.get("validated_findings", []):
        mission.validated_findings.append(_deserialize_finding(f))

    return mission


def _deserialize_finding(data: dict) -> Finding:
    return Finding(
        title=data["title"],
        severity=Severity(data["severity"]),
        description=data["description"],
        evidence=data["evidence"],
        host=data["host"],
        port=data.get("port"),
        cve_ids=data.get("cve_ids", []),
        validated=data.get("validated", False),
        false_positive=data.get("false_positive", False),
    )
