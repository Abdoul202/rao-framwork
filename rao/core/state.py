"""Shared state that flows through the LangGraph agent pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    service: str
    version: str = ""


@dataclass
class HostInfo:
    ip: str
    hostname: str = ""
    os_guess: str = ""
    ports: list[PortInfo] = field(default_factory=list)


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    evidence: str
    host: str
    port: int | None = None
    cve_ids: list[str] = field(default_factory=list)
    validated: bool = False
    false_positive: bool = False


@dataclass
class WebScanInfo:
    """Stored web scan results for a host."""
    url: str
    status_code: int = 0
    server: str = ""
    technologies: list[str] = field(default_factory=list)
    missing_headers: int = 0
    exposed_paths: int = 0
    cors_issues: int = 0


@dataclass
class SubdomainInfo:
    subdomain: str
    ip: str
    source: str = ""


@dataclass
class MissionState:
    """State object passed between agents in the graph."""

    target: str
    scope: list[str] = field(default_factory=list)
    hosts: list[HostInfo] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    validated_findings: list[Finding] = field(default_factory=list)
    web_scans: list[WebScanInfo] = field(default_factory=list)
    subdomains: list[SubdomainInfo] = field(default_factory=list)
    current_phase: str = "reconnaissance"
    errors: list[str] = field(default_factory=list)
