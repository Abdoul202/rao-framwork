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
    """Summary of a web scan stored inside MissionState.

    Stores counts (not full detail lists) — keeps the mission state light.
    The full detail lists live in WebScanResult (web_scanner.py) during the
    active scan and are only needed for display / HTML report generation.

    Field names use _count suffix to avoid confusion with WebScanResult's
    list attributes of similar names (BUG #1 fix).
    """
    url: str
    status_code: int = 0
    server: str = ""
    technologies: list[str] = field(default_factory=list)
    missing_headers_count: int = 0
    exposed_paths_count: int = 0
    cors_issues_count: int = 0


@dataclass
class SubdomainInfo:
    subdomain: str
    ip: str
    source: str = ""


@dataclass
class SSLFinding:
    """Lightweight SSL/TLS finding stored in mission state."""
    host: str
    port: int
    severity: str
    title: str
    detail: str


@dataclass
class OSINTSummary:
    """High-level OSINT summary stored in mission state."""
    target: str
    registrar: str = ""
    shodan_ports: list[int] = field(default_factory=list)
    shodan_vulns: list[str] = field(default_factory=list)
    otx_pulse_count: int = 0
    emails_found: int = 0
    github_leaks: int = 0
    google_dorks: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)  # {severity, title, detail}


@dataclass
class MissionState:
    """State object passed between agents in the graph."""

    target: str
    scope: list[str] = field(default_factory=list)
    hosts: list[HostInfo] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    validated_findings: list[Finding] = field(default_factory=list)
    # BUG #3 fix: web_scans and subdomains are now populated by the CLI
    web_scans: list[WebScanInfo] = field(default_factory=list)
    subdomains: list[SubdomainInfo] = field(default_factory=list)
    current_phase: str = "reconnaissance"
    errors: list[str] = field(default_factory=list)
    # Operator output: raw attack plan text from LLM (plain text, intentional)
    attack_plan: str = ""
    # Structured attack steps parsed from attack_plan (populated by OperatorAgent)
    attack_steps: list = field(default_factory=list)  # list[AttackStep] — avoids circular import
    # v0.2 additions — default_factory keeps backward compat with saved sessions
    ssl_findings: list[SSLFinding] = field(default_factory=list)
    osint: OSINTSummary | None = None
    nuclei_findings: list[Finding] = field(default_factory=list)
