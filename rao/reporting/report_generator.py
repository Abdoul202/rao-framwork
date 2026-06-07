"""Generate structured reports from mission results."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table

from rao.config import settings
from rao.core.state import MissionState, Severity

logger = logging.getLogger(__name__)

# N4 fix: module-level console instance (not re-created on every call)
_console = Console()


def generate_report(mission: MissionState) -> Path:
    """Generate both console output and JSON report."""
    _print_console_report(mission)
    return _save_json_report(mission)


def _print_console_report(mission: MissionState) -> None:
    """Rich console output for immediate feedback."""
    _console.print(f"\n{'='*60}", style="bold blue")
    _console.print("  RAO-Framework - Mission Report", style="bold white")
    _console.print(f"{'='*60}", style="bold blue")

    _console.print(f"\nTarget: {mission.target}")
    _console.print(f"Hosts discovered: {len(mission.hosts)}")
    _console.print(f"Total findings: {len(mission.findings)}")
    _console.print(f"Validated findings: {len(mission.validated_findings)}")

    if mission.validated_findings:
        table = Table(title="\nValidated Findings", show_lines=True)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Title", width=40)
        table.add_column("Host", width=20)
        table.add_column("CVEs", width=20)

        severity_colors = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "bright_red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "dim",
        }

        for f in sorted(
            mission.validated_findings,
            key=lambda x: list(Severity).index(x.severity),
        ):
            color = severity_colors.get(f.severity, "white")
            table.add_row(
                f"[{color}]{f.severity.value.upper()}[/{color}]",
                f.title[:40],
                # N2 fix: port can be None — display "N/A" instead of "None"
                f"{f.host}:{f.port if f.port is not None else 'N/A'}",
                ", ".join(f.cve_ids) if f.cve_ids else "-",
            )

        _console.print(table)

    if mission.errors:
        _console.print(f"\n[yellow]Errors ({len(mission.errors)}):[/yellow]")
        for err in mission.errors:
            _console.print(f"  - {err}", style="dim")

    _console.print()


def _save_json_report(mission: MissionState) -> Path:
    """Save detailed JSON report to disk."""
    output_dir = Path(settings.report_output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # Extraire le domaine/host depuis la cible (URL ou IP)
    _parsed = urlparse(mission.target if "://" in mission.target else f"http://{mission.target}")
    _domain = _parsed.hostname or mission.target

    # Nom de fichier sûr basé sur le domaine
    _safe_domain = re.sub(r"[^a-zA-Z0-9]+", "_", _domain).strip("_")
    filename = f"rao_report_{_safe_domain}_{timestamp}.json"
    filepath = output_dir / filename

    # N1 fix: version from importlib.metadata, not hardcoded
    try:
        from importlib.metadata import version as _pkg_version
        _version = _pkg_version("rao-framework")
    except Exception:
        _version = "0.0.0-dev"

    report = {
        "meta": {
            "framework": "RAO-Framework",
            "version": _version,           # N1 fix
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": mission.target,
            "domain": _domain,
        },
        "summary": {
            "hosts_discovered": len(mission.hosts),
            "total_findings": len(mission.findings),
            "validated_findings": len(mission.validated_findings),
            "by_severity": _count_by_severity(mission.validated_findings),
        },
        "hosts": [
            {
                "ip": h.ip,
                "hostname": h.hostname,
                "os": h.os_guess,
                "open_ports": [
                    {
                        "port": p.port,
                        "protocol": p.protocol,
                        "service": p.service,
                        "version": p.version,
                    }
                    for p in h.ports
                ],
            }
            for h in mission.hosts
        ],
        "findings": [
            {
                "title": f.title,
                "severity": f.severity.value,
                "host": f.host,
                "port": f.port,
                "description": f.description,
                "evidence": f.evidence,
                "cves": f.cve_ids,
                "validated": f.validated,
                "false_positive": f.false_positive,
            }
            for f in mission.validated_findings
        ],
        # N3 fix: include attack_plan, web_scans, subdomains in JSON output
        "attack_plan": mission.attack_plan or None,
        "web_scans": [
            {
                "url": ws.url,
                "status_code": ws.status_code,
                "server": ws.server,
                "technologies": ws.technologies,
                "missing_headers_count": ws.missing_headers_count,
                "exposed_paths_count": ws.exposed_paths_count,
                "cors_issues_count": ws.cors_issues_count,
            }
            for ws in mission.web_scans
        ],
        "subdomains": [
            {"subdomain": s.subdomain, "ip": s.ip, "source": s.source}
            for s in mission.subdomains
        ],
        "errors": mission.errors,
    }

    filepath.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    logger.info("Report saved to %s", filepath)
    return filepath


def _count_by_severity(findings) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts
