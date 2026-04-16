"""Generate structured reports from mission results."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table

from rao.config import settings
from rao.core.state import MissionState, Severity

logger = logging.getLogger(__name__)


def generate_report(mission: MissionState) -> Path:
    """Generate both console output and JSON report."""
    _print_console_report(mission)
    return _save_json_report(mission)


def _print_console_report(mission: MissionState) -> None:
    """Rich console output for immediate feedback."""
    console = Console()

    console.print(f"\n{'='*60}", style="bold blue")
    console.print("  RAO-Framework - Mission Report", style="bold white")
    console.print(f"{'='*60}", style="bold blue")

    console.print(f"\nTarget: {mission.target}")
    console.print(f"Hosts discovered: {len(mission.hosts)}")
    console.print(f"Total findings: {len(mission.findings)}")
    console.print(f"Validated findings: {len(mission.validated_findings)}")

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
                f"{f.host}:{f.port}",
                ", ".join(f.cve_ids) if f.cve_ids else "-",
            )

        console.print(table)

    if mission.errors:
        console.print(f"\n[yellow]Errors ({len(mission.errors)}):[/yellow]")
        for err in mission.errors:
            console.print(f"  - {err}", style="dim")

    console.print()


def _save_json_report(mission: MissionState) -> Path:
    """Save detailed JSON report to disk."""
    output_dir = Path(settings.report_output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"rao_report_{mission.target.replace('.', '_')}_{timestamp}.json"
    filepath = output_dir / filename

    report = {
        "meta": {
            "framework": "RAO-Framework",
            "version": "0.1.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": mission.target,
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
