"""Reporting for LLM red team runs: console (Rich), JSON, and an OWASP LLM
Top 10 coverage matrix."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table

from rao.config import settings
from rao.tools.llm_redteam.models import LLMRedTeamResult, OwaspLLM

logger = logging.getLogger(__name__)

_SEV_COLOR = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "dim",
    "info": "dim",
}


def _safe(label: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", label)[:60] or "target"


def print_console_report(result: LLMRedTeamResult, console: Console | None = None) -> None:
    console = console or Console()
    successes = result.successes

    # ── Findings table (successes first) ───────────────────────────────────
    table = Table(title=f"LLM Red Team — {result.target_label}")
    table.add_column("OWASP", style="cyan", no_wrap=True)
    table.add_column("Probe")
    table.add_column("Result", no_wrap=True)
    table.add_column("Conf", justify="right", no_wrap=True)
    table.add_column("Detector", style="dim", no_wrap=True)

    for f in sorted(result.findings, key=lambda x: (not x.success, x.owasp_id.value)):
        if f.error:
            res = "[dim]error[/dim]"
        elif f.success:
            col = _SEV_COLOR.get(f.severity.value, "red")
            res = f"[{col}]VULNERABLE[/{col}]"
        else:
            res = "[green]blocked[/green]"
        table.add_row(
            f.owasp_id.value,
            f.name,
            res,
            f"{f.confidence:.2f}",
            f.detector,
        )
    console.print(table)

    # ── OWASP coverage matrix ──────────────────────────────────────────────
    cov = result.coverage()
    cov_table = Table(title="OWASP LLM Top 10 — Coverage")
    cov_table.add_column("ID", style="cyan", no_wrap=True)
    cov_table.add_column("Category")
    cov_table.add_column("Probed", justify="right")
    cov_table.add_column("Vulnerable", justify="right")
    for owasp in OwaspLLM:
        row = cov.get(owasp.value)
        if not row:
            continue
        vuln = row["succeeded"]
        vuln_txt = f"[red]{vuln}[/red]" if vuln else "[green]0[/green]"
        cov_table.add_row(owasp.value, owasp.label, str(row["probed"]), vuln_txt)
    console.print(cov_table)

    # ── Summary line ───────────────────────────────────────────────────────
    sev = result.by_severity()
    console.print(
        f"\n[bold]{len(successes)}[/bold] vulnerable / {result.total} probes  "
        f"([red]crit {sev['critical']}[/red], [red]high {sev['high']}[/red], "
        f"[yellow]med {sev['medium']}[/yellow])  "
        f"judge_used={result.judge_used}"
    )
    if result.errors:
        console.print(f"[dim]{len(result.errors)} probe error(s) — see JSON report[/dim]")


def save_json_report(result: LLMRedTeamResult, output_dir: str | None = None) -> Path:
    base = Path(output_dir or settings.report_output_dir) / "llm_redteam" / result.target_id
    base.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = base / f"report_{_safe(result.target_label)}_{ts}.json"
    payload = {
        "meta": {
            "framework": "RAO-Framework",
            "module": "llm_redteam",
            "target_id": result.target_id,
            "target": result.target_label,
            "started_at": result.started_at,
            "finished_at": result.finished_at,
            "judge_used": result.judge_used,
        },
        "summary": {
            "total_probes": result.total,
            "vulnerable": len(result.successes),
            "by_severity": result.by_severity(),
            "coverage": result.coverage(),
        },
        "findings": [f.model_dump(mode="json") for f in result.findings],
        "errors": result.errors,
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
