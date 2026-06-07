"""Baseline persistence and regression diffing — the 'continuous' layer.

Each target keeps a baseline of per-probe status. A new run is compared against
it to surface:

  NEW         a probe that now succeeds but did not before  -> regression
  FIXED       a probe that succeeded before but now blocked
  PERSISTENT  a probe that succeeds in both

`--ci` fails the build when there is any NEW entry.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from rao.config import settings
from rao.tools.llm_redteam.models import LLMRedTeamResult

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def probe_status(result: LLMRedTeamResult) -> dict[str, dict]:
    """Reduce a run to per-probe status. A probe is 'vulnerable' if ANY of its
    payload findings succeeded."""
    status: dict[str, dict] = {}
    for f in result.findings:
        row = status.setdefault(
            f.probe_id,
            {
                "name": f.name,
                "owasp_id": f.owasp_id.value,
                "severity": f.severity.value,
                "vulnerable": False,
            },
        )
        if f.success:
            row["vulnerable"] = True
    return status


def baseline_path(target_id: str, base_dir: str | None = None) -> Path:
    base = Path(base_dir or settings.report_output_dir) / "llm_redteam" / target_id
    return base / "baseline.json"


def load_baseline(target_id: str, base_dir: str | None = None) -> dict[str, dict]:
    path = baseline_path(target_id, base_dir)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("probes", {})
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Could not read baseline %s: %s", path, exc)
        return {}


def save_baseline(
    target_id: str, statuses: dict[str, dict], base_dir: str | None = None
) -> Path:
    """Persist current statuses, preserving first_seen across runs."""
    path = baseline_path(target_id, base_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    prior = load_baseline(target_id, base_dir)
    now = _now()
    out: dict[str, dict] = {}
    for pid, row in statuses.items():
        prev = prior.get(pid, {})
        out[pid] = {
            **row,
            "first_seen": prev.get("first_seen", now),
            "last_seen": now,
        }
    path.write_text(
        json.dumps({"target_id": target_id, "updated_at": now, "probes": out}, indent=2),
        encoding="utf-8",
    )
    return path


@dataclass
class BaselineDiff:
    new: list[dict] = field(default_factory=list)         # regressions
    fixed: list[dict] = field(default_factory=list)
    persistent: list[dict] = field(default_factory=list)

    @property
    def has_regressions(self) -> bool:
        return bool(self.new)

    def summary(self) -> str:
        return (
            f"NEW={len(self.new)} FIXED={len(self.fixed)} "
            f"PERSISTENT={len(self.persistent)}"
        )


def diff_baseline(prior: dict[str, dict], current: dict[str, dict]) -> BaselineDiff:
    """Compare a prior baseline to the current run's per-probe status."""
    diff = BaselineDiff()
    for pid, row in current.items():
        was_vuln = bool(prior.get(pid, {}).get("vulnerable", False))
        now_vuln = bool(row.get("vulnerable", False))
        entry = {"probe_id": pid, **{k: row.get(k) for k in ("name", "owasp_id", "severity")}}
        if now_vuln and not was_vuln:
            diff.new.append(entry)
        elif now_vuln and was_vuln:
            diff.persistent.append(entry)
        elif not now_vuln and was_vuln:
            diff.fixed.append(entry)
    return diff
