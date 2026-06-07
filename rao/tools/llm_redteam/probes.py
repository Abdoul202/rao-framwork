"""Probe catalogue loader and payload rendering."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from pathlib import Path

import yaml

from rao.tools.llm_redteam.models import LLMProbe, OwaspLLM

logger = logging.getLogger(__name__)

DEFAULT_PROBES_PATH = Path(__file__).parent / "data" / "llm_probes.yaml"


def load_probes(path: str | Path | None = None) -> list[LLMProbe]:
    """Load and validate the probe catalogue from a YAML file."""
    p = Path(path) if path else DEFAULT_PROBES_PATH
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    items = raw.get("probes", [])
    probes: list[LLMProbe] = []
    for entry in items:
        try:
            probes.append(LLMProbe(**entry))
        except Exception as exc:  # noqa: BLE001 — skip malformed entries, keep going
            logger.warning("Skipping malformed probe %r: %s", entry.get("id", "?"), exc)
    logger.debug("Loaded %d probes from %s", len(probes), p)
    return probes


def filter_probes(
    probes: Iterable[LLMProbe], categories: Iterable[str] | None
) -> list[LLMProbe]:
    """Keep only probes whose OWASP id is in `categories` (case-insensitive).

    `categories` may contain ids like "LLM01" or "llm01". None => keep all.
    """
    if not categories:
        return list(probes)
    wanted = {c.strip().upper() for c in categories if c.strip()}
    valid = {o.value for o in OwaspLLM}
    unknown = wanted - valid
    if unknown:
        logger.warning("Ignoring unknown OWASP categories: %s", ", ".join(sorted(unknown)))
    return [p for p in probes if p.owasp_id.value in wanted]


def render_payload(payload: str, *, canary: str = "", inject: str = "") -> str:
    """Substitute runtime tokens into a payload template."""
    return payload.replace("{{CANARY}}", canary).replace("{{INJECT}}", inject)
