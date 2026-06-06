"""
Nuclei Plugin — Template-based vulnerability scanner wrapper.

Wraps the Nuclei CLI (https://github.com/projectdiscovery/nuclei) as a
RAO ToolPlugin. Requires nuclei to be installed separately:

    # Go install (recommended)
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

    # Or via the package manager
    sudo apt install nuclei   # Kali Linux
    brew install nuclei       # macOS

Usage via CLI
-------------
    rao nuclei-scan https://target.com --confirm
    rao scan target.com --confirm --nuclei
    rao scan target.com --confirm --nuclei --nuclei-severity critical,high

Usage via Python API
--------------------
    from rao.tools.nuclei_plugin import NucleiPlugin
    plugin = NucleiPlugin()
    result = plugin.run("https://target.com", severity="high,critical", tags="cve")

Findings from Nuclei are automatically converted to RAO ``Finding`` objects
and merged into the mission's ``validated_findings`` list.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any

from rao.core.state import Finding, Severity
from rao.tools.plugin import ToolPlugin, ToolResult
from rao.tools.plugin import registry as _registry

logger = logging.getLogger(__name__)

# Nuclei severity → RAO Severity mapping
_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "info":     Severity.INFO,
    "unknown":  Severity.LOW,
}

# Default profile for automated mission scans (fast + high value)
DEFAULT_SEVERITY = "medium,high,critical"
DEFAULT_TAGS     = "cve,misconfig,oast,exposure,default-logins"
DEFAULT_TIMEOUT  = 300   # 5 minutes max


@dataclass
class NucleiResult:
    target: str
    raw_findings: list[dict] = field(default_factory=list)
    rao_findings: list[Finding] = field(default_factory=list)
    error: str = ""
    nuclei_version: str = ""

    @property
    def is_ok(self) -> bool:
        return not self.error


class NucleiPlugin(ToolPlugin):
    """RAO ToolPlugin wrapping the Nuclei scanner CLI.

    Nuclei brings 9000+ community-maintained vulnerability templates
    covering CVEs, misconfigurations, exposed panels, default credentials,
    and more — without requiring reimplementation in RAO.
    """

    name        = "nuclei"
    description = "Template-based vulnerability scanner (9000+ templates, ProjectDiscovery)"
    version     = "1.0.0"
    author      = "RAO-Framework"
    requires    = ["nuclei"]   # system binary

    def __init__(self) -> None:
        self._binary = self._find_binary()

    def is_available(self) -> bool:
        """Return True if the nuclei binary is accessible."""
        return self._binary is not None

    def run(
        self,
        target: str,
        severity: str = DEFAULT_SEVERITY,
        tags: str = DEFAULT_TAGS,
        templates: str | None = None,
        rate_limit: int = 150,
        timeout: int = DEFAULT_TIMEOUT,
        extra_args: list[str] | None = None,
        **kwargs: Any,
    ) -> ToolResult:
        """Run Nuclei against a target.

        Parameters
        ----------
        target:
            URL or IP address.
        severity:
            Comma-separated severity filter (info/low/medium/high/critical).
        tags:
            Comma-separated template tags to run.
        templates:
            Specific template path or glob. Overrides ``tags`` if set.
        rate_limit:
            Max requests per second (default: 150).
        timeout:
            Max scan duration in seconds (default: 300).
        extra_args:
            Additional raw nuclei CLI arguments.

        Returns
        -------
        ToolResult
            ``data["findings"]`` contains list of raw Nuclei JSON findings.
            ``data["rao_findings"]`` contains converted Finding objects.
        """
        if not self._binary:
            return ToolResult(
                success=False,
                error="nuclei binary not found. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            )

        cmd = self._build_command(target, severity, tags, templates, rate_limit, extra_args)
        logger.info("Nuclei: %s", " ".join(cmd))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            logger.warning("Nuclei timed out after %ds on %s", timeout, target)
            return ToolResult(success=False, error=f"Nuclei timed out after {timeout}s")
        except Exception as e:
            logger.error("Nuclei execution failed: %s", e)
            return ToolResult(success=False, error=str(e))

        raw_findings = self._parse_output(proc.stdout)
        rao_findings = [self._to_rao_finding(f, target) for f in raw_findings]

        logger.info(
            "Nuclei: %d findings on %s (exit=%d)", len(raw_findings), target, proc.returncode
        )

        return ToolResult(
            success=True,
            data={
                "findings":     raw_findings,
                "rao_findings": rao_findings,
                "target":       target,
                "stderr":       proc.stderr[:2000] if proc.stderr else "",
            },
            raw=proc.stdout,
        )

    def get_version(self) -> str:
        """Return the installed Nuclei version string."""
        if not self._binary:
            return "not installed"
        try:
            out = subprocess.check_output([self._binary, "-version"], text=True, timeout=10)
            return out.strip().split("\n")[0]
        except Exception:
            return "unknown"

    # ── Private helpers ───────────────────────────────────────────────────────

    def _find_binary(self) -> str | None:
        """Locate the nuclei binary in PATH or common install locations."""
        # shutil.which checks PATH
        path = shutil.which("nuclei")
        if path:
            return path
        # Common Go install path
        import os
        go_path = os.path.expanduser("~/go/bin/nuclei")
        if os.path.isfile(go_path):
            return go_path
        return None

    def _build_command(
        self,
        target: str,
        severity: str,
        tags: str,
        templates: str | None,
        rate_limit: int,
        extra_args: list[str] | None,
    ) -> list[str]:
        """Build the nuclei command list."""
        cmd = [
            self._binary,
            "-u", target,
            "-severity", severity,
            "-rate-limit", str(rate_limit),
            "-json",       # structured JSON output — one finding per line
            "-silent",     # suppress progress bars
            "-no-color",   # avoid ANSI codes in JSON lines
            "-timeout", "10",
        ]

        if templates:
            cmd += ["-t", templates]
        else:
            cmd += ["-tags", tags]

        if extra_args:
            cmd += extra_args

        return cmd

    def _parse_output(self, stdout: str) -> list[dict]:
        """Parse Nuclei JSON output (one JSON object per line)."""
        findings = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                findings.append(obj)
            except json.JSONDecodeError:
                # Nuclei sometimes emits non-JSON progress lines even with -silent
                logger.debug("Non-JSON nuclei line: %s", line[:100])
        return findings

    def _to_rao_finding(self, nuclei_finding: dict, target: str) -> Finding:
        """Convert a raw Nuclei JSON finding to a RAO Finding object."""
        info = nuclei_finding.get("info", {})
        matched_at = nuclei_finding.get("matched-at", target)
        template_id = nuclei_finding.get("template-id", "nuclei-unknown")

        raw_severity = info.get("severity", "medium").lower()
        severity = _SEVERITY_MAP.get(raw_severity, Severity.MEDIUM)

        name = info.get("name", template_id)
        description = info.get("description", "")
        reference = info.get("reference", [])
        if isinstance(reference, list):
            reference = " | ".join(reference[:3])

        # Extract CVE IDs from classification metadata
        classification = info.get("classification", {})
        cve_ids: list[str] = classification.get("cve-id", [])
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]

        return Finding(
            title=f"[Nuclei] {name}",
            severity=severity,
            description=description or f"Nuclei template '{template_id}' matched.",
            evidence=f"Matched at: {matched_at} | Template: {template_id} | Ref: {reference}",
            host=target,
            cve_ids=cve_ids,
            validated=True,   # Nuclei findings are template-confirmed, skip Critic
        )


# ── Module-level singleton ────────────────────────────────────────────────────

nuclei_plugin = NucleiPlugin()

# Auto-register in the global plugin registry
try:
    _registry.register(nuclei_plugin)
except ValueError:
    pass  # Already registered (e.g. on reimport)
