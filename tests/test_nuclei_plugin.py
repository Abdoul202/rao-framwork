"""Tests for the NucleiPlugin tool wrapper.

All tests are fully mocked — no nuclei binary, no network access required.
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from rao.core.state import Finding, Severity
from rao.tools.nuclei_plugin import NucleiPlugin

# ── Fixtures ──────────────────────────────────────────────────────────────────

def _raw_finding(
    template_id: str = "cve-2024-1234",
    severity: str = "high",
    name: str = "Test CVE",
    matched_at: str = "https://example.com",
    cve_ids: list[str] | None = None,
) -> dict:
    return {
        "template-id": template_id,
        "matched-at": matched_at,
        "info": {
            "name": name,
            "severity": severity,
            "description": "A test vulnerability description.",
            "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
            "classification": {"cve-id": cve_ids or ["CVE-2024-1234"]},
        },
    }


@pytest.fixture
def plugin_no_binary():
    """NucleiPlugin with no binary available."""
    with patch("shutil.which", return_value=None), \
         patch("os.path.isfile", return_value=False):
        return NucleiPlugin()


@pytest.fixture
def plugin_with_binary():
    """NucleiPlugin with a mocked binary at /usr/bin/nuclei."""
    with patch("shutil.which", return_value="/usr/bin/nuclei"):
        return NucleiPlugin()


# ── Availability ──────────────────────────────────────────────────────────────

def test_is_available_false_when_no_binary(plugin_no_binary):
    assert plugin_no_binary.is_available() is False


def test_is_available_true_when_binary_found(plugin_with_binary):
    assert plugin_with_binary.is_available() is True


def test_run_returns_error_when_no_binary(plugin_no_binary):
    result = plugin_no_binary.run("https://example.com")
    assert result.success is False
    assert "nuclei binary not found" in result.error


# ── Plugin metadata ───────────────────────────────────────────────────────────

def test_plugin_metadata():
    assert NucleiPlugin.name == "nuclei"
    assert NucleiPlugin.version == "1.0.0"
    assert "nuclei" in NucleiPlugin.requires


# ── Output parsing ────────────────────────────────────────────────────────────

def test_parse_output_valid_json(plugin_no_binary):
    raw = _raw_finding()
    stdout = json.dumps(raw) + "\n" + json.dumps(raw)
    findings = plugin_no_binary._parse_output(stdout)
    assert len(findings) == 2
    assert findings[0]["template-id"] == "cve-2024-1234"


def test_parse_output_skips_non_json_lines(plugin_no_binary):
    stdout = "not json\n" + json.dumps(_raw_finding()) + "\nalso not json"
    findings = plugin_no_binary._parse_output(stdout)
    assert len(findings) == 1


def test_parse_output_empty_stdout(plugin_no_binary):
    assert plugin_no_binary._parse_output("") == []


def test_parse_output_blank_lines_ignored(plugin_no_binary):
    stdout = "\n\n" + json.dumps(_raw_finding()) + "\n\n"
    findings = plugin_no_binary._parse_output(stdout)
    assert len(findings) == 1


# ── Finding conversion ────────────────────────────────────────────────────────

def test_to_rao_finding_maps_severity_high(plugin_no_binary):
    raw = _raw_finding(severity="high")
    finding = plugin_no_binary._to_rao_finding(raw, "https://example.com")
    assert finding.severity == Severity.HIGH


def test_to_rao_finding_maps_severity_critical(plugin_no_binary):
    raw = _raw_finding(severity="critical")
    finding = plugin_no_binary._to_rao_finding(raw, "https://example.com")
    assert finding.severity == Severity.CRITICAL


def test_to_rao_finding_maps_severity_unknown_to_low(plugin_no_binary):
    raw = _raw_finding(severity="unknown")
    finding = plugin_no_binary._to_rao_finding(raw, "https://example.com")
    assert finding.severity == Severity.LOW


def test_to_rao_finding_extracts_cves(plugin_no_binary):
    raw = _raw_finding(cve_ids=["CVE-2024-1234", "CVE-2024-5678"])
    finding = plugin_no_binary._to_rao_finding(raw, "https://example.com")
    assert "CVE-2024-1234" in finding.cve_ids
    assert "CVE-2024-5678" in finding.cve_ids


def test_to_rao_finding_validated_true(plugin_no_binary):
    """Nuclei findings skip the Critic — must be pre-validated."""
    raw = _raw_finding()
    finding = plugin_no_binary._to_rao_finding(raw, "https://example.com")
    assert finding.validated is True


def test_to_rao_finding_title_has_nuclei_prefix(plugin_no_binary):
    raw = _raw_finding(name="Exposed Admin Panel")
    finding = plugin_no_binary._to_rao_finding(raw, "https://example.com")
    assert finding.title.startswith("[Nuclei]")
    assert "Exposed Admin Panel" in finding.title


def test_to_rao_finding_cve_as_string_is_wrapped_in_list(plugin_no_binary):
    """Nuclei sometimes emits cve-id as a string, not a list."""
    raw = _raw_finding()
    raw["info"]["classification"]["cve-id"] = "CVE-2024-9999"
    finding = plugin_no_binary._to_rao_finding(raw, "https://example.com")
    assert finding.cve_ids == ["CVE-2024-9999"]


# ── Command building ──────────────────────────────────────────────────────────

def test_build_command_default_tags(plugin_with_binary):
    cmd = plugin_with_binary._build_command(
        target="https://t.com",
        severity="high,critical",
        tags="cve,misconfig",
        templates=None,
        rate_limit=150,
        extra_args=None,
    )
    assert "-tags" in cmd
    assert "cve,misconfig" in cmd
    assert "-json" in cmd
    assert "-silent" in cmd


def test_build_command_with_templates_overrides_tags(plugin_with_binary):
    cmd = plugin_with_binary._build_command(
        target="https://t.com",
        severity="critical",
        tags="cve",
        templates="/path/to/templates/",
        rate_limit=100,
        extra_args=None,
    )
    assert "-t" in cmd
    assert "/path/to/templates/" in cmd
    assert "-tags" not in cmd


def test_build_command_includes_extra_args(plugin_with_binary):
    cmd = plugin_with_binary._build_command(
        target="https://t.com",
        severity="high",
        tags="cve",
        templates=None,
        rate_limit=150,
        extra_args=["-interactsh-server", "https://interactsh.com"],
    )
    assert "-interactsh-server" in cmd


# ── Full run mocked subprocess ────────────────────────────────────────────────

def test_run_success_mocked_subprocess(plugin_with_binary):
    raw = _raw_finding()
    mock_proc = MagicMock()
    mock_proc.stdout = json.dumps(raw)
    mock_proc.stderr = ""
    mock_proc.returncode = 0

    with patch("subprocess.run", return_value=mock_proc):
        result = plugin_with_binary.run("https://example.com")

    assert result.success is True
    assert len(result.data["rao_findings"]) == 1
    assert isinstance(result.data["rao_findings"][0], Finding)


def test_run_timeout_handled(plugin_with_binary):
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="nuclei", timeout=300)):
        result = plugin_with_binary.run("https://example.com", timeout=300)

    assert result.success is False
    assert "timed out" in result.error.lower()


def test_run_subprocess_exception_handled(plugin_with_binary):
    with patch("subprocess.run", side_effect=OSError("Permission denied")):
        result = plugin_with_binary.run("https://example.com")

    assert result.success is False
    assert "Permission denied" in result.error
