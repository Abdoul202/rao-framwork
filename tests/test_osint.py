"""Tests for the OSINTCollector.

All external HTTP calls and API interactions are mocked.
No network access or API keys required.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from rao.tools.osint import OSINTCollector, OSINTResult

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def collector():
    """OSINTCollector with all env keys absent."""
    with patch.dict("os.environ", {}, clear=False):
        return OSINTCollector(timeout=5)


@pytest.fixture
def empty_result():
    return OSINTResult(target="example.com")


# ── IP detection ──────────────────────────────────────────────────────────────

def test_is_ip_valid_ipv4():
    assert OSINTCollector._is_ip("192.168.1.1") is True


def test_is_ip_valid_ipv6():
    assert OSINTCollector._is_ip("::1") is True


def test_is_ip_domain_returns_false():
    assert OSINTCollector._is_ip("example.com") is False


def test_is_ip_subdomain_returns_false():
    assert OSINTCollector._is_ip("mail.example.com") is False


# ── Google dorks ──────────────────────────────────────────────────────────────

def test_generate_google_dorks_returns_list(collector):
    dorks = collector._generate_google_dorks("example.com")
    assert isinstance(dorks, list)
    assert len(dorks) >= 5


def test_generate_google_dorks_contain_domain(collector):
    dorks = collector._generate_google_dorks("example.com")
    assert all("example.com" in d for d in dorks)


def test_generate_google_dorks_cover_common_patterns(collector):
    dorks = collector._generate_google_dorks("example.com")
    combined = " ".join(dorks)
    assert "filetype:env" in combined or "filetype" in combined
    assert "admin" in combined.lower() or "login" in combined.lower()


# ── Finding compilation ───────────────────────────────────────────────────────

def test_compile_findings_shodan_vulns(collector, empty_result):
    empty_result.shodan_info = {"vulns": ["CVE-2021-44228"], "open_ports": []}
    collector._compile_findings(empty_result)
    titles = [f["title"] for f in empty_result.findings]
    assert any("CVE-2021-44228" in t for t in titles)


def test_compile_findings_risky_ports_flagged(collector, empty_result):
    empty_result.shodan_info = {"vulns": [], "open_ports": [23, 3389]}
    collector._compile_findings(empty_result)
    titles = [f["title"] for f in empty_result.findings]
    assert any("23" in t or "3389" in t for t in titles)


def test_compile_findings_safe_ports_not_flagged(collector, empty_result):
    empty_result.shodan_info = {"vulns": [], "open_ports": [80, 443]}
    collector._compile_findings(empty_result)
    # port 80/443 are not in the risky list — should produce 0 findings
    assert len(empty_result.findings) == 0


def test_compile_findings_otx_pulses(collector, empty_result):
    empty_result.otx_pulses = [
        {"name": "Malware Campaign", "description": "Bad actor", "tags": [], "created": ""},
        {"name": "APT Group", "description": "Nation state", "tags": [], "created": ""},
    ]
    collector._compile_findings(empty_result)
    titles = [f["title"] for f in empty_result.findings]
    assert any("OTX" in t or "AlienVault" in t or "threat report" in t for t in titles)


def test_compile_findings_github_results(collector, empty_result):
    empty_result.github_results = [
        {"name": "config.env", "path": ".env", "url": "https://github.com/x/y", "repository": "x/y", "query": "example.com password"},
    ]
    collector._compile_findings(empty_result)
    titles = [f["title"] for f in empty_result.findings]
    assert any("GitHub" in t or "leak" in t.lower() for t in titles)


def test_compile_findings_emails_info_severity(collector, empty_result):
    empty_result.emails = [
        {"email": "admin@example.com", "first_name": "Admin", "last_name": "User", "position": "IT", "confidence": 90},
    ]
    collector._compile_findings(empty_result)
    infos = [f for f in empty_result.findings if f["severity"] == "info"]
    assert len(infos) >= 1


# ── collect() integration ─────────────────────────────────────────────────────

def test_collect_returns_osint_result(collector):
    """collect() must always return an OSINTResult even with all sources failing."""
    with patch.object(collector, "_collect_whois"), \
         patch.object(collector, "_collect_otx"), \
         patch.object(collector, "_collect_github"):
        result = collector.collect("example.com")

    assert isinstance(result, OSINTResult)
    assert result.target == "example.com"


def test_collect_skips_shodan_without_key(collector):
    """When SHODAN_API_KEY is empty, _collect_shodan must not be called."""
    collector._shodan_key = ""
    with patch.object(collector, "_collect_whois"), \
         patch.object(collector, "_collect_shodan") as mock_shodan, \
         patch.object(collector, "_collect_otx"), \
         patch.object(collector, "_collect_github"):
        collector.collect("example.com")

    mock_shodan.assert_not_called()


def test_collect_skips_hunter_without_key(collector):
    """When HUNTER_API_KEY is empty, _collect_hunter must not be called."""
    collector._hunter_key = ""
    with patch.object(collector, "_collect_whois"), \
         patch.object(collector, "_collect_otx"), \
         patch.object(collector, "_collect_github"), \
         patch.object(collector, "_collect_hunter") as mock_hunter:
        collector.collect("example.com")

    mock_hunter.assert_not_called()
