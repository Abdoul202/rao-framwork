"""Tests for web scanner logic."""

from rao.tools.web_scanner import SECURITY_HEADERS, WebScanner


def test_normalize_url_adds_https():
    scanner = WebScanner()
    assert scanner._normalize_url("example.com") == "https://example.com"
    assert scanner._normalize_url("http://example.com") == "http://example.com"
    assert scanner._normalize_url("https://example.com") == "https://example.com"


def test_security_headers_list_is_complete():
    expected = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
    ]
    for header in expected:
        assert header in SECURITY_HEADERS


def test_sensitive_paths_includes_critical():
    from rao.tools.web_scanner import SENSITIVE_PATHS

    assert "/.env" in SENSITIVE_PATHS
    assert "/.git/HEAD" in SENSITIVE_PATHS
    assert "/robots.txt" in SENSITIVE_PATHS
