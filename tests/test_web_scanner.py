"""Tests for web scanner — v0.5 additions.

Tests for the new detection methods: SSTI, Open Redirect, Path Traversal,
SQLi POST, and SQLi Blind. All tests use unittest.mock to avoid real
HTTP requests.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from rao.tools.web_scanner import (
    REDIRECT_PARAMS,
    REDIRECT_TARGET,
    SQLI_BLIND_PAYLOADS,
    SQLI_BLIND_THRESHOLD,
    SSTI_PAYLOADS,
    TRAVERSAL_PAYLOADS,
    TRAVERSAL_SUCCESS,
    WebScanner,
    WebScanResult,
)

# ── Existing tests (kept) ─────────────────────────────────────────────────────

def test_normalize_url_adds_https():
    scanner = WebScanner()
    assert scanner._normalize_url("example.com") == "https://example.com"
    assert scanner._normalize_url("http://example.com") == "http://example.com"
    assert scanner._normalize_url("https://example.com") == "https://example.com"


def test_security_headers_list_is_complete():
    from rao.tools.web_scanner import SECURITY_HEADERS

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


# ── WebScanResult — new fields ────────────────────────────────────────────────

def test_scan_result_has_ssti_field():
    r = WebScanResult(url="https://example.com")
    assert r.ssti_indicators == []


def test_scan_result_has_open_redirect_field():
    r = WebScanResult(url="https://example.com")
    assert r.open_redirect_indicators == []


def test_scan_result_has_path_traversal_field():
    r = WebScanResult(url="https://example.com")
    assert r.path_traversal_indicators == []


def test_scan_result_has_sqli_blind_field():
    r = WebScanResult(url="https://example.com")
    assert r.sqli_blind_indicators == []


def test_scan_result_has_sqli_post_field():
    r = WebScanResult(url="https://example.com")
    assert r.sqli_post_indicators == []


# ── Constants completeness ────────────────────────────────────────────────────

def test_ssti_payloads_cover_main_engines():
    engines = [hint for _, _, hint in SSTI_PAYLOADS]
    assert any("Jinja2" in e for e in engines)
    assert any("Freemarker" in e for e in engines)


def test_ssti_payloads_use_unique_math():
    """Each SSTI payload should produce a unique integer result (14167696)."""
    for _payload, expected, _ in SSTI_PAYLOADS:
        assert expected == "14167696"


def test_redirect_params_covers_common_names():
    for name in ("redirect", "url", "next", "return", "destination"):
        assert name in REDIRECT_PARAMS


def test_redirect_target_is_external():
    assert REDIRECT_TARGET.startswith("https://")
    assert "evil" in REDIRECT_TARGET


def test_traversal_payloads_include_encoding_variant():
    encoded = [p for p in TRAVERSAL_PAYLOADS if "%2e" in p.lower()]
    assert len(encoded) >= 1


def test_traversal_success_patterns_cover_unix_and_windows():
    assert any("root:x:" in p for p in TRAVERSAL_SUCCESS)
    assert any("[fonts]" in p or "[extensions]" in p for p in TRAVERSAL_SUCCESS)


def test_sqli_blind_threshold_reasonable():
    """Threshold must be > 4s to avoid false positives on slow servers."""
    assert SQLI_BLIND_THRESHOLD >= 4.0


def test_sqli_blind_payloads_cover_multiple_dbs():
    payloads_str = " ".join(SQLI_BLIND_PAYLOADS)
    assert "SLEEP" in payloads_str       # MySQL
    assert "WAITFOR" in payloads_str     # MSSQL
    assert "pg_sleep" in payloads_str    # PostgreSQL


# ── _test_ssti ────────────────────────────────────────────────────────────────

class TestSSTIDetection:
    def _make_scanner(self):
        return WebScanner(test_injections=True, path_scan_delay=0)

    def test_ssti_detected_when_result_reflected(self):
        """If the evaluated result (14167696) appears in the response, SSTI is flagged."""
        scanner = self._make_scanner()
        result = WebScanResult(url="https://example.com?q=test")

        mock_resp = MagicMock()
        mock_resp.text = "Result: 14167696"

        with patch.object(scanner.session, "get", return_value=mock_resp):
            scanner._test_ssti("https://example.com?q=test", result)

        assert len(result.ssti_indicators) >= 1
        assert result.ssti_indicators[0]["expected"] == "14167696"

    def test_ssti_not_flagged_when_result_absent(self):
        scanner = self._make_scanner()
        result = WebScanResult(url="https://example.com?q=test")

        mock_resp = MagicMock()
        mock_resp.text = "Hello world, nothing special here."

        with patch.object(scanner.session, "get", return_value=mock_resp):
            scanner._test_ssti("https://example.com?q=test", result)

        assert result.ssti_indicators == []

    def test_ssti_no_params_uses_defaults(self):
        """When URL has no params, scanner should still attempt defaults (q, search)."""
        scanner = self._make_scanner()
        result = WebScanResult(url="https://example.com")

        mock_resp = MagicMock()
        mock_resp.text = "no match"

        with patch.object(scanner.session, "get", return_value=mock_resp):
            scanner._test_ssti("https://example.com", result)

        assert result.ssti_indicators == []  # No match, no crash

    def test_ssti_network_error_is_silent(self):
        scanner = self._make_scanner()
        result = WebScanResult(url="https://example.com?q=test")

        with patch.object(scanner.session, "get", side_effect=ConnectionError("timeout")):
            scanner._test_ssti("https://example.com?q=test", result)

        assert result.ssti_indicators == []


# ── _test_open_redirect ───────────────────────────────────────────────────────

class TestOpenRedirectDetection:
    def _make_scanner(self):
        return WebScanner(test_injections=True, path_scan_delay=0)

    def test_redirect_detected_in_location_header(self):
        scanner = self._make_scanner()
        result = WebScanResult(url="https://example.com")

        mock_resp = MagicMock()
        mock_resp.headers = {"Location": "https://evil.attacker.com/pwned"}
        mock_resp.status_code = 302

        with patch.object(scanner.session, "get", return_value=mock_resp):
            scanner._test_open_redirect("https://example.com", result)

        assert len(result.open_redirect_indicators) >= 1
        assert "evil.attacker.com" in result.open_redirect_indicators[0]["redirect_to"]

    def test_redirect_not_flagged_when_safe_location(self):
        scanner = self._make_scanner()
        result = WebScanResult(url="https://example.com")

        mock_resp = MagicMock()
        mock_resp.headers = {"Location": "/dashboard"}
        mock_resp.status_code = 302

        with patch.object(scanner.session, "get", return_value=mock_resp):
            scanner._test_open_redirect("https://example.com", result)

        assert result.open_redirect_indicators == []

    def test_redirect_network_error_is_silent(self):
        scanner = self._make_scanner()
        result = WebScanResult(url="https://example.com")

        with patch.object(scanner.session, "get", side_effect=Exception("conn refused")):
            scanner._test_open_redirect("https://example.com", result)

        assert result.open_redirect_indicators == []


# ── _test_path_traversal ──────────────────────────────────────────────────────

class TestPathTraversalDetection:
    def _make_scanner(self):
        return WebScanner(test_injections=True, path_scan_delay=0)

    def test_traversal_detected_on_passwd_pattern(self):
        scanner = self._make_scanner()
        result = WebScanResult(url="https://example.com?file=test.txt")

        mock_resp = MagicMock()
        mock_resp.text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1"

        with patch.object(scanner.session, "get", return_value=mock_resp):
            scanner._test_path_traversal("https://example.com?file=test.txt", result)

        assert len(result.path_traversal_indicators) >= 1
        assert result.path_traversal_indicators[0]["parameter"] == "file"

    def test_traversal_not_flagged_on_clean_response(self):
        scanner = self._make_scanner()
        result = WebScanResult(url="https://example.com?file=test.txt")

        mock_resp = MagicMock()
        mock_resp.text = "<html>Normal page content</html>"

        with patch.object(scanner.session, "get", return_value=mock_resp):
            scanner._test_path_traversal("https://example.com?file=test.txt", result)

        assert result.path_traversal_indicators == []

    def test_traversal_tests_known_file_params_on_paramless_url(self):
        """Without URL params, scanner tries TRAVERSAL_PARAMS (file, path, etc.)."""
        scanner = self._make_scanner()
        result = WebScanResult(url="https://example.com")

        mock_resp = MagicMock()
        mock_resp.text = "nothing here"

        with patch.object(scanner.session, "get", return_value=mock_resp):
            scanner._test_path_traversal("https://example.com", result)

        assert result.path_traversal_indicators == []  # No match, no crash


# ── _test_sqli_post ───────────────────────────────────────────────────────────

class TestSQLiPOSTDetection:
    def _make_scanner(self):
        return WebScanner(test_injections=True, path_scan_delay=0)

    def test_sqli_post_detected_on_error_pattern(self):
        scanner = self._make_scanner()
        result = WebScanResult(url="https://example.com/login")

        mock_resp = MagicMock()
        mock_resp.text = "You have an error in your SQL syntax near 'OR'='1'"

        with patch.object(scanner.session, "post", return_value=mock_resp):
            scanner._test_sqli_post("https://example.com/login", result)

        assert len(result.sqli_post_indicators) >= 1
        assert result.sqli_post_indicators[0]["method"] == "POST"

    def test_sqli_post_not_flagged_on_clean_response(self):
        scanner = self._make_scanner()
        result = WebScanResult(url="https://example.com/login")

        mock_resp = MagicMock()
        mock_resp.text = "Invalid credentials. Please try again."

        with patch.object(scanner.session, "post", return_value=mock_resp):
            scanner._test_sqli_post("https://example.com/login", result)

        assert result.sqli_post_indicators == []


# ── _test_sqli_blind ─────────────────────────────────────────────────────────

class TestSQLiBlindDetection:
    def _make_scanner(self):
        return WebScanner(test_injections=True, path_scan_delay=0)

    def test_blind_sqli_detected_on_delayed_response(self):
        """Simulate a 5-second response delay → blind SQLi indicator."""
        import time

        scanner = self._make_scanner()
        result = WebScanResult(url="https://example.com?id=1")

        call_count = [0]

        def slow_get(*args, **kwargs):
            call_count[0] += 1
            # Only delay the first call (the blind payload)
            if call_count[0] == 1:
                time.sleep(5)
            return MagicMock()

        with patch.object(scanner.session, "get", side_effect=slow_get):
            scanner._test_sqli_blind("https://example.com?id=1", result)

        assert len(result.sqli_blind_indicators) >= 1
        assert result.sqli_blind_indicators[0]["elapsed_seconds"] >= SQLI_BLIND_THRESHOLD

    def test_blind_sqli_not_flagged_on_fast_response(self):
        scanner = self._make_scanner()
        result = WebScanResult(url="https://example.com?id=1")

        mock_resp = MagicMock()
        with patch.object(scanner.session, "get", return_value=mock_resp):
            scanner._test_sqli_blind("https://example.com?id=1", result)

        assert result.sqli_blind_indicators == []
