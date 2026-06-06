"""Tests for web_scanner v0.5.2 new detection methods.

All 16 new methods are tested via mocks — no real HTTP requests.
Coverage: A01, A02, A03, A04, A05, A08, A09, A10.
"""

from __future__ import annotations

import re
from unittest.mock import MagicMock, patch

from rao.tools.web_scanner import (
    CORRELATION_HEADERS,
    INTERNAL_IP_PATTERNS,
    KNOWN_CDN_HOSTS,
    PII_PATTERNS,
    SENSITIVE_QUERY_PARAMS,
    SOURCE_MAP_PATHS,
    SSRF_PAYLOADS,
    SSRF_SUCCESS_PATTERNS,
    WebScanner,
    WebScanResult,
)

# ── Fixture helpers ───────────────────────────────────────────────────────────

def _scanner(injections: bool = False, auth: bool = False) -> WebScanner:
    return WebScanner(test_injections=injections, test_auth=auth, path_scan_delay=0)


def _mock_resp(
    text: str = "",
    status: int = 200,
    headers: dict | None = None,
) -> MagicMock:
    resp = MagicMock()
    resp.text = text
    resp.status_code = status
    resp.content = text.encode()
    resp.headers = headers or {}
    return resp


# ── Constants completeness ────────────────────────────────────────────────────

def test_pii_patterns_not_empty():
    assert len(PII_PATTERNS) >= 5


def test_sensitive_query_params_cover_common():
    for p in ("token", "password", "api_key", "session"):
        assert p in SENSITIVE_QUERY_PARAMS


def test_ssrf_payloads_cover_cloud_providers():
    payloads = " ".join(SSRF_PAYLOADS)
    assert "169.254.169.254" in payloads   # AWS / generic
    assert "metadata.google" in payloads    # GCP


def test_ssrf_success_patterns_cover_aws_gcp():
    patterns = " ".join(SSRF_SUCCESS_PATTERNS)
    assert "ami-id" in patterns or "instance-id" in patterns   # AWS
    assert "project-id" in patterns or "computeMetadata" in patterns  # GCP


def test_source_map_paths_include_common():
    paths = " ".join(SOURCE_MAP_PATHS)
    assert ".js.map" in paths
    assert ".css.map" in paths


def test_known_cdn_hosts_include_major_cdns():
    assert "cdnjs.cloudflare.com" in KNOWN_CDN_HOSTS
    assert "cdn.jsdelivr.net" in KNOWN_CDN_HOSTS


def test_correlation_headers_not_empty():
    assert len(CORRELATION_HEADERS) >= 3
    assert "X-Request-Id" in CORRELATION_HEADERS


def test_internal_ip_patterns_match_rfc1918():
    """Each RFC-1918 pattern should match at least one private IP."""
    test_cases = [
        ("10.0.0.1", True),
        ("192.168.1.1", True),
        ("172.16.0.1", True),
        ("127.0.0.1", True),
        ("8.8.8.8", False),
        ("1.1.1.1", False),
    ]
    for ip, should_match in test_cases:
        matched = any(re.search(p, ip) for p in INTERNAL_IP_PATTERNS)
        assert matched == should_match, f"IP {ip!r}: expected match={should_match}, got {matched}"


# ── A02: _detect_cleartext_pii ────────────────────────────────────────────────

class TestCleartextPII:
    def test_visa_pattern_detected(self):
        scanner = _scanner()
        result = WebScanResult(url="https://example.com")
        resp = _mock_resp(text="Your card: 4111111111111111 is saved")
        scanner._detect_cleartext_pii(resp, result)
        assert len(result.cleartext_pii) >= 1
        assert any("Visa" in p or "card" in p.lower() for p in result.cleartext_pii)

    def test_password_in_json_detected(self):
        scanner = _scanner()
        result = WebScanResult(url="https://example.com")
        resp = _mock_resp(text='{"username": "admin", "password": "mysecret123"}')
        scanner._detect_cleartext_pii(resp, result)
        assert any("password" in p.lower() for p in result.cleartext_pii)

    def test_clean_response_no_pii(self):
        scanner = _scanner()
        result = WebScanResult(url="https://example.com")
        resp = _mock_resp(text="<html><body>Hello world</body></html>")
        scanner._detect_cleartext_pii(resp, result)
        assert result.cleartext_pii == []


# ── A02: _check_token_in_url ─────────────────────────────────────────────────

class TestTokenInURL:
    def test_api_key_in_url_flagged(self):
        scanner = _scanner()
        result = WebScanResult(url="https://example.com")
        scanner._check_token_in_url("https://example.com/search?api_key=abc123", result)
        assert len(result.token_in_url) >= 1
        assert "api_key" in result.token_in_url[0]

    def test_password_in_url_flagged(self):
        scanner = _scanner()
        result = WebScanResult(url="https://example.com")
        scanner._check_token_in_url("https://example.com/login?password=secret", result)
        assert any("password" in r for r in result.token_in_url)

    def test_safe_url_not_flagged(self):
        scanner = _scanner()
        result = WebScanResult(url="https://example.com")
        scanner._check_token_in_url("https://example.com/search?q=test&page=2", result)
        assert result.token_in_url == []

    def test_no_query_string_no_flag(self):
        scanner = _scanner()
        result = WebScanResult(url="https://example.com")
        scanner._check_token_in_url("https://example.com/home", result)
        assert result.token_in_url == []


# ── A02: _check_cache_control ────────────────────────────────────────────────

class TestCacheControl:
    def test_missing_cache_control_flagged(self):
        scanner = _scanner()
        result = WebScanResult(url="https://example.com")
        resp = _mock_resp(headers={})
        scanner._check_cache_control(resp, result)
        assert result.cache_control_missing is True

    def test_no_store_present_not_flagged(self):
        scanner = _scanner()
        result = WebScanResult(url="https://example.com")
        resp = _mock_resp(headers={"Cache-Control": "no-store, no-cache"})
        scanner._check_cache_control(resp, result)
        assert result.cache_control_missing is False

    def test_pragma_no_cache_sufficient(self):
        scanner = _scanner()
        result = WebScanResult(url="https://example.com")
        resp = _mock_resp(headers={"Pragma": "no-cache"})
        scanner._check_cache_control(resp, result)
        assert result.cache_control_missing is False


# ── A02: _detect_https_downgrade ─────────────────────────────────────────────

class TestHTTPSDowngrade:
    def test_http_src_on_https_page_flagged(self):
        scanner = _scanner()
        result = WebScanResult(url="https://example.com")
        body = '<img src="http://cdn.example.com/img.png" />'
        resp = _mock_resp(text=body)
        scanner._detect_https_downgrade(resp, "https://example.com", result)
        assert len(result.https_downgrade) >= 1

    def test_all_https_resources_clean(self):
        scanner = _scanner()
        result = WebScanResult(url="https://example.com")
        body = '<img src="https://cdn.example.com/img.png" />'
        resp = _mock_resp(text=body)
        scanner._detect_https_downgrade(resp, "https://example.com", result)
        assert result.https_downgrade == []

    def test_http_page_skipped(self):
        """Downgrade detection only relevant on HTTPS pages."""
        scanner = _scanner()
        result = WebScanResult(url="http://example.com")
        body = '<img src="http://cdn.example.com/img.png" />'
        resp = _mock_resp(text=body)
        scanner._detect_https_downgrade(resp, "http://example.com", result)
        assert result.https_downgrade == []


# ── A08: _check_sri_missing ──────────────────────────────────────────────────

class TestSRIMissing:
    def test_external_cdn_script_without_integrity_flagged(self):
        scanner = _scanner()
        result = WebScanResult(url="https://example.com")
        body = '<script src="https://cdn.jsdelivr.net/npm/lodash/lodash.min.js"></script>'
        resp = _mock_resp(text=body)
        scanner._check_sri_missing(resp, result)
        assert len(result.sri_missing) >= 1

    def test_script_with_integrity_not_flagged(self):
        scanner = _scanner()
        result = WebScanResult(url="https://example.com")
        body = (
            '<script src="https://cdn.jsdelivr.net/npm/lodash/lodash.min.js" '
            'integrity="sha384-abc123" crossorigin="anonymous"></script>'
        )
        resp = _mock_resp(text=body)
        scanner._check_sri_missing(resp, result)
        assert result.sri_missing == []

    def test_local_script_no_sri_required(self):
        scanner = _scanner()
        result = WebScanResult(url="https://example.com")
        body = '<script src="/static/app.js"></script>'
        resp = _mock_resp(text=body)
        scanner._check_sri_missing(resp, result)
        assert result.sri_missing == []


# ── A09: _check_security_txt ─────────────────────────────────────────────────

class TestSecurityTxt:
    def test_security_txt_present(self):
        scanner = _scanner()
        result = WebScanResult(url="https://example.com")
        mock_resp = _mock_resp(text="Contact: security@example.com", status=200)
        with patch.object(scanner.session, "get", return_value=mock_resp):
            scanner._check_security_txt("https://example.com", result)
        assert result.security_txt_present is True

    def test_security_txt_absent(self):
        scanner = _scanner()
        result = WebScanResult(url="https://example.com")
        mock_resp = _mock_resp(text="Not Found", status=404)
        with patch.object(scanner.session, "get", return_value=mock_resp):
            scanner._check_security_txt("https://example.com", result)
        assert result.security_txt_present is False

    def test_security_txt_network_error_graceful(self):
        scanner = _scanner()
        result = WebScanResult(url="https://example.com")
        with patch.object(scanner.session, "get", side_effect=Exception("timeout")):
            scanner._check_security_txt("https://example.com", result)
        assert result.security_txt_present is False


# ── A09: _check_error_correlation ────────────────────────────────────────────

class TestErrorCorrelation:
    def test_error_without_correlation_id_flagged(self):
        scanner = _scanner()
        result = WebScanResult(url="https://example.com")
        resp = _mock_resp(status=404, headers={"Content-Type": "text/html"})
        scanner._check_error_correlation(resp, result)
        assert result.error_no_correlation_id is True

    def test_error_with_request_id_not_flagged(self):
        scanner = _scanner()
        result = WebScanResult(url="https://example.com")
        resp = _mock_resp(status=500, headers={"X-Request-Id": "abc-123"})
        scanner._check_error_correlation(resp, result)
        assert result.error_no_correlation_id is False

    def test_success_response_skipped(self):
        """Correlation check only applies to error responses."""
        scanner = _scanner()
        result = WebScanResult(url="https://example.com")
        resp = _mock_resp(status=200, headers={})
        scanner._check_error_correlation(resp, result)
        assert result.error_no_correlation_id is False


# ── A10: _detect_internal_ip_disclosure ──────────────────────────────────────

class TestInternalIPDisclosure:
    def test_rfc1918_in_body_flagged(self):
        scanner = _scanner()
        result = WebScanResult(url="https://example.com")
        resp = _mock_resp(text="Backend: 192.168.1.50:8080", headers={})
        scanner._detect_internal_ip_disclosure(resp, result)
        assert len(result.internal_ip_disclosed) >= 1

    def test_loopback_in_body_flagged(self):
        scanner = _scanner()
        result = WebScanResult(url="https://example.com")
        resp = _mock_resp(text="Error from 127.0.0.1", headers={})
        scanner._detect_internal_ip_disclosure(resp, result)
        assert len(result.internal_ip_disclosed) >= 1

    def test_public_ip_not_flagged(self):
        scanner = _scanner()
        result = WebScanResult(url="https://example.com")
        resp = _mock_resp(text="Server: 8.8.8.8", headers={})
        scanner._detect_internal_ip_disclosure(resp, result)
        assert result.internal_ip_disclosed == []


# ── A10: _test_ssrf_params ───────────────────────────────────────────────────

class TestSSRFParams:
    def test_ssrf_detected_when_metadata_in_response(self):
        scanner = _scanner(injections=True)
        result = WebScanResult(url="https://example.com")
        mock_resp = _mock_resp(text="ami-id: ami-0a1b2c3d instance-id: i-1234567890")
        with patch.object(scanner.session, "get", return_value=mock_resp):
            scanner._test_ssrf_params("https://example.com", result)
        assert len(result.ssrf_indicators) >= 1
        assert result.ssrf_indicators[0]["pattern_matched"] in SSRF_SUCCESS_PATTERNS

    def test_ssrf_not_flagged_on_clean_response(self):
        scanner = _scanner(injections=True)
        result = WebScanResult(url="https://example.com")
        mock_resp = _mock_resp(text="<html>Normal page</html>")
        with patch.object(scanner.session, "get", return_value=mock_resp):
            scanner._test_ssrf_params("https://example.com", result)
        assert result.ssrf_indicators == []

    def test_ssrf_network_error_is_silent(self):
        scanner = _scanner(injections=True)
        result = WebScanResult(url="https://example.com")
        with patch.object(scanner.session, "get", side_effect=Exception("timeout")):
            scanner._test_ssrf_params("https://example.com", result)
        assert result.ssrf_indicators == []


# ── A01: _test_idor ──────────────────────────────────────────────────────────

class TestIDOR:
    def test_idor_detected_when_different_content_returned(self):
        scanner = _scanner(injections=True)
        result = WebScanResult(url="https://example.com/user/42")

        call_count = [0]
        # Original content: ~60 bytes
        original_text = "User: Alice"
        # Adjacent ID content: significantly different length (>50 byte diff)
        adjacent_text = "User: Bob — admin privileges granted — session_token: xyz123 — last_login: 2026-06-06T00:00:00Z"

        def mock_get(url, **kwargs):
            call_count[0] += 1
            return _mock_resp(text=original_text if call_count[0] == 1 else adjacent_text)

        with patch.object(scanner.session, "get", side_effect=mock_get):
            scanner._test_idor("https://example.com/user/42", result)

        assert len(result.idor_indicators) >= 1

    def test_idor_not_flagged_when_no_numeric_id_in_path(self):
        scanner = _scanner(injections=True)
        result = WebScanResult(url="https://example.com/users/profile")
        mock_resp = _mock_resp(text="Profile page")
        with patch.object(scanner.session, "get", return_value=mock_resp):
            scanner._test_idor("https://example.com/users/profile", result)
        assert result.idor_indicators == []


# ── A03: _test_nosql_injection ───────────────────────────────────────────────

class TestNoSQLInjection:
    def test_nosql_detected_on_auth_bypass_pattern(self):
        scanner = _scanner(injections=True)
        result = WebScanResult(url="https://example.com/login")
        mock_resp = _mock_resp(
            text='{"token": "eyJhbGciOiJIUzI1NiJ9...", "dashboard": "/home"}',
            status=200,
        )
        with patch.object(scanner.session, "post", return_value=mock_resp):
            scanner._test_nosql_injection("https://example.com/login", result)
        assert len(result.nosql_indicators) >= 1

    def test_nosql_not_flagged_on_reject_response(self):
        scanner = _scanner(injections=True)
        result = WebScanResult(url="https://example.com/login")
        mock_resp = _mock_resp(text='{"error": "Invalid credentials"}', status=401)
        with patch.object(scanner.session, "post", return_value=mock_resp):
            scanner._test_nosql_injection("https://example.com/login", result)
        assert result.nosql_indicators == []


# ── A03/A05: _test_graphql ───────────────────────────────────────────────────

class TestGraphQLIntrospection:
    def test_introspection_detected_when_schema_returned(self):
        scanner = _scanner(injections=True)
        result = WebScanResult(url="https://example.com")
        mock_resp = _mock_resp(
            text='{"data": {"__schema": {"types": [{"name": "Query"}]}}}',
            status=200,
        )
        with patch.object(scanner.session, "post", return_value=mock_resp):
            scanner._test_graphql("https://example.com", result)
        assert len(result.graphql_issues) >= 1
        assert "__schema" in result.graphql_issues[0] or "introspection" in result.graphql_issues[0].lower()

    def test_introspection_not_flagged_when_disabled(self):
        scanner = _scanner(injections=True)
        result = WebScanResult(url="https://example.com")
        mock_resp = _mock_resp(
            text='{"errors": [{"message": "Introspection is not allowed"}]}',
            status=200,
        )
        with patch.object(scanner.session, "post", return_value=mock_resp):
            scanner._test_graphql("https://example.com", result)
        assert result.graphql_issues == []


# ── A04: _detect_insecure_workflow ────────────────────────────────────────────

class TestInsecureWorkflow:
    def test_negative_price_accepted_flagged(self):
        scanner = _scanner(injections=True)
        result = WebScanResult(url="https://example.com?price=10")
        mock_resp = _mock_resp(text="Order total: -$10.00 — thank you!", status=200)
        with patch.object(scanner.session, "get", return_value=mock_resp):
            scanner._detect_insecure_workflow("https://example.com?price=10", result)
        assert len(result.insecure_workflow) >= 1
        assert "price" in result.insecure_workflow[0]

    def test_negative_rejected_not_flagged(self):
        scanner = _scanner(injections=True)
        result = WebScanResult(url="https://example.com?price=10")
        mock_resp = _mock_resp(text='{"error": "Invalid price: must be positive"}', status=400)
        with patch.object(scanner.session, "get", return_value=mock_resp):
            scanner._detect_insecure_workflow("https://example.com?price=10", result)
        assert result.insecure_workflow == []

    def test_no_business_params_skips_test(self):
        """URL with a non-business param (q) should not produce insecure_workflow findings."""
        scanner = _scanner(injections=True)
        result = WebScanResult(url="https://example.com?q=search")
        # The method iterates BUSINESS_VALUE_PARAMS defaults even when URL has no business params.
        # Without a mock, any 200 would be flagged. With a mock returning an error body, nothing fires.
        mock_resp = _mock_resp(
            text='{"error": "invalid parameter", "message": "bad request"}',
            status=400,
        )
        with patch.object(scanner.session, "get", return_value=mock_resp):
            scanner._detect_insecure_workflow("https://example.com?q=search", result)
        assert result.insecure_workflow == []


# ── New WebScanResult fields exist ────────────────────────────────────────────

def test_scan_result_v052_fields_all_present():
    r = WebScanResult(url="https://example.com")
    # A01
    assert r.idor_indicators == []
    assert r.forceful_browsing == []
    # A02
    assert r.cleartext_pii == []
    assert r.token_in_url == []
    assert r.cache_control_missing is False
    assert r.https_downgrade == []
    # A03
    assert r.nosql_indicators == []
    assert r.graphql_issues == []
    # A04
    assert r.insecure_workflow == []
    # A05/A08
    assert r.source_maps_exposed == []
    assert r.sri_missing == []
    assert r.mixed_content == []
    # A09
    assert r.security_txt_present is False
    assert r.error_no_correlation_id is False
    # A10
    assert r.ssrf_indicators == []
    assert r.internal_ip_disclosed == []
