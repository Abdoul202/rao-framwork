"""Unit tests for SSLAnalyzer — mocked socket/ssl, no real network required.

Coverage:
    - SSLResult dataclass properties
    - Hostname matching (exact, wildcard, SAN, case)
    - _compile_findings: all finding types (weak proto, cipher, cert issues, HSTS, Heartbleed)
    - _check_hsts: present / missing / parse failure
    - _check_heartbleed_indicator: with/without legacy TLS
    - _connect_with_protocol: success / SSLError / ConnectionRefused
    - _probe_protocols: integration with mock
    - analyze(): end-to-end with fully mocked sub-methods
"""

from __future__ import annotations

import ssl
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from rao.tools.ssl_analyzer import (
    HSTS_MIN_AGE_SECONDS,
    CertInfo,
    SSLAnalyzer,
    SSLResult,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_pem_cert(
    subject: str = "example.com",
    issuer: str = "Let's Encrypt Authority X3",
    san: list[tuple[str, str]] | None = None,
    days_until_expiry: int = 90,
    expired: bool = False,
) -> dict:
    """Return a fake pem_cert dict as returned by SSLSocket.getpeercert()."""
    now = datetime.now(tz=timezone.utc)
    if expired:
        not_after = now - timedelta(days=10)
    else:
        not_after = now + timedelta(days=days_until_expiry)

    return {
        "subject": [[("commonName", subject)]],
        "issuer": [[("commonName", issuer)]],
        "subjectAltName": san or [("DNS", subject)],
        "notBefore": now.strftime("%b %d %H:%M:%S %Y GMT"),
        "notAfter": not_after.strftime("%b %d %H:%M:%S %Y GMT"),
    }


# ── SSLResult dataclass ────────────────────────────────────────────────────────

class TestSSLResult:
    def test_is_ok_clean(self):
        r = SSLResult(host="example.com", port=443)
        assert r.is_ok is True

    def test_is_ok_with_error(self):
        r = SSLResult(host="example.com", port=443, error="connection refused")
        assert r.is_ok is False

    def test_default_lists_empty(self):
        r = SSLResult(host="h", port=8443)
        assert r.supported_protocols == []
        assert r.weak_protocols == []
        assert r.weak_ciphers_detected == []
        assert r.findings == []

    def test_default_flags_false(self):
        r = SSLResult(host="h", port=443)
        assert r.hsts_present is False
        assert r.heartbleed_indicator is False

    def test_host_port_stored(self):
        r = SSLResult(host="myhost", port=8443)
        assert r.host == "myhost"
        assert r.port == 8443


# ── Hostname matching ─────────────────────────────────────────────────────────

class TestHostnameMatching:
    def setup_method(self):
        self.a = SSLAnalyzer()

    def test_exact_cn_match(self):
        cert = CertInfo(subject="example.com", san=[])
        assert self.a._hostname_matches("example.com", cert) is True

    def test_exact_san_match(self):
        cert = CertInfo(subject="other.com", san=["example.com", "www.example.com"])
        assert self.a._hostname_matches("www.example.com", cert) is True

    def test_wildcard_match_subdomain(self):
        cert = CertInfo(subject="*.example.com", san=["*.example.com"])
        assert self.a._hostname_matches("api.example.com", cert) is True

    def test_wildcard_no_match_two_levels(self):
        cert = CertInfo(subject="*.example.com", san=["*.example.com"])
        # deep.sub.example.com should NOT match *.example.com
        assert self.a._hostname_matches("deep.sub.example.com", cert) is False

    def test_no_match_different_domain(self):
        cert = CertInfo(subject="other.com", san=["other.com"])
        assert self.a._hostname_matches("example.com", cert) is False

    def test_case_insensitive_san(self):
        cert = CertInfo(subject="EXAMPLE.COM", san=["EXAMPLE.COM"])
        assert self.a._hostname_matches("example.com", cert) is True

    def test_empty_san_falls_back_to_subject(self):
        cert = CertInfo(subject="example.com", san=[])
        assert self.a._hostname_matches("example.com", cert) is True


# ── _compile_findings ─────────────────────────────────────────────────────────

class TestCompileFindings:
    def setup_method(self):
        self.a = SSLAnalyzer()

    def _fresh(self, **kwargs) -> SSLResult:
        return SSLResult(host="h", port=443, **kwargs)

    # Weak protocols
    def test_weak_protocol_tls10_is_high(self):
        r = self._fresh()
        r.weak_protocols = ["TLSv1.0"]
        self.a._compile_findings(r)
        assert any(f["severity"] == "high" and "TLSv1.0" in f["title"] for f in r.findings)

    def test_weak_protocol_tls11_is_high(self):
        r = self._fresh()
        r.weak_protocols = ["TLSv1.1"]
        self.a._compile_findings(r)
        assert any("TLSv1.1" in f["title"] for f in r.findings)

    def test_multiple_weak_protocols_all_flagged(self):
        r = self._fresh()
        r.weak_protocols = ["TLSv1.0", "TLSv1.1"]
        self.a._compile_findings(r)
        titles = [f["title"] for f in r.findings]
        assert any("TLSv1.0" in t for t in titles)
        assert any("TLSv1.1" in t for t in titles)

    # Weak ciphers
    def test_weak_cipher_is_high(self):
        r = self._fresh()
        r.weak_ciphers_detected = ["RC4-SHA"]
        self.a._compile_findings(r)
        assert any(f["severity"] == "high" and "RC4-SHA" in f["title"] for f in r.findings)

    # Certificate expiry
    def test_expired_cert_is_critical(self):
        r = self._fresh()
        r.cert.is_expired = True
        r.cert.days_until_expiry = -5
        self.a._compile_findings(r)
        assert any(f["severity"] == "critical" for f in r.findings)

    def test_expiring_in_15_days_is_medium(self):
        r = self._fresh()
        r.cert.is_expired = False
        r.cert.days_until_expiry = 15
        self.a._compile_findings(r)
        assert any(f["severity"] == "medium" for f in r.findings)

    def test_expiring_in_31_days_no_expiry_finding(self):
        """31 days is outside the ≤30 warning window."""
        r = self._fresh()
        r.cert.is_expired = False
        r.cert.days_until_expiry = 31
        r.hsts_present = True
        r.hsts_max_age = HSTS_MIN_AGE_SECONDS + 1
        self.a._compile_findings(r)
        expiry_findings = [f for f in r.findings if "expir" in f["title"].lower()]
        assert expiry_findings == []

    # Self-signed
    def test_self_signed_is_high(self):
        r = self._fresh()
        r.cert.is_self_signed = True
        self.a._compile_findings(r)
        assert any("Self-signed" in f["title"] and f["severity"] == "high" for f in r.findings)

    # Hostname mismatch
    def test_hostname_mismatch_is_high(self):
        r = self._fresh()
        r.cert.hostname_mismatch = True
        self.a._compile_findings(r)
        assert any("mismatch" in f["title"].lower() and f["severity"] == "high" for f in r.findings)

    # HSTS
    def test_missing_hsts_is_medium(self):
        r = self._fresh()
        r.hsts_present = False
        self.a._compile_findings(r)
        assert any("HSTS" in f["title"] and f["severity"] == "medium" for f in r.findings)

    def test_short_hsts_max_age_is_low(self):
        r = self._fresh()
        r.hsts_present = True
        r.hsts_max_age = 3600  # 1 hour — below 6-month minimum
        self.a._compile_findings(r)
        assert any(f["severity"] == "low" and "max-age" in f["title"].lower() for f in r.findings)

    def test_adequate_hsts_no_hsts_finding(self):
        r = self._fresh()
        r.hsts_present = True
        r.hsts_max_age = HSTS_MIN_AGE_SECONDS + 1
        self.a._compile_findings(r)
        hsts_findings = [f for f in r.findings if "HSTS" in f["title"]]
        assert hsts_findings == []

    # Heartbleed
    def test_heartbleed_indicator_is_info(self):
        r = self._fresh()
        r.heartbleed_indicator = True
        self.a._compile_findings(r)
        assert any(f["severity"] == "info" and "Heartbleed" in f["title"] for f in r.findings)

    # Clean result
    def test_completely_clean_result_no_findings(self):
        r = self._fresh()
        r.hsts_present = True
        r.hsts_max_age = HSTS_MIN_AGE_SECONDS + 1
        self.a._compile_findings(r)
        assert r.findings == []

    # Finding structure
    def test_finding_has_required_keys(self):
        r = self._fresh()
        r.weak_protocols = ["TLSv1.0"]
        self.a._compile_findings(r)
        f = r.findings[0]
        assert "severity" in f
        assert "title" in f
        assert "detail" in f


# ── _check_hsts ───────────────────────────────────────────────────────────────

class TestCheckHSTS:
    def setup_method(self):
        self.a = SSLAnalyzer()

    def test_hsts_present_and_parsed(self):
        r = SSLResult(host="example.com", port=443)
        mock_resp = MagicMock()
        mock_resp.headers = {"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}
        with patch("requests.get", return_value=mock_resp):
            self.a._check_hsts("example.com", 443, r)
        assert r.hsts_present is True
        assert r.hsts_max_age == 31536000

    def test_hsts_header_absent(self):
        r = SSLResult(host="example.com", port=443)
        mock_resp = MagicMock()
        mock_resp.headers = {}
        with patch("requests.get", return_value=mock_resp):
            self.a._check_hsts("example.com", 443, r)
        assert r.hsts_present is False
        assert r.hsts_max_age == 0

    def test_hsts_malformed_max_age_does_not_crash(self):
        r = SSLResult(host="example.com", port=443)
        mock_resp = MagicMock()
        mock_resp.headers = {"Strict-Transport-Security": "max-age=INVALID"}
        with patch("requests.get", return_value=mock_resp):
            self.a._check_hsts("example.com", 443, r)
        assert r.hsts_present is True
        assert r.hsts_max_age == 0  # parse failure → 0

    def test_hsts_network_failure_is_silent(self):
        r = SSLResult(host="example.com", port=443)
        with patch("requests.get", side_effect=Exception("timeout")):
            self.a._check_hsts("example.com", 443, r)
        assert r.hsts_present is False


# ── _check_heartbleed_indicator ───────────────────────────────────────────────

class TestHeartbleedIndicator:
    def setup_method(self):
        self.a = SSLAnalyzer()

    def test_flagged_with_tlsv10(self):
        r = SSLResult(host="h", port=443)
        r.weak_protocols = ["TLSv1.0"]
        self.a._check_heartbleed_indicator("h", 443, r)
        assert r.heartbleed_indicator is True

    def test_flagged_with_tlsv11(self):
        r = SSLResult(host="h", port=443)
        r.weak_protocols = ["TLSv1.1"]
        self.a._check_heartbleed_indicator("h", 443, r)
        assert r.heartbleed_indicator is True

    def test_not_flagged_with_modern_tls_only(self):
        r = SSLResult(host="h", port=443)
        r.weak_protocols = []
        self.a._check_heartbleed_indicator("h", 443, r)
        assert r.heartbleed_indicator is False

    def test_not_flagged_empty_weak_protocols(self):
        r = SSLResult(host="h", port=443)
        self.a._check_heartbleed_indicator("h", 443, r)
        assert r.heartbleed_indicator is False


# ── _connect_with_protocol ────────────────────────────────────────────────────

class TestConnectWithProtocol:
    def setup_method(self):
        self.a = SSLAnalyzer(timeout=5)

    def test_returns_true_on_successful_connection(self):
        mock_ctx = MagicMock()
        mock_ssock = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
        mock_sock = MagicMock()

        with patch("ssl.SSLContext", return_value=mock_ctx):
            with patch("socket.create_connection") as mc:
                mc.return_value.__enter__ = MagicMock(return_value=mock_sock)
                mc.return_value.__exit__ = MagicMock(return_value=False)
                result = self.a._connect_with_protocol("host", 443, 2)

        assert result is True

    def test_returns_false_on_ssl_error(self):
        with patch("ssl.SSLContext"):
            with patch("socket.create_connection", side_effect=ssl.SSLError("alert handshake failure")):
                result = self.a._connect_with_protocol("host", 443, 2)
        assert result is False

    def test_returns_false_on_connection_refused(self):
        with patch("ssl.SSLContext"):
            with patch("socket.create_connection", side_effect=ConnectionRefusedError()):
                result = self.a._connect_with_protocol("host", 443, 2)
        assert result is False

    def test_returns_false_on_timeout(self):
        with patch("ssl.SSLContext"):
            with patch("socket.create_connection", side_effect=TimeoutError("timed out")):
                result = self.a._connect_with_protocol("host", 443, 2)
        assert result is False


# ── analyze() integration (fully mocked sub-methods) ─────────────────────────

class TestAnalyzeIntegration:
    def setup_method(self):
        self.a = SSLAnalyzer(timeout=5)

    def _mock_analyze(self, setup_result=None):
        """Run analyze() with all sub-methods mocked."""
        def noop(*args, **kwargs):
            pass

        def set_good_hsts(h, p, r):
            r.hsts_present = True
            r.hsts_max_age = HSTS_MIN_AGE_SECONDS + 1

        with patch.object(self.a, "_probe_protocols", side_effect=noop):
            with patch.object(self.a, "_inspect_certificate", side_effect=noop):
                with patch.object(self.a, "_check_hsts", side_effect=set_good_hsts):
                    with patch.object(self.a, "_check_heartbleed_indicator", side_effect=noop):
                        if setup_result:
                            setup_result(self.a)
                        return self.a.analyze("example.com", 443)

    def test_returns_ssl_result_instance(self):
        r = self._mock_analyze()
        assert isinstance(r, SSLResult)

    def test_host_and_port_correct(self):
        r = self._mock_analyze()
        assert r.host == "example.com"
        assert r.port == 443

    def test_clean_mock_server_no_findings(self):
        r = self._mock_analyze()
        assert r.findings == []
        assert r.is_ok is True

    def test_weak_protocol_propagates_to_findings(self):
        def add_weak(h, p, r):
            r.weak_protocols = ["TLSv1.0"]

        with patch.object(self.a, "_probe_protocols", side_effect=add_weak):
            with patch.object(self.a, "_inspect_certificate"):
                with patch.object(self.a, "_check_hsts"):
                    with patch.object(self.a, "_check_heartbleed_indicator"):
                        r = self.a.analyze("example.com", 443)

        assert any("TLSv1.0" in f["title"] for f in r.findings)

    def test_default_port_is_443(self):
        with patch.object(self.a, "_probe_protocols"):
            with patch.object(self.a, "_inspect_certificate"):
                with patch.object(self.a, "_check_hsts"):
                    with patch.object(self.a, "_check_heartbleed_indicator"):
                        r = self.a.analyze("example.com")
        assert r.port == 443
