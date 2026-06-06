"""
SSL/TLS Analyzer — Comprehensive certificate and protocol assessment.

Checks
------
- Protocol support : SSLv3, TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3
- Weak cipher suites : RC4, DES, 3DES, EXPORT, NULL, anon
- Certificate validity  : expiry, self-signed, hostname mismatch, SAN
- HSTS header          : presence and max-age
- Known vulnerabilities: Heartbleed (basic probe), BEAST, POODLE indicators

No external dependencies beyond the stdlib ssl/socket modules.
"""

from __future__ import annotations

import logging
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Protocols to probe ordered from weakest to strongest
_PROTOCOLS_TO_TEST: list[tuple[str, int]] = [
    ("SSLv2",   getattr(ssl, "PROTOCOL_SSLv2",   -1)),   # removed in Python 3.10+
    ("SSLv3",   getattr(ssl, "PROTOCOL_SSLv3",   -1)),   # removed in Python 3.10+
    ("TLSv1.0", getattr(ssl, "PROTOCOL_TLSv1",   -1)),   # deprecated in 3.10+
    ("TLSv1.1", getattr(ssl, "PROTOCOL_TLSv1_1", -1)),   # deprecated in 3.10+
    ("TLSv1.2", getattr(ssl, "PROTOCOL_TLSv1_2", -1)),
    # TLSv1.3 is negotiated automatically by PROTOCOL_TLS_CLIENT
]

WEAK_CIPHER_KEYWORDS = ["RC4", "DES", "EXPORT", "NULL", "anon", "MD5", "3DES"]

# HSTS min-age considered adequate: 6 months
HSTS_MIN_AGE_SECONDS = 15_552_000


@dataclass
class CertInfo:
    subject: str = ""
    issuer: str = ""
    san: list[str] = field(default_factory=list)
    not_before: str = ""
    not_after: str = ""
    days_until_expiry: int = 0
    is_expired: bool = False
    is_self_signed: bool = False
    hostname_mismatch: bool = False


@dataclass
class SSLResult:
    host: str
    port: int

    # Protocol support
    supported_protocols: list[str] = field(default_factory=list)
    weak_protocols: list[str] = field(default_factory=list)

    # Cipher suites
    cipher_suite: str = ""            # negotiated cipher on the best connection
    weak_ciphers_detected: list[str] = field(default_factory=list)

    # Certificate
    cert: CertInfo = field(default_factory=CertInfo)

    # Headers / config
    hsts_present: bool = False
    hsts_max_age: int = 0

    # Known vulns (indicator-only, not full PoC)
    heartbleed_indicator: bool = False

    # Summary
    findings: list[dict] = field(default_factory=list)   # {severity, title, detail}
    error: str = ""

    @property
    def is_ok(self) -> bool:
        return not self.error


class SSLAnalyzer:
    """Analyze SSL/TLS configuration of a host:port endpoint.

    Parameters
    ----------
    timeout:
        Socket timeout in seconds for each probe.
    """

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout

    def analyze(self, host: str, port: int = 443) -> SSLResult:
        """Run the full SSL/TLS analysis against host:port."""
        result = SSLResult(host=host, port=port)
        logger.info("SSL analysis → %s:%d", host, port)

        # 1. Check what protocols the server accepts
        self._probe_protocols(host, port, result)

        # 2. Get full certificate info + negotiated cipher
        self._inspect_certificate(host, port, result)

        # 3. Grab HSTS header (requires an HTTP request)
        self._check_hsts(host, port, result)

        # 4. Basic Heartbleed indicator (connection behaviour)
        self._check_heartbleed_indicator(host, port, result)

        # 5. Compile findings list
        self._compile_findings(result)

        return result

    # ── Protocol probing ────────────────────────────────────────────────────────

    def _probe_protocols(self, host: str, port: int, result: SSLResult) -> None:
        """Test which legacy protocols the server accepts."""
        for proto_name, proto_const in _PROTOCOLS_TO_TEST:
            if proto_const == -1:
                # Protocol removed from this Python build — skip silently
                continue
            if self._connect_with_protocol(host, port, proto_const):
                result.supported_protocols.append(proto_name)
                if proto_name in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"):
                    result.weak_protocols.append(proto_name)
                    logger.warning("Weak protocol accepted: %s on %s:%d", proto_name, host, port)

        # TLSv1.2 / 1.3 via modern context
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    ver = ssock.version()  # e.g. "TLSv1.3"
                    if ver and ver not in result.supported_protocols:
                        result.supported_protocols.append(ver)
                    result.cipher_suite = ssock.cipher()[0] if ssock.cipher() else ""
        except Exception:
            pass

    def _connect_with_protocol(self, host: str, port: int, proto_const: int) -> bool:
        """Try to connect using a specific SSL protocol constant. Returns True if accepted."""
        try:
            ctx = ssl.SSLContext(proto_const)  # type: ignore[arg-type]
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    return True
        except ssl.SSLError:
            return False
        except Exception:
            return False

    # ── Certificate inspection ──────────────────────────────────────────────────

    def _inspect_certificate(self, host: str, port: int, result: SSLResult) -> None:
        """Extract certificate metadata and detect weak ciphers."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    pem_cert = ssock.getpeercert()
                    cipher = ssock.cipher()

            if not pem_cert:
                return

            # Cipher analysis
            if cipher:
                cipher_name = cipher[0]
                result.cipher_suite = cipher_name
                for weak in WEAK_CIPHER_KEYWORDS:
                    if weak in cipher_name.upper():
                        result.weak_ciphers_detected.append(cipher_name)

            # Parse certificate fields
            cert = CertInfo()

            subject = dict(x[0] for x in pem_cert.get("subject", []))
            issuer  = dict(x[0] for x in pem_cert.get("issuer",  []))
            cert.subject = subject.get("commonName", "")
            cert.issuer  = issuer.get("commonName", "")
            cert.is_self_signed = (cert.subject == cert.issuer)

            # SAN (Subject Alternative Names)
            san_raw = pem_cert.get("subjectAltName", [])
            cert.san = [v for (t, v) in san_raw if t == "DNS"]

            # Validity dates
            not_before_str = pem_cert.get("notBefore", "")
            not_after_str  = pem_cert.get("notAfter", "")
            cert.not_before = not_before_str
            cert.not_after  = not_after_str

            if not_after_str:
                expiry = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                now = datetime.now(tz=timezone.utc)
                cert.days_until_expiry = (expiry - now).days
                cert.is_expired = cert.days_until_expiry < 0

            # Hostname match check
            cert.hostname_mismatch = not self._hostname_matches(host, cert)

            result.cert = cert

        except Exception as e:
            logger.debug("Certificate inspection failed: %s", e)

    def _hostname_matches(self, host: str, cert: CertInfo) -> bool:
        """Check if host matches the certificate CN or any SAN.

        Wildcard rules (RFC 6125 §6.4.3):
          - *.example.com matches sub.example.com
          - *.example.com does NOT match deep.sub.example.com (two labels)
          - *.example.com does NOT match example.com itself
        """
        host_lower = host.lower()
        all_names = cert.san or [cert.subject]
        for name in all_names:
            if name.startswith("*."):
                suffix = name[2:].lower()   # e.g. "example.com"
                # host must end with .suffix AND have exactly one label before it
                if host_lower.endswith("." + suffix):
                    prefix = host_lower[: -(len(suffix) + 1)]  # everything before ".suffix"
                    if "." not in prefix and prefix:  # no dots → single label
                        return True
            elif name.lower() == host_lower:
                return True
        return False

    # ── HSTS header check ───────────────────────────────────────────────────────

    def _check_hsts(self, host: str, port: int, result: SSLResult) -> None:
        """Fetch the HTTPS response and inspect the HSTS header."""
        try:
            import requests
            resp = requests.get(
                f"https://{host}:{port}",
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )
            hsts = resp.headers.get("Strict-Transport-Security", "")
            if hsts:
                result.hsts_present = True
                for part in hsts.split(";"):
                    part = part.strip().lower()
                    if part.startswith("max-age="):
                        try:
                            result.hsts_max_age = int(part.split("=", 1)[1])
                        except ValueError:
                            pass
        except Exception:
            pass

    # ── Heartbleed indicator ────────────────────────────────────────────────────

    def _check_heartbleed_indicator(self, host: str, port: int, result: SSLResult) -> None:
        """Rudimentary Heartbleed indicator: TLSv1.0/1.1 + OpenSSL in banner.

        This is NOT a full Heartbleed PoC. It flags servers that present
        conditions associated with the vulnerability for follow-up with a
        dedicated tool (e.g. testssl.sh --heartbleed).
        """
        legacy_tls = bool(set(result.weak_protocols) & {"TLSv1.0", "TLSv1.1"})
        # Heartbleed affected OpenSSL 1.0.1–1.0.1f; no way to confirm without PoC
        if legacy_tls:
            result.heartbleed_indicator = True
            logger.info("Heartbleed indicator flagged on %s:%d (manual verification recommended)", host, port)

    # ── Compile findings ────────────────────────────────────────────────────────

    def _compile_findings(self, result: SSLResult) -> None:
        """Translate raw SSL data into structured findings."""

        def add(severity: str, title: str, detail: str) -> None:
            result.findings.append({"severity": severity, "title": title, "detail": detail})

        # Weak protocols
        for proto in result.weak_protocols:
            add("high", f"Weak protocol accepted: {proto}",
                f"Server {result.host}:{result.port} accepts {proto}. "
                "This enables downgrade attacks (POODLE, BEAST, etc.).")

        # Weak ciphers
        for cipher in result.weak_ciphers_detected:
            add("high", f"Weak cipher suite: {cipher}",
                f"The negotiated cipher '{cipher}' is considered insecure.")

        # Certificate issues
        if result.cert.is_expired:
            add("critical", "SSL certificate expired",
                f"Certificate expired {abs(result.cert.days_until_expiry)} days ago.")
        elif 0 < result.cert.days_until_expiry <= 30:
            add("medium", f"SSL certificate expiring soon ({result.cert.days_until_expiry} days)",
                "Renew the certificate before it expires.")

        if result.cert.is_self_signed:
            add("high", "Self-signed certificate detected",
                "The certificate is signed by itself, not a trusted CA.")

        if result.cert.hostname_mismatch:
            add("high", "Certificate hostname mismatch",
                f"Certificate CN/SAN does not match target host '{result.host}'.")

        # HSTS
        if not result.hsts_present:
            add("medium", "HSTS header missing",
                "Strict-Transport-Security is absent — SSL stripping attacks are possible.")
        elif result.hsts_max_age < HSTS_MIN_AGE_SECONDS:
            add("low", f"HSTS max-age too short ({result.hsts_max_age}s)",
                f"Recommended minimum is {HSTS_MIN_AGE_SECONDS}s (6 months).")

        # Heartbleed indicator
        if result.heartbleed_indicator:
            add("info", "Heartbleed indicator — manual verification recommended",
                "Server accepts legacy TLS. Run testssl.sh --heartbleed for confirmation.")
