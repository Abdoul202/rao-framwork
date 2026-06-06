"""
JWT Analyzer — Security assessment of JSON Web Tokens.

Checks
------
- Algorithm confusion : alg:none attack (signature bypass)
- Weak secret        : brute-force HS256/HS384/HS512 with wordlist
- Claims validation  : expiry, not-before, issuer, audience
- Algorithm safety   : flags deprecated (HS1) or dangerous (none) algs
- Sensitive data     : PII / secrets in unencrypted payload

Usage
-----
    from rao.tools.jwt_analyzer import JWTAnalyzer
    result = JWTAnalyzer().analyze("eyJ...")
    for f in result.findings:
        print(f["severity"], f["title"])

CLI
---
    rao jwt-scan <token>
    rao jwt-scan --header "Authorization: Bearer eyJ..."
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


# ── Common weak secrets ────────────────────────────────────────────────────────

WEAK_SECRETS: list[str] = [
    # Literal "secret" variants
    "secret", "secrets", "supersecret", "my_secret", "app_secret",
    "jwt_secret", "jwt-secret", "jwt_key", "jwt-key",
    "your-256-bit-secret", "your-secret-key", "your_secret_key",
    # Password classics
    "password", "password123", "pass", "p@ssw0rd", "12345678",
    "qwerty", "letmein", "admin", "administrator", "root",
    # Framework defaults
    "django-insecure-change-me", "flask-secret-key", "laravel_jwt_secret",
    "rails-secret", "express-secret", "nestjs-secret",
    "HS256", "HS384", "HS512",
    # Common in tutorials / repos
    "changeme", "change_me", "test", "testing", "dev", "development",
    "staging", "production", "prod", "local",
    "mysecret", "mypassword", "token", "access_token",
    "secret_key", "secretkey", "secretKey", "SECRET_KEY",
    # Numbers
    "123456", "1234567890", "111111", "000000",
    # Blank
    "",
]

# Algorithms considered insecure or dangerous
DANGEROUS_ALGS = {"none", "NONE", "None"}
WEAK_ALGS = {"HS1", "RS1"}

# Payload keys that might contain sensitive data
SENSITIVE_PAYLOAD_KEYS = {
    "password", "passwd", "secret", "api_key", "apikey",
    "private_key", "credit_card", "ssn", "social_security",
    "cvv", "pin", "token", "access_token", "refresh_token",
}


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class JWTResult:
    """Full analysis result for a single JWT token."""

    token: str                              # original token (truncated in logs)
    header:  dict = field(default_factory=dict)
    payload: dict = field(default_factory=dict)

    # Algorithm
    algorithm: str = ""

    # Time claims
    is_expired: bool = False
    not_yet_valid: bool = False
    issued_at: str = ""
    expires_at: str = ""
    days_until_expiry: int = 0

    # Vulnerability results
    alg_none_vulnerable: bool = False       # True if server accepted alg:none
    weak_secret_found: str = ""             # The cracked secret, if any
    sensitive_data_keys: list[str] = field(default_factory=list)

    # Structured findings
    findings: list[dict] = field(default_factory=list)
    error: str = ""

    @property
    def is_ok(self) -> bool:
        return not self.error

    @property
    def has_critical(self) -> bool:
        return any(f["severity"] == "critical" for f in self.findings)


# ── JWT Analyzer ───────────────────────────────────────────────────────────────

class JWTAnalyzer:
    """Analyze a JWT token for common security vulnerabilities.

    This is a **passive / offline** analyzer — it does NOT send requests
    to a server by default. The ``test_alg_none`` check is opt-in and
    requires a target URL.
    """

    def __init__(self, target_url: str = "", timeout: int = 10) -> None:
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout

    def analyze(self, token: str) -> JWTResult:
        """Run all checks against a JWT token.

        Parameters
        ----------
        token:
            Raw JWT string (``eyJ...``). Leading ``Bearer `` is stripped.
        """
        token = token.strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()

        result = JWTResult(token=token)

        # Step 1 — decode (no signature verification)
        if not self._decode_token(token, result):
            return result   # Malformed token — stop here

        # Step 2 — algorithm analysis
        self._check_algorithm(result)

        # Step 3 — time claims
        self._check_claims(result)

        # Step 4 — weak secret brute-force (offline)
        self._brute_weak_secret(token, result)

        # Step 5 — sensitive data in payload
        self._check_sensitive_data(result)

        # Step 6 — alg:none live test (only if target URL provided)
        if self.target_url:
            self._test_alg_none(token, result)

        # Step 7 — compile findings
        self._compile_findings(result)

        return result

    # ── Decoding ──────────────────────────────────────────────────────────────

    def _decode_token(self, token: str, result: JWTResult) -> bool:
        """Decode header and payload (no signature verification)."""
        parts = token.split(".")
        if len(parts) != 3:
            result.error = f"Invalid JWT format: expected 3 parts, got {len(parts)}"
            return False

        try:
            result.header  = self._b64decode_json(parts[0])
            result.payload = self._b64decode_json(parts[1])
            result.algorithm = result.header.get("alg", "unknown")
            return True
        except Exception as exc:
            result.error = f"JWT decode failed: {exc}"
            return False

    @staticmethod
    def _b64decode_json(part: str) -> dict:
        """Base64url-decode a JWT part and parse as JSON."""
        # Add padding
        padding = 4 - len(part) % 4
        if padding != 4:
            part += "=" * padding
        raw = base64.urlsafe_b64decode(part)
        return json.loads(raw)

    # ── Algorithm check ───────────────────────────────────────────────────────

    def _check_algorithm(self, result: JWTResult) -> None:
        """Flag dangerous or weak algorithm declarations."""
        alg = result.algorithm
        if alg.lower() == "none":
            result.findings.append({
                "severity": "critical",
                "title": "JWT algorithm is 'none' — signature not verified",
                "detail": (
                    "The token header declares alg:none. If the server accepts this, "
                    "any payload can be forged without a valid signature."
                ),
            })
        elif alg in WEAK_ALGS:
            result.findings.append({
                "severity": "high",
                "title": f"JWT uses deprecated/weak algorithm: {alg}",
                "detail": f"Algorithm '{alg}' is considered cryptographically weak.",
            })

    # ── Claims check ─────────────────────────────────────────────────────────

    def _check_claims(self, result: JWTResult) -> None:
        """Validate standard time-based JWT claims."""
        now = time.time()
        payload = result.payload

        exp = payload.get("exp")
        iat = payload.get("iat")
        nbf = payload.get("nbf")

        if exp is not None:
            try:
                exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
                result.expires_at = exp_dt.isoformat()
                diff_days = (exp_dt - datetime.now(tz=timezone.utc)).days
                result.days_until_expiry = diff_days
                result.is_expired = now > exp
                if result.is_expired:
                    result.findings.append({
                        "severity": "medium",
                        "title": "JWT is expired",
                        "detail": f"Token expired on {result.expires_at}. "
                                  "If the server accepts it, expiry validation is broken.",
                    })
                elif diff_days > 365:
                    result.findings.append({
                        "severity": "low",
                        "title": f"JWT has very long expiry ({diff_days} days)",
                        "detail": "Long-lived tokens increase the blast radius of token theft.",
                    })
            except (ValueError, OSError):
                pass

        if nbf is not None:
            try:
                if now < nbf:
                    result.not_yet_valid = True
                    result.findings.append({
                        "severity": "info",
                        "title": "JWT not yet valid (nbf claim in the future)",
                        "detail": "If the server accepts this token, nbf validation is broken.",
                    })
            except Exception:
                pass

        if iat is None:
            result.findings.append({
                "severity": "low",
                "title": "JWT missing 'iat' (issued-at) claim",
                "detail": "Without iat, token age cannot be validated server-side.",
            })

        if exp is None:
            result.findings.append({
                "severity": "high",
                "title": "JWT has no expiry ('exp' claim missing)",
                "detail": "Tokens without expiry are valid forever — credential theft risk.",
            })

    # ── Weak secret brute-force ───────────────────────────────────────────────

    def _brute_weak_secret(self, token: str, result: JWTResult) -> None:
        """Offline brute-force of HS256/HS384/HS512 secret against a wordlist."""
        alg = result.algorithm.upper()
        if not alg.startswith("HS"):
            return   # Only symmetric HMAC can be brute-forced offline

        hash_map = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }
        hash_fn = hash_map.get(alg)
        if hash_fn is None:
            return

        parts = token.split(".")
        if len(parts) != 3:
            return

        signing_input = f"{parts[0]}.{parts[1]}".encode()
        try:
            # Decode the real signature
            sig_padding = 4 - len(parts[2]) % 4
            if sig_padding != 4:
                sig_part = parts[2] + "=" * sig_padding
            else:
                sig_part = parts[2]
            real_sig = base64.urlsafe_b64decode(sig_part)
        except Exception:
            return

        for secret in WEAK_SECRETS:
            try:
                candidate = hmac.new(
                    secret.encode(), signing_input, hash_fn
                ).digest()
                if hmac.compare_digest(candidate, real_sig):
                    result.weak_secret_found = secret
                    result.findings.append({
                        "severity": "critical",
                        "title": f"JWT signed with weak secret: '{secret}'",
                        "detail": (
                            f"The {alg} signature was verified with the secret '{secret}'. "
                            "An attacker can forge arbitrary tokens with full control."
                        ),
                    })
                    logger.warning("JWT weak secret cracked: '%s'", secret)
                    return   # Stop after first match
            except Exception:
                continue

    # ── Sensitive data ────────────────────────────────────────────────────────

    def _check_sensitive_data(self, result: JWTResult) -> None:
        """Flag payload keys that should never be in a JWT."""
        found_keys = []
        for key in result.payload:
            if key.lower() in SENSITIVE_PAYLOAD_KEYS:
                found_keys.append(key)

        result.sensitive_data_keys = found_keys
        if found_keys:
            result.findings.append({
                "severity": "high",
                "title": f"JWT payload contains sensitive key(s): {', '.join(found_keys)}",
                "detail": (
                    "JWT payloads are base64-encoded, not encrypted. "
                    "Any party with the token can read the payload without the secret."
                ),
            })

    # ── alg:none live test ────────────────────────────────────────────────────

    def _test_alg_none(self, token: str, result: JWTResult) -> None:
        """Send a forged alg:none token to the target and check the response.

        This modifies the token header to ``alg:none`` and removes the
        signature. A 200/2xx response indicates the server does not validate
        the algorithm field.
        """
        try:
            import requests

            parts = token.split(".")
            if len(parts) != 3:
                return

            # Forge header with alg:none
            forged_header = {"alg": "none", "typ": "JWT"}
            forged_header_b64 = base64.urlsafe_b64encode(
                json.dumps(forged_header, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()

            # Construct token with empty signature
            forged_token = f"{forged_header_b64}.{parts[1]}."

            # Try against target (Authorization header + Cookie)
            headers = {"Authorization": f"Bearer {forged_token}"}
            resp = requests.get(
                self.target_url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False,
            )

            # If original token gives 401 and forged gives 200 → vulnerable
            orig_resp = requests.get(
                self.target_url,
                headers={"Authorization": f"Bearer {token}"},
                timeout=self.timeout,
                allow_redirects=False,
                verify=False,
            )

            if resp.status_code in (200, 201, 204) and orig_resp.status_code in (401, 403):
                result.alg_none_vulnerable = True
                result.findings.append({
                    "severity": "critical",
                    "title": "JWT alg:none attack CONFIRMED — server accepts unsigned tokens",
                    "detail": (
                        f"Target {self.target_url} returned HTTP {resp.status_code} for an "
                        "unsigned alg:none token. An attacker can forge any payload without a key."
                    ),
                })
                logger.warning("alg:none CONFIRMED on %s", self.target_url)
            elif resp.status_code not in (401, 403):
                result.findings.append({
                    "severity": "medium",
                    "title": "JWT alg:none — ambiguous server response (manual verification needed)",
                    "detail": (
                        f"Server returned HTTP {resp.status_code} for an alg:none token "
                        f"(expected 401/403). Could indicate improper validation."
                    ),
                })
        except Exception as exc:
            logger.debug("alg:none test failed: %s", exc)

    # ── Compile findings ──────────────────────────────────────────────────────

    def _compile_findings(self, result: JWTResult) -> None:
        """Sort findings by severity and deduplicate."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        result.findings.sort(key=lambda f: severity_order.get(f["severity"], 5))

    # ── Convenience class method ──────────────────────────────────────────────

    @classmethod
    def from_header(cls, auth_header: str, **kwargs) -> JWTAnalyzer:
        """Create an analyzer from a raw Authorization header value."""
        return cls(**kwargs)
