"""Tests for JWTAnalyzer.

All tests are fully offline — no network access required.
The alg:none live test is tested via mock requests only.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest

from rao.tools.jwt_analyzer import JWTAnalyzer

# ── Helpers ───────────────────────────────────────────────────────────────────

def _b64url(data: dict) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(data, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()


def _make_token(
    header: dict,
    payload: dict,
    secret: str = "secret",
    algorithm: str = "HS256",
) -> str:
    """Create a real signed JWT for testing."""
    h = _b64url(header)
    p = _b64url(payload)
    signing_input = f"{h}.{p}".encode()
    hash_fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[algorithm]
    sig = hmac.new(secret.encode(), signing_input, hash_fn).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{h}.{p}.{sig_b64}"


def _make_none_token(payload: dict) -> str:
    """Create an alg:none token with empty signature."""
    h = _b64url({"alg": "none", "typ": "JWT"})
    p = _b64url(payload)
    return f"{h}.{p}."


@pytest.fixture
def analyzer():
    return JWTAnalyzer()


@pytest.fixture
def valid_payload():
    now = int(time.time())
    return {
        "sub": "1234567890",
        "name": "Test User",
        "iat": now - 100,
        "exp": now + 3600,
    }


@pytest.fixture
def valid_token(valid_payload):
    header = {"alg": "HS256", "typ": "JWT"}
    return _make_token(header, valid_payload, secret="secret")


# ── Decoding ──────────────────────────────────────────────────────────────────

def test_decode_valid_token(analyzer, valid_token, valid_payload):
    result = analyzer.analyze(valid_token)
    assert result.error == ""
    assert result.algorithm == "HS256"
    assert result.payload.get("sub") == "1234567890"


def test_decode_strips_bearer_prefix(analyzer, valid_token):
    result = analyzer.analyze(f"Bearer {valid_token}")
    assert result.error == ""
    assert result.algorithm == "HS256"


def test_malformed_token_two_parts(analyzer):
    result = analyzer.analyze("only.twoparts")
    assert result.error != ""
    assert "3 parts" in result.error


def test_malformed_token_not_base64(analyzer):
    result = analyzer.analyze("not!!!.valid!!!.base64!!!")
    assert result.error != ""


# ── Algorithm checks ──────────────────────────────────────────────────────────

def test_alg_none_in_header_flagged(analyzer):
    """A token declaring alg:none should be flagged even without live test."""
    token = _make_none_token({"sub": "user", "role": "admin"})
    result = analyzer.analyze(token)
    titles = [f["title"] for f in result.findings]
    assert any("none" in t.lower() for t in titles)


def test_alg_hs256_no_algorithm_finding(analyzer, valid_token):
    result = analyzer.analyze(valid_token)
    titles = [f["title"] for f in result.findings]
    assert not any("algorithm" in t.lower() for t in titles)


# ── Claims ────────────────────────────────────────────────────────────────────

def test_expired_token_flagged(analyzer):
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "x", "exp": int(time.time()) - 3600, "iat": int(time.time()) - 7200}
    token = _make_token(header, payload, "secret")
    result = analyzer.analyze(token)
    assert result.is_expired is True
    assert any("expired" in f["title"].lower() for f in result.findings)


def test_missing_exp_flagged(analyzer):
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "x", "iat": int(time.time())}
    token = _make_token(header, payload, "secret")
    result = analyzer.analyze(token)
    assert any("expiry" in f["title"].lower() or "exp" in f["title"].lower()
               for f in result.findings)


def test_missing_iat_flagged(analyzer):
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "x", "exp": int(time.time()) + 3600}
    token = _make_token(header, payload, "secret")
    result = analyzer.analyze(token)
    assert any("iat" in f["title"].lower() for f in result.findings)


def test_very_long_expiry_flagged(analyzer):
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": "x",
        "iat": int(time.time()),
        "exp": int(time.time()) + 365 * 24 * 3600 * 2,  # 2 years
    }
    token = _make_token(header, payload, "secret")
    result = analyzer.analyze(token)
    assert any("long expiry" in f["title"].lower() for f in result.findings)


# ── Weak secret ───────────────────────────────────────────────────────────────

def test_weak_secret_cracked(analyzer, valid_payload):
    """A token signed with 'secret' should be cracked."""
    header = {"alg": "HS256", "typ": "JWT"}
    token = _make_token(header, valid_payload, secret="secret")
    result = analyzer.analyze(token)
    assert result.weak_secret_found == "secret"
    assert any("weak secret" in f["title"].lower() for f in result.findings)
    assert any(f["severity"] == "critical" for f in result.findings)


def test_strong_secret_not_cracked(analyzer, valid_payload):
    """A token signed with a strong secret should not be cracked."""
    header = {"alg": "HS256", "typ": "JWT"}
    token = _make_token(header, valid_payload, secret="x9Kq$mP!7vL#2nRw8dTz")
    result = analyzer.analyze(token)
    assert result.weak_secret_found == ""


def test_rsa_token_skips_brute_force(analyzer):
    """RS256 tokens should not attempt offline brute-force."""
    # Simulate an RS256 token (header only, payload, fake sig)
    h = _b64url({"alg": "RS256", "typ": "JWT"})
    p = _b64url({"sub": "x", "exp": int(time.time()) + 3600, "iat": int(time.time())})
    token = f"{h}.{p}.fakesignature"
    result = analyzer.analyze(token)
    assert result.weak_secret_found == ""


# ── Sensitive data ────────────────────────────────────────────────────────────

def test_sensitive_key_in_payload_flagged(analyzer):
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": "user",
        "password": "supersecret123",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    token = _make_token(header, payload, "secret")
    result = analyzer.analyze(token)
    assert "password" in result.sensitive_data_keys
    assert any("sensitive" in f["title"].lower() for f in result.findings)


def test_normal_payload_no_sensitive_finding(analyzer, valid_token):
    result = analyzer.analyze(valid_token)
    assert result.sensitive_data_keys == []


# ── has_critical property ─────────────────────────────────────────────────────

def test_has_critical_true_for_weak_secret(analyzer, valid_payload):
    header = {"alg": "HS256", "typ": "JWT"}
    token = _make_token(header, valid_payload, secret="password")
    result = analyzer.analyze(token)
    assert result.has_critical is True


def test_has_critical_false_for_clean_token(analyzer):
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": "x",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    token = _make_token(header, payload, secret="xK9$mP!7vL#2nRw8dTz")
    result = analyzer.analyze(token)
    assert result.has_critical is False
