"""Tests for scope validator."""

import pytest

from rao.tools.scope_validator import ScopeError, ScopeValidator


def test_private_ip_allowed_by_default():
    validator = ScopeValidator(allowed_targets=["192.168.1.0/24"])
    assert validator.validate("192.168.1.50") is True


def test_public_ip_blocked_by_default():
    validator = ScopeValidator(allowed_targets=["8.8.8.8"], allow_public=False)
    with pytest.raises(ScopeError):
        validator.validate("8.8.8.8")


def test_public_ip_allowed_when_enabled():
    validator = ScopeValidator(
        allowed_targets=["8.8.8.0/24"], allow_public=True
    )
    assert validator.validate("8.8.8.8") is True


def test_invalid_target_format():
    validator = ScopeValidator(allowed_targets=["192.168.1.0/24"])
    with pytest.raises(ScopeError, match="Invalid target format"):
        validator.validate("not_valid_at_all!!!")


def test_validate_all_filters_invalid():
    validator = ScopeValidator(
        allowed_targets=["192.168.1.0/24"], allow_public=False
    )
    targets = ["192.168.1.1", "192.168.1.2", "8.8.8.8"]
    valid = validator.validate_all(targets)
    assert "192.168.1.1" in valid
    assert "192.168.1.2" in valid
    assert "8.8.8.8" not in valid


# N16 fix: 127.0.0.1 is now in CRITICAL_BLOCKLIST — it raises ScopeError,
# NOT returns True. The old test was correct for the old behavior but is now
# wrong after the SSRF blocklist was added.
def test_localhost_is_in_critical_blocklist():
    """127.0.0.1 is CRITICAL_BLOCKLIST — must raise ScopeError regardless of scope."""
    validator = ScopeValidator(allowed_targets=["127.0.0.1"], allow_private=True)
    with pytest.raises(ScopeError, match="critical blocklist"):
        validator.validate("127.0.0.1")


def test_link_local_is_blocked():
    """169.254.x.x (cloud metadata) must always be blocked."""
    validator = ScopeValidator(allowed_targets=["169.254.169.254"], allow_private=True)
    with pytest.raises(ScopeError, match="critical blocklist"):
        validator.validate("169.254.169.254")


def test_multicast_is_blocked():
    """224.x.x.x (multicast) must always be blocked."""
    validator = ScopeValidator(allowed_targets=["224.0.0.1"], allow_private=True)
    with pytest.raises(ScopeError, match="critical blocklist"):
        validator.validate("224.0.0.1")
