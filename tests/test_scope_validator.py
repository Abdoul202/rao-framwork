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


def test_localhost_is_private():
    validator = ScopeValidator(allowed_targets=["127.0.0.1"])
    assert validator.validate("127.0.0.1") is True


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
