"""Tests for subdomain enumerator."""

from unittest.mock import patch

from rao.tools.subdomain_enum import SubdomainEnumerator


def test_resolve_localhost():
    enumerator = SubdomainEnumerator()
    ip = enumerator._resolve("localhost")
    assert ip == "127.0.0.1"


def test_resolve_nonexistent():
    enumerator = SubdomainEnumerator()
    ip = enumerator._resolve("this.domain.definitely.does.not.exist.xyz123")
    assert ip is None


def test_crtsh_parse_handles_failure():
    enumerator = SubdomainEnumerator()
    with patch("requests.get", side_effect=Exception("timeout")):
        result = enumerator._query_crtsh("example.com")
    assert result == []
