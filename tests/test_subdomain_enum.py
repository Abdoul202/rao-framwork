"""Tests for subdomain enumerator."""

from unittest.mock import patch

from rao.tools.subdomain_enum import SubdomainEnumerator

# N19 fix: mock socket.gethostbyname instead of doing real DNS resolution.
# The old test called gethostbyname("localhost") directly, which is fragile
# in CI (can resolve to ::1 on IPv6-only runners, not "127.0.0.1").

def test_resolve_known_host():
    """_resolve returns the IP when DNS resolves successfully."""
    enumerator = SubdomainEnumerator()
    with patch("socket.gethostbyname", return_value="127.0.0.1"):
        ip = enumerator._resolve("localhost")
    assert ip == "127.0.0.1"


def test_resolve_nonexistent():
    """_resolve returns None when DNS resolution fails."""
    enumerator = SubdomainEnumerator()
    ip = enumerator._resolve("this.domain.definitely.does.not.exist.xyz123abc")
    assert ip is None


def test_resolve_gaierror_returns_none():
    """_resolve must return None on socket.gaierror, not raise."""
    import socket

    enumerator = SubdomainEnumerator()
    with patch("socket.gethostbyname", side_effect=socket.gaierror("NXDOMAIN")):
        ip = enumerator._resolve("nxdomain.example.com")
    assert ip is None


def test_crtsh_parse_handles_failure():
    """If crt.sh AND HackerTarget fail, _query_crtsh must return []."""
    enumerator = SubdomainEnumerator()
    with patch("requests.get", side_effect=Exception("timeout")):
        result = enumerator._query_crtsh("example.com")
    assert result == []


def test_crtsh_filters_wildcards():
    """Wildcard entries like *.example.com must be filtered out."""
    enumerator = SubdomainEnumerator()
    mock_response = [
        {"name_value": "*.example.com\nwww.example.com\napi.example.com"},
    ]
    with patch("requests.get") as mock_get:
        mock_get.return_value.json.return_value = mock_response
        mock_get.return_value.raise_for_status = lambda: None
        result = enumerator._query_crtsh("example.com")
    # _query_crtsh now returns list of (subdomain, source) tuples
    subdomains = [s for s, _ in result]
    sources    = [src for _, src in result]
    # Wildcards must be excluded
    assert not any("*" in s for s in subdomains)
    assert "www.example.com" in subdomains
    assert "api.example.com" in subdomains
    assert all(src == "crt.sh" for src in sources)


def test_resolve_timeout_restores_socket_timeout():
    """N19 fix: socket timeout must be restored after _resolve, even on error."""
    import socket

    enumerator = SubdomainEnumerator(timeout=3)
    original_timeout = socket.getdefaulttimeout()

    with patch("socket.gethostbyname", side_effect=socket.gaierror):
        enumerator._resolve("example.com")

    # Timeout must be restored to the original value
    assert socket.getdefaulttimeout() == original_timeout
