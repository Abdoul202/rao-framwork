"""
Scope Validator - Ensure all targets are authorized before scanning.

Prevents scope creep by validating IPs, domains, and CIDR ranges.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket

logger = logging.getLogger(__name__)

DOMAIN_REGEX = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


class ScopeError(Exception):
    """Raised when a target is out of scope."""


class ScopeValidator:
    """Validate and enforce target scope rules."""

    def __init__(
        self,
        allowed_targets: list[str],
        allow_private: bool = True,
        allow_public: bool = False,
    ) -> None:
        self.allowed_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.allowed_domains: list[str] = []
        self.allow_private = allow_private
        self.allow_public = allow_public
        self._parse_scope(allowed_targets)

    def _parse_scope(self, targets: list[str]) -> None:
        for target in targets:
            try:
                network = ipaddress.ip_network(target, strict=False)
                self.allowed_cidrs.append(network)
            except ValueError:
                if DOMAIN_REGEX.match(target):
                    self.allowed_domains.append(target.lower())
                else:
                    logger.warning("Unrecognized scope entry: %s", target)

    def validate(self, target: str) -> bool:
        """
        Check if a target is within scope.

        Raises ScopeError if out of scope.
        Returns True if valid.
        """
        # Check domain scope
        if DOMAIN_REGEX.match(target):
            return self._validate_domain(target)

        # Check IP scope
        try:
            ip = ipaddress.ip_address(target)
            return self._validate_ip(ip)
        except ValueError:
            pass

        # Try CIDR
        try:
            network = ipaddress.ip_network(target, strict=False)
            for addr in network.hosts():
                self._validate_ip(addr)
            return True
        except ValueError:
            raise ScopeError(f"Invalid target format: {target}")

    def _validate_domain(self, domain: str) -> bool:
        domain = domain.lower()

        # Check exact match or subdomain match
        for allowed in self.allowed_domains:
            if domain == allowed or domain.endswith(f".{allowed}"):
                return True

        # Resolve and check IP
        try:
            ip_str = socket.gethostbyname(domain)
            ip = ipaddress.ip_address(ip_str)
            return self._validate_ip(ip)
        except socket.gaierror:
            raise ScopeError(f"Cannot resolve domain: {domain}")

    def _validate_ip(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        is_private = any(ip in net for net in PRIVATE_RANGES)

        if is_private and not self.allow_private:
            raise ScopeError(f"Private IP {ip} not allowed in scope")

        if not is_private and not self.allow_public:
            raise ScopeError(
                f"Public IP {ip} not allowed - set allow_public=True for authorized external targets"
            )

        # Check against explicit CIDR scope
        if self.allowed_cidrs:
            if any(ip in cidr for cidr in self.allowed_cidrs):
                return True
            # If CIDRs are defined, IP must be in one of them
            if not is_private:
                raise ScopeError(f"IP {ip} not in any allowed CIDR range")

        return True

    def validate_all(self, targets: list[str]) -> list[str]:
        """Validate a list of targets, return only valid ones."""
        valid = []
        for target in targets:
            try:
                self.validate(target)
                valid.append(target)
            except ScopeError as e:
                logger.warning("Scope violation: %s", e)
        return valid
