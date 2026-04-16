"""Neo4j graph store for attack paths and host relationships."""

from __future__ import annotations

import logging

from neo4j import GraphDatabase

from rao.config import settings
from rao.core.state import Finding, HostInfo

logger = logging.getLogger(__name__)


class AttackGraph:
    """Store and query attack paths in Neo4j."""

    def __init__(self) -> None:
        self.driver = GraphDatabase.driver(
            settings.neo4j.uri,
            auth=(settings.neo4j.user, settings.neo4j.password),
        )

    def close(self) -> None:
        self.driver.close()

    def store_host(self, host: HostInfo) -> None:
        """Create a Host node with its Service nodes."""
        with self.driver.session() as session:
            session.execute_write(self._create_host_tx, host)

    def store_finding(self, finding: Finding) -> None:
        """Create a Vulnerability node linked to its Host."""
        with self.driver.session() as session:
            session.execute_write(self._create_finding_tx, finding)

    def get_attack_paths(self, target_ip: str) -> list[dict]:
        """Query all findings connected to a host, ordered by severity."""
        with self.driver.session() as session:
            result = session.execute_read(self._get_paths_tx, target_ip)
            return result

    @staticmethod
    def _create_host_tx(tx, host: HostInfo) -> None:
        tx.run(
            """
            MERGE (h:Host {ip: $ip})
            SET h.hostname = $hostname, h.os = $os
            """,
            ip=host.ip,
            hostname=host.hostname,
            os=host.os_guess,
        )
        for port in host.ports:
            tx.run(
                """
                MERGE (s:Service {host: $ip, port: $port})
                SET s.protocol = $proto, s.name = $service, s.version = $version
                WITH s
                MATCH (h:Host {ip: $ip})
                MERGE (h)-[:RUNS]->(s)
                """,
                ip=host.ip,
                port=port.port,
                proto=port.protocol,
                service=port.service,
                version=port.version,
            )

    @staticmethod
    def _create_finding_tx(tx, finding: Finding) -> None:
        tx.run(
            """
            MERGE (v:Vulnerability {title: $title, host: $host})
            SET v.severity = $severity,
                v.description = $description,
                v.port = $port,
                v.validated = $validated,
                v.false_positive = $false_positive,
                v.cves = $cves
            WITH v
            MATCH (h:Host {ip: $host})
            MERGE (h)-[:HAS_VULN]->(v)
            """,
            title=finding.title,
            host=finding.host,
            severity=finding.severity.value,
            description=finding.description,
            port=finding.port,
            validated=finding.validated,
            false_positive=finding.false_positive,
            cves=finding.cve_ids,
        )

    @staticmethod
    def _get_paths_tx(tx, target_ip: str) -> list[dict]:
        result = tx.run(
            """
            MATCH (h:Host {ip: $ip})-[:HAS_VULN]->(v:Vulnerability)
            WHERE v.false_positive = false
            RETURN v.title AS title, v.severity AS severity,
                   v.port AS port, v.cves AS cves
            ORDER BY
                CASE v.severity
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3
                    ELSE 4
                END
            """,
            ip=target_ip,
        )
        return [dict(record) for record in result]
