"""Neo4j graph store for attack paths and host relationships."""

from __future__ import annotations

import logging

from rao.config import settings
from rao.core.state import Finding, HostInfo

logger = logging.getLogger(__name__)


class AttackGraph:
    """Store and query attack paths in Neo4j.

    N12 fix: GraphDatabase.driver() is wrapped in try/except.
    If Neo4j is offline (or password not set), self._available is False
    and all operations are no-ops with warning logs instead of crashes.

    N13 fix: close() checks self._available before accessing driver.
    """

    def __init__(self) -> None:
        self._available = False
        self.driver = None

        try:
            from neo4j import GraphDatabase

            if not settings.neo4j.password:
                logger.warning(
                    "Neo4j: NEO4J_PASSWORD is empty — skipping connection. "
                    "Set NEO4J_PASSWORD in your .env file to enable the knowledge graph."
                )
                return

            self.driver = GraphDatabase.driver(
                settings.neo4j.uri,
                auth=(settings.neo4j.user, settings.neo4j.password),
            )
            # Verify connectivity — driver() doesn't connect eagerly
            self.driver.verify_connectivity()
            self._available = True
            logger.debug("Neo4j: connected to %s.", settings.neo4j.uri)
        except Exception as e:
            logger.warning(
                "Neo4j unavailable — knowledge graph disabled. "
                "Attack paths will not be stored. Reason: %s: %s",
                type(e).__name__, e,
            )
            self.driver = None

    def close(self) -> None:
        # N13 fix: guard against driver=None before calling .close()
        if self.driver is not None:
            try:
                self.driver.close()
            except Exception as e:
                logger.debug("Neo4j close error (non-fatal): %s", e)

    def store_host(self, host: HostInfo) -> None:
        """Create a Host node with its Service nodes."""
        if not self._available:
            return
        try:
            with self.driver.session() as session:
                session.execute_write(self._create_host_tx, host)
        except Exception as e:
            logger.warning("Neo4j: failed to store host %s: %s", host.ip, e)

    def store_finding(self, finding: Finding) -> None:
        """Create a Vulnerability node linked to its Host."""
        if not self._available:
            return
        try:
            with self.driver.session() as session:
                session.execute_write(self._create_finding_tx, finding)
        except Exception as e:
            logger.warning("Neo4j: failed to store finding '%s': %s", finding.title, e)

    def get_attack_paths(self, target_ip: str) -> list[dict]:
        """Query all findings connected to a host, ordered by severity.

        N15 fix: Returns an empty list when the host is not found in the
        graph. Callers must not treat [] as "no vulnerabilities" — only as
        "no data in graph". Log a debug message to distinguish the two cases.
        """
        if not self._available:
            return []
        try:
            with self.driver.session() as session:
                result = session.execute_read(self._get_paths_tx, target_ip)
                if not result:
                    logger.debug(
                        "Neo4j: no attack paths for %s — host may not be stored in graph yet.",
                        target_ip,
                    )
                return result
        except Exception as e:
            logger.warning("Neo4j: query failed for %s: %s", target_ip, e)
            return []

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
        # N14 note: all values pass through Cypher parameterisation ($param),
        # which is safe against injection. Unicode in $title is handled by
        # the neo4j Python driver's binary protocol.
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
