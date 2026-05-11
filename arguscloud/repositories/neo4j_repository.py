"""Neo4j implementation of the GraphRepository interface.

This module provides the concrete implementation for Neo4j database
operations, encapsulating all Cypher queries and Neo4j-specific logic.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from neo4j import Driver

from arguscloud.repositories.base import GraphRepository, NodeFilter, ProfileData

logger = logging.getLogger(__name__)

# Allowlist of valid Cypher relationship types used in the codebase.
# Defense-in-depth: validated by regex AND membership check before interpolation.
# Allows UPPER_SNAKE_CASE and PascalCase/camelCase identifiers (no spaces or
# special characters that could break Cypher relationship-type interpolation).
_EDGE_TYPE_REGEX = re.compile(r'^[A-Za-z][A-Za-z0-9_]{0,59}$')

VALID_EDGE_TYPES: frozenset = frozenset({
    # IAM / identity relationships
    "TRUSTS",
    "ATTACHED_POLICY",
    "ATTACHED_INLINE_POLICY",
    "MEMBER_OF",
    "HAS_INSTANCE_PROFILE",
    # EC2 / network topology
    "IN_SUBNET",
    "IN_VPC",
    "MEMBER_OF_SECURITY_GROUP",
    "CONTAINS",
    "ROUTE_TABLE",
    "VPC_PEERING",
    "VPC_ENDPOINT",
    # Resource policy / principal relationships
    "RESOURCE_POLICY",
    "POLICY_PRINCIPAL",
    # Cross-resource relationships
    "ASSUMES_ROLE",
    "ATTACK_PATH",
    "RELATES_TO",
    # Normalizer-produced edge types (camel-case aliases kept for compatibility)
    "AttachedPolicy",
    "AttachedInlinePolicy",
    "Trusts",
    "MemberOf",
    "HasInstanceProfile",
    "InSubnet",
    "InVPC",
    "MemberOfSecurityGroup",
    "Contains",
    "ResourcePolicy",
    "PolicyPrincipal",
    "AssumesRole",
    "AttackPath",
    "RelatesTo",
    "VPCPeering",
    "VPCEndpoint",
    "RouteTable",
    "OrgRoot",
    "ServiceControlPolicy",
    "OrganizationalUnit",
    "Account",
    # Relationship used in server.py edge persistence
    "REL",
    # IAM privilege escalation / assume-role relationships
    "CanAssume",
    "CAN_ASSUME",
})


def _upsert_profile_atomic(
    tx,
    *,
    name: str,
    now: str,
    mode: str,
    exists: bool,
    nodes_payload: List[Dict[str, Any]],
    edges_by_type: Dict[str, List[Dict[str, Any]]],
) -> tuple:
    """Transaction function executed by ``session.execute_write`` (H-08).

    Deletes old profile data (overwrite mode), upserts all resource nodes in
    one UNWIND statement, then upserts edges grouped by relationship type so
    each group is one UNWIND statement.  All of this runs in a single Neo4j
    explicit transaction.

    Returns:
        Tuple of (node_count, edge_count).
    """
    if mode == "overwrite" and exists:
        tx.run(
            "MATCH (n {profile: $name}) DETACH DELETE n",
            name=name,
        )

    # Upsert all nodes in one round-trip (UNWIND batching).
    tx.run(
        """
        UNWIND $nodes AS n
        MERGE (r:Resource {id: n.id})
        SET r += n.properties,
            r.profile = $name,
            r.type = n.type,
            r.provider = n.provider,
            r.created_at = COALESCE(r.created_at, $now),
            r.updated_at = $now
        """,
        nodes=nodes_payload,
        name=name,
        now=now,
    )

    # Upsert edges grouped by type — one UNWIND per relationship type so the
    # type can be interpolated safely (already validated against the allowlist).
    edge_count = 0
    for edge_type, edge_list in edges_by_type.items():
        tx.run(
            f"""
            UNWIND $edges AS e
            MATCH (a:Resource {{id: e.src}}), (b:Resource {{id: e.dst}})
            MERGE (a)-[r:{edge_type}]->(b)
            SET r += e.properties
            """,
            edges=edge_list,
        )
        edge_count += len(edge_list)

    return len(nodes_payload), edge_count


class Neo4jGraphRepository(GraphRepository):
    """Neo4j implementation of GraphRepository.

    This class encapsulates all Neo4j-specific database operations,
    providing a clean interface for the API layer.

    Attributes:
        driver: Neo4j driver instance
    """

    def __init__(self, driver: Driver):
        """Initialize the repository with a Neo4j driver.

        Args:
            driver: Configured Neo4j driver instance
        """
        self.driver = driver
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        """Create Neo4j constraints and indexes if they do not already exist.

        Runs on every startup so the graph is always indexed.  Wrapped in a
        broad except so that older Neo4j instances (pre-4.x) that lack
        IF NOT EXISTS support log a warning rather than crashing.
        """
        statements = [
            (
                "CREATE CONSTRAINT resource_id_unique IF NOT EXISTS "
                "FOR (n:Resource) REQUIRE n.id IS UNIQUE"
            ),
            (
                "CREATE INDEX profile_name_idx IF NOT EXISTS "
                "FOR (p:Profile) ON (p.name)"
            ),
        ]
        try:
            with self.driver.session() as session:
                for stmt in statements:
                    session.run(stmt)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Could not create Neo4j schema constraints/indexes "
                "(may already exist or Neo4j version too old): %s",
                exc,
            )

    def get_nodes(self, filters: NodeFilter) -> List[Dict[str, Any]]:
        """Get nodes matching the given filters."""
        query = "MATCH (n) "
        params: Dict[str, Any] = {}
        conditions = []

        if filters.provider:
            conditions.append("n.provider = $provider")
            params["provider"] = filters.provider

        if filters.node_type:
            conditions.append("n.type = $type")
            params["type"] = filters.node_type

        if filters.profile:
            conditions.append("n.profile = $profile")
            params["profile"] = filters.profile

        if conditions:
            query += "WHERE " + " AND ".join(conditions) + " "

        query += f"""
        RETURN n.id AS id, n.type AS type,
               n.provider AS provider, properties(n) AS props
        LIMIT {filters.limit}
        """

        with self.driver.session() as session:
            result = session.run(query, params)
            return [
                {
                    "id": record["id"],
                    "type": record["type"],
                    "provider": record["provider"] or "unknown",
                    "properties": record["props"],
                }
                for record in result
            ]

    def get_edges(self, filters: NodeFilter) -> List[Dict[str, Any]]:
        """Get edges matching the given filters."""
        query = "MATCH (a)-[r]->(b) "
        params: Dict[str, Any] = {}
        conditions = []

        if filters.provider:
            conditions.append("(a.provider = $provider OR b.provider = $provider)")
            params["provider"] = filters.provider

        if filters.profile:
            conditions.append("(a.profile = $profile OR b.profile = $profile)")
            params["profile"] = filters.profile

        if conditions:
            query += "WHERE " + " AND ".join(conditions) + " "

        query += f"""
        RETURN a.id AS src, b.id AS dst, type(r) AS type, properties(r) AS props
        LIMIT {filters.limit}
        """

        with self.driver.session() as session:
            result = session.run(query, params)
            return [
                {
                    "src": record["src"],
                    "dst": record["dst"],
                    "type": record["type"],
                    "properties": record["props"],
                }
                for record in result
            ]

    def get_attack_paths(
        self,
        severity: Optional[str] = None,
        provider: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        """Get attack path edges."""
        query = "MATCH (a)-[r:AttackPath]->(b) "
        params: Dict[str, Any] = {}
        conditions = []

        if severity:
            conditions.append("r.severity = $severity")
            params["severity"] = severity

        if provider:
            conditions.append("(a.provider = $provider OR b.provider = $provider)")
            params["provider"] = provider

        if conditions:
            query += "WHERE " + " AND ".join(conditions) + " "

        # Order by severity for consistent results
        query += """
        RETURN a.id AS src, b.id AS dst, 'AttackPath' AS type, properties(r) AS props
        ORDER BY
            CASE r.severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END
        """
        query += f"LIMIT {limit}"

        with self.driver.session() as session:
            result = session.run(query, params)
            return [
                {
                    "src": record["src"],
                    "dst": record["dst"],
                    "type": record["type"],
                    "properties": record["props"],
                }
                for record in result
            ]

    def get_findings_summary(
        self,
        provider: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get aggregated findings summary."""
        params: Dict[str, Any] = {}
        where_clause = ""

        if provider:
            where_clause = "WHERE a.provider = $provider OR b.provider = $provider"
            params["provider"] = provider

        # Get counts by severity
        severity_query = f"""
        MATCH (a)-[r:AttackPath]->(b)
        {where_clause}
        RETURN r.severity AS severity, count(*) AS count
        """

        # Get counts by rule
        rule_query = f"""
        MATCH (a)-[r:AttackPath]->(b)
        {where_clause}
        RETURN r.rule AS rule, count(*) AS count
        """

        # Get top critical/high findings
        top_findings_query = f"""
        MATCH (a)-[r:AttackPath]->(b)
        {where_clause}
        WHERE r.severity IN ['critical', 'high']
        RETURN a.id AS src, b.id AS dst, properties(r) AS props
        ORDER BY
            CASE r.severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
            END
        LIMIT 20
        """

        with self.driver.session() as session:
            # Severity counts
            severity_result = session.run(severity_query, params)
            by_severity = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            }
            total = 0
            for record in severity_result:
                sev = record["severity"] or "unknown"
                count = record["count"]
                if sev in by_severity:
                    by_severity[sev] = count
                total += count

            # Rule counts
            rule_result = session.run(rule_query, params)
            by_rule = {}
            for record in rule_result:
                rule = record["rule"] or "unknown"
                by_rule[rule] = record["count"]

            # Top findings
            findings_result = session.run(top_findings_query, params)
            critical_findings = []
            high_findings = []
            for record in findings_result:
                finding = {
                    "src": record["src"],
                    "dst": record["dst"],
                    "properties": record["props"],
                }
                severity = record["props"].get("severity", "")
                if severity == "critical":
                    critical_findings.append(finding)
                elif severity == "high":
                    high_findings.append(finding)

            return {
                "total": total,
                "by_severity": by_severity,
                "by_rule": by_rule,
                "critical_findings": critical_findings[:10],
                "high_findings": high_findings[:10],
            }

    def get_resources_summary(
        self,
        provider: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get aggregated resources summary."""
        params: Dict[str, Any] = {}
        where_clause = ""

        if provider:
            where_clause = "WHERE n.provider = $provider"
            params["provider"] = provider

        query = f"""
        MATCH (n)
        {where_clause}
        RETURN n.type AS type, count(*) AS count
        """

        with self.driver.session() as session:
            result = session.run(query, params)
            by_type = {}
            total = 0
            for record in result:
                node_type = record["type"] or "unknown"
                count = record["count"]
                by_type[node_type] = count
                total += count

            return {
                "total": total,
                "by_type": by_type,
            }

    def execute_read_query(
        self,
        cypher: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Execute a validated read-only Cypher query."""
        with self.driver.session() as session:
            result = session.run(cypher, params or {})
            return [record.data() for record in result]

    def list_profiles(self) -> List[Dict[str, Any]]:
        """List all profiles with metadata (single aggregating query — no N+1)."""
        query = """
        MATCH (p:Profile)
        OPTIONAL MATCH (n:Resource {profile: p.name})
        WITH p, count(DISTINCT n) AS node_count
        OPTIONAL MATCH (a:Resource {profile: p.name})-[r]->(b:Resource {profile: p.name})
        RETURN p.name AS name,
               node_count,
               count(r) AS edge_count,
               p.created_at AS created_at
        ORDER BY p.created_at DESC
        """

        with self.driver.session() as session:
            result = session.run(query)
            profiles = []
            for record in result:
                profiles.append({
                    "name": record["name"],
                    "node_count": record["node_count"],
                    "edge_count": record["edge_count"],
                    "created_at": record["created_at"],
                })
            return profiles

    def get_profile(self, name: str) -> Optional[ProfileData]:
        """Get a specific profile by name."""
        # Check if profile exists
        check_query = """
        MATCH (n {profile: $name})
        RETURN count(n) AS count
        """

        with self.driver.session() as session:
            check_result = session.run(check_query, {"name": name})
            check_record = check_result.single()
            if not check_record or check_record["count"] == 0:
                return None

            # Get nodes
            nodes_query = """
            MATCH (n {profile: $name})
            RETURN n.id AS id, n.type AS type, n.provider AS provider, properties(n) AS props
            """
            nodes_result = session.run(nodes_query, {"name": name})
            nodes = [
                {
                    "id": record["id"],
                    "type": record["type"],
                    "provider": record["provider"] or "unknown",
                    "properties": record["props"],
                }
                for record in nodes_result
            ]

            # Get edges
            edges_query = """
            MATCH (a {profile: $name})-[r]->(b)
            RETURN a.id AS src, b.id AS dst, type(r) AS type, properties(r) AS props
            """
            edges_result = session.run(edges_query, {"name": name})
            edges = [
                {
                    "src": record["src"],
                    "dst": record["dst"],
                    "type": record["type"],
                    "properties": record["props"],
                }
                for record in edges_result
            ]

            return ProfileData(
                name=name,
                nodes=nodes,
                edges=edges,
                meta={
                    "node_count": len(nodes),
                    "edge_count": len(edges),
                },
            )

    def save_profile(
        self,
        name: str,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
        mode: str = "create",
    ) -> Dict[str, Any]:
        """Save profile data to the database atomically (H-08).

        All writes run inside a single Neo4j explicit transaction via
        ``session.execute_write``.  Nodes are UPSERTed with UNWIND batching;
        edges are grouped by type so each group can be written with a single
        UNWIND statement (Cypher relationship types cannot be parameterised).
        """
        now = datetime.utcnow().isoformat()

        # Validate all edge types eagerly BEFORE opening a transaction so that
        # a bad payload is rejected before any writes occur.
        for edge in edges:
            edge_type = edge.get("type", "RELATES_TO")
            if not _EDGE_TYPE_REGEX.match(edge_type):
                raise ValueError(f"invalid edge type (format): {edge_type!r}")
            if edge_type not in VALID_EDGE_TYPES:
                raise ValueError(f"invalid edge type: {edge_type!r}")

        # Build the payloads that will be forwarded into the transaction.
        nodes_payload = [
            {
                "id": n["id"],
                "type": n.get("type", "unknown"),
                "provider": n.get("provider", "unknown"),
                "properties": n.get("properties", {}),
            }
            for n in nodes
        ]

        # Group edges by type so we can UNWIND per type inside the transaction.
        edges_by_type: Dict[str, List[Dict[str, Any]]] = {}
        for edge in edges:
            edge_type = edge.get("type", "RELATES_TO")
            edges_by_type.setdefault(edge_type, []).append(
                {
                    "src": edge["src"],
                    "dst": edge["dst"],
                    "properties": edge.get("properties", {}),
                }
            )

        with self.driver.session() as session:
            # Existence check runs outside the write transaction (read-only).
            check_query = """
            MATCH (n {profile: $name})
            RETURN count(n) AS count
            """
            check_result = session.run(check_query, {"name": name})
            check_record = check_result.single()
            exists = check_record and check_record["count"] > 0

            if mode == "create" and exists:
                raise ValueError(f"Profile '{name}' already exists")

            # The entire write (delete + node upserts + edge upserts) runs in
            # one explicit transaction — atomic (H-08).
            node_count, edge_count = session.execute_write(
                _upsert_profile_atomic,
                name=name,
                now=now,
                mode=mode,
                exists=exists,
                nodes_payload=nodes_payload,
                edges_by_type=edges_by_type,
            )

            return {
                "success": True,
                "name": name,
                "node_count": node_count,
                "edge_count": edge_count,
                "mode": mode,
            }

    def delete_profile(self, name: str) -> bool:
        """Delete a profile by name."""
        with self.driver.session() as session:
            # Check if exists
            check_query = """
            MATCH (n {profile: $name})
            RETURN count(n) AS count
            """
            check_result = session.run(check_query, {"name": name})
            check_record = check_result.single()
            if not check_record or check_record["count"] == 0:
                return False

            # Delete
            delete_query = """
            MATCH (n {profile: $name})
            DETACH DELETE n
            """
            session.run(delete_query, {"name": name})
            return True

    def rename_profile(self, old_name: str, new_name: str) -> bool:
        """Rename a profile."""
        with self.driver.session() as session:
            # Check old exists
            check_old = session.run(
                "MATCH (n {profile: $name}) RETURN count(n) AS count",
                {"name": old_name},
            )
            old_record = check_old.single()
            if not old_record or old_record["count"] == 0:
                raise ValueError(f"Profile '{old_name}' not found")

            # Check new doesn't exist
            check_new = session.run(
                "MATCH (n {profile: $name}) RETURN count(n) AS count",
                {"name": new_name},
            )
            new_record = check_new.single()
            if new_record and new_record["count"] > 0:
                raise ValueError(f"Profile '{new_name}' already exists")

            # Rename
            rename_query = """
            MATCH (n {profile: $old_name})
            SET n.profile = $new_name
            """
            session.run(rename_query, {"old_name": old_name, "new_name": new_name})
            return True

    def health_check(self) -> bool:
        """Check database connectivity."""
        try:
            with self.driver.session() as session:
                session.run("RETURN 1")
            return True
        except Exception as e:
            logger.warning(f"Health check failed: {type(e).__name__}")
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        with self.driver.session() as session:
            node_result = session.run("MATCH (n) RETURN count(n) AS count")
            node_count = node_result.single()["count"]

            edge_result = session.run("MATCH ()-[r]->() RETURN count(r) AS count")
            edge_count = edge_result.single()["count"]

            profile_result = session.run(
                "MATCH (n) WHERE n.profile IS NOT NULL "
                "RETURN count(DISTINCT n.profile) AS count"
            )
            profile_count = profile_result.single()["count"]

            return {
                "node_count": node_count,
                "edge_count": edge_count,
                "profile_count": profile_count,
            }
