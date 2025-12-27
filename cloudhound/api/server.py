"""CloudHound API server with authentication support."""

from __future__ import annotations

import argparse
import os
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, request, g
from flask_cors import CORS
from neo4j import GraphDatabase

from .auth import AuthConfig, init_auth, require_auth


def get_driver(uri: str, user: str, password: str):
    """Create Neo4j driver connection."""
    return GraphDatabase.driver(uri, auth=(user, password))


def create_app(
    uri: str,
    user: str,
    password: str,
    auth_config: Optional[AuthConfig] = None
) -> Flask:
    """Create and configure the CloudHound API Flask application.

    Args:
        uri: Neo4j connection URI
        user: Neo4j username
        password: Neo4j password
        auth_config: Optional authentication configuration

    Returns:
        Configured Flask application
    """
    driver = get_driver(uri, user, password)
    app = Flask(__name__)
    CORS(app)

    # Initialize authentication
    init_auth(app, auth_config)

    @app.after_request
    def add_cors(resp):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization,X-API-Key"
        resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
        return resp

    @app.route("/health")
    def health():
        """Health check endpoint (unauthenticated)."""
        try:
            with driver.session() as session:
                session.run("RETURN 1").single()
            return jsonify({"status": "ok", "database": "connected"})
        except Exception as exc:
            return jsonify({"status": "error", "detail": str(exc)}), 500

    @app.route("/graph")
    @require_auth(allow_read=True)
    def graph():
        """Get graph nodes and edges."""
        limit = int(request.args.get("limit", "500"))
        provider = request.args.get("provider")  # Optional filter by cloud provider
        node_type = request.args.get("type")  # Optional filter by node type

        nodes = _query_nodes(driver, limit, provider=provider, node_type=node_type)
        edges = _query_edges(driver, limit, provider=provider)
        return jsonify({
            "nodes": nodes,
            "edges": edges,
            "meta": {
                "total_nodes": len(nodes),
                "total_edges": len(edges),
                "limit": limit
            }
        })

    @app.route("/attackpaths")
    @require_auth(allow_read=True)
    def attackpaths():
        """Get attack path edges."""
        limit = int(request.args.get("limit", "500"))
        severity = request.args.get("severity")  # Optional filter by severity
        provider = request.args.get("provider")  # Optional filter by provider

        edges = _query_attack_paths(driver, limit, severity=severity, provider=provider)
        return jsonify({
            "edges": edges,
            "meta": {
                "total": len(edges),
                "limit": limit
            }
        })

    @app.route("/findings")
    @require_auth(allow_read=True)
    def findings():
        """Get security findings summary."""
        edges = _query_attack_paths(driver, limit=10000)

        # Group by severity
        by_severity: Dict[str, List] = {"critical": [], "high": [], "medium": [], "low": []}
        for edge in edges:
            sev = edge.get("properties", {}).get("severity", "medium")
            if sev in by_severity:
                by_severity[sev].append(edge)

        # Group by rule
        by_rule: Dict[str, int] = {}
        for edge in edges:
            rule = edge.get("properties", {}).get("rule", "unknown")
            by_rule[rule] = by_rule.get(rule, 0) + 1

        return jsonify({
            "total": len(edges),
            "by_severity": {k: len(v) for k, v in by_severity.items()},
            "by_rule": by_rule,
            "critical_findings": by_severity["critical"][:20],
            "high_findings": by_severity["high"][:20],
        })

    @app.route("/resources")
    @require_auth(allow_read=True)
    def resources():
        """Get resource inventory."""
        provider = request.args.get("provider")
        nodes = _query_nodes(driver, limit=10000, provider=provider)

        # Group by type
        by_type: Dict[str, int] = {}
        for node in nodes:
            ntype = node.get("type", "unknown")
            by_type[ntype] = by_type.get(ntype, 0) + 1

        return jsonify({
            "total": len(nodes),
            "by_type": by_type,
        })

    @app.route("/query", methods=["POST"])
    @require_auth
    def query():
        """Execute a custom Cypher query."""
        body = request.get_json(force=True) or {}
        cypher = body.get("cypher")
        limit = int(body.get("limit", 200))

        if not cypher:
            return jsonify({"error": "missing cypher"}), 400

        # Basic query sanitization - prevent destructive operations
        cypher_upper = cypher.upper()
        dangerous_keywords = ["DELETE", "REMOVE", "DROP", "CREATE", "MERGE", "SET"]
        if any(kw in cypher_upper for kw in dangerous_keywords):
            return jsonify({
                "error": "Query contains disallowed operations",
                "message": "Only read operations (MATCH, RETURN) are allowed"
            }), 403

        try:
            with driver.session() as session:
                # Append LIMIT if not present
                if "LIMIT" not in cypher_upper:
                    cypher = f"{cypher} LIMIT {limit}"
                records = session.run(cypher)
                results = [r.data() for r in records]
            return jsonify({"results": results, "count": len(results)})
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/export/<format>")
    @require_auth(allow_read=True)
    def export(format: str):
        """Export findings in various formats."""
        from cloudhound.core.graph import GraphData, Node, Edge
        from cloudhound.exporters import JSONExporter, SARIFExporter, HTMLExporter

        # Fetch all data
        nodes_data = _query_nodes(driver, limit=10000)
        edges_data = _query_edges(driver, limit=10000)
        attack_paths = _query_attack_paths(driver, limit=10000)

        # Convert to graph objects
        nodes = [Node(id=n["id"], type=n["type"], properties=n.get("properties", {}))
                 for n in nodes_data]
        edges = [Edge(src=e["src"], dst=e["dst"], type=e["type"], properties=e.get("properties", {}))
                 for e in attack_paths]

        graph = GraphData(nodes=nodes, edges=edges)

        if format == "json":
            exporter = JSONExporter(graph, edges)
            content = exporter.export()
            return app.response_class(content, mimetype="application/json")

        elif format == "sarif":
            exporter = SARIFExporter(graph, edges)
            content = exporter.export()
            return app.response_class(content, mimetype="application/json")

        elif format == "html":
            exporter = HTMLExporter(graph, edges)
            content = exporter.export()
            return app.response_class(content, mimetype="text/html")

        else:
            return jsonify({"error": f"Unknown format: {format}"}), 400

    return app


def _query_nodes(
    driver,
    limit: int,
    provider: Optional[str] = None,
    node_type: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Query nodes from Neo4j."""
    cypher = "MATCH (n:Resource) "
    params: Dict[str, Any] = {"limit": limit}

    conditions = []
    if provider:
        conditions.append("n.provider = $provider")
        params["provider"] = provider
    if node_type:
        conditions.append("n.type = $type")
        params["type"] = node_type

    if conditions:
        cypher += "WHERE " + " AND ".join(conditions) + " "

    cypher += "RETURN n.id AS id, n.type AS type, n.provider AS provider, properties(n) AS props LIMIT $limit"

    with driver.session() as session:
        records = session.run(cypher, **params)
        return [
            {
                "id": r["id"],
                "type": r["type"],
                "provider": r["provider"],
                "properties": r["props"]
            }
            for r in records
        ]


def _query_edges(
    driver,
    limit: int,
    provider: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Query edges from Neo4j."""
    cypher = "MATCH (a:Resource)-[r:REL]->(b:Resource) "
    params: Dict[str, Any] = {"limit": limit}

    if provider:
        cypher += "WHERE a.provider = $provider "
        params["provider"] = provider

    cypher += "RETURN a.id AS src, b.id AS dst, r.type AS type, properties(r) AS props LIMIT $limit"

    with driver.session() as session:
        records = session.run(cypher, **params)
        return [
            {
                "src": r["src"],
                "dst": r["dst"],
                "type": r["type"],
                "properties": r["props"]
            }
            for r in records
        ]


def _query_attack_paths(
    driver,
    limit: int,
    severity: Optional[str] = None,
    provider: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Query attack path edges from Neo4j."""
    cypher = "MATCH (a:Resource)-[r:REL]->(b:Resource) WHERE r.type = 'AttackPath' "
    params: Dict[str, Any] = {"limit": limit}

    if severity:
        cypher += "AND r.severity = $severity "
        params["severity"] = severity
    if provider:
        cypher += "AND a.provider = $provider "
        params["provider"] = provider

    cypher += "RETURN a.id AS src, b.id AS dst, r.type AS type, properties(r) AS props ORDER BY "
    cypher += "CASE r.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END "
    cypher += "LIMIT $limit"

    with driver.session() as session:
        records = session.run(cypher, **params)
        return [
            {
                "src": r["src"],
                "dst": r["dst"],
                "type": r["type"],
                "properties": r["props"]
            }
            for r in records
        ]


def main():
    """Run the CloudHound API server."""
    parser = argparse.ArgumentParser(description="CloudHound API Server")
    parser.add_argument("--uri", default=os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
    parser.add_argument("--user", default=os.environ.get("NEO4J_USER", "neo4j"))
    parser.add_argument("--password", default=os.environ.get("NEO4J_PASSWORD", "letmein123"))
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--no-auth", action="store_true", help="Disable authentication")
    args = parser.parse_args()

    auth_config = None
    if args.no_auth:
        auth_config = AuthConfig(enabled=False)

    app = create_app(args.uri, args.user, args.password, auth_config)
    print(f"CloudHound API starting on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
