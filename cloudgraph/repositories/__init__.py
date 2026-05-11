"""CloudGraph repository layer for database abstraction.

This module provides an abstraction layer between the API and the
database, making it easier to test, maintain, and potentially
swap database implementations.
"""

from cloudgraph.repositories.base import (
    GraphRepository,
    NodeFilter,
    ProfileData,
)
from cloudgraph.repositories.neo4j_repository import Neo4jGraphRepository

__all__ = [
    "GraphRepository",
    "NodeFilter",
    "ProfileData",
    "Neo4jGraphRepository",
]
