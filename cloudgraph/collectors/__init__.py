"""Cloud resource collectors."""

from cloudgraph.core.registry import collectors

# Import provider modules to register collectors
from . import aws

__all__ = ["collectors", "aws"]
