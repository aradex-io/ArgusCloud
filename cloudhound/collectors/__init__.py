"""Cloud resource collectors."""

from cloudhound.core.registry import collectors

# Import provider modules to register collectors
from . import aws

__all__ = ["collectors", "aws"]
