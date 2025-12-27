"""Data normalizers that convert raw cloud data to graph format."""

from cloudhound.core.registry import normalizers

# Import provider modules to register normalizers
from . import aws

__all__ = ["normalizers", "aws"]
