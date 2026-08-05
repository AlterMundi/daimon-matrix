"""Externally installed Daimon Matrix provider.

The supported host is exactly Hermes 0.19.0.
"""

from pathlib import Path

from daimon_matrix.hermes_body import MatrixMemoryProvider


def register(ctx):
    """Register the exclusive provider through Hermes' supported collector."""

    ctx.register_memory_provider(MatrixMemoryProvider(Path(__file__).parent))
