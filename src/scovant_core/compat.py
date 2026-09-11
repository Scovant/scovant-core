"""Optional integration points for embedding hosts.

`SoftTimeLimitExceeded`: when the package runs inside a Celery worker the
host's soft time-limit exception must propagate through the network probes
(they catch broad exceptions to degrade gracefully). Outside Celery the name
resolves to a local class that is never raised, so the same `except
SoftTimeLimitExceeded: raise` clauses are inert.

Type-checking note: whether `celery` is importable is a property of the
environment, not of this package (it is not a dependency, and a Cloud
checkout has it installed). The import errors are therefore switched off for
this module in `pyproject.toml` rather than with an inline `type: ignore`,
which would itself be flagged as unused in the environment where celery is
absent — `mypy src` is clean both with and without celery installed.
"""
from __future__ import annotations

try:  # pragma: no cover - exercised only inside a Celery host
    from celery.exceptions import SoftTimeLimitExceeded
except ImportError:  # pragma: no cover

    class SoftTimeLimitExceeded(Exception):  # type: ignore[no-redef]
        """Placeholder raised by nobody outside a Celery host."""


__all__ = ["SoftTimeLimitExceeded"]
