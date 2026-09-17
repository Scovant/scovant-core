"""Security-category checks. `WEB_CHECKS` (CORE-SECURITY-001..006) is the
first family; `MACHINE_DATA_CHECKS` (CORE-SECURITY-007..010) reads the
secret-detection engine in `_secrets.py` over machine-facing surfaces;
`PROMPT_SURFACE_CHECKS` (CORE-SECURITY-011..016) heuristically screens the
same machine-facing surfaces for agent-addressed instruction manipulation."""
from __future__ import annotations

from scovant_core.checks.security.machine_data import MACHINE_DATA_CHECKS
from scovant_core.checks.security.prompt_surface import PROMPT_SURFACE_CHECKS
from scovant_core.checks.security.web import WEB_CHECKS

SECURITY_CHECKS = [*WEB_CHECKS, *MACHINE_DATA_CHECKS, *PROMPT_SURFACE_CHECKS]

__all__ = ["SECURITY_CHECKS"]
