"""Check registration entry point. Import order matters: `registry` first (so
`CHECKS` exists to be extended), then each category module (which appends its
checks to `registry.CHECKS` at import time). `registry.RULESET_DIGEST` is a
PEP 562 module `__getattr__` that recomputes from the current `CHECKS` on
every access, so no rebuild step is needed here once category modules land."""
from __future__ import annotations

from scovant_core.checks import registry  # noqa: F401 — import first, CHECKS starts empty here
from scovant_core.checks.access import ACCESS_CHECKS
from scovant_core.checks.interfaces import INTERFACES_CHECKS
from scovant_core.checks.machine import MACHINE_CHECKS
from scovant_core.checks.operability import OPERABILITY_CHECKS
from scovant_core.checks.security import SECURITY_CHECKS
from scovant_core.checks.trust import TRUST_CHECKS

registry.CHECKS.extend(ACCESS_CHECKS)
registry.CHECKS.extend(MACHINE_CHECKS)
registry.CHECKS.extend(INTERFACES_CHECKS)
registry.CHECKS.extend(TRUST_CHECKS)
registry.CHECKS.extend(OPERABILITY_CHECKS)
registry.CHECKS.extend(SECURITY_CHECKS)

# This completes the registry of exactly 66 checks (see
# `tests/test_registry.py::test_registry_has_sixty_six`).
