"""Operability & Efficiency checks — completes the registry at 45."""
from __future__ import annotations

from scovant_core.checks.operability.core_operability_001 import ServerRenderedCoreContent
from scovant_core.checks.operability.core_operability_002 import RedirectComplexity
from scovant_core.checks.operability.core_operability_003 import CacheValidators
from scovant_core.checks.operability.core_operability_004 import BrokenMachineEndpoints
from scovant_core.checks.operability.core_operability_005 import AgentParseCost
from scovant_core.checks.operability.core_operability_006 import FormControlLabels
from scovant_core.checks.operability.core_operability_007 import MachineReferenceIntegrity

OPERABILITY_CHECKS = [
    ServerRenderedCoreContent(),
    RedirectComplexity(),
    CacheValidators(),
    BrokenMachineEndpoints(),
    AgentParseCost(),
    FormControlLabels(),
    MachineReferenceIntegrity(),
]

__all__ = ["OPERABILITY_CHECKS"]
