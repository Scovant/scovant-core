"""Operability & Efficiency checks — completes the registry at 50."""
from __future__ import annotations

from scovant_core.checks.operability.core_operability_001 import ServerRenderedCoreContent
from scovant_core.checks.operability.core_operability_002 import RedirectComplexity
from scovant_core.checks.operability.core_operability_003 import CacheValidators
from scovant_core.checks.operability.core_operability_004 import BrokenMachineEndpoints
from scovant_core.checks.operability.core_operability_005 import AgentParseCost
from scovant_core.checks.operability.core_operability_006 import FormControlLabels
from scovant_core.checks.operability.core_operability_007 import MachineReferenceIntegrity
from scovant_core.checks.operability.core_operability_008 import UnknownPathsReturn404
from scovant_core.checks.operability.core_operability_009 import RateLimitSignalled
from scovant_core.checks.operability.core_operability_010 import ChallengeServedAs200
from scovant_core.checks.operability.core_operability_011 import DiscoveryLinkage

OPERABILITY_CHECKS = [
    ServerRenderedCoreContent(),
    RedirectComplexity(),
    CacheValidators(),
    BrokenMachineEndpoints(),
    AgentParseCost(),
    FormControlLabels(),
    MachineReferenceIntegrity(),
    UnknownPathsReturn404(),
    RateLimitSignalled(),
    ChallengeServedAs200(),
    DiscoveryLinkage(),
]

__all__ = ["OPERABILITY_CHECKS"]
