"""CORE-ACCESS-001..011: Access & Discovery checks."""
from __future__ import annotations

from scovant_core.checks.access.core_access_001 import HttpsReachability
from scovant_core.checks.access.core_access_002 import RobotsTxtAvailability
from scovant_core.checks.access.core_access_003 import AiSearchCrawlerPolicy
from scovant_core.checks.access.core_access_004 import TrainingVsSearchSeparation
from scovant_core.checks.access.core_access_005 import SitemapAvailability
from scovant_core.checks.access.core_access_006 import SitemapFreshness
from scovant_core.checks.access.core_access_007 import CanonicalIntegrity
from scovant_core.checks.access.core_access_008 import Indexability
from scovant_core.checks.access.core_access_009 import LlmsTxtIntegrity
from scovant_core.checks.access.core_access_010 import ContentSignalDeclaration
from scovant_core.checks.access.core_access_011 import LlmsTxtUtility

ACCESS_CHECKS = [
    HttpsReachability(),
    RobotsTxtAvailability(),
    AiSearchCrawlerPolicy(),
    TrainingVsSearchSeparation(),
    SitemapAvailability(),
    SitemapFreshness(),
    CanonicalIntegrity(),
    Indexability(),
    LlmsTxtIntegrity(),
    ContentSignalDeclaration(),
    LlmsTxtUtility(),
]

__all__ = ["ACCESS_CHECKS"]
