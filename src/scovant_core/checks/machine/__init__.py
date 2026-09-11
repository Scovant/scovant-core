"""CORE-MACHINE-001..012: Machine Understanding checks."""
from __future__ import annotations

from scovant_core.checks.machine.core_machine_001 import JsonLdParseability
from scovant_core.checks.machine.core_machine_002 import OrganizationEntity
from scovant_core.checks.machine.core_machine_003 import WebSiteOrPageEntity
from scovant_core.checks.machine.core_machine_004 import ProductStructuredData
from scovant_core.checks.machine.core_machine_005 import OfferCompleteness
from scovant_core.checks.machine.core_machine_006 import ProductIdentifierCount
from scovant_core.checks.machine.core_machine_007 import Breadcrumbs
from scovant_core.checks.machine.core_machine_008 import MetadataQuality
from scovant_core.checks.machine.core_machine_009 import HeadingStructure
from scovant_core.checks.machine.core_machine_010 import LanguageDeclaration
from scovant_core.checks.machine.core_machine_011 import ImageAltCoverage
from scovant_core.checks.machine.core_machine_012 import VisibleVsStructuredPrice

MACHINE_CHECKS = [
    JsonLdParseability(),
    OrganizationEntity(),
    WebSiteOrPageEntity(),
    ProductStructuredData(),
    OfferCompleteness(),
    ProductIdentifierCount(),
    Breadcrumbs(),
    MetadataQuality(),
    HeadingStructure(),
    LanguageDeclaration(),
    ImageAltCoverage(),
    VisibleVsStructuredPrice(),
]

__all__ = ["MACHINE_CHECKS"]
