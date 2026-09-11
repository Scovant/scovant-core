"""CORE-TRUST-001..007: Trust & Commerce checks."""
from __future__ import annotations

from scovant_core.checks.trust.core_trust_001 import ContactDiscoverability
from scovant_core.checks.trust.core_trust_002 import ShippingPolicyDiscoverability
from scovant_core.checks.trust.core_trust_003 import ReturnsPolicyDiscoverability
from scovant_core.checks.trust.core_trust_004 import PrivacyPolicyDiscoverability
from scovant_core.checks.trust.core_trust_005 import TermsDiscoverability
from scovant_core.checks.trust.core_trust_006 import SecurityTxtDiscoverability
from scovant_core.checks.trust.core_trust_007 import PricingDiscoverability

TRUST_CHECKS = [
    ContactDiscoverability(),
    ShippingPolicyDiscoverability(),
    ReturnsPolicyDiscoverability(),
    PrivacyPolicyDiscoverability(),
    TermsDiscoverability(),
    SecurityTxtDiscoverability(),
    PricingDiscoverability(),
]

__all__ = ["TRUST_CHECKS"]
