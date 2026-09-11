"""CORE-INTERFACE-001..009 (partial): Agent Interfaces checks."""
from __future__ import annotations

from scovant_core.checks.interfaces.core_interface_001 import McpDiscoveryPresence
from scovant_core.checks.interfaces.core_interface_002 import McpServerDeclarationQuality
from scovant_core.checks.interfaces.core_interface_003 import WebMcpStaticPresence
from scovant_core.checks.interfaces.core_interface_004 import WebMcpToolQuality
from scovant_core.checks.interfaces.core_interface_005 import OpenApiDiscovery
from scovant_core.checks.interfaces.core_interface_006 import OAuthAuthorizationServerMetadata
from scovant_core.checks.interfaces.core_interface_007 import OAuthProtectedResourceMetadata
from scovant_core.checks.interfaces.core_interface_008 import UcpProfilePresence
from scovant_core.checks.interfaces.core_interface_009 import AgentDiscoverySurfacePresence

INTERFACES_CHECKS = [
    McpDiscoveryPresence(),
    McpServerDeclarationQuality(),
    WebMcpStaticPresence(),
    WebMcpToolQuality(),
    OpenApiDiscovery(),
    OAuthAuthorizationServerMetadata(),
    OAuthProtectedResourceMetadata(),
    UcpProfilePresence(),
    AgentDiscoverySurfacePresence(),
]

__all__ = ["INTERFACES_CHECKS"]
