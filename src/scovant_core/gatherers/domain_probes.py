"""Gatherers for the four domain probes Technical Readiness reads beyond the
scored Core checks: markdown-for-agents, homepage Link headers, agent payment
protocols and the consolidated machine-representation probe.

Each wraps the shared producer Cloud's crawler also calls, through the guarded
client's probe adapter (redirect-following, size-capped, deadline-aware).
`probe_adapter` kinds: `html` for the two probes that read a homepage body
(markdown negotiation, machine-rep alternates); `text` (1 MiB) for Link headers
(headers only) and agent payments (small JSON documents, the producer caps its
own read at 512 KiB). Only the R2 adapter requests these, so they are never
fetched when the Technical pass is off.
"""
from __future__ import annotations

from scovant_core.context import ScanContext
from scovant_core.evidence import EvidenceStore, register_gatherer
from scovant_core.gatherers.agent_payments import check_agent_payments
from scovant_core.gatherers.link_headers import check_link_headers
from scovant_core.gatherers.machine_rep import check_machine_rep
from scovant_core.gatherers.markdown import check_markdown_negotiation
from scovant_core.security.client import SecureClient


@register_gatherer("markdown_agents")
def gather_markdown_agents(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    return check_markdown_negotiation(client.probe_adapter("html"), ctx.origin or "")


@register_gatherer("link_headers_surface")
def gather_link_headers(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    return check_link_headers(client.probe_adapter("text"), ctx.origin or "")


@register_gatherer("agent_payments_surface")
def gather_agent_payments(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    return check_agent_payments(client.probe_adapter("text"), ctx.origin or "")


@register_gatherer("machine_rep_surface")
def gather_machine_rep(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    http = store.try_get("http") or {}
    return check_machine_rep(client.probe_adapter("html"), ctx.origin or "", http.get("html") or None)
