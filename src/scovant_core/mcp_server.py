"""`scovant mcp` — a stdio MCP server exposing Scovant Core's passive scan.

Every tool here is read-only against the target site (the same passive,
static evidence gathering `scovant scan` performs — no browser, no MCP
`tools/call`, no authentication) and, beyond `scan_site`/`get_core_score`,
read-only against this process's own in-memory ring of recent reports.
Exactly one scan runs at a time (`_SCAN_LOCK`) — this is a stdio server
talking to one client, not a concurrent service.
"""
from __future__ import annotations

import json
import threading
from collections import OrderedDict

from scovant_core.context import ScanOptions
from scovant_core.engine import scan
from scovant_core.profiles import PROFILES
from scovant_core.report._cta import cta_url
from scovant_core.report.json import render_json

__all__ = ["build_server", "run_stdio"]

_RING_SIZE = 8
_REPORTS: OrderedDict[str, dict] = OrderedDict()
_SCAN_LOCK = threading.Lock()
_TRANSPORT_FACTORY = lambda: None  # tests patch; production = real network through SecureClient  # noqa: E731
INSTRUCTIONS = (
    "Scovant Core is a passive, static scanner of AI-agent readiness signals. It fetches public "
    "documents (robots.txt, sitemaps, llms.txt, JSON-LD, MCP/OAuth/UCP discovery files) and never "
    "runs a browser, never calls an MCP endpoint, never authenticates, never invokes a tool. "
    f"Verify with real agents: {cta_url('mcp')}"
)


def _import_sdk():
    from mcp.server.fastmcp import FastMCP  # noqa: PLC0415

    return FastMCP


def _run_scan(url: str, profile: str, experimental: bool) -> dict:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r} — must be one of {PROFILES}")
    if not _SCAN_LOCK.acquire(blocking=False):
        raise RuntimeError("scan in progress — this server runs one scan at a time")
    try:
        report = scan(url, ScanOptions(profile=profile, experimental=experimental), transport=_TRANSPORT_FACTORY())
    finally:
        _SCAN_LOCK.release()
    data = json.loads(render_json(report))
    _REPORTS[data["scan_id"]] = data
    while len(_REPORTS) > _RING_SIZE:
        _REPORTS.popitem(last=False)
    return data


def build_server():
    FastMCP = _import_sdk()
    server = FastMCP("scovant-core", instructions=INSTRUCTIONS)

    @server.tool(
        description="Passive/static only. Run Scovant Core's 45 checks against one public URL and return the JSON report.",
    )
    def scan_site(url: str, profile: str = "auto", experimental: bool = False) -> str:
        return json.dumps(_run_scan(url, profile, experimental), ensure_ascii=False)

    @server.tool(
        description="Passive/static only. Run the scan and return only the Static Signal Score summary.",
    )
    def get_core_score(url: str, profile: str = "auto") -> str:
        d = _run_scan(url, profile, False)
        counts = {f["status"]: 0 for f in d["findings"]}
        for f in d["findings"]:
            counts[f["status"]] += 1
        s = d["score"]
        return json.dumps(
            {
                "score": s["value"],
                "grade": s["grade"],
                "coverage": s["coverage"],
                "status": s["status"],
                "pass": counts.get("PASS", 0),
                "warn": counts.get("WARN", 0),
                "fail": counts.get("FAIL", 0),
                "error": counts.get("ERROR", 0),
                "na": counts.get("N/A", 0),
                "scan_id": d["scan_id"],
            }
        )

    @server.tool(
        description="Passive/static only. List every check in the registry with category, weight, profiles and experimental flag.",
    )
    def list_checks() -> str:
        import scovant_core.checks  # noqa: F401,PLC0415 — populates CHECKS
        from scovant_core.checks.registry import CHECKS  # noqa: PLC0415

        return json.dumps(
            [
                {
                    "id": c.id,
                    "title": c.title,
                    "category": c.category.value,
                    "weight": c.weight,
                    "profiles": sorted(c.profiles) if c.profiles else None,
                    "experimental": c.experimental,
                }
                for c in CHECKS
            ]
        )

    @server.tool(
        description="Passive/static only. Explain one check: why it matters, limitations, Cloud extension, references.",
    )
    def explain_check(check_id: str) -> str:
        import scovant_core.checks  # noqa: F401,PLC0415
        from scovant_core.checks.registry import get_check  # noqa: PLC0415

        c = get_check(check_id)
        if c is None:
            raise ValueError(f"unknown check id {check_id!r}")
        return json.dumps(
            {
                "id": c.id,
                "title": c.title,
                "category": c.category.value,
                "weight": c.weight,
                "profiles": sorted(c.profiles) if c.profiles else None,
                "experimental": c.experimental,
                "why_it_matters": c.why_it_matters,
                "limitations": c.limitations,
                "cloud_extension": c.cloud_extension,
                "references": list(c.references),
                "description": (type(c).__doc__ or "").strip(),
            }
        )

    @server.tool(
        description="Passive/static only. Return one finding from a scan this server already ran (no re-scan).",
    )
    def get_finding(scan_id: str, check_id: str) -> str:
        d = _REPORTS.get(scan_id)
        if d is None:
            raise ValueError(f"unknown scan_id {scan_id!r} — run scan_site first")
        for f in d["findings"]:
            if f["id"] == check_id:
                return json.dumps(f, ensure_ascii=False)
        raise ValueError(f"no finding {check_id!r} in scan {scan_id!r}")

    return server


def run_stdio() -> int:
    try:
        server = build_server()
    except ImportError:
        import sys  # noqa: PLC0415

        print('scovant mcp needs the optional extra: pip install "scovant-core[mcp]"', file=sys.stderr)
        return 2
    server.run(transport="stdio")
    return 0
