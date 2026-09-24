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
import os
import sys
import threading
from collections import OrderedDict

from scovant_core.context import ScanOptions
from scovant_core.engine import scan
from scovant_core.models import Report
from scovant_core.profiles import PROFILES
from scovant_core.report._cta import cta_url
from scovant_core.report.json import render_json
from scovant_core.report.markdown import render_markdown

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


def _medium() -> str:
    """utm_medium for the CTA this server prints. The Claude Code plugin sets
    SCOVANT_CTA_MEDIUM=claude-code in its .mcp.json `env`; anything the CTA
    builder does not know falls back to "mcp" with one stderr line — a bad
    env var must never stop the server from starting."""
    value = os.environ.get("SCOVANT_CTA_MEDIUM", "mcp")
    try:
        cta_url(value)
    except ValueError:
        print(f"scovant mcp: unknown SCOVANT_CTA_MEDIUM {value!r}, using 'mcp'", file=sys.stderr)
        return "mcp"
    return value


_FORMATS = ("findings", "summary", "json", "markdown")


def _run_scan(
    url: str, profile: str, experimental: bool, allow_private_networks: bool = False
) -> tuple[Report, dict]:
    """Returns (report, data). `data` is the full JSON dict and is what the
    ring buffer keeps, whatever shape the caller asked for — so get_finding
    can read any check, including PASSed ones, after a `findings` call."""
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r} — must be one of {PROFILES}")
    if not _SCAN_LOCK.acquire(blocking=False):
        raise RuntimeError("scan in progress — this server runs one scan at a time")
    try:
        report = scan(
            url,
            ScanOptions(profile=profile, experimental=experimental, allow_private_networks=allow_private_networks),
            transport=_TRANSPORT_FACTORY(),
        )
    finally:
        _SCAN_LOCK.release()
    data = json.loads(render_json(report))
    _REPORTS[data["scan_id"]] = data
    while len(_REPORTS) > _RING_SIZE:
        _REPORTS.popitem(last=False)
    return report, data


def _counts(data: dict) -> dict:
    counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "ERROR": 0, "N/A": 0}
    for f in data["findings"]:
        counts[f["status"]] = counts.get(f["status"], 0) + 1
    return counts


def _summary(data: dict) -> dict:
    s, counts = data["score"], _counts(data)
    return {
        "score": s["value"],
        "grade": s["grade"],
        "coverage": s["coverage"],
        "status": s["status"],
        "pass": counts["PASS"],
        "warn": counts["WARN"],
        "fail": counts["FAIL"],
        "error": counts["ERROR"],
        "na": counts["N/A"],
        "scan_id": data["scan_id"],
    }


_SECURITY_DISCLAIMER = "Passive Agentic Security & Trust signals — never scored, not an overall security rating."


def _shape_findings(data: dict, medium: str) -> dict:
    """The plugin's default: everything an agent needs to act, nothing it
    does not — non-PASS findings with their evidence, PASS as ids only.

    SECURITY-category findings (CORE-SECURITY-*) are never scored (see
    `models.Category.SECURITY`/`Report.security`) and must never sit
    interleaved with the readiness `findings` a caller might sort/act on as
    if they carried weight toward the score — they're split into their own
    `security_findings` list with an explicit disclaimer instead."""
    s, t = data["score"], data["target"]
    findings = data["findings"]
    return {
        "scan_id": data["scan_id"],
        "input_url": t["input_url"],
        "final_url": t["final_url"],
        "profile": t["resolved_profile"],
        "score": {
            "value": s["value"], "grade": s["grade"], "coverage": s["coverage"],
            "status": s["status"], "scope": s["scope"],
        },
        "counts": _counts(data),
        "findings": [f for f in findings if f["status"] != "PASS" and f["category"] != "security"],
        "security_findings": [f for f in findings if f["status"] != "PASS" and f["category"] == "security"],
        "security_disclaimer": _SECURITY_DISCLAIMER,
        "passed": [f["id"] for f in findings if f["status"] == "PASS"],
        "cta": cta_url(medium),
    }


def build_server():
    FastMCP = _import_sdk()
    server = FastMCP("scovant-core", instructions=INSTRUCTIONS)
    # FastMCP takes no version; the low-level server would otherwise advertise
    # the mcp SDK's own version in `initialize.serverInfo`. Tell clients ours.
    from scovant_core import __version__  # noqa: PLC0415

    server._mcp_server.version = __version__  # noqa: SLF001

    import scovant_core.checks  # noqa: F401,PLC0415
    from scovant_core.checks.registry import CHECKS  # noqa: PLC0415

    _count = len(CHECKS)

    @server.tool(
        description=(
            f"Passive/static only. Run Scovant Core's {_count} checks against one URL. "
            "format: findings (default — non-PASS findings with evidence, PASS ids only) | "
            "summary | json (full report) | markdown. allow_private_networks lets a "
            "localhost/private entry host be scanned (that host only)."
        ),
    )
    def scan_site(
        url: str,
        profile: str = "auto",
        experimental: bool = False,
        format: str = "findings",
        allow_private_networks: bool = False,
    ) -> str:
        if format not in _FORMATS:
            raise ValueError(f"unknown format {format!r} — must be one of {_FORMATS}")
        report, data = _run_scan(url, profile, experimental, allow_private_networks)
        if format == "json":
            return json.dumps(data, ensure_ascii=False)
        if format == "summary":
            return json.dumps(_summary(data))
        if format == "markdown":
            return render_markdown(report, utm_medium=_medium())
        return json.dumps(_shape_findings(data, _medium()), ensure_ascii=False)

    @server.tool(
        description="Passive/static only. Run the scan and return only the Static Signal Score summary.",
    )
    def get_core_score(url: str, profile: str = "auto") -> str:
        _, d = _run_scan(url, profile, False)
        return json.dumps(_summary(d))

    @server.tool(
        description="Passive/static only. List every check in the registry with category, weight, profiles and experimental flag.",
    )
    def list_checks() -> str:
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
