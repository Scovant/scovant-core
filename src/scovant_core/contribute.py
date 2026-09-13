"""Opt-in community contribution (product spec §36–37). One POST to one fixed URL, after the scan, never blocking."""
from __future__ import annotations

import contextlib
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from scovant_core.models import Report
from scovant_core.security.policy import CORE_USER_AGENT

CONTRIBUTE_URL = "https://scovant.com/api/public/core/contribute"
_HTTP_FACTORY = lambda: httpx.Client(follow_redirects=False, trust_env=False, headers={"User-Agent": CORE_USER_AGENT})  # noqa: E731


@dataclass(frozen=True)
class ContributeResult:
    ok: bool
    status: int | None
    message: str
    deduplicated: bool = False


def build_payload(report: Report) -> dict:
    host = (urlsplit(report.target.final_url or report.target.input_url).hostname or "").lower()
    s = report.score
    return {
        "domain": host, "timestamp": report.completed_at,
        "core_version": report.core_version, "ruleset_version": report.ruleset_version,
        "ruleset_digest": report.provenance.get("ruleset_digest", ""),
        "profile": report.target.resolved_profile,
        "experimental": bool(report.provenance.get("experimental")),
        "check_statuses": {f.id: f.status.value for f in report.findings},
        "score": {"value": s.value, "grade": s.grade, "coverage": s.coverage, "status": s.status},
        "scan_scope": s.scope, "score_status": s.status,
        "error_count": int(report.metrics.get("error_count", 0)),
    }


def send(payload: dict, *, url: str = CONTRIBUTE_URL, timeout: float = 10.0) -> ContributeResult:
    try:
        with _HTTP_FACTORY() as client:
            resp = client.post(url, json=payload, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 — never raise past the CLI
        return ContributeResult(False, None, f"failed: {type(exc).__name__}")
    if resp.status_code == 503:
        return ContributeResult(False, 503, "failed: contributions are not being accepted right now")
    if resp.status_code // 100 != 2:
        detail = ""
        with contextlib.suppress(Exception):
            detail = str(resp.json().get("detail", ""))
        status = resp.status_code
        return ContributeResult(
            False, status, f"failed: rejected ({status}{(' ' + detail) if detail else ''})"
        )
    body = {}
    with contextlib.suppress(Exception):
        body = resp.json()
    dedup = bool(body.get("deduplicated"))
    return ContributeResult(True, resp.status_code, "deduplicated" if dedup else "accepted", dedup)
