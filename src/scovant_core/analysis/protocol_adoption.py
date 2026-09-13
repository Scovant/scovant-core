"""Descriptive protocol adoption (0.2.0 audit §1): which optional
agent-facing protocols a site publishes, derived from the findings' own
statuses and evidence. This NEVER enters the score — absence of an
optional protocol is not a defect, presence is not a bonus; each check
that feeds this metric already carries its own PASS/WARN/FAIL/N-A/ERROR
scoring semantics independently. States: present | absent | invalid |
not_checked."""
from __future__ import annotations

from scovant_core.models import CheckResult, CheckStatus

PROTOCOLS: tuple[str, ...] = (
    "mcp", "webmcp", "ucp", "llms_txt", "openapi", "oauth", "content_signal", "security_txt",
)

# protocol -> (presence check id, evidence key disambiguating an
# absence-shaped WARN/FAIL from an invalid-shaped one — None when the
# presence check's own N/A branch already covers confirmed absence and no
# such WARN exists, validity check ids that can independently mark a
# present protocol invalid).
#
# Evidence keys below are the REAL key each check emits in its own `ev = {...}`
# (verified by reading each check's source, not assumed from a naming
# convention):
#   CORE-INTERFACE-001 (mcp)            -> "exists"    (discovery["exists"])
#   CORE-INTERFACE-003 (webmcp)         -> no ambiguous WARN; key unused
#   CORE-INTERFACE-005 (openapi)        -> "found_url" (the ONLY check whose
#                                           WARN status can mean either
#                                           "found but invalid" or "not
#                                           found" (api-profile absence WARN)
#                                           — every other check's absence is
#                                           fully resolved by its own N/A
#                                           branch, so its key is unused)
#   CORE-INTERFACE-007 (oauth)          -> no ambiguous WARN; key unused
#   CORE-INTERFACE-008 (ucp)            -> "exists" (unused; no ambiguous WARN)
#   CORE-ACCESS-009 (llms_txt)          -> no ambiguous WARN; key is None
#   CORE-ACCESS-010 (content_signal)    -> "declared" (unused; no ambiguous WARN)
#   CORE-TRUST-006 (security_txt)       -> "found_url" (unused; no ambiguous WARN)
_MAP: dict[str, tuple[str, str | None, tuple[str, ...]]] = {
    "mcp": ("CORE-INTERFACE-001", "exists", ("CORE-INTERFACE-002",)),
    "webmcp": ("CORE-INTERFACE-003", None, ("CORE-INTERFACE-004",)),
    "ucp": ("CORE-INTERFACE-008", "exists", ()),
    "llms_txt": ("CORE-ACCESS-009", None, ()),
    "openapi": ("CORE-INTERFACE-005", "found_url", ()),
    "oauth": ("CORE-INTERFACE-007", None, ("CORE-INTERFACE-006",)),
    "content_signal": ("CORE-ACCESS-010", "declared", ()),
    "security_txt": ("CORE-TRUST-006", "found_url", ()),
}


def _found(r: CheckResult, key: str) -> bool:
    return bool((r.evidence or {}).get(key))


def _state(presence: CheckResult | None, validity: list[CheckResult], key: str | None) -> str:
    if presence is None or presence.status is CheckStatus.ERROR:
        return "not_checked"
    if presence.status is CheckStatus.NA:
        # Two structurally different things both produce N/A: a check's OWN
        # confirmed-absence branch (every one of them passes non-empty
        # evidence — a real HTTP status, a parsed absence signal, ...), and
        # `CoreCheck.run()`'s profile-skip guard (`checks/base.py`), which
        # returns `self.na(f"Not applicable to the {ctx.profile} profile.")`
        # with NO evidence at all whenever `applicable(ctx)` is false — the
        # check never even ran for this site's profile. Reporting the
        # latter as "absent" claims a confirmed absence that was never
        # measured (e.g. CORE-INTERFACE-008/ucp is profile-scoped to
        # commerce; on an api/saas scan it is skipped, not "found absent").
        return "not_checked" if not presence.evidence else "absent"
    if presence.status is CheckStatus.PASS:
        if any(v.status in (CheckStatus.WARN, CheckStatus.FAIL) for v in validity):
            return "invalid"
        return "present"
    if presence.status in (CheckStatus.WARN, CheckStatus.FAIL):
        # A WARN/FAIL presence status is invalid-shaped UNLESS the evidence
        # says the thing was never found in the first place (the -005
        # api-profile "no OpenAPI document discovered" WARN) — the only
        # ambiguous case among the checks feeding this metric; every other
        # check's own N/A branch already fully resolves confirmed absence,
        # so `key` is `None` for them and this disambiguation never applies.
        if key is not None and not _found(presence, key):
            return "absent"
        return "invalid"
    return "not_checked"


def protocol_adoption(findings: list[CheckResult]) -> dict[str, str]:
    """Pure function of `findings` — never reads the score, never needs a
    `Report`."""
    by_id = {f.id: f for f in findings}
    out: dict[str, str] = {}
    for proto in PROTOCOLS:
        pres_id, key, validity_ids = _MAP[proto]
        validity = [by_id[i] for i in validity_ids if i in by_id]
        out[proto] = _state(by_id.get(pres_id), validity, key)
    return out
