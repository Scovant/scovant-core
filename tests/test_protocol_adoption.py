"""0.2.0: protocol adoption is descriptive — derived from findings, never scored."""
from scovant_core.analysis.protocol_adoption import PROTOCOLS, protocol_adoption
from scovant_core.models import Category, CheckResult, CheckStatus, Confidence, Severity


def _r(cid, status, **ev):
    return CheckResult(id=cid, title=cid, category=Category.INTERFACES, status=status,
                       severity=Severity.INFO, confidence=Confidence.MEDIUM, weight=1,
                       summary="", evidence=ev)


def test_keys_are_ordered_and_complete():
    assert PROTOCOLS == ("mcp", "webmcp", "ucp", "llms_txt", "openapi", "oauth", "content_signal", "security_txt")
    assert list(protocol_adoption([]).keys()) == list(PROTOCOLS)
    assert set(protocol_adoption([]).values()) == {"not_checked"}


def test_mcp_present_absent_invalid():
    # CORE-INTERFACE-001's real evidence key is "exists" (see
    # `checks/interfaces/core_interface_001.py`'s `ev = {...}`), not "found".
    assert protocol_adoption([_r("CORE-INTERFACE-001", CheckStatus.PASS, exists=True)])["mcp"] == "present"
    assert protocol_adoption([_r("CORE-INTERFACE-001", CheckStatus.NA, exists=False)])["mcp"] == "absent"
    assert protocol_adoption([_r("CORE-INTERFACE-001", CheckStatus.PASS, exists=True),
                              _r("CORE-INTERFACE-002", CheckStatus.WARN, servers_count=1)])["mcp"] == "invalid"
    assert protocol_adoption([_r("CORE-INTERFACE-001", CheckStatus.ERROR)])["mcp"] == "not_checked"


def test_openapi_states():
    assert protocol_adoption([_r("CORE-INTERFACE-005", CheckStatus.PASS, found_url="https://example.com/openapi.json")])["openapi"] == "present"
    assert protocol_adoption([_r("CORE-INTERFACE-005", CheckStatus.WARN, found_url="https://example.com/openapi.json", parseable=False)])["openapi"] == "invalid"
    assert protocol_adoption([_r("CORE-INTERFACE-005", CheckStatus.WARN, found_url=None)])["openapi"] == "absent"   # api profile WARN branch
    assert protocol_adoption([_r("CORE-INTERFACE-005", CheckStatus.NA, found_url=None)])["openapi"] == "absent"


def test_llms_content_signal_security_txt_and_oauth():
    # Real evidence keys: ACCESS-009 -> "valid" (unused here — its own N/A
    # branch already resolves absence), ACCESS-010 -> "declared",
    # TRUST-006 -> "found_url", INTERFACE-007 -> no ambiguous key needed.
    a = protocol_adoption([
        _r("CORE-ACCESS-009", CheckStatus.WARN, valid=False),
        _r("CORE-ACCESS-010", CheckStatus.NA, declared=False),
        _r("CORE-TRUST-006", CheckStatus.PASS, found_url="https://example.com/.well-known/security.txt"),
        _r("CORE-INTERFACE-006", CheckStatus.NA),
        _r("CORE-INTERFACE-007", CheckStatus.PASS, resource_value="https://example.com/"),
    ])
    assert a["llms_txt"] == "invalid" and a["content_signal"] == "absent"
    assert a["security_txt"] == "present" and a["oauth"] == "present"


def test_profile_scoped_na_is_not_checked_not_absent():
    """`CoreCheck`'s `run` method (in checks/base.py) returns `na(f"Not
    applicable to the {ctx.profile} profile.")` with EMPTY evidence whenever a check's
    own `applicable(ctx)` is false — the check never ran for this site's
    profile at all. That is structurally distinct from every check's own
    confirmed-absence N/A branch, which always passes non-empty evidence (a
    real HTTP status, a parsed absence signal, ...). A profile-scoped skip
    must read as `not_checked`, never as a confirmed `absent` the scan never
    actually measured."""
    # CORE-INTERFACE-008 (ucp) is profile-scoped to {commerce}; on an
    # api/saas scan `run()` short-circuits via the branch above — exactly
    # this evidence-less shape.
    skipped = _r("CORE-INTERFACE-008", CheckStatus.NA)
    assert skipped.evidence == {}
    assert protocol_adoption([skipped])["ucp"] == "not_checked"

    # Contrast: the SAME check's own confirmed-absence branch always
    # attaches non-empty evidence (e.g. `{"exists": False, ...}`) — that
    # case must keep reading as "absent".
    confirmed_absent = _r("CORE-INTERFACE-008", CheckStatus.NA, exists=False, found=False)
    assert protocol_adoption([confirmed_absent])["ucp"] == "absent"


def test_never_reads_the_score(monkeypatch):
    # Purely a function of findings: no import of scoring, no Report needed.
    import scovant_core.analysis.protocol_adoption as m
    assert "scoring" not in m.__dict__ and not hasattr(m, "score_results")
