"""CORE-MACHINE-013 + the representations gatherer, and the scovant.com reference fixture."""
from pathlib import Path

from scovant_core.representations.compare import compare, html_facts, markdown_facts
from scovant_core.representations.fetch import variant_verdict

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "representations"
HOME = "https://scovant.com/"


def _f(body, ctype):
    return {"status": 200, "content_type": ctype, "vary": "Accept", "preference_applied": None,
            "bytes": len(body), "latency_ms": 1, "truncated": False, "final_url": HOME,
            "body": body, "error": None}


def test_reference_fixture_scovant_home():
    html = (FIX / "scovant-home.html").read_text()
    md = (FIX / "scovant-home.md").read_text()
    c = compare(html_facts(html, HOME), markdown_facts(md, HOME))
    v = variant_verdict(_f(html, "text/html"), _f(md, "text/markdown; charset=utf-8"),
                        variant="mirror", page_url=HOME)
    assert c["prices"]["applicable"] is True and c["prices"]["missing"] == []
    assert v["status"] == "PASS", (c["links"], c["entities"])


def test_check_registered_experimental_and_in_crosswalk():
    from scovant_core.checks.machine import MACHINE_CHECKS
    from scovant_core.crosswalk import CHECK_ROWS
    check = next(c for c in MACHINE_CHECKS if c.id == "CORE-MACHINE-013")
    assert check.experimental is True and check.verification_mode == "PASSIVE_OBSERVED"
    assert any(r.check_id == "CORE-MACHINE-013" for r in CHECK_ROWS)


class _Store:
    """Minimal stand-in: the check only calls store.get(name)."""
    def __init__(self, data):
        self._d = data

    def get(self, name):
        return self._d[name]


def _store(pages):
    return _Store({"representations": {"attempted": True, "reason": None, "pages": pages}})


def _page(statuses):
    return {"url": HOME, "variants": {k: {"status": s, "reason": None, "compare": None, "fetch": {}}
                                      for k, s in statuses.items()}}


def _eval(store):
    from scovant_core.checks.machine.core_machine_013 import RepresentationParity
    return RepresentationParity().evaluate(store, None)


def test_worst_status_wins_and_all_na_is_na():
    assert _eval(_store([_page({"markdown": "PASS", "mirror": "FAIL", "consolidated": "NA"})])).status == "FAIL"
    assert _eval(_store([_page({"markdown": "PASS", "mirror": "WARN", "consolidated": "NA"})])).status == "WARN"
    assert _eval(_store([_page({"markdown": "PASS", "mirror": "NA", "consolidated": "NA"})])).status == "PASS"
    assert _eval(_store([_page({"markdown": "NA", "mirror": "NA", "consolidated": "NA"})])).status == "N/A"
    err = _eval(_store([_page({"markdown": "NOT_MEASURED", "mirror": "INCONCLUSIVE", "consolidated": "NA"})]))
    assert err.status == "ERROR"


def test_not_attempted_outside_experimental_is_na():
    store = _Store({"representations": {"attempted": False, "reason": "experimental_off", "pages": []}})
    assert _eval(store).status == "N/A"
