"""Named positive/negative corpus for the HTTP-semantics checks
(CORE-OPERABILITY-008 soft-404, -009 429/Retry-After, -010 challenge-as-200).
Each fixture pins status, severity, evidence keys and a wording fragment, so a
detector change that flips a known negative is a red test, not a surprise."""
import json
from pathlib import Path

import pytest

import scovant_core.gatherers._register  # noqa: F401 — registers http/pages/soft_404/...
from scovant_core.checks.operability.core_operability_008 import UnknownPathsReturn404
from scovant_core.checks.operability.core_operability_009 import RateLimitSignalled
from scovant_core.checks.operability.core_operability_010 import ChallengeServedAs200
from scovant_core.gatherers.soft_404 import PROBE_PREFIX, probe_token
from tests.test_http_semantics import _ctx, _handler, _scan

CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "http-semantics"
CHECKS = {"CORE-OPERABILITY-008": UnknownPathsReturn404, "CORE-OPERABILITY-009": RateLimitSignalled,
          "CORE-OPERABILITY-010": ChallengeServedAs200}
CASES = sorted(p.name for p in CORPUS.iterdir() if (p / "case.json").exists())


def _routes(case_dir: Path, case: dict, scan_id: str) -> tuple[dict, str]:
    # Derived from the scan context, never a literal: the gatherer builds the
    # probe path from `ctx.scan_id`, so hardcoding the token here would make
    # every `@probe` route silently unreachable the day that derivation changes
    # — and a case like `normal-404` would then pass on the handler's catch-all
    # 404 instead of on the route it declares.
    probe_path = f"{PROBE_PREFIX}{probe_token(scan_id)}"
    routes = {}
    routed_probe = "/" + probe_path.lstrip("/")
    for path, r in case["routes"].items():
        body = (case_dir / r["body_file"]).read_text() if "body_file" in r else r.get("body", "")
        routes[routed_probe if path == "@probe" else path] = (r["status"], body, r.get("headers", {}))
    return routes, routed_probe


@pytest.mark.parametrize("name", CASES)
def test_corpus_case(name):
    case_dir = CORPUS / name
    case = json.loads((case_dir / "case.json").read_text())
    ctx = _ctx()
    routes, routed_probe = _routes(case_dir, case, ctx.scan_id)
    store, ctx = _scan(_handler(routes), ctx)
    res = CHECKS[case["check"]]().evaluate(store, ctx)
    exp = case["expected"]
    if case["check"] == "CORE-OPERABILITY-008":
        # The probe the check actually made must be the path this case routed.
        # Otherwise the `@probe` route was never hit and the case passed on the
        # handler's catch-all 404 — which, for `normal-404`, is the expected
        # answer: it would pass while proving nothing.
        assert res.evidence["probed_url"].endswith(routed_probe), (name, res.evidence["probed_url"])
    assert res.status.value == exp["status"], (name, res.summary)
    if "severity" in exp:
        assert res.severity.value == exp["severity"], (name, res.severity)
    for k in exp.get("evidence_keys", []):
        assert k in res.evidence, (name, k, sorted(res.evidence))
    if "summary_contains" in exp:
        assert exp["summary_contains"].lower() in res.summary.lower(), (name, res.summary)


def test_corpus_has_all_twelve_named_cases():
    assert set(CASES) == {"challenge-cloudflare", "challenge-akamai", "akamai-sensor-only", "login-normal",
                          "cookie-consent", "age-gate", "maintenance", "spa-shell", "real-soft-404", "normal-404",
                          "429-with-retry-after", "429-without-retry-after"}


def test_spa_shell_and_real_soft_404_differ_in_status_and_wording():
    shell = json.loads((CORPUS / "spa-shell" / "case.json").read_text())["expected"]
    real = json.loads((CORPUS / "real-soft-404" / "case.json").read_text())["expected"]
    # AND, not OR: a tuple comparison would pass while one half still matched
    assert shell["status"] != real["status"], (shell["status"], real["status"])
    assert shell["summary_contains"] != real["summary_contains"]
