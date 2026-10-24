"""Wave 4 PR-12: the machine-readable catalog and `scovant rules|checks`."""
from __future__ import annotations

import json

import pytest


def test_catalog_ids_match_registries():
    from scovant_core.catalog import build_catalog
    from scovant_core.checks.registry import CHECKS
    from scovant_core.crosswalk import AGENT_ONLY_RULES, counts
    from scovant_core.rules import RULES

    cat = build_catalog()
    assert cat["rule_ids"] == sorted({r.code for r in RULES} | set(AGENT_ONLY_RULES))
    assert cat["check_ids"] == sorted(c.id for c in CHECKS)
    assert cat["counts"] == counts()
    assert len(cat["rules"]) == cat["counts"]["rules"]
    assert len(cat["checks"]) == cat["counts"]["checks"]


def test_technical_scored_follows_the_manifest():
    from scovant_core.catalog import build_catalog
    from scovant_core.r2.manifest import ScoreEffect
    from scovant_core.r2.technical import technical_manifest

    m = technical_manifest()
    for r in build_catalog()["rules"]:
        spec = m.get(r["code"]) if r["code"] in m else None
        want = bool(spec and spec.score_effect == ScoreEffect.WEIGHTED and spec.maturity == "required")
        assert r["technical_scored"] is want, r["code"]
    assert any(r["technical_scored"] for r in build_catalog()["rules"])


def test_agent_only_rules_are_marked_cloud_execution():
    from scovant_core.catalog import build_catalog
    from scovant_core.crosswalk import AGENT_ONLY_RULES

    rows = {r["code"]: r for r in build_catalog()["rules"]}
    for code in AGENT_ONLY_RULES:
        assert rows[code]["evidence_core"] == "cloud_execution_only"
        assert rows[code]["requires_execution"] is True
        assert rows[code]["technical_scored"] is False


def test_cli_rules_json_round_trips(capsys):
    from scovant_core.cli import main

    assert main(["rules", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert [r["code"] for r in data["rules"]] == data["rule_ids"]


def test_cli_checks_text_lists_every_check(capsys):
    from scovant_core.checks.registry import CHECKS
    from scovant_core.cli import main

    assert main(["checks"]) == 0
    out = capsys.readouterr().out
    assert all(c.id in out for c in CHECKS)
    assert "68 checks" in out


@pytest.mark.parametrize("argv", [["rules"], ["rules", "--json"], ["checks"], ["checks", "--json"]])
def test_catalog_commands_make_no_network_calls(argv, monkeypatch, capsys):
    import httpx

    def boom(*a, **k):
        raise AssertionError("network call from a catalog command")

    monkeypatch.setattr(httpx.Client, "send", boom)
    monkeypatch.setattr(httpx.AsyncClient, "send", boom)
    from scovant_core.cli import main

    assert main(argv) == 0
