"""v0.1.1 (audit P0 §5): one purpose-aware registry; the checks and the
robots parser derive their identity lists from it. No literal bot token may
live outside registry/ai_bots.py."""
from __future__ import annotations

import re
from pathlib import Path

from scovant_core.registry import ai_bots as reg

SRC = Path(__file__).resolve().parents[1] / "src" / "scovant_core"


def test_registry_axes_and_version():
    assert reg.REGISTRY_VERSION == "2026.09.13"
    purposes = {b.purpose for b in reg.ALL_CRAWLERS}
    assert purposes == {"search", "user_fetch", "training", "content_use_control"}
    for b in reg.ALL_CRAWLERS:
        assert b.identity_type in ("user_agent", "robots_token")
        assert b.official_source.startswith("https://") and re.fullmatch(r"\d{4}-\d{2}-\d{2}", b.last_reviewed)
    assert {b.token for b in reg.SEARCH_ENGINE_CRAWLERS} == {"Googlebot", "Bingbot"}
    assert len(reg.AI_USER_AGENTS) == 13                      # Cloud pins this to robots.txt


def test_specific_purposes():
    by = {b.token: b for b in reg.ALL_CRAWLERS}
    assert by["ChatGPT-User"].purpose == "user_fetch" and by["Claude-User"].purpose == "user_fetch"
    assert by["Google-Extended"].purpose == "content_use_control" and by["Google-Extended"].identity_type == "robots_token"
    assert by["Applebot-Extended"].identity_type == "robots_token"
    assert by["OAI-SearchBot"].purpose == "search" and by["GPTBot"].purpose == "training"


def test_by_purpose_is_derived():
    assert "OAI-SearchBot" in reg.by_purpose("search") and "Googlebot" in reg.by_purpose("search")
    assert set(reg.by_purpose("user_fetch")) == {"ChatGPT-User", "Claude-User", "Perplexity-User", "DuckAssistBot"}


def test_identities_and_parser_derive_from_registry():
    from scovant_core.checks.access import _identities as ids
    from scovant_core.parsers import robots
    assert set(ids.SEARCH_CRAWLERS) == set(reg.by_purpose("search"))
    assert set(ids.USER_FETCH_CRAWLERS) == set(reg.by_purpose("user_fetch"))
    assert set(ids.TRAINING_CRAWLERS) == set(reg.by_purpose("training"))
    assert set(ids.CONTENT_USE_TOKENS) == set(reg.by_purpose("content_use_control"))
    assert set(robots._AI_AGENTS) == {b.token for b in reg.ALL_CRAWLERS}


def test_no_literal_identity_outside_the_registry():
    tokens = sorted({b.token for b in reg.ALL_CRAWLERS}, key=len, reverse=True)
    pattern = re.compile("|".join(re.escape(t) for t in tokens))
    offenders = []
    for path in list((SRC / "checks").rglob("*.py")) + list((SRC / "parsers").rglob("*.py")) + list((SRC / "analysis").rglob("*.py")):
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#") or '"""' in line:
                continue
            if pattern.search(line):
                offenders.append(f"{path.relative_to(SRC)}:{i}: {line.strip()}")
    assert offenders == [], "\n".join(offenders)
