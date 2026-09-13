"""Crawler identity token groups used by the CORE-ACCESS checks, derived
from the ONE registry (`registry.ai_bots`) — no literal crawler token may be
hand-copied here (see `tests/test_registry_derivation.py`)."""
from __future__ import annotations

from scovant_core.registry.ai_bots import by_purpose

SEARCH_CRAWLERS: tuple[str, ...] = by_purpose("search")
USER_FETCH_CRAWLERS: tuple[str, ...] = by_purpose("user_fetch")
TRAINING_CRAWLERS: tuple[str, ...] = by_purpose("training")
CONTENT_USE_TOKENS: tuple[str, ...] = by_purpose("content_use_control")
