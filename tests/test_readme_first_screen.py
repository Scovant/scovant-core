"""The README's first screen is the only thing most readers see: it must say
what Core is, and — because the whole project's honesty claim rests on it —
what Core is NOT. Pinned here so a rewrite cannot quietly drop either half,
or push them below the fold."""
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
HEAD = "\n".join(_ROOT.joinpath("README.md").read_text(encoding="utf-8").splitlines()[:40])


def test_first_screen_states_what_core_is_and_is_not():
    for phrase in (
        "open-source, evidence-first scanner for passive AI-agent readiness signals on websites",
        "Scovant Core measures what a site declares. Scovant Cloud measures what real agents actually experience.",
        "Core does NOT execute real agents.",
    ):
        assert phrase in HEAD, phrase


def test_contribution_trust_is_stated_publicly():
    readme = _ROOT.joinpath("README.md").read_text(encoding="utf-8")
    method = _ROOT.joinpath("docs", "methodology.md").read_text(encoding="utf-8")
    for doc in (readme, method):
        assert (
            "Client-provided scores are never incorporated directly into authoritative "
            "Scovant research datasets" in doc
        )
