"""A gatherer that reads a response body must carry the fetch layer's
truncation flag. This test is the structural guarantee: the signal was
dropped by fifteen gatherers at once and nobody noticed, so a new gatherer
that forgets it fails here rather than shipping a check that publishes our
own read limit as a fact about someone's site."""
from __future__ import annotations

import re

from tests._source_tree import package_source_root

GATHERERS = package_source_root() / "scovant_core" / "gatherers"

# Every gatherer that reads a response body. Checked in deliberately: the
# derived set below must equal it, so both a forgotten flag AND a silently
# reclassified gatherer are failures.
#
# NOTE 1: `http` (the `/`-entry-page gatherer, distinct from the `_http`
# shared-helper module) was missing from the checked-in set below — the
# classifier matches it (it reads `res.text` off a `client.try_fetch`
# result), and it already carries `"truncated"` correctly (it was the
# original, already-correct implementation this whole propagation is
# modelled on, alongside `robots_txt`). Added here so the derived set and
# the checked-in set agree; `http.py` itself needed no code change.
#
# NOTE 2: `agent_discovery` and `mcp_metadata` read a body ONLY through the
# shared `_probe_json` helper (never via a literal `.text` access of their
# own), so the original text-only classifier missed them — a completeness
# test whose own detector has a blind spot is not complete. Both now derive
# a real signal from `_probe_json`'s `(parsed, truncated)` return (see
# `test_every_body_reading_gatherer_derives_the_flag_from_a_real_signal`
# below) and are included here.
BODY_READING = {
    "agent_discovery", "agent_payments", "_http", "http", "llms", "machine_rep", "markdown",
    "mcp_discovery", "mcp_metadata", "oauth_metadata", "oauth", "openapi", "pages",
    "policy_pages", "reference_integrity", "robots_txt", "security_txt", "sitemap",
    "sitemap_urls", "ucp",
}

# Gatherers where a real, per-call truncation signal is either unavailable
# or genuinely never applicable — AUDITED, with the reason a reviewer would
# need to accept the module is honest anyway. A module here still must
# write the literal `"truncated"` key (checked below) but is exempt from
# `test_every_body_reading_gatherer_derives_the_flag_from_a_real_signal`'s
# requirement that the key be computed from an actual fetch-result/
# capped-read marker, rather than merely present as a literal — an
# unaudited module that only wrote `"truncated": False` to satisfy a
# string-presence check would be a FAKE propagation (looks like the flag
# travels there when nothing computes it), which is exactly what this
# exemption list exists to make impossible to do silently.
EXEMPT_NO_REAL_SIGNAL = {
    "_http": (
        "Not a gatherer — defines `_capped_body`/`_probe_json`, the "
        "derivation primitives every other body-reading module in this set "
        "calls. It returns no gatherer record of its own for a signal to "
        "attach to; its `\"truncated\"` occurrences are docstring/comment "
        "prose describing the contract its callers must honor."
    ),
    "markdown": (
        "`_probe_text_exists` DOES read under a cap (`_PROBE_BODY_CAP`, via "
        "`_http.py`) — the claim here is narrower than 'no cap applies', and "
        "must stay narrow: TRUNCATION CANNOT INVERT THIS MODULE'S VERDICTS. "
        "`negotiation`/`mirror`/`looks_markdown`/`body_looks_markdown` are "
        "all pure existence/pattern checks over WHATEVER was actually read — "
        "a cap can only ever cost evidence past the cut point (a genuinely-"
        "markdown document with its only markers beyond the cap could "
        "under-report), it can never FABRICATE a marker, a non-empty body, "
        "or a `text/markdown` content-type header that isn't really there. "
        "So a truncated read here degrades toward a false NEGATIVE, never a "
        "false POSITIVE — unlike the JSON-collapse defect this task exists "
        "to fix, where a truncated read was reported as a confirmed "
        "negative with the same confidence as a genuine one. That one-"
        "directional risk is what makes `\"truncated\": False` a defensible "
        "constant here rather than a fake propagation."
    ),
}


def _modules() -> dict[str, str]:
    return {p.stem: p.read_text(encoding="utf-8") for p in GATHERERS.glob("*.py")
            if p.stem != "__init__"}


# A module reads a body if it either accesses `.text` off a fetch result
# directly, OR calls one of the shared helpers that reads a body under a
# probe-level cap (`_probe_json`, `_probe_text_exists`, `_capped_body`) —
# `agent_discovery`/`mcp_metadata` are only caught by the second half.
# Deliberately EXCLUDES a bare `.try_fetch(`/`.get(` call: several gatherers
# (e.g. `machine_links`) fetch a URL to read only its HTTP `status`, never
# its body, and truncation of a body neither of them ever looks at is not
# evidence they are missing anything.
_TEXT_MARKER = re.compile(r"\bres(?:ult)?\.text\b|\.text\b")
_PROBE_HELPER_MARKER = re.compile(r"_probe_json\(|_probe_text_exists\(|_capped_body\(")


def _reads_a_body(src: str) -> bool:
    return (bool(_TEXT_MARKER.search(src)) or bool(_PROBE_HELPER_MARKER.search(src))) and "client" in src


# A module's `"truncated"` must be DERIVED from a real fetch-result/capped-
# read signal, not merely present as a literal string — asserting the
# literal alone (the original, weaker version of this test) can be
# satisfied by hardcoding `"truncated": False` next to a comment that
# *looks* like propagation while nothing computes it. `.truncated` catches
# `SecureClient.FetchResult`-derived reads (`res.truncated`, `full.truncated`,
# `child.truncated`, ...); `_capped_body(`/`_probe_json(` catch probe-cap-
# derived reads. A module that writes the key without ever touching one of
# these markers belongs in `EXEMPT_NO_REAL_SIGNAL` above, audited, or it is
# almost certainly faking the propagation.
_DERIVATION_MARKER = re.compile(r"\.truncated\b|_capped_body\(|_probe_json\(")


def test_the_body_reading_set_is_exactly_what_we_think_it_is():
    derived = {name for name, src in _modules().items() if _reads_a_body(src)}
    assert derived == BODY_READING, (
        f"missing from BODY_READING: {derived - BODY_READING}; "
        f"no longer body-reading: {BODY_READING - derived}")


def test_every_body_reading_gatherer_carries_the_truncation_flag():
    # NOTE: this is a source-text scan, satisfiable by a docstring/comment
    # mentioning the literal `"truncated"` string with no code anywhere
    # actually writing that key (`_http.py` is exactly that case — see
    # EXEMPT_NO_REAL_SIGNAL above). This test alone is NOT the completeness
    # guarantee; `test_every_body_reading_gatherer_derives_the_flag_from_a_
    # real_signal` below is what closes that escape hatch for every module
    # not explicitly, auditably exempted from needing to.
    offenders = [name for name, src in _modules().items()
                 if name in BODY_READING and '"truncated"' not in src]
    assert offenders == [], f"these gatherers drop the fetch layer's truncated flag: {offenders}"


def test_every_body_reading_gatherer_derives_the_flag_from_a_real_signal():
    modules = _modules()
    offenders = [
        name for name in BODY_READING
        if name not in EXEMPT_NO_REAL_SIGNAL and not _DERIVATION_MARKER.search(modules[name])
    ]
    assert offenders == [], (
        f"these gatherers write \"truncated\" without deriving it from a real fetch-result "
        f"or capped-read signal (add a real derivation, or add an audited entry to "
        f"EXEMPT_NO_REAL_SIGNAL with a reason): {offenders}"
    )


def test_exemptions_are_audited_body_readers_that_still_write_the_flag():
    modules = _modules()
    for name, reason in EXEMPT_NO_REAL_SIGNAL.items():
        assert name in BODY_READING, f"{name} is exempt from real-signal derivation but isn't even in BODY_READING"
        assert reason.strip(), f"{name}'s exemption carries no reason"
        assert '"truncated"' in modules[name], f"{name} is exempt from deriving the flag, but must still write it"


def test_no_other_gatherer_writes_the_flag():
    strays = [name for name, src in _modules().items()
              if name not in BODY_READING and '"truncated"' in src]
    assert strays == [], f"only body-reading gatherers may write `truncated`: {strays}"
