"""CORE-OPERABILITY-005: agent parse cost. Reads the `page_metrics` entry
record — an explicit, documented ESTIMATE (`text_chars // token_chars_ratio`,
never a real tokenizer count; see `analysis/page_cost.py`), scaled by
`ScanOptions.token_chars_ratio`."""
from __future__ import annotations

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity

_LOW_MAX_TOKENS = 8_000
_MEDIUM_MAX_TOKENS = 20_000


def _record_band(ev: dict, band: str, truncated: bool) -> None:
    """Write the cost band as a measurement when the body was read in full,
    and as a lower bound (`level: None`) when it was not — see the comment at
    the call sites."""
    if truncated:
        ev["level"], ev["level_at_least"] = None, band
    else:
        ev["level"] = band


class AgentParseCost(CoreCheck):
    id = "CORE-OPERABILITY-005"
    title = "Agent parse cost"
    category = Category.OPERABILITY
    weight = 3
    severity_on_fail = Severity.MEDIUM
    references = ("https://platform.openai.com/docs/guides/text-generation",)
    why_it_matters = "Every token of markup and script an agent parses before reaching real content is budget it can't spend understanding the page — a bloated entry page costs every agent that visits it, on every visit."
    limitations = "`estimated_tokens` is a character-count estimate (chars / token_chars_ratio), never a real tokenizer count, and only the entry page is measured."
    cloud_extension = "Scovant Cloud measures parse cost across the full sampled page set with a real BPE tokenizer."

    def evaluate(self, store, ctx):
        metrics = store.get("page_metrics")
        entry = metrics.get("entry")
        if entry is None:
            return self.error("the entry page's parse-cost metrics are unavailable.", {"entry_url": ctx.final_url})

        tokens = entry["estimated_tokens"]
        ev = {**entry, "token_chars_ratio": ctx.options.token_chars_ratio}
        # `estimated_tokens` is a character count over the entry page's own
        # fetched body (`analysis/page_cost.py`) — a page cut off at the
        # fetch cap DEFLATES that count, which can flip a genuinely bloated
        # page's verdict from WARN to a false PASS. `page_metrics["entry"]`
        # is derived from `pages[0]["parsed"]["page_cost"]` (see
        # `gatherers/page_metrics.py`), so `pages[0]` is exactly the
        # document this verdict is drawn from; `entry is not None` above
        # already guarantees `pages` is non-empty and `pages[0]` parsed.
        pages = store.get("pages")["pages"]
        note, truncated = record_truncation(pages[0], ev, document="entry page")
        conf = truncated_confidence(truncated)

        # A band is a below-threshold CLASSIFICATION — exactly the claim the
        # truncated summary below stops making. Publishing `level: "LOW"`
        # beside a sentence saying the true cost may be higher would leave
        # the over-claim standing in the evidence for any consumer reading
        # that key, so on a partial read the band is reported as a lower
        # bound and `level` itself is `None`: not classifiable, never a
        # band we cannot support (the same "None, never a confident value"
        # discipline the truncation flag itself follows).
        if tokens < _LOW_MAX_TOKENS:
            _record_band(ev, "LOW", truncated)
            return self.result(CheckStatus.PASS, self._pass_summary(tokens, "low", truncated),
                               evidence=ev, confidence=conf)
        if tokens <= _MEDIUM_MAX_TOKENS:
            _record_band(ev, "MEDIUM", truncated)
            return self.result(CheckStatus.PASS, self._pass_summary(tokens, "medium", truncated),
                               evidence=ev, confidence=conf)
        # HIGH is the one band a deflated count cannot overstate: the floor
        # already sits above the top threshold, so the classification holds
        # however much of the body was read.
        ev["level"] = "HIGH"
        # Unlike the PASS branches above, a truncated read here can never
        # invert this verdict's DIRECTION: "high" is already the top band,
        # and a deflated count only ever means the real cost is AT LEAST
        # this bad, never that it was overstated — so the plain generic
        # note (an incomplete-claim caveat, not a wrong-direction one) is
        # honest as-is.
        return self.result(
            CheckStatus.WARN, f"The entry page's estimated parse cost is ~{tokens} tokens (high)." + note, evidence=ev,
            confidence=conf,
            remediation="Reduce markup/script bulk (or split content across pages) so an agent parses less per visit.",
        )

    @staticmethod
    def _pass_summary(tokens: int, level: str, truncated: bool) -> str:
        """A PASS verdict here asserts a below-threshold cost — a claim a
        truncated read cannot honestly make: `estimated_tokens` is deflated
        by a body cut off at the fetch cap, so the true cost may sit above
        this band (even above the HIGH threshold) even though this read's
        count does not. A trailing note ("read only in part") would still
        leave the number itself standing as a below-threshold MEASUREMENT,
        which is a directionally wrong magnitude claim, not merely an
        incomplete one (unlike every other truncation case in this plan —
        see the WARN/HIGH branch above, where the direction is never wrong).
        So the truncated case rephrases the count as a FLOOR instead: no
        status change (still PASS, still this confidence — escalating to
        WARN would manufacture a finding this plan forbids), only the
        sentence stops claiming a measurement it cannot back."""
        if not truncated:
            return f"The entry page's estimated parse cost is ~{tokens} tokens ({level})."
        # The band word is dropped, not merely qualified: "(low)" IS the
        # below-threshold classification this sentence exists to disclaim,
        # and leaving it in restated the over-claim the floor removes.
        return (
            f"The entry page's estimated parse cost is at least ~{tokens} tokens (at least the "
            f"{level} band) — the entry page body exceeded the fetch size cap and was read only "
            "in part, so the true cost may be higher than this count reflects."
        )
