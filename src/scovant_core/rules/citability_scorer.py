"""Deterministic per-block citability scorer: how readily an AI answer engine
can quote a passage on its own.

Pure: no I/O. A block (one heading-bounded passage, see
`parsers.html.extract_content_blocks`) earns points on five dimensions:

1. self-containment — length (134–167 words is best) and, with a term
   pack, how little it leans on pronouns;
2. statistical density — percentages, money amounts, a year, several
   numbers, and (pack) a cited source;
3. structural readability — average sentence length, a numbered list, line
   breaks, and (pack) transition words and Flesch reading ease;
4. answer quality — a question heading, a figure in the first 60 words,
   and (pack) a definition;
5. uniqueness (pack only) — first-hand research or worked examples.

Language-neutral signals work in any language; pack signals need a term
pack (`citability_terms`). Without one they are skipped AND left out of the
maximum, never scored as 0. The block total is the earned share of the
available points, 0–100, rounded to one decimal; a page scores the mean of
its five best blocks.
"""
from __future__ import annotations

import re

from scovant_core.rules.citability_terms import get_pack

_PCT = re.compile(r"\d+(?:\.\d+)?\s*%")
_YEAR = re.compile(r"\b20[0-3]\d\b")
_CURRENCY = re.compile(r"(?:[$€£¥₽₩₹]|\b(?:usd|eur|gbp|jpy|rub|cny|inr)\b)\s?\d", re.IGNORECASE)
_NUMBER = re.compile(r"\b\d[\d,. ]*\d\b")
_LIST_MARKER = re.compile(r"(?:^|\s)\d+[.)]\s")
_CJK = re.compile(r"[一-鿿぀-ヿ가-힯]")
_VOWEL_GROUP = re.compile(r"[aeiouyаеёиоуыэюя]+", re.IGNORECASE)


def _is_cjk(text: str) -> bool:
    return bool(_CJK.search(text))


def _word_count(text: str) -> int:
    if _is_cjk(text):
        return len(_CJK.findall(text)) + len(re.findall(r"[A-Za-z]+", text))
    return len(text.split())


def _sentences(text: str) -> list[str]:
    return [s for s in re.split(r"[.!?。！？]+", text) if s.strip()]


def _syllables(word: str) -> int:
    return max(len(_VOWEL_GROUP.findall(word)), 1)


def _flesch_reading_ease(
    text: str, coefficients: tuple[float, float, float] = (206.835, 1.015, 84.6)
) -> float:
    """Flesch reading-ease score with a vowel-group syllable estimate.

    ``coefficients`` is ``(c0, c1, c2)`` in ``c0 - c1*ASL - c2*ASW``; the
    default is the classic English set, and a term pack may carry its own
    (the Russian pack uses Oborneva's adaptation).
    """
    sents = _sentences(text)
    words = text.split()
    if not sents or not words:
        return 0.0
    c0, c1, c2 = coefficients
    asl = len(words) / len(sents)
    asw = sum(_syllables(w) for w in words) / len(words)
    return c0 - c1 * asl - c2 * asw


class _Acc:
    """Accumulates (earned, max) point pairs; pack signals add nothing when there is no pack."""

    def __init__(self) -> None:
        self.earned = 0.0
        self.max = 0.0

    def add(self, earned: float, maximum: float) -> None:
        self.earned += earned
        self.max += maximum

    def final(self) -> float:
        if self.max <= 0:
            return 0.0
        return round(self.earned / self.max * 100.0, 1)


def _contains_any(haystack: str, needles: list[str]) -> bool:
    return any(n in haystack for n in needles)


def _count_any(haystack: str, needles: list[str]) -> int:
    return sum(haystack.count(n) for n in needles)


def score_block(text: str, heading: str | None, page_language: str | None) -> dict:
    pack = get_pack(page_language)
    lower = text.lower()
    wc = _word_count(text)
    sents = _sentences(text)
    acc = _Acc()

    # --- Dim 1: Self-containment & length (neutral 15 + overlay pronouns 10) ---
    if 134 <= wc <= 167:
        band = 15.0
    elif 100 <= wc <= 200:
        band = 11.0
    elif 80 <= wc <= 250:
        band = 6.0
    elif wc < 30 or wc > 400:
        band = 0.0
    else:
        band = 3.0
    acc.add(band, 15.0)
    if pack is not None:
        pron = _count_any(" " + lower + " ", [" " + p + " " for p in pack["pronouns"]])
        ratio = pron / wc if wc else 1.0
        acc.add(10.0 if ratio < 0.02 else 6.0 if ratio < 0.04 else 3.0 if ratio < 0.06 else 0.0, 10.0)

    # --- Dim 2: Statistical density (neutral 16 + overlay source markers 4) ---
    sd = min(len(_PCT.findall(text)) * 3, 6) + min(len(_CURRENCY.findall(text)) * 3, 5)
    sd += 3 if _YEAR.search(text) else 0
    sd += 2 if len(_NUMBER.findall(text)) >= 2 else 0
    acc.add(min(sd, 16.0), 16.0)
    if pack is not None:
        acc.add(4.0 if _contains_any(lower, pack["source_markers"]) else 0.0, 4.0)

    # --- Dim 3: Structural readability ---
    # A pack with Flesch coefficients splits the structural points 4/3/3
    # (cap 10) so the 6-point Flesch overlay keeps the dimension at 20; any
    # other block keeps the 8/4/4 split (cap 16).
    has_flesch = pack is not None and bool(pack.get("flesch_coefficients"))
    _d3_avg, _d3_list, _d3_nl, _d3_cap = (4.0, 3.0, 3.0, 10.0) if has_flesch else (8.0, 4.0, 4.0, 16.0)
    sr = 0.0
    if sents:
        avg = wc / len(sents)
        sr += _d3_avg if 10 <= avg <= 25 else _d3_avg * 0.625 if 8 <= avg <= 30 else _d3_avg * 0.25
    sr += _d3_list if _LIST_MARKER.search(text) else 0.0
    sr += _d3_nl if "\n" in text else 0.0
    acc.add(min(sr, _d3_cap), _d3_cap)
    if pack is not None:
        acc.add(4.0 if _contains_any(lower, pack["transition_words"]) else 0.0, 4.0)
    if pack is not None and pack.get("flesch_coefficients"):
        fre = _flesch_reading_ease(text, pack["flesch_coefficients"])
        acc.add(6.0 if fre >= 60 else 4.0 if fre >= 45 else 2.0 if fre >= 30 else 0.0, 6.0)

    # --- Dim 4: Answer-block quality (neutral 13 + overlay definitions 12) ---
    ab = 0.0
    if heading and heading.strip().endswith(("?", "？")):
        ab += 7.0
    first = " ".join(text.split()[:60]).lower()
    if _PCT.search(first) or _YEAR.search(first) or re.search(r"\b\d", first):
        ab += 6.0
    acc.add(min(ab, 13.0), 13.0)
    if pack is not None:
        acc.add(12.0 if _contains_any(" " + lower + " ", pack["definition_markers"]) else 0.0, 12.0)

    # --- Dim 5: Uniqueness (overlay-only 10) ---
    if pack is not None:
        acc.add(10.0 if _contains_any(lower, pack["research_markers"]) else 0.0, 10.0)

    total = acc.final()
    grade = "A" if total >= 80 else "B" if total >= 65 else "C" if total >= 50 else "D" if total >= 35 else "F"
    return {"total": total, "grade": grade, "breakdown": {"word_count": wc}}


def page_citability(blocks: list[dict], page_language: str | None) -> float:
    """The page's citability: the mean of its five best block totals, 0 with no blocks."""
    if not blocks:
        return 0.0
    scores = sorted(
        (score_block(b["text"], b.get("heading"), page_language)["total"] for b in blocks),
        reverse=True,
    )
    top = scores[:5]
    return round(sum(top) / len(top), 1)
