"""Per-language term packs for the citability scorer.

Full packs ship for English (`en`) and Russian (`ru`). Every other language
is scored on the language-neutral signals only: `get_pack` returns None, and
the scorer then skips the pack signals AND leaves their points out of the
maximum, so an unsupported language is never scored as if it had failed
them.

A pack lists definition markers, transition words, pronouns (a passage that
leans on them is not self-contained), source markers and first-hand
research markers. `flesch_coefficients` is `(c0, c1, c2)` for the Flesch
reading-ease overlay `c0 - c1*ASL - c2*ASW` (average sentence length,
average syllables per word); a pack without it skips that overlay. The
syllable count is a Latin/Cyrillic vowel-group estimate, meaningless for
CJK scripts, so a CJK pack must never carry the key.
"""
from __future__ import annotations

TermPack = dict  # {definition_markers, transition_words, pronouns, source_markers, research_markers[, flesch_coefficients]}

_PACKS: dict[str, TermPack] = {
    "en": {
        "definition_markers": [
            " is a ", " is an ", " is the ", " are a ", " refers to ",
            " means ", " defined as ", " in other words", " in simple terms",
        ],
        "transition_words": [
            "first", "second", "third", "finally", "additionally",
            "moreover", "furthermore", "however", "for example", "in addition",
        ],
        "pronouns": [
            "it", "they", "them", "their", "this", "that", "these",
            "those", "he", "she", "his", "her",
        ],
        "source_markers": [
            "according to", "research shows", "studies show", "studies indicate",
            "data shows", "report found", "survey found", "as reported by",
        ],
        "research_markers": [
            "our study", "our research", "our data", "our analysis",
            "we found", "we analyzed", "we surveyed", "case study",
            "for example", "for instance", "in practice", "real-world",
        ],
        "flesch_coefficients": (206.835, 1.015, 84.6),
    },
    "ru": {
        "definition_markers": [
            " это ", " является ", " означает", " называется", " представляет собой",
            " определяется как", " другими словами", " проще говоря",
        ],
        "transition_words": [
            "во-первых", "во-вторых", "в-третьих", "наконец", "кроме того",
            "более того", "однако", "например", "к тому же", "таким образом",
        ],
        "pronouns": [
            "он", "она", "оно", "они", "их", "его", "её", "ее",
            "это", "эти", "тот", "та", "те", "который", "которая",
        ],
        "source_markers": [
            "по данным", "согласно", "исследование показывает", "исследования показывают",
            "данные показывают", "как сообщает", "по информации",
        ],
        "research_markers": [
            "наше исследование", "наши данные", "наш анализ", "мы обнаружили",
            "мы проанализировали", "например", "к примеру", "на практике",
            "из практики", "реальный пример",
        ],
        "flesch_coefficients": (206.835, 1.3, 60.1),
    },
}


def get_pack(lang: str | None) -> TermPack | None:
    """Return the TermPack for a language code, or None if unsupported."""
    if not lang:
        return None
    return _PACKS.get(lang.strip().lower())
