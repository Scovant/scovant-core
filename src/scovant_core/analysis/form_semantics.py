"""Form-control label-semantics analysis over already-fetched HTML. Pure,
I/O-free.

An input or select is considered labelled when it has an `aria-label`,
`aria-labelledby`, or `title` attribute, is wrapped by a `<label>`, or a
`<label for=id>` referencing its `id` exists elsewhere in the document.
Inputs whose `type` carries no user-facing label semantics of its own
(`hidden`, `submit`, `button`, `reset`, `image`) are excluded from both the
input count and the unlabelled count. A `<button>` is considered named when
it has text content, `aria-label`, `title`, or a `value` attribute.
"""
from __future__ import annotations

from bs4 import BeautifulSoup, Tag

_EXCLUDED_INPUT_TYPES = frozenset({"hidden", "submit", "button", "reset", "image"})


def _is_labelled(el: Tag, soup: BeautifulSoup) -> bool:
    if el.get("aria-label") or el.get("aria-labelledby") or el.get("title"):
        return True
    if el.find_parent("label") is not None:
        return True
    el_id = el.get("id")
    return bool(el_id and soup.find("label", attrs={"for": el_id}) is not None)


def analyse_forms(html: str) -> dict:
    """Return `{forms, inputs, unlabeled_inputs, unnamed_buttons, unlabeled_selects}`."""
    if not html:
        return {"forms": 0, "inputs": 0, "unlabeled_inputs": 0, "unnamed_buttons": 0, "unlabeled_selects": 0}

    soup = BeautifulSoup(html, "lxml")

    inputs = 0
    unlabeled_inputs = 0
    for inp in soup.find_all("input"):
        inp_type = inp.get("type")
        itype = (inp_type if isinstance(inp_type, str) else "text").strip().lower()
        if itype in _EXCLUDED_INPUT_TYPES:
            continue
        inputs += 1
        if not _is_labelled(inp, soup):
            unlabeled_inputs += 1

    unlabeled_selects = sum(1 for sel in soup.find_all("select") if not _is_labelled(sel, soup))

    unnamed_buttons = 0
    for btn in soup.find_all("button"):
        named = bool(btn.get_text(strip=True) or btn.get("aria-label") or btn.get("title") or btn.get("value"))
        if not named:
            unnamed_buttons += 1

    return {
        "forms": len(soup.find_all("form")),
        "inputs": inputs,
        "unlabeled_inputs": unlabeled_inputs,
        "unnamed_buttons": unnamed_buttons,
        "unlabeled_selects": unlabeled_selects,
    }
