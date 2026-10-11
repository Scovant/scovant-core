"""Page token cost with a bundled o200k_base tokenizer.

Same measure as the hosted product: `text` = tokens of the visible text,
`skeleton` = tokens of headings + link/button/label texts + input hints,
`total` = their sum. The tokenizer needs the optional `[tokens]` extra
(`tiktoken`); without it `page_token_cost` returns None and the rules that
read the cost are not measured. The BPE vocabulary ships INSIDE the package
(`data/o200k_base.tiktoken`) and the encoding is built from that file —
nothing is ever downloaded at runtime.

The split pattern and special-token ids come from tiktoken (MIT, OpenAI). The
vocabulary file is the unmodified o200k_base file OpenAI publishes; see
THIRD_PARTY_NOTICES.md for its source and provenance.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.resources as ir
from functools import lru_cache

from bs4 import BeautifulSoup

_BPE_SHA256 = "446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d"
# pat_str and special tokens: from tiktoken_ext/openai_public.py (MIT, OpenAI).
_PAT_STR = "|".join([
    r"""[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}]*[\p{Ll}\p{Lm}\p{Lo}\p{M}]+(?i:'s|'t|'re|'ve|'m|'ll|'d)?""",
    r"""[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}]+[\p{Ll}\p{Lm}\p{Lo}\p{M}]*(?i:'s|'t|'re|'ve|'m|'ll|'d)?""",
    r"""\p{N}{1,3}""",
    r""" ?[^\s\p{L}\p{N}]+[\r\n/]*""",
    r"""\s*[\r\n]+""",
    r"""\s+(?!\S)""",
    r"""\s+""",
])
_SPECIAL_TOKENS = {"<|endoftext|>": 199999, "<|endofprompt|>": 200018}


@lru_cache(maxsize=1)
def _encoder():
    """The local o200k_base encoding, or None without the `[tokens]` extra."""
    try:
        import tiktoken  # noqa: PLC0415
    except ImportError:
        return None
    path = ir.files("scovant_core.analysis") / "data" / "o200k_base.tiktoken"
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != _BPE_SHA256:
        return None  # a corrupted vocabulary is "no tokenizer", never a wrong count
    # tiktoken's own loader would route through its download cache; the file
    # is "<base64 token> <rank>" per line, parsed here directly.
    ranks = {base64.b64decode(tok): int(rank)
             for tok, rank in (line.split() for line in data.splitlines() if line)}
    return tiktoken.Encoding(name="o200k_base", pat_str=_PAT_STR, mergeable_ranks=ranks,
                             special_tokens=_SPECIAL_TOKENS)


def tokenizer_available() -> bool:
    return _encoder() is not None


def _count(enc, text: str) -> int:
    return len(enc.encode(text, disallowed_special=())) if text else 0


def _skeleton_text(headings: list[dict], html: str) -> str:
    parts: list[str] = [h.get("text", "") for h in headings]
    soup = BeautifulSoup(html, "lxml")
    for el in soup.find_all(["a", "button", "label"]):
        t = el.get_text(strip=True) or el.get("aria-label") or ""
        if t:
            parts.append(str(t))
    for el in soup.find_all("input"):
        t = el.get("value") or el.get("placeholder") or el.get("aria-label") or ""
        if t:
            parts.append(str(t))
    return "\n".join(p for p in parts if p)


def page_token_cost(visible_text: str, headings: list[dict], html: str) -> dict | None:
    enc = _encoder()
    if enc is None:
        return None
    text_tokens = _count(enc, visible_text)
    skeleton_tokens = _count(enc, _skeleton_text(headings, html))
    return {"total": text_tokens + skeleton_tokens, "text": text_tokens, "skeleton": skeleton_tokens}
