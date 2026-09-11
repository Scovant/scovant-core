"""Visible-price extraction and numeric normalisation over already-fetched
page text. Pure, I/O-free.

`find_visible_prices` is deliberately conservative: it only matches text
that pairs a digit run with a currency symbol or a recognised ISO-4217-ish
currency code, so a bare date (`2026-09-05`) or version string (`v1.2.3`)
never matches — neither carries a currency marker.
"""
from __future__ import annotations

import re

_CURRENCY_SYMBOLS = "$€£¥"
_CURRENCY_CODES = "USD|EUR|GBP|UAH|PLN|CZK|JPY|CHF"

_PRICE_PATTERN = re.compile(
    rf"(?:[{_CURRENCY_SYMBOLS}]\s?\d[\d.,]*|\d[\d.,]*\s?(?:{_CURRENCY_CODES}))"
)

MAX_VISIBLE_PRICES = 20


def find_visible_prices(text: str, limit: int = MAX_VISIBLE_PRICES) -> list[str]:
    """Return up to `limit` visible-text price-shaped matches, in the order
    they appear. Never raises; empty/`None` text yields an empty list."""
    if not text:
        return []
    return _PRICE_PATTERN.findall(text)[:limit]


def parse_price_value(s: str) -> float | None:
    """Best-effort numeric normalisation of a price-shaped string, handling
    both comma-thousands/period-decimal (`1,299.00`) and period-thousands/
    comma-decimal (`1.299,00`) conventions, plain decimals (`19.99`), and
    space-thousands (`1 299`). Returns `None` when the result isn't a valid
    number rather than raising."""
    if not s:
        return None
    cleaned = re.sub(r"[^\d.,\s]", "", str(s)).strip()
    if not cleaned:
        return None

    has_comma = "," in cleaned
    has_dot = "." in cleaned

    if has_comma and has_dot:
        decimal_sep = "," if cleaned.rfind(",") > cleaned.rfind(".") else "."
        thousands_sep = "." if decimal_sep == "," else ","
        cleaned = cleaned.replace(thousands_sep, "").replace(" ", "")
        cleaned = cleaned.replace(decimal_sep, ".")
    elif has_comma or has_dot:
        sep = "," if has_comma else "."
        parts = cleaned.split(sep)
        # A single separator with a short (<=2 digit) trailing group reads as
        # a decimal point; anything else (multiple groups, or a longer
        # trailing group) reads as a thousands separator.
        if len(parts) == 2 and len(parts[1]) <= 2:
            cleaned = parts[0].replace(" ", "") + "." + parts[1]
        else:
            cleaned = cleaned.replace(sep, "").replace(" ", "")
    else:
        cleaned = cleaned.replace(" ", "")

    try:
        return float(cleaned)
    except ValueError:
        return None
