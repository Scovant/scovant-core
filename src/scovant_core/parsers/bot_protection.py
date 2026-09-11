"""Bot-protection / anti-bot detection from an already-fetched HTTP response."""
from __future__ import annotations

import re
from typing import Any

# Cloudflare challenge indicators
_CF_BODY_PATTERNS = [
    re.compile(r"cf-browser-verification", re.I),
    re.compile(r"just a moment\.\.\.", re.I),
    re.compile(r"checking your browser", re.I),
    re.compile(r"enable javascript and cookies", re.I),
]

# CAPTCHA WIDGET markers — only present when a captcha is actually embedded
# (a real wall). Safe to flag regardless of page size.
_CAPTCHA_WIDGET_PATTERNS = [
    re.compile(r"g-recaptcha", re.I),
    re.compile(r"grecaptcha\.(?:execute|render|ready)", re.I),
    re.compile(r"(?:www\.google\.com|recaptcha\.net)/recaptcha", re.I),
    re.compile(r"recaptcha/api\.js", re.I),
    re.compile(r"\bh-captcha\b", re.I),
    re.compile(r"(?:js\.)?hcaptcha\.com", re.I),
    re.compile(r"data-sitekey=", re.I),
    re.compile(r"cf-turnstile|challenges\.cloudflare\.com", re.I),
]

# Bare-word CAPTCHA mentions — only meaningful on a small challenge/interstitial
# page, NOT on a content-rich page that merely discusses captchas in copy.
_CAPTCHA_BODY_PATTERNS = [
    re.compile(r"\bcaptcha\b", re.I),
    re.compile(r"\bhcaptcha\b", re.I),
    re.compile(r"\brecaptcha\b", re.I),
]

# A genuine challenge/interstitial page is tiny. Above this many chars of
# visible text, body-keyword heuristics are treated as ordinary content.
_INTERSTITIAL_MAX_VISIBLE_CHARS = 400

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def _visible_text_len(body: str) -> int:
    """Approximate visible-text length of an HTML body (tags stripped)."""
    stripped = _TAG_RE.sub(" ", body or "")
    return len(_WS_RE.sub(" ", stripped).strip())


# WAF/CDN headers that indicate bot protection
_WAF_HEADERS = {
    "cf-ray": "cloudflare",
    "x-sucuri-id": "waf",
    "x-sucuri-cache": "waf",
    "x-protected-by": "waf",
    "x-firewall-protection": "waf",
}


def _augment_cf_fields(result: dict[str, Any], lower_headers: dict[str, str]) -> dict[str, Any]:
    """Copy cf-ray/provider observability fields onto a detect_bot_protection
    result when a cf-ray header is present, without touching the existing
    return shape for non-cloudflare cases.

    - cf_ray + provider="cloudflare" are added whenever the cf-ray header is
      present, block or not (pure observability).
    - layer="edge_security" + retry_recommended=False are added only when the
      response is blocked — a verified-bot signature doesn't bypass Cloudflare's
      edge security layer, so retrying with the same identity is futile.
    """
    cf_ray = lower_headers.get("cf-ray")
    if cf_ray:
        result["cf_ray"] = cf_ray
        result["provider"] = "cloudflare"
        if result.get("blocked"):
            result["layer"] = "edge_security"
            result["retry_recommended"] = False
    return result


def detect_bot_protection(
    http_status: int,
    headers: dict[str, str],
    body: str,
    user_agent_type: str,
) -> dict[str, Any]:
    """Detect bot protection mechanisms from an HTTP response.

    Args:
        http_status: HTTP response status code.
        headers: Response headers dict (keys case-insensitive in practice).
        body: Response body text.
        user_agent_type: "browser" | "ai_crawler"

    Returns:
        {
            "blocked": bool,
            "protection_type": str | None,  e.g. "cloudflare", "captcha", "waf", "http_block"
            "details": str | None,
            "cf_ray": str | None,        # present only when a cf-ray header was seen
            "provider": str | None,      # "cloudflare" when a cf-ray header was seen
            "layer": str | None,         # "edge_security" on a cloudflare block
            "retry_recommended": bool | None,  # False on a cloudflare block
        }
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}

    # --- CAPTCHA widget actually embedded (real wall, any page size) ---
    for pat in _CAPTCHA_WIDGET_PATTERNS:
        if pat.search(body):
            return _augment_cf_fields({
                "blocked": True,
                "protection_type": "captcha",
                "details": "CAPTCHA widget detected in response body",
            }, lower_headers)

    # --- Interstitial body-text heuristics (only on small challenge pages) ---
    if _visible_text_len(body) <= _INTERSTITIAL_MAX_VISIBLE_CHARS:
        if any(pat.search(body) for pat in _CF_BODY_PATTERNS):
            return _augment_cf_fields({
                "blocked": True,
                "protection_type": "cloudflare",
                "details": "Cloudflare browser challenge page detected",
            }, lower_headers)
        for pat in _CAPTCHA_BODY_PATTERNS:
            if pat.search(body):
                return _augment_cf_fields({
                    "blocked": True,
                    "protection_type": "captcha",
                    "details": "CAPTCHA challenge detected in response body",
                }, lower_headers)

    # --- cf-ray header (Cloudflare) with blocking status ---
    if "cf-ray" in lower_headers and http_status in (403, 503):
        return _augment_cf_fields({
            "blocked": True,
            "protection_type": "cloudflare",
            "details": f"Cloudflare block (cf-ray: {lower_headers['cf-ray']}, status {http_status})",
        }, lower_headers)

    # --- WAF/CDN headers ---
    for header_key, ptype in _WAF_HEADERS.items():
        if header_key in lower_headers and http_status in (403, 503):
            return _augment_cf_fields({
                "blocked": True,
                "protection_type": ptype,
                "details": f"WAF/CDN block detected via {header_key} header (status {http_status})",
            }, lower_headers)

    # --- Plain HTTP block status ---
    if http_status == 403:
        return _augment_cf_fields({
            "blocked": True,
            "protection_type": "http_block",
            "details": "HTTP 403 Forbidden",
        }, lower_headers)

    if http_status == 503:
        return _augment_cf_fields({
            "blocked": True,
            "protection_type": "http_block",
            "details": "HTTP 503 Service Unavailable",
        }, lower_headers)

    return _augment_cf_fields({
        "blocked": False,
        "protection_type": None,
        "details": None,
    }, lower_headers)
