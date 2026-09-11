"""HTML parsers over already-fetched page markup.

All functions accept raw HTML as a string and return typed dicts or lists.
Uses lxml as the BeautifulSoup parser to avoid MarkupResemblesLocatorWarning.
"""
from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from scovant_core.security.tld import tld_extractor

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _soup(html: str) -> BeautifulSoup:
    """Return a BeautifulSoup tree using the lxml parser."""
    return BeautifulSoup(html, "lxml")


def coerce_attr_str(value: Any, default: str | None = None) -> str | None:
    """Narrow a bs4 attribute value (`str | AttributeValueList | None`) to
    `str | None`. The attributes read via this helper (href/content/lang/…)
    are single-valued per the HTML spec, so bs4 only ever returns a list for
    them on malformed markup — joined with a space rather than dropped."""
    if value is None:
        return default
    if isinstance(value, str):
        return value
    return " ".join(value)


# ---------------------------------------------------------------------------
# Public extractors
# ---------------------------------------------------------------------------

def extract_metadata(html: str) -> dict[str, str | None]:
    """Return {title, meta_description, canonical_url, robots_meta}."""
    soup = _soup(html)

    title_tag = soup.find("title")
    title = title_tag.get_text(strip=True) if title_tag else None

    desc_tag = soup.find("meta", attrs={"name": re.compile(r"^description$", re.I)})
    meta_description = coerce_attr_str(desc_tag.get("content")) if desc_tag else None
    if meta_description == "":
        meta_description = None

    canonical_tag = soup.find("link", attrs={"rel": re.compile(r"canonical", re.I)})
    canonical_url = coerce_attr_str(canonical_tag.get("href")) if canonical_tag else None

    robots_tag = soup.find("meta", attrs={"name": re.compile(r"^robots$", re.I)})
    robots_meta = coerce_attr_str(robots_tag.get("content")) if robots_tag else None

    return {
        "title": title,
        "meta_description": meta_description,
        "canonical_url": canonical_url,
        "robots_meta": robots_meta,
    }


def extract_headings(html: str) -> list[dict[str, str]]:
    """Return [{level, text}, ...] for h1–h6 in document order."""
    soup = _soup(html)
    headings: list[dict[str, str]] = []
    for tag in soup.find_all(re.compile(r"^h[1-6]$")):
        headings.append({"level": tag.name, "text": tag.get_text(strip=True)})
    return headings


def extract_schema_org(html: str) -> list[dict[str, Any]]:
    """Return parsed JSON-LD blocks from <script type="application/ld+json"> tags."""
    soup = _soup(html)
    results: list[dict[str, Any]] = []

    for script in soup.find_all("script", attrs={"type": "application/ld+json"}):
        raw = script.string or script.get_text()
        if not raw or not raw.strip():
            continue
        try:
            data = json.loads(raw.strip())
        except json.JSONDecodeError:
            continue

        # Handle @graph wrapper
        if isinstance(data, dict) and "@graph" in data:
            for item in data["@graph"]:
                if isinstance(item, dict):
                    results.append(item)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    results.append(item)
        elif isinstance(data, dict):
            results.append(data)

    return results


def extract_og_meta(html: str) -> dict[str, str | None]:
    """Return {og_title, og_description, og_image, og_url}."""
    soup = _soup(html)

    def _og(prop: str) -> str | None:
        tag = soup.find("meta", attrs={"property": f"og:{prop}"})
        return coerce_attr_str(tag.get("content")) if tag else None

    return {
        "og_title": _og("title"),
        "og_description": _og("description"),
        "og_image": _og("image"),
        "og_url": _og("url"),
    }


def extract_visible_text(html: str) -> str:
    """Return visible text stripped of script/style/nav/footer, max 5000 chars."""
    soup = _soup(html)

    for tag in soup.find_all(["script", "style", "nav", "footer", "head"]):
        tag.decompose()

    text = soup.get_text(separator=" ", strip=True)

    # Collapse multiple whitespace
    text = re.sub(r"\s+", " ", text).strip()

    return text[:5000]


# Policy link patterns: (key, href_patterns, text_patterns)
_POLICY_PATTERNS: list[tuple[str, list[str], list[str]]] = [
    (
        "returns_policy_url",
        [r"/return", r"/refund", r"return-policy", r"refund-policy"],
        [r"return", r"refund"],
    ),
    (
        "shipping_policy_url",
        [r"/shipping", r"shipping-policy", r"delivery"],
        [r"shipping", r"delivery"],
    ),
    (
        "privacy_policy_url",
        [r"/privacy", r"privacy-policy"],
        [r"privacy"],
    ),
    (
        "terms_url",
        [r"/terms", r"terms-of-service", r"terms-and-conditions", r"/tos"],
        [r"terms", r"tos"],
    ),
]


def extract_policy_links(html: str, base_url: str) -> dict[str, str | None]:
    """Return {returns_policy_url, shipping_policy_url, privacy_policy_url, terms_url}.

    Resolves relative URLs against base_url.
    """
    soup = _soup(html)
    result: dict[str, str | None] = {
        "returns_policy_url": None,
        "shipping_policy_url": None,
        "privacy_policy_url": None,
        "terms_url": None,
    }

    links = soup.find_all("a", href=True)

    for key, href_pats, text_pats in _POLICY_PATTERNS:
        for link in links:
            href = coerce_attr_str(link.get("href"), "") or ""
            text = link.get_text(strip=True).lower()

            href_match = any(re.search(p, href, re.I) for p in href_pats)
            text_match = any(re.search(p, text, re.I) for p in text_pats)

            if href_match or text_match:
                absolute = urljoin(base_url, href)
                result[key] = absolute
                break

    return result


# ---------------------------------------------------------------------------
# extract_internal_links — internal-link graph data collection
# ---------------------------------------------------------------------------
#
# A crawler that stores each fetched page's URL exactly as it was queued (no
# canonicalization on ingest, no redirect-target substitution, no dedup
# normalization before queuing) can end up with sitemap/target URLs that
# differ in case, trailing slash, or query-param order from a page's own
# outbound links pointing at the same resource.
#
# `normalize_internal_url` therefore does the minimum a caller building a
# link graph needs (scheme+host lowercased, fragment stripped,
# `utm_*`/`gclid`/`fbclid` stripped, trailing slash preserved as-is,
# everything else left alone) and NO MORE — it cannot fully guarantee a join
# against a stored-URL column unless the caller re-normalizes both sides with
# this same helper before joining. A link-graph builder that re-normalizes
# every node key AND every link target with this helper before joining is
# what actually makes the graph resilient to trivial formatting drift
# between a stored page URL and a link some other sampled page pointed at it
# with.

_TRACKING_PARAM_PREFIXES = ("utm_",)
_TRACKING_PARAM_NAMES = {"gclid", "fbclid"}

MAX_INTERNAL_LINKS = 200


def normalize_internal_url(url: str) -> str:
    """Normalize a URL for internal-link graph joins.

    Lowercases scheme+host, strips the fragment, strips tracking params
    (utm_*, gclid, fbclid) while KEEPING every other query param (incl.
    order), and preserves the path (incl. trailing slash) exactly as given.
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    netloc = parts.netloc.lower()

    kept_params = [
        (key, value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if not key.lower().startswith(_TRACKING_PARAM_PREFIXES)
        and key.lower() not in _TRACKING_PARAM_NAMES
    ]
    query = urlencode(kept_params)

    return urlunsplit((scheme, netloc, parts.path, query, ""))


def _registrable_domain(url: str) -> str:
    """Return the registrable domain (eTLD+1) for `url`, via the pinned
    network-free `tld_extractor` — never a fresh `tldextract` instance.
    """
    host = urlsplit(url).hostname or ""
    ext = tld_extractor(host)
    if ext.suffix and ext.domain:
        return f"{ext.domain}.{ext.suffix}"
    return host


def extract_internal_links(html: str, base_url: str) -> dict[str, Any]:
    """Return {"urls": [...], "truncated": bool} — same-registrable-domain
    links (incl. subdomains) found in `html`, absolutized against
    `base_url`, normalized, deduped, and capped at `MAX_INTERNAL_LINKS`.

    Malformed hrefs (javascript:, mailto:, tel:, empty, unparseable) are
    skipped without raising.
    """
    soup = _soup(html)
    base_domain = _registrable_domain(base_url)

    urls: list[str] = []
    seen: set[str] = set()

    for link in soup.find_all("a", href=True):
        href = (coerce_attr_str(link.get("href")) or "").strip()
        if not href or href.startswith("#"):
            continue

        try:
            absolute = urljoin(base_url, href)
            parts = urlsplit(absolute)
            if parts.scheme not in ("http", "https"):
                continue
            if _registrable_domain(absolute) != base_domain:
                continue
            normalized = normalize_internal_url(absolute)
        except (ValueError, UnicodeError):
            continue

        if normalized in seen:
            continue
        seen.add(normalized)
        urls.append(normalized)

    truncated = len(urls) > MAX_INTERNAL_LINKS
    if truncated:
        urls = urls[:MAX_INTERNAL_LINKS]

    return {"urls": urls, "truncated": truncated}


def extract_product_data(schema_org: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Extract product info from schema.org entities.

    Returns {product_name, price, currency, availability, variants, offers}
    or None if no Product entity found.
    """
    product: dict[str, Any] | None = None

    for item in schema_org:
        item_type = item.get("@type", "")
        if isinstance(item_type, list):
            matches = any(t == "Product" for t in item_type)
        else:
            matches = item_type == "Product"
        if matches:
            product = item
            break

    if product is None:
        return None

    # Normalise offers to a list
    raw_offers = product.get("offers")
    if raw_offers is None:
        offers_list: list[dict[str, Any]] = []
    elif isinstance(raw_offers, dict):
        offers_list = [raw_offers]
    elif isinstance(raw_offers, list):
        offers_list = raw_offers
    else:
        offers_list = []

    # Pull primary price / currency / availability from first offer
    primary_offer = offers_list[0] if offers_list else {}
    price = primary_offer.get("price") or product.get("price")
    currency = primary_offer.get("priceCurrency") or product.get("priceCurrency")
    availability = primary_offer.get("availability") or product.get("availability")

    # Variants: schema.org doesn't have a standard field; capture hasVariant if present
    variants: list[dict[str, Any]] = product.get("hasVariant", [])

    return {
        "product_name": product.get("name"),
        "price": price,
        "currency": currency,
        "availability": availability,
        "variants": variants,
        "offers": offers_list,
    }


# Patterns to detect add-to-cart and signup CTAs
_ADD_TO_CART_PATTERN = re.compile(r"add[\s\-_]*to[\s\-_]*cart|buy[\s\-_]*now", re.I)
_SIGNUP_PATTERN = re.compile(r"sign[\s\-_]*up|register|get[\s\-_]*started|create[\s\-_]*account|newsletter", re.I)


def extract_semantic_signals(html: str) -> dict[str, Any]:
    """Return semantic accessibility and CTA signals.

    Returns:
        has_aria_labels: bool
        interactive_elements_count: int
        labeled_elements_count: int
        add_to_cart_found: bool
        signup_cta_found: bool
    """
    soup = _soup(html)

    interactive_tags = soup.find_all(["button", "input", "select", "textarea", "a"])
    # Also capture elements with role attribute that make them interactive
    role_interactive = soup.find_all(
        None, attrs={"role": re.compile(r"button|textbox|combobox|listbox|checkbox|radio", re.I)}
    )

    all_interactive = list(interactive_tags) + [
        el for el in role_interactive if el not in interactive_tags
    ]

    def _has_accessible_name(el) -> bool:
        # An interactive control's accessible name can come from any of these.
        if el.get("aria-label") or el.get("aria-labelledby") or el.get("aria-describedby"):
            return True
        if el.get("title"):
            return True
        if (el.get_text(strip=True) or ""):
            return True
        # submit/button inputs use value; image inputs/links use alt
        return bool(el.get("value") or el.get("alt"))

    aria_labeled = [
        el for el in all_interactive
        if el.get("aria-label") or el.get("aria-labelledby") or el.get("aria-describedby")
    ]
    labeled = [el for el in all_interactive if _has_accessible_name(el)]

    has_aria_labels = len(aria_labeled) > 0

    # Check add-to-cart: buttons or links whose text or aria-label matches
    add_to_cart_found = False
    signup_cta_found = False

    for el in soup.find_all(["button", "a", "input"]):
        text = (el.get_text(strip=True) or "")
        aria = (el.get("aria-label") or "")
        value = (el.get("value") or "")
        combined = f"{text} {aria} {value}"

        if _ADD_TO_CART_PATTERN.search(combined):
            add_to_cart_found = True
        if _SIGNUP_PATTERN.search(combined):
            signup_cta_found = True

    return {
        "has_aria_labels": has_aria_labels,
        "interactive_elements_count": len(all_interactive),
        "labeled_elements_count": len(labeled),
        "add_to_cart_found": add_to_cart_found,
        "signup_cta_found": signup_cta_found,
    }


def detect_page_language(html: str) -> str | None:
    """Return the lowercased primary language subtag from <html lang>, else None."""
    soup = _soup(html)
    tag = soup.find("html")
    lang = coerce_attr_str(tag.get("lang")) if tag else None
    if not lang:
        return None
    return lang.strip().lower().split("-")[0] or None


def extract_content_blocks(html: str) -> list[dict]:
    """Split a page into heading-bounded content blocks, useful for
    downstream content-quality scoring (e.g. a citability-style heuristic).

    Strips non-content elements, groups body text under the nearest preceding
    h1–h4, and keeps only blocks with >= 20 words.
    """
    soup = _soup(html)
    for tag in soup.find_all(["script", "style", "nav", "footer", "header", "aside", "form"]):
        tag.decompose()

    blocks: list[dict] = []
    heading: str | None = None
    buf: list[str] = []

    def flush() -> None:
        if not buf:
            return
        text = " ".join(buf)
        text = re.sub(r"\s+", " ", text).strip()
        if len(text.split()) >= 20:
            blocks.append({"heading": heading, "text": text, "word_count": len(text.split())})

    for el in soup.find_all(["h1", "h2", "h3", "h4", "p", "ul", "ol", "table"]):
        if el.name in ("h1", "h2", "h3", "h4"):
            flush()
            heading = el.get_text(strip=True) or None
            buf = []
        else:
            t = el.get_text(separator=" ", strip=True)
            if t and len(t.split()) >= 5:
                buf.append(t)
    flush()
    return blocks


# ---------------------------------------------------------------------------
# SPA-shell detection (render escalation)
# ---------------------------------------------------------------------------

# Framework hydration markers present in the STATIC (pre-JS) HTML — any of these
# substrings is a positive client-render signal.
_SPA_FRAMEWORK_MARKERS = (
    "__NEXT_DATA__",
    "__NUXT__",
    'id="__nuxt"',
    "data-reactroot",
    "ng-version",
    "data-server-rendered",
    "__remixContext",
    "__sveltekit",
    'id="q-app"',
)

# Ids a framework-less SPA typically mounts into.
_SPA_MOUNT_IDS = {"root", "app", "__next"}

# Minimum deferred (src / type=module) scripts for the framework-less pattern.
_SPA_MIN_SCRIPTS = 2


def has_spa_shell_marker(html: str) -> bool:
    """Return True when the static HTML shows a client-render (SPA-shell) signal.

    Positive when EITHER:
      * any framework hydration marker substring/id is present
        (``__NEXT_DATA__``, ``__NUXT__``, ``id="__nuxt"``, ``data-reactroot``,
        ``ng-version``, ``data-server-rendered``, ``__remixContext``,
        ``__sveltekit``, ``id="q-app"``), OR
      * the framework-less mount pattern: a ``div`` with id in {root, app,
        __next} whose stripped inner text is < 20 chars AND at least
        ``_SPA_MIN_SCRIPTS`` ``<script>`` tags carry ``src`` or
        ``type="module"``.

    Reads the RAW html (pre-JS) so it sees the shell structure. Best-effort:
    any error (incl. non-str input) returns ``False`` — fail closed, never
    render on uncertainty.
    """
    try:
        # (a) Framework markers — cheap substring scan on the raw HTML.
        for marker in _SPA_FRAMEWORK_MARKERS:
            if marker in html:
                return True

        # (b) Framework-less mount pattern.
        soup = _soup(html)

        mount = None
        for div in soup.find_all("div", id=True):
            if div.get("id") in _SPA_MOUNT_IDS:
                mount = div
                break
        if mount is None:
            return False
        if len(mount.get_text(strip=True)) >= 20:
            return False

        deferred_scripts = 0
        for script in soup.find_all("script"):
            if script.get("src") or script.get("type") == "module":
                deferred_scripts += 1
        return deferred_scripts >= _SPA_MIN_SCRIPTS
    except Exception:  # noqa: BLE001 — best-effort, fail closed
        return False


_LANDMARK_TAGS = ("main", "article", "nav", "section", "header", "footer", "aside")


def extract_landmark_tags(html: str) -> dict[str, int]:
    """Count semantic HTML5 landmark tags — agents use them to segment pages."""
    soup = _soup(html)
    return {tag: len(soup.find_all(tag)) for tag in _LANDMARK_TAGS}
