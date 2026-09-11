"""Contact-method discovery: scans the entry page's anchors for a contact
page, a `mailto:` link, or (as a last resort) a social-profile link."""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from scovant_core.context import ScanContext
from scovant_core.evidence import EvidenceStore, register_gatherer
from scovant_core.parsers.html import coerce_attr_str
from scovant_core.security.client import SecureClient

_CONTACT_RE = re.compile(r"contact|support|help", re.I)
_SOCIAL_HOSTS = {"twitter.com", "x.com", "facebook.com", "linkedin.com", "instagram.com"}


def _social_host(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    return host in _SOCIAL_HOSTS


@register_gatherer("contact")
def gather_contact(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    http = store.get("http")
    html = http["html"]
    if not html:
        return {"contact_url": None, "kind": None}

    soup = BeautifulSoup(html, "lxml")
    base_url = ctx.final_url or ctx.input_url
    anchors = soup.find_all("a", href=True)

    for a in anchors:
        href = (coerce_attr_str(a.get("href")) or "").strip()
        if not href:
            continue
        if href.lower().startswith("mailto:"):
            return {"contact_url": href, "kind": "mailto"}
        text = a.get_text(strip=True)
        if _CONTACT_RE.search(text) or _CONTACT_RE.search(href):
            return {"contact_url": urljoin(base_url, href), "kind": "page"}

    for a in anchors:
        href = (coerce_attr_str(a.get("href")) or "").strip()
        if href and _social_host(href):
            return {"contact_url": href, "kind": "social"}

    return {"contact_url": None, "kind": None}
