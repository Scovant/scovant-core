"""Public evidence the Core rules read.

Each block is a JSON object keyed by name inside the domain evidence (the
page evidence is one page's extracted fields). Producers: Scovant Cloud's
crawler fills them for every scanned site; Core's own gatherers fill the
same shapes for the pages they fetch. A missing block means "not measured",
never "absent on the site".
"""
from __future__ import annotations

from typing import TypedDict


class ContentSignalsEvidence(TypedDict, total=False):
    """robots.txt Content-Signal directives (`parsers.content_signals`)."""
    present: bool          # at least one well-formed directive was adopted
    declared: bool         # a Content-Signal line exists, well-formed or not
    dimensions: dict[str, str]
    syntax_errors: list[str]


class SitemapEvidence(TypedDict, total=False):
    """Sitemap discovery (`gatherers.sitemap.check_sitemap`)."""
    exists: bool
    valid: bool
    url: str | None


class DomainEvidence(TypedDict, total=False):
    content_signals: ContentSignalsEvidence
    sitemap: SitemapEvidence
