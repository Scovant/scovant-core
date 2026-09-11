"""Tests for the pinned tldextract instance."""
from __future__ import annotations

from scovant_core.security.tld import tld_extractor


def test_registered_domain_extraction():
    result = tld_extractor("https://shop.example.co.uk/x")
    assert result.registered_domain == "example.co.uk"


def test_no_network_fetch_configured():
    assert tld_extractor.suffix_list_urls == ()
