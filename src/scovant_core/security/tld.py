"""The shared tldextract instance, pinned to the bundled public-suffix
snapshot (``suffix_list_urls=()``, no cache dir) so first use never performs
a network fetch. Always use this instance instead of a bare
``tldextract.extract``, whose default extractor may block on a fetch.
"""
from __future__ import annotations

import tldextract

tld_extractor = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
