"""The within-sample crawl-graph builder (pure; ported from Cloud)."""
from __future__ import annotations

ROOT = "https://example.com/"
A = "https://example.com/a"
B = "https://example.com/b"
C = "https://example.com/c"
D = "https://example.com/d"
OUT_OF_SAMPLE = "https://example.com/not-sampled"


def _fixture_pages() -> dict[str, list[str]]:
    """5-page fixture: root -> A, B; A -> C, out-of-sample; D isolated."""
    return {
        ROOT: [A, B],
        A: [C, OUT_OF_SAMPLE],
        B: [],
        C: [],
        D: [],
    }


def test_crawl_graph_depths_and_sampled_count():
    from scovant_core.analysis.crawl_graph import build_crawl_graph

    graph = build_crawl_graph(_fixture_pages(), ROOT)

    assert graph["sampled"] == 5
    assert graph["root"] == ROOT
    assert graph["pages"][ROOT]["depth"] == 0
    assert graph["pages"][A]["depth"] == 1
    assert graph["pages"][B]["depth"] == 1
    assert graph["pages"][C]["depth"] == 2
    assert graph["pages"][D]["depth"] is None


def test_crawl_graph_inlinks():
    from scovant_core.analysis.crawl_graph import build_crawl_graph

    graph = build_crawl_graph(_fixture_pages(), ROOT)

    assert graph["pages"][D]["inlinks"] == 0


def test_crawl_graph_outlinks_in_sample_vs_raw():
    from scovant_core.analysis.crawl_graph import build_crawl_graph

    graph = build_crawl_graph(_fixture_pages(), ROOT)

    # A links to C (in-sample) and one out-of-sample same-domain URL
    assert graph["pages"][A]["outlinks_in_sample"] == 1
    assert graph["pages"][A]["outlinks_raw"] == 2

    # D has no raw outlinks at all
    assert graph["pages"][D]["outlinks_raw"] == 0


def test_crawl_graph_root_present_no_fallback():
    from scovant_core.analysis.crawl_graph import build_crawl_graph

    graph = build_crawl_graph(_fixture_pages(), ROOT)

    assert graph.get("root_fallback") is False


def test_crawl_graph_root_missing_uses_lexically_shortest_url_as_origin():
    from scovant_core.analysis.crawl_graph import build_crawl_graph

    pages = _fixture_pages()
    missing_root = "https://example.com/does-not-exist"

    graph = build_crawl_graph(pages, missing_root)

    assert graph["root_fallback"] is True
    # Lexically shortest sampled URL among ROOT/A/B/C/D is ROOT itself
    # ("https://example.com/" is shorter than "https://example.com/a" etc.)
    assert graph["root"] == ROOT
    assert graph["pages"][ROOT]["depth"] == 0
    assert graph["pages"][A]["depth"] == 1


def test_crawl_graph_normalizes_node_keys_and_link_targets():
    """The graph builder normalizes independently of extractor output —
    joins must not miss on trivial formatting differences (case, tracking
    params, fragments) between a page's own snapshot URL and a link target
    pointing at it.
    """
    from scovant_core.analysis.crawl_graph import build_crawl_graph

    root = "https://Example.com/"
    a = "https://example.com/a"
    pages = {
        root: [a + "?utm_source=x#frag"],
        a: [],
    }
    graph = build_crawl_graph(pages, root)

    assert graph["sampled"] == 2
    assert graph["pages"][a]["inlinks"] == 1
    assert graph["pages"][a]["depth"] == 1
