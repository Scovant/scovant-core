"""A `document=` label on `record_truncation()` must name the ONE document
the check's verdict was actually drawn from. Nothing pinned this before this
test existed — which is exactly how CORE-ACCESS-009 shipped labeling its
truncation note "llms.txt" while the flag it labels is an OR across TWO
distinctly-named documents (llms.txt AND /llms-full.txt, see
`gatherers/llms.py`): a fully-read llms.txt beside a truncated
llms-full.txt produced a note claiming llms.txt itself was cut off. The fix
was to drop the label there (the generic "the document body…" wording is
true regardless of which of the two was cut); this test is the guard against
the same defect recurring on the next document.

Static, AST-based (not a regex scan): every `record_truncation`/
`robots_truncation` call site under `checks/` that passes `document=` must
be an audited entry below, keyed by (file, the exact source of its first
argument, the label). Two independent failure modes:

1. The first argument is a bare gatherer-record variable name that folds
   more than one distinctly-named document into one `truncated` flag
   (`FOLDED_RECORD_NAMES`, audited from the gatherers themselves) — this
   fails immediately, unconditionally, with no way to add it to the audited
   list, because no single document name could ever be honest there.
2. Any call site — new, moved, or with a changed label — that isn't already
   in `AUDITED_DOCUMENT_CALLS` fails, forcing a deliberate audit entry
   (mirroring the BODY_READING/EXEMPT_NO_REAL_SIGNAL idiom already used by
   test_truncation_contract.py) instead of a label nobody checked.
"""
from __future__ import annotations

import ast

from tests._source_tree import package_source_root

CHECKS_ROOT = package_source_root() / "scovant_core" / "checks"

# Gatherer records whose own `["truncated"]` is an OR across more than one
# DISTINCTLY-NAMED document — audited straight from the gatherer source, not
# guessed. A `document=` label may NEVER be attached to one of these.
# The same rule, for fields rather than whole records: a synthesized
# single-purpose dict (`{"truncated": sitemap.get("body_truncated", False)}`)
# reads as "one field of one document" and so slipped past the record-name
# guard above — but `sitemap_urls["body_truncated"]` is itself an OR across
# the sitemap index, a followed child sitemap and the direct probe
# (gatherers/sitemap_urls.py), so `document="sitemap"` there claimed a
# specific document had been cut when a different one had. Any field listed
# here is folded wherever it is read from, whole record or synthesized dict.
FOLDED_FIELD_NAMES = frozenset({
    "body_truncated",  # sitemap index OR child sitemap OR direct probe (gatherers/sitemap_urls.py)
})

FOLDED_RECORD_NAMES = frozenset({
    "llms",              # llms.txt AND /llms-full.txt (gatherers/llms.py)
    "agent_discovery",   # /.well-known/mcp.json AND /ai-plugin.json AND ... (gatherers/agent_discovery.py)
    "agent_payments",    # multiple probed protocol endpoints (gatherers/agent_payments.py)
    "mcp_discovery",     # the discovery file AND the server card (gatherers/mcp_discovery.py)
    "mcp_metadata",      # multiple probed candidate paths (gatherers/mcp_metadata.py)
    "oauth_metadata",    # the authorization-server AND protected-resource metadata documents (gatherers/oauth_metadata.py)
    "oauth",             # the OAuth doc AND its linked authorization-server metadata (gatherers/oauth.py)
    "policy_pages",      # every fetched policy page (gatherers/policy_pages.py)
    "reference_integrity",  # every reference it resolves (gatherers/reference_integrity.py)
})

# Every audited `document=` call site: (relative path under checks/, the
# `ast.unparse()` of its first positional argument, the label passed).
# Computed once from the real source and asserted to still match exactly —
# a mismatch means either a call site changed without updating this audit,
# or this audit is stale. Both are failures.
AUDITED_DOCUMENT_CALLS: set[tuple[str, str, str]] = {
    ("access/core_access_002.py", "robots", "robots.txt"),
    ("access/core_access_003.py", "robots", "robots.txt"),
    ("access/core_access_004.py", "robots", "robots.txt"),
    ("access/core_access_010.py", "robots", "robots.txt"),
    ("access/core_access_007.py", "entry", "entry page"),
    ("access/core_access_008.py", "entry", "entry page"),
    ("interfaces/core_interface_005.py", "openapi", "OpenAPI document"),
    ("interfaces/core_interface_006.py", "as_", "OAuth authorization-server metadata"),
    ("interfaces/core_interface_007.py", "pr", "OAuth protected-resource metadata"),
    ("interfaces/core_interface_008.py", "ucp", "UCP profile"),
    ("trust/core_trust_001.py", "entry", "entry page"),
    ("trust/core_trust_006.py", "sec", "security.txt"),
    ("trust/core_trust_007.py", "pricing_page", "pricing page"),
    ("trust/core_trust_007.py", "priced", "product page"),
    ("operability/core_operability_001.py", "entry", "entry page"),
    ("operability/core_operability_005.py", "pages[0]", "entry page"),
}


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _document_labeled_calls() -> list[tuple[str, ast.Call]]:
    found: list[tuple[str, ast.Call]] = []
    for path in sorted(CHECKS_ROOT.rglob("*.py")):
        rel = str(path.relative_to(CHECKS_ROOT))
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _call_name(node) not in ("record_truncation", "robots_truncation"):
                continue
            if any(kw.arg == "document" for kw in node.keywords):
                found.append((rel, node))
    return found


def test_no_document_label_is_attached_to_a_folded_multi_document_record():
    calls = _document_labeled_calls()
    offenders = [
        (rel, ast.unparse(node.args[0]))
        for rel, node in calls
        if node.args and (
            (isinstance(node.args[0], ast.Name) and node.args[0].id in FOLDED_RECORD_NAMES)
            # ...and the same, one level in: a synthesized dict whose value
            # is lifted out of a folded FIELD is exactly as dishonest to
            # label as the folded record it came from.
            or any(isinstance(n, ast.Constant) and n.value in FOLDED_FIELD_NAMES
                   for n in ast.walk(node.args[0]))
        )
    ]
    assert offenders == [], (
        "these call sites label a truncation note with a specific document name, but read a "
        "gatherer record that folds more than one distinctly-named document's truncation flag "
        f"into one boolean — the label cannot be honest there: {offenders}"
    )


def test_every_document_label_call_site_is_audited():
    calls = _document_labeled_calls()
    discovered = {
        (rel, ast.unparse(node.args[0]), ast.literal_eval(next(kw.value for kw in node.keywords if kw.arg == "document")))
        for rel, node in calls
        if node.args
    }
    assert discovered == AUDITED_DOCUMENT_CALLS, (
        f"unaudited document= call site(s), review and update AUDITED_DOCUMENT_CALLS: "
        f"new/changed: {discovered - AUDITED_DOCUMENT_CALLS}; "
        f"removed/stale: {AUDITED_DOCUMENT_CALLS - discovered}"
    )
