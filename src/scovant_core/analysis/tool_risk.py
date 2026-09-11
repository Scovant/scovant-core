"""Static, NAME-BASED-GUESS risk classification for MCP tools (TOOL-RISK-001).

`classify_tool_risk` is a pure heuristic over a tool's name/description/
input-schema-key surface — it never inspects the tool's actual implementation
(there is none to inspect: E1 is a read-only initialize+tools/list snapshot,
`tools/call` is never issued). It is a naming-convention guess, not a proof:
a tool named `get_report` that secretly deletes data would be misclassified
READ_ONLY, and a tool named `delete_cache_stats` that only clears an in-memory
counter would be misclassified DESTRUCTIVE. The classification is surfaced to
agents/operators as an informational hint, never as a graded defect — see the
host's tool-risk rule (TOOL-RISK-001).
"""
from __future__ import annotations

# Longest/most-specific-first within each tier isn't required here because
# every prefix set is checked as its own pass, in risk-severity order
# (DESTRUCTIVE > EXTERNAL_SIDE_EFFECT > WRITE > READ_ONLY) — a name matching
# more than one tier's markers is classified by the highest-severity tier it
# matches, so a name like "send_delete_request" reads as DESTRUCTIVE.
_DESTRUCTIVE_PREFIXES = ("delete_", "remove_", "drop_", "refund_", "cancel_", "revoke_")
_EXTERNAL_MARKERS = ("send_", "email", "sms", "payment", "charge", "notify", "publish")
_WRITE_PREFIXES = ("create_", "update_", "set_", "post_", "put_", "add_", "write_")
_READ_ONLY_PREFIXES = ("get_", "list_", "search_", "read_", "fetch_", "query_", "describe_")


def classify_tool_risk(name: str, description: str, input_schema_keys: list[str]) -> str:
    """Guess a tool's risk class from its name/description text.

    Returns one of READ_ONLY | WRITE | DESTRUCTIVE | EXTERNAL_SIDE_EFFECT |
    UNKNOWN. Case-insensitive. Never raises — a malformed/missing name or
    description degrades to UNKNOWN rather than erroring, since this feeds a
    scoring-engine rule that must never blow up a scan.
    """
    try:
        haystack = f"{name or ''} {description or ''}".lower()
    except Exception:
        return "UNKNOWN"

    if any(marker in haystack for marker in _DESTRUCTIVE_PREFIXES):
        return "DESTRUCTIVE"
    if any(marker in haystack for marker in _EXTERNAL_MARKERS):
        return "EXTERNAL_SIDE_EFFECT"
    if any(marker in haystack for marker in _WRITE_PREFIXES):
        return "WRITE"
    if any(marker in haystack for marker in _READ_ONLY_PREFIXES):
        return "READ_ONLY"
    return "UNKNOWN"
