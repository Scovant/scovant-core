"""Every CHECK that draws a verdict from a document body must declare when
that body was read only in part. `test_truncation_contract.py` proves this
one level lower — every GATHERER that reads a body carries and derives the
flag — but says nothing about whether a check that consumes one of those
gatherer records actually surfaces it. Nothing there stops a new check from
reading a truncatable record, ignoring the flag, and silently publishing a
verdict at full confidence anyway. This file is that guarantee, mirroring
`test_truncation_contract.py`'s derived-set-must-equal-checked-in-set shape.

Static, AST-based, over the real check registry — not a regex scan and not
a runtime fixture (`tests/test_truncation_behaviour.py` already proves real
runtime behaviour for a representative subset; building a truncated/full
store for every profile every check needs is out of proportion with what
this file exists to catch: a check that stopped calling the truncation
helpers at all, or that computes a confidence and then never uses it).
"""
from __future__ import annotations

import ast
from pathlib import Path

from scovant_core.checks import registry
from tests._source_tree import package_source_root

SRC_ROOT = package_source_root()
CHECKS_ROOT = SRC_ROOT / "scovant_core" / "checks"

# The two direct entry points every participating check calls, plus one
# audited delegate: `policy_verdict` (checks/trust/_policy.py) is not itself
# a check, but CORE-TRUST-002/-003/-004/-005 all route their verdict through
# it, and it calls `record_truncation`/`truncated_confidence` internally and
# returns the resulting confidence in its `(status, summary, evidence,
# confidence)` quadruple — verified by reading `_policy.py` directly, not
# assumed. A check that delegates through it still declares a partial read;
# excluding it here would make those four checks look like non-participants.
_TRUNCATION_ENTRY_POINTS = frozenset({"record_truncation", "robots_truncation"})
_DELEGATES = frozenset({"policy_verdict"})

# The checks that genuinely do NOT draw their verdict from a document body —
# audited, with the reason, mirroring EXEMPT_NO_REAL_SIGNAL's idiom in
# test_truncation_contract.py. A check landing here must be provably reading
# only status codes, response headers, or the redirect chain — never bytes
# that could have been cut off by the per-document-kind fetch cap.
EXEMPT_CHECKS: dict[str, str] = {
    "CORE-ACCESS-001": (
        "HTTPS reachability. Reads only `http['status']`, `['final_url']`, "
        "`['redirect_chain']` and `['error']` — no body content."
    ),
    "CORE-OPERABILITY-002": (
        "Redirect chain complexity. Reads only `http['redirect_chain']`/"
        "`['error']` — the shape of the chain, never a response body."
    ),
    "CORE-OPERABILITY-003": (
        "Cache validators. Reads only `http['headers']` (ETag, "
        "Last-Modified, Cache-Control) — headers, never a body."
    ),
    "CORE-OPERABILITY-004": (
        "Broken machine-consumable endpoints. Each reference's VERDICT is its "
        "resolved HTTP `status`/`ok` from `machine_links`, and a real status code "
        "is unaffected by a body being cut off past the fetch cap. The reference "
        "SET is a different matter and this exemption does not claim otherwise: "
        "`gatherers/machine_links.py` assembles it from the entry page's canonical "
        "URL and policy links, the sitemap URL, the OpenAPI URL and the llms.txt "
        "URL list — every one of them extracted from a body that could have been "
        "cut off, so an oversized llms.txt can shrink the set this check reports "
        "over. That dependency is one gatherer hop upstream and is disclosed by "
        "the checks that read those documents (CORE-ACCESS-005/-006/-007/-009); "
        "wiring it through here is a deliberate open item, not a claim of "
        "independence."
    ),
}


def _call_target_names(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _module_path(check) -> Path:
    mod = type(check).__module__
    return SRC_ROOT / (mod.replace(".", "/") + ".py")


def _tree_for(check) -> ast.Module:
    return ast.parse(_module_path(check).read_text(encoding="utf-8"))


def _participates(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_target_names(node) in (_TRUNCATION_ENTRY_POINTS | _DELEGATES):
            return True
    return False


def _all_check_ids() -> set[str]:
    return {c.id for c in registry.CHECKS}


# The derived participating set, computed once against the real registry and
# checked in below — a mismatch means a check started or stopped calling the
# truncation helpers without anyone deciding whether that's correct.
PARTICIPATING_CHECKS: frozenset[str] = frozenset(_all_check_ids() - EXEMPT_CHECKS.keys())


def test_every_check_is_either_participating_or_an_audited_exemption():
    all_ids = _all_check_ids()
    assert set(EXEMPT_CHECKS) <= all_ids, f"audited exemption for a check id that no longer exists: {set(EXEMPT_CHECKS) - all_ids}"
    assert PARTICIPATING_CHECKS | set(EXEMPT_CHECKS) == all_ids
    assert PARTICIPATING_CHECKS.isdisjoint(EXEMPT_CHECKS)


def test_the_participating_check_set_is_exactly_what_we_think_it_is():
    """Every check NOT in the audited exemption list must actually call
    `record_truncation`/`robots_truncation` (directly or via the audited
    `policy_verdict` delegate) somewhere in its `evaluate()`. A check that
    quietly stopped doing so — the exact regression this file exists to
    catch — falls out of the derived set and fails here, named."""
    by_id = {c.id: c for c in registry.CHECKS}
    derived = {check_id for check_id, check in by_id.items() if _participates(_tree_for(check))}
    assert derived == PARTICIPATING_CHECKS, (
        f"no longer calling a truncation entry point (now looks EXEMPT — audit it or fix it): "
        f"{PARTICIPATING_CHECKS - derived}; "
        f"newly calling one (remove from EXEMPT_CHECKS, it now participates): "
        f"{derived - PARTICIPATING_CHECKS}"
    )


def test_every_exempt_check_is_provably_status_header_or_redirect_only():
    """A stronger check than trusting the docstring above: an exempt check's
    source must never reference a body-shaped field name that would suggest
    it secretly reads document content."""
    by_id = {c.id: c for c in registry.CHECKS}
    _BODY_SHAPED_MARKERS = ("parsed_jsonld", "text_chars", "raw_jsonld", ".text", "['html']", '["html"]', "body")
    offenders = {}
    for check_id in EXEMPT_CHECKS:
        src = _module_path(by_id[check_id]).read_text(encoding="utf-8")
        hit = [m for m in _BODY_SHAPED_MARKERS if m in src]
        if hit:
            offenders[check_id] = hit
    assert offenders == {}, f"an 'exempt' check's source mentions body-shaped data: {offenders}"


def _confidence_source_names(func: ast.FunctionDef) -> set[str]:
    """Names assigned FROM a call to `truncated_confidence(...)`, or bound as
    the 4th element of a tuple/list unpacking of a `policy_verdict(...)`
    call (its `(status, summary, evidence, confidence)` return shape)."""
    names: set[str] = set()
    for node in ast.walk(func):
        if not isinstance(node, ast.Assign):
            continue
        value = node.value
        if isinstance(value, ast.Call) and _call_target_names(value) == "truncated_confidence":
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        if isinstance(value, ast.Call) and _call_target_names(value) == "policy_verdict":
            for target in node.targets:
                if isinstance(target, (ast.Tuple, ast.List)) and len(target.elts) == 4:
                    last = target.elts[3]
                    if isinstance(last, ast.Name):
                        names.add(last.id)
    return names


def _confidence_kwarg_names(func: ast.FunctionDef) -> set[str]:
    """Names passed as `confidence=` into a `self.result(...)` call anywhere
    in the function (nested helper calls aren't followed — every
    participating check's own `evaluate()` calls `self.result` directly)."""
    names: set[str] = set()
    for node in ast.walk(func):
        if not (isinstance(node, ast.Call) and _call_target_names(node) == "result"):
            continue
        for kw in node.keywords:
            if kw.arg == "confidence" and isinstance(kw.value, ast.Name):
                names.add(kw.value.id)
    return names


def test_every_participating_check_actually_uses_the_confidence_it_computes():
    """Calling `record_truncation`/`policy_verdict` alone is not enough — a
    check that computes a degraded confidence and then never passes it to
    `self.result(confidence=...)` still publishes at the default HIGH
    confidence (`CoreCheck.result`'s default) despite having the truncation
    signal in hand. This is the wiring half of "declares a partial read":
    the flag must actually reach the emitted `CheckResult`, not just exist
    as a local variable next to it."""
    by_id = {c.id: c for c in registry.CHECKS}
    offenders = []
    for check_id in PARTICIPATING_CHECKS:
        tree = _tree_for(by_id[check_id])
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "evaluate":
                produced = _confidence_source_names(node)
                used = _confidence_kwarg_names(node)
                if not (produced & used):
                    offenders.append((check_id, sorted(produced), sorted(used)))
    assert offenders == [], (
        f"these checks compute a truncation-derived confidence but never pass it into "
        f"self.result(confidence=...): {offenders}"
    )


# --- Per-BRANCH completeness -------------------------------------------------
#
# Everything above is per-CHECK: one `self.result(confidence=conf)` anywhere in
# `evaluate()` satisfies it, and nothing asserted the note reached the summary
# at all. That is exactly how five truncation-blind N/A branches shipped past a
# green suite — CORE-ACCESS-006 called `record_truncation` and passed `conf` on
# five later branches while its FIRST branch published "No valid sitemap to
# evaluate freshness for." at HIGH confidence with no flag and no note, drawn
# from the very body CORE-ACCESS-005 was reporting as partly read in the same
# report. The tests below raise the guarantee to the property the file claims:
# EVERY verdict-emitting branch of a participating check either carries both
# halves of the disclosure (the truncation-derived confidence AND the note in
# its summary) or is an audited exemption naming why its verdict does not come
# from a body we may only have read in part.
#
# `self.error(...)` returns are never in scope: `CoreCheck.error` is already
# LOW confidence and its summary claims nothing about a document's content.

# (check id, the branch's first summary string literal) -> why silence is
# honest there. Admission is deliberately narrow, and every reason below was
# read against the branch's own code, not assumed:
#
#   (a) the verdict was established INDEPENDENTLY of any body that could have
#       been cut off — a real 404/410, a soft-404 HTML catch-all
#       classification, a probe that found nothing to read, or a
#       profile/option precondition that reads no document at all; or
#   (b) the verdict is about the COMPOSITION of a sampled set rather than
#       about content read out of a body. Such a branch is NOT independent of
#       truncation — an oversized sitemap or entry page can shrink the sample
#       — but the dependency is one gatherer hop upstream and is disclosed by
#       the check that reads that document. It is recorded here in those
#       words rather than dressed up as independence (the CORE-OPERABILITY-004
#       lesson: an audited exemption carrying a false reason is worse than no
#       exemption at all).
#
# A branch that draws an absence verdict from the possibly-partial document
# itself does NOT belong here — that is finding 1 of the final review, and the
# five branches it named are wired up instead.
AUDITED_SILENT_BRANCHES: dict[tuple[str, str], str] = {
    ("CORE-ACCESS-003", "No robots.txt is published; all crawlers, including search/retrieval crawlers, are allowed by default."): (
        "(a) `classify_robots_readability` returns `absent` on a literal 404 and nothing else "
        "(checks/access/_robots_readability.py) — a served-as-HTML catch-all, a missing status "
        "and every other non-200 are classified `unreadable` and return ERROR before this "
        "branch is reached. So the verdict comes from the status line, never from a body. "
        "Publishes at a fixed MEDIUM regardless, so it cannot over-claim either."
    ),
    ("CORE-ACCESS-004", "No robots.txt is published; all crawlers, including training crawlers, are allowed by default."): (
        "(a) the same 404-only `absent` readability verdict as CORE-ACCESS-003, at the same "
        "fixed MEDIUM."
    ),
    ("CORE-ACCESS-005", "No sitemap was found."): (
        "(a) absence is established by a real 404/410, a failed probe, or a soft-404 HTML "
        "catch-all — never by the sitemap body, which on this branch was never read. The "
        "truncation of some other, unrelated read has no bearing on it (see the comment in "
        "core_access_005.py)."
    ),
    ("CORE-INTERFACE-005", "No OpenAPI document discovered at the conventional paths."): (
        "(b) each candidate's VERDICT is a status: the branch is reached only after "
        "`document_status` has ruled out every unreadable status across all candidates, so what "
        "remains is a real 404/410 or an HTML catch-all on each. The candidate SET is a "
        "different matter and this exemption does not claim independence: alongside the five "
        "fixed conventional paths, `gatherers/openapi.py` adds same-origin entry-page links "
        "whose href names `openapi`/`swagger`, extracted from the entry page's HTML — a body "
        "that can be cut off at the fetch cap, taking a link past the cut with it. That "
        "dependency is one gatherer hop upstream and is disclosed by the checks that read the "
        "entry page (CORE-ACCESS-007/-008, CORE-OPERABILITY-001); wiring it through here is a "
        "deliberate open item, the same one recorded on CORE-OPERABILITY-004."
    ),
    ("CORE-INTERFACE-006", "No OAuth authorization-server metadata is published."): (
        "(a) a real 404/410 on the well-known path; no body fed this verdict."
    ),
    ("CORE-INTERFACE-006", "No OAuth authorization-server metadata is published — the path is served by an HTML catch-all."): (
        "(a) the soft-404 classification is drawn from the response's content type and shape, "
        "and says the document is absent however much of the catch-all page we read."
    ),
    ("CORE-INTERFACE-007", "No OAuth protected-resource metadata is published."): (
        "(a) a real 404/410 on the well-known path; no body fed this verdict."
    ),
    ("CORE-INTERFACE-007", "No OAuth protected-resource metadata is published — the path is served by an HTML catch-all."): (
        "(a) soft-404 classification, as for CORE-INTERFACE-006."
    ),
    ("CORE-INTERFACE-008", "No UCP profile is published."): (
        "(a) a real 404/410 on the well-known path; no body fed this verdict."
    ),
    ("CORE-INTERFACE-008", "No UCP profile is published — the path is served by an HTML catch-all."): (
        "(a) soft-404 classification, as for CORE-INTERFACE-006."
    ),
    ("CORE-TRUST-006", "No security.txt was found at /.well-known/security.txt or /security.txt."): (
        "(a) a real 404/410 on both conventional paths."
    ),
    ("CORE-TRUST-006", "No security.txt was found — the path is served by an HTML catch-all."): (
        "(a) soft-404 classification, as for CORE-INTERFACE-006."
    ),
    ("CORE-OPERABILITY-007", "Machine reference integrity was not evaluated (experimental off)."): (
        "(a) an option precondition — the gatherer never ran, so no document was read at all."
    ),
    ("CORE-MACHINE-007", "Only the entry page was sampled; there are no additional pages to check for breadcrumbs."): (
        "(b) a claim about the composition of the sampled page set (`selection`), not about "
        "content read out of any page body. The sample can be shrunk by a truncated sitemap or "
        "entry page; that dependency is upstream and is disclosed by CORE-ACCESS-005/-006/-007, "
        "which read those documents."
    ),
}


def _first_string_literal(node: ast.AST) -> str | None:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            return sub.value
    return None


def _note_carrying_names(func: ast.FunctionDef) -> set[str]:
    """Names that carry a truncation note: the first element of a
    `note, truncated = record_truncation(...)`/`robots_truncation(...)`
    unpacking, the `summary` element of `policy_verdict(...)`'s quadruple
    (which splices the note into the summary itself), and — to a fixpoint —
    any name assigned from an expression that already mentions one of them.

    KNOWN LOOSENESS, deliberate: BOTH halves of that unpacking are admitted
    (see the loop below), so a summary that mentions only the truncation
    FLAG — not the note text — satisfies the note half of the check. That is
    what lets an audited summary delegate (`_SUMMARY_DELEGATES`) build the
    wording itself instead of concatenating the standard note, which
    `CORE-OPERABILITY-005` genuinely needs; but it is looser than this
    file's name claims, and a check could pass by passing the flag into any
    expression that reaches a summary. The audited delegate list is the
    thing keeping that narrow."""
    names: set[str] = set()
    for node in ast.walk(func):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        called = _call_target_names(node.value)
        for target in node.targets:
            if not isinstance(target, (ast.Tuple, ast.List)):
                continue
            if called in _TRUNCATION_ENTRY_POINTS and len(target.elts) == 2:
                # Both halves of `note, truncated = record_truncation(...)`:
                # the note itself, and the flag, which an audited summary
                # delegate (`_SUMMARY_DELEGATES`) uses to build the wording.
                for elt in target.elts:
                    if isinstance(elt, ast.Name):
                        names.add(elt.id)
            if called == "policy_verdict" and len(target.elts) == 4 and isinstance(target.elts[1], ast.Name):
                names.add(target.elts[1].id)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(func):
            if not isinstance(node, ast.Assign):
                continue
            mentions = {n.id for n in ast.walk(node.value) if isinstance(n, ast.Name)}
            if not (mentions & names):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id not in names:
                    names.add(target.id)
                    changed = True
    return names


def _verdict_returns(func: ast.FunctionDef) -> list[ast.Call]:
    """Every returned `result(...)`/`na(...)` verdict call in the function.
    An `error(...)` return is excluded by construction (see the note above)."""
    out: list[ast.Call] = []
    for node in ast.walk(func):
        if not (isinstance(node, ast.Return) and isinstance(node.value, ast.Call)):
            continue
        if _call_target_names(node.value) in ("result", "na"):
            out.append(node.value)
    return out


def _summary_arg(call: ast.Call) -> ast.AST | None:
    """`result(status, summary, ...)` puts the summary second; `na(summary,
    ...)` puts it first."""
    if _call_target_names(call) == "na":
        return call.args[0] if call.args else None
    return call.args[1] if len(call.args) > 1 else None


# Summary builders that splice the truncation wording in themselves. Audited
# by reading them: `_pass_summary` (checks/operability/core_operability_005.py)
# takes the truncation flag and rephrases a below-threshold measurement as a
# floor — a stronger disclosure than appending the standard note, which is why
# it is accepted here rather than forced to concatenate one.
_SUMMARY_DELEGATES = frozenset({"_pass_summary"})


def _caps_confidence(value: ast.AST, conf_names: set[str]) -> bool:
    """A branch may satisfy the confidence half three ways, all equivalent in
    effect: pass a name bound from `truncated_confidence(...)`, call it
    inline, or pass a fixed `Confidence.MEDIUM`/`LOW` — a branch that never
    publishes at HIGH cannot over-claim on a partly-read document."""
    if isinstance(value, ast.Name) and value.id in conf_names:
        return True
    if isinstance(value, ast.Call) and _call_target_names(value) == "truncated_confidence":
        return True
    return isinstance(value, ast.Attribute) and value.attr in ("MEDIUM", "LOW")


def _branch_disclosure(call: ast.Call, conf_names: set[str], note_names: set[str]) -> tuple[bool, bool]:
    passes_conf = any(
        kw.arg == "confidence" and _caps_confidence(kw.value, conf_names) for kw in call.keywords
    )
    summary = _summary_arg(call)
    if summary is None:
        return passes_conf, False
    carries_note = any(isinstance(n, ast.Name) and n.id in note_names for n in ast.walk(summary))
    if not carries_note and isinstance(summary, ast.Call) and _call_target_names(summary) in _SUMMARY_DELEGATES:
        carries_note = any(isinstance(n, ast.Name) and n.id in note_names for n in ast.walk(summary))
    return passes_conf, carries_note


def test_every_verdict_branch_of_a_participating_check_declares_a_partial_read():
    by_id = {c.id: c for c in registry.CHECKS}
    offenders = []
    for check_id in sorted(PARTICIPATING_CHECKS):
        tree = _tree_for(by_id[check_id])
        for node in ast.walk(tree):
            if not (isinstance(node, ast.FunctionDef) and node.name == "evaluate"):
                continue
            conf_names = _confidence_source_names(node)
            note_names = _note_carrying_names(node)
            for call in _verdict_returns(node):
                literal = _first_string_literal(_summary_arg(call)) or ""
                if (check_id, literal) in AUDITED_SILENT_BRANCHES:
                    continue
                passes_conf, carries_note = _branch_disclosure(call, conf_names, note_names)
                if not (passes_conf and carries_note):
                    offenders.append((check_id, literal[:70], f"confidence={passes_conf}", f"note={carries_note}"))
    assert offenders == [], (
        "these verdict branches publish without one or both halves of the truncation disclosure "
        "(the truncation-derived confidence and the note in the summary). Either wire both in, or "
        f"add the branch to AUDITED_SILENT_BRANCHES with the reason its verdict cannot come from a "
        f"partly-read body: {offenders}"
    )


def test_the_audited_silent_branch_list_is_not_stale():
    """An audited exemption whose branch no longer exists (renamed summary,
    deleted branch) silently stops guarding anything — and would quietly
    re-admit a truncation-blind branch under the same key later."""
    by_id = {c.id: c for c in registry.CHECKS}
    live: set[tuple[str, str]] = set()
    for check_id in PARTICIPATING_CHECKS:
        tree = _tree_for(by_id[check_id])
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "evaluate":
                for call in _verdict_returns(node):
                    live.add((check_id, _first_string_literal(_summary_arg(call)) or ""))
    stale = set(AUDITED_SILENT_BRANCHES) - live
    assert stale == set(), f"audited silent branch(es) that no longer exist: {sorted(stale)}"
