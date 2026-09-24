"""CORE-SECURITY-007..010 — public machine-facing data exposure (MACHINE-DATA-*).

Every check here reads TEXT already assembled by the `machine_text`
gatherer, or the structured `mcp_discovery`/`openapi` gatherer records
derived from a document body — never a fresh probe of its own. All four are
passive: no authentication, no `tools/call`, no form submission."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from scovant_core.analysis.tool_risk import classify_tool_risk
from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.checks.security._secrets import detect_secrets, is_placeholder
from scovant_core.models import Category, CheckStatus, Confidence, Severity

_LIMITS = ("Passive signal only. Scovant Core reports declaration and exposure in public machine-facing documents; "
           "it never tests exploitability, authenticates or invokes tools.")
_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)
_PRIVATE_SUFFIXES = (".internal", ".local", ".corp", ".lan", ".intranet")
_METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "metadata", "100.100.100.200"}
_PLACEHOLDER_TLDS = (".example", ".invalid", ".test", ".localhost", "example.com", "example.org", "example.net")
_PRIVILEGED_RE = re.compile(r"(^|/|_)(admin|internal|debug|impersonat\w*|drop_\w+|reset_\w+|delete_\w*|\w+_all)($|/|_)", re.I)
_SENSITIVE_FIELDS = ("password", "passwd", "access_token", "refresh_token", "api_secret", "client_secret",
                      "private_key", "card_number", "cvv", "cvc", "ssn")


class _Unreadable(Exception):
    """The entry URL could not be read as a real page — every check here
    degrades to ERROR on this, never N/A, since "nothing to evaluate" must
    never be claimed about a page we did not get. Carries the honest reason
    and evidence so the report says WHICH shape it was: a transport error
    (`{"error": kind}`) or a non-200 answer (`{"http_status": N}` — a bot
    wall's 403 is a fetch that happened and was refused, not a fetch that
    could not be made)."""

    def __init__(self, reason: str, evidence: dict):
        super().__init__(reason)
        self.reason = reason
        self.evidence = evidence


class _MachineData(CoreCheck):
    category = Category.SECURITY
    security_domain = "data_exposure"
    verification_mode = "DECLARED"
    security_tags = ("agentic-security", "data-exposure")
    limitations = _LIMITS
    cloud_extension = "Scovant Cloud tests observed data minimisation with synthetic identities."

    def _check_readable(self, store) -> dict:
        """A non-200 entry response (a bot wall, a 403, a dead domain) makes
        these four checks ERROR rather than evaluating whatever surfaces
        happened to be gathered — the ERROR-lowers-coverage invariant
        (`checks/base.py`) applies here exactly as it does to every other
        check: a site that could not be read honestly must not score as if
        nothing suspicious was found on it."""
        http = store.get("http")
        if http.get("error"):
            kind = (http["error"] or {}).get("kind", "error")
            raise _Unreadable(f"entry URL could not be fetched ({kind})", {"error": kind})
        if http.get("status") != 200:
            raise _Unreadable(f"entry URL answered HTTP {http.get('status')}, not 200",
                              {"http_status": http.get("status")})
        return http

    def _machine_text(self, store) -> dict:
        """Readable-entry check, then the assembled `machine_text` record
        (never a fresh fetch of its own — `machine_text` only reads what
        other gatherers already fetched)."""
        self._check_readable(store)
        return store.get("machine_text")


def _is_placeholder_host(host: str) -> bool:
    """`host` IS one of `_PLACEHOLDER_TLDS`'s entries, or a subdomain of one
    (dot-prefixed match) — never a bare-substring `endswith`, which would
    also match `notexample.com` against `example.com` or a host that merely
    happens to end in the letters `test` without a `.` boundary."""
    return any(host == t.lstrip(".") or host.endswith("." + t.lstrip(".")) for t in _PLACEHOLDER_TLDS)


def _host_is_internal(host: str) -> bool:
    h = host.lower().rstrip(".")
    if h in _METADATA_HOSTS or h == "localhost" or h.endswith(_PRIVATE_SUFFIXES):
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


class CredentialExposed(_MachineData):
    id = "CORE-SECURITY-007"
    family_id = "MACHINE-DATA-001"
    title = "Credential-like value exposed in a machine-facing surface"
    fix_owner = "backend"
    severity_on_fail = Severity.HIGH
    references = ("https://owasp.org/www-project-top-10-for-large-language-model-applications/",)
    standards = ("OWASP Agentic Top 10 2026: ASI03 (partial)",)
    why_it_matters = ("llms.txt, discovery files and schemas are read verbatim by agents; a live key there is "
                       "copied into every agent's context window.")

    def evaluate(self, store, ctx):
        try:
            mt = self._machine_text(store)
        except _Unreadable as exc:
            return self.error(exc.reason, exc.evidence)
        surfaces = mt["surfaces"]
        if not surfaces:
            return self.na("No machine-facing surface was gathered.")
        hits = []
        for s in surfaces:
            for h in detect_secrets(s["text"]):
                hits.append({"kind": h.kind, "confidence": h.confidence.value, "source": s["source"],
                             "surface_kind": s["kind"], **h.redacted})
        ev = {"surfaces_scanned": len(surfaces), "hits": hits[:20], "hit_count": len(hits)}
        note, truncated = record_truncation({"truncated": mt["capped"]}, ev)
        conf = truncated_confidence(truncated)
        high_count = sum(1 for h in hits if h["confidence"] == "high")
        if high_count:
            return self.result(CheckStatus.FAIL,
                                f"{len(hits)} credential-like value(s), {high_count} at high confidence, exposed (values redacted).{note}",
                                evidence=ev, confidence=conf,
                                remediation="Rotate the exposed credential now, then remove it from the public document.")
        if hits:
            return self.result(CheckStatus.WARN,
                                f"{len(hits)} possible credential-like value(s) (heuristic match, redacted).{note}",
                                evidence=ev, confidence=truncated_confidence(truncated, default=Confidence.MEDIUM),
                                severity=Severity.MEDIUM,
                                remediation="Confirm whether the value is live; rotate and remove if so.")
        return self.result(CheckStatus.PASS, f"No credential-like values in the gathered machine-facing surfaces.{note}",
                            evidence=ev, confidence=conf)


class InternalReference(_MachineData):
    id = "CORE-SECURITY-008"
    family_id = "MACHINE-DATA-002"
    title = "Internal network reference exposed"
    fix_owner = "devops"
    severity_on_fail = Severity.LOW
    references = ("https://www.rfc-editor.org/rfc/rfc1918",)
    standards = ("RFC 1918",)
    why_it_matters = ("Private addresses, metadata endpoints and internal hostnames in public documents map the "
                       "inside of a deployment; not a vulnerability by itself, hence low severity.")

    def evaluate(self, store, ctx):
        try:
            mt = self._machine_text(store)
        except _Unreadable as exc:
            return self.error(exc.reason, exc.evidence)
        surfaces = mt["surfaces"]
        if not surfaces:
            return self.na("No machine-facing surface was gathered.")
        own = (urlsplit(ctx.origin or ctx.input_url).hostname or "").lower()
        hits, seen = [], set()
        for s in surfaces:
            for m in _URL_RE.finditer(s["text"]):
                host = (urlsplit(m.group(0)).hostname or "").lower()
                if not host or host == own or _is_placeholder_host(host) or host in seen:
                    continue
                if _host_is_internal(host):
                    seen.add(host)
                    hits.append({"host": host, "source": s["source"], "surface_kind": s["kind"]})
        ev = {"surfaces_scanned": len(surfaces), "hits": hits[:20]}
        note, truncated = record_truncation({"truncated": mt["capped"]}, ev)
        conf = truncated_confidence(truncated)
        if hits:
            return self.result(CheckStatus.WARN,
                                f"{len(hits)} internal network reference(s) in public machine-facing documents.{note}",
                                evidence=ev, confidence=conf,
                                remediation="Remove internal hostnames/addresses from public documents; keep them in internal docs only.")
        return self.result(CheckStatus.PASS, f"No internal network references found.{note}", evidence=ev, confidence=conf)


class PrivilegedEndpoint(_MachineData):
    id = "CORE-SECURITY-009"
    family_id = "MACHINE-DATA-003"
    title = "Privileged endpoint advertised to agents"
    fix_owner = "mcp"
    severity_on_fail = Severity.MEDIUM
    experimental = True
    references = ("https://modelcontextprotocol.io/specification/",)
    standards = ("OWASP Agentic Top 10 2026: ASI02 (partial)",)
    why_it_matters = ("An agent-facing declaration of an admin or destructive interface invites its use; Core "
                       "reports the declaration only.")
    promotion_criteria = ("Precision ≥ 0.8 on a hand-labelled sample of ≥ 50 declared-privileged hits "
                           "from the calibration corpus, and a WARN rate ≤ 5% on the marketing corpus.")
    limitations = ("Passive signal only. Scovant Core reports declared MCP server names and OpenAPI paths; the "
                   "privileged/destructive classification is a NAME-BASED GUESS, never an inspection of actual "
                   "behaviour, and it never authenticates, invokes a tool or submits a request.")

    def evaluate(self, store, ctx):
        try:
            self._check_readable(store)
        except _Unreadable as exc:
            return self.error(exc.reason, exc.evidence)
        mcp = store.gathered("mcp_discovery") or {}
        api = store.gathered("openapi") or {}
        names: list[tuple[str, str]] = []
        for srv in ((mcp.get("discovery") or {}).get("servers") or []):
            if srv.get("name"):
                names.append((str(srv["name"]), "mcp_server"))
        for path in api.get("paths") or []:
            names.append((str(path), "openapi_path"))
        any_truncated = bool(mcp.get("truncated")) or bool(api.get("truncated"))
        if not names:
            # An empty declared-interface set is genuinely absent evidence
            # UNLESS the source record itself was cut off at the fetch cap —
            # `_extract_paths_and_schemas`/`_parse_servers` degrade to an
            # empty list on a truncated body exactly as they do on a real
            # absence, so a partial read must not be reported as if nothing
            # was ever declared.
            if any_truncated:
                return self.na("No agent-facing interface declarations gathered.", {"truncated": True},
                                confidence=Confidence.MEDIUM)
            return self.na("No agent-facing interface declarations gathered.")
        ev = {"declared": len(names)}
        note, truncated = record_truncation({"truncated": any_truncated}, ev)
        conf = truncated_confidence(truncated, default=Confidence.MEDIUM)
        risks = {n: classify_tool_risk(n, "", []) for n, _k in names}
        hits = [{"name": n, "surface_kind": k, "risk": risks[n]} for n, k in names
                if _PRIVILEGED_RE.search(n) or risks[n] == "DESTRUCTIVE"]
        ev["hits"] = hits[:20]
        if hits:
            return self.result(CheckStatus.WARN,
                                f"{len(hits)} administrative/destructive interface(s) advertised to agents.{note}",
                                evidence=ev, confidence=conf,
                                remediation="Keep admin/destructive interfaces out of public agent metadata, or "
                                            "gate them behind explicit authorization and confirmation.")
        return self.result(CheckStatus.PASS, f"No administrative/destructive interfaces advertised.{note}",
                            evidence=ev, confidence=conf)


class SensitiveSchemaField(_MachineData):
    id = "CORE-SECURITY-010"
    family_id = "MACHINE-DATA-004"
    title = "Sensitive field advertised in a machine schema"
    fix_owner = "backend"
    severity_on_fail = Severity.MEDIUM
    experimental = True
    references = ("https://spec.openapis.org/oas/latest.html",)
    standards = ("OpenAPI 3",)
    why_it_matters = ("A schema that names a password field is normal; one that ships a sample or real value for "
                       "it is a leak. The classification distinguishes the three.")
    promotion_criteria = ("Zero FAIL verdicts on the public fixture corpus and ≥ 3 confirmed true positives "
                           "(real_value_like) on the calibration corpus.")
    limitations = ("Passive signal only. Scovant Core reports declared OpenAPI schema field names and their "
                   "example/default values; it never authenticates, invokes an endpoint or submits a request.")

    def evaluate(self, store, ctx):
        try:
            self._check_readable(store)
        except _Unreadable as exc:
            return self.error(exc.reason, exc.evidence)
        api = store.gathered("openapi") or {}
        schemas = api.get("schemas")
        if not schemas:
            # An empty `schemas` map is genuinely "nothing to classify" UNLESS
            # the openapi document itself was cut off at the fetch cap —
            # `_extract_paths_and_schemas` degrades to `{}` on a truncated
            # body exactly as it does when there is genuinely no
            # `components.schemas` block, so a partial read must not be
            # reported as if the document declared no sensitive fields.
            if api.get("truncated"):
                return self.na("No machine schema gathered.", {"truncated": True}, confidence=Confidence.MEDIUM)
            return self.na("No machine schema gathered.")
        hits = []
        for schema, props in schemas.items():
            for prop, meta in (props or {}).items():
                if not any(k in prop.lower() for k in _SENSITIVE_FIELDS):
                    continue
                sample = None
                if isinstance(meta, dict):
                    sample = meta.get("example") if isinstance(meta.get("example"), str) else None
                    if sample is None and isinstance(meta.get("default"), str):
                        sample = meta.get("default")
                redacted: dict = {}
                if sample is None:
                    cls = "field_name_only"
                else:
                    secret_hits = detect_secrets(f"{prop}: {sample}")
                    if secret_hits and not is_placeholder(sample):
                        cls = "real_value_like"
                        redacted = secret_hits[0].redacted
                    else:
                        cls = "sample_value"
                hits.append({"schema": schema, "field": prop, "classification": cls, **redacted})
        ev = {"hits": hits[:30]}
        note, truncated = record_truncation({"truncated": bool(api.get("truncated"))}, ev, document="the OpenAPI schema")
        conf = truncated_confidence(truncated, default=Confidence.MEDIUM)
        if any(h["classification"] == "real_value_like" for h in hits):
            return self.result(CheckStatus.FAIL, f"A sensitive schema field carries a value that looks real (redacted).{note}",
                                evidence=ev, confidence=truncated_confidence(truncated), severity=Severity.HIGH,
                                remediation="Remove real values from schema examples; rotate the credential.")
        if any(h["classification"] == "sample_value" for h in hits):
            return self.result(CheckStatus.WARN, f"Sensitive schema field(s) ship sample values.{note}", evidence=ev,
                                confidence=conf,
                                remediation="Use obviously fake placeholders (e.g. <redacted>) for sensitive examples.")
        return self.result(CheckStatus.PASS, f"Sensitive fields are declared by name only.{note}", evidence=ev, confidence=conf)


MACHINE_DATA_CHECKS: list[CoreCheck] = [CredentialExposed(), InternalReference(), PrivilegedEndpoint(), SensitiveSchemaField()]
