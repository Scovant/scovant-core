"""CORE-SECURITY-017/018 — passive consistency of a site's published OAuth
metadata (MCP-AUTH-011/012). Both read the `oauth_metadata` gatherer's record
of the two documents Core already fetches; no request of their own, no token,
no client registration, no redirect."""
from __future__ import annotations

from urllib.parse import urlsplit

from scovant_core.checks._document import document_status
from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.gatherers.oauth_metadata import normalize_issuer
from scovant_core.models import Category, CheckStatus, Severity

_LIMITS = ("Passive signal only. Scovant Core reads the published metadata documents at the origin of the site "
           "itself; it never authenticates, registers a client or runs an OAuth flow, so it cannot see "
           "what the server enforces beyond what it advertises.")
_PROMOTION_PR = ("Calibrate on a large real-world scan corpus after two weekly rescans: every "
                 "resource-origin FAIL reviewed by hand against the published document, none traced to our "
                 "own fetch, and no FAIL caused by a legitimate resource identifier on a sibling host.")
_PROMOTION_AS = ("Calibrate on a large real-world scan corpus after two weekly rescans: every issuer FAIL "
                 "reviewed by hand (issuers that carry a path are the expected edge case), none traced to our "
                 "own fetch, and the PKCE/iss low WARN rate reported separately from the FAILs.")


def _https(url: str) -> bool:
    return url.lower().startswith("https://")


def _same_host(a: str, b: str) -> bool:
    return (urlsplit(a).hostname or "").lower() == (urlsplit(b).hostname or "").lower()


class _Unreadable(Exception):
    def __init__(self, status: CheckStatus, reason: str):
        super().__init__(reason)
        self.status, self.reason = status, reason


def _read(record: dict, *, what: str) -> None:
    """Raise `_Unreadable` with ERROR (our fetch failed, or our own cap cut the
    body before it parsed) or N/A (not published, HTML catch-all, not JSON)."""
    v = document_status(record, what=what)
    if v:
        raise _Unreadable(v.status, v.reason)
    if not record["parseable"]:
        if record.get("truncated"):
            raise _Unreadable(CheckStatus.ERROR, f"{what} was cut off at the fetch cap before it could be parsed")
        raise _Unreadable(CheckStatus.NA, f"{what} is not a JSON object (treated as not published)")


class _Oauth(CoreCheck):
    category = Category.SECURITY
    security_domain = "auth"
    fix_owner = "identity"
    verification_mode = "PASSIVE_OBSERVED"
    security_tags = ("agentic-security", "oauth")
    experimental = True
    severity_on_fail = Severity.HIGH
    limitations = _LIMITS
    cloud_extension = ("Scovant Cloud shows this finding in the Agentic Security & Trust section with "
                       "regression tracking and an exact re-test command.")

    @staticmethod
    def _grade(*, fails: list[str], warns_medium: list[str], warns_low: list[str], ev: dict,
               messages: dict[str, str], fix: dict[str, str], pass_summary: str):
        """`(status, summary, severity, remediation)` for the problems found —
        the worst verdict, every problem listed in `ev["problems"]`. The caller
        makes the one `self.result` call, so the truncation confidence and note
        are wired in `evaluate()` where the audit reads them."""
        problems = [*fails, *warns_medium, *warns_low]
        ev["problems"] = problems
        if not problems:
            return CheckStatus.PASS, pass_summary, None, ""
        summary = " ".join(messages[p] for p in problems)
        remediation = " ".join(dict.fromkeys(fix[p] for p in problems))
        if fails:
            return CheckStatus.FAIL, summary, Severity.HIGH, remediation
        return CheckStatus.WARN, summary, (Severity.MEDIUM if warns_medium else Severity.LOW), remediation


class ProtectedResourceConsistency(_Oauth):
    id = "CORE-SECURITY-017"
    family_id = "MCP-AUTH-011"
    promotion_criteria = _PROMOTION_PR
    title = "OAuth protected-resource metadata consistency"
    references = ("https://www.rfc-editor.org/rfc/rfc9728",)
    standards = ("RFC 9728", "OWASP Agentic Top 10 2026: ASI03 (partial)")
    why_it_matters = ("An agent obtains a token for the `resource` this document names. When that names a "
                      "different origin, or points at authorization servers over plain HTTP, tokens are no "
                      "longer bound to this server and can be minted, replayed or intercepted elsewhere.")

    _MESSAGES = {
        "resource_other_origin": "The declared `resource` names a different site than the one serving it.",
        "resource_sibling_host": ("The declared `resource` names another host on this site (for example the "
                                  "apex instead of `www.`) than the one serving the document."),
        "resource_missing": "The document does not declare `resource`.",
        "authorization_servers_invalid": "`authorization_servers` is missing, empty or not a list of URLs.",
        "authorization_server_not_https": "An authorization server is declared over plain HTTP.",
        "jwks_uri_not_https": "`jwks_uri` is declared over plain HTTP.",
    }
    _FIX = {
        "resource_other_origin": "Set `resource` to this server's own canonical URL so tokens are audience-bound to it.",
        "resource_sibling_host": ("Serve the document from the host `resource` names (redirect the other host "
                                  "to it), or set `resource` to the host that serves it."),
        "resource_missing": "Declare `resource` as this server's canonical URL (RFC 9728 §2).",
        "authorization_servers_invalid": "Declare `authorization_servers` as a non-empty list of issuer URLs.",
        "authorization_server_not_https": "Declare every authorization server with an HTTPS URL.",
        "jwks_uri_not_https": "Serve `jwks_uri` over HTTPS.",
    }

    def evaluate(self, store, ctx):
        pr = store.get("oauth_metadata")["protected_resource"]
        ev = {"document": pr["url"], "http_status": pr["status"]}
        if pr.get("served_url") and pr["served_url"] != pr["url"]:
            ev["served_from"] = pr["served_url"]
        note, truncated = record_truncation(pr, ev, document="OAuth protected-resource metadata")
        conf = truncated_confidence(truncated)
        try:
            _read(pr, what="OAuth protected-resource metadata")
        except _Unreadable as exc:
            if exc.status is CheckStatus.ERROR:
                return self.error(exc.reason, ev)
            return self.na(exc.reason + note, ev, confidence=conf)
        ev.update({"resource": pr["resource"], "authorization_servers": pr["authorization_servers"],
                   "jwks_uri": pr["jwks_uri"]})

        fails, warns = [], []
        if pr["resource"] is None:
            if not truncated:
                warns.append("resource_missing")
        elif pr["resource_matches_origin"] is False:
            if pr.get("resource_same_site") is True:
                warns.append("resource_sibling_host")
            else:
                fails.append("resource_other_origin")
        valid = pr["authorization_servers_valid"]
        if valid is False or (valid is None and not truncated):
            warns.append("authorization_servers_invalid")
        if any(isinstance(u, str) and not _https(u) for u in pr["authorization_servers"]):
            warns.append("authorization_server_not_https")
        if pr["jwks_uri"] and not _https(pr["jwks_uri"]):
            warns.append("jwks_uri_not_https")
        status, summary, severity, remediation = self._grade(
            fails=fails, warns_medium=warns, warns_low=[], ev=ev, messages=self._MESSAGES, fix=self._FIX,
            pass_summary="Protected-resource metadata names this origin and uses https throughout.")
        return self.result(status, summary + note, evidence=ev, confidence=conf, severity=severity,
                           remediation=remediation)


class AuthorizationServerConsistency(_Oauth):
    id = "CORE-SECURITY-018"
    family_id = "MCP-AUTH-012"
    promotion_criteria = _PROMOTION_AS
    title = "OAuth authorization-server metadata consistency"
    references = ("https://www.rfc-editor.org/rfc/rfc8414", "https://www.rfc-editor.org/rfc/rfc9207")
    standards = ("RFC 8414", "RFC 9207", "OWASP Agentic Top 10 2026: ASI03 (partial)")
    why_it_matters = ("An agent client trusts this document to tell it who issues tokens and where to send "
                      "the user. An issuer that does not match where the document is served, endpoints over "
                      "plain HTTP, or no advertised PKCE/issuer-identification leave room for mix-up and code "
                      "interception attacks.")

    _MESSAGES = {
        "issuer_missing": "The metadata does not declare `issuer`.",
        "issuer_mismatch": "`issuer` is not exactly the URL the metadata is served under.",
        "issuer_sibling_host": ("`issuer` names another host on this site than the one serving the metadata "
                                "(for example the apex instead of `www.`)."),
        "authorization_endpoint_missing": "`authorization_endpoint` is not declared.",
        "authorization_endpoint_not_https": "`authorization_endpoint` is declared over plain HTTP.",
        "token_endpoint_missing": "`token_endpoint` is not declared.",
        "token_endpoint_not_https": "`token_endpoint` is declared over plain HTTP.",
        "pkce_s256_not_advertised": ("PKCE with S256 is not advertised in `code_challenge_methods_supported` "
                                     "(the server may still enforce it; agents cannot discover that it does)."),
        "iss_parameter_not_advertised": ("The RFC 9207 `iss` authorization-response parameter is not advertised "
                                         "(the server may still enforce it; agents cannot discover that it does)."),
        "issuer_not_in_protected_resource": ("The protected-resource metadata does not list this authorization "
                                             "server's issuer in `authorization_servers`."),
    }
    _FIX = {
        "issuer_missing": "Declare `issuer` as this server's exact issuer URL (RFC 8414 §2).",
        "issuer_mismatch": ("Serve the metadata at the well-known URL derived from the issuer, or set `issuer` "
                            "to exactly that URL (RFC 8414 issuer rule)."),
        "issuer_sibling_host": ("Serve the metadata from the issuer's own host (redirect the other host to it), "
                                "or set `issuer` to the host that serves it (RFC 8414 issuer rule)."),
        "authorization_endpoint_missing": "Declare `authorization_endpoint` with an HTTPS URL.",
        "authorization_endpoint_not_https": "Serve `authorization_endpoint` over HTTPS.",
        "token_endpoint_missing": "Declare `token_endpoint` with an HTTPS URL.",
        "token_endpoint_not_https": "Serve `token_endpoint` over HTTPS.",
        "pkce_s256_not_advertised": "Require PKCE and list \"S256\" in `code_challenge_methods_supported`.",
        "iss_parameter_not_advertised": ("Return `iss` in authorization responses and set "
                                         "`authorization_response_iss_parameter_supported: true`."),
        "issuer_not_in_protected_resource": ("List this issuer in the protected-resource metadata's "
                                             "`authorization_servers`, or remove the stale entry."),
    }

    def evaluate(self, store, ctx):
        oauth = store.get("oauth_metadata")
        a, pr = oauth["authorization_server"], oauth["protected_resource"]
        ev = {"document": a["url"], "http_status": a["status"]}
        if a.get("served_url") and a["served_url"] != a["url"]:
            ev["served_from"] = a["served_url"]
        note, truncated = record_truncation(a, ev, document="OAuth authorization-server metadata")
        conf = truncated_confidence(truncated)
        try:
            _read(a, what="OAuth authorization-server metadata")
        except _Unreadable as exc:
            if exc.status is CheckStatus.ERROR:
                return self.error(exc.reason, ev)
            return self.na(exc.reason + note, ev, confidence=conf)
        ev.update({
            "issuer": a["issuer"],
            "authorization_endpoint": a["authorization_endpoint"],
            "token_endpoint": a["token_endpoint"],
            "code_challenge_methods_supported": a["code_challenge_methods_supported"],
            "iss_parameter_supported": a["iss_parameter_supported"],
            "registration": {
                "dynamic_registration": a["registration_endpoint"] is not None,
                "client_id_metadata_document": a["client_id_metadata_document_supported"] is True,
            },
        })

        fails, medium, low = [], [], []
        if a["issuer"] is None:
            if not truncated:
                fails.append("issuer_missing")
        elif a["issuer_exact"] is False:
            # A different host on the same site is a medium WARN; the same
            # host with a path, or another site, stays a FAIL.
            if a.get("issuer_same_site") is True and not _same_host(a["issuer"], a.get("served_url") or a["url"]):
                medium.append("issuer_sibling_host")
            else:
                fails.append("issuer_mismatch")
        for name in ("authorization_endpoint", "token_endpoint"):
            url = a[name]
            if url is None:
                if not truncated:
                    medium.append(f"{name}_missing")
            elif not _https(url):
                medium.append(f"{name}_not_https")
        methods = a["code_challenge_methods_supported"]
        if (methods is None and not truncated) or (methods is not None and "S256" not in methods):
            low.append("pkce_s256_not_advertised")
        if a["iss_parameter_supported"] is False or (a["iss_parameter_supported"] is None and not truncated):
            low.append("iss_parameter_not_advertised")
        if (a["issuer"] is not None and pr["parseable"] and pr["authorization_servers_valid"] is True
                and normalize_issuer(a["issuer"]) not in {normalize_issuer(u) for u in pr["authorization_servers"]}):
            low.append("issuer_not_in_protected_resource")
        status, summary, severity, remediation = self._grade(
            fails=fails, warns_medium=medium, warns_low=low, ev=ev, messages=self._MESSAGES, fix=self._FIX,
            pass_summary="Authorization-server metadata is consistent and advertises PKCE and issuer identification.")
        return self.result(status, summary + note, evidence=ev, confidence=conf, severity=severity,
                           remediation=remediation)


OAUTH_CHECKS = [ProtectedResourceConsistency(), AuthorizationServerConsistency()]
