"""CORE-SECURITY-001..006 — web security baseline + security.txt validity (RFC 9116)."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Confidence, Severity

_BASE_LIMITS = ("Passive signal only. Scovant Core did not authenticate, submit forms or invoke tools; "
                "observed authorization behaviour is not tested.")
_HSTS_MAX_AGE = re.compile(r"max-age\s*=\s*(\d+)", re.I)
_SESSION_LIKE = re.compile(r"sess|sid|token|auth|csrf|jwt|login|remember", re.I)
_ANALYTICS_LIKE = re.compile(r"^(_ga|_gid|_gat|_fbp|_hj|ajs_|amp_|utm|__utm)", re.I)


class _Web(CoreCheck):
    category = Category.SECURITY
    security_domain = "web_baseline"
    verification_mode = "PASSIVE_OBSERVED"
    security_tags = ("agentic-security", "web-baseline")
    limitations = _BASE_LIMITS
    cloud_extension = "Scovant Cloud shows this finding in the Agentic Security & Trust section with regression tracking."


class HttpsBaseline(_Web):
    id = "CORE-SECURITY-001"
    family_id = "SEC-WEB-001"
    title = "HTTPS baseline"
    fix_owner = "edge_cdn"
    severity_on_fail = Severity.MEDIUM
    references = ("https://www.rfc-editor.org/rfc/rfc9110",)
    standards = ("MDN:HTTPS",)
    why_it_matters = ("An agent that can be downgraded to plain HTTP can be read and rewritten in transit; "
                       "the entry URL's scheme and the http→https redirect are the two externally observable signals.")

    def evaluate(self, store, ctx):
        http = store.get("http")
        if http.get("error"):
            if http["error"]["kind"] == "security":
                return self.result(CheckStatus.FAIL, "TLS/security error on the https origin.",
                                    evidence={"error": http["error"]["kind"]})
            return self.error("entry URL could not be fetched")
        final_scheme = urlsplit(http["final_url"] or ctx.input_url).scheme
        d = http["downgrade"]
        ev = {"final_scheme": final_scheme, "downgrade_attempted": d["attempted"], "downgrade_status": d["status"],
              "redirected_to_https": d["redirected_to_https"]}
        if final_scheme != "https":
            return self.result(CheckStatus.FAIL, "The site is served over plain HTTP.", evidence=ev,
                                remediation="Serve the site over HTTPS and redirect every http:// request to https://.")
        if d["attempted"] and d["redirected_to_https"] is False:
            return self.result(CheckStatus.WARN, "https is served, but http:// answers 200 without redirecting to https.",
                                evidence=ev, remediation="Redirect http:// to https:// (301) at the edge.")
        conf = Confidence.HIGH if d["attempted"] and not d["error"] else Confidence.MEDIUM
        return self.result(CheckStatus.PASS, "Served over https; http:// redirects to https.", evidence=ev, confidence=conf)


class Hsts(_Web):
    id = "CORE-SECURITY-002"
    family_id = "SEC-WEB-002"
    title = "HSTS presence"
    fix_owner = "edge_cdn"
    severity_on_fail = Severity.LOW
    references = ("https://www.rfc-editor.org/rfc/rfc6797",)
    standards = ("RFC 6797",)
    why_it_matters = "Strict-Transport-Security keeps a returning agent on https even when it is handed an http:// link."

    def evaluate(self, store, ctx):
        http = store.get("http")
        if http.get("error"):
            return self.error("entry URL could not be fetched")
        if urlsplit(http["final_url"] or ctx.input_url).scheme != "https":
            return self.na("HSTS is not meaningful over plain http.")
        raw = http["security_headers"].get("strict-transport-security")
        m = _HSTS_MAX_AGE.search(raw or "")
        ev = {"header": raw, "max_age": int(m.group(1)) if m else None}
        if m and int(m.group(1)) >= 86400:
            return self.result(CheckStatus.PASS, "HSTS present with a meaningful max-age.", evidence=ev)
        return self.result(
            CheckStatus.WARN,
            "HSTS missing, unparsable or max-age below one day." if raw else "No Strict-Transport-Security header.",
            evidence=ev,
            remediation="Send Strict-Transport-Security: max-age=31536000 (add includeSubDomains once every subdomain is https).",
        )


class CspFraming(_Web):
    id = "CORE-SECURITY-003"
    family_id = "SEC-WEB-003"
    title = "Content-Security-Policy / framing policy"
    fix_owner = "frontend"
    severity_on_fail = Severity.MEDIUM
    references = ("https://www.w3.org/TR/CSP3/",)
    standards = ("CSP3",)
    why_it_matters = ("A framing policy stops a page being embedded and click-jacked; a CSP is the declared "
                       "allow-list agents can read. Neither alone proves XSS protection, and this check never claims it.")

    def evaluate(self, store, ctx):
        http = store.get("http")
        if http.get("error"):
            return self.error("entry URL could not be fetched")
        sh = http["security_headers"]
        csp = sh.get("content-security-policy") or sh.get("content-security-policy-report-only")
        xfo = sh.get("x-frame-options")
        framing = bool(xfo) or ("frame-ancestors" in (csp or "").lower())
        ev = {
            "csp_present": bool(csp),
            "csp_report_only": bool(sh.get("content-security-policy-report-only")) and not sh.get("content-security-policy"),
            "frame_ancestors": "frame-ancestors" in (csp or "").lower(),
            "x_frame_options": xfo,
        }
        if csp and framing:
            return self.result(CheckStatus.PASS, "CSP present with a framing directive.", evidence=ev)
        if csp:
            return self.result(CheckStatus.WARN, "CSP present but no framing policy (frame-ancestors or X-Frame-Options).",
                                evidence=ev, remediation="Add frame-ancestors 'none' (or your allowed origins) to the CSP.")
        if xfo:
            return self.result(CheckStatus.WARN, "X-Frame-Options present but no Content-Security-Policy.",
                                evidence=ev, remediation="Publish a Content-Security-Policy; keep frame-ancestors in it.")
        return self.result(CheckStatus.FAIL, "Neither Content-Security-Policy nor X-Frame-Options is sent.", evidence=ev,
                            remediation="Send a Content-Security-Policy with frame-ancestors, or at least X-Frame-Options: DENY.")


class CookieAttributes(_Web):
    id = "CORE-SECURITY-004"
    family_id = "SEC-WEB-004"
    title = "Security-relevant cookie attributes"
    fix_owner = "backend"
    severity_on_fail = Severity.MEDIUM
    references = ("https://www.rfc-editor.org/rfc/rfc6265",)
    standards = ("RFC 6265bis",)
    why_it_matters = ("A session-like cookie without Secure/HttpOnly/SameSite can be stolen or replayed by an "
                       "agent-driven page; only names and attribute flags are inspected, never values.")

    def evaluate(self, store, ctx):
        http = store.get("http")
        if http.get("error"):
            return self.error("entry URL could not be fetched")
        cookies = http["set_cookie"]
        if not cookies:
            return self.na("No cookies set on the entry response.")
        https = urlsplit(http["final_url"] or ctx.input_url).scheme == "https"
        rows, fails, warns = [], [], []
        for c in cookies:
            cls = "analytics_like" if _ANALYTICS_LIKE.search(c["name"]) else ("session_like" if _SESSION_LIKE.search(c["name"]) else "unknown")
            rows.append({**c, "classification": cls})
            if cls == "session_like":
                if https and not (c["secure"] and c["httponly"]):
                    fails.append(c["name"])
                elif not c["samesite"]:
                    warns.append(c["name"])
            elif cls == "unknown" and https and not c["secure"]:
                warns.append(c["name"])
        ev = {"cookies": rows, "failing": fails, "warning": warns}
        if fails:
            return self.result(CheckStatus.FAIL, f"Session-like cookie(s) without Secure+HttpOnly: {', '.join(fails)}.",
                                evidence=ev, remediation="Set Secure and HttpOnly on session cookies; add SameSite=Lax or Strict.")
        if warns:
            return self.result(CheckStatus.WARN, f"Cookie(s) missing SameSite or Secure: {', '.join(warns)}.",
                                evidence=ev, remediation="Add SameSite (Lax/Strict) and Secure to these cookies.")
        if any(r["classification"] == "session_like" for r in rows):
            return self.result(CheckStatus.PASS, "Session-like cookies carry Secure, HttpOnly and SameSite.", evidence=ev)
        return self.result(CheckStatus.PASS, "No session-like cookies were set; the cookie(s) present carry no flag concerns.", evidence=ev)


class ReferrerMimeHygiene(_Web):
    id = "CORE-SECURITY-005"
    family_id = "SEC-WEB-005"
    title = "Referrer / MIME hygiene headers"
    fix_owner = "edge_cdn"
    severity_on_fail = Severity.LOW
    references = ("https://www.w3.org/TR/referrer-policy/",)
    standards = ("Referrer Policy", "X-Content-Type-Options")
    why_it_matters = "Two low-cost headers that stop URL leakage and MIME sniffing; informational weight only."

    def evaluate(self, store, ctx):
        http = store.get("http")
        if http.get("error"):
            return self.error("entry URL could not be fetched")
        sh = http["security_headers"]
        missing = [h for h in ("referrer-policy", "x-content-type-options") if not sh.get(h)]
        ev = {"referrer_policy": sh.get("referrer-policy"), "x_content_type_options": sh.get("x-content-type-options"), "missing": missing}
        if not missing and "nosniff" in (sh.get("x-content-type-options") or "").lower():
            return self.result(CheckStatus.PASS, "Referrer-Policy and X-Content-Type-Options: nosniff are set.", evidence=ev)
        return self.result(CheckStatus.WARN, "Missing: " + ", ".join(missing or ["nosniff value"]) + ".", evidence=ev,
                            remediation="Send Referrer-Policy: strict-origin-when-cross-origin and X-Content-Type-Options: nosniff.")


class SecurityTxtValidity(_Web):
    id = "CORE-SECURITY-006"
    family_id = "SEC-TXT-001"
    title = "security.txt validity (RFC 9116)"
    security_domain = "disclosure"
    verification_mode = "DECLARED"
    fix_owner = "security"
    severity_on_fail = Severity.MEDIUM
    references = ("https://www.rfc-editor.org/rfc/rfc9116",)
    standards = ("RFC 9116",)
    why_it_matters = ("An expired or mis-located security.txt sends a reporter (human or agent) to a dead contact; "
                       "CORE-TRUST-006 reports presence, this check reports validity.")

    def evaluate(self, store, ctx):
        s = store.get("security_txt")
        if s["found_url"] is None:
            if s["status"] is None:
                return self.error("security.txt could not be read")
            return self.na("No security.txt published.")
        problems, warns = [], []
        if s["expires"] is None or s["expires_parsed"] is None:
            problems.append("Expires missing or unparsable")
        elif s["expired"]:
            problems.append("Expires is in the past")
        if not s["contact"]:
            warns.append("Contact missing")
        if not s["canonical_location"]:
            warns.append("served from legacy /security.txt, not /.well-known/security.txt")
        if s["canonical_uris"] and s["found_url"] not in s["canonical_uris"]:
            warns.append("Canonical: does not list the URL it was fetched from")
        ev = {"found_url": s["found_url"], "expires": s["expires"], "expired": s["expired"],
              "canonical_location": s["canonical_location"], "canonical_uris": s["canonical_uris"], "contact": s["contact"]}
        # The document WAS actually read and parsed past this point (the
        # absence/error branches above never reach here) — its `truncated`
        # field is single-document by construction (mirrors CORE-TRUST-006,
        # which reads the same gatherer record).
        note, truncated = record_truncation(s, ev, document="security.txt")
        conf = truncated_confidence(truncated)
        if problems:
            return self.result(CheckStatus.FAIL, "; ".join(problems) + "." + note, evidence=ev, confidence=conf,
                                remediation="Set Expires to a future date (RFC 3339) and keep it fresh.")
        if warns:
            return self.result(CheckStatus.WARN, "; ".join(warns) + "." + note, evidence=ev, confidence=conf,
                                remediation="Serve security.txt at /.well-known/, list its own URL under Canonical:, include Contact:.")
        return self.result(CheckStatus.PASS, "security.txt is at the canonical location, has Contact and a future Expires." + note,
                            evidence=ev, confidence=conf)


WEB_CHECKS: list[CoreCheck] = [HttpsBaseline(), Hsts(), CspFraming(), CookieAttributes(), ReferrerMimeHygiene(), SecurityTxtValidity()]
