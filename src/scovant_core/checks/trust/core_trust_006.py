"""CORE-TRUST-006: security.txt (RFC 9116), read from
`gatherers/security_txt.py`."""
from __future__ import annotations

from scovant_core.checks._document import document_status
from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus


class SecurityTxtDiscoverability(CoreCheck):
    id = "CORE-TRUST-006"
    title = "security.txt discoverability"
    category = Category.TRUST
    verification_mode = "DECLARED"
    profiles = frozenset({"saas", "api", "commerce"})
    weight = 2
    references = ("https://www.rfc-editor.org/rfc/rfc9116",)
    why_it_matters = (
        "A security researcher — human or an automated scanner — needs a documented way to report a "
        "vulnerability; an agent auditing a site's operational maturity reads security.txt as that signal."
    )
    limitations = "Only the conventional /.well-known/security.txt and legacy /security.txt paths are probed."
    cloud_extension = "Scovant Cloud validates the full RFC 9116 field set (Canonical, Encryption, Preferred-Languages), not only Contact and Expires."

    def evaluate(self, store, ctx):
        sec = store.get("security_txt")
        ev = {
            "found_url": sec["found_url"], "status": sec["status"], "contact": sec["contact"],
            "expires": sec["expires"], "expires_valid": sec["expires_valid"],
        }

        # Only recorded when true — keeps evidence (and the goldens) byte-
        # identical for the common case (a real security.txt is never
        # served through an HTML catch-all) while still surfacing the rare
        # soft-200 case when it happens.
        if sec["served_as_html"]:
            ev["served_as_html"] = True

        # `found_url is None` with `status is None` means both paths failed
        # OUR fetch (a real network error, not a real HTTP response) — that
        # is unmeasured (ERROR), not "genuinely absent" (N/A) — see
        # CoreCheck's ERROR-vs-N/A discipline. `document_status` covers both
        # that and the found_url-is-None ladder in one call: a `found_url`
        # implies `status == 200`/not served-as-html, so it returns `None`
        # (proceed) for the PASS/WARN branches below unchanged.
        v = document_status(sec, what="security.txt")
        if v:
            if v.status is CheckStatus.ERROR:
                if sec["status"] is None:
                    return self.error("security.txt could not be read.", ev)
                return self.error(f"security.txt could not be read (HTTP {sec['status']}).", ev)
            if sec["served_as_html"]:
                return self.na(
                    "No security.txt was found — the path is served by an HTML catch-all.", ev
                )
            return self.na("No security.txt was found at /.well-known/security.txt or /security.txt.", ev)

        # Every branch below is drawn from the ONE security.txt document
        # that was actually found and read (`document_status` above already
        # ruled out the absence/error paths, neither of which was ever
        # parsed as a security.txt body) — `sec["truncated"]` is single-
        # document by construction (not in FOLDED_RECORD_NAMES), so the
        # note can honestly name it.
        note, truncated = record_truncation(sec, ev, document="security.txt")
        conf = truncated_confidence(truncated)

        if sec["contact"] and (sec["expires"] is None or sec["expires_valid"]):
            return self.result(CheckStatus.PASS, "A valid security.txt was found with a contact method." + note,
                               evidence=ev, confidence=conf)

        if not sec["contact"]:
            return self.result(
                CheckStatus.WARN, "security.txt was found but has no Contact field." + note, evidence=ev, confidence=conf,
                remediation="Add a Contact field (RFC 9116) to security.txt.",
            )

        return self.result(
            CheckStatus.WARN, "security.txt was found but its Expires date has passed." + note, evidence=ev, confidence=conf,
            remediation="Update the Expires field in security.txt to a future date.",
        )
