"""CORE-OPERABILITY-003: cache validators on the entry response. Reads the
`http` entry response headers. Informational by design (product spec §14):
an agent re-fetching the same URL repeatedly pays needless bytes without a
validator to conditionally GET against, but this is an efficiency signal,
never a defect that should drag a category score down hard."""
from __future__ import annotations

from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity
from scovant_core.security.url_safety import redact_message


class CacheValidators(CoreCheck):
    id = "CORE-OPERABILITY-003"
    title = "Cache validators"
    category = Category.OPERABILITY
    weight = 1
    severity_on_fail = Severity.INFO
    references = ("https://www.rfc-editor.org/rfc/rfc9110#name-validator-fields",)
    why_it_matters = "Without an ETag or Last-Modified, an agent revisiting a page can never issue a conditional GET — it re-downloads the full page every time."
    limitations = "Only the entry response's own headers are checked; per-page-type validator strategy is not inspected."
    cloud_extension = "Scovant Cloud checks cache-validator presence and correctness across the full sampled page set."

    def evaluate(self, store, ctx):
        http = store.get("http")
        if http["error"]:
            err = {**http["error"], "message": redact_message(http["error"]["message"], http["input_url"])}
            return self.error(f"the entry URL could not be fetched ({http['error']['kind']}).", {"error": err})

        headers = http["headers"] or {}
        etag = headers.get("etag")
        last_modified = headers.get("last-modified")
        cache_control = headers.get("cache-control")
        ev = {"etag": etag, "last_modified": last_modified, "cache_control": cache_control}

        if etag or last_modified:
            return self.result(CheckStatus.PASS, "The entry response carries an ETag or Last-Modified validator.", evidence=ev)
        if cache_control:
            return self.result(
                CheckStatus.WARN, "The entry response carries only a Cache-Control header, no ETag or Last-Modified.",
                evidence=ev, remediation="Add an ETag or Last-Modified header so agents can issue conditional GETs.",
            )
        return self.result(
            CheckStatus.WARN, "The entry response carries no cache validator (ETag, Last-Modified, or Cache-Control).",
            evidence=ev, remediation="Add an ETag or Last-Modified header so agents can issue conditional GETs.",
        )
