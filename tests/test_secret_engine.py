from __future__ import annotations

import hashlib
import json
import pathlib
import re

import pytest

from scovant_core.checks.security._secrets import detect_secrets, is_placeholder, shannon_entropy
from scovant_core.models import Confidence
from scovant_core.security.redaction import redact_secret
from scovant_core.security.secret_patterns import VENDOR_PATTERNS

AWS = "AKIA" + "I" * 16
GH = "ghp_" + "a" * 24
STRIPE = "sk_" + "live_" + "z" * 20
OPENAI = "sk-" + "q" * 24
JWT = "eyJ" + "a" * 10 + ".eyJ" + "b" * 10 + ".sig"
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----"
GENERIC = '"api_key": "' + "f3a9c1e7b2d4" * 4 + '"'


def test_vendor_table_has_the_guards_nine_kinds():
    assert set(VENDOR_PATTERNS) == {"aws_access_key", "scovant_api_token", "paddle_key", "github_token",
                                    "slack_token", "google_api_key", "openai_style_key", "private_key_block", "jwt"}
    for v in VENDOR_PATTERNS.values():
        re.compile(v)


def test_redact_secret_shape():
    r = redact_secret(AWS)
    assert r == {"redacted": "AKIA…IIII", "sha256_prefix": hashlib.sha256(AWS.encode()).hexdigest()[:8], "length": 20}
    assert redact_secret("short")["redacted"] == "***"


@pytest.mark.parametrize("value,kind,conf", [
    (AWS, "aws_access_key", Confidence.HIGH), (GH, "github_token", Confidence.HIGH),
    (STRIPE, "stripe_live_key", Confidence.HIGH), (OPENAI, "openai_style_key", Confidence.HIGH),
    (JWT, "jwt", Confidence.MEDIUM), (PEM, "private_key_block", Confidence.HIGH),
    ("https://" + "user:" + "p4ss" * 3 + "@example.com/", "basic_auth_url", Confidence.HIGH),
    (GENERIC, "generic_assignment", Confidence.MEDIUM),
])
def test_detects_each_family_and_redacts(value, kind, conf):
    hits = detect_secrets("prefix " + value + " suffix")
    assert [h.kind for h in hits] == [kind] and hits[0].confidence == conf
    dumped = json.dumps(hits[0].redacted)
    assert value not in dumped and "sha256_prefix" in dumped


@pytest.mark.parametrize("value", [
    "AKIA" + "IOSFODNN7EXAMPLE", "sk_" + "live_" + "x" * 20, '"api_key": "<your-api-key-here>"',
    '"api_key": "${API_KEY}"', '"token": "REDACTED_REDACTED_REDACTED_REDACTED"', '"secret": "changeme-changeme-changeme-x"',
    '"api_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"',
])
def test_placeholders_are_suppressed(value):
    assert is_placeholder(value.split(":")[-1].strip(' "')) or detect_secrets(value) == []


def test_generic_assignment_requires_entropy():
    assert detect_secrets('"api_key": "abababababababababababababab"') == []
    assert shannon_entropy("abab" * 7) < 3.5


def test_embedded_x_run_does_not_suppress_a_real_token():
    # A real github token that merely CONTAINS a run of six x's must still be
    # detected — only a value DOMINATED by an x-run (a masking placeholder)
    # is suppressed. Fix round 1, IMPORTANT finding 1.
    value = "ghp_" + "a1B2c3D4e5F6" + "x" * 6 + "G7h8I9j0K1l2M3"
    hits = detect_secrets("prefix " + value + " suffix")
    assert [h.kind for h in hits] == ["github_token"]
    assert hits[0].confidence == Confidence.HIGH


def test_stripe_shaped_all_x_placeholder_is_still_suppressed():
    value = "sk_" + "live_" + "x" * 20
    assert is_placeholder(value)
    assert detect_secrets("prefix " + value + " suffix") == []


def test_overlap_suppression_uses_full_interval_not_just_start():
    # generic_assignment's capture starts one character BEFORE the vendor
    # github_token match and extends INTO it (a leading "-" the generic
    # pattern's character class accepts but the earlier start-only check
    # never saw as an overlap). Only the vendor hit should survive.
    # Fix round 1, MINOR finding 2.
    value = "ghp_" + "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0"
    text = "token=-" + value + " end"
    hits = detect_secrets(text)
    assert [h.kind for h in hits] == ["github_token"]


def test_no_committed_fixture_matches_a_vendor_pattern():
    root = pathlib.Path(__file__).resolve().parents[1]
    vendor = [re.compile(v) for v in VENDOR_PATTERNS.values()] + [re.compile(r"\bsk_live_[0-9a-zA-Z]{16,}")]
    for p in list((root / "fixtures").rglob("*")) + list((root / "tests").rglob("*.py")):
        if p.is_file():
            text = p.read_text(errors="ignore")
            for rx in vendor:
                assert not rx.search(text), f"{p}: vendor-shaped secret literal committed (assemble it at runtime)"
