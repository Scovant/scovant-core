"""Pins the committed JSON schema to its generator (`schema.py`) and proves
every golden fixture validates against it — see docs/methodology.md §
Report schema."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from scovant_core.models import REPORT_SCHEMA_VERSION
from scovant_core.schema import render_schema, report_schema
from tests.conftest import FIXTURES

DOC = Path(__file__).resolve().parents[1] / "docs" / "report.schema.json"


def test_committed_schema_matches_generator():
    assert DOC.read_text() == render_schema(), "run: python -m scovant_core.schema"


def test_schema_is_valid_draft_2020_12_and_pins_version():
    s = report_schema()
    Draft202012Validator.check_schema(s)
    assert s["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert s["$id"].endswith("/docs/report.schema.json")
    assert s["properties"]["schema_version"]["const"] == REPORT_SCHEMA_VERSION
    assert s.get("additionalProperties", True) is not False  # additive keys allowed (D2)


@pytest.mark.parametrize("site", ["commerce-good", "commerce-bad", "api-good", "saas-mixed"])
def test_goldens_validate_against_schema(site):
    data = json.loads((FIXTURES / "sites" / "expected" / f"{site}.json").read_text())
    Draft202012Validator(report_schema()).validate(data)
