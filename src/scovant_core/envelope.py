"""Evidence envelope — one versioned record for experimental evidence.

Every new experimental capability reports through `EvidenceEnvelope`. An
envelope never moves a score by itself: `scored` is false unless the record
names the rule it feeds (`rule_id`), and promoting a signal into a scored rule
follows the promotion gate in docs/evidence-envelope.md.

`python -m scovant_core.envelope [--stdout]` writes the committed
docs/evidence-envelope.schema.json (or prints it).
"""
from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Final, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ENVELOPE_VERSION: Final = "1.0"

SOURCES = ("CORE", "CLOUD", "IMPORT")
VERIFICATION_MODES = ("DECLARED", "PASSIVE_OBSERVED", "ACTIVE_SAFE", "SYNTHETIC_AUTHORIZED")
STATUSES = ("PASS", "WARN", "FAIL", "NA", "ERROR", "INCONCLUSIVE", "NOT_MEASURED")
MATURITIES = ("EXPERIMENTAL", "BETA", "STABLE")
ENVIRONMENTS = ("PUBLIC", "PRODUCTION_READ_ONLY", "SANDBOX")
FIX_OWNERS = ("frontend", "backend", "identity", "mcp", "edge_cdn", "devops", "content",
              "commerce", "security")

# Names already in use by existing evidence → envelope verification mode.
VERIFICATION_MODE_MAPPING: dict[str, str] = {
    "DECLARED": "DECLARED",
    "PASSIVE_OBSERVED": "PASSIVE_OBSERVED",
    "STATIC_DECLARED": "DECLARED",
    "ACTIVE_AUTHORIZED": "ACTIVE_SAFE",
}


def map_verification_mode(name: str, environment: str) -> str:
    """Envelope mode for an existing verification-mode name. An authenticated
    active call against a sandbox is a synthetic write, not a safe read."""
    mode = VERIFICATION_MODE_MAPPING[name]
    if name == "ACTIVE_AUTHORIZED" and environment == "SANDBOX":
        return "SYNTHETIC_AUTHORIZED"
    return mode


# The invariants below, expressed for non-Python consumers of the schema.
_SCHEMA_INVARIANTS: list[dict[str, Any]] = [
    {"if": {"properties": {"scored": {"const": True}}, "required": ["scored"]},
     "then": {"properties": {"rule_id": {"type": "string"}}, "required": ["rule_id"]}},
    {"if": {"properties": {"verification_mode": {"const": "SYNTHETIC_AUTHORIZED"}},
            "required": ["verification_mode"]},
     "then": {"properties": {"environment": {"const": "SANDBOX"}}, "required": ["environment"]}},
    {"if": {"properties": {"status": {"enum": ["WARN", "FAIL"]}}, "required": ["status"]},
     "then": {"properties": {"fix_owner": {"type": "string"}}, "required": ["fix_owner"]}},
]


class EvidenceEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", json_schema_extra={"allOf": cast(Any, _SCHEMA_INVARIANTS)})

    envelope_version: Literal["1.0"] = ENVELOPE_VERSION
    id: uuid.UUID
    scan_id: str | None = None
    source: Literal["CORE", "CLOUD", "IMPORT"]
    verification_mode: Literal["DECLARED", "PASSIVE_OBSERVED", "ACTIVE_SAFE", "SYNTHETIC_AUTHORIZED"]
    status: Literal["PASS", "WARN", "FAIL", "NA", "ERROR", "INCONCLUSIVE", "NOT_MEASURED"]
    maturity: Literal["EXPERIMENTAL", "BETA", "STABLE"]
    scored: bool = False
    rule_id: str | None = None
    check_id: str | None = None
    capability: str = Field(min_length=1)
    principal: dict[str, Any] = Field(default_factory=dict)
    intent: dict[str, Any] = Field(default_factory=dict)
    environment: Literal["PUBLIC", "PRODUCTION_READ_ONLY", "SANDBOX"]
    observed_at: datetime
    collector_version: str = Field(min_length=1)
    ruleset_version: str | None = None
    policy_id: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    fix_owner: Literal["frontend", "backend", "identity", "mcp", "edge_cdn", "devops", "content",
                       "commerce", "security"] | None = None

    @field_validator("observed_at")
    @classmethod
    def _aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.utcoffset() is None:
            raise ValueError("observed_at must carry a timezone")
        return v

    @model_validator(mode="after")
    def _invariants(self) -> EvidenceEnvelope:
        if self.scored and not self.rule_id:
            raise ValueError("scored evidence must name the rule it feeds (rule_id)")
        if self.verification_mode == "SYNTHETIC_AUTHORIZED" and self.environment != "SANDBOX":
            raise ValueError("SYNTHETIC_AUTHORIZED evidence must come from a SANDBOX environment")
        if self.status in ("WARN", "FAIL") and self.fix_owner is None:
            raise ValueError("WARN and FAIL evidence must name a fix_owner")
        return self


def validate_envelope(data: dict) -> EvidenceEnvelope:
    return EvidenceEnvelope.model_validate(data)


# Dereferenceable by construction, like report.schema.json.
SCHEMA_ID = "https://raw.githubusercontent.com/Scovant/scovant-core/main/docs/evidence-envelope.schema.json"


def envelope_schema() -> dict:
    s = EvidenceEnvelope.model_json_schema()
    s["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    s["$id"] = SCHEMA_ID
    s["title"] = "Scovant evidence envelope"
    s["description"] = (
        "One record of experimental evidence. Changing any field mints a new "
        "envelope_version; unknown top-level keys are rejected."
    )
    s["properties"]["envelope_version"] = {"type": "string", "const": ENVELOPE_VERSION}
    return s


def render_envelope_schema() -> str:
    return json.dumps(envelope_schema(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    """`python -m scovant_core.envelope [--stdout]` — rewrite the committed
    docs/evidence-envelope.schema.json, or print it."""
    args = list(sys.argv[1:] if argv is None else argv)
    unknown = [a for a in args if a != "--stdout"]
    if unknown:
        print(f"usage: python -m scovant_core.envelope [--stdout] (unknown argument: {unknown[0]})",
              file=sys.stderr)
        return 2
    text = render_envelope_schema()
    docs = Path(__file__).resolve().parents[2] / "docs"
    if "--stdout" in args:
        sys.stdout.write(text)
        return 0
    if not docs.is_dir():
        print("No docs/ directory next to the package source — run "
              "`python -m scovant_core.envelope --stdout` to print the schema instead.",
              file=sys.stderr)
        return 2
    out = docs / "evidence-envelope.schema.json"
    out.write_text(text, encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
