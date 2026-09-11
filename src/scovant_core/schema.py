"""Report JSON schema — generated from the pydantic models (never hand-written).

`report_schema()` is `Report.model_json_schema()` (pydantic v2, JSON Schema
draft 2020-12 by construction) plus `$schema`/`$id`/`title`/`description` and
a `const`-pinned `schema_version`. `python -m scovant_core.schema` writes the
committed `docs/report.schema.json` (or prints it with `--stdout`, the
only mode available from an installed wheel); `tests/test_schema.py` regenerates and
compares it, and validates every golden fixture against it — the same
"generated file pinned by a test" discipline as `docs.py`/`docs/checks.md`.

Bump policy (see docs/methodology.md § Report schema): adding a key to the
report is NOT a breaking change and does not bump `REPORT_SCHEMA_VERSION`.
Removing or retyping an existing field is breaking and bumps it. The schema
therefore deliberately does not set `additionalProperties: false` at the top
level — that constraint isn't added by pydantic, and this module must not
narrow it.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from scovant_core.models import REPORT_SCHEMA_VERSION, Report

# Dereferenceable by construction: a consumer that resolves `$id` must get
# the schema document itself, not GitHub's HTML view of it.
SCHEMA_ID = "https://raw.githubusercontent.com/Scovant/scovant-core/main/docs/report.schema.json"


def report_schema() -> dict:
    s = Report.model_json_schema()
    s["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    s["$id"] = SCHEMA_ID
    s["title"] = "Scovant Core report"
    s["description"] = (
        "Output of `scovant scan --format json`. Additive keys may appear without a "
        "schema_version bump; a removed or retyped field bumps schema_version."
    )
    s["properties"]["schema_version"] = {"type": "string", "const": REPORT_SCHEMA_VERSION}
    return s


def render_schema() -> str:
    return json.dumps(report_schema(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    """`python -m scovant_core.schema [--stdout]`.

    With `--stdout` (or when the repository's `docs/` directory is not
    present, i.e. anyone running this from an installed wheel) the schema is
    written to standard output, so consumers can pipe it somewhere useful.
    The default in a checkout is to rewrite the committed
    `docs/report.schema.json`; asking for that from an installed package is
    an error with an actionable message, never a bare traceback.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    unknown = [a for a in args if a != "--stdout"]
    if unknown:
        print(f"usage: python -m scovant_core.schema [--stdout] (unknown argument: {unknown[0]})",
              file=sys.stderr)
        return 2
    text = render_schema()
    docs = Path(__file__).resolve().parents[2] / "docs"
    if "--stdout" in args:
        sys.stdout.write(text)
        return 0
    if not docs.is_dir():
        print(
            "No docs/ directory next to the package source — this writes the repository's "
            "committed docs/report.schema.json and needs a git checkout of scovant-core. "
            "Run `python -m scovant_core.schema --stdout` to print the schema instead.",
            file=sys.stderr,
        )
        return 2
    out = docs / "report.schema.json"
    out.write_text(text, encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
