"""Canonical JSON rendering: byte-stable for a given `Report` so two scans
with the same clock/scan_id diff cleanly (CI, `--diff`, golden tests)."""
from __future__ import annotations

import json

from scovant_core.models import Report


def render_json(report: Report) -> str:
    data = report.model_dump(mode="json")
    data["findings"] = sorted(data["findings"], key=lambda f: f["id"])
    return json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False)
