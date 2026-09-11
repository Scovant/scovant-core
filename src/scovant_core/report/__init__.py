"""Report renderers. `render_json` and `render_text` each take the same
`Report` model and are the only two output formats this package ships."""
from __future__ import annotations

from scovant_core.report.json import render_json
from scovant_core.report.text import render_text

__all__ = ["render_json", "render_text"]
