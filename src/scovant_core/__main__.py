"""Lets `python -m scovant_core` run the CLI directly — the npm launcher's
third fallback (no uv, no pipx) execs exactly this when only a bare `python3`
with the package installed is available.
"""
from __future__ import annotations

import sys

from scovant_core.cli import main

if __name__ == "__main__":
    sys.exit(main())
