"""The OSS boundary at source level: nothing in the package may import Cloud."""
import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "scovant_core"
_CLOUD_IMPORT = re.compile(r"^\s*(from|import)\s+app(\.|\s|$)", re.M)


def test_package_never_imports_cloud():
    if not SRC.exists():
        # test-core-isolated copies only tests/ + fixtures/ into the isolated
        # run — src/ is deliberately absent there (that's the whole point:
        # proving the package installs and tests from a dir with no `app/`).
        # An empty SRC.rglob() would otherwise make `offenders == []` pass
        # vacuously with nothing actually checked; skip explicitly instead.
        pytest.skip("package sources not present (isolated run)")
    offenders = [
        str(p.relative_to(SRC))
        for p in SRC.rglob("*.py")
        if _CLOUD_IMPORT.search(p.read_text())
    ]
    assert offenders == []
