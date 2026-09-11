"""Where the package's own `.py` sources live, for the AST-based tripwires.

Several tests parse the package's source rather than only importing it —
that is the only way to assert a *structural* property (every gatherer
carries the truncation flag; every check that reads a body declares a
partial read) instead of the behaviour of whichever code path a fixture
happens to exercise.

Those tests must keep working in the isolated run, where only
`tests/ fixtures/ docs/ npm/` are copied next to each other and the package
itself comes from a wheel installed into a virtualenv — there is no `src/`
beside `tests/` there. The wheel is pure Python and ships the same `.py`
files, so the installed package is an equally valid source tree; resolving
to it keeps these tripwires *live* in that job rather than skipping them,
which is exactly the run that has historically caught what nothing else
could see.

Preference order is deliberate: the working tree first, so a local run
checks the code being edited and not a stale installed copy.
"""
from __future__ import annotations

from pathlib import Path

_REPO_SRC = Path(__file__).resolve().parents[1] / "src"


def package_source_root() -> Path:
    """The directory that contains the `scovant_core` package directory."""
    if (_REPO_SRC / "scovant_core").is_dir():
        return _REPO_SRC
    import scovant_core

    return Path(scovant_core.__file__).resolve().parent.parent
