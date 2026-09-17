"""Pin the package's gitleaks allow-list to the two synthetic secret-shaped
fixtures it exists for, so it can never silently widen and never outlive the
fixtures it names.

The release workflow's export job runs the pinned gitleaks CLI over an
export of this package tree as an independent second scanner next to the
maintainers' publish guard. `.gitleaks.toml` at the package root allow-lists
the two fixtures under `fixtures/security/machine-secret-exposed/` and
`fixtures/sites/security-bad/` whose whole purpose is to exercise the
package's own MACHINE-DATA-001 secret detector with a credential-SHAPED
value — they hold no real credential.
"""

import re
import tomllib
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent.parent

EXPECTED_PATHS = [
    r"""fixtures/security/machine-secret-exposed/llms\.txt""",
    r"""fixtures/sites/security-bad/llms\.txt""",
]

# The credential-shaped value the two fixtures exist to hold, matching the
# generic_assignment shape the package's own secret detector looks for.
GENERIC_ASSIGNMENT_RE = re.compile(r'"api_key"\s*:\s*"[0-9a-f]{24,}"')


def _load_config() -> dict:
    config_path = PACKAGE_ROOT / ".gitleaks.toml"
    assert config_path.is_file(), f"missing {config_path}"
    with config_path.open("rb") as f:
        return tomllib.load(f)


def test_allowlist_paths_are_exactly_the_two_fixtures():
    config = _load_config()
    allowlist = config.get("allowlist", {})
    assert allowlist.get("paths") == EXPECTED_PATHS, (
        "the gitleaks allow-list must name exactly the two synthetic "
        "secret-shaped fixtures, no more and no less — widening it must be "
        "deliberate, never a silent side effect"
    )


def test_allowlisted_files_exist_and_hold_a_secret_shaped_value():
    for rel_pattern in EXPECTED_PATHS:
        # Each pattern is a literal path in regex form (no metacharacters
        # beyond the escaped dot) — de-escape it back to a real path.
        rel_path = rel_pattern.replace(r"\.", ".")
        target = PACKAGE_ROOT / rel_path
        assert target.is_file(), f"allow-listed fixture is missing: {target}"

        text = target.read_text(encoding="utf-8")
        assert GENERIC_ASSIGNMENT_RE.search(text), (
            f"{target} no longer contains a generic_assignment-shaped "
            "secret — the allow-list entry has outlived its purpose"
        )


def test_allowlist_has_no_extra_entries_beyond_the_two_paths():
    config = _load_config()
    allowlist = config.get("allowlist", {})
    # Only `description` and `paths` are expected — no `regexes`, `commits`,
    # `stopwords`, etc. that would widen the allow-list in a way the two
    # tests above can't see.
    assert set(allowlist.keys()) <= {"description", "paths"}
