import hashlib

import scovant_core
from scovant_core.provenance import (
    OPTIONAL_DEPENDENCIES,
    RUNTIME_DEPENDENCIES,
    environment_fingerprint,
)


def _versions(table):
    def v(name):
        if name in table:
            return table[name]
        raise __import__("importlib.metadata").metadata.PackageNotFoundError(name)
    return v


def test_fingerprint_is_deterministic_and_lists_every_runtime_dep():
    table = {"httpx": "0.28.1", "beautifulsoup4": "4.12.3", "lxml": "5.3.0", "tldextract": "5.1.2"}
    deps, digest = environment_fingerprint(versions=_versions(table), python="3.12.3")
    assert deps == {**table, "mcp": "absent"}
    assert set(RUNTIME_DEPENDENCIES) | set(OPTIONAL_DEPENDENCIES) == set(deps)
    lines = "\n".join(sorted(f"{k}=={v}" for k, v in deps.items()))
    expected = hashlib.sha256(f"core_version={scovant_core.__version__}\npython=3.12.3\n{lines}".encode()).hexdigest()
    assert digest == expected
    assert environment_fingerprint(versions=_versions(table), python="3.12.3")[1] == digest


def test_fingerprint_changes_with_a_dependency_version():
    a = environment_fingerprint(versions=_versions({"httpx": "0.28.1"}), python="3.12.3")[1]
    b = environment_fingerprint(versions=_versions({"httpx": "0.28.0"}), python="3.12.3")[1]
    assert a != b
