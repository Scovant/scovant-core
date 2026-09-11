"""Network safety policy for a scan (all limits are per process, per scan)."""
from __future__ import annotations

from dataclasses import dataclass, field

import scovant_core

# The one Core user-agent constant. Defined here (not in `engine.py`) so
# gatherers that need it for an outbound probe (`reference_integrity`) can
# import it without reaching into `engine`, which would be a cycle
# (`engine` imports `security.client`, which imports this module).
CORE_USER_AGENT = (
    f"ScovantCore/{scovant_core.__version__} (+https://github.com/Scovant/scovant-core)"
)

DEFAULT_SIZE_LIMITS = {
    "html": 5 * 1024 * 1024,
    "robots": 1 * 1024 * 1024,
    "sitemap_index": 5 * 1024 * 1024,
    "sitemap": 10 * 1024 * 1024,
    "json": 10 * 1024 * 1024,
    "text": 1 * 1024 * 1024,
}


@dataclass(frozen=True)
class SecurityPolicy:
    # Opt-in only: `False` unless the caller sets `ScanOptions.allow_private_networks`
    # (CLI: `--allow-private-networks`) — see docs/security.md § Private-network
    # targets (opt-in) for what this lifts and what stays in force. Narrow by
    # design: even with this `True`, the address block is lifted ONLY for a
    # hostname listed in `private_hosts` below — a redirect hop or any
    # discovered link (sitemap URL, policy page, well-known document, ...) on
    # a DIFFERENT host stays fully guarded.
    allow_private_networks: bool = False
    # Lower-cased hostnames the block is lifted for when `allow_private_networks`
    # is `True`. `engine.scan` populates this with exactly the entry URL's own
    # host — never empty-means-everything, and never derived from anything the
    # scan discovers mid-run.
    private_hosts: frozenset[str] = field(default_factory=frozenset)
    max_redirects: int = 5
    connect_timeout: float = 5.0
    request_timeout: float = 15.0
    total_budget_seconds: float = 60.0
    per_domain_concurrency: int = 4   # reserved — not enforced in this version
    # per-`kind` byte caps; any caller-supplied dict (even a partial one, e.g.
    # `size_limits={"robots": 1024}`) has its overrides merged onto
    # DEFAULT_SIZE_LIMITS in __post_init__ below, so a partial override still
    # has every other kind's default limit available.
    size_limits: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_SIZE_LIMITS))

    def __post_init__(self) -> None:
        # a caller supplying a partial override (e.g. `size_limits={"robots": 1024}`
        # in a test) still gets every other kind's default limit, never a KeyError.
        merged = dict(DEFAULT_SIZE_LIMITS)
        merged.update(self.size_limits)
        object.__setattr__(self, "size_limits", merged)

    def limit_for(self, kind: str) -> int:
        return self.size_limits.get(kind, self.size_limits["text"])
