"""Per-scan options and mutable context threaded through gatherers/checks."""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit


@dataclass(frozen=True)
class ScanOptions:
    profile: str = "auto"
    max_pages: int = 5
    timeout: float = 60.0
    user_agent_suffix: str | None = None
    experimental: bool = False
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    token_chars_ratio: int = 4
    allow_private_networks: bool = False


@dataclass
class ScanContext:
    input_url: str
    options: ScanOptions
    final_url: str | None = None
    origin: str | None = None          # scheme://host[:port] of the final URL
    resolved_profile: str = "auto"
    profile_confidence: float = 0.0
    notes: list[str] = field(default_factory=list)
    scan_id: str = ""

    def set_final_url(self, url: str) -> None:
        self.final_url = url
        p = urlsplit(url)
        self.origin = f"{p.scheme}://{p.netloc}"

    @property
    def profile(self) -> str:
        return self.resolved_profile
