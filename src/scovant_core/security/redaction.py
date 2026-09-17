from __future__ import annotations

import hashlib


def redact_secret(value: str) -> dict:
    """The only shape a matched secret may take in evidence. Never the value."""
    shown = f"{value[:4]}…{value[-4:]}" if len(value) >= 12 else "***"
    return {"redacted": shown, "sha256_prefix": hashlib.sha256(value.encode()).hexdigest()[:8], "length": len(value)}
