"""``llms.txt`` parsing and validation."""
from __future__ import annotations

import re
from typing import Any


def parse_llms_txt(content: str, http_status: int) -> dict[str, Any]:
    """Parse llms.txt content and validate it.

    Returns:
        {
            "exists": bool,
            "valid": bool,
            "urls": [...],
            "raw_content": str,
            "errors": [...],
        }
    """
    result: dict[str, Any] = {
        "exists": False,
        "valid": False,
        "urls": [],
        "raw_content": content,
        "errors": [],
    }

    if http_status != 200:
        return result

    result["exists"] = True
    errors: list[str] = []

    # Extract URLs from Markdown links: [text](url)
    urls = re.findall(r"\[(?:[^\]]*)\]\((https?://[^)]+)\)", content)

    if not urls:
        errors.append("No URLs found in llms.txt — at least one link is required")

    if errors:
        result["errors"] = errors
        return result

    result["valid"] = True
    result["urls"] = urls
    return result
