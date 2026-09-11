"""``Content-Signal:`` directive parsing (robots.txt extension)."""
from __future__ import annotations

from typing import Any

_KNOWN_DIMENSIONS = ("search", "ai-input", "ai-train")
_VALID_VALUES = ("yes", "no")


def parse_content_signals(robots_content: str) -> dict[str, Any]:
    """Parse ``Content-Signal:`` directives from robots.txt content.

    Format per contentsignals.org / the IETF draft:
    ``Content-Signal: ai-train=no, search=yes, ai-input=no``.
    Multiple lines (one per user-agent group) are merged, later lines winning
    on a repeated directive name. Names and values are lowercased.

    Returns:
        {
          "present": bool,                # a well-formed name=value directive
                                          # was adopted
          "directives": dict[str, str],   # every well-formed name=value pair
          "declared": bool,               # a Content-Signal LINE exists at all
          "dimensions": {"search"|"ai-input"|"ai-train": "yes"|"no"|"unset"},
          "syntax_errors": list[str],
        }

    ``dimensions`` is a clarity view: each of the three known content-use
    dimensions is explicitly yes/no/unset, so a caller can reason about
    POLICY CLARITY (was a value declared at all) separately from AGENT
    AVAILABILITY (what the declared value says).

    ``present`` keeps its original, narrower meaning (a well-formed directive
    was adopted) — a caller that instead needs "a Content-Signal line exists
    regardless of whether it parsed" should read ``declared``.
    """
    result: dict[str, Any] = {
        "present": False,
        "directives": {},
        "declared": False,
        "dimensions": {d: "unset" for d in _KNOWN_DIMENSIONS},
        "syntax_errors": [],
    }
    if not robots_content or not robots_content.strip():
        return result

    any_directive_line = False
    for raw_line in robots_content.splitlines():
        line = raw_line.strip()
        if "#" in line:
            line = line[: line.index("#")].strip()
        if not line.lower().startswith("content-signal:"):
            continue
        any_directive_line = True
        payload = line[len("content-signal:"):].strip()
        for part in payload.split(","):
            part = part.strip()
            if not part:
                continue
            name, sep, value = part.partition("=")
            name, value = name.strip().lower(), value.strip().lower()
            if not sep or not name or not value:
                result["syntax_errors"].append(
                    f"malformed Content-Signal token {part!r} (expected name=value)"
                )
                continue
            # Every well-formed name=value pair is recorded here regardless
            # of whether the name is one of the three known dimensions.
            result["directives"][name] = value
            if name in _KNOWN_DIMENSIONS:
                if value in _VALID_VALUES:
                    result["dimensions"][name] = value  # later line wins
                else:
                    result["syntax_errors"].append(
                        f"unrecognized value for {name!r}: {value!r} "
                        f"(expected yes|no)"
                    )

    result["declared"] = any_directive_line
    # Deliberately NOT `any_directive_line` — see the docstring note on
    # `present` vs `declared`.
    result["present"] = bool(result["directives"])
    return result
