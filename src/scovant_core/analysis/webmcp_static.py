"""Static (non-executing) extraction of WebMCP `registerTool(...)` calls from
inline `<script>` bodies. Pure, I/O-free — no browser, no JS evaluation.

Only `<script>` tags without a `src` attribute are scanned (an external
script's body isn't present in the fetched HTML at all). Each
`registerTool(`/`navigator.modelContext.registerTool(` call is matched by
the bare `registerTool(` substring; its first argument is taken as the
balanced `{...}` object literal immediately following the `(` (only
whitespace may separate them). That literal is then permissively normalised
(single-quoted strings, unquoted keys, trailing commas) into valid JSON and
parsed. A literal that never balances, or that still fails to parse as a
JSON object after normalisation, counts as a parse error rather than raising
or silently vanishing.
"""
from __future__ import annotations

import json
import re

from bs4 import BeautifulSoup

MAX_TOOLS = 50

_REGISTER_CALL = re.compile(r"registerTool\s*\(")
_SINGLE_QUOTED = re.compile(r"'((?:[^'\\]|\\.)*)'")
_UNQUOTED_KEY = re.compile(r'([{,]\s*)([A-Za-z_$][\w$]*)\s*:')
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def _blank_comments_and_strings(text: str) -> str:
    """Return `text` with the contents of `//` line comments, `/*...*/`
    block comments, and `'...'`/`"..."`/`` `...` `` string literals replaced
    by spaces — same length, same offsets, everything else preserved
    verbatim (newlines kept as newlines). Used ONLY to locate a *bare*
    `registerTool(` call (so one written inside a comment or a string is
    never mistaken for a real registration); the actual object-literal
    argument is re-extracted from the ORIGINAL text at the matched offset,
    since it legitimately contains string values of its own.

    Because a string's contents are blanked in the very same left-to-right
    pass that looks for comment openers, a `//` that occurs inside a string
    (e.g. `'http://example.com'`) is already consumed as string content by
    the time a comment check would see it — it can never be misread as a
    line comment. A bare `//` outside any string IS a comment.
    """
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        two = text[i:i + 2]
        if two == "//":
            j = i
            while j < n and text[j] != "\n":
                out[j] = " "
                j += 1
            i = j
            continue
        if two == "/*":
            end = text.find("*/", i + 2)
            end = end + 2 if end != -1 else n
            for j in range(i, end):
                if text[j] != "\n":
                    out[j] = " "
            i = end
            continue
        ch = text[i]
        if ch in ("'", '"', "`"):
            quote = ch
            j = i + 1
            out[i] = " "
            while j < n:
                if text[j] == "\\":
                    out[j] = " "
                    if j + 1 < n:
                        out[j + 1] = " " if text[j + 1] != "\n" else "\n"
                    j += 2
                    continue
                if text[j] == quote:
                    out[j] = " "
                    j += 1
                    break
                if text[j] != "\n":
                    out[j] = " "
                j += 1
            i = j
            continue
        i += 1
    return "".join(out)


def _find_matching_brace(text: str, start: int) -> int | None:
    """`text[start]` must be `{`. Return the index one past its matching
    close brace, tracking nested `{}`/`[]` and skipping over quoted strings
    (single or double, with backslash escapes). `None` if it never balances
    before the text ends."""
    depth = 0
    i, n = start, len(text)
    quote: str | None = None
    while i < n:
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def _normalize_literal(literal: str) -> str:
    def _requote(m: re.Match[str]) -> str:
        inner = m.group(1).replace('\\"', '"').replace('"', '\\"')
        return f'"{inner}"'

    normalized = _SINGLE_QUOTED.sub(_requote, literal)
    normalized = _UNQUOTED_KEY.sub(r'\1"\2":', normalized)
    normalized = _TRAILING_COMMA.sub(r"\1", normalized)
    return normalized


def _shape_tool(data: dict) -> dict:
    input_schema = data.get("inputSchema")
    has_schema = isinstance(input_schema, dict) and ("type" in input_schema or "properties" in input_schema)
    keys: list[str] = []
    if isinstance(input_schema, dict):
        props = input_schema.get("properties")
        if isinstance(props, dict):
            keys = sorted(props.keys())
    return {
        "name": data.get("name"),
        "description": data.get("description"),
        "input_schema_keys": keys,
        "has_schema": has_schema,
    }


def extract_webmcp_tools(html: str) -> tuple[list[dict], int]:
    """Return `([{name, description, input_schema_keys, has_schema}], parse_errors)`
    from every `registerTool(` call found in inline (`src`-less) `<script>`
    bodies, capped at `MAX_TOOLS` tools. Never raises."""
    if not html:
        return [], 0

    soup = BeautifulSoup(html, "lxml")
    tools: list[dict] = []
    parse_errors = 0

    for script in soup.find_all("script"):
        if script.get("src"):
            continue
        body = script.string or script.get_text() or ""
        if "registerTool" not in body:
            continue

        # Search for the CALL SITE in a comment/string-blanked copy — a
        # `registerTool(` written inside a `//`/`/* */` comment or inside a
        # string literal is not a real registration. The balanced object
        # literal is still pulled from the ORIGINAL text below, since it
        # legitimately contains string values of its own.
        blanked = _blank_comments_and_strings(body)
        if "registerTool" not in blanked:
            continue

        for m in _REGISTER_CALL.finditer(blanked):
            if len(tools) >= MAX_TOOLS:
                return tools, parse_errors

            start = blanked.find("{", m.end())
            if start == -1 or blanked[m.end():start].strip():
                # No object-literal argument (e.g. `registerTool(cfg)`, an
                # identifier reference we can't statically resolve), or
                # something other than whitespace sits between "(" and "{"
                # — not our shape. Skipped, not an error.
                continue

            end = _find_matching_brace(body, start)
            if end is None:
                parse_errors += 1
                continue

            normalized = _normalize_literal(body[start:end])
            try:
                data = json.loads(normalized)
            except json.JSONDecodeError:
                parse_errors += 1
                continue
            if not isinstance(data, dict):
                parse_errors += 1
                continue

            tools.append(_shape_tool(data))

    return tools, parse_errors
