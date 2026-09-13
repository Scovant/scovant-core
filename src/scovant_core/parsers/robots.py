"""robots.txt evaluation for a given user-agent token (stdlib robotparser)."""
from __future__ import annotations

from io import StringIO
from typing import Any
from urllib.robotparser import RobotFileParser

from scovant_core.registry.ai_bots import ALL_CRAWLERS

CORE_USER_AGENT_TOKEN = "ScovantCore"

# Every registered crawler token (see `registry.ai_bots.ALL_CRAWLERS`) —
# `parse_robots_txt` extracts each one's per-agent Allow/Disallow directives
# individually below.
_AI_AGENTS = tuple(b.token for b in ALL_CRAWLERS)


def _parser(robots_txt: str) -> RobotFileParser:
    p = RobotFileParser()
    p.parse((robots_txt or "").splitlines())
    return p


def is_allowed(robots_txt: str, user_agent_token: str, url: str) -> bool:
    if not (robots_txt or "").strip():
        return True
    return _parser(robots_txt).can_fetch(user_agent_token, url)


def parse_robots_txt(robots_content: str) -> dict[str, Any]:
    """Parse robots.txt and return per-agent directives plus sitemaps.

    Returns:
        {
            "general": {"allow": [...], "disallow": [...]},
            # one entry per registered crawler token (see `_AI_AGENTS`)
            "sitemaps": [...],
        }
    """
    result: dict[str, Any] = {"general": {"allow": [], "disallow": []}, "sitemaps": []}
    for agent in _AI_AGENTS:
        result[agent] = {"allow": [], "disallow": []}

    if not robots_content or not robots_content.strip():
        return result

    # Parse with urllib.robotparser for standard wildcard handling
    parser = RobotFileParser()
    parser.parse(StringIO(robots_content).readlines())

    # Custom line-by-line parsing to extract per-agent directives
    current_agents: list[str] = []

    for raw_line in robots_content.splitlines():
        line = raw_line.strip()

        # Strip inline comments
        if "#" in line:
            line = line[: line.index("#")].strip()

        if not line:
            current_agents = []
            continue

        lower = line.lower()

        if lower.startswith("user-agent:"):
            agent = line[len("user-agent:"):].strip()
            current_agents.append(agent)

        elif lower.startswith("disallow:"):
            path = line[len("disallow:"):].strip()
            for agent in current_agents:
                if agent == "*":
                    if path:
                        result["general"]["disallow"].append(path)
                elif agent in _AI_AGENTS and path:
                    result[agent]["disallow"].append(path)

        elif lower.startswith("allow:"):
            path = line[len("allow:"):].strip()
            for agent in current_agents:
                if agent == "*":
                    if path:
                        result["general"]["allow"].append(path)
                elif agent in _AI_AGENTS and path:
                    result[agent]["allow"].append(path)

        elif lower.startswith("sitemap:"):
            url = line[len("sitemap:"):].strip()
            if url:
                result["sitemaps"].append(url)

    return result
