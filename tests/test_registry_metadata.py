"""Core 0.24.1: metadata for the official MCP Registry (server.json + the
`mcp-name` marker the registry reads from the PyPI long description)."""
from __future__ import annotations

import json
import tomllib
from pathlib import Path

import scovant_core

ROOT = Path(__file__).resolve().parents[1]
NAME = "io.github.Scovant/scovant-core"


def _server() -> dict:
    return json.loads((ROOT / "server.json").read_text(encoding="utf-8"))


def test_server_json_name_and_version():
    s = _server()
    assert s["name"] == NAME
    assert s["version"] == scovant_core.__version__
    assert s["$schema"].startswith("https://static.modelcontextprotocol.io/schemas/")


def test_description_fits_the_registry_limit():
    assert 0 < len(_server()["description"]) <= 100


def test_pypi_package_entry_matches_the_release():
    (pkg,) = _server()["packages"]
    assert pkg["registryType"] == "pypi"
    assert pkg["identifier"] == "scovant-core"
    assert pkg["version"] == scovant_core.__version__
    assert pkg["transport"] == {"type": "stdio"}
    assert pkg["runtimeHint"] == "uvx"
    assert [a["value"] for a in pkg["packageArguments"]] == ["mcp"]


def test_readme_carries_the_mcp_name_marker():
    assert f"<!-- mcp-name: {NAME} -->" in (ROOT / "README.md").read_text(encoding="utf-8")


def test_the_package_name_is_also_an_executable():
    """`uvx scovant-core …` (the registry's launch shape) needs a console
    script named after the package."""
    scripts = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["scripts"]
    assert scripts["scovant-core"] == scripts["scovant"] == "scovant_core.cli:main"


def test_the_sdist_ships_server_json():
    """The sdist carries tests/, and this module reads server.json, so the
    file must be in the sdist too (final review I1, 2026-11-02)."""
    include = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "tool"]["hatch"]["build"]["targets"]["sdist"]["include"]
    assert any(entry.strip("/") == "server.json" for entry in include)
