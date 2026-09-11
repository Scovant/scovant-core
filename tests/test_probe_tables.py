"""Shape tests for the discovery/payment probe constant tables."""
from scovant_core.gatherers.probe_tables import DISCOVERY_PROBES, PAYMENT_PROBES


def test_payment_probes_shape():
    # x402/acp were dropped pending verification and later re-added along
    # with mpp once the blockers were documented resolved — see the
    # module's re-verification log.
    assert set(PAYMENT_PROBES) == {"l402", "x402", "acp", "mpp"}
    for probe in PAYMENT_PROBES.values():
        assert probe["kind"] in {
            "well_known_json", "challenge_header", "json_text_marker", "x402",
        }
        if probe["kind"] == "well_known_json":
            assert probe["path"].startswith("/")
        elif probe["kind"] == "challenge_header":
            assert probe["header"] == "www-authenticate"
            assert probe["marker"]  # non-empty match marker
        elif probe["kind"] == "json_text_marker":
            assert probe["path"].startswith("/")
            assert probe["marker"]
        else:  # x402 composite
            assert probe["catalog_path"].startswith("/")
            assert all(p.startswith("/") for p in probe["status_paths"])
            assert probe["json_marker"]


def test_discovery_probes_shape():
    expected = {
        "agents_txt", "agents_json", "ai_plugin", "openapi_root",
        "openapi_well_known", "skill_md", "a2a_card", "a2a_card_legacy",
        "oauth_as", "oauth_pr",
        # added later, alongside the re-added payment probes above
        "agent_skills", "agent_skills_legacy", "llms_full_txt",
    }
    assert set(DISCOVERY_PROBES) == expected
    for probe in DISCOVERY_PROBES.values():
        assert probe["path"].startswith("/")
        assert probe["content"] in {"json", "text"}


def test_mcp_not_in_discovery_probes():
    # MCP has its own rules (MCP_ENDPOINT_ABSENT / MCP_DISCOVERY_INVALID)
    # and its own probes — never probe it here.
    assert all("mcp" not in p["path"] for p in DISCOVERY_PROBES.values())
