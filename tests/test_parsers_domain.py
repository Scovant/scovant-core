"""Tests for the domain-level parsers (robots.txt, llms.txt, MCP discovery,
UCP profile, bot-protection detection)."""

from scovant_core.parsers.bot_protection import detect_bot_protection
from scovant_core.parsers.llms_txt import parse_llms_txt
from scovant_core.parsers.mcp import check_mcp_discovery
from scovant_core.parsers.robots import parse_robots_txt
from scovant_core.parsers.ucp import check_ucp_profile

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

ROBOTS_BLOCK_GPTBOT = """\
User-agent: *
Disallow: /admin/

User-agent: GPTBot
Disallow: /

Sitemap: https://example.com/sitemap.xml
"""

ROBOTS_BLOCK_ALL = """\
User-agent: *
Disallow: /
"""

ROBOTS_ALLOW_ALL = """\
User-agent: *
Allow: /
Disallow:

Sitemap: https://example.com/sitemap.xml
Sitemap: https://example.com/sitemap2.xml
"""

ROBOTS_MULTI_AI_BLOCKED = """\
User-agent: *
Disallow: /private/

User-agent: GPTBot
Disallow: /

User-agent: ClaudeBot
Disallow: /

User-agent: Google-Extended
Disallow: /research/

User-agent: PerplexityBot
Allow: /
Disallow:
"""

ROBOTS_EMPTY = ""

ROBOTS_GPTBOT_PARTIAL_ALLOW = """\
User-agent: GPTBot
Allow: /public/
Disallow: /

User-agent: ClaudeBot
Allow: /
"""

LLMS_TXT_VALID = """\
# Example Site

> A short description of the site.

## Documentation

- [Getting Started](https://example.com/docs/start): Introduction guide
- [API Reference](https://example.com/docs/api): Full API docs
- [FAQ](https://example.com/faq): Frequently asked questions
"""

LLMS_TXT_NO_URLS = """\
# Example Site

This is some text but no links at all.
Just paragraphs.
"""

LLMS_TXT_EMPTY = ""

CLOUDFLARE_CHALLENGE_BODY = """\
<!DOCTYPE html>
<html>
<head><title>Just a moment...</title></head>
<body>
<div id="cf-browser-verification">
  <h2>Checking your browser...</h2>
  <p>This process is automatic. Your browser will redirect shortly.</p>
</div>
</body>
</html>
"""

CAPTCHA_BODY = """\
<!DOCTYPE html>
<html>
<body>
  <h1>Security Check</h1>
  <div class="captcha-container">
    <script src="https://hcaptcha.com/1/api.js"></script>
    <div class="h-captcha" data-sitekey="abc123"></div>
  </div>
</body>
</html>
"""

RECAPTCHA_BODY = """\
<!DOCTYPE html>
<html>
<body>
  <form>
    <div class="g-recaptcha" data-sitekey="xyz456"></div>
    <script src="https://www.google.com/recaptcha/api.js"></script>
  </form>
</body>
</html>
"""

NORMAL_BODY = """\
<!DOCTYPE html>
<html>
<head><title>Welcome</title></head>
<body><h1>Hello World</h1><p>Regular page content.</p></body>
</html>
"""

MCP_VALID_JSON = """\
{
  "mcpServers": {
    "example": {
      "url": "https://example.com/mcp",
      "description": "Example MCP server"
    }
  }
}
"""

MCP_VALID_WITH_ENDPOINTS = """\
{
  "mcpServers": {
    "main": {
      "url": "https://api.example.com/mcp/v1",
      "description": "Main MCP endpoint"
    },
    "search": {
      "url": "https://api.example.com/mcp/search",
      "description": "Search MCP endpoint"
    }
  }
}
"""

MCP_INVALID_JSON = "{ this is not valid json }"

MCP_VALID_JSON_NO_MCP = """\
{
  "name": "example",
  "version": "1.0.0"
}
"""


# ---------------------------------------------------------------------------
# parse_robots_txt
# ---------------------------------------------------------------------------

class TestParseRobotsTxt:
    def test_returns_all_expected_keys(self):
        result = parse_robots_txt(ROBOTS_BLOCK_GPTBOT)
        assert "general" in result
        assert "GPTBot" in result
        assert "ClaudeBot" in result
        assert "Google-Extended" in result
        assert "PerplexityBot" in result
        assert "sitemaps" in result

    def test_general_has_allow_and_disallow_keys(self):
        result = parse_robots_txt(ROBOTS_BLOCK_GPTBOT)
        assert "allow" in result["general"]
        assert "disallow" in result["general"]

    def test_ai_agent_keys_have_allow_and_disallow(self):
        result = parse_robots_txt(ROBOTS_BLOCK_GPTBOT)
        for agent in ("GPTBot", "ClaudeBot", "Google-Extended", "PerplexityBot"):
            assert "allow" in result[agent], f"{agent} missing 'allow'"
            assert "disallow" in result[agent], f"{agent} missing 'disallow'"

    def test_gptbot_disallow_slash_detected(self):
        result = parse_robots_txt(ROBOTS_BLOCK_GPTBOT)
        assert "/" in result["GPTBot"]["disallow"]

    def test_general_partial_block_not_full_disallow(self):
        result = parse_robots_txt(ROBOTS_BLOCK_GPTBOT)
        assert "/" not in result["general"]["disallow"]

    def test_block_all_wildcard(self):
        result = parse_robots_txt(ROBOTS_BLOCK_ALL)
        assert "/" in result["general"]["disallow"]

    def test_allow_all_wildcard(self):
        result = parse_robots_txt(ROBOTS_ALLOW_ALL)
        assert "/" in result["general"]["allow"]
        assert "/" not in result["general"]["disallow"]

    def test_sitemaps_extracted(self):
        result = parse_robots_txt(ROBOTS_BLOCK_GPTBOT)
        assert "https://example.com/sitemap.xml" in result["sitemaps"]

    def test_multiple_sitemaps_extracted(self):
        result = parse_robots_txt(ROBOTS_ALLOW_ALL)
        assert len(result["sitemaps"]) == 2
        assert "https://example.com/sitemap.xml" in result["sitemaps"]
        assert "https://example.com/sitemap2.xml" in result["sitemaps"]

    def test_empty_robots_returns_empty_lists(self):
        result = parse_robots_txt(ROBOTS_EMPTY)
        assert result["general"]["allow"] == []
        assert result["general"]["disallow"] == []
        assert result["sitemaps"] == []

    def test_multiple_ai_bots_blocked_separately(self):
        result = parse_robots_txt(ROBOTS_MULTI_AI_BLOCKED)
        assert "/" in result["GPTBot"]["disallow"]
        assert "/" in result["ClaudeBot"]["disallow"]

    def test_partial_ai_block_google_extended(self):
        result = parse_robots_txt(ROBOTS_MULTI_AI_BLOCKED)
        assert "/research/" in result["Google-Extended"]["disallow"]
        assert "/" not in result["Google-Extended"]["disallow"] or "/research/" in result["Google-Extended"]["disallow"]

    def test_perplexitybot_allowed_when_explicitly_allowed(self):
        result = parse_robots_txt(ROBOTS_MULTI_AI_BLOCKED)
        assert "/" in result["PerplexityBot"]["allow"]

    def test_gptbot_partial_allow(self):
        result = parse_robots_txt(ROBOTS_GPTBOT_PARTIAL_ALLOW)
        assert "/public/" in result["GPTBot"]["allow"]
        assert "/" in result["GPTBot"]["disallow"]

    def test_claudebot_allowed_returns_allow(self):
        result = parse_robots_txt(ROBOTS_GPTBOT_PARTIAL_ALLOW)
        assert "/" in result["ClaudeBot"]["allow"]

    def test_no_sitemaps_returns_empty_list(self):
        result = parse_robots_txt(ROBOTS_BLOCK_ALL)
        assert result["sitemaps"] == []

    def test_gptbot_not_mentioned_returns_empty(self):
        result = parse_robots_txt(ROBOTS_BLOCK_ALL)
        assert result["GPTBot"]["allow"] == []
        assert result["GPTBot"]["disallow"] == []


# ---------------------------------------------------------------------------
# parse_llms_txt
# ---------------------------------------------------------------------------

class TestParseLlmsTxt:
    def test_returns_all_expected_keys(self):
        result = parse_llms_txt(LLMS_TXT_VALID, 200)
        assert "exists" in result
        assert "valid" in result
        assert "urls" in result
        assert "raw_content" in result
        assert "errors" in result

    def test_http_404_not_exists(self):
        result = parse_llms_txt("Not Found", 404)
        assert result["exists"] is False
        assert result["valid"] is False

    def test_http_200_with_valid_markdown_exists_and_valid(self):
        result = parse_llms_txt(LLMS_TXT_VALID, 200)
        assert result["exists"] is True
        assert result["valid"] is True

    def test_valid_llms_txt_extracts_urls(self):
        result = parse_llms_txt(LLMS_TXT_VALID, 200)
        assert len(result["urls"]) >= 1
        assert "https://example.com/docs/start" in result["urls"]

    def test_valid_llms_txt_extracts_all_urls(self):
        result = parse_llms_txt(LLMS_TXT_VALID, 200)
        assert "https://example.com/docs/api" in result["urls"]
        assert "https://example.com/faq" in result["urls"]

    def test_http_200_no_urls_is_invalid(self):
        result = parse_llms_txt(LLMS_TXT_NO_URLS, 200)
        assert result["exists"] is True
        assert result["valid"] is False
        assert len(result["errors"]) > 0

    def test_empty_content_is_invalid(self):
        result = parse_llms_txt(LLMS_TXT_EMPTY, 200)
        assert result["exists"] is True
        assert result["valid"] is False

    def test_raw_content_preserved(self):
        result = parse_llms_txt(LLMS_TXT_VALID, 200)
        assert result["raw_content"] == LLMS_TXT_VALID

    def test_no_errors_for_valid(self):
        result = parse_llms_txt(LLMS_TXT_VALID, 200)
        assert result["errors"] == []

    def test_http_404_raw_content_preserved(self):
        result = parse_llms_txt("Not Found", 404)
        assert result["raw_content"] == "Not Found"

    def test_http_500_not_exists(self):
        result = parse_llms_txt("Server Error", 500)
        assert result["exists"] is False
        assert result["valid"] is False

    def test_urls_are_strings(self):
        result = parse_llms_txt(LLMS_TXT_VALID, 200)
        for url in result["urls"]:
            assert isinstance(url, str)


# ---------------------------------------------------------------------------
# check_mcp_discovery
# ---------------------------------------------------------------------------

class TestCheckMcpDiscovery:
    def test_returns_all_expected_keys(self):
        result = check_mcp_discovery(MCP_VALID_JSON, 200)
        assert "exists" in result
        assert "valid" in result
        assert "endpoints" in result

    def test_none_content_not_exists(self):
        result = check_mcp_discovery(None, 404)
        assert result["exists"] is False
        assert result["valid"] is False

    def test_http_404_not_exists(self):
        result = check_mcp_discovery("{}", 404)
        assert result["exists"] is False
        assert result["valid"] is False

    def test_valid_mcp_json_exists_and_valid(self):
        result = check_mcp_discovery(MCP_VALID_JSON, 200)
        assert result["exists"] is True
        assert result["valid"] is True

    def test_invalid_json_exists_but_not_valid(self):
        result = check_mcp_discovery(MCP_INVALID_JSON, 200)
        assert result["exists"] is True
        assert result["valid"] is False

    def test_valid_json_no_mcp_description_not_valid(self):
        result = check_mcp_discovery(MCP_VALID_JSON_NO_MCP, 200)
        assert result["exists"] is True
        assert result["valid"] is False

    def test_valid_mcp_extracts_endpoints(self):
        result = check_mcp_discovery(MCP_VALID_WITH_ENDPOINTS, 200)
        assert len(result["endpoints"]) == 2

    def test_single_endpoint_extracted(self):
        result = check_mcp_discovery(MCP_VALID_JSON, 200)
        assert len(result["endpoints"]) >= 1
        assert "https://example.com/mcp" in result["endpoints"]

    def test_endpoints_empty_for_invalid(self):
        result = check_mcp_discovery(MCP_INVALID_JSON, 200)
        assert result["endpoints"] == []

    def test_endpoints_empty_when_not_exists(self):
        result = check_mcp_discovery(None, 404)
        assert result["endpoints"] == []


# ---------------------------------------------------------------------------
# detect_bot_protection
# ---------------------------------------------------------------------------

class TestDetectBotProtection:
    def test_returns_all_expected_keys(self):
        result = detect_bot_protection(200, {}, NORMAL_BODY, "browser")
        assert "blocked" in result
        assert "protection_type" in result
        assert "details" in result

    def test_normal_200_not_blocked(self):
        result = detect_bot_protection(200, {}, NORMAL_BODY, "browser")
        assert result["blocked"] is False
        assert result["protection_type"] is None

    def test_http_403_blocked(self):
        result = detect_bot_protection(403, {}, "Forbidden", "ai_crawler")
        assert result["blocked"] is True

    def test_http_503_blocked(self):
        result = detect_bot_protection(503, {}, "Service Unavailable", "ai_crawler")
        assert result["blocked"] is True

    def test_cloudflare_challenge_body_blocked(self):
        result = detect_bot_protection(200, {}, CLOUDFLARE_CHALLENGE_BODY, "ai_crawler")
        assert result["blocked"] is True
        assert result["protection_type"] == "cloudflare"

    def test_cloudflare_cf_ray_header_blocked(self):
        headers = {"cf-ray": "abc123def456-SJC", "server": "cloudflare"}
        result = detect_bot_protection(403, headers, "Forbidden", "ai_crawler")
        assert result["blocked"] is True
        assert result["protection_type"] == "cloudflare"

    def test_cloudflare_challenge_has_details(self):
        result = detect_bot_protection(200, {}, CLOUDFLARE_CHALLENGE_BODY, "ai_crawler")
        assert result["details"] is not None

    def test_hcaptcha_body_blocked(self):
        result = detect_bot_protection(200, {}, CAPTCHA_BODY, "ai_crawler")
        assert result["blocked"] is True
        assert result["protection_type"] == "captcha"

    def test_recaptcha_body_blocked(self):
        result = detect_bot_protection(200, {}, RECAPTCHA_BODY, "ai_crawler")
        assert result["blocked"] is True
        assert result["protection_type"] == "captcha"

    # --- Akamai: a denial, never the mere presence of the bot-manager sensor ---
    # `_abck` and the `/akam/<n>/` script ride on EVERY response from an
    # Akamai-fronted site, so a verdict keyed on them would mark working pages
    # as blocked — and Cloud scores that (BOT_PROTECTION_BLOCKING_AGENTS, x0.80
    # on a third party's score), so these four negatives are load-bearing.
    def test_akamai_access_denied_page_blocked(self):
        body = ('<html><body><p>Access Denied. You do not have permission to access this resource.</p>'
                '<p>Reference #18.0a1b2c3d.0000000000.0e1f2a3b</p>'
                '<script src="/akam/13/0a1b2c3d"></script></body></html>')
        result = detect_bot_protection(200, {}, body, "ai_crawler")
        assert result["blocked"] is True
        assert result["protection_type"] == "akamai"

    def test_akamai_sensor_script_alone_is_not_a_block(self):
        body = ('<html><body><main><h1>Widgets</h1><p>A short but successful page.</p></main>'
                '<script src="/akam/13/0a1b2c3d"></script></body></html>')
        assert detect_bot_protection(200, {}, body, "ai_crawler")["blocked"] is False

    def test_akamai_sensor_cookie_alone_is_not_a_block(self):
        body = '<html><body><p>Hello.</p><script>window._abck = "";</script></body></html>'
        assert detect_bot_protection(200, {}, body, "ai_crawler")["blocked"] is False

    def test_spa_shell_behind_akamai_is_not_a_block(self):
        body = ('<html><body><div id="root"></div><script src="/akam/13/0a1b2c3d"></script>'
                '<script src="/assets/app.js"></script></body></html>')
        assert detect_bot_protection(200, {}, body, "ai_crawler")["blocked"] is False

    def test_prose_quoting_a_plain_reference_number_is_not_a_block(self):
        body = '<html><body><p>See Reference #12. for the return policy.</p></body></html>'
        assert detect_bot_protection(200, {}, body, "ai_crawler")["blocked"] is False

    def test_403_has_protection_type(self):
        result = detect_bot_protection(403, {}, "Access Denied", "ai_crawler")
        assert result["protection_type"] is not None

    def test_503_has_protection_type(self):
        result = detect_bot_protection(503, {}, "", "ai_crawler")
        assert result["protection_type"] is not None

    def test_normal_200_details_is_none(self):
        result = detect_bot_protection(200, {}, NORMAL_BODY, "browser")
        assert result["details"] is None

    def test_case_insensitive_captcha_detection(self):
        body = "<div>Please complete the CAPTCHA to continue</div>"
        result = detect_bot_protection(200, {}, body, "ai_crawler")
        assert result["blocked"] is True
        assert result["protection_type"] == "captcha"

    def test_waf_header_detected(self):
        headers = {"x-sucuri-id": "12345"}
        result = detect_bot_protection(403, headers, "Access Denied by WAF", "ai_crawler")
        assert result["blocked"] is True


# ─── check_ucp_profile ──────────────────────────────────────────────────────

UCP_VALID_FULL = """
{
  "ucp": {
    "version": "2026-01-15",
    "services": {
      "dev.ucp.commerce": [
        {
          "version": "2026-01-15",
          "spec": "https://example.com/specification/commerce",
          "transport": "REST",
          "endpoint": "https://shop.example.com/ucp/v1",
          "schema": "https://example.com/schemas/commerce.json"
        }
      ]
    },
    "capabilities": {
      "dev.ucp.commerce.checkout": [
        {
          "version": "2026-01-15",
          "spec": "https://example.com/specification/checkout",
          "schema": "https://example.com/schemas/checkout.json"
        }
      ],
      "dev.ucp.commerce.order": [
        {
          "version": "2026-01-15",
          "spec": "https://example.com/specification/order",
          "schema": "https://example.com/schemas/order.json"
        }
      ]
    }
  },
  "signing_keys": [{"kid": "k1", "kty": "EC", "use": "sig"}]
}
"""

UCP_VALID_NO_CHECKOUT = """
{
  "ucp": {
    "version": "2026-01-15",
    "services": {
      "dev.ucp.order": [
        {
          "version": "2026-01-15",
          "spec": "https://example.com/specification/order",
          "transport": "REST",
          "endpoint": "https://shop.example.com/ucp/v1",
          "schema": "https://example.com/schemas/order.json"
        }
      ]
    },
    "capabilities": {
      "dev.ucp.commerce.order": [
        {
          "version": "2026-01-15",
          "spec": "https://example.com/specification/order",
          "schema": "https://example.com/schemas/order.json"
        }
      ]
    }
  },
  "signing_keys": [{"kid": "k1", "kty": "EC", "use": "sig"}]
}
"""

UCP_MISSING_CAPABILITIES = """
{
  "ucp": {
    "version": "2026-01-15",
    "services": {}
  },
  "signing_keys": [{"kid": "k1", "kty": "EC", "use": "sig"}]
}
"""

UCP_MULTI_TRANSPORT = """
{
  "ucp": {
    "version": "2026-01-15",
    "services": {
      "dev.ucp.commerce": [
        {
          "version": "2026-01-15",
          "spec": "https://example.com/specification/commerce",
          "transport": "REST",
          "endpoint": "https://shop.example.com/ucp/v1",
          "schema": "https://example.com/schemas/commerce.json"
        },
        {
          "version": "2026-01-15",
          "spec": "https://example.com/specification/commerce",
          "transport": "MCP",
          "endpoint": "https://shop.example.com/mcp",
          "schema": "https://example.com/schemas/commerce-mcp.json"
        }
      ]
    },
    "capabilities": {
      "dev.ucp.commerce.checkout": [
        {
          "version": "2026-01-15",
          "spec": "https://example.com/specification/checkout",
          "schema": "https://example.com/schemas/checkout.json"
        }
      ]
    }
  },
  "signing_keys": [{"kid": "k1", "kty": "EC", "use": "sig"}]
}
"""


class TestCheckUcpProfile:
    def test_valid_full_profile(self):
        result = check_ucp_profile(UCP_VALID_FULL, 200)
        assert result["exists"] is True
        assert result["valid"] is True
        assert result["version"] == "2026-01-15"
        assert result["has_checkout"] is True
        assert "dev.ucp.commerce.checkout" in result["capabilities"]
        assert "dev.ucp.commerce.order" in result["capabilities"]
        assert result["validation_errors"] == []

    def test_404_not_exists(self):
        result = check_ucp_profile(None, 404)
        assert result["exists"] is False
        assert result["valid"] is False
        assert result["has_checkout"] is False
        assert result["capabilities"] == []

    def test_200_invalid_json(self):
        result = check_ucp_profile("not json {", 200)
        assert result["exists"] is True
        assert result["valid"] is False
        assert "invalid JSON" in result["validation_errors"]

    def test_missing_required_key(self):
        result = check_ucp_profile(UCP_MISSING_CAPABILITIES, 200)
        assert result["exists"] is True
        assert result["valid"] is False
        # Should report missing capabilities key
        assert any("capabilities" in err for err in result["validation_errors"])

    def test_valid_without_checkout(self):
        result = check_ucp_profile(UCP_VALID_NO_CHECKOUT, 200)
        assert result["exists"] is True
        assert result["valid"] is True
        assert result["has_checkout"] is False
        assert "dev.ucp.commerce.order" in result["capabilities"]

    def test_multiple_transports_collected(self):
        result = check_ucp_profile(UCP_MULTI_TRANSPORT, 200)
        assert result["exists"] is True
        assert result["valid"] is True
        assert set(result["transports"]) == {"REST", "MCP"}


# ─── signing_keys_valid (JWK shape check) ──────────────────────────────────

UCP_VALID_JWK = """
{
  "ucp": {"version": "2026-01-15", "services": {}, "capabilities": {}},
  "signing_keys": [
    {"kid": "k1", "kty": "EC", "use": "sig"},
    {"kid": "k2", "kty": "RSA", "use": "sig"}
  ]
}
"""

UCP_EMPTY_SIGNING_KEYS = """
{
  "ucp": {"version": "2026-01-15", "services": {}, "capabilities": {}},
  "signing_keys": []
}
"""

UCP_MISSING_JWK_FIELDS = """
{
  "ucp": {"version": "2026-01-15", "services": {}, "capabilities": {}},
  "signing_keys": [{"kid": "k1"}]
}
"""


class TestSigningKeysValid:
    def test_valid_jwk_array(self):
        result = check_ucp_profile(UCP_VALID_JWK, 200)
        assert result["valid"] is True
        assert result["signing_keys_valid"] is True

    def test_empty_signing_keys_array_marks_invalid(self):
        result = check_ucp_profile(UCP_EMPTY_SIGNING_KEYS, 200)
        # Profile itself stays valid (signing_keys is a list, just empty)
        assert result["valid"] is True
        # The new strict check flips
        assert result["signing_keys_valid"] is False

    def test_entry_missing_required_fields_marks_invalid(self):
        result = check_ucp_profile(UCP_MISSING_JWK_FIELDS, 200)
        assert result["valid"] is True
        assert result["signing_keys_valid"] is False
