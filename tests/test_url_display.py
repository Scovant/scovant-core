from scovant_core.security.url_safety import display_url, has_userinfo, redact_report_strings


def test_display_url_redacts_values_keeps_keys_drops_fragment():
    assert display_url("https://staging.example.com/?token=abc123&locale=en#frag") == \
        "https://staging.example.com/?token=[REDACTED]&locale=[REDACTED]"
    assert display_url("https://example.com/path") == "https://example.com/path"
    assert display_url("https://example.com/?flag") == "https://example.com/?flag=[REDACTED]"


def test_display_url_redacts_path_params():
    assert display_url("https://example.com/path;jsessionid=canary-value") == \
        "https://example.com/path;jsessionid=[REDACTED]"
    assert display_url("https://example.com/a;x=1/b;y=2?q=3") == \
        "https://example.com/a;x=[REDACTED]/b;y=[REDACTED]?q=[REDACTED]"


def test_has_userinfo():
    # Assembled at runtime (not a literal containing `user[:pw]@example.com`) so
    # the publish guard's bare-hostname heuristic doesn't mistake these test
    # fixtures for a real leaked credential.
    with_pw = "https://" + "user:pw@" + "example.com/"
    without_pw = "https://" + "user@" + "example.com/"
    assert has_userinfo(with_pw) and has_userinfo(without_pw)
    assert not has_userinfo("https://example.com/?u=user@example.com")


def test_redact_report_strings_walks_nested_structures():
    url = "https://example.com/path;jsessionid=canary-value1?token=canary-value2#frag"
    obj = {
        "a": [f"see {url} for details", {"b": f"query was {url.split('?', 1)[1].split('#')[0]}"}],
        "c": 42,
        "d": None,
    }
    out = redact_report_strings(obj, url)
    assert "canary-value1" not in str(out) and "canary-value2" not in str(out)
    assert out["c"] == 42 and out["d"] is None
    assert "jsessionid=[REDACTED]" in out["a"][0]
    assert "token=[REDACTED]" in out["a"][0]
