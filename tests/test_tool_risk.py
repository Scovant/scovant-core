from scovant_core.analysis.tool_risk import classify_tool_risk


def test_destructive_verbs():
    assert classify_tool_risk("delete_order", "Deletes an order.", []) == "DESTRUCTIVE"
    assert classify_tool_risk("remove_user", "", []) == "DESTRUCTIVE"
    assert classify_tool_risk("drop_table", "", []) == "DESTRUCTIVE"
    assert classify_tool_risk("refund_payment", "", []) == "DESTRUCTIVE"
    assert classify_tool_risk("cancel_subscription", "", []) == "DESTRUCTIVE"
    assert classify_tool_risk("revoke_access", "", []) == "DESTRUCTIVE"


def test_external_side_effect_verbs():
    assert classify_tool_risk("send_invoice", "", []) == "EXTERNAL_SIDE_EFFECT"
    assert classify_tool_risk("notify_customer", "", []) == "EXTERNAL_SIDE_EFFECT"
    assert classify_tool_risk("publish_post", "", []) == "EXTERNAL_SIDE_EFFECT"
    assert classify_tool_risk("charge_card", "", []) == "EXTERNAL_SIDE_EFFECT"
    assert classify_tool_risk("weird_tool", "Sends an email confirmation.", []) == "EXTERNAL_SIDE_EFFECT"
    assert classify_tool_risk("weird_tool", "Sends an SMS alert.", []) == "EXTERNAL_SIDE_EFFECT"
    assert classify_tool_risk("process_payment", "", []) == "EXTERNAL_SIDE_EFFECT"


def test_write_verbs():
    assert classify_tool_risk("create_order", "", []) == "WRITE"
    assert classify_tool_risk("update_profile", "", []) == "WRITE"
    assert classify_tool_risk("set_preferences", "", []) == "WRITE"
    assert classify_tool_risk("post_comment", "", []) == "WRITE"
    assert classify_tool_risk("put_object", "", []) == "WRITE"
    assert classify_tool_risk("add_item", "", []) == "WRITE"
    assert classify_tool_risk("write_log", "", []) == "WRITE"


def test_read_only_verbs():
    assert classify_tool_risk("get_order_status", "", []) == "READ_ONLY"
    assert classify_tool_risk("list_products", "", []) == "READ_ONLY"
    assert classify_tool_risk("search_catalog", "", []) == "READ_ONLY"
    assert classify_tool_risk("read_file", "", []) == "READ_ONLY"
    assert classify_tool_risk("fetch_data", "", []) == "READ_ONLY"
    assert classify_tool_risk("query_database", "", []) == "READ_ONLY"
    assert classify_tool_risk("describe_schema", "", []) == "READ_ONLY"


def test_unknown_for_nonsense_name():
    assert classify_tool_risk("frobnicate_widget", "Does a thing.", []) == "UNKNOWN"
    assert classify_tool_risk("", "", []) == "UNKNOWN"


def test_case_insensitive():
    assert classify_tool_risk("DELETE_ORDER", "", []) == "DESTRUCTIVE"
    assert classify_tool_risk("Get_Order_Status", "", []) == "READ_ONLY"
    assert classify_tool_risk("CREATE_Order", "", []) == "WRITE"


def test_never_raises_on_none_inputs():
    # Defensive: the rule always passes real strings, but the fn must never
    # blow up a scan even on malformed input.
    assert classify_tool_risk(None, None, []) == "UNKNOWN"
