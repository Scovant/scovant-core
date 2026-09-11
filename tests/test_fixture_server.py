"""`tests/_fixture_server.py` serves one `fixtures/sites/<name>` directory
over real HTTP for the local CLI dry run and the public-repo Action smoke
test. This pins that a request path cannot escape that directory."""
from __future__ import annotations

import http.client
import threading
from http.server import HTTPServer

from tests._fixture_server import FIXTURES, FixtureRequestHandler


def _start_server() -> HTTPServer:
    server = HTTPServer(("127.0.0.1", 0), FixtureRequestHandler)
    server.root = FIXTURES / "commerce-good"  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_path_traversal_request_is_404():
    server = _start_server()
    try:
        port = server.server_address[1]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/../../etc/passwd")
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 404
    finally:
        server.shutdown()
        server.server_close()


def test_path_traversal_via_encoded_dots_is_still_scoped_to_root():
    server = _start_server()
    try:
        port = server.server_address[1]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/products/../../../../../../etc/passwd")
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 404
    finally:
        server.shutdown()
        server.server_close()


def test_legitimate_request_still_serves_the_fixture():
    server = _start_server()
    try:
        port = server.server_address[1]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/")
        resp = conn.getresponse()
        body = resp.read()
        assert resp.status == 200
        assert b"<html" in body.lower() or b"<!doctype" in body.lower()
    finally:
        server.shutdown()
        server.server_close()
