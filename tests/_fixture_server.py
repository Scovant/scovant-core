"""A minimal, dependency-free HTTP server over one `fixtures/sites/<name>`
directory — used for the local CLI dry run and the public-repo Action smoke
test (`.github/workflows/action-smoke.yml`), both of which need a REAL
`http://` target (the in-process `FixtureTransport` in `tests/conftest.py`
only works inside this process, via `httpx.BaseTransport` injection).

Serving rules mirror `FixtureTransport`: a directory path serves that
directory's `index.html`; a `<file>.headers` JSON sidecar (if present)
merges into the response headers; anything else missing is a 404. Binds
`127.0.0.1` only — never `0.0.0.0` — since this is a test fixture, not a
real server.

Usage: `python -m tests._fixture_server <site-name> <port>`, e.g.
`python -m tests._fixture_server commerce-good 8765`.
"""
from __future__ import annotations

import json
import mimetypes
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "sites"


class FixtureRequestHandler(BaseHTTPRequestHandler):
    root: Path = FIXTURES  # overridden per-instance via server.root

    def log_message(self, format: str, *args) -> None:  # noqa: A002 — stdlib signature
        pass  # quiet by default; the dry run only cares about the scan output

    def do_GET(self) -> None:  # noqa: N802 — stdlib method name
        root: Path = self.server.root  # type: ignore[attr-defined]
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        # Normalise against a synthetic root so `..` segments collapse instead
        # of escaping the fixture directory (e.g. `/../../etc/passwd`); the
        # explicit `..`-segment check is defense in depth against any request
        # path `normpath` itself would not neutralise.
        normalized = os.path.normpath("/" + path).lstrip("/")
        if normalized == ".":
            normalized = ""
        if ".." in normalized.split("/"):
            self.send_error(404, "not found")
            return
        rel = "index.html" if normalized == "" else normalized
        f = root / rel
        if f.is_dir():
            f = f / "index.html"
        elif not f.exists() and not f.suffix and f.with_suffix(".html").exists():
            # clean-URL convenience, mirroring FixtureTransport: `/products/widget`
            # (no extension, no literal file) serves `products/widget.html`.
            f = f.with_suffix(".html")
        if not f.exists() or not f.is_file():
            self.send_error(404, "not found")
            return
        ctype = mimetypes.guess_type(f.name)[0] or "application/octet-stream"
        if f.suffix == ".txt":
            ctype = "text/plain"
        body = f.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        sidecar = f.with_name(f.name + ".headers")
        if sidecar.exists():
            for key, value in json.loads(sidecar.read_text()).items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)


def serve(site: str, port: int) -> None:
    server = HTTPServer(("127.0.0.1", port), FixtureRequestHandler)
    server.root = FIXTURES / site  # type: ignore[attr-defined]
    if not server.root.is_dir():  # type: ignore[attr-defined]
        raise SystemExit(f"no such fixture site: {site!r} (looked in {FIXTURES})")
    server.serve_forever()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: python -m tests._fixture_server <site-name> <port>")
    serve(sys.argv[1], int(sys.argv[2]))
