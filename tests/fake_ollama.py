"""A tiny in-process stand-in for the Ollama HTTP API (stdlib only)."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class FakeOllama:
    """Serve canned replies on 127.0.0.1 and record what the client sent.

    Use as a context manager; ``host`` is the base URL to hand to the client.
    """

    def __init__(
        self,
        response: str = '{"command": "ls", "explanation": "List files.", "risk": "safe"}',
        models: tuple[str, ...] = ("qwen2.5-coder:3b",),
        *,
        status: int = 200,
        raw_body: bytes | None = None,
        delay: float = 0.0,
    ) -> None:
        self.response = response
        self.models = models
        self.status = status
        self.raw_body = raw_body
        self.delay = delay
        self.requests: list[tuple[str, dict[str, Any]]] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                pass

            def _send(self, status: int, body: bytes) -> None:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                fake.requests.append((self.path, {}))
                if self.path == "/api/version":
                    self._send(200, b'{"version": "0.0.0-fake"}')
                elif self.path == "/api/tags":
                    body = json.dumps({"models": [{"name": m} for m in fake.models]})
                    self._send(200, body.encode())
                else:
                    self._send(404, b'{"error": "not found"}')

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length) or b"{}")
                fake.requests.append((self.path, payload))
                if fake.delay:
                    time.sleep(fake.delay)
                if fake.raw_body is not None:
                    self._send(fake.status, fake.raw_body)
                elif fake.status != 200:
                    self._send(fake.status, b'{"error": "model \'x\' not found"}')
                else:
                    body = json.dumps({"response": fake.response, "done": True})
                    self._send(200, body.encode())

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def host(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def __enter__(self) -> FakeOllama:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
