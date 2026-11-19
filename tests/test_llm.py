"""HTTP client tests against an in-process fake Ollama (no network, no mocks of urllib)."""

from __future__ import annotations

import os
import socket
import unittest
from unittest import mock

from shellsage.llm import (
    ModelNotFound,
    OllamaClient,
    OllamaError,
    OllamaTimeout,
    OllamaUnreachable,
)
from tests.fake_ollama import FakeOllama


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


class OllamaClientTests(unittest.TestCase):
    def test_generate_sends_expected_payload(self) -> None:
        with FakeOllama(response='{"command": "ls"}') as fake:
            client = OllamaClient(fake.host, timeout=5)
            text = client.generate("m:1", "the prompt", system="the system", temperature=0.2)
        self.assertEqual(text, '{"command": "ls"}')
        path, payload = fake.requests[-1]
        self.assertEqual(path, "/api/generate")
        self.assertEqual(payload["model"], "m:1")
        self.assertEqual(payload["prompt"], "the prompt")
        self.assertEqual(payload["system"], "the system")
        self.assertEqual(payload["format"], "json")
        self.assertIs(payload["stream"], False)
        self.assertEqual(payload["options"], {"temperature": 0.2})

    def test_json_format_can_be_disabled(self) -> None:
        with FakeOllama() as fake:
            OllamaClient(fake.host, timeout=5).generate("m", "p", json_format=False)
        self.assertNotIn("format", fake.requests[-1][1])
        self.assertNotIn("system", fake.requests[-1][1])

    def test_version_and_models(self) -> None:
        with FakeOllama(models=("qwen2.5-coder:3b", "llama3.2:latest")) as fake:
            client = OllamaClient(fake.host, timeout=5)
            self.assertEqual(client.version(), "0.0.0-fake")
            self.assertEqual(client.list_models(), ["qwen2.5-coder:3b", "llama3.2:latest"])
            self.assertTrue(client.has_model("qwen2.5-coder:3b"))
            self.assertTrue(client.has_model("llama3.2"), "bare name should match :latest")
            self.assertFalse(client.has_model("qwen2.5-coder"))
            self.assertFalse(client.has_model("mistral"))

    def test_missing_model(self) -> None:
        with FakeOllama(status=404) as fake, self.assertRaises(ModelNotFound) as caught:
            OllamaClient(fake.host, timeout=5).generate("ghost:1", "p")
        self.assertIn("ollama pull ghost:1", str(caught.exception))

    def test_server_error(self) -> None:
        with FakeOllama(status=500) as fake, self.assertRaises(OllamaError) as caught:
            OllamaClient(fake.host, timeout=5).generate("m", "p")
        self.assertIn("500", str(caught.exception))

    def test_unreachable(self) -> None:
        client = OllamaClient(f"http://127.0.0.1:{free_port()}", timeout=2)
        with self.assertRaises(OllamaUnreachable) as caught:
            client.generate("m", "p")
        self.assertIn("ollama serve", str(caught.exception))

    def test_timeout(self) -> None:
        with FakeOllama(delay=1.5) as fake, self.assertRaises(OllamaTimeout):
            OllamaClient(fake.host, timeout=0.3).generate("m", "p")

    def test_non_json_body(self) -> None:
        with FakeOllama(raw_body=b"<html>nginx</html>") as fake, self.assertRaises(OllamaError):
            OllamaClient(fake.host, timeout=5).generate("m", "p")

    def test_json_without_response_field(self) -> None:
        with FakeOllama(raw_body=b'{"done": true}') as fake, self.assertRaises(OllamaError):
            OllamaClient(fake.host, timeout=5).generate("m", "p")

    def test_error_field_in_200_reply(self) -> None:
        with FakeOllama(raw_body=b'{"error": "out of memory"}') as fake:
            with self.assertRaises(OllamaError) as caught:
                OllamaClient(fake.host, timeout=5).generate("m", "p")
        self.assertIn("out of memory", str(caught.exception))

    def test_json_array_body(self) -> None:
        with FakeOllama(raw_body=b"[1, 2]") as fake, self.assertRaises(OllamaError):
            OllamaClient(fake.host, timeout=5).generate("m", "p")

    def test_loopback_ignores_proxy_environment(self) -> None:
        # A proxy that does not exist: if it were used, the request would fail.
        dead = f"http://127.0.0.1:{free_port()}"
        with mock.patch.dict(os.environ, {"http_proxy": dead, "HTTP_PROXY": dead, "no_proxy": ""}):
            with FakeOllama() as fake:
                self.assertEqual(OllamaClient(fake.host, timeout=5).version(), "0.0.0-fake")

    def test_all_errors_share_a_base_class(self) -> None:
        for kind in (ModelNotFound, OllamaTimeout, OllamaUnreachable):
            self.assertTrue(issubclass(kind, OllamaError))


if __name__ == "__main__":
    unittest.main()
