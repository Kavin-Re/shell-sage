"""Minimal Ollama HTTP client built on :mod:`urllib` (no third-party packages)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

__all__ = [
    "ModelNotFound",
    "OllamaClient",
    "OllamaError",
    "OllamaTimeout",
    "OllamaUnreachable",
]

_LOOPBACK = {"localhost", "127.0.0.1", "::1"}
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class OllamaError(RuntimeError):
    """Base class; ``str(exc)`` is a message fit for the user."""


class OllamaUnreachable(OllamaError):
    pass


class OllamaTimeout(OllamaError):
    pass


class ModelNotFound(OllamaError):
    pass


class OllamaClient:
    """Talks to one Ollama server.

    For loopback hosts, proxy settings from the environment are ignored so
    that a corporate ``http_proxy`` cannot swallow (or receive) local prompts.
    """

    def __init__(self, host: str, timeout: float = 60.0) -> None:
        self.host = host.rstrip("/")
        self.timeout = timeout
        handlers: list[urllib.request.BaseHandler] = []
        if (urlsplit(self.host).hostname or "") in _LOOPBACK:
            handlers.append(urllib.request.ProxyHandler({}))
        self._opener = urllib.request.build_opener(*handlers)

    # -- transport ---------------------------------------------------------- #

    def _request(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        url = self.host + path
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "shellsage"},
            method="GET" if data is None else "POST",
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                body = response.read(_MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            detail = self._error_detail(exc)
            if exc.code == 404 and payload is not None and "model" in payload:
                raise ModelNotFound(
                    f"model {payload['model']!r} is not available on {self.host} "
                    f"(run: ollama pull {payload['model']})"
                ) from None
            raise OllamaError(f"Ollama returned HTTP {exc.code}: {detail}") from None
        except TimeoutError:
            raise OllamaTimeout(
                f"no answer from {self.host} within {self.timeout:g}s "
                "(first use of a model can be slow - raise the timeout or retry)"
            ) from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise OllamaTimeout(
                    f"no answer from {self.host} within {self.timeout:g}s"
                ) from None
            raise OllamaUnreachable(
                f"cannot reach Ollama at {self.host} ({exc.reason}) - is `ollama serve` running?"
            ) from None
        except OSError as exc:
            raise OllamaUnreachable(f"cannot reach Ollama at {self.host} ({exc})") from None
        if len(body) > _MAX_RESPONSE_BYTES:
            raise OllamaError("Ollama response is unexpectedly large; refusing to parse it")
        try:
            parsed = json.loads(body.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            raise OllamaError(
                f"{url} did not return JSON - is this really an Ollama server?"
            ) from None
        if not isinstance(parsed, dict):
            raise OllamaError(f"{url} returned an unexpected JSON document")
        return parsed

    @staticmethod
    def _error_detail(exc: urllib.error.HTTPError) -> str:
        try:
            raw = exc.read(2048).decode("utf-8", errors="replace")
            parsed = json.loads(raw)
            if isinstance(parsed, dict) and isinstance(parsed.get("error"), str):
                return str(parsed["error"])
            return raw.strip() or str(exc.reason)
        except (OSError, ValueError):
            return str(exc.reason)

    # -- API ---------------------------------------------------------------- #

    def generate(
        self,
        model: str,
        prompt: str,
        *,
        system: str = "",
        json_format: bool = True,
        temperature: float = 0.1,
    ) -> str:
        """Run one non-streaming completion and return the raw response text."""
        payload: dict[str, Any] = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if system:
            payload["system"] = system
        if json_format:
            payload["format"] = "json"
        reply = self._request("/api/generate", payload)
        if isinstance(reply.get("error"), str):
            raise OllamaError(f"Ollama error: {reply['error']}")
        text = reply.get("response")
        if not isinstance(text, str):
            raise OllamaError("Ollama reply has no 'response' field")
        return text

    def version(self) -> str:
        reply = self._request("/api/version")
        return str(reply.get("version", "unknown"))

    def list_models(self) -> list[str]:
        reply = self._request("/api/tags")
        models = reply.get("models")
        if not isinstance(models, list):
            return []
        names: list[str] = []
        for entry in models:
            if isinstance(entry, dict):
                name = entry.get("name") or entry.get("model")
                if isinstance(name, str):
                    names.append(name)
        return names

    def has_model(self, model: str) -> bool:
        wanted = model if ":" in model else model + ":latest"
        return any(name in (model, wanted) for name in self.list_models())
