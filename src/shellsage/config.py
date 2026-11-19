"""Configuration: defaults < config file < environment < command line.

The config file is TOML at ``$SHELLSAGE_CONFIG``, else
``$XDG_CONFIG_HOME/shellsage/config.toml``, else ``~/.config/shellsage/config.toml``.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on Python 3.10
    try:
        import tomli as tomllib
    except ModuleNotFoundError:
        tomllib = None

__all__ = ["DEFAULT_HOST", "DEFAULT_MODEL", "Config", "ConfigError", "config_path", "load_config"]

DEFAULT_MODEL = "qwen2.5-coder:3b"
DEFAULT_HOST = "http://127.0.0.1:11434"
MAX_HISTORY_LINES = 50
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}


class ConfigError(ValueError):
    """The configuration is invalid; the message is safe to show to the user."""


@dataclass(frozen=True)
class Config:
    """Effective settings for one run."""

    model: str = DEFAULT_MODEL
    host: str = DEFAULT_HOST
    timeout: float = 60.0
    temperature: float = 0.1
    history_lines: int = 0  # 0 = shell history is never read (the default)
    history_file: str = ""  # "" = auto-detect from $HISTFILE / shell
    redact_patterns: tuple[str, ...] = ()
    shell: str = ""  # "" = auto-detect from $SHELL
    color: str = "auto"  # auto | always | never
    allow_danger: bool = False  # config-file only, on purpose
    source: str = ""  # path of the file that was loaded, if any
    warnings: tuple[str, ...] = ()

    @property
    def host_is_local(self) -> bool:
        return (urlsplit(self.host).hostname or "") in _LOOPBACK


# (section, key) -> (Config field, expected type)
_FILE_SCHEMA: dict[tuple[str, str], tuple[str, type]] = {
    ("ollama", "model"): ("model", str),
    ("ollama", "host"): ("host", str),
    ("ollama", "timeout"): ("timeout", float),
    ("ollama", "temperature"): ("temperature", float),
    ("context", "history_lines"): ("history_lines", int),
    ("context", "history_file"): ("history_file", str),
    ("context", "redact_patterns"): ("redact_patterns", tuple),
    ("context", "shell"): ("shell", str),
    ("ui", "color"): ("color", str),
    ("safety", "allow_danger"): ("allow_danger", bool),
}
# Environment variable -> (Config field, expected type)
_ENV_SCHEMA: dict[str, tuple[str, type]] = {
    "SHELLSAGE_MODEL": ("model", str),
    "SHELLSAGE_HOST": ("host", str),
    "SHELLSAGE_TIMEOUT": ("timeout", float),
    "SHELLSAGE_TEMPERATURE": ("temperature", float),
    "SHELLSAGE_HISTORY_LINES": ("history_lines", int),
    "SHELLSAGE_HISTORY_FILE": ("history_file", str),
    "SHELLSAGE_SHELL": ("shell", str),
    "SHELLSAGE_COLOR": ("color", str),
}


def config_path(env: Mapping[str, str] | None = None) -> Path:
    """Where the config file is looked for (it does not have to exist)."""
    env = os.environ if env is None else env
    explicit = env.get("SHELLSAGE_CONFIG")
    if explicit:
        return Path(explicit).expanduser()
    base = env.get("XDG_CONFIG_HOME") or str(Path(env.get("HOME") or Path.home()) / ".config")
    return Path(base) / "shellsage" / "config.toml"


def normalize_host(value: str) -> str:
    """Validate and normalise the Ollama base URL (http/https only)."""
    host = value.strip().rstrip("/")
    if not host:
        raise ConfigError("host must not be empty")
    if "://" not in host:
        host = "http://" + host
    parts = urlsplit(host)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ConfigError(f"host must be an http(s) URL, got {value!r}")
    if parts.username or parts.password:
        raise ConfigError("host must not embed credentials")
    return host


def _coerce(name: str, value: Any, kind: type, origin: str) -> Any:
    """Convert ``value`` (from TOML or an env string) to ``kind`` or raise ConfigError."""
    try:
        if kind is bool:
            if isinstance(value, bool):
                return value
            raise TypeError
        if kind is int:
            if isinstance(value, (bool, float)):
                raise TypeError
            return int(value)
        if kind is float:
            if isinstance(value, bool):
                raise TypeError
            return float(value)
        if kind is tuple:
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise TypeError
            return tuple(value)
        if not isinstance(value, str):
            raise TypeError
        return value
    except (TypeError, ValueError):
        wanted = {tuple: "a list of strings", bool: "true or false", int: "an integer",
                  float: "a number", str: "a string"}[kind]  # fmt: skip
        raise ConfigError(f"{origin}: {name} must be {wanted}, got {value!r}") from None


def validate(config: Config) -> Config:
    """Check ranges and cross-field rules; returns a normalised copy."""
    if not config.model.strip():
        raise ConfigError("model must not be empty")
    if not 1 <= config.timeout <= 3600:
        raise ConfigError(f"timeout must be between 1 and 3600 seconds, got {config.timeout:g}")
    if not 0 <= config.temperature <= 2:
        raise ConfigError(f"temperature must be between 0 and 2, got {config.temperature:g}")
    if not 0 <= config.history_lines <= MAX_HISTORY_LINES:
        raise ConfigError(
            f"history_lines must be between 0 and {MAX_HISTORY_LINES}, got {config.history_lines}"
        )
    if config.color not in ("auto", "always", "never"):
        raise ConfigError(f"color must be auto, always or never, got {config.color!r}")
    for pattern in config.redact_patterns:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ConfigError(f"redact_patterns: invalid regex {pattern!r}: {exc}") from None
    return replace(config, model=config.model.strip(), host=normalize_host(config.host))


def _read_file(path: Path) -> tuple[dict[str, Any], list[str]]:
    if tomllib is None:  # pragma: no cover - Python 3.10 without tomli
        return {}, [f"{path}: ignored - install 'tomli' to read config files on Python 3.10"]
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from None
    except OSError as exc:
        raise ConfigError(f"{path}: cannot read config file: {exc.strerror}") from None
    values: dict[str, Any] = {}
    warnings: list[str] = []
    for section, body in data.items():
        if not isinstance(body, dict):
            warnings.append(f"{path}: ignoring top-level key {section!r} (expected a [section])")
            continue
        for key, raw in body.items():
            spec = _FILE_SCHEMA.get((section, key))
            if spec is None:
                warnings.append(f"{path}: ignoring unknown setting [{section}] {key}")
                continue
            field, kind = spec
            values[field] = _coerce(f"[{section}] {key}", raw, kind, str(path))
    return values, warnings


def load_config(
    env: Mapping[str, str] | None = None,
    overrides: Mapping[str, Any] | None = None,
) -> Config:
    """Build the effective :class:`Config`.

    ``overrides`` are command-line values; ``None`` entries are ignored.
    Raises :class:`ConfigError` with a user-facing message on any problem.
    """
    env = os.environ if env is None else env
    values: dict[str, Any] = {}
    warnings: list[str] = []
    source = ""

    path = config_path(env)
    if path.is_file():
        values, warnings = _read_file(path)
        source = str(path)
    elif env.get("SHELLSAGE_CONFIG"):
        raise ConfigError(f"SHELLSAGE_CONFIG points to a missing file: {path}")

    for variable, (field, kind) in _ENV_SCHEMA.items():
        raw = env.get(variable)
        if raw is not None and raw != "":
            values[field] = _coerce(variable, raw, kind, "environment")

    for field, value in (overrides or {}).items():
        if value is not None:
            values[field] = value

    config = Config(**values, source=source, warnings=tuple(warnings))
    return validate(config)
