"""Secret redaction for text that is about to be shown to a model.

Redaction is best effort: it recognises common credential shapes, it cannot
recognise every secret. That is why shell history is opt-in in the first place.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

__all__ = ["PLACEHOLDER", "Redactor", "redact"]

PLACEHOLDER = "[REDACTED]"

_SECRET_WORD = (
    r"pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
    r"auth|credential|session[_-]?id|client[_-]?secret"
)

# (name, pattern, replacement). Order matters: specific shapes first.
_BUILTIN: tuple[tuple[str, str, str], ...] = (
    (
        "private-key",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)",
        PLACEHOLDER,
    ),
    (
        "url-credentials",
        r"\b([a-zA-Z][a-zA-Z0-9+.-]*://)[^\s/:@]+:[^\s/@]+@",
        r"\1" + PLACEHOLDER + "@",
    ),
    ("aws-access-key-id", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b", PLACEHOLDER),
    (
        "github-token",
        r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{22,})\b",
        PLACEHOLDER,
    ),
    ("gitlab-token", r"\bglpat-[A-Za-z0-9_-]{20,}", PLACEHOLDER),
    ("slack-token", r"\bxox[abeprs]-[A-Za-z0-9-]{10,}", PLACEHOLDER),
    ("sk-key", r"\bsk-[A-Za-z0-9_-]{20,}", PLACEHOLDER),
    ("google-api-key", r"\bAIza[0-9A-Za-z_-]{35}\b", PLACEHOLDER),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", PLACEHOLDER),
    (
        "auth-header",
        r"(?i)\b(authorization\s*:\s*(?:bearer|basic|token)\s+)[^\s'\"]+",
        r"\1" + PLACEHOLDER,
    ),
    ("bearer", r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{12,}", r"\1" + PLACEHOLDER),
    # NAME_WITH_SECRET_WORD=value   (export DB_PASSWORD=..., API_KEY: ..., "token": "...")
    (
        "assignment",
        r"(?i)([A-Za-z0-9_.-]*(?:" + _SECRET_WORD + r")[A-Za-z0-9_.-]*[\"']?\s*[=:]\s*)"
        r"(?!\[REDACTED\])(\"[^\"]*\"|'[^']*'|[^\s'\"&;|]+)",
        r"\1" + PLACEHOLDER,
    ),
    # --password VALUE / --token=VALUE / --api-key VALUE
    (
        "long-option",
        r"(?i)(--[a-z0-9-]*(?:"
        + _SECRET_WORD
        + r")[a-z0-9-]*[ =])(?!\[REDACTED\])(\"[^\"]*\"|'[^']*'|[^\s'\"]+)",
        r"\1" + PLACEHOLDER,
    ),
    # curl -u user:pass, wget --user/--password handled above
    (
        "curl-user",
        r"(\bcurl\b[^|;&\n]*?\s(?:-u|--user)[ =]?)(\"[^\"]*\"|'[^']*'|[^\s'\"]+)",
        r"\1" + PLACEHOLDER,
    ),
    # mysql -pSECRET, sshpass -p SECRET
    (
        "db-password",
        r"(\b(?:mysql|mysqldump|mysqladmin|mariadb)\b[^|;&\n]*?\s-p)([^\s]+)",
        r"\1" + PLACEHOLDER,
    ),
    ("sshpass", r"(\bsshpass\s+-p\s*)(\"[^\"]*\"|'[^']*'|[^\s'\"]+)", r"\1" + PLACEHOLDER),
    ("hex-blob", r"\b[A-Fa-f0-9]{32,}\b", PLACEHOLDER),
)


class Redactor:
    """Apply the built-in patterns plus any user-supplied regexes."""

    def __init__(self, extra_patterns: Sequence[str] = ()) -> None:
        self._rules: list[tuple[re.Pattern[str], str]] = [
            (re.compile(pattern), replacement) for _name, pattern, replacement in _BUILTIN
        ]
        # User patterns replace the whole match; a bad regex raises re.error here
        # (config validation reports it before we get this far).
        self._rules.extend((re.compile(p), PLACEHOLDER) for p in extra_patterns)

    def redact(self, text: str) -> str:
        for pattern, replacement in self._rules:
            text = pattern.sub(replacement, text)
        return text

    def redact_lines(self, lines: Iterable[str]) -> list[str]:
        return [self.redact(line) for line in lines]


def redact(text: str, extra_patterns: Sequence[str] = ()) -> str:
    """Convenience wrapper around :class:`Redactor`."""
    return Redactor(extra_patterns).redact(text)
