"""Collect the local context that is sent to the model along with the request.

Everything gathered here is visible with ``sage --show-prompt``. Shell history
is only read when the user opted in (``history_lines > 0``) and always passes
through :class:`shellsage.redact.Redactor` first.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from shellsage.config import Config
from shellsage.redact import Redactor

__all__ = ["KNOWN_TOOLS", "Context", "detect_shell", "gather", "read_history"]

# Tools worth telling the model about: it should not suggest `rg` or `fd` on a
# machine that only has grep and find.
KNOWN_TOOLS: tuple[str, ...] = (
    "apt", "awk", "brew", "curl", "dnf", "docker", "fd", "ffmpeg", "fzf", "gcc", "git",
    "htop", "ip", "journalctl", "jq", "kubectl", "lsof", "make", "nmcli", "node", "npm",
    "pacman", "podman", "python3", "rg", "rsync", "sensors", "ss", "ssh", "systemctl",
    "tar", "tmux", "unzip", "wget", "zip", "zypper",
)  # fmt: skip
_SUPPORTED_SHELLS = ("bash", "zsh", "sh", "dash", "ksh", "fish")
_ZSH_EXTENDED = re.compile(r"^: \d+:\d+;")


@dataclass(frozen=True)
class Context:
    cwd: str
    os_name: str
    shell: str
    is_root: bool
    tools: tuple[str, ...]
    history: tuple[str, ...] = ()


def detect_shell(env: Mapping[str, str], override: str = "") -> str:
    """Name of the shell commands should be written for (default: bash)."""
    name = Path(override or env.get("SHELL", "")).name
    return name if name in _SUPPORTED_SHELLS else "bash"


def os_description() -> str:
    """Human-readable OS, e.g. ``Linux (Ubuntu 24.04.1 LTS)``."""
    system = platform.system() or "Unknown"
    detail = ""
    if system == "Linux":
        try:
            detail = platform.freedesktop_os_release().get("PRETTY_NAME", "")
        except OSError:
            detail = ""
        if "microsoft" in platform.release().lower():
            detail = f"{detail}, WSL".lstrip(", ")
    elif system == "Darwin":
        detail = f"macOS {platform.mac_ver()[0]}".strip()
    return f"{system} ({detail})" if detail else system


def display_cwd(env: Mapping[str, str]) -> str:
    """Current directory with the home prefix shortened to ``~``."""
    try:
        cwd = os.getcwd()
    except OSError:
        return "(unknown - the current directory no longer exists)"
    home = env.get("HOME", "")
    if home and (cwd == home or cwd.startswith(home.rstrip("/") + "/")):
        return "~" + cwd[len(home.rstrip("/")) :]
    return cwd


def available_tools(which: Callable[[str], str | None] = shutil.which) -> tuple[str, ...]:
    return tuple(tool for tool in KNOWN_TOOLS if which(tool))


def history_path(env: Mapping[str, str], shell: str, configured: str = "") -> Path:
    if configured:
        return Path(configured).expanduser()
    if env.get("HISTFILE"):
        return Path(env["HISTFILE"]).expanduser()
    home = Path(env.get("HOME") or Path.home())
    return home / (".zsh_history" if shell == "zsh" else ".bash_history")


def read_history(path: Path, lines: int, redactor: Redactor) -> tuple[str, ...]:
    """Return the last ``lines`` distinct history entries, redacted.

    Never raises: an unreadable history file simply yields no history.
    """
    if lines <= 0:
        return ()
    try:
        raw = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ()
    entries: list[str] = []
    for line in raw[-(lines * 4) :]:
        entry = _ZSH_EXTENDED.sub("", line).strip()
        if not entry or entry.startswith("#"):  # bash HISTTIMEFORMAT timestamps
            continue
        if entries and entries[-1] == entry:
            continue
        entries.append(entry[:300])
    return tuple(redactor.redact_lines(entries[-lines:]))


def gather(
    config: Config,
    env: Mapping[str, str] | None = None,
    which: Callable[[str], str | None] = shutil.which,
) -> Context:
    env = os.environ if env is None else env
    shell = detect_shell(env, config.shell)
    history: tuple[str, ...] = ()
    if config.history_lines > 0:
        history = read_history(
            history_path(env, shell, config.history_file),
            config.history_lines,
            Redactor(config.redact_patterns),
        )
    geteuid = getattr(os, "geteuid", None)
    return Context(
        cwd=display_cwd(env),
        os_name=os_description(),
        shell=shell,
        is_root=bool(geteuid and geteuid() == 0),
        tools=available_tools(which),
        history=history,
    )
