"""``sage doctor`` - check that the local setup can actually answer a request."""

from __future__ import annotations

import shutil
import sys
from collections.abc import Callable, Mapping
from typing import TextIO

from shellsage import __version__
from shellsage.config import Config, config_path
from shellsage.context import detect_shell
from shellsage.llm import OllamaClient, OllamaError
from shellsage.ui import Style

__all__ = ["run_doctor"]


def run_doctor(
    config: Config,
    client: OllamaClient,
    env: Mapping[str, str],
    out: TextIO,
    style: Style,
    which: Callable[[str], str | None] = shutil.which,
) -> int:
    """Print a checklist; return 0 when every required check passed, else 1."""
    failed = False

    def report(status: str, title: str, detail: str = "", hint: str = "") -> None:
        nonlocal failed
        colour = {"ok": "green", "warn": "yellow", "FAIL": "red"}[status]
        failed = failed or status == "FAIL"
        out.write(f"  [{style.paint(status.center(4), colour)}] {title}")
        out.write(f": {detail}\n" if detail else "\n")
        if hint:
            out.write(f"         {style.paint(hint, 'dim')}\n")

    out.write(f"ShellSage {__version__} doctor\n\n")

    report("ok", "Python", ".".join(str(part) for part in sys.version_info[:3]))

    if config.source:
        report("ok", "Config file", config.source)
    else:
        report("ok", "Config file", f"none (defaults in use; looked for {config_path(env)})")
    for warning in config.warnings:
        report("warn", "Config", warning)

    if config.host_is_local:
        report(
            "ok", "Privacy", f"{config.host} is a loopback address; prompts stay on this machine"
        )
    else:
        report(
            "warn",
            "Privacy",
            f"{config.host} is not this machine",
            "your task text and context will be sent over the network to that host",
        )

    reachable = False
    try:
        server_version = client.version()
        reachable = True
        report("ok", "Ollama server", f"reachable at {config.host} (version {server_version})")
    except OllamaError as exc:
        report("FAIL", "Ollama server", str(exc), "start it with: ollama serve")

    if reachable:
        try:
            if client.has_model(config.model):
                report("ok", "Model", f"{config.model} is pulled")
            else:
                available = ", ".join(client.list_models()) or "none"
                report(
                    "FAIL",
                    "Model",
                    f"{config.model} is not pulled (available: {available})",
                    f"pull it with: ollama pull {config.model}",
                )
        except OllamaError as exc:
            report("FAIL", "Model", str(exc))
    else:
        report("warn", "Model", f"{config.model} (not checked - server unreachable)")

    report("ok", "Shell", detect_shell(env, config.shell))
    if config.history_lines:
        report(
            "warn",
            "Shell history",
            f"last {config.history_lines} lines are sent to the model after redaction",
            "redaction is best effort; set history_lines = 0 to disable",
        )
    else:
        report("ok", "Shell history", "not read (history_lines = 0)")
    if config.allow_danger:
        report(
            "warn",
            "Safety",
            "allow_danger = true: DANGER commands can run after typed confirmation",
        )
    else:
        report("ok", "Safety", "DANGER commands are never executed by ShellSage")

    clipboard = next(
        (t for t in ("wl-copy", "xclip", "xsel", "pbcopy", "clip.exe") if which(t)), None
    )
    if clipboard:
        report("ok", "Clipboard", clipboard)
    else:
        report(
            "warn", "Clipboard", "no clipboard tool found; [c]opy will print the command instead"
        )

    out.write("\n")
    out.write("Something needs attention.\n" if failed else "All required checks passed.\n")
    return 1 if failed else 0
