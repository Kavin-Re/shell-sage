"""Terminal presentation helpers: colour, rendering, clipboard, line editing."""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from typing import TextIO

from shellsage.prompt import Explanation
from shellsage.risk import Finding, Risk

__all__ = [
    "Style",
    "color_enabled",
    "copy_to_clipboard",
    "edit_line",
    "render_card",
    "render_explanation",
    "visible",
]

_CODES = {"bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33", "cyan": "36"}
_RISK_COLOR = {Risk.SAFE: "green", Risk.CAUTION: "yellow", Risk.DANGER: "red"}
_UNPRINTABLE = re.compile("[\x00-\x08\x0b-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")


def color_enabled(mode: str, stream: TextIO, env: Mapping[str, str]) -> bool:
    """Decide whether to emit ANSI colour.

    ``never``/``always`` are explicit. ``auto`` honours https://no-color.org
    (any non-empty ``NO_COLOR``), ``TERM=dumb`` and whether the stream is a TTY.
    """
    if mode == "never":
        return False
    if mode == "always":
        return True
    if env.get("NO_COLOR") or env.get("TERM") == "dumb":
        return False
    try:
        return stream.isatty()
    except (AttributeError, ValueError):
        return False


class Style:
    """Tiny ANSI painter that degrades to plain text."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def paint(self, text: str, *names: str) -> str:
        if not self.enabled or not names:
            return text
        codes = ";".join(_CODES[name] for name in names)
        return f"\x1b[{codes}m{text}\x1b[0m"

    def risk(self, level: Risk) -> str:
        return self.paint(level.label, "bold", _RISK_COLOR[level])


def visible(text: str) -> str:
    r"""Make control and invisible characters visible (``\x1b`` instead of ESC).

    A model reply is untrusted: without this, escape sequences could repaint
    the terminal so that the command shown differs from the command run.
    """
    return _UNPRINTABLE.sub(lambda m: m.group().encode("unicode_escape").decode("ascii"), text)


def render_card(
    command: str,
    explanation: str,
    level: Risk,
    findings: Sequence[Finding],
    style: Style,
    notes: Sequence[str] = (),
) -> str:
    """The block shown for every suggestion: command, explanation, risk, reasons."""
    lines = [""]
    shown = visible(command).split("\n")
    lines.append(f"  {style.paint('$', 'dim')} {style.paint(shown[0], 'bold', 'cyan')}")
    lines.extend(f"    {style.paint(extra, 'bold', 'cyan')}" for extra in shown[1:])
    if explanation:
        lines.append("")
        lines.append(f"  {explanation}")
    lines.append("")
    if findings:
        lines.append(f"  risk: {style.risk(level)}")
        for finding in findings:
            marker = style.paint("!", _RISK_COLOR[finding.level])
            lines.append(
                f"    {marker} {finding.reason} {style.paint(f'[{finding.category}]', 'dim')}"
            )
    else:
        lines.append(f"  risk: {style.risk(level)} {style.paint('(no risk rule matched)', 'dim')}")
    for note in notes:
        lines.append(f"  {style.paint('note:', 'dim')} {note}")
    lines.append("")
    return "\n".join(lines)


def render_explanation(explanation: Explanation, style: Style) -> str:
    lines: list[str] = [""]
    if explanation.summary:
        lines.append(f"  {explanation.summary}")
        lines.append("")
    if explanation.breakdown:
        width = min(max(len(part) for part, _ in explanation.breakdown), 28)
        for part, meaning in explanation.breakdown:
            lines.append(f"    {style.paint(visible(part).ljust(width), 'cyan')}  {meaning}")
        lines.append("")
    for warning in explanation.warnings:
        lines.append(f"  {style.paint('model warning:', 'yellow')} {warning}")
    if explanation.warnings:
        lines.append("")
    return "\n".join(lines)


def _clipboard_commands(env: Mapping[str, str]) -> list[list[str]]:
    commands: list[list[str]] = []
    if env.get("WAYLAND_DISPLAY"):
        commands.append(["wl-copy"])
    if env.get("DISPLAY"):
        commands.append(["xclip", "-selection", "clipboard"])
        commands.append(["xsel", "--clipboard", "--input"])
    commands.extend([["pbcopy"], ["clip.exe"], ["termux-clipboard-set"]])
    return commands


def copy_to_clipboard(
    text: str,
    env: Mapping[str, str],
    which: Callable[[str], str | None] = shutil.which,
) -> str | None:
    """Copy ``text`` using the first clipboard tool that works; return its name."""
    for command in _clipboard_commands(env):
        if not which(command[0]):
            continue
        try:
            done = subprocess.run(
                command, input=text.encode("utf-8"), timeout=3, check=False,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )  # fmt: skip
        except (OSError, subprocess.SubprocessError):
            continue
        if done.returncode == 0:
            return command[0]
    return None


def edit_line(prompt: str, initial: str) -> str:
    """Let the user edit ``initial``.

    With GNU readline the line is pre-filled and edited in place. libedit (the
    default on macOS and some Python builds) cannot pre-fill reliably, and some
    platforms have no readline at all; there the current command is shown and
    a replacement is typed, with Enter keeping it unchanged.
    """
    try:
        import readline  # noqa: PLC0415 - optional, not present on every platform
    except ImportError:
        readline = None  # type: ignore[assignment]
    gnu = readline is not None and "libedit" not in (readline.__doc__ or "")
    if not gnu:
        print(f"  current: {visible(initial)}")
        print("  type the full replacement (Enter alone keeps it)")
        return input(prompt) or initial

    def prefill() -> None:
        readline.insert_text(initial)
        readline.redisplay()

    readline.set_startup_hook(prefill)
    try:
        return input(prompt)
    finally:
        readline.set_startup_hook(None)
