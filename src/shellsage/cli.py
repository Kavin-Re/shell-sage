"""Command-line entry point for ``sage``."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from importlib import resources
from typing import Any, TextIO

from shellsage import __version__
from shellsage.config import Config, ConfigError, load_config
from shellsage.context import Context, gather
from shellsage.doctor import run_doctor
from shellsage.llm import OllamaClient, OllamaError
from shellsage.prompt import (
    EXPLAIN_SYSTEM_PROMPT,
    SYSTEM_PROMPT,
    build_explain_prompt,
    build_prompt,
    parse_explanation,
    parse_suggestion,
)
from shellsage.risk import Assessment, Finding, Risk, classify
from shellsage.ui import (
    Style,
    color_enabled,
    copy_to_clipboard,
    edit_line,
    render_card,
    render_explanation,
)

__all__ = ["EXIT_CAUTION", "EXIT_DANGER", "EXIT_ERROR", "EXIT_REFUSED", "EXIT_USAGE", "IO", "main"]

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_REFUSED = 3  # the risk policy did not allow non-interactive execution
EXIT_CAUTION = 10  # --check only
EXIT_DANGER = 20  # --check only
EXIT_INTERRUPTED = 130

_BUILTIN_NAMES = """
. : [ [[ alias bg bind break builtin case cd command compgen complete continue coproc
declare dirs disown do done echo elif else esac eval exec exit export false fc fg fi for
function getopts hash help history if in jobs kill let local logout popd printf pushd pwd
read readonly return select set shift shopt source test then time times trap true type
typeset ulimit umask unalias unset until wait while { }
"""
_SHELL_BUILTINS = frozenset(_BUILTIN_NAMES.split())
_PLAIN_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")

_EPILOG = """\
examples:
  sage find all log files larger than 50MB
  sage --dry-run "show which process is listening on port 8080"
  sage --explain "tar -xzvf backup.tar.gz -C /opt"
  sage --check "curl https://example.com/install.sh | sh"   # offline risk check only
  sage doctor                 check Ollama, the model and your configuration
  sage config                 print the effective configuration
  sage shell-init bash        print the shell hook (add: eval "$(sage shell-init bash)")

exit status:
  0 success (or the exit status of the command you chose to run)
  1 error (Ollama unreachable, no command suggested, ...)   2 usage error
  3 execution refused by the risk policy                    130 interrupted
  --check: 0 SAFE, 10 CAUTION, 20 DANGER

Words starting with "-" in a task must come after "--":  sage -- list files -la style
"""


def _stdin_isatty() -> bool:
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False


def _default_input(prompt: str) -> str:
    return input(prompt)


def _default_run(shell: str, command: str) -> int:
    """Run ``command`` in ``shell`` attached to the terminal; return its exit status."""
    executable = shutil.which(shell) or "/bin/sh"
    code = subprocess.run([executable, "-c", command], check=False).returncode
    return 128 - code if code < 0 else code


def _default_client(config: Config) -> OllamaClient:
    return OllamaClient(config.host, config.timeout)


@dataclass
class IO:
    """Everything the CLI touches outside its own process (replaceable in tests)."""

    stdout: TextIO = field(default_factory=lambda: sys.stdout)
    stderr: TextIO = field(default_factory=lambda: sys.stderr)
    env: Mapping[str, str] = field(default_factory=lambda: os.environ)
    stdin_isatty: Callable[[], bool] = _stdin_isatty
    input_fn: Callable[[str], str] = _default_input
    edit_fn: Callable[[str, str], str] = edit_line
    run_fn: Callable[[str, str], int] = _default_run
    copy_fn: Callable[[str, Mapping[str, str]], str | None] = copy_to_clipboard
    client_factory: Callable[[Config], OllamaClient] = _default_client
    which: Callable[[str], str | None] = shutil.which

    def stdout_isatty(self) -> bool:
        try:
            return self.stdout.isatty()
        except (AttributeError, ValueError):
            return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sage",
        description="Turn plain English into a shell command using a local Ollama model, "
        "explain it, and grade its risk before anything runs.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("task", nargs="*", help="what you want to do, in plain language")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("-x", "--explain", metavar="COMMAND", help="explain an existing command")
    mode.add_argument(
        "-c", "--check", metavar="COMMAND",
        help="grade a command with the offline risk engine only (no model call)",
    )  # fmt: skip
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "-n", "--dry-run", action="store_true", help="show the suggestion, never execute"
    )
    action.add_argument(
        "-y", "--yes", action="store_true",
        help="execute without asking - honoured only when the risk level is SAFE",
    )  # fmt: skip
    parser.add_argument("--json", action="store_true", help="machine-readable output; implies -n")
    parser.add_argument("-m", "--model", help="Ollama model tag (default: qwen2.5-coder:3b)")
    parser.add_argument("--host", help="Ollama base URL (default: http://127.0.0.1:11434)")
    parser.add_argument("--timeout", type=float, metavar="SECONDS", help="request timeout")
    history = parser.add_mutually_exclusive_group()
    history.add_argument(
        "--history", type=int, metavar="N", dest="history_lines",
        help="include the last N shell-history lines (redacted) as context",
    )  # fmt: skip
    history.add_argument(
        "--no-history", action="store_const", const=0, dest="history_lines",
        help="do not read shell history even if the config enables it",
    )  # fmt: skip
    parser.add_argument(
        "--show-prompt", action="store_true",
        help="print exactly what would be sent to the model, then exit",
    )  # fmt: skip
    parser.add_argument("--color", choices=("auto", "always", "never"), help="colour output")
    parser.add_argument("-V", "--version", action="version", version=f"shellsage {__version__}")
    return parser


def _missing_tools(assessment: Assessment, which: Callable[[str], str | None]) -> list[str]:
    return [
        name
        for name in assessment.programs
        if name not in _SHELL_BUILTINS and _PLAIN_NAME.fullmatch(name) and not which(name)
    ]


def _assess(
    command: str, model_risk: Risk | None, env: Mapping[str, str]
) -> tuple[Risk, list[Finding], Assessment]:
    """Run the risk engine; the model's own label may raise the level, never lower it."""
    try:
        cwd: str | None = os.getcwd()
    except OSError:
        cwd = None
    assessment = classify(command, cwd=cwd, home=env.get("HOME"))
    findings = list(assessment.findings)
    level = assessment.level
    if model_risk is not None and model_risk > level:
        level = model_risk
        findings.insert(
            0,
            Finding(model_risk, "model", f"the model itself rated this command {model_risk.label}"),
        )
    return level, findings, assessment


def _findings_json(findings: Sequence[Finding]) -> list[dict[str, str]]:
    return [{"level": f.level.label, "category": f.category, "reason": f.reason} for f in findings]


class _App:
    def __init__(self, args: argparse.Namespace, config: Config, io: IO) -> None:
        self.args = args
        self.config = config
        self.io = io
        self.style = Style(color_enabled(config.color, io.stderr, io.env))
        self.interactive = io.stdin_isatty() and io.stdout_isatty()

    # -- output helpers ----------------------------------------------------- #

    def say(self, text: str = "") -> None:
        self.io.stderr.write(text + "\n")
        self.io.stderr.flush()

    def error(self, text: str) -> None:
        self.say(f"{self.style.paint('sage:', 'red')} {text}")

    def emit(self, text: str) -> None:
        self.io.stdout.write(text + "\n")
        self.io.stdout.flush()

    def ask(self, prompt: str) -> str:
        return self.io.input_fn(prompt).strip()

    # -- modes -------------------------------------------------------------- #

    def check(self, command: str) -> int:
        level, findings, _assessment = _assess(command, None, self.io.env)
        if self.args.json:
            self.emit(
                json.dumps(
                    {"command": command, "risk": level.label, "findings": _findings_json(findings)},
                    indent=2,
                )
            )
        else:
            self.say(render_card(command, "", level, findings, self.style).rstrip("\n"))
            self.say()
        return {Risk.SAFE: EXIT_OK, Risk.CAUTION: EXIT_CAUTION, Risk.DANGER: EXIT_DANGER}[level]

    def explain(self, command: str) -> int:
        context = gather(self.config, self.io.env, self.io.which)
        prompt = build_explain_prompt(command, context)
        if self.args.show_prompt:
            self.emit(f"--- system ---\n{EXPLAIN_SYSTEM_PROMPT}\n--- prompt ---\n{prompt}")
            return EXIT_OK
        level, findings, _assessment = _assess(command, None, self.io.env)
        if not self.args.json:
            self.say(render_card(command, "", level, findings, self.style).rstrip("\n"))
        try:
            raw = self.io.client_factory(self.config).generate(
                self.config.model, prompt, system=EXPLAIN_SYSTEM_PROMPT,
                temperature=self.config.temperature,
            )  # fmt: skip
        except OllamaError as exc:
            self.say()
            self.error(f"{exc}")
            self.say("The risk assessment above is computed locally and is still valid.")
            return EXIT_ERROR
        explanation = parse_explanation(raw)
        if self.args.json:
            self.emit(
                json.dumps(
                    {
                        "command": command,
                        "risk": level.label,
                        "findings": _findings_json(findings),
                        "summary": explanation.summary,
                        "breakdown": [
                            {"part": part, "meaning": meaning}
                            for part, meaning in explanation.breakdown
                        ],
                        "warnings": list(explanation.warnings),
                        "model": self.config.model,
                    },
                    indent=2,
                )
            )
        else:
            self.say(render_explanation(explanation, self.style).rstrip("\n"))
            self.say()
        return EXIT_OK

    def suggest(self, task: str) -> int:
        context = gather(self.config, self.io.env, self.io.which)
        prompt = build_prompt(task, context)
        if self.args.show_prompt:
            self.emit(f"--- system ---\n{SYSTEM_PROMPT}\n--- prompt ---\n{prompt}")
            return EXIT_OK
        client = self.io.client_factory(self.config)
        if self.interactive:
            self.say(
                self.style.paint(f"asking {self.config.model} at {self.config.host} ...", "dim")
            )
        try:
            raw = client.generate(
                self.config.model, prompt, system=SYSTEM_PROMPT,
                temperature=self.config.temperature,
            )  # fmt: skip
        except OllamaError as exc:
            self.error(f"{exc}")
            self.say("Run `sage doctor` to diagnose.")
            return EXIT_ERROR
        suggestion = parse_suggestion(raw)
        command, explanation = suggestion.command, suggestion.explanation
        if not command:
            self.error("the model did not suggest a command.")
            if explanation:
                self.say(f"  {explanation}")
            return EXIT_ERROR

        level, findings, assessment = _assess(command, suggestion.model_risk, self.io.env)
        notes = [
            f"`{tool}` is not on your PATH" for tool in _missing_tools(assessment, self.io.which)
        ]
        if not suggestion.structured:
            notes.append(
                "the model ignored the JSON format; the command was extracted from free text"
            )

        if self.args.json:
            self.emit(
                json.dumps(
                    {
                        "command": command,
                        "explanation": explanation,
                        "risk": level.label,
                        "findings": _findings_json(findings),
                        "notes": notes,
                        "model": self.config.model,
                    },
                    indent=2,
                )
            )
            return EXIT_OK

        self.say(render_card(command, explanation, level, findings, self.style, notes).rstrip("\n"))
        self.say()

        if self.args.dry_run:
            return self._print_only(command)
        if self.args.yes:
            if level is Risk.SAFE:
                return self.io.run_fn(context.shell, command)
            if not self.interactive:
                self.error(
                    f"--yes only applies to SAFE commands; this one is {level.label}. Not executed."
                )
                self._print_only(command)
                return EXIT_REFUSED
            self.say(f"--yes only applies to SAFE commands; this one is {level.label}.")
        if not self.interactive:
            self.say("Not a terminal: nothing was executed (use --yes for SAFE commands).")
            return self._print_only(command)
        return self._menu(command, level, context)

    def _print_only(self, command: str) -> int:
        """Emit the bare command on stdout when it is being captured or piped."""
        if not self.io.stdout_isatty():
            self.emit(command)
        return EXIT_OK

    # -- interactive loop --------------------------------------------------- #

    def _menu(self, command: str, level: Risk, context: Context) -> int:
        keys = self.style.paint
        menu = (
            f"  {keys('[r]', 'bold')}un  {keys('[e]', 'bold')}dit  {keys('[c]', 'bold')}opy  "
            f"e{keys('[x]', 'bold')}plain  {keys('[q]', 'bold')}uit > "
        )
        while True:
            choice = self.ask(menu).lower()
            if choice in ("q", "quit", "n", "no"):
                return EXIT_OK
            if choice in ("r", "run", "y", "yes"):
                if self._may_run(level):
                    return self.io.run_fn(context.shell, command)
            elif choice in ("e", "edit"):
                edited = self.io.edit_fn("  edit > ", command).strip()
                if edited and edited != command:
                    command = edited
                    # The edited text is new, untrusted input: grade it from scratch.
                    level, findings, _assessment = _assess(command, None, self.io.env)
                    note = ["edited by you - explanation above no longer applies"]
                    self.say(
                        render_card(command, "", level, findings, self.style, note).rstrip("\n")
                    )
                    self.say()
            elif choice in ("c", "copy"):
                tool = self.io.copy_fn(command, self.io.env)
                if tool:
                    self.say(f"  copied to clipboard ({tool})")
                else:
                    self.say("  no clipboard tool found - here is the command:")
                    self.emit(command)
                return EXIT_OK
            elif choice in ("x", "explain"):
                self._explain_inline(command, context)
            elif choice:
                self.say("  choose r, e, c, x or q")

    def _may_run(self, level: Risk) -> bool:
        if level is Risk.SAFE:
            return True
        if level is Risk.CAUTION:
            return self.ask("  CAUTION - run it anyway? [y/N] ").lower() in ("y", "yes")
        if not self.config.allow_danger:
            self.say(
                "  "
                + self.style.paint("refused:", "bold", "red")
                + " ShellSage does not execute DANGER commands. Read the reasons above;\n"
                "  if you are certain, [c]opy it and run it yourself."
            )
            return False
        typed = self.ask('  DANGER - type "yes, run it" to execute: ')
        return typed == "yes, run it"

    def _explain_inline(self, command: str, context: Context) -> None:
        try:
            raw = self.io.client_factory(self.config).generate(
                self.config.model, build_explain_prompt(command, context),
                system=EXPLAIN_SYSTEM_PROMPT, temperature=self.config.temperature,
            )  # fmt: skip
        except OllamaError as exc:
            self.error(f"{exc}")
            return
        self.say(render_explanation(parse_explanation(raw), self.style).rstrip("\n"))
        self.say()


def _show_config(config: Config, out: TextIO) -> int:
    out.write(f"# source: {config.source or 'built-in defaults (no config file found)'}\n")
    rows: list[tuple[str, Any]] = [
        ("model", config.model),
        ("host", config.host),
        ("timeout", config.timeout),
        ("temperature", config.temperature),
        ("history_lines", config.history_lines),
        ("history_file", config.history_file or "(auto)"),
        ("redact_patterns", f"{len(config.redact_patterns)} custom + built-in set"),
        ("shell", config.shell or "(auto)"),
        ("color", config.color),
        ("allow_danger", config.allow_danger),
    ]
    for key, value in rows:
        out.write(f"{key:<16} = {value}\n")
    return EXIT_OK


def shell_hook(shell: str) -> str:
    """Source text of the bundled hook for ``shell`` (``bash`` or ``zsh``)."""
    return (
        resources.files("shellsage").joinpath("shell").joinpath(f"sage.{shell}").read_text("utf-8")
    )


def main(argv: Sequence[str] | None = None, io: IO | None = None) -> int:
    io = io or IO()
    parser = build_parser()
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    task_words: list[str] = args.task

    if len(task_words) == 2 and task_words[0] == "shell-init" and task_words[1] in ("bash", "zsh"):
        io.stdout.write(shell_hook(task_words[1]))
        return EXIT_OK
    if (args.explain is not None or args.check is not None) and task_words:
        parser.error(
            "--explain/--check take the command as one quoted argument, with no extra words"
        )

    overrides = {
        "model": args.model,
        "host": args.host,
        "timeout": args.timeout,
        "history_lines": args.history_lines,
        "color": args.color,
    }
    try:
        config = load_config(io.env, overrides)
    except ConfigError as exc:
        io.stderr.write(f"sage: configuration error: {exc}\n")
        return EXIT_USAGE

    app = _App(args, config, io)
    for warning in config.warnings:
        app.say(f"sage: warning: {warning}")
    try:
        if args.check is not None:
            return app.check(args.check)
        if args.explain is not None:
            return app.explain(args.explain)
        if task_words == ["doctor"]:
            style = Style(color_enabled(config.color, io.stdout, io.env))
            return run_doctor(config, io.client_factory(config), io.env, io.stdout, style, io.which)
        if task_words == ["config"]:
            return _show_config(config, io.stdout)
        task = " ".join(task_words).strip()
        if not task:
            parser.print_usage(io.stderr)
            io.stderr.write(
                'sage: tell me what you want to do, e.g.  sage "find files over 50MB"\n'
            )
            return EXIT_USAGE
        return app.suggest(task)
    except (KeyboardInterrupt, EOFError):
        io.stderr.write("\n")
        return EXIT_INTERRUPTED
