"""Context gathering: shell detection, history reading, tool discovery."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from shellsage.config import Config
from shellsage.context import (
    available_tools,
    detect_shell,
    display_cwd,
    gather,
    history_path,
    os_description,
    read_history,
)
from shellsage.redact import PLACEHOLDER, Redactor


class ShellDetectionTests(unittest.TestCase):
    def test_from_env(self) -> None:
        self.assertEqual(detect_shell({"SHELL": "/usr/bin/zsh"}), "zsh")
        self.assertEqual(detect_shell({"SHELL": "/bin/bash"}), "bash")

    def test_unknown_or_missing_falls_back_to_bash(self) -> None:
        self.assertEqual(detect_shell({}), "bash")
        self.assertEqual(detect_shell({"SHELL": "/usr/bin/nu"}), "bash")

    def test_override_wins(self) -> None:
        self.assertEqual(detect_shell({"SHELL": "/bin/bash"}, "zsh"), "zsh")


class HistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def history(self, text: str, lines: int = 5) -> tuple[str, ...]:
        path = self.dir / "history"
        path.write_bytes(text.encode("utf-8", errors="surrogateescape"))
        return read_history(path, lines, Redactor())

    def test_last_n_lines(self) -> None:
        text = "\n".join(f"cmd{i}" for i in range(20)) + "\n"
        self.assertEqual(self.history(text, 3), ("cmd17", "cmd18", "cmd19"))

    def test_secrets_are_redacted(self) -> None:
        result = self.history("ls\nexport GITHUB_TOKEN=abc123\ncurl -u me:pw https://x\n")
        self.assertEqual(result[0], "ls")
        self.assertNotIn("abc123", " ".join(result))
        self.assertNotIn("me:pw", " ".join(result))
        self.assertIn(PLACEHOLDER, result[1])

    def test_zsh_extended_format_and_bash_timestamps(self) -> None:
        result = self.history(": 1700000000:0;git status\n#1700000001\nls -la\n")
        self.assertEqual(result, ("git status", "ls -la"))

    def test_consecutive_duplicates_collapse(self) -> None:
        self.assertEqual(self.history("ls\nls\nls\npwd\n"), ("ls", "pwd"))

    def test_zero_lines_reads_nothing(self) -> None:
        self.assertEqual(read_history(self.dir / "does-not-matter", 0, Redactor()), ())

    def test_missing_file_is_not_an_error(self) -> None:
        self.assertEqual(read_history(self.dir / "missing", 5, Redactor()), ())

    def test_invalid_utf8_is_tolerated(self) -> None:
        path = self.dir / "history"
        path.write_bytes(b"ls\n\xff\xfe broken\npwd\n")
        self.assertEqual(read_history(path, 5, Redactor())[-1], "pwd")

    def test_very_long_lines_are_truncated(self) -> None:
        self.assertEqual(len(self.history("echo " + "z" * 5000 + "\n")[0]), 300)

    def test_history_path(self) -> None:
        self.assertEqual(history_path({"HOME": "/h"}, "bash"), Path("/h/.bash_history"))
        self.assertEqual(history_path({"HOME": "/h"}, "zsh"), Path("/h/.zsh_history"))
        self.assertEqual(
            history_path({"HOME": "/h", "HISTFILE": "/x/hist"}, "bash"), Path("/x/hist")
        )
        self.assertEqual(
            history_path({"HOME": "/h", "HISTFILE": "/x"}, "bash", "/cfg"), Path("/cfg")
        )


class GatherTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = Path(self._tmp.name)
        (self.home / ".bash_history").write_text(
            "export API_KEY=zzz999\nmake test\n", encoding="utf-8"
        )
        self.env = {"HOME": str(self.home), "SHELL": "/bin/bash"}

    def test_history_is_off_by_default(self) -> None:
        context = gather(Config(), self.env, which=lambda name: None)
        self.assertEqual(context.history, ())
        self.assertEqual(context.tools, ())
        self.assertEqual(context.shell, "bash")

    def test_history_opt_in_is_redacted(self) -> None:
        context = gather(Config(history_lines=5), self.env, which=lambda name: None)
        self.assertEqual(context.history, (f"export API_KEY={PLACEHOLDER}", "make test"))

    def test_custom_redact_patterns_apply(self) -> None:
        config = Config(history_lines=5, redact_patterns=("make",))
        context = gather(config, self.env, which=lambda name: None)
        self.assertEqual(context.history[1], f"{PLACEHOLDER} test")

    def test_tools_use_injected_lookup(self) -> None:
        tools = available_tools(lambda name: "/usr/bin/" + name if name in ("git", "jq") else None)
        self.assertEqual(tools, ("git", "jq"))

    def test_cwd_is_shortened_under_home(self) -> None:
        here = os.getcwd()
        self.assertEqual(display_cwd({"HOME": here}), "~")
        self.assertEqual(
            display_cwd({"HOME": os.path.dirname(here)}), "~/" + os.path.basename(here)
        )
        self.assertEqual(display_cwd({"HOME": "/definitely/not/here"}), here)
        self.assertEqual(display_cwd({}), here)

    def test_os_description_is_nonempty(self) -> None:
        self.assertTrue(os_description())

    def test_does_not_need_a_controlling_terminal(self) -> None:
        # v0.x called os.getlogin(), which raises OSError without a tty (cron, CI, containers).
        gather(Config(), {"HOME": str(self.home)}, which=lambda name: None)


if __name__ == "__main__":
    unittest.main()
