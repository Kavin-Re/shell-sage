"""Behavioural tests for the bash command-not-found hook (run in a real bash)."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parent.parent / "src" / "shellsage" / "shell"
BASH = shutil.which("bash")
ZSH = shutil.which("zsh")

try:
    import pty
except ImportError:  # pragma: no cover - non-POSIX
    pty = None  # type: ignore[assignment]

FAKE_SAGE = """#!/bin/sh
printf '%s\\n' "$@" > "$SAGE_LOG"
exit 0
"""


@unittest.skipUnless(BASH, "bash is not installed")
class BashHookTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        sage = self.bin / "sage"
        sage.write_text(FAKE_SAGE, encoding="utf-8")
        sage.chmod(0o755)
        self.log = self.dir / "sage.log"
        self.env = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "HOME": str(self.dir),
            "SAGE_LOG": str(self.log),
            "TERM": "dumb",
        }

    def script(self, line: str, prelude: str = "") -> str:
        return f'{prelude}\nsource "{HOOKS / "sage.bash"}"\n{line}\necho "rc=$?"\n'

    def run_plain(
        self, line: str, prelude: str = "", **env: str
    ) -> subprocess.CompletedProcess[str]:
        assert BASH is not None
        return subprocess.run(
            [BASH, "--norc", "--noprofile", "-c", self.script(line, prelude)],
            env={**self.env, **env}, stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=20, check=False,
        )  # fmt: skip

    def run_tty(self, line: str, typed: str, **env: str) -> str:
        """Run with stdin/stdout/stderr on a pseudo-terminal; return everything printed."""
        assert BASH is not None and pty is not None
        master, slave = pty.openpty()
        try:
            process = subprocess.Popen(
                [BASH, "--norc", "--noprofile", "-c", self.script(line)],
                env={**self.env, **env}, stdin=slave, stdout=slave, stderr=slave, close_fds=True,
            )  # fmt: skip
            os.close(slave)
            slave = -1
            if typed:
                os.write(master, typed.encode())
            chunks: list[bytes] = []
            while True:
                try:
                    data = os.read(master, 4096)
                except OSError:
                    break
                if not data:
                    break
                chunks.append(data)
            process.wait(timeout=20)
            return b"".join(chunks).decode(errors="replace")
        finally:
            if slave >= 0:
                os.close(slave)
            os.close(master)

    def sage_args(self) -> list[str] | None:
        if not self.log.exists():
            return None
        return self.log.read_text(encoding="utf-8").splitlines()

    # -- declined cases ------------------------------------------------------ #

    def test_syntax(self) -> None:
        assert BASH is not None
        done = subprocess.run(
            [BASH, "-n", str(HOOKS / "sage.bash")], capture_output=True, check=False
        )
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_single_word_typo_is_left_alone(self) -> None:
        done = self.run_plain("gti")
        self.assertIn("rc=127", done.stdout)
        self.assertIn("gti: command not found", done.stderr)
        self.assertIsNone(self.sage_args())

    def test_two_word_typo_is_left_alone(self) -> None:
        done = self.run_plain("gti status")
        self.assertIn("rc=127", done.stdout)
        self.assertIsNone(self.sage_args())

    def test_never_fires_without_a_terminal(self) -> None:
        done = self.run_plain("please find the big files")
        self.assertIn("rc=127", done.stdout)
        self.assertIn("command not found", done.stderr)
        self.assertIsNone(self.sage_args(), "scripts and pipes must never reach the model")

    def test_existing_handler_is_preserved(self) -> None:
        prelude = 'command_not_found_handle() { echo "DISTRO-HANDLER $1"; return 127; }'
        done = self.run_plain("gti status", prelude)
        self.assertIn("DISTRO-HANDLER gti", done.stdout)
        self.assertIn("rc=127", done.stdout)

    def test_sourcing_twice_does_not_recurse(self) -> None:
        prelude = f'source "{HOOKS / "sage.bash"}"'
        done = self.run_plain("gti", prelude)
        self.assertIn("rc=127", done.stdout)
        self.assertEqual(done.stderr.count("command not found"), 1)

    # -- terminal cases ------------------------------------------------------ #

    @unittest.skipUnless(pty, "needs a pseudo-terminal")
    def test_multi_word_on_terminal_asks_then_calls_sage(self) -> None:
        output = self.run_tty("please find the big files", "y\n")
        self.assertIn("Ask ShellSage? [y/N]", output)
        self.assertEqual(self.sage_args(), ["--", "please", "find", "the", "big", "files"])
        self.assertIn("rc=127", output, "exit status must stay 'command not found'")

    @unittest.skipUnless(pty, "needs a pseudo-terminal")
    def test_answering_no_sends_nothing(self) -> None:
        for typed in ("n\n", "\n"):
            with self.subTest(typed=typed):
                output = self.run_tty("please find the big files", typed)
                self.assertIsNone(self.sage_args())
                self.assertIn("rc=127", output)

    @unittest.skipUnless(pty, "needs a pseudo-terminal")
    def test_confirmation_can_be_disabled(self) -> None:
        output = self.run_tty("please show disk usage", "", SHELLSAGE_HOOK_CONFIRM="0")
        self.assertNotIn("Ask ShellSage?", output)
        self.assertEqual(self.sage_args(), ["--", "please", "show", "disk", "usage"])
        self.assertIn("rc=127", output)

    @unittest.skipUnless(pty, "needs a pseudo-terminal")
    def test_min_words_is_configurable(self) -> None:
        self.run_tty("gti status", "", SHELLSAGE_HOOK_CONFIRM="0", SHELLSAGE_HOOK_MIN_WORDS="2")
        self.assertEqual(self.sage_args(), ["--", "gti", "status"])

    @unittest.skipUnless(pty, "needs a pseudo-terminal")
    def test_arguments_with_spaces_and_dashes_survive(self) -> None:
        self.run_tty("lsit 'my files' -la now", "", SHELLSAGE_HOOK_CONFIRM="0")
        self.assertEqual(self.sage_args(), ["--", "lsit", "my files", "-la", "now"])

    @unittest.skipUnless(pty, "needs a pseudo-terminal")
    def test_declines_when_sage_is_not_installed(self) -> None:
        output = self.run_tty("please find the big files", "", PATH="/usr/bin:/bin")
        self.assertIn("command not found", output)
        self.assertIn("rc=127", output)


@unittest.skipUnless(ZSH, "zsh is not installed")
class ZshHookTests(unittest.TestCase):
    def test_syntax(self) -> None:
        assert ZSH is not None
        done = subprocess.run(
            [ZSH, "-n", str(HOOKS / "sage.zsh")], capture_output=True, check=False
        )
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_declines_without_terminal_and_keeps_127(self) -> None:
        assert ZSH is not None
        script = f'source "{HOOKS / "sage.zsh"}"\nfind_all the big files\necho "rc=$?"\n'
        done = subprocess.run(
            [ZSH, "-f", "-c", script], stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=20, check=False,
        )  # fmt: skip
        self.assertIn("rc=127", done.stdout)
        self.assertIn("command not found", done.stderr)


if __name__ == "__main__":
    unittest.main()
