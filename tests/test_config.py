"""Configuration loading, precedence and validation."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from shellsage.config import (
    DEFAULT_HOST,
    DEFAULT_MODEL,
    ConfigError,
    config_path,
    load_config,
    normalize_host,
)

FULL = """
[ollama]
model = "llama3.2:3b"
host = "localhost:11434/"
timeout = 90
temperature = 0.3

[context]
history_lines = 8
history_file = "~/.my_history"
redact_patterns = ["corp-[0-9]+"]
shell = "zsh"

[ui]
color = "never"

[safety]
allow_danger = true
"""


class ConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def write(self, text: str) -> dict[str, str]:
        path = self.dir / "config.toml"
        path.write_text(text, encoding="utf-8")
        return {"SHELLSAGE_CONFIG": str(path), "HOME": str(self.dir)}

    def test_defaults(self) -> None:
        config = load_config({"HOME": str(self.dir)})
        self.assertEqual(config.model, DEFAULT_MODEL)
        self.assertEqual(config.host, DEFAULT_HOST)
        self.assertEqual(config.history_lines, 0, "history must be opt-in")
        self.assertFalse(config.allow_danger)
        self.assertEqual(config.source, "")
        self.assertTrue(config.host_is_local)

    def test_path_resolution(self) -> None:
        self.assertEqual(config_path({"HOME": "/h"}), Path("/h/.config/shellsage/config.toml"))
        self.assertEqual(
            config_path({"HOME": "/h", "XDG_CONFIG_HOME": "/x"}), Path("/x/shellsage/config.toml")
        )
        self.assertEqual(config_path({"SHELLSAGE_CONFIG": "/c.toml"}), Path("/c.toml"))

    def test_xdg_file_is_found(self) -> None:
        target = self.dir / "xdg" / "shellsage"
        target.mkdir(parents=True)
        (target / "config.toml").write_text('[ollama]\nmodel = "m:1"\n', encoding="utf-8")
        config = load_config({"HOME": str(self.dir), "XDG_CONFIG_HOME": str(self.dir / "xdg")})
        self.assertEqual(config.model, "m:1")
        self.assertTrue(config.source.endswith("config.toml"))

    def test_full_file(self) -> None:
        config = load_config(self.write(FULL))
        self.assertEqual(config.model, "llama3.2:3b")
        self.assertEqual(config.host, "http://localhost:11434")
        self.assertEqual(config.timeout, 90.0)
        self.assertEqual(config.temperature, 0.3)
        self.assertEqual(config.history_lines, 8)
        self.assertEqual(config.history_file, "~/.my_history")
        self.assertEqual(config.redact_patterns, ("corp-[0-9]+",))
        self.assertEqual(config.shell, "zsh")
        self.assertEqual(config.color, "never")
        self.assertTrue(config.allow_danger)

    def test_precedence_file_env_cli(self) -> None:
        env = self.write('[ollama]\nmodel = "from-file"\ntimeout = 10\n')
        self.assertEqual(load_config(env).model, "from-file")
        env["SHELLSAGE_MODEL"] = "from-env"
        env["SHELLSAGE_TIMEOUT"] = "20"
        config = load_config(env)
        self.assertEqual((config.model, config.timeout), ("from-env", 20.0))
        config = load_config(env, {"model": "from-cli", "timeout": None})
        self.assertEqual((config.model, config.timeout), ("from-cli", 20.0))

    def test_env_variables(self) -> None:
        env = {
            "HOME": str(self.dir),
            "SHELLSAGE_HOST": "http://10.0.0.5:11434",
            "SHELLSAGE_HISTORY_LINES": "5",
            "SHELLSAGE_COLOR": "always",
            "SHELLSAGE_SHELL": "zsh",
            "SHELLSAGE_TEMPERATURE": "0",
        }
        config = load_config(env)
        self.assertEqual(config.host, "http://10.0.0.5:11434")
        self.assertFalse(config.host_is_local)
        self.assertEqual(config.history_lines, 5)
        self.assertEqual(config.color, "always")
        self.assertEqual(config.temperature, 0.0)

    def test_empty_env_value_is_ignored(self) -> None:
        self.assertEqual(
            load_config({"HOME": str(self.dir), "SHELLSAGE_MODEL": ""}).model, DEFAULT_MODEL
        )

    def test_allow_danger_cannot_be_set_from_environment(self) -> None:
        config = load_config({"HOME": str(self.dir), "SHELLSAGE_ALLOW_DANGER": "1"})
        self.assertFalse(config.allow_danger)

    def test_unknown_keys_warn_but_load(self) -> None:
        config = load_config(self.write('stray = 1\n[ollama]\nmodle = "typo"\n[nope]\nx = 1\n'))
        self.assertEqual(config.model, DEFAULT_MODEL)
        self.assertEqual(len(config.warnings), 3)
        self.assertTrue(any("modle" in w for w in config.warnings))

    def test_invalid_values(self) -> None:
        bad = [
            "[ollama]\nmodel = 5\n",
            '[ollama]\nmodel = "  "\n',
            '[ollama]\ntimeout = "soon"\n',
            "[ollama]\ntimeout = 0\n",
            "[ollama]\ntimeout = true\n",
            "[ollama]\ntemperature = 9\n",
            '[ollama]\nhost = "ftp://example.com"\n',
            '[ollama]\nhost = "file:///etc/passwd"\n',
            '[ollama]\nhost = "http://user:pw@example.com"\n',
            '[ollama]\nhost = ""\n',
            "[context]\nhistory_lines = -1\n",
            "[context]\nhistory_lines = 5000\n",
            "[context]\nhistory_lines = 2.5\n",
            '[context]\nredact_patterns = "notalist"\n',
            "[context]\nredact_patterns = [1, 2]\n",
            '[context]\nredact_patterns = ["(unclosed"]\n',
            '[ui]\ncolor = "rainbow"\n',
            '[safety]\nallow_danger = "yes"\n',
            "[safety]\nallow_danger = 1\n",
            "this is = not [valid toml\n",
        ]
        for text in bad:
            with self.subTest(text=text), self.assertRaises(ConfigError):
                load_config(self.write(text))

    def test_invalid_env_values(self) -> None:
        for name, value in [("SHELLSAGE_TIMEOUT", "fast"), ("SHELLSAGE_HISTORY_LINES", "many"),
                            ("SHELLSAGE_COLOR", "blue"), ("SHELLSAGE_HOST", "gopher://x")]:  # fmt: skip
            with self.subTest(name=name), self.assertRaises(ConfigError):
                load_config({"HOME": str(self.dir), name: value})

    def test_missing_explicit_file_is_an_error(self) -> None:
        with self.assertRaises(ConfigError):
            load_config({"SHELLSAGE_CONFIG": str(self.dir / "nope.toml")})

    def test_error_message_names_the_setting(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            load_config(self.write('[ollama]\ntimeout = "soon"\n'))
        self.assertIn("[ollama] timeout", str(caught.exception))

    def test_normalize_host(self) -> None:
        self.assertEqual(normalize_host("127.0.0.1:11434"), "http://127.0.0.1:11434")
        self.assertEqual(normalize_host("https://ollama.lan/"), "https://ollama.lan")
        self.assertEqual(normalize_host(" http://[::1]:11434 "), "http://[::1]:11434")

    def test_example_config_in_repo_is_valid(self) -> None:
        example = Path(__file__).resolve().parent.parent / "config.example.toml"
        config = load_config({"SHELLSAGE_CONFIG": str(example)})
        self.assertEqual(config.warnings, ())
        self.assertEqual(config.model, DEFAULT_MODEL)
        self.assertEqual(config.history_lines, 0)
        self.assertFalse(config.allow_danger)


if __name__ == "__main__":
    unittest.main()
