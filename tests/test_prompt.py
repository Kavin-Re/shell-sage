"""Prompt building and reply parsing (including every fallback path)."""

from __future__ import annotations

import unittest

from shellsage.context import Context
from shellsage.prompt import (
    SYSTEM_PROMPT,
    build_explain_prompt,
    build_prompt,
    clean_text,
    parse_explanation,
    parse_suggestion,
)
from shellsage.risk import Risk

ESC = chr(27)
CONTEXT = Context(
    cwd="~/projects/demo",
    os_name="Linux (Ubuntu 24.04 LTS)",
    shell="bash",
    is_root=False,
    tools=("git", "jq"),
    history=("git status", "export TOKEN=[REDACTED]"),
)


class ParseSuggestionTests(unittest.TestCase):
    def test_strict_json(self) -> None:
        s = parse_suggestion('{"command": "ls -la", "explanation": "Lists files.", "risk": "safe"}')
        self.assertEqual(s.command, "ls -la")
        self.assertEqual(s.explanation, "Lists files.")
        self.assertIs(s.model_risk, Risk.SAFE)
        self.assertTrue(s.structured)

    def test_json_with_whitespace_and_key_case(self) -> None:
        s = parse_suggestion('\n  {"Command": "pwd", "Explanation": "x", "RISK": "Caution"}\n')
        self.assertEqual(s.command, "pwd")
        self.assertIs(s.model_risk, Risk.CAUTION)

    def test_json_wrapped_in_prose(self) -> None:
        s = parse_suggestion(
            'Sure! Here you go:\n{"command": "df -h", "explanation": "Disk."}\nBye'
        )
        self.assertEqual(s.command, "df -h")
        self.assertIsNone(s.model_risk)
        self.assertTrue(s.structured)

    def test_json_inside_code_fence(self) -> None:
        raw = 'Here:\n```json\n{"command": "uptime", "explanation": "Load.", "risk": "safe"}\n```'
        self.assertEqual(parse_suggestion(raw).command, "uptime")

    def test_json_with_braces_inside_strings(self) -> None:
        raw = '{"command": "awk \'{print $1}\' f | sort", "explanation": "uses {braces}"}'
        self.assertEqual(parse_suggestion(raw).command, "awk '{print $1}' f | sort")

    def test_alternative_keys(self) -> None:
        self.assertEqual(parse_suggestion('{"cmd": "whoami"}').command, "whoami")
        self.assertEqual(parse_suggestion('{"bash": "id", "description": "d"}').explanation, "d")

    def test_command_given_as_list(self) -> None:
        s = parse_suggestion('{"command": ["cd /tmp", "ls"], "explanation": "x"}')
        self.assertEqual(s.command, "cd /tmp && ls")

    def test_command_wrapped_in_backticks_or_prompt(self) -> None:
        self.assertEqual(parse_suggestion('{"command": "`ls -la`"}').command, "ls -la")
        self.assertEqual(parse_suggestion('{"command": "$ ls -la"}').command, "ls -la")
        self.assertEqual(
            parse_suggestion('{"command": "```bash\\nls -la\\n```"}').command, "ls -la"
        )

    def test_variable_at_start_is_not_mistaken_for_prompt(self) -> None:
        self.assertEqual(
            parse_suggestion('{"command": "$EDITOR notes.md"}').command, "$EDITOR notes.md"
        )

    def test_empty_command_is_preserved(self) -> None:
        s = parse_suggestion('{"command": "", "explanation": "Which directory do you mean?"}')
        self.assertEqual(s.command, "")
        self.assertEqual(s.explanation, "Which directory do you mean?")

    def test_wrong_types_do_not_crash(self) -> None:
        for raw in [
            '{"command": 5}',
            '{"command": null}',
            '{"command": {"a": 1}}',
            "[]",
            "42",
            '"x"',
        ]:
            with self.subTest(raw=raw):
                parse_suggestion(raw)

    def test_unknown_risk_label_is_ignored(self) -> None:
        self.assertIsNone(parse_suggestion('{"command": "ls", "risk": "spicy"}').model_risk)
        self.assertIsNone(parse_suggestion('{"command": "ls", "risk": 7}').model_risk)

    def test_fallback_code_fence(self) -> None:
        s = parse_suggestion("You can use:\n```bash\nfind . -size +50M\n```\nHope that helps")
        self.assertEqual(s.command, "find . -size +50M")
        self.assertFalse(s.structured)
        self.assertIsNone(s.model_risk)

    def test_fallback_inline_code(self) -> None:
        self.assertEqual(parse_suggestion("Run `du -sh .` to see it.").command, "du -sh .")

    def test_fallback_first_line(self) -> None:
        s = parse_suggestion("\n\n  ls -la /var/log  \nthis lists logs")
        self.assertEqual(s.command, "ls -la /var/log")
        self.assertFalse(s.structured)

    def test_fallback_truncated_json(self) -> None:
        s = parse_suggestion('{"command": "ls -la", "explan')
        self.assertFalse(s.structured)  # scraped, and flagged as such to the user

    def test_empty_reply(self) -> None:
        s = parse_suggestion("")
        self.assertEqual(s.command, "")
        self.assertFalse(s.structured)

    def test_explanation_is_stripped_of_escape_sequences(self) -> None:
        raw = '{"command": "ls", "explanation": "ok ' + "\\u001b[2J\\u001b[31mowned" + '"}'
        self.assertEqual(parse_suggestion(raw).explanation, "ok owned")

    def test_command_control_characters_are_kept_for_the_risk_engine(self) -> None:
        raw = '{"command": "ls ' + "\\u001b[2K" + '"}'
        self.assertIn(ESC, parse_suggestion(raw).command)

    def test_multiline_command_is_kept(self) -> None:
        s = parse_suggestion('{"command": "ls\\nrm -rf /"}')
        self.assertEqual(s.command, "ls\nrm -rf /")

    def test_backslash_continuation_is_joined(self) -> None:
        s = parse_suggestion('{"command": "docker run \\\\\\n  -it ubuntu"}')
        self.assertEqual(s.command, "docker run -it ubuntu")


class ParseExplanationTests(unittest.TestCase):
    def test_structured(self) -> None:
        raw = (
            '{"summary": "Extracts an archive.", "breakdown": [{"part": "tar", "meaning": "archiver"},'
            ' {"part": "-x", "meaning": "extract"}, {"bad": 1}, "junk"], "warnings": ["overwrites files"]}'
        )
        e = parse_explanation(raw)
        self.assertEqual(e.summary, "Extracts an archive.")
        self.assertEqual(e.breakdown, (("tar", "archiver"), ("-x", "extract")))
        self.assertEqual(e.warnings, ("overwrites files",))
        self.assertTrue(e.structured)

    def test_warning_as_string_and_missing_fields(self) -> None:
        e = parse_explanation('{"warnings": "careful"}')
        self.assertEqual(e.warnings, ("careful",))
        self.assertEqual(e.summary, "")
        self.assertEqual(e.breakdown, ())

    def test_free_text_fallback(self) -> None:
        e = parse_explanation("It lists files.")
        self.assertEqual(e.summary, "It lists files.")
        self.assertFalse(e.structured)


class BuildPromptTests(unittest.TestCase):
    def test_contains_context_and_task(self) -> None:
        prompt = build_prompt("  show disk usage ", CONTEXT)
        for needle in ["os: Linux (Ubuntu 24.04 LTS)", "shell: bash", "cwd: ~/projects/demo",
                       "available_tools: git, jq", "running_as_root: no",
                       "<task>\nshow disk usage\n</task>"]:  # fmt: skip
            self.assertIn(needle, prompt)

    def test_history_block_only_when_present(self) -> None:
        with_history = build_prompt("x", CONTEXT)
        self.assertIn("<history>\ngit status\nexport TOKEN=[REDACTED]\n</history>", with_history)
        bare = Context("~", "Linux", "zsh", False, ())
        without = build_prompt("x", bare)
        self.assertNotIn("<history>", without)
        self.assertIn("(coreutils only)", without)

    def test_no_username_or_hostname_fields(self) -> None:
        prompt = build_prompt("x", CONTEXT)
        self.assertNotIn("user:", prompt)
        self.assertNotIn("host:", prompt)

    def test_explain_prompt(self) -> None:
        prompt = build_explain_prompt("tar -xzf a.tgz", CONTEXT)
        self.assertIn("<command>\ntar -xzf a.tgz\n</command>", prompt)
        self.assertNotIn("<history>", prompt)

    def test_system_prompt_states_the_contract(self) -> None:
        for needle in ['"command"', '"explanation"', '"risk"', "untrusted"]:
            self.assertIn(needle, SYSTEM_PROMPT)

    def test_clean_text(self) -> None:
        self.assertEqual(clean_text(f" a{ESC}[31mb{ESC}[0m{chr(7)} "), "ab")


if __name__ == "__main__":
    unittest.main()
