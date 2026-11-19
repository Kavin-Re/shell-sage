"""Presentation helpers."""

from __future__ import annotations

import io
import shutil
import unittest
from unittest import mock

from shellsage.prompt import Explanation
from shellsage.risk import Finding, Risk
from shellsage.ui import (
    Style,
    color_enabled,
    copy_to_clipboard,
    render_card,
    render_explanation,
    visible,
)

ESC = chr(27)


class Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


class ColorTests(unittest.TestCase):
    def test_auto_on_tty(self) -> None:
        self.assertTrue(color_enabled("auto", Tty(), {"TERM": "xterm-256color"}))

    def test_auto_off_when_not_a_tty(self) -> None:
        self.assertFalse(color_enabled("auto", io.StringIO(), {"TERM": "xterm"}))

    def test_no_color_is_respected(self) -> None:
        self.assertFalse(color_enabled("auto", Tty(), {"NO_COLOR": "1"}))
        self.assertTrue(color_enabled("auto", Tty(), {"NO_COLOR": ""}), "empty NO_COLOR is unset")

    def test_dumb_terminal(self) -> None:
        self.assertFalse(color_enabled("auto", Tty(), {"TERM": "dumb"}))

    def test_explicit_modes(self) -> None:
        self.assertTrue(color_enabled("always", io.StringIO(), {"NO_COLOR": "1"}))
        self.assertFalse(color_enabled("never", Tty(), {}))

    def test_style(self) -> None:
        self.assertEqual(Style(False).paint("x", "red", "bold"), "x")
        self.assertEqual(Style(True).paint("x", "red"), f"{ESC}[31mx{ESC}[0m")
        self.assertEqual(Style(True).paint("x"), "x")
        self.assertIn("DANGER", Style(True).risk(Risk.DANGER))


class RenderTests(unittest.TestCase):
    def test_visible_escapes_control_and_invisible_characters(self) -> None:
        self.assertEqual(visible(f"ls {ESC}[2K"), "ls \\x1b[2K")
        self.assertEqual(visible("a" + chr(0x202E) + "b"), "a\\u202eb")
        self.assertEqual(visible("plain | text\n"), "plain | text\n")

    def test_card_without_findings(self) -> None:
        card = render_card("ls -la", "Lists files.", Risk.SAFE, (), Style(False))
        self.assertIn("$ ls -la", card)
        self.assertIn("Lists files.", card)
        self.assertIn("risk: SAFE (no risk rule matched)", card)
        self.assertNotIn(ESC, card)

    def test_card_with_findings_and_notes(self) -> None:
        findings = (Finding(Risk.DANGER, "disk", "overwrites the disk"),)
        card = render_card(
            "dd of=/dev/sda", "", Risk.DANGER, findings, Style(False), ["fd missing"]
        )
        self.assertIn("risk: DANGER", card)
        self.assertIn("! overwrites the disk [disk]", card)
        self.assertIn("note: fd missing", card)

    def test_card_never_emits_raw_escape_from_command(self) -> None:
        card = render_card(f"ls {ESC}[2J", "", Risk.CAUTION, (), Style(False))
        self.assertNotIn(ESC, card)

    def test_multiline_command(self) -> None:
        card = render_card("ls\npwd", "", Risk.SAFE, (), Style(False))
        self.assertIn("$ ls\n    pwd", card)

    def test_explanation(self) -> None:
        text = render_explanation(
            Explanation(
                "Does a thing.", (("tar", "archiver"), ("-x", "extract")), ("careful",), True
            ),
            Style(False),
        )
        self.assertIn("Does a thing.", text)
        self.assertIn("tar  archiver", text)
        self.assertIn("-x   extract", text)
        self.assertIn("model warning: careful", text)


class ClipboardTests(unittest.TestCase):
    def test_no_tool_available(self) -> None:
        self.assertIsNone(copy_to_clipboard("x", {}, which=lambda name: None))

    def test_uses_first_working_tool(self) -> None:
        # `true` accepts any stdin and exits 0; pretend it is pbcopy.
        true_path = shutil.which("true")
        if true_path is None:
            self.skipTest("no `true` binary")
        with mock.patch("shellsage.ui._clipboard_commands", return_value=[["true"]]):
            self.assertEqual(copy_to_clipboard("x", {}), "true")


if __name__ == "__main__":
    unittest.main()
