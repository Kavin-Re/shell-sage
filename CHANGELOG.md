# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-19

A ground-up rewrite. The single 60-line script became an installable package
with a real safety model. Upgrading from 0.x: see "Migrating" at the end.

### Added

- **Risk engine** (`shellsage.risk`): a quote- and substitution-aware lexer plus
  rule-based classifier with three levels (`SAFE`, `CAUTION`, `DANGER`) and a
  human-readable reason for every finding. Sees through `sudo`, `env`, `xargs`,
  `sh -c`, `eval`, `$(...)`, backticks, `find -exec`, `ssh host cmd`, quoting
  tricks and brace expansion. Covers recursive deletes of `/`, `~` and system
  directories, raw-device writes, disk formatting, recursive permission
  changes, fork bombs, `curl | sh` and download-then-execute, reverse shells,
  base64-decode-to-shell and more.
- **Execution policy**: `DANGER` commands are never executed (copy only) unless
  `allow_danger = true` is set in the config file *and* a phrase is typed.
  `--yes` is honoured for `SAFE` commands only. The model's own risk label can
  raise the level but never lower it.
- **Interactive flow**: command, explanation and risk are shown, then
  `[r]un / [e]dit / [c]opy / e[x]plain / [q]uit`. Edited commands are re-graded.
- `sage --explain "<command>"`: explain an existing command.
- `sage --check "<command>"`: offline risk grading with exit status 0/10/20;
  no model needed.
- `sage doctor`: checks the Ollama server, the model, privacy-relevant settings.
- `sage config`, `sage shell-init bash|zsh`, `--dry-run`, `--json`,
  `--show-prompt`, `--history N` / `--no-history`, `--model`, `--host`,
  `--timeout`, `--color`.
- Structured output: the model is asked for JSON (`format: "json"`) with
  `command`, `explanation` and `risk`; replies that ignore the contract are
  still parsed (embedded JSON, code fences, first line) and flagged.
- Configuration file (`~/.config/shellsage/config.toml`) and `SHELLSAGE_*`
  environment variables, with validation and clear error messages.
- Context: OS/distribution, shell and a check of which common tools are
  installed, so the model does not suggest `rg` on a machine that only has `grep`.
- Secret redaction for shell history (tokens, passwords, AWS keys, JWTs,
  credentials in URLs, private keys, custom regexes).
- Colour output that respects `NO_COLOR`, `TERM=dumb` and non-TTY streams;
  control characters in model output are made visible instead of being sent to
  the terminal.
- Packaging (`pyproject.toml`, console script `sage`), `install.sh`, MIT
  license, CI (ruff, mypy --strict, unit tests on Python 3.10-3.13).
- 190+ unit tests using only the standard library, including an in-process
  fake Ollama server and tests that run the bash hook in a real bash.

### Changed

- HTTP now uses `urllib` from the standard library; the `requests` dependency
  is gone. There are **no runtime dependencies** on Python 3.11+.
- Shell history is **opt-in** (it was always sent before) and is redacted.
- The user name is no longer sent to the model; the working directory is sent
  with the home prefix shortened to `~`.
- Default request timeout is 60 s instead of 10 s (the first request has to
  load the model).
- The shell hook only reacts to inputs of three or more words in an interactive
  terminal, asks before sending anything, keeps any pre-existing
  `command_not_found_handle`, and always returns 127.
- Minimum Python is 3.10 (the README previously said 3.12+).

### Fixed

- The substring "safety filter" flagged `rm` inside `format`/`firmware`, `dd`
  inside `add` and any `>` inside quotes, while missing `chmod -R 777 /`,
  `curl | sh`, fork bombs and writes to `/dev/sda`. Replaced by the risk engine.
- A flagged command was hidden behind a warning with no way to act on it; a
  non-flagged command was printed with no explanation. Both now get the same
  card and menu.
- `os.getlogin()` crashed when there was no controlling terminal (cron, CI,
  containers, some terminal emulators).
- Every failure was reported as "Ollama is offline" (bare `except`), including
  JSON errors and timeouts. Errors are now specific.
- The hook returned exit status 0 for a command that did not exist, which broke
  `$?`, `set -e` and `||` chains, and sent every typo to the model.
- Only the first line of the model reply was used and all backticks were
  deleted, which corrupted commands that legitimately contain backticks.
- README: the Ollama install line contained a pasted Markdown link inside the
  code block and could not be copied and run.

### Migrating from 0.x

- `python3 ~/shell-sage/src/main.py ...` still works: `src/main.py` is now a
  thin launcher for the package. Prefer `pip install .` and the `sage` command.
- Replace the old `command_not_found_handle` snippet in `~/.bashrc` with
  `eval "$(sage shell-init bash)"`.
- If you relied on history being sent, set `history_lines` in the config file
  or pass `--history N`.

## [0.1.0]

Initial single-file script (`src/main.py`): prompt Ollama with the working
directory, user name and the last five history lines; print the first line of
the reply.

[1.0.0]: https://github.com/Kavin-Re/shell-sage/releases/tag/v1.0.0
