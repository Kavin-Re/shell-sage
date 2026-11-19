# Contributing to shell-sage

Thanks for your interest. shell-sage (`sage`): CLI that turns natural language into bash via a local Ollama model, with a risk gate.

## Getting started

Python 3.10+ and a local Ollama server for real use. The tests need neither.

```
python3 -m pip install -e ".[dev]"      # ruff + mypy
```

## Testing

```
python3 -m unittest discover -s tests -t .      # standard library only, no install needed
ruff check . && ruff format --check . && mypy   # mypy runs in strict mode
```

CI runs these on Python 3.10 to 3.13, with zsh installed so the zsh hook tests run, plus shell-syntax checks and a smoke test of the installed `sage` command.

## Pull requests

- Open an issue first for larger changes.
- Keep PRs focused and fill in the pull request template.
- Follow `.editorconfig` and match the style of surrounding code.

## Conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
