#!/usr/bin/env sh
# ShellSage installer. Run from a clone of the repository:
#
#   ./install.sh            install the `sage` command (pipx if available, else pip --user)
#   ./install.sh --hook     ...and add the shell hook to ~/.bashrc or ~/.zshrc
#   ./install.sh --dry-run  print what would be done, change nothing
#
# The script never uses sudo and never downloads or pipes anything into a shell.

set -eu

HOOK=0
DRY=0
for arg in "$@"; do
    case "$arg" in
        --hook) HOOK=1 ;;
        --dry-run) DRY=1 ;;
        -h | --help)
            sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "install.sh: unknown option: $arg" >&2
            exit 2
            ;;
    esac
done

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

run() {
    echo "+ $*"
    if [ "$DRY" -eq 0 ]; then
        "$@"
    fi
}

if ! command -v python3 >/dev/null 2>&1; then
    echo "install.sh: python3 not found (ShellSage needs Python 3.10 or newer)" >&2
    exit 1
fi
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
    echo "install.sh: Python 3.10 or newer is required, found: $(python3 --version 2>&1)" >&2
    exit 1
fi

if command -v pipx >/dev/null 2>&1; then
    run pipx install --force "$HERE"
else
    echo "pipx not found; falling back to: pip install --user"
    echo "(on distributions with an externally managed Python, install pipx first)"
    run python3 -m pip install --user "$HERE"
fi

if [ "$HOOK" -eq 1 ]; then
    case "${SHELL:-}" in
        */zsh) RC="$HOME/.zshrc"; NAME=zsh ;;
        *) RC="$HOME/.bashrc"; NAME=bash ;;
    esac
    LINE="command -v sage >/dev/null 2>&1 && eval \"\$(sage shell-init $NAME)\"  # ShellSage hook"
    if [ -f "$RC" ] && grep -q 'sage shell-init' "$RC"; then
        echo "hook already present in $RC"
    else
        echo "+ append ShellSage hook to $RC"
        if [ "$DRY" -eq 0 ]; then
            printf '\n%s\n' "$LINE" >>"$RC"
        fi
    fi
fi

cat <<'NEXT'

Done. Next steps:
  1. Install Ollama (https://ollama.com/download) and start it:   ollama serve
  2. Pull the default model:                                       ollama pull qwen2.5-coder:3b
  3. Check your setup:                                             sage doctor
  4. Try it:                                                       sage "show the ten largest files here"

If `sage` is not found, add ~/.local/bin to your PATH.
NEXT
