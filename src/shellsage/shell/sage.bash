# ShellSage hook for bash.  Load it with:   eval "$(sage shell-init bash)"
#
# When you type a sentence that is not a command, bash calls
# command_not_found_handle. This hook offers to hand the sentence to `sage`.
#
# Guard rails (all of them are deliberate):
#   * only fires for inputs of SHELLSAGE_HOOK_MIN_WORDS words or more (default 3),
#     so ordinary typos like `gti status` never reach the model;
#   * only fires in an interactive terminal (never in scripts, pipes or subshells
#     without a tty);
#   * asks before sending anything unless SHELLSAGE_HOOK_CONFIRM=0;
#   * always returns 127, so `$?`, `set -e`, `||` and prompts that show the exit
#     status keep their normal "command not found" meaning;
#   * a handler that already existed (e.g. Ubuntu's command-not-found package
#     suggestions) is preserved and used for everything this hook declines.

if [ -n "${BASH_VERSION:-}" ]; then

if declare -F command_not_found_handle >/dev/null \
    && ! declare -F _shellsage_orig_cnf_handle >/dev/null \
    && [[ "$(declare -f command_not_found_handle)" != *_shellsage_decline* ]]; then
    eval "_shellsage_orig_cnf_handle() $(declare -f command_not_found_handle | tail -n +2)"
fi

_shellsage_decline() {
    if declare -F _shellsage_orig_cnf_handle >/dev/null; then
        _shellsage_orig_cnf_handle "$@"
        return $?
    fi
    printf '%s: %s: command not found\n' "${0##*/}" "$1" >&2
    return 127
}

command_not_found_handle() {
    if [[ $# -lt ${SHELLSAGE_HOOK_MIN_WORDS:-3} || ! -t 0 || ! -t 2 ]] \
        || ! command -v sage >/dev/null 2>&1; then
        _shellsage_decline "$@"
        return $?
    fi
    if [[ "${SHELLSAGE_HOOK_CONFIRM:-1}" != 0 ]]; then
        local reply
        printf 'sage: "%s" is not a command. Ask ShellSage? [y/N] ' "$1" >&2
        read -r reply
        if [[ "$reply" != [yY]* ]]; then
            return 127
        fi
    fi
    sage -- "$@"
    return 127
}

fi
