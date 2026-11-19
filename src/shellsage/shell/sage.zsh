# ShellSage hook for zsh.  Load it with:   eval "$(sage shell-init zsh)"
#
# Same contract as the bash hook: multi-word input only (default: 3+ words),
# interactive terminals only, asks before sending (SHELLSAGE_HOOK_CONFIRM=0 to
# skip), always returns 127, and chains to any handler that was already defined.

if [ -n "${ZSH_VERSION:-}" ]; then

if (( ${+functions[command_not_found_handler]} )) \
    && (( ! ${+functions[_shellsage_orig_cnf_handler]} )) \
    && [[ "${functions[command_not_found_handler]}" != *_shellsage_decline* ]]; then
    functions[_shellsage_orig_cnf_handler]="${functions[command_not_found_handler]}"
fi

_shellsage_decline() {
    if (( ${+functions[_shellsage_orig_cnf_handler]} )); then
        _shellsage_orig_cnf_handler "$@"
        return $?
    fi
    print -u2 -r -- "zsh: command not found: $1"
    return 127
}

command_not_found_handler() {
    if (( $# < ${SHELLSAGE_HOOK_MIN_WORDS:-3} )) || [[ ! -t 0 || ! -t 2 ]] \
        || (( ! ${+commands[sage]} )); then
        _shellsage_decline "$@"
        return $?
    fi
    if [[ "${SHELLSAGE_HOOK_CONFIRM:-1}" != 0 ]]; then
        local reply
        print -u2 -n -r -- "sage: \"$1\" is not a command. Ask ShellSage? [y/N] "
        read -r reply
        if [[ "$reply" != [yY]* ]]; then
            return 127
        fi
    fi
    sage -- "$@"
    return 127
}

fi
