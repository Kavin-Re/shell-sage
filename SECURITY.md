# Security policy

ShellSage puts a deterministic risk engine between a language model and your
shell. If that engine can be fooled, that is a security bug and I want to know.

## What counts

- **Risk-engine bypass**: a command that can destroy data, a disk or a system,
  or that executes code fetched from the network, yet is graded `SAFE`
  (or `CAUTION` when it clearly belongs in `DANGER`).
- **Policy bypass**: any way to make `sage --yes`, the shell hook or the
  interactive menu execute a `DANGER` command without `allow_danger = true`
  and the typed confirmation.
- **Redaction miss** for a common credential format in shell history.
- **Terminal injection**: model output that reaches the terminal with live
  escape sequences.

The documented limits in the README ("What the engine does not catch") are
known; improvements are still welcome as normal issues or pull requests.

## Reporting

Please open a private report through GitHub: *Security* tab -> *Report a
vulnerability* on <https://github.com/Kavin-Re/shell-sage>. If private reporting
is not enabled on the repository, open a normal issue that says only "security
report, please enable private reporting" and do not include details.

Include the exact command line, the output of `sage --check '<command>' --json`
and your `sage --version`.

## Supported versions

Only the latest release receives fixes.
