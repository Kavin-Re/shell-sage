"""Deterministic, rule-based risk classifier for shell commands.

The classifier never asks the model anything. It lexes the command line into
words and operators (quote- and substitution-aware), unquotes each word with
:mod:`shlex`, resolves wrappers such as ``sudo``/``env``/``xargs``/``sh -c`` and
then applies per-program rules.

Levels
------
``SAFE``     no rule matched (this is *not* a proof of harmlessness)
``CAUTION``  changes state, needs privileges or cannot be fully inspected
``DANGER``   can destroy a system, a disk or a home directory, or runs
             code fetched from the network

Known limits are documented in the README ("Safety model").
"""

from __future__ import annotations

import enum
import posixpath
import re
import shlex
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

__all__ = ["Assessment", "Finding", "LexError", "Risk", "Token", "classify", "lex"]


class Risk(enum.IntEnum):
    """Ordered risk level; higher is worse."""

    SAFE = 0
    CAUTION = 1
    DANGER = 2

    @property
    def label(self) -> str:
        return self.name

    @classmethod
    def parse(cls, value: object) -> Risk | None:
        """Map a free-form label (e.g. from the model) to a level, if possible."""
        if not isinstance(value, str):
            return None
        key = value.strip().lower()
        aliases = {
            "safe": cls.SAFE,
            "low": cls.SAFE,
            "none": cls.SAFE,
            "caution": cls.CAUTION,
            "medium": cls.CAUTION,
            "moderate": cls.CAUTION,
            "warning": cls.CAUTION,
            "danger": cls.DANGER,
            "dangerous": cls.DANGER,
            "high": cls.DANGER,
            "critical": cls.DANGER,
        }
        return aliases.get(key)


@dataclass(frozen=True)
class Finding:
    """One matched rule."""

    level: Risk
    category: str
    reason: str


@dataclass(frozen=True)
class Assessment:
    """Result of :func:`classify`."""

    command: str
    level: Risk
    findings: tuple[Finding, ...]
    programs: tuple[str, ...]

    @property
    def reasons(self) -> tuple[str, ...]:
        return tuple(f.reason for f in self.findings)

    @property
    def categories(self) -> frozenset[str]:
        return frozenset(f.category for f in self.findings)


# --------------------------------------------------------------------------- #
# Lexer
# --------------------------------------------------------------------------- #


class LexError(ValueError):
    """The command line is not well formed (e.g. an unterminated quote)."""


@dataclass(frozen=True)
class Token:
    kind: str  # "word" or "op"
    text: str  # raw source text, quotes included


# Longest first so that max-munch works with a simple linear scan.
_OPERATORS = (
    "&>>", "<<<", "<<-",
    "&&", "||", ";;", "|&", ">>", "<<", ">&", "<&", "&>", ">|", "<>",
    "|", "&", ";", "(", ")", "<", ">",
)  # fmt: skip
_REDIRECT_OPS = frozenset({">", ">>", ">|", "&>", "&>>", "<>", "<", "<<", "<<<", "<<-", ">&", "<&"})
_OUTPUT_REDIRECTS = frozenset({">", ">>", ">|", "&>", "&>>", "<>", ">&"})
_PIPE_OPS = frozenset({"|", "|&"})
_FD_DUP = re.compile(r"[<>]&(\d+|-)")


def _match_paren(text: str, start: int) -> int:
    """Return the index of the ``)`` matching the ``(`` at ``start``."""
    depth = 0
    i = start
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            j = text.find("'", i + 1)
            if j < 0:
                raise LexError("unterminated single quote")
            i = j + 1
            continue
        if c == '"':
            i = _scan_dquote(text, i, None)
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise LexError("unbalanced parenthesis")


def _scan_backtick(text: str, start: int) -> int:
    """Return the index just past the closing backtick."""
    i = start + 1
    n = len(text)
    while i < n:
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == "`":
            return i + 1
        i += 1
    raise LexError("unterminated backtick")


def _scan_dquote(text: str, start: int, subs: list[str] | None) -> int:
    """Return the index just past the closing double quote.

    Command substitutions found inside the quotes are appended to ``subs``.
    """
    i = start + 1
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            return i + 1
        if c == "$" and text.startswith("(", i + 1):
            end = _match_paren(text, i + 1)
            if subs is not None and not text.startswith("((", i + 1):
                subs.append(text[i + 2 : end])
            i = end + 1
            continue
        if c == "`":
            end = _scan_backtick(text, i)
            if subs is not None:
                subs.append(text[i + 1 : end - 1])
            i = end
            continue
        i += 1
    raise LexError("unterminated double quote")


def lex(text: str) -> tuple[list[Token], list[str]]:
    """Split a command line into words and operators.

    Returns ``(tokens, substitutions)`` where ``substitutions`` holds the inner
    source of every ``$(...)``, backtick and ``<(...)``/``>(...)`` found, so the
    caller can analyse them recursively. Raises :class:`LexError` on malformed
    input.
    """
    tokens: list[Token] = []
    subs: list[str] = []
    buf: list[str] = []
    i = 0
    n = len(text)

    def flush() -> None:
        if buf:
            tokens.append(Token("word", "".join(buf)))
            buf.clear()

    while i < n:
        c = text[i]
        if c == "\\":
            if text.startswith("\n", i + 1):  # line continuation
                i += 2
                continue
            buf.append(text[i : i + 2])
            i += 2
            continue
        if c == "'":
            j = text.find("'", i + 1)
            if j < 0:
                raise LexError("unterminated single quote")
            buf.append(text[i : j + 1])
            i = j + 1
            continue
        if c == '"':
            j = _scan_dquote(text, i, subs)
            buf.append(text[i:j])
            i = j
            continue
        if c == "`":
            j = _scan_backtick(text, i)
            subs.append(text[i + 1 : j - 1])
            buf.append(text[i:j])
            i = j
            continue
        if c == "$" and text.startswith("(", i + 1):
            end = _match_paren(text, i + 1)
            if not text.startswith("((", i + 1):  # $((...)) is arithmetic, not a command
                subs.append(text[i + 2 : end])
            buf.append(text[i : end + 1])
            i = end + 1
            continue
        if c == "$" and text.startswith("{", i + 1):
            end = text.find("}", i + 2)
            if end < 0:
                raise LexError("unterminated ${")
            buf.append(text[i : end + 1])
            i = end + 1
            continue
        if c in "<>" and text.startswith("(", i + 1) and not buf:  # process substitution
            end = _match_paren(text, i + 1)
            subs.append(text[i + 2 : end])
            tokens.append(Token("word", text[i : end + 1]))
            i = end + 1
            continue
        if c in " \t\r":
            flush()
            i += 1
            continue
        if c == "\n":
            flush()
            tokens.append(Token("op", ";"))
            i += 1
            continue
        if c == "#" and not buf:
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        dup = _FD_DUP.match(text, i) if c in "<>" else None
        if dup:  # 2>&1, >&2, <&- : pure descriptor plumbing, nothing to analyse
            if "".join(buf).isdigit():
                buf.clear()
            flush()
            i = dup.end()
            continue
        op = next((o for o in _OPERATORS if text.startswith(o, i)), None)
        if op is not None:
            if op in _REDIRECT_OPS and "".join(buf).isdigit():
                buf.clear()  # "2>" - the digit is a file descriptor, not a word
            flush()
            tokens.append(Token("op", op))
            i += len(op)
            continue
        buf.append(c)
        i += 1
    flush()
    return tokens, subs


def _unquote(raw: str) -> str:
    """Remove one level of shell quoting from a single raw word."""
    try:
        parts = shlex.split(raw, posix=True)
    except ValueError:
        return raw.strip("'\"")
    return " ".join(parts)


# --------------------------------------------------------------------------- #
# Path classification
# --------------------------------------------------------------------------- #

_SYSTEM_DIRS = frozenset(
    {
        "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64", "/opt",
        "/proc", "/root", "/sbin", "/srv", "/sys", "/usr", "/var",
        "/usr/bin", "/usr/lib", "/usr/sbin", "/usr/local", "/usr/share", "/var/lib", "/var/log",
        "/Applications", "/Library", "/System", "/Users", "/Volumes", "/private",
    }
)  # fmt: skip
_SYSTEM_PREFIXES = ("/bin/", "/boot/", "/etc/", "/lib/", "/lib32/", "/lib64/", "/sbin/",
                    "/usr/", "/var/lib/", "/sys/", "/proc/", "/System/", "/Library/")  # fmt: skip
_CRITICAL_FILES = frozenset(
    {
        "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers",
        "/etc/fstab", "/etc/crypttab", "/etc/ssh/sshd_config",
        "/etc/pam.d", "/etc/sudoers.d", "/etc/ssh",
        "/proc/sysrq-trigger",
    }
)  # fmt: skip
_DEVICE = re.compile(
    r"^/dev/(sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\d|mmcblk\d|disk\d|rdisk\d|mapper/|md\d|"
    r"dm-\d|loop\d|sr\d|mtd|(mem|kmem|port)$)"
)
_HOME_PREFIXES = ("${HOME}", "$HOME", "~")
_STARTUP_FILES = re.compile(
    r"(^|/)(\.bashrc|\.bash_profile|\.bash_login|\.profile|\.zshrc|\.zshenv|\.zprofile|"
    r"\.ssh/authorized_keys|\.ssh/config)$"
)


def classify_path(path: str, home: str | None = None) -> str:
    """Bucket a path operand.

    One of ``root``, ``home``, ``system`` (a top-level system directory),
    ``critical`` (boot/auth files), ``device`` (raw block/memory device),
    ``under-system``, ``cwd``, ``parent``, ``variable`` or ``other``.
    """
    p = path.strip()
    if not p:
        return "other"
    in_home = False
    for prefix in _HOME_PREFIXES:
        if p == prefix or p.startswith(prefix + "/"):
            p = p[len(prefix) :] or "/"
            in_home = True
            break
    # Strip trailing "match everything" globs: "/*", "/.*", "/." and "/".
    while p != "/":
        for suffix in ("/*", "/.*", "/.", "/"):
            if p.endswith(suffix):
                p = p[: -len(suffix)] or "/"
                break
        else:
            break
    if in_home:
        return "home" if posixpath.normpath(p) == "/" else "other"
    if p.startswith("/"):
        q = posixpath.normpath(p)
        if q.startswith("//"):
            q = q[1:]
        if q == "/":
            return "root"
        if _DEVICE.match(q):
            return "device"
        if q in _CRITICAL_FILES or q.startswith("/boot/"):
            return "critical"
        if q in _SYSTEM_DIRS:
            return "system"
        if home and q == posixpath.normpath(home):
            return "home"
        if posixpath.dirname(q) in ("/home", "/Users"):
            return "home"
        if q.startswith(_SYSTEM_PREFIXES):
            return "under-system"
        return "other"
    if p in (".", "*", ".*"):
        return "cwd"
    if p == ".." or (p.startswith("../") and set(p) <= set("./")):
        return "parent"
    if p.startswith("$"):
        return "variable"
    return "other"


# --------------------------------------------------------------------------- #
# Rule tables
# --------------------------------------------------------------------------- #

_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "mksh", "fish", "ash"})
_INTERPRETERS = frozenset({"python", "python2", "python3", "perl", "ruby", "node", "php", "lua"})
_INLINE_CODE_FLAGS = {"python": "-c", "python2": "-c", "python3": "-c", "perl": "-e",
                      "ruby": "-e", "node": "-e", "php": "-r", "lua": "-e"}  # fmt: skip
_NET_FETCH = frozenset(
    {"curl", "wget", "fetch", "nc", "ncat", "netcat", "aria2c", "http", "https", "socat", "ftp",
     "tftp", "scp"}
)  # fmt: skip
_DECODERS = frozenset({"base64", "base32", "xxd", "openssl", "uudecode", "rev"})
_PRIVILEGE = frozenset({"sudo", "doas", "pkexec", "run0"})
_PLAIN_WRAPPERS = frozenset(
    {"nohup", "time", "command", "builtin", "exec", "setsid", "unbuffer", "busybox", "toybox",
     "caffeinate", "proot", "fakeroot"}
)  # fmt: skip
# Wrapper -> options that consume the following argument.
_OPTION_WRAPPERS: dict[str, frozenset[str]] = {
    "env": frozenset({"-u", "--unset", "-C", "--chdir", "-S", "--split-string"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "ionice": frozenset({"-c", "-n", "-p", "--class", "--classdata"}),
    "stdbuf": frozenset({"-i", "-o", "-e"}),
    "timeout": frozenset({"-s", "--signal", "-k", "--kill-after"}),
    "watch": frozenset({"-n", "--interval", "-d"}),
    "xargs": frozenset({"-I", "-n", "-P", "-d", "-L", "-s", "-E", "-a", "--max-args",
                        "--max-procs", "--delimiter", "--arg-file", "--replace"}),
    "strace": frozenset({"-o", "-e", "-p", "-s"}),
    "flock": frozenset({"-w", "--timeout", "-E"}),
}  # fmt: skip
_SUDO_ARG_OPTS = frozenset({"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t",
                            "--user", "--group", "--host", "--prompt", "--chdir"})  # fmt: skip
_SSH_ARG_OPTS = frozenset("-" + c for c in "bcDEeFIiJLlmOopQRSWw")
_KEYWORDS = frozenset({"if", "then", "else", "elif", "fi", "do", "done", "while", "until",
                       "!", "{", "}", "function"})  # fmt: skip
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+?=")

_DISK_FORMATTERS = frozenset({"mke2fs", "mkswap", "blkdiscard", "mkdosfs", "newfs", "pvcreate",
                              "vgremove", "lvremove", "zpool", "badblocks", "hdparm", "nvme",
                              "diskutil"})  # fmt: skip
_PARTITIONERS = frozenset({"fdisk", "sfdisk", "gdisk", "sgdisk", "cfdisk", "parted"})
_POWER = frozenset({"shutdown", "reboot", "halt", "poweroff", "init", "telinit"})
_PROC_KILLERS = frozenset({"kill", "killall", "pkill", "skill", "xkill", "fuser"})
_ACCOUNT = frozenset({"userdel", "deluser", "groupdel", "usermod", "passwd", "chpasswd",
                      "visudo", "useradd", "adduser", "gpasswd"})  # fmt: skip
_SYSTEM_STATE = frozenset({"mount", "umount", "swapoff", "swapon", "losetup", "modprobe",
                           "rmmod", "insmod", "sysctl", "setenforce", "update-grub",
                           "grub-install", "efibootmgr", "systemd-run", "chroot", "nsenter",
                           "timedatectl", "hostnamectl", "ldconfig"})  # fmt: skip
_PKG_MANAGERS = frozenset({"apt", "apt-get", "aptitude", "dnf", "yum", "zypper", "apk", "brew",
                           "snap", "flatpak", "pacman", "yay", "paru", "pip", "pip3", "pipx",
                           "npm", "gem", "cargo", "dpkg", "rpm"})  # fmt: skip
_PKG_REMOVE_VERBS = frozenset({"remove", "purge", "autoremove", "erase", "uninstall", "rm",
                               "del", "autopurge", "-r", "-P", "-e", "--purge", "--remove",
                               "--erase"})  # fmt: skip
_FORK_BOMBS = (
    # name(){ name|name& };name   - the classic ":(){ :|:& };:" and renamed variants
    re.compile(r"([A-Za-z_:.][\w:.]*)\s*\(\s*\)\s*\{[^}]*?\1\s*\|\s*\1\s*&"),
    re.compile(r"function\s+([A-Za-z_:.][\w:.]*)\s*(?:\(\s*\))?\s*\{[^}]*?\1\s*\|\s*\1\s*&"),
    # self-re-executing script: $0 & $0, or while true; do $0 & done
    re.compile(r"\$0\s*&\s*\$0|\$0\s*\|\s*\$0\s*&"),
)
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_INVISIBLE_CHARS = re.compile("[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")

_FIREWALL_EDIT_VERBS = (["add"], ["delete"], ["allow"], ["deny"], ["insert"])

_MAX_DEPTH = 6
_MAX_COMMAND_CHARS = 20_000


def _split_opts(args: Sequence[str]) -> tuple[set[str], set[str], list[str]]:
    """Split argv into (short flag letters, long options, operands)."""
    short: set[str] = set()
    long: set[str] = set()
    operands: list[str] = []
    end = False
    for a in args:
        if end:
            operands.append(a)
        elif a == "--":
            end = True
        elif a.startswith("--"):
            long.add(a.split("=", 1)[0])
        elif a.startswith("-") and len(a) > 1:
            short.update(a[1:])
        else:
            operands.append(a)
    return short, long, operands


def _skip_options(args: Sequence[str], with_arg: frozenset[str]) -> list[str]:
    """Drop leading options (and the arguments of those in ``with_arg``)."""
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return list(args[i + 1 :])
        if not a.startswith("-") or a == "-":
            break
        i += 2 if a in with_arg else 1
    return list(args[i:])


_BRACES = re.compile(r"\{([^{}]*,[^{}]*)\}")
_PATH_SEVERITY = ("root", "device", "critical", "home", "system", "under-system", "parent",
                  "cwd", "variable")  # fmt: skip


def _expand_braces(word: str, limit: int = 64) -> list[str]:
    """Expand ``/{bin,etc}`` style braces the way the shell would (bounded)."""
    pending: list[str] = [word]
    done: list[str] = []
    while pending and len(pending) + len(done) < limit:
        current = pending.pop()
        match = _BRACES.search(current)
        if match is None:
            done.append(current)
            continue
        for option in match.group(1).split(","):
            pending.append(current[: match.start()] + option + current[match.end() :])
    return done + pending


def _basename(word: str) -> str:
    name = word.rsplit("/", 1)[-1] if "/" in word else word
    return name.lstrip("\\")


# --------------------------------------------------------------------------- #
# Analyzer
# --------------------------------------------------------------------------- #


class _Analyzer:
    def __init__(self, cwd: str | None, home: str | None) -> None:
        self.cwd = cwd
        self.home = home
        self.findings: list[Finding] = []
        self.programs: list[str] = []
        self.downloaded: set[str] = set()  # file names saved by curl/wget so far

    # -- bookkeeping -------------------------------------------------------- #

    def add(self, level: Risk, category: str, reason: str) -> None:
        finding = Finding(level, category, reason)
        if finding not in self.findings:
            self.findings.append(finding)

    def path(self, operand: str) -> str:
        """Bucket an operand; with brace expansion, the most sensitive member wins."""
        kinds = {classify_path(word, self.home) for word in _expand_braces(operand)}
        return next((kind for kind in _PATH_SEVERITY if kind in kinds), "other")

    def _sub_programs(self, text: str) -> set[str]:
        """Programs invoked anywhere inside ``text`` (analysed in isolation)."""
        probe = _Analyzer(self.cwd, self.home)
        probe.script(text, _MAX_DEPTH - 2)
        return set(probe.programs)

    # -- structure ---------------------------------------------------------- #

    def script(self, text: str, depth: int = 0) -> None:
        if depth > _MAX_DEPTH:
            self.add(Risk.CAUTION, "parse", "nested too deeply to analyse completely")
            return
        try:
            tokens, subs = lex(text)
        except LexError as exc:
            self.add(Risk.CAUTION, "parse", f"could not parse the command reliably ({exc})")
            self._fallback(text, depth)
            return
        for sub in subs:
            self.script(sub, depth + 1)

        pipeline: list[tuple[str, list[str]]] = []
        words: list[str] = []
        redirects: list[tuple[str, str]] = []

        def end_simple() -> None:
            if words or redirects:
                result = self.simple(list(words), list(redirects), depth)
                if result is not None:
                    pipeline.append(result)
            words.clear()
            redirects.clear()

        def end_pipeline() -> None:
            end_simple()
            self.pipeline(pipeline)
            pipeline.clear()

        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok.kind == "word":
                words.append(tok.text)
            elif tok.text in _REDIRECT_OPS:
                if i + 1 < len(tokens) and tokens[i + 1].kind == "word":
                    redirects.append((tok.text, tokens[i + 1].text))
                    i += 1
            elif tok.text in _PIPE_OPS:
                end_simple()
            else:
                end_pipeline()
            i += 1
        end_pipeline()

    def _fallback(self, text: str, depth: int) -> None:
        """Best-effort analysis of text the lexer rejected."""
        for chunk in re.split(r"[;|&\n]+", text):
            argv = chunk.replace('"', " ").replace("'", " ").replace("`", " ").split()
            if argv:
                self.argv(argv, depth + 1)

    def pipeline(self, commands: Sequence[tuple[str, list[str]]]) -> None:
        for index, (prog, args) in enumerate(commands):
            if index == 0 or not self._reads_code_from_stdin(prog, args):
                continue
            upstream = {p for p, _ in commands[:index]}
            if upstream & _NET_FETCH:
                self.add(
                    Risk.DANGER,
                    "network-exec",
                    f"pipes data downloaded from the network straight into `{prog}` "
                    "(remote code execution without review)",
                )
            elif upstream & _DECODERS:
                self.add(
                    Risk.DANGER,
                    "obfuscation",
                    f"decodes hidden text and pipes it into `{prog}` for execution",
                )
            else:
                self.add(
                    Risk.CAUTION,
                    "opaque",
                    f"pipes generated text into `{prog}`, which will execute it",
                )

    @staticmethod
    def _reads_code_from_stdin(prog: str, args: Sequence[str]) -> bool:
        if prog not in _SHELLS and prog not in _INTERPRETERS:
            return False
        short, _long, operands = _split_opts(args)
        if prog in _SHELLS:
            if any(re.fullmatch(r"-[A-Za-z]*c", a) for a in args):
                return False
            return "s" in short or not [o for o in operands if o != "-"]
        if _INLINE_CODE_FLAGS.get(prog, "-c") in args:
            return False
        return not [o for o in operands if o != "-"]

    # -- simple commands ---------------------------------------------------- #

    def simple(
        self, words: list[str], redirects: list[tuple[str, str]], depth: int
    ) -> tuple[str, list[str]] | None:
        raw_words = list(words)
        while raw_words and _ASSIGNMENT.match(raw_words[0]):
            raw_words.pop(0)
        argv = [_unquote(w) for w in raw_words]
        while argv and argv[0] in _KEYWORDS:
            argv.pop(0)
            raw_words.pop(0)
        for op, target in redirects:
            self.redirect(op, _unquote(target), bare=not argv or argv[0] in (":", "true"))
        if not argv:
            return None
        return self.argv(argv, depth, raw_words)

    def redirect(self, op: str, target: str, *, bare: bool) -> None:
        if op not in _OUTPUT_REDIRECTS:
            return
        if target.startswith(("/dev/tcp/", "/dev/udp/")):
            self.add(
                Risk.DANGER,
                "network-exec",
                f"connects the shell to a network socket ({target}) - reverse-shell pattern",
            )
            return
        kind = self.path(target)
        if kind == "device":
            self.add(
                Risk.DANGER,
                "device-write",
                f"redirects output onto the raw device {target}, destroying its contents",
            )
        elif kind == "critical":
            self.add(Risk.DANGER, "system", f"overwrites the critical system file {target}")
        elif kind in ("under-system", "system"):
            self.add(Risk.CAUTION, "system", f"writes to the system path {target}")
        elif _STARTUP_FILES.search(target):
            self.add(
                Risk.CAUTION,
                "persistence",
                f"modifies {target}, which runs or grants access on every login",
            )
        elif bare and op in (">", ">|", "&>") and not target.startswith("/dev/"):
            self.add(Risk.CAUTION, "destructive", f"truncates {target} to zero bytes")

    def argv(
        self, argv: Sequence[str], depth: int, raw: Sequence[str] | None = None
    ) -> tuple[str, list[str]] | None:
        if not argv:
            return None
        if depth > _MAX_DEPTH:
            self.add(Risk.CAUTION, "parse", "nested too deeply to analyse completely")
            return None
        first = argv[0]
        args = list(argv[1:])
        if first.startswith("$") or "$(" in first or "`" in first:
            self.add(
                Risk.CAUTION,
                "obfuscation",
                "the command name is computed at run time, so it cannot be inspected",
            )
            if any(self.path(a) in ("root", "home", "system", "device") for a in args):
                self.add(
                    Risk.DANGER,
                    "obfuscation",
                    "an uninspectable command is being applied to /, a home directory "
                    "or a raw device",
                )
            return None
        prog = _basename(first)

        # ---- wrappers: resolve to the command that actually runs ---------- #
        if prog in _PRIVILEGE:
            self.add(Risk.CAUTION, "privileged", f"runs with elevated privileges ({prog})")
            rest = _skip_options(args, _SUDO_ARG_OPTS)
            while rest and _ASSIGNMENT.match(rest[0]):
                rest.pop(0)
            if not rest:
                self.programs.append(prog)
                return prog, args
            return self.argv(rest, depth + 1)
        if prog == "su":
            self.add(Risk.CAUTION, "privileged", "switches user (su)")
            self.programs.append(prog)
            for flag in ("-c", "--command"):
                if flag in args and args.index(flag) + 1 < len(args):
                    self.script(args[args.index(flag) + 1], depth + 1)
            return prog, args
        if prog in _PLAIN_WRAPPERS:
            rest = _skip_options(args, frozenset())
            return self.argv(rest, depth + 1) if rest else (prog, args)
        if prog in _OPTION_WRAPPERS:
            rest = _skip_options(args, _OPTION_WRAPPERS[prog])
            if prog == "env":
                while rest and _ASSIGNMENT.match(rest[0]):
                    rest.pop(0)
            if prog == "timeout" and rest:
                rest = rest[1:]  # the duration
            if not rest:
                self.programs.append(prog)
                return prog, args
            if prog == "watch" and len(rest) == 1:
                self.script(rest[0], depth + 1)
                return prog, args
            return self.argv(rest, depth + 1)

        self.programs.append(prog)
        self._check_runs_download(prog, first, args)

        # ---- code-carrying commands --------------------------------------- #
        if prog in _SHELLS or prog in ("eval", "source", "."):
            self._check_fetched_code(prog, raw if raw is not None else argv)
        if prog in _SHELLS:
            for index, a in enumerate(args):
                if re.fullmatch(r"-[A-Za-z]*c", a) and index + 1 < len(args):
                    self.script(args[index + 1], depth + 1)
                    break
            return prog, args
        if prog == "eval":
            self.add(Risk.CAUTION, "opaque", "eval executes text assembled at run time")
            self.script(" ".join(args), depth + 1)
            return prog, args
        if prog in _INTERPRETERS:
            flag = _INLINE_CODE_FLAGS.get(prog, "-c")
            if flag in args:
                self.add(
                    Risk.CAUTION,
                    "opaque",
                    f"runs inline {prog} code that the risk engine cannot inspect",
                )
                code = " ".join(args[args.index(flag) + 1 :][:1])
                for literal in re.findall(r"'([^']{4,})'|\"([^\"]{4,})\"", code):
                    probe = _Analyzer(self.cwd, self.home)
                    probe.script(literal[0] or literal[1], _MAX_DEPTH - 1)
                    if any(f.level is Risk.DANGER for f in probe.findings):
                        self.add(
                            Risk.DANGER,
                            "opaque",
                            f"the inline {prog} code contains a dangerous shell command",
                        )
            return prog, args
        if prog == "ssh":
            rest = _skip_options(args, _SSH_ARG_OPTS)
            if len(rest) > 1:
                self.add(Risk.CAUTION, "remote", f"runs a command on the remote host {rest[0]}")
                self.script(" ".join(rest[1:]), depth + 1)
            return prog, args

        handler = _HANDLERS.get(prog)
        if handler is None and prog.startswith("mkfs"):
            handler = _Analyzer._disk_format
        if handler is not None:
            handler(self, prog, args, depth)
        return prog, args

    def _check_runs_download(self, prog: str, first: str, args: Sequence[str]) -> None:
        """Flag ``curl -O x.sh && bash x.sh`` - same risk as ``curl | bash``."""
        if not self.downloaded:
            return
        candidates = [first] if "/" in first else []
        if prog in _SHELLS or prog in _INTERPRETERS or prog in ("source", "."):
            candidates += [a for a in args if not a.startswith("-")][:1]
        for candidate in candidates:
            if posixpath.basename(candidate) in self.downloaded:
                self.add(
                    Risk.DANGER,
                    "network-exec",
                    f"executes {candidate}, which was downloaded earlier in the same "
                    "command line (remote code execution without review)",
                )

    def _note_download(self, prog: str, args: Sequence[str]) -> None:
        output: str | None = None
        remote_name = prog == "wget"
        urls: list[str] = []
        skip = False
        for index, a in enumerate(args):
            if skip:
                skip = False
                continue
            nxt = args[index + 1] if index + 1 < len(args) else ""
            if (a in ("-o", "--output") and prog == "curl") or (
                a in ("-O", "--output-document") and prog == "wget"
            ):
                output, skip = nxt, True
            elif (
                prog == "wget" and a.startswith("-") and not a.startswith("--") and a.endswith("O")
            ):
                output, skip = nxt, True  # -qO FILE
            elif prog == "wget" and re.match(r"^-[a-zA-Z]*O.+", a):
                output = a[a.index("O") + 1 :]  # -qO- / -Ofile
            elif prog == "curl" and (
                a in ("--remote-name", "--remote-name-all")
                or re.fullmatch(r"-[a-zA-Z]*O[a-zA-Z]*", a)
            ):
                remote_name = True
            elif not a.startswith("-"):
                urls.append(a)
        if output is not None:
            if output != "-":
                self.downloaded.add(posixpath.basename(output))
        elif remote_name:
            for url in urls:
                name = posixpath.basename(url.split("?", 1)[0].rstrip("/"))
                if name:
                    self.downloaded.add(name)

    def _check_fetched_code(self, prog: str, raw_words: Sequence[str]) -> None:
        for word in raw_words[1:]:
            if "$(" not in word and "`" not in word and "<(" not in word:
                continue
            try:
                _tokens, subs = lex(word)
            except LexError:
                continue
            for sub in subs:
                if self._sub_programs(sub) & _NET_FETCH:
                    self.add(
                        Risk.DANGER,
                        "network-exec",
                        f"`{prog}` executes code that is downloaded at run time",
                    )
                    return

    # -- per-program rules -------------------------------------------------- #

    def _rm(self, prog: str, args: list[str], depth: int) -> None:
        short, long, operands = _split_opts(args)
        recursive = bool(short & {"r", "R"}) or "--recursive" in long
        if "--no-preserve-root" in long:
            self.add(Risk.DANGER, "destructive", "disables rm's protection of /")
        how = "recursively deletes" if recursive else "deletes"
        for target in operands:
            kind = self.path(target)
            if kind == "root":
                self.add(Risk.DANGER, "destructive", f"{how} the root filesystem ({target})")
            elif kind == "home" and (recursive or target.rstrip("/").endswith("*")):
                self.add(Risk.DANGER, "destructive", f"{how} an entire home directory ({target})")
            elif kind == "system" and (recursive or target.rstrip("/").endswith("*")):
                self.add(Risk.DANGER, "destructive", f"{how} the system directory {target}")
            elif kind == "critical":
                self.add(Risk.DANGER, "destructive", f"deletes the critical system file {target}")
            elif kind == "device":
                self.add(Risk.DANGER, "destructive", f"removes the device node {target}")
            elif kind == "under-system":
                self.add(Risk.CAUTION, "system", f"{how} files inside a system directory")
            elif kind in ("cwd", "parent") and recursive:
                here = posixpath.normpath(self.cwd) if self.cwd else None
                home = posixpath.normpath(self.home) if self.home else None
                if kind == "parent" or (here is not None and here in ("/", home)):
                    self.add(
                        Risk.DANGER,
                        "destructive",
                        f"recursively deletes everything in {target!r} relative to "
                        f"{here or 'the current directory'}",
                    )
                else:
                    self.add(
                        Risk.CAUTION,
                        "destructive",
                        "recursively deletes everything in the current directory",
                    )
            elif kind == "variable" and recursive:
                self.add(
                    Risk.CAUTION,
                    "destructive",
                    f"recursive delete of {target}: if the variable is empty this "
                    "expands towards /",
                )
        self.add(
            Risk.CAUTION,
            "destructive",
            f"{how} files permanently (no trash, no undo)",
        )

    def _dd(self, prog: str, args: list[str], depth: int) -> None:
        for a in args:
            if not a.startswith("of="):
                continue
            target = a[3:]
            kind = self.path(target)
            if kind == "device":
                self.add(
                    Risk.DANGER, "disk", f"dd overwrites the raw device {target} block by block"
                )
            elif kind == "critical":
                self.add(Risk.DANGER, "system", f"dd overwrites the critical file {target}")
            else:
                self.add(Risk.CAUTION, "disk", f"dd overwrites {target} without confirmation")

    def _disk_format(self, prog: str, args: list[str], depth: int) -> None:
        short, long, operands = _split_opts(args)
        if prog == "zpool" and not (operands and operands[0] in ("destroy", "labelclear")):
            return
        if prog == "hdparm" and not (long & {"--security-erase", "--trim-sector-ranges"}):
            return
        if prog == "nvme" and not (operands and operands[0] in ("format", "sanitize")):
            return
        if prog == "diskutil" and not (
            operands and operands[0].lower().startswith(("erase", "partition", "zero", "secure"))
        ):
            return
        if prog == "badblocks" and "w" not in short:
            return
        self.add(Risk.DANGER, "disk", f"{prog} creates/erases filesystem structures on a device")

    def _partition(self, prog: str, args: list[str], depth: int) -> None:
        short, long, operands = _split_opts(args)
        read_only = (
            "l" in short
            or long & {"--list", "--dump", "--print", "--version", "--help"}
            or (prog == "sfdisk" and "d" in short)
            or (prog == "sgdisk" and "p" in short)
            or (prog == "parted" and "print" in operands)
        )
        if not read_only:
            self.add(Risk.DANGER, "disk", f"{prog} can rewrite the partition table of a disk")

    def _wipefs(self, prog: str, args: list[str], depth: int) -> None:
        short, long, _ops = _split_opts(args)
        if short & {"a", "o"} or long & {"--all", "--offset"}:
            self.add(Risk.DANGER, "disk", "wipefs erases filesystem signatures from a device")

    def _cryptsetup(self, prog: str, args: list[str], depth: int) -> None:
        _s, _l, operands = _split_opts(args)
        if operands and operands[0] in ("luksFormat", "erase", "luksErase", "reencrypt"):
            self.add(Risk.DANGER, "disk", f"cryptsetup {operands[0]} destroys data on the device")
        else:
            self.add(Risk.CAUTION, "disk", "changes encrypted-volume state")

    def _shred(self, prog: str, args: list[str], depth: int) -> None:
        _s, _l, operands = _split_opts(args)
        if any(self.path(o) in ("device", "critical", "root") for o in operands):
            self.add(Risk.DANGER, "disk", "shred irrecoverably overwrites a device or system file")
        else:
            self.add(Risk.CAUTION, "destructive", "shred irrecoverably overwrites file contents")

    def _perm(self, prog: str, args: list[str], depth: int) -> None:
        recursive = False
        positional: list[str] = []
        for a in args:
            if a in ("-R", "--recursive") or re.fullmatch(r"-[RvfchHLP]*R[RvfchHLP]*", a):
                recursive = True
            elif a.startswith("--") or re.fullmatch(r"-[vfchHLP]+", a):
                continue
            else:
                positional.append(a)
        if not positional:
            return
        spec, targets = positional[0], positional[1:]
        what = {"chmod": "permissions", "chown": "ownership", "chgrp": "group ownership"}[prog]
        for target in targets:
            kind = self.path(target)
            if kind == "root" or (kind in ("system", "home") and recursive):
                self.add(
                    Risk.DANGER,
                    "permission",
                    f"{'recursively ' if recursive else ''}changes {what} of {target} - "
                    "this breaks sudo, ssh and most of the system",
                )
            elif kind == "critical":
                self.add(Risk.DANGER, "permission", f"changes {what} of the critical file {target}")
            elif kind in ("system", "under-system", "device"):
                self.add(Risk.CAUTION, "permission", f"changes {what} of the system path {target}")
            elif kind in ("cwd", "parent") and recursive:
                here = posixpath.normpath(self.cwd) if self.cwd else None
                if here == "/":
                    self.add(Risk.DANGER, "permission", f"recursively changes {what} of /")
        if prog == "chmod":
            world_writable = bool(re.fullmatch(r"[0-7]?[0-7][0-7][2367]", spec)) or any(
                re.match(r"^[ug]*[oa][ugoa]*[+=][rxXst]*w", clause) for clause in spec.split(",")
            )
            if world_writable:
                self.add(Risk.CAUTION, "permission", f"mode {spec} makes files world-writable")
            if re.fullmatch(r"[2467][0-7]{3}", spec) or re.search(r"[+=][rwxX]*s", spec):
                self.add(Risk.CAUTION, "permission", f"mode {spec} sets the setuid/setgid bit")
        if recursive:
            self.add(Risk.CAUTION, "permission", f"recursively changes {what}")

    def _mv(self, prog: str, args: list[str], depth: int) -> None:
        _s, _l, operands = _split_opts(args)
        if len(operands) < 2:
            return
        *sources, dest = operands
        for src in sources:
            kind = self.path(src)
            if kind in ("root", "home", "system", "critical"):
                self.add(
                    Risk.DANGER, "destructive", f"moves {src} away from where the system expects it"
                )
            elif kind == "under-system":
                self.add(Risk.CAUTION, "system", f"moves the system file {src}")
        if dest == "/dev/null":
            self.add(Risk.DANGER, "destructive", "moving files to /dev/null destroys them")
        self._write_target(prog, dest)

    def _write_target(self, prog: str, dest: str) -> None:
        kind = self.path(dest)
        if kind == "device":
            self.add(Risk.DANGER, "device-write", f"{prog} writes directly onto the device {dest}")
        elif kind == "critical":
            self.add(Risk.DANGER, "system", f"{prog} overwrites the critical system file {dest}")
        elif kind in ("under-system", "system"):
            self.add(Risk.CAUTION, "system", f"{prog} writes into the system path {dest}")
        elif _STARTUP_FILES.search(dest):
            self.add(Risk.CAUTION, "persistence", f"{prog} modifies the login/startup file {dest}")

    def _cp(self, prog: str, args: list[str], depth: int) -> None:
        _s, _l, operands = _split_opts(args)
        if len(operands) >= 2:
            self._write_target(prog, operands[-1])

    def _tee(self, prog: str, args: list[str], depth: int) -> None:
        _s, _l, operands = _split_opts(args)
        for dest in operands:
            self._write_target(prog, dest)

    def _truncate(self, prog: str, args: list[str], depth: int) -> None:
        _s, _l, operands = _split_opts(args)
        if any(self.path(o) in ("device", "critical") for o in operands):
            self.add(Risk.DANGER, "destructive", "truncates a device or critical system file")
        else:
            self.add(Risk.CAUTION, "destructive", "truncate discards file contents")

    def _sed(self, prog: str, args: list[str], depth: int) -> None:
        short, _long, operands = _split_opts(args)
        in_place = any(a.startswith("-i") or a.startswith("--in-place") for a in args) or (
            prog == "perl" and "i" in short
        )
        if not in_place:
            return
        if any(self.path(o) == "critical" for o in operands):
            self.add(Risk.DANGER, "system", "edits a critical system file in place")
        else:
            self.add(Risk.CAUTION, "destructive", f"{prog} -i rewrites files in place (no backup)")

    def _power(self, prog: str, args: list[str], depth: int) -> None:
        if prog in ("init", "telinit") and not (set(args) & {"0", "6"}):
            return
        self.add(Risk.CAUTION, "availability", f"{prog} powers off or restarts the machine")

    def _systemctl(self, prog: str, args: list[str], depth: int) -> None:
        _s, _l, operands = _split_opts(args)
        verb = operands[0] if operands else ""
        if prog == "service":
            verb = operands[1] if len(operands) > 1 else ""
        if verb in ("poweroff", "reboot", "halt", "suspend", "hibernate", "kexec", "emergency",
                    "rescue"):  # fmt: skip
            self.add(Risk.CAUTION, "availability", f"{prog} {verb} takes the machine down")
        elif verb in ("stop", "disable", "mask", "restart", "kill", "isolate", "daemon-reexec",
                      "enable", "start", "reload", "unmask", "edit", "set-default"):  # fmt: skip
            self.add(Risk.CAUTION, "system", f"{prog} {verb} changes the state of a service")

    def _kill(self, prog: str, args: list[str], depth: int) -> None:
        if prog == "kill":
            for index, a in enumerate(args):
                if a == "-1" and (index > 0 and args[index - 1] not in ("-s", "-n")):
                    self.add(
                        Risk.DANGER,
                        "availability",
                        "kill ... -1 signals every process you are allowed to signal",
                    )
            if "1" in args[1:] or args == ["1"]:
                self.add(Risk.CAUTION, "availability", "signals PID 1 (init)")
        self.add(Risk.CAUTION, "availability", f"{prog} terminates running processes")

    def _find(self, prog: str, args: list[str], depth: int) -> None:
        paths: list[str] = []
        i = 0
        while i < len(args) and not args[i].startswith(("-", "(", "!")):
            paths.append(args[i])
            i += 1
        wide = [p for p in paths if self.path(p) in ("root", "home", "system")]
        destructive = False
        before = sum(1 for f in self.findings if f.category in ("destructive", "disk"))
        while i < len(args):
            a = args[i]
            if a == "-delete":
                destructive = True
            elif a in ("-exec", "-execdir", "-ok", "-okdir"):
                j = i + 1
                while j < len(args) and args[j] not in (";", "+"):
                    j += 1
                self.argv(args[i + 1 : j], depth + 1)
                i = j
            elif a in ("-fprint", "-fprintf", "-fls", "-fprint0") and i + 1 < len(args):
                self._write_target("find", args[i + 1])
            i += 1
        after = sum(1 for f in self.findings if f.category in ("destructive", "disk"))
        if destructive:
            self.add(Risk.CAUTION, "destructive", "find -delete removes every match permanently")
        if (destructive or after > before) and wide:
            self.add(
                Risk.DANGER,
                "destructive",
                f"applies a destructive action to everything find matches under {wide[0]}",
            )

    def _git(self, prog: str, args: list[str], depth: int) -> None:
        rest = list(args)
        while rest and rest[0].startswith("-"):
            rest = rest[2:] if rest[0] in ("-C", "-c", "--git-dir", "--work-tree") else rest[1:]
        if not rest:
            return
        verb, tail = rest[0], rest[1:]
        short, long, operands = _split_opts(tail)
        msg: str | None = None
        if verb == "reset" and "--hard" in long:
            msg = "git reset --hard discards uncommitted changes"
        elif verb == "clean" and ("f" in short or "--force" in long):
            msg = "git clean -f deletes untracked files permanently"
        elif verb == "push" and (
            "f" in short
            or long & {"--force", "--force-with-lease", "--delete", "--mirror", "--prune"}
            or "d" in short
            or any(o.startswith("+") or o.startswith(":") for o in operands)
        ):
            msg = "git push rewrites or deletes history on the remote"
        elif verb in ("checkout", "restore") and ("." in operands or ("--" in tail and operands)):
            msg = f"git {verb} overwrites uncommitted changes in the working tree"
        elif verb == "branch" and ("D" in short or ("d" in short and "--force" in long)):
            msg = "git branch -D deletes a branch even if unmerged"
        elif verb == "stash" and operands[:1] in (["drop"], ["clear"]):
            msg = "git stash drop/clear discards stashed work"
        elif verb in ("filter-branch", "filter-repo") or (
            verb == "reflog" and "expire" in operands
        ):
            msg = f"git {verb} rewrites repository history"
        elif verb == "rebase" or (verb == "commit" and "--amend" in long):
            msg = f"git {verb} rewrites local history"
        if msg:
            self.add(Risk.CAUTION, "vcs", msg)

    def _pkg(self, prog: str, args: list[str], depth: int) -> None:
        if prog in ("pacman", "yay", "paru"):
            if any(re.fullmatch(r"-R[a-z]*", a) for a in args) or "--remove" in args:
                self.add(Risk.CAUTION, "system", f"{prog} removes installed packages")
            return
        if prog in ("dpkg", "rpm"):
            if set(args) & {"-r", "-P", "-e", "--purge", "--remove", "--erase"}:
                self.add(Risk.CAUTION, "system", f"{prog} removes installed packages")
            return
        _s, _l, operands = _split_opts(args)
        if operands and operands[0] in _PKG_REMOVE_VERBS:
            self.add(Risk.CAUTION, "system", f"{prog} {operands[0]} removes installed packages")

    def _container(self, prog: str, args: list[str], depth: int) -> None:
        short, long, operands = _split_opts(args)
        joined = " ".join(operands[:3])
        if re.match(r"(system|volume|image|container|network|builder) (prune|rm)\b", joined) or (
            operands[:1] in (["rm"], ["rmi"], ["kill"], ["prune"])
        ):
            self.add(
                Risk.CAUTION,
                "destructive",
                f"{prog} {' '.join(operands[:2])} deletes container data",
            )
        if operands[:1] in (["run"], ["exec"], ["create"]):
            mounts_root = any(re.match(r"^/:(/|$)", a) for a in args) or any(
                a.startswith(("--volume=/:", "-v/:")) for a in args
            )
            if "--privileged" in long or mounts_root or "--pid=host" in args:
                self.add(
                    Risk.CAUTION,
                    "privileged",
                    f"{prog} container gets host-level access (privileged or / mounted)",
                )
        if (
            operands[:1] == ["compose"]
            and "down" in operands
            and ("v" in short or "--volumes" in long)
        ):
            self.add(Risk.CAUTION, "destructive", "compose down -v deletes named volumes")

    def _infra(self, prog: str, args: list[str], depth: int) -> None:
        _s, _l, operands = _split_opts(args)
        verbs = {
            "kubectl": {"delete", "drain", "replace"},
            "terraform": {"destroy", "apply"},
            "tofu": {"destroy", "apply"},
            "helm": {"uninstall", "delete", "rollback"},
        }
        hit = next((o for o in operands if o in verbs.get(prog, set())), None)
        if hit:
            self.add(
                Risk.CAUTION, "destructive", f"{prog} {hit} changes or deletes live infrastructure"
            )

    def _firewall(self, prog: str, args: list[str], depth: int) -> None:
        short, long, operands = _split_opts(args)
        flush = (
            bool(short & {"F", "X", "Z"})
            or "--flush" in long
            or operands[:1] == ["flush"]
            or (prog == "ufw" and operands[:1] in (["disable"], ["reset"]))
        )
        if flush:
            self.add(Risk.CAUTION, "system", f"{prog} flushes or disables firewall rules")
        elif short & {"A", "I", "D", "P", "R"} or operands[:1] in _FIREWALL_EDIT_VERBS:
            self.add(Risk.CAUTION, "system", f"{prog} changes firewall rules")

    def _crontab(self, prog: str, args: list[str], depth: int) -> None:
        if "-r" in args:
            self.add(Risk.CAUTION, "destructive", "crontab -r deletes all of your cron jobs")

    def _account(self, prog: str, args: list[str], depth: int) -> None:
        self.add(Risk.CAUTION, "system", f"{prog} changes user accounts or credentials")

    def _system_state(self, prog: str, args: list[str], depth: int) -> None:
        short, _long, operands = _split_opts(args)
        if prog == "sysctl" and "w" not in short and not any("=" in o for o in operands):
            return
        if prog == "mount" and not operands:
            return
        if prog in ("timedatectl", "hostnamectl") and not any(
            o.startswith("set-") for o in operands
        ):
            return
        if prog == "losetup" and (not args or short & {"a", "l", "j"}):
            return
        if prog == "efibootmgr" and not args:
            return
        self.add(Risk.CAUTION, "system", f"{prog} changes kernel, boot or mount state")

    def _netcat(self, prog: str, args: list[str], depth: int) -> None:
        short, long, _operands = _split_opts(args)
        if prog == "socat":
            if any("exec:" in a.lower() or "system:" in a.lower() for a in args):
                self.add(
                    Risk.DANGER, "network-exec", "socat attaches a program to a network socket"
                )
            return
        if short & {"e", "c"} or long & {"--exec", "--sh-exec"}:
            self.add(
                Risk.DANGER,
                "network-exec",
                f"{prog} -e attaches a shell to a network connection (remote shell)",
            )
        elif "l" in short or "--listen" in long:
            self.add(Risk.CAUTION, "network", f"{prog} opens a listening network port")

    def _upload(self, prog: str, args: list[str], depth: int) -> None:
        data_flags = (
            "-d",
            "--data",
            "--data-binary",
            "--data-raw",
            "--data-urlencode",
            "-F",
            "--form",
        )
        for index, a in enumerate(args):
            nxt = args[index + 1] if index + 1 < len(args) else ""
            uploads = (
                a in ("-T", "--upload-file")
                or a.startswith(("--upload-file=", "--post-file", "--body-file"))
                or (a in data_flags and "@" in nxt)
                or bool(re.match(r"^(-d|-F|--data(-binary)?=|--form=)@", a))
            )
            if uploads:
                self.add(Risk.CAUTION, "network", f"{prog} uploads a local file to a remote server")
        self._note_download(prog, args)
        if prog == "curl":
            for index, a in enumerate(args):
                if a in ("-o", "--output") and index + 1 < len(args):
                    self._write_target(prog, args[index + 1])
        if prog == "wget":
            for index, a in enumerate(args):
                if a in ("-O", "--output-document") and index + 1 < len(args):
                    self._write_target(prog, args[index + 1])

    def _rsync(self, prog: str, args: list[str], depth: int) -> None:
        _s, long, operands = _split_opts(args)
        if any(opt.startswith("--delete") or opt == "--remove-source-files" for opt in long):
            self.add(Risk.CAUTION, "destructive", "rsync --delete removes files at the destination")
        if operands:
            self._write_target(prog, operands[-1])

    def _alias(self, prog: str, args: list[str], depth: int) -> None:
        for a in args:
            name, sep, body = a.partition("=")
            if sep and body:
                self.add(
                    Risk.CAUTION,
                    "persistence",
                    f"redefines what `{name}` does for the rest of the session",
                )
                self.script(body, depth + 1)

    def _history(self, prog: str, args: list[str], depth: int) -> None:
        if "-c" in args or "-w" in args:
            self.add(Risk.CAUTION, "destructive", "rewrites or clears shell history")


_Handler = Callable[[_Analyzer, str, list[str], int], None]
_HANDLERS: dict[str, _Handler] = {}


def _register(names: Iterable[str], handler: _Handler) -> None:
    for name in names:
        _HANDLERS[name] = handler


_register(["rm", "rmdir", "unlink"], _Analyzer._rm)
_register(["dd"], _Analyzer._dd)
_register(_DISK_FORMATTERS, _Analyzer._disk_format)
_register(_PARTITIONERS, _Analyzer._partition)
_register(["wipefs"], _Analyzer._wipefs)
_register(["cryptsetup"], _Analyzer._cryptsetup)
_register(["shred", "srm", "wipe"], _Analyzer._shred)
_register(["chmod", "chown", "chgrp"], _Analyzer._perm)
_register(["mv"], _Analyzer._mv)
_register(["cp", "install", "ln"], _Analyzer._cp)
_register(["tee"], _Analyzer._tee)
_register(["truncate"], _Analyzer._truncate)
_register(["sed", "gsed"], _Analyzer._sed)
_register(_POWER, _Analyzer._power)
_register(["systemctl", "service"], _Analyzer._systemctl)
_register(_PROC_KILLERS, _Analyzer._kill)
_register(["find", "fd", "fdfind"], _Analyzer._find)
_register(["git"], _Analyzer._git)
_register(_PKG_MANAGERS, _Analyzer._pkg)
_register(["docker", "podman", "nerdctl"], _Analyzer._container)
_register(["kubectl", "terraform", "tofu", "helm"], _Analyzer._infra)
_register(["iptables", "ip6tables", "nft", "ufw"], _Analyzer._firewall)
_register(["crontab"], _Analyzer._crontab)
_register(_ACCOUNT, _Analyzer._account)
_register(_SYSTEM_STATE, _Analyzer._system_state)
_register(["nc", "ncat", "netcat", "socat"], _Analyzer._netcat)
_register(["curl", "wget"], _Analyzer._upload)
_register(["rsync"], _Analyzer._rsync)
_register(["history"], _Analyzer._history)
_register(["alias"], _Analyzer._alias)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def classify(command: str, *, cwd: str | None = None, home: str | None = None) -> Assessment:
    """Classify ``command`` and explain why.

    ``cwd`` and ``home`` are optional context: with them, relative wildcards
    such as ``rm -rf *`` are escalated when the working directory is ``/`` or
    the home directory, and ``/home/<you>`` is recognised as a home directory.
    """
    analyzer = _Analyzer(cwd, home)
    text = command
    if len(command) > _MAX_COMMAND_CHARS:
        text = command[:_MAX_COMMAND_CHARS]
        analyzer.add(
            Risk.CAUTION,
            "parse",
            f"command is longer than {_MAX_COMMAND_CHARS} characters; only the start was analysed",
        )
    if any(p.search(text) for p in _FORK_BOMBS):
        analyzer.add(
            Risk.DANGER,
            "fork-bomb",
            "defines a function that keeps spawning copies of itself (fork bomb) - "
            "this exhausts the process table and freezes the machine",
        )
    if _CONTROL_CHARS.search(command):
        analyzer.add(
            Risk.CAUTION,
            "obfuscation",
            "contains control characters that can hide text in a terminal",
        )
    if _INVISIBLE_CHARS.search(command):
        analyzer.add(
            Risk.CAUTION,
            "obfuscation",
            "contains invisible or bidirectional Unicode characters",
        )
    analyzer.script(text)
    findings = tuple(sorted(analyzer.findings, key=lambda f: -int(f.level)))
    level = max((f.level for f in findings), default=Risk.SAFE)
    programs = tuple(dict.fromkeys(analyzer.programs))
    return Assessment(command=command, level=level, findings=findings, programs=programs)
