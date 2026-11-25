import asyncio
import base64
import contextlib
import functools
import hashlib
import ipaddress
import json
import os
import posixpath
import re
import shutil
import stat
import tarfile
import tempfile
import threading
import time
import urllib.parse
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path

import yaml

from localci import ci_report
from localci.github import GitHub
from localci.policy import (
    Blocked,
    dependabot_pr,
    github_token_referenced,
    is_local_workflow,
    plan,
    secret_references,
    workflow_files,
)
from localci.review_evidence import (
    classify_review,
    configuration_diagnostic,
    primary_findings,
    terminal_event,
)
from localci.store import Store
from localci.telemetry import sample_resources


def apply_review_token_ceiling(review_config, token_ceiling: int | None) -> None:
    """Cap the trusted base review config at the operator's token ceiling.

    Other keys of `runBounds`, `review` and `review.roundBudgets` are kept. A
    section that is not a mapping raises ValueError with a message for the operator.
    """

    def section(parent, key, path):
        value = parent.get(key)
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ValueError(f"Base .mergecraft/config.yaml is invalid: `{path}` must be a mapping")
        return value

    if not isinstance(review_config, dict):
        raise ValueError("Base .mergecraft/config.yaml is invalid: the top level must be a mapping")
    if token_ceiling is None:
        return
    run_bounds = section(review_config, "runBounds", "runBounds")
    review = section(review_config, "review", "review")
    round_budgets = section(review, "roundBudgets", "review.roundBudgets")
    review_config["runBounds"] = {**run_bounds, "tokenBudget": token_ceiling, "tokenBudgetTolerance": 0}
    review_config["review"] = {**review, "roundBudgets": {**round_budgets, "multipliers": [1.0]}}


class Cancelled(RuntimeError):
    pass


_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
# Fragments derived from a secret (its stripped form, individual lines, base64 windows)
# are redacted only when reasonably long, so short pieces cannot wreck unrelated log text.
MIN_SECRET_FRAGMENT = 8
# Single lines of a multi-line secret (a kubeconfig, a JSON key file) are often ordinary
# text such as "clusters:"; only lines long enough to be distinctive become patterns.
MIN_SECRET_LINE = 12
_PEM_ARMOR = re.compile(r"-----(?:BEGIN|END) [A-Z0-9 ]+-----")
OUTPUT_LINE_LIMIT = 100_000
OVERSIZED_LINE = "[oversized output line omitted]\n"
CAPTURE_LIMIT = 2_000_000  # Bytes of captured stdout (workflow files, review.patch).
HELD_BYTES = 16_384  # Trailing base64 lines a log batch may keep back for the next one.


def strip_controls(text: str) -> str:
    return _CONTROL.sub("", _ANSI.sub("", text))


_URLSAFE = str.maketrans("+/", "-_")


def _base64_forms(secret: bytes) -> set[str]:
    """Base64 of the secret on its own and embedded in a longer value.

    ``user:SECRET`` or ``SECRET\n`` encode the secret at a different byte offset
    and with different padding. Encoding it at each of the three alignments and
    keeping only the characters that depend on the secret alone gives a core that
    appears in every such encoding. Both the standard and URL-safe alphabets.
    """
    forms = {base64.b64encode(secret).decode()}
    for offset in range(3):
        encoded = base64.b64encode(b"\0" * offset + secret).decode()
        start = -(-offset * 8 // 6)  # First character made only of secret bits.
        end = (offset + len(secret)) * 8 // 6  # Characters complete without later bytes.
        forms.add(encoded[start:end])
    forms |= {form.translate(_URLSAFE) for form in forms}
    return {form for form in forms if len(form) >= MIN_SECRET_FRAGMENT}


_BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-"
# Encoded secrets are also found piecewise: every BASE64_WINDOW-character substring
# of an encoding is indexed, and text is probed every BASE64_STEP characters (plus
# at both ends of each token). Any stretch of at least BASE64_WINDOW + BASE64_STEP - 1
# encoded characters is therefore found wherever it is, and a stretch of at least
# BASE64_WINDOW characters at the start or end of a token. 12 base64 characters are
# 72 secret bits, so ordinary output does not match by chance.
BASE64_WINDOW = 12
BASE64_STEP = 4
_GUARANTEED = BASE64_WINDOW + BASE64_STEP - 1
# A maximal run of base64 characters (standard and URL-safe) long enough to hold a window.
_BASE64_TOKEN = re.compile(rf"(?<![A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{{{BASE64_WINDOW},}})(={{0,2}})")


@functools.lru_cache(maxsize=16)
def _base64_index(secrets: tuple[str, ...]) -> tuple[frozenset[str], tuple[str, ...]]:
    """Every BASE64_WINDOW-character window of every base64 form of the secrets, and
    the cores too short to be found reliably by windows (searched for whole)."""
    windows: set[str] = set()
    short: set[str] = set()
    for secret in secrets:
        if not secret.strip():
            continue
        for form in _base64_forms(secret.encode()):
            core = form.rstrip("=")
            if len(core) < _GUARANTEED:
                short.add(core)
            windows.update(core[i : i + BASE64_WINDOW] for i in range(len(core) - BASE64_WINDOW + 1))
    return frozenset(windows), tuple(core for core in short if len(core) >= MIN_SECRET_FRAGMENT)


def _probe(token: str, windows: frozenset[str]) -> bool:
    """Whether ``token`` holds a window: every BASE64_STEP characters and at both ends."""
    size = BASE64_WINDOW
    last = len(token) - size
    if last < 0:
        return False
    if token[:size] in windows or token[last:] in windows:
        return True
    for position in range(BASE64_STEP, last, BASE64_STEP):
        if token[position : position + size] in windows:
            return True
    return False


def _base64_tail(line: str) -> tuple[int, int, int]:
    """The base64 token (padding and trailing blanks excluded) that ends ``line``:
    start, end and length. Plain string scans from the end: linear even for a very
    long line, which a regular expression retried at every position would not be."""
    end = len(line.rstrip(" \t\r").rstrip("="))
    start = len(line[:end].rstrip(_BASE64_ALPHABET))
    return start, end, end - start


def _plausible_base64_line(line: str) -> bool:
    """Only hold a whole base64 payload, not any ordinary line ending in a word."""
    start, _, length = _base64_tail(line)
    if length < BASE64_WINDOW:
        return False
    payload = line[:start].strip()
    return not payload or payload == "|" or (payload.startswith("[") and payload.endswith("|"))


def _joined_spans(joined: str, offsets: list[int], windows: frozenset[str], short: tuple[str, ...]):
    """Spans of ``joined`` covered by an encoded secret that crosses a line boundary.

    An encoding inside a single token is the token scan's job; here only windows
    around each boundary between tokens are probed: the last window of the token
    before it, the first window after it and the two in between on the same
    BASE64_STEP grid. Every stretch of BASE64_WINDOW + BASE64_STEP - 1 encoded
    characters that crosses a boundary holds one of them. A hit is extended one
    character at a time while every window is indexed, so the span reaches the
    true ends of the encoding, including pieces too small to be found alone.
    """
    size = BASE64_WINDOW
    last = len(joined) - size
    probes = sorted(
        position
        for boundary in offsets[1:]
        for position in range(boundary - size, boundary + 1, BASE64_STEP)
        if 0 <= position <= last
    )
    spans = []
    covered = 0  # Positions before this are already inside a span.
    for position in probes:
        if position < covered or joined[position : position + size] not in windows:
            continue
        first = position
        while first > covered and joined[first - 1 : first - 1 + size] in windows:
            first -= 1
        final = position
        while final < last and joined[final + 1 : final + 1 + size] in windows:
            final += 1
        spans.append((first, final + size))
        covered = final + 1
    for core in short:
        found = joined.find(core)
        while found >= 0:
            spans.append((found, found + len(core)))
            found = joined.find(core, found + 1)
    return spans


def _redact_wrapped_base64(text: str, windows: frozenset[str], short: tuple[str, ...]) -> str:
    """Redact encoded secrets that a tool wrapped across consecutive output lines.

    ``base64`` breaks long output into lines (76 columns; PEM 64; ``fold -w N``),
    so no single line holds the whole encoding. Consecutive lines that end in a
    base64 token are joined (a final 1-3 character token, as the last line of a
    wrapped block often is, closes the run) and every token that overlaps an
    encoded secret in the joined text is redacted, so the edges of the encoding on
    neighbouring lines go too. A line prefix (act's ``[job]   | ``) is kept.
    """
    if "\n" not in text:
        return text
    lines = text.split("\n")
    run: list[tuple[int, int, int]] = []  # line index, token start, token end

    def flush():
        if len(run) > 1:
            joined = "".join(lines[index][start:end] for index, start, end in run)
            offsets, offset = [], 0
            for _, start, end in run:
                offsets.append(offset)
                offset += end - start
            spans = sorted(_joined_spans(joined, offsets, windows, short))
            current = 0  # Spans ending at or before a token cannot touch later tokens.
            for (index, start, end), first in zip(run if spans else (), offsets, strict=False):
                after = first + end - start
                while current < len(spans) and spans[current][1] <= first:
                    current += 1
                if current < len(spans) and spans[current][0] < after:
                    line = lines[index]
                    lines[index] = line[:start] + "[redacted]" + line[end:].lstrip("=")
        run.clear()

    for index, line in enumerate(lines):
        start, end, size = _base64_tail(line)
        if size >= 4:
            run.append((index, start, end))
        elif size and run:
            run.append((index, start, end))  # A short last line closes the run.
            flush()
        else:
            flush()
    flush()
    return "\n".join(lines)


def _redact_base64(text: str, secrets: tuple[str, ...]) -> str:
    """Redact base64 encodings of secrets, including partial and wrapped ones.

    First wrapped blocks (see ``_redact_wrapped_base64``), then every remaining
    base64 token that holds a window of an encoding, wherever it is on its line:
    this alone covers a block interleaved with other output, split across two
    calls (log batches are flushed every 0.25 s or 64 KiB) or wrapped at any
    width of at least BASE64_WINDOW + BASE64_STEP - 1 columns.

    Residual exposure: a piece of an encoding cut off from the rest by an
    interleaved line, a batch boundary or a prefix glued to the token with
    base64 characters survives if it is shorter than 15 base64 characters
    (BASE64_WINDOW + BASE64_STEP - 1, at most 10 secret bytes), or shorter than
    12 characters (at most 8 bytes) when it is at the start or end of its token.
    Secrets whose encoding is shorter than 15 characters (about 10 bytes) are only
    found whole, on one line or across a wrapped block.
    """
    windows, short = _base64_index(secrets)
    if not windows and not short:
        return text
    text = _redact_wrapped_base64(text, windows, short)
    if not windows:
        return text
    return _BASE64_TOKEN.sub(
        lambda match: "[redacted]" if _probe(match[1], windows) else match[0],
        text,
    )


def _distinctive(fragment: str) -> bool:
    """A short line that looks like a credential, not like ordinary text."""
    return (
        not any(c.isspace() for c in fragment)
        and any(c.isdigit() for c in fragment)
        and any(c.isalpha() for c in fragment)
    )


@functools.lru_cache(maxsize=16)
def _secret_forms(secrets: tuple[str, ...]) -> tuple[str, ...]:
    forms: set[str] = set()
    for secret in secrets:
        if not secret.strip():
            continue  # A blank value would replace every space or newline in the log.
        forms |= _base64_forms(secret.encode())
        # These encodings are never shorter than the value itself.
        forms |= {
            secret,
            json.dumps(secret)[1:-1],
            json.dumps(secret, ensure_ascii=False)[1:-1],
            urllib.parse.quote(secret, safe=""),
        }
        # Logs are line-oriented and stripped of control characters: also cover
        # the normalised value and each line of a multi-line secret.
        normalised = strip_controls(secret)
        if len(normalised) >= MIN_SECRET_FRAGMENT:
            forms.add(normalised)
        for line in re.split(r"\r\n|\r|\n", secret):
            for fragment in (line.strip(), strip_controls(line).strip()):
                if _PEM_ARMOR.fullmatch(fragment):
                    continue
                # A password line printed on its own, but not "clusters:" or "name: a".
                if len(fragment) >= MIN_SECRET_LINE or (
                    len(fragment) >= MIN_SECRET_FRAGMENT and _distinctive(fragment)
                ):
                    forms.add(fragment)
    forms.discard("")
    return tuple(sorted(forms, key=len, reverse=True))


def redaction_values(ci: dict[str, str], review: dict[str, str]) -> list[str]:
    """Indexed review-provider names are public metadata. Their credentials remain secret."""
    return [*ci.values(), *(v for k, v in review.items() if not re.fullmatch(r"LLM_PROVIDER_[0-9]+", k))]


def redact(text: str, secrets: list[str]) -> str:
    key = tuple(secrets)
    for form in _secret_forms(key):
        text = text.replace(form, "[redacted]")
    text = _redact_base64(text, key)
    return re.sub(r"(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)", "[redacted]", text)


def sanitize(text: str, secrets: list[str]) -> str:
    """Redact, strip escapes/control characters, then redact again.

    The first pass catches secrets that themselves contain stripped characters;
    the second catches secrets split by escapes that stripping rejoined. When
    stripping changed nothing, the second pass would see the first pass's own
    output again and is skipped.
    """
    first = redact(text, secrets)
    stripped = strip_controls(first)
    return first if stripped == first else redact(stripped, secrets)


AGENT_FILES = {
    "agents.md",
    "agents.override.md",
    "claude.md",
    "claude.local.md",
    "gemini.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    "opencode.json",
    "opencode.jsonc",
    ".mcp.json",
}
AGENT_PREFIXES = (".aider",)
# Generic names that are agent rule files at the top of a repository but ordinary
# documentation deeper in the tree (docs/agent.md, docs/CONTEXT.md).
ROOT_AGENT_FILES = {"agent.md", "context.md"}
AGENT_DIRS = {
    ".cursor",
    ".claude",
    ".opencode",
    ".mergecraft",
    ".agents",
    ".clinerules",
    ".windsurf",
    ".gemini",
    ".roo",
    ".kiro",
    ".junie",
}
# Entries that are agent configuration only inside a particular directory.
SCOPED_AGENT_ENTRIES = {
    ".github": {"copilot-instructions.md", "instructions", "prompts", "chatmodes", "agents"},
    ".vscode": {"mcp.json"},
}


_DOTENV_KEY = re.compile(r"[A-Za-z0-9_.]+")  # What godotenv accepts as a name (ASCII subset).
_DOTENV_BLANK = " \t\v\f\r\x85\xa0"  # godotenv's isSpace: trimmed around unquoted values.


def _dotenv_value(value: str, unused: str) -> str:
    """One value for act's ``--secret-file``/``--var-file``, read by joho/godotenv v1.5.1.

    Single-quoted values are taken literally, but the closing quote must not follow
    a backslash. Double-quoted values get backslash escapes (``\\n``, ``\\r``, and a
    backslash before any other character drops it) and then ``$NAME`` expansion,
    which ``\\$`` prevents; a value must not end in ``"`` either, since quote
    characters at both ends are trimmed: an empty expansion of a name that is not
    in the file is appended to keep it. Unquoted values are trimmed, lose a
    `` #comment`` and get ``$`` expansion: used only for a value ending in a
    backslash, which neither quoted form can hold.
    """
    if not any(c in value for c in "'\n\r") and not value.endswith("\\"):
        return f"'{value}'"
    if not value.endswith("\\"):
        escaped = "".join(
            {"\\": "\\\\", '"': '\\"', "$": "\\$", "\n": "\\n", "\r": "\\r"}.get(c, c) for c in value
        )
        return f'"{escaped}' + ("${" + unused + "}" if value.endswith('"') else "") + '"'
    unquoted_safe = (
        not any(c in value for c in "\n\r")
        and value[:1] not in ("'", '"', *_DOTENV_BLANK)
        and value[-1:] not in _DOTENV_BLANK
        and not any(value[i] == "#" and value[i - 1] in _DOTENV_BLANK for i in range(1, len(value)))
    )
    if unquoted_safe:
        return value.replace("$", "\\$")
    raise RuntimeError("A variable or secret value ending in a backslash cannot be passed to act unchanged")


def dotenv_file(values: dict[str, str]) -> str:
    """The ``KEY=value`` file act reads with godotenv, every value preserved exactly.

    The only encoder for act's secret and variable files: unquoted ``KEY=value``
    would lose `` #...`` and surrounding blanks and expand ``$VAR``; JSON
    double-quoting additionally mangles ``\\uXXXX`` escapes. Non-ASCII is written
    as UTF-8.
    """
    unused = "LOCALCI_EMPTY"
    while unused in values:
        unused += "_"
    lines = []
    for key, value in values.items():
        if not _DOTENV_KEY.fullmatch(key):
            raise RuntimeError(f"Name {key!r} is not usable in act's secret or variable files")
        lines.append(f"{key}={_dotenv_value(str(value), unused)}\n")
    return "".join(lines)


def docker_env_file(values: dict[str, str]) -> str:
    """A ``docker --env-file``: everything after ``=`` is literal (no quotes, comments
    or expansion) and a line is one variable, so values cannot hold line breaks."""
    lines = []
    for key, value in values.items():
        if not key or any(c in key for c in "= \t\r\n\0") or key.startswith("#"):
            raise RuntimeError(f"Name {key!r} is not usable in the review environment")
        if any(c in value for c in "\r\n\0"):
            raise RuntimeError(
                f"Value of {key} contains a line break or NUL and cannot be passed to the review"
            )
        lines.append(f"{key}={value}\n")
    return "".join(lines)


# Run with ``sh -c`` in the CI worker (docker:dind, busybox): remove every container on
# the nested daemon and verify none is left. No ``xargs -r``, which busybox builds may
# lack: an empty list must not run ``docker rm`` (it would fail without arguments).
NESTED_CLEANUP = (
    'ids=$(docker ps -aq) && { [ -z "$ids" ] || docker rm -f $ids >/dev/null; } && [ -z "$(docker ps -aq)" ]'
)


WORKER_RUNTIMES = {"privileged": ["--privileged"], "sysbox-runc": ["--runtime=sysbox-runc"]}


def worker_runtime() -> str:
    """The CI worker's container runtime, from LOCALCI_WORKER_RUNTIME.

    ``privileged`` (the default) runs Docker-in-Docker with ``--privileged``.
    ``sysbox-runc`` runs it as a Sysbox system container, which the host must have
    installed and registered as a Docker runtime. ``docker cp`` cannot write into a
    Sysbox container's filesystem, so files are streamed with tar in that mode.
    """
    value = os.environ.get("LOCALCI_WORKER_RUNTIME", "").strip() or "privileged"
    if value not in WORKER_RUNTIMES:
        raise RuntimeError(
            f"LOCALCI_WORKER_RUNTIME must be one of {', '.join(WORKER_RUNTIMES)}; got {value!r}"
        )
    return value


def nested_network_arguments() -> list[str]:
    """dockerd address options for the nested daemon, from LOCALCI_NESTED_BIP and
    LOCALCI_NESTED_ADDRESS_POOL; neither is passed when unset.

    By default the nested daemon gives its docker0 Docker's default bridge address.
    On a host whose daemon sends container DNS to a resolver on the host's own
    docker0 (``"dns"`` in daemon.json set to that address), the nested docker0 then
    holds the resolver's address: the worker's lookups reach its own bridge, where
    nothing answers, and every image pull fails with "server misbehaving". Setting
    ranges that are unused on the host avoids that.
    """
    bip = os.environ.get("LOCALCI_NESTED_BIP", "").strip()
    pool = os.environ.get("LOCALCI_NESTED_ADDRESS_POOL", "").strip()
    args = []
    try:
        interface = ipaddress.ip_interface(bip) if bip else None
        network = ipaddress.ip_network(pool) if pool else None
    except ValueError:
        raise RuntimeError(
            "LOCALCI_NESTED_BIP must be an IPv4 address with prefix and LOCALCI_NESTED_ADDRESS_POOL an IPv4 "
            f"network; got {bip!r} and {pool!r}"
        ) from None
    if interface is not None:
        if interface.version != 4:
            raise RuntimeError(f"LOCALCI_NESTED_BIP must be an IPv4 address with prefix; got {bip!r}")
        args.append(f"--bip={bip}")
    if network is not None:
        if network.version != 4 or network.prefixlen > 24:
            raise RuntimeError(
                f"LOCALCI_NESTED_ADDRESS_POOL must be an IPv4 network of /24 or larger; got {pool!r}"
            )
        args.append(f"--default-address-pool=base={pool},size=24")
    if interface is not None and network is not None and interface.network.overlaps(network):
        raise RuntimeError("LOCALCI_NESTED_BIP must not overlap LOCALCI_NESTED_ADDRESS_POOL")
    return args


def nested_dns_arguments() -> list[str]:
    """dockerd ``--dns`` options for the nested daemon, from LOCALCI_NESTED_DNS.

    On its per-run network the worker resolves through Docker's embedded DNS at a
    loopback address, which containers on the nested daemon's own bridge cannot
    reach; that daemon then falls back to public resolvers. Hosts that need
    internal names inside ``docker build``/``docker run`` steps list their
    resolvers here (comma-separated IP addresses).
    """
    servers = [s.strip() for s in os.environ.get("LOCALCI_NESTED_DNS", "").split(",") if s.strip()]
    for server in servers:
        try:
            if "%" in server:  # dockerd rejects zoned addresses and would not start.
                raise ValueError(server)
            ipaddress.ip_address(server)
        except ValueError:
            raise RuntimeError(
                f"LOCALCI_NESTED_DNS must be comma-separated IP addresses without a zone; got {server!r}"
            ) from None
    return [f"--dns={server}" for server in servers]


def remove_agent_configuration(root: Path) -> list[str]:
    """Delete PR-authored agent instructions/configuration at any depth, case-insensitively.

    Never follows symlinks: a matching link is unlinked itself, and linked
    directories are not descended into. A link named like a directory that holds
    agent configuration (``.github``, ``.vscode``, ``.claude``...) is unlinked too:
    its scoped entries (``copilot-instructions.md``, ``mcp.json``) would otherwise
    stay readable through it, under a target whose own name does not match.
    ``.git`` is skipped.
    """
    removed = []
    for directory, dirs, files in os.walk(root, topdown=True, followlinks=False):
        parent = Path(directory)
        kept = []
        for name in [*dirs, *files]:
            lowered = name.casefold()
            if name == ".git" and parent == root:
                continue
            match = (
                lowered in AGENT_FILES
                or lowered in AGENT_DIRS
                or lowered.startswith(AGENT_PREFIXES)
                or (parent == root and lowered in ROOT_AGENT_FILES)
                or lowered in SCOPED_AGENT_ENTRIES.get(parent.name.casefold(), ())
            )
            target = parent / name
            if not match and lowered in SCOPED_AGENT_ENTRIES:
                match = target.is_symlink()  # The link only; its target is never touched.
            if not match:
                if name in dirs:
                    kept.append(name)
                continue
            if target.is_symlink() or not target.is_dir():
                target.unlink()
            else:
                shutil.rmtree(target)
            removed.append(str(target.relative_to(root)))
        dirs[:] = [d for d in dirs if d in kept]
    return removed


def read_export(path: Path, limit: int) -> bytes | None:
    """Read a file copied out of a container: regular file only, no links, bounded.

    Anything else at the path (symlink, FIFO, device, directory, oversized file)
    is removed so later readers cannot block on it or follow it.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError:
        fd = None
    data = None
    if fd is not None:
        try:
            info = os.fstat(fd)
            if stat.S_ISREG(info.st_mode) and info.st_size <= limit:
                with os.fdopen(fd, "rb", closefd=False) as handle:
                    data = handle.read(limit + 1)
                if len(data) > limit:
                    data = None
        finally:
            os.close(fd)
    if data is None:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path, ignore_errors=True)
        else:
            with contextlib.suppress(FileNotFoundError):
                path.unlink()
    return data


def offline_review_prompt(head: str, base: str) -> str:
    return (
        "Local CI execution context (authoritative for source/scope acquisition): "
        "this is an offline diff review. This context supersedes repository guidance "
        "about GitHub PR API calls, checkout_pr or GitHub Actions scope acquisition. "
        "Retain all domain-specific review criteria and verification requirements. "
        "Scope is already established from /control/review.patch; there is no GitHub "
        "PR API in this container. "
        f"HEAD is {head}; base is {base}. "
        "Do not rediscover the PR, branch or merge-base. Use the supplied full "
        "diff and read every changed file before the terminal verdict. "
        "Plan related reads together and issue independent reads in the same model turn. "
        "Read every changed hunk with its surrounding functions, types and relevant callers; "
        "expand context whenever necessary to verify a finding. Reuse already-read ranges "
        "instead of repeatedly loading entire large files. The full source remains available. "
        "Do not skip scope, analyzers, verification or unresolved coverage to save tokens. "
        "For git grep put all options "
        "before the pattern, revision and -- paths. Unsupported commands must "
        "not be retried unchanged. Reuse precomputed analyzer results. "
        "Retain all required verification and report coverage gaps honestly. "
        "Finish with a concise written review explaining scope, evidence, "
        "findings and remaining uncertainty."
    )


class Runner:
    def __init__(self, store: Store, github: GitHub, root: Path, secret_reader):
        self.store, self.github, self.root, self.secret_reader = store, github, root, secret_reader
        self.log_path = root / "unused"
        self.run: dict = {}
        self.sensitive: list[str] = []
        self.deadline = 0.0
        self.completed_jobs = 0
        self._lane = ContextVar("runner_lane", default="setup")
        self._phases: dict[str, str] = {}
        self._write_lock = threading.RLock()
        self.phase = "Setup"
        self.event_count = 0
        self.review_events: dict[str, dict] = {}

    @property
    def phase(self):
        return self._phases.get(self._lane.get(), "Setup")

    @phase.setter
    def phase(self, value):
        self._phases[self._lane.get()] = value

    def log(self, text: str):
        with self._write_lock:
            self._log(text)

    def _log(self, text: str):
        # Capture only bounded terminal protocol fields, even after log retention caps.
        if self._lane.get() == "review":
            for line in text.splitlines():
                event = terminal_event(line)
                if event:
                    if event["event"] == "verdict":
                        self.review_events.pop("run_finished", None)
                    self.review_events[event["event"]] = event
        if self._lane.get() != "review":
            for line in text.splitlines():
                parsed = re.match(r"^\[([^]]+)\] ?(.*)", line)
                if parsed and ci_report.job_result(parsed[1], parsed[2]) == "success":
                    self.completed_jobs += 1
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if self.log_path.exists() and self.log_path.stat().st_size > 8_000_000:
            return
        clean = sanitize(text, self.sensitive)
        events = []
        with self.log_path.open("a") as f:
            for line in clean.splitlines():
                timestamp = time.time()
                stamp = datetime.fromtimestamp(timestamp, UTC).isoformat(timespec="milliseconds")
                f.write(f"{stamp} {line}\n")
                if self.run.get("id") and self.event_count < 50000:
                    # Consume act's single separator only. Extra indentation identifies
                    # step output and must reach the shared result recognizer intact.
                    parsed = re.match(r"^\[([^]]+)\] ?(.*)", line)
                    job = parsed[1] if parsed else ""
                    raw_message = parsed[2] if parsed else line
                    result = ci_report.job_result(job, raw_message) if self._lane.get() != "review" else None
                    message = raw_message.lstrip()
                    if (
                        not result
                        and raw_message != message
                        and re.fullmatch(r"\s*🏁  Job (?:succeeded|failed)\s*", raw_message)
                    ):
                        # Keep forged result-looking output distinguishable in the index.
                        message = raw_message
                    level = (
                        "error"
                        if re.search(
                            r"error|failed|failure|❌|command not found|permission denied", message, re.I
                        )
                        else "info"
                    )
                    events.append((self.run["id"], timestamp, self.phase, job, level, message))
                    self.event_count += 1
        self.store.append_events(events)

    def cancelled(self):
        rows = self.store.rows("SELECT cancel FROM runs WHERE id=?", (self.run["id"],))
        if rows and rows[0]["cancel"]:
            raise Cancelled("Cancelled by operator or superseded PR revision")
        if time.monotonic() > self.deadline:
            raise TimeoutError("Run exceeded its wall-clock limit")

    async def command(
        self,
        *args: str,
        cwd: Path | None = None,
        env: dict | None = None,
        capture: bool = False,
        check: bool = True,
        max_seconds: int = 3600,
        honor_cancel: bool = True,
        output: Path | None = None,
        quiet: bool = False,
        stdin_file: Path | None = None,
        stdout_file: Path | None = None,
    ) -> tuple[int, str]:
        """Run a command; ``honor_cancel=False`` is for bounded cleanup that must run anyway.

        Uncaptured, stdout and stderr go to the run log together, in order. With
        ``capture`` stdout is returned as text instead (undecodable bytes replaced);
        with ``output`` its exact bytes are written to that file (review.patch) and
        "" is returned. Captured stdout is never logged and at most 2 MB. A captured
        command's stderr still goes to the run log, sanitized like any output, so
        warnings stay visible without corrupting the captured data; ``quiet``
        discards it instead, for probes whose failure is expected and already
        reported by the caller (an optional file that is absent, a daemon that is
        not ready yet).

        ``stdin_file`` feeds a file to the command's stdin; ``stdout_file`` writes its
        stdout to a file without the capture limit, with stderr logged as for a
        captured command. Both are for tar streams into and out of a Sysbox worker.
        """
        if honor_cancel:
            await asyncio.to_thread(self.cancelled)
        captured = capture or output is not None
        if not captured and stdout_file is None:
            stderr = asyncio.subprocess.STDOUT
        else:
            stderr = asyncio.subprocess.DEVNULL if quiet else asyncio.subprocess.PIPE
        with contextlib.ExitStack() as files:
            stdin = files.enter_context(stdin_file.open("rb")) if stdin_file else None
            stdout = files.enter_context(stdout_file.open("wb")) if stdout_file else asyncio.subprocess.PIPE
            proc = await asyncio.create_subprocess_exec(
                *args,
                cwd=cwd,
                env=env,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
        data = bytearray()

        async def collect(stream: asyncio.StreamReader):
            # Byte-exact: workflow files and review.patch must not be altered, so long
            # lines are kept and nothing is decoded here; only the total size is bounded.
            while chunk := await stream.read(65536):
                data.extend(chunk)
                if len(data) > CAPTURE_LIMIT:
                    raise RuntimeError("Command output exceeded limit")

        async def log_lines(stream: asyncio.StreamReader):
            pending = b""
            # True while skipping the rest of a line already known to exceed the limit.
            oversized = False
            lines: list[str] = []
            buffered = 0
            last_flush = time.monotonic()

            async def flush(hold: bool = False):
                nonlocal buffered, last_flush
                # Bound commit frequency during verbose scanners without delaying
                # sparse live output. The raw log and structured index stay aligned.
                # A batch flushed while output continues keeps back its trailing lines
                # that end in base64 (bounded): a wrapped encoding is then redacted
                # with its neighbouring lines in one batch instead of in two.
                keep, kept = 0, 0
                while hold and keep < len(lines) and kept + len(lines[-1 - keep]) <= HELD_BYTES:
                    if not _plausible_base64_line(lines[-1 - keep].rstrip("\n")):
                        break
                    kept += len(lines[-1 - keep])
                    keep += 1
                ready = len(lines) - keep
                if ready:
                    await asyncio.to_thread(self.log, "".join(lines[:ready]))
                    del lines[:ready]
                    buffered = kept
                last_flush = time.monotonic()

            def emit(text: str):
                nonlocal buffered
                lines.append(text)
                buffered += len(text)

            while True:
                try:
                    chunk = await asyncio.wait_for(stream.read(65536), timeout=0.25)
                except TimeoutError:
                    await flush()
                    continue
                if not chunk:
                    break
                start = 0
                while True:
                    end = chunk.find(b"\n", start)
                    piece = chunk[start:] if end < 0 else chunk[start:end]
                    if not oversized and len(pending) + len(piece) > OUTPUT_LINE_LIMIT:
                        # Drop the entire line, including its tail, so no secret fragment survives.
                        oversized, pending = True, b""
                        emit(OVERSIZED_LINE)
                    if end < 0:
                        if not oversized:
                            pending += piece  # bounded by the line limit
                        break
                    if oversized:
                        oversized = False
                    else:
                        emit((pending + piece).decode(errors="replace") + "\n")
                    pending = b""
                    start = end + 1
                if buffered >= 65536 or time.monotonic() - last_flush >= 0.25:
                    await flush(hold=True)
            if pending and not oversized:
                emit(pending.decode(errors="replace"))
            await flush()

        readers = []
        if proc.stdout:
            readers.append(asyncio.create_task(collect(proc.stdout) if captured else log_lines(proc.stdout)))
        if (captured or stdout_file is not None) and proc.stderr:
            readers.append(asyncio.create_task(log_lines(proc.stderr)))
        start = time.monotonic()
        try:
            while proc.returncode is None:
                if honor_cancel:
                    await asyncio.to_thread(self.cancelled)
                if time.monotonic() - start > max_seconds:
                    raise TimeoutError(f"{args[0]} exceeded timeout")
                for reader in readers:
                    if reader.done() and reader.exception():
                        raise reader.exception()  # type: ignore[misc]
                await asyncio.sleep(0.4)
            for reader in readers:
                await reader
        finally:
            if proc.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(proc.pid, 9)
                await proc.wait()
            for reader in readers:
                reader.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await reader
        code = proc.returncode or 0
        if code and check:
            raise RuntimeError(f"{args[0]} exited {code}; see run log")
        if output is not None:
            output.write_bytes(bytes(data))
            return code, ""
        return code, data.decode(errors="replace")

    async def copy_to_worker(self, name: str, source: Path, dest: str, sysbox: bool, max_seconds: int = 3600):
        """Copy a file or directory to ``dest`` in the CI worker, as ``docker cp`` would."""
        if not sysbox:
            await self.command("docker", "cp", str(source), f"{name}:{dest}", max_seconds=max_seconds)
            return
        parent, target = posixpath.split(dest.rstrip("/"))
        with tempfile.NamedTemporaryFile(dir=source.parent, prefix=".localci-", suffix=".tar") as archive:

            def pack():
                with tarfile.open(fileobj=archive, mode="w") as bundle:
                    bundle.add(source, arcname=target)
                archive.flush()

            await asyncio.to_thread(pack)
            await self.command(
                "docker",
                "exec",
                "-i",
                name,
                "tar",
                "-xf",
                "-",
                "-C",
                parent or "/",
                stdin_file=Path(archive.name),
                max_seconds=max_seconds,
            )

    async def copy_artifacts_from_worker(self, name: str, dest: Path, sysbox: bool):
        """Copy the worker's /artifacts tree into ``dest``; missing artifacts are not an error."""
        if not sysbox:
            await self.command("docker", "cp", f"{name}:/artifacts/.", str(dest), check=False)
            return
        with tempfile.NamedTemporaryFile(dir=dest.parent, prefix=".localci-", suffix=".tar") as archive:
            code, _ = await self.command(
                "docker",
                "exec",
                name,
                "tar",
                "-C",
                "/artifacts",
                "-cf",
                "-",
                ".",
                stdout_file=Path(archive.name),
                check=False,
            )
            if code:
                return

            def unpack():
                # Regular files and directories only, never outside dest: the tar stream
                # comes from a worker that ran PR code.
                def regular(member, path):
                    return tarfile.data_filter(member, path) if member.isfile() or member.isdir() else None

                with tarfile.open(archive.name, "r") as bundle:
                    bundle.extractall(dest, filter=regular)

            try:
                await asyncio.to_thread(unpack)
            except (tarfile.TarError, OSError) as exc:
                await asyncio.to_thread(self.log, f"Could not copy CI artifacts: {exc}\n")

    async def _quiet_docker(self, *args: str) -> str:
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
            )
        except OSError:
            return ""
        try:
            output, _ = await asyncio.wait_for(proc.communicate(), 30)
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            return ""
        return output.decode(errors="replace")

    async def cleanup(self, name: str):
        """Remove a run container (idempotent). Never the run network: _finalize
        removes it once the run is finished and the CI worker attached to it is gone."""
        await self._quiet_docker("rm", "-fv", name)

    async def remove_network(self, name: str):
        """Remove a per-run network, waiting briefly for its last container to detach.

        Container removal can outlive its own time limit; a network left behind is
        removed by the worker's sweep, but each one occupies a Docker address pool.
        """
        for delay in (0, 2, 5, 10):
            await asyncio.sleep(delay)
            await self._quiet_docker("network", "rm", name)
            listing = await self._quiet_docker(
                "network", "ls", "--filter", f"name={name}", "--format", "{{.Name}}"
            )
            if name not in listing.split():
                return

    async def cleanup_networks(self):
        """Remove every leftover per-run network (for startup sweeps); in-use ones are kept."""
        listing = await self._quiet_docker("network", "ls", "-q", "--filter", "label=localci.worker=true")
        for network in listing.split():
            await self._quiet_docker("network", "rm", network)

    def step(self, name: str, state: str, message: str = "", **details):
        with self._write_lock:
            self._step(name, state, message, **details)

    def _step(self, name: str, state: str, message: str = "", **details):
        steps = json.loads(
            self.store.rows("SELECT steps FROM runs WHERE id=?", (self.run["id"],))[0]["steps"]
        )
        entry = next((s for s in steps if s["name"] == name), None)
        now = time.time()
        if entry:
            entry.update(state=state, message=message)
        else:
            entry = {"name": name, "state": state, "message": message, "started": now}
            steps.append(entry)
        entry.update(details)
        if state == "running":
            self.phase = name
            entry["started"] = now
            entry.pop("finished", None)
        elif state != "queued":
            entry["finished"] = now
        self.store.execute(
            "UPDATE runs SET steps=?,published=0 WHERE id=?", (json.dumps(steps), self.run["id"])
        )

    async def execute(self, run: dict):
        self.run = run
        config = json.loads(run["config"])
        pr = json.loads(run["snapshot"])
        skip_review = bool(config.get("review") and dependabot_pr(pr))
        run_review = bool(config.get("review") and not skip_review)
        self.deadline = time.monotonic() + config.get("timeout", 7200)
        work = self.root / "work" / run["id"]
        checkout, control = work / "repo", work / "control"
        self.log_path = self.root / "logs" / f"{run['id']}.log"
        name = f"localci-run-{run['id']}"
        review_name = name + "-review"
        network = name
        metrics = None
        resources = config.get("execution", {})
        final_state, message = "success", "All configured checks passed"
        end_reason = None
        executed = 0  # CI jobs that ran, plus the review.
        ci_jobs = 0  # CI jobs alone: a passing review must not stand in for CI that never ran.
        try:
            work.mkdir(parents=True, mode=0o700)
            control.mkdir()
            token = self.github.token()
            secrets = self.secret_reader(run["repo"], "ci")
            review_secrets = self.secret_reader(run["repo"], "review") if run_review else {}
            if config.get("github_auth") == "gh":
                secrets = {**secrets, "GITHUB_TOKEN": token, "GH_TOKEN": token}
            self.sensitive = [token, *redaction_values(secrets, review_secrets)]
            metrics = asyncio.create_task(sample_resources(self.store, run["id"], {name, review_name}))
            if skip_review:
                await asyncio.to_thread(
                    self.step,
                    "mergeCraft",
                    "skipped",
                    "Dependabot PR: mergeCraft review is disabled; CI still runs",
                )
            await asyncio.to_thread(self.step, "Checkout", "running")
            basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
            self.sensitive.append(basic)
            git_env = {
                **os.environ,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
                "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}",
            }
            await self.command(
                "git",
                "clone",
                "--no-checkout",
                "--",
                f"https://github.com/{run['repo']}.git",
                str(checkout),
                env=git_env,
                max_seconds=600,
            )
            for sha in (run["head"], run["base"]):
                if not re.fullmatch(r"[0-9a-f]{40}", sha):
                    raise Blocked("Invalid GitHub commit SHA")
                await self.command("git", "fetch", "origin", sha, cwd=checkout, env=git_env, max_seconds=300)
            await self.command("git", "checkout", "--detach", run["base"], cwd=checkout)
            # Pin workflows to the trusted base. The tested tree is a real merge, like PR CI on GitHub.
            prepared = []
            workflow_secrets: dict[str, set[str]] = {}
            blockers = []
            files = workflow_files(config.get("workflows", []))
            for path, filename in files.items():
                override = config.get("workflow_overrides", {}).get(path)
                if override:
                    text = override["content"]
                    origin = (
                        "uploaded or pasted here"
                        if is_local_workflow(path)
                        else f"imported from {override['source_ref']}"
                    )
                    await asyncio.to_thread(
                        self.log, f"Using local workflow v{override['version']}: {path} ({origin})\n"
                    )
                elif is_local_workflow(path):
                    # Deleted after it was selected: there is nothing in the repository to fall back to.
                    blockers.append(
                        f"{path}: this local workflow was deleted; unselect it in repository settings"
                    )
                    await asyncio.to_thread(self.step, filename, "blocked", blockers[-1])
                    continue
                else:
                    code, text = await self.command(
                        "git",
                        "show",
                        f"{run['base']}:{path}",
                        cwd=checkout,
                        capture=True,
                        check=False,
                        quiet=True,
                    )
                    if code:
                        blockers.append(f"{path}: not found in base commit {run['base'][:12]}")
                        await asyncio.to_thread(self.step, filename, "blocked", blockers[-1])
                        continue
                    await asyncio.to_thread(
                        self.log,
                        f"Using GitHub base {run['base'][:12]}: {path}; "
                        f"executing on {os.environ.get('LOCALCI_HOST_LABEL', 'local worker')}\n",
                    )
                try:
                    data, notes = plan(text, set(secrets), config.get("variables", {}))
                    destination = control / filename
                    destination.write_text(yaml.safe_dump(data, sort_keys=False))
                    names, dynamic = secret_references(data)
                    # Enabling host GitHub login is the operator's opt-in for every selected
                    # workflow: actions default their token input to github.token without
                    # naming it, so withholding it from "non-referencing" workflows breaks them.
                    if "GITHUB_TOKEN" in secrets or github_token_referenced(data):
                        names.add("GITHUB_TOKEN")
                    workflow_secrets[destination.name] = (
                        set(secrets) if dynamic else {n.upper() for n in names}
                    )
                    prepared.append(destination.name)
                    await asyncio.to_thread(self.log, "\n".join(notes) + "\n")
                except Blocked as exc:
                    blockers.append(str(exc))
                    await asyncio.to_thread(self.step, filename, "blocked", str(exc))
            code, _ = await self.command(
                "git",
                "-c",
                "user.name=Local CI",
                "-c",
                "user.email=localci@localhost",
                "merge",
                "--no-ff",
                "--no-edit",
                run["head"],
                cwd=checkout,
                check=False,
            )
            if code:
                raise Blocked("PR does not merge cleanly into its base; resolve conflicts first")
            _, tested_sha = await self.command("git", "rev-parse", "HEAD", cwd=checkout, capture=True)
            await asyncio.to_thread(
                self.step,
                "Checkout",
                "success",
                f"Testing merge {tested_sha.strip()[:12]} of {run['head'][:12]} into {run['base'][:12]}",
            )
            event = {
                "action": "synchronize",
                "number": pr["number"],
                "pull_request": pr,
                "repository": pr["base"]["repo"],
                "sender": pr["user"],
            }
            (control / "event.json").write_text(json.dumps(event))
            (control / "vars").write_text(dotenv_file(config.get("variables", {})), encoding="utf-8")
            # Values referenced by each workflow; written and copied into the worker only
            # for the duration of that workflow's act invocation (see ci_phase), never
            # via argv/logs. With host GitHub login enabled, every workflow also gets the token.
            # Privileged CI remains host-root-equivalent and jobs of the SAME workflow
            # share its secrets and worker: this is least exposure, not a sandbox boundary.
            workflow_values = {
                filename: {
                    k: v
                    for k, v in secrets.items()
                    if k in workflow_secrets[filename] or k.upper() in workflow_secrets[filename]
                }
                for filename in prepared
            }
            ci_secret_dir = work / "ci-secrets"
            if not prepared and (not run_review or not review_secrets):
                if run_review and not review_secrets:
                    await asyncio.to_thread(
                        self.step, "mergeCraft", "blocked", "Configure a local review provider credential"
                    )
                    blockers.append("mergeCraft requires a locally configured provider credential")
                raise Blocked("; ".join(blockers) or "No CI workflows selected")
            artifact_dir = self.root / "artifacts" / run["id"]
            artifact_dir.mkdir(parents=True, exist_ok=True)
            # Separate outer containers, repository exports and credential paths allow
            # review and CI to overlap without exposing review credentials to CI.
            # Both container limits together stay within the configured run budget.
            total_cpus = resources.get("cpus_per_run", 8)
            total_memory = resources.get("memory_gb_per_run", 24)
            parallel = bool(prepared and run_review and review_secrets)
            review_cpus = min(2, total_cpus / 4) if parallel else min(4, total_cpus)
            review_memory = min(4, total_memory / 4) if parallel else min(8, total_memory)
            ci_cpus = total_cpus - review_cpus if parallel else total_cpus
            ci_memory = total_memory - review_memory if parallel else total_memory
            for filename in prepared:
                await asyncio.to_thread(self.step, filename, "queued")
            if run_review:
                await asyncio.to_thread(self.step, "mergeCraft", "queued")

            async def remove_worker_secrets(filename: str) -> bool:
                (ci_secret_dir / f"{filename}.secrets").unlink(missing_ok=True)
                try:
                    code, _ = await self.command(
                        "docker",
                        "exec",
                        name,
                        "rm",
                        "-f",
                        f"/control/{filename}.secrets",
                        check=False,
                        capture=True,
                        max_seconds=60,
                        honor_cancel=False,
                    )
                except Exception:
                    return False
                return code == 0

            async def remove_nested_containers() -> bool:
                # Every container on the nested daemon, verified gone: a job of the
                # previous workflow could otherwise leave one running (detached, with
                # /control mounted) to read the next workflow's secrets file.
                try:
                    code, _ = await self.command(
                        "docker",
                        "exec",
                        name,
                        "sh",
                        "-c",
                        NESTED_CLEANUP,
                        check=False,
                        capture=True,
                        max_seconds=120,
                        honor_cancel=False,
                    )
                except Exception:
                    return False
                return code == 0

            async def ci_phase():
                nonlocal executed, ci_jobs, final_state, message
                if prepared:
                    runtime = worker_runtime()
                    sysbox = runtime == "sysbox-runc"
                    # A user-defined bridge per run, for the CI worker only: concurrent runs
                    # cannot reach each other's artifact server or job service ports over
                    # Docker's shared default bridge. Named after the worker container;
                    # removed only by _finalize (remove_network), after the container.
                    await self.command(
                        "docker", "network", "rm", network, check=False, capture=True, quiet=True
                    )
                    await self.command(
                        "docker",
                        "network",
                        "create",
                        "--driver",
                        "bridge",
                        "--label",
                        "localci.worker=true",
                        network,
                    )
                    await self.command(
                        "docker",
                        "run",
                        "-d",
                        "--name",
                        name,
                        "--label",
                        "localci.worker=true",
                        "--network",
                        network,
                        *WORKER_RUNTIMES[runtime],
                        f"--memory={ci_memory}g",
                        f"--cpus={ci_cpus}",
                        "--pids-limit=8192",
                        "-e",
                        "DOCKER_TLS_CERTDIR=",
                        os.environ.get("LOCALCI_WORKER_IMAGE", "localci-worker:1"),
                        "--host=unix:///var/run/docker.sock",
                        *nested_network_arguments(),
                        *nested_dns_arguments(),
                    )
                    for _ in range(60):
                        code, _ = await self.command(
                            "docker", "exec", name, "docker", "info", capture=True, check=False, quiet=True
                        )
                        if code == 0:
                            break
                        await asyncio.sleep(1)
                    else:
                        raise RuntimeError("Docker worker failed to start")
                    await asyncio.to_thread(
                        self.log,
                        "Sysbox nested Docker ready. PR code runs in a user-namespaced system container "
                        "that shares the host kernel; trusted repositories only.\n"
                        if sysbox
                        else "Privileged nested Docker ready. PR code has host-root-equivalent access; "
                        "trusted repositories only.\n",
                    )
                    await self.copy_to_worker(name, checkout, "/workspace", sysbox)
                    await self.copy_to_worker(name, control, "/control", sysbox)
                    # Seed the local runner image, avoiding a full image download on every run.
                    if sysbox:
                        await self.command(
                            "docker",
                            "exec",
                            "-i",
                            name,
                            "docker",
                            "load",
                            stdin_file=Path("/opt/localci/runner-image.tar"),
                            max_seconds=600,
                        )
                    else:
                        await self.command(
                            "docker",
                            "cp",
                            "/opt/localci/runner-image.tar",
                            f"{name}:/runner-image.tar",
                            max_seconds=600,
                        )
                        await self.command(
                            "docker",
                            "exec",
                            name,
                            "sh",
                            "-c",
                            "docker load -i /runner-image.tar && rm /runner-image.tar",
                            max_seconds=600,
                        )
                    for index, filename in enumerate(prepared):
                        # Workflows share the worker and its nested daemon; fail closed if a
                        # previous workflow's containers cannot be removed. Still least
                        # exposure only: a privileged job can escape the nested daemon into
                        # the worker itself and outlive this cleanup.
                        if index and not await remove_nested_containers():
                            raise RuntimeError(
                                f"Could not remove containers left by the previous workflow from the "
                                f"CI worker; stopping CI before {filename}"
                            )
                        self.completed_jobs = 0
                        await asyncio.to_thread(self.step, filename, "running")
                        await asyncio.to_thread(self.log, f"\n--- {filename} ---\n")
                        args = [
                            "docker",
                            "exec",
                            "-w",
                            "/control",
                            name,
                            "act",
                            "pull_request",
                            "-C",
                            "/workspace",
                            "-W",
                            f"/control/{filename}",
                            "-e",
                            "/control/event.json",
                            "--actor",
                            pr["user"]["login"],
                            "--secret-file",
                            f"/control/{filename}.secrets",
                            "--var-file",
                            "/control/vars",
                            "--env-file",
                            "/dev/null",
                            "--input-file",
                            "/dev/null",
                            "--artifact-server-path",
                            "/artifacts",
                            "--artifact-server-addr",
                            "0.0.0.0",
                            "--artifact-server-port",
                            "34567",
                            "--network",
                            "host",
                            "--container-options",
                            "--init --security-opt seccomp=unconfined --shm-size=2g "
                            "--tmpfs /tmp:rw,exec,nosuid,size=4g,mode=1777",
                            "--pull=false",
                            "--concurrent-jobs",
                            str(config.get("job_parallelism", 1)),
                            "--rm",
                        ]
                        for label in ("ubuntu-latest", "ubuntu-24.04"):
                            args += ["-P", f"{label}=localci-jobs:1"]
                        for version in ("22.04", "20.04"):
                            args += ["-P", f"ubuntu-{version}=ghcr.io/catthehacker/ubuntu:act-{version}"]
                        # Only this workflow's secrets are present in the worker, and only
                        # while its act invocation runs; removed before the next starts.
                        ci_secret_dir.mkdir(mode=0o700, exist_ok=True)
                        secret_file = ci_secret_dir / f"{filename}.secrets"
                        secret_file.touch(mode=0o600)
                        secret_file.write_text(
                            dotenv_file({"GITHUB_TOKEN": "", **workflow_values[filename]}), encoding="utf-8"
                        )
                        removed = False
                        try:
                            await self.copy_to_worker(
                                name, secret_file, f"/control/{filename}.secrets", sysbox
                            )
                            code, _ = await self.command(*args, check=False)
                        finally:
                            removed = await remove_worker_secrets(filename)
                        if not removed:
                            raise RuntimeError(
                                f"Could not remove {filename} secrets from the CI worker; stopping CI"
                            )
                        executed += self.completed_jobs
                        ci_jobs += self.completed_jobs
                        state = "failure" if code else ("success" if self.completed_jobs else "skipped")
                        await asyncio.to_thread(
                            self.step,
                            filename,
                            state,
                            f"act exited {code}; {self.completed_jobs} jobs passed",
                        )
                        if code:
                            final_state, message = "failure", "One or more CI workflows failed"
                    # CI-controlled artifacts cannot overwrite review evidence.
                    ci_artifacts = artifact_dir / "ci"
                    ci_artifacts.mkdir(exist_ok=True)
                    await self.copy_artifacts_from_worker(name, ci_artifacts, sysbox)

            async def review_phase():
                nonlocal executed, final_state, message
                if run_review:
                    await asyncio.to_thread(self.step, "mergeCraft", "running")
                    if not review_secrets:
                        blockers.append("mergeCraft requires a locally configured provider credential")
                        await asyncio.to_thread(self.step, "mergeCraft", "blocked", blockers[-1])
                    else:
                        # Build an independent repository for review; linked worktree pointers cannot cross containers.
                        review_dir = work / "review-export"
                        await self.command("git", "clone", "--no-local", str(checkout), str(review_dir))
                        await self.command("git", "checkout", "--detach", run["head"], cwd=review_dir)
                        # Remove PR-authored agent configuration and prompt instructions at any depth.
                        removed = await asyncio.to_thread(remove_agent_configuration, review_dir)
                        if removed:
                            await asyncio.to_thread(
                                self.log,
                                f"Removed {len(removed)} PR-authored agent configuration entries from the review tree.\n",
                            )
                        code, base_config = await self.command(
                            "git",
                            "show",
                            f"{run['base']}:.mergecraft/config.yaml",
                            cwd=checkout,
                            capture=True,
                            check=False,
                            quiet=True,  # Optional file: absent in most repositories.
                        )
                        review_config = yaml.safe_load(base_config) if code == 0 else {}
                        review_config = review_config or {}
                        # Only the operator's snapshotted repo setting can override
                        # the trusted base budget; never load this from the PR head.
                        token_ceiling = config.get("review_token_ceiling")
                        try:
                            apply_review_token_ceiling(review_config, token_ceiling)
                        except ValueError as exc:
                            blockers.append(str(exc))
                            await asyncio.to_thread(self.step, "mergeCraft", "blocked", blockers[-1])
                            return
                        review_config.update(
                            push="disabled",
                            shell="disabled",
                            prApproveEnabled=False,
                            autoMergeEnabled=False,
                            trust={"selfReview": "off", "agentSandbox": "never"},
                        )
                        instructions = dict(review_config.get("modeInstructions") or {})
                        instructions["Review"] = (
                            str(instructions.get("Review", ""))
                            + "\n\n"
                            + offline_review_prompt(run["head"], run["base"])
                        )
                        review_config["modeInstructions"] = instructions
                        review_control = work / "review-control"
                        review_control.mkdir()
                        shutil.copyfile(
                            Path(__file__).with_name("review_bootstrap.py"),
                            review_control / "review-bootstrap.py",
                        )
                        (review_control / "review-config.yaml").write_text(yaml.safe_dump(review_config))
                        # The exact bytes of the diff (non-UTF-8 hunks included); git's
                        # warnings (e.g. the rename limit) go to the run log, not the patch.
                        await self.command(
                            "git",
                            "diff",
                            f"{run['base']}...{run['head']}",
                            cwd=checkout,
                            output=review_control / "review.patch",
                        )
                        review_timeout = config.get("review_timeout", 3000)
                        budget_env = (
                            {"MERGECRAFT_TOKEN_BUDGET": str(token_ceiling)}
                            if token_ceiling is not None
                            else {}
                        )
                        (work / "review-env").write_text(
                            docker_env_file(
                                {
                                    **review_secrets,
                                    "LOCALCI_PROFILE_PATH": "/tmp/mergecraft-profile.jsonl",
                                    "MERGECRAFT_NONINTERACTIVE": "1",
                                    "MERGECRAFT_ENV": "/dev/null",
                                    "MERGECRAFT_CONFIG": "/control/review-config.yaml",
                                    "MERGECRAFT_RUN_TIMEOUT_S": str(review_timeout),
                                    "MERGECRAFT_COST_BUDGET_USD": "5",
                                    **budget_env,
                                }
                            ),
                            encoding="utf-8",
                        )
                        (work / "review-env").chmod(0o600)
                        await asyncio.to_thread(
                            self.log,
                            f"Independent mergeCraft review: {review_timeout // 60} minute limit, $5 budget; "
                            + (
                                f"operator token ceiling {token_ceiling:,} (zero tolerance); "
                                if token_ceiling is not None
                                else "token budget from trusted base config; "
                            )
                            + "CI does not wait for review.\n",
                        )
                        await self.command(
                            "docker",
                            "create",
                            "--init",
                            "--name",
                            review_name,
                            "--label",
                            "localci.worker=true",
                            # No --network: Docker's default bridge gives the outbound access
                            # to the model provider it needs. The per-run network would also
                            # reach the privileged CI worker running PR code; user-defined
                            # bridges are isolated from the default bridge.
                            f"--memory={review_memory}g",
                            f"--cpus={review_cpus}",
                            "--pids-limit=1024",
                            "--env-file",
                            str(work / "review-env"),
                            "-w",
                            "/review",
                            "--entrypoint",
                            "python",
                            os.environ["LOCALCI_REVIEW_IMAGE"],
                            "/control/review-bootstrap.py",
                            "review",
                            "--diff",
                            "/control/review.patch",
                            "--agent",
                            "--prompt",
                            offline_review_prompt(run["head"], run["base"]),
                            "--json",
                            "/tmp/review.json",
                        )
                        await self.command("docker", "cp", str(review_dir) + "/.", f"{review_name}:/review")
                        await self.command("docker", "cp", str(review_control), f"{review_name}:/control")
                        _, review_image_id = await self.command(
                            "docker",
                            "inspect",
                            "--format",
                            "{{.Image}}",
                            review_name,
                            check=False,
                            capture=True,
                        )
                        review_started = time.monotonic()
                        code, _ = await self.command(
                            "docker", "start", "-a", review_name, check=False, max_seconds=review_timeout + 60
                        )
                        (artifact_dir / "mergecraft-runtime.json").write_text(
                            json.dumps(
                                {
                                    "image": review_image_id.strip(),
                                    "run_id": run["id"],
                                    "repo": run["repo"],
                                    "head": run["head"],
                                    "base": run["base"],
                                    "exit_code": code,
                                    "terminal": self.review_events,
                                    "container_seconds": round(time.monotonic() - review_started, 2),
                                    "timeout_seconds": review_timeout,
                                    "model_attempt_limit": 3,
                                }
                            )
                        )
                        artifact_code, _ = await self.command(
                            "docker",
                            "cp",
                            f"{review_name}:/tmp/review.json",
                            str(artifact_dir / "mergecraft.json"),
                            check=False,
                            capture=True,
                            quiet=True,  # Absent when the review did not produce it.
                        )
                        if artifact_code:
                            await asyncio.to_thread(
                                self.log,
                                f"mergeCraft exited {code} without a JSON report; see its diagnostic output above.\n",
                            )

                        def export(path: Path, limit: int) -> bytes | None:
                            # Container-controlled output: regular file only, no links/FIFOs, bounded.
                            data = read_export(path, limit)
                            if data is None:
                                return None
                            data = redact(data.decode(errors="replace"), self.sensitive).encode()
                            path.write_bytes(data)
                            return data

                        result_file = artifact_dir / "mergecraft.json"
                        result_data = await asyncio.to_thread(export, result_file, 2_000_000)
                        evidence_file = artifact_dir / "mergecraft-evidence.json"
                        await self.command(
                            "docker",
                            "cp",
                            f"{review_name}:/tmp/mergecraft-evidence.json",
                            str(evidence_file),
                            check=False,
                            capture=True,
                            quiet=True,  # Absent when the review did not produce it.
                        )
                        evidence_data = await asyncio.to_thread(export, evidence_file, 10_000_000)
                        for filename, limit in (
                            ("mergecraft-review.md", 1_000_000),
                            ("mergecraft-metrics.json", 100_000),
                            ("mergecraft-profile.jsonl", 6_000_000),
                            ("mergecraft-usage.json", 100_000),
                        ):
                            exported = artifact_dir / filename
                            await self.command(
                                "docker",
                                "cp",
                                f"{review_name}:/tmp/{filename}",
                                str(exported),
                                check=False,
                                capture=True,
                                quiet=True,  # Absent when the review did not produce it.
                            )
                            await asyncio.to_thread(export, exported, limit)
                        runtime_path = artifact_dir / "mergecraft-runtime.json"
                        runtime = json.loads(runtime_path.read_text())
                        if evidence_data is not None:
                            runtime["evidence_sha256"] = hashlib.sha256(evidence_data).hexdigest()
                        runtime_path.write_text(json.dumps(runtime))
                        findings = None
                        try:
                            findings = primary_findings(artifact_dir)
                            primary_available = True
                        except (ValueError, TypeError, OSError):
                            primary_available = False
                        state, detail = classify_review(
                            code,
                            self.review_events,
                            primary_available=primary_available,
                            findings=findings,
                            failure_threshold=config.get("review_failure_threshold", "major"),
                            configuration_error=redact(
                                await asyncio.to_thread(configuration_diagnostic, self.store, run["id"]),
                                self.sensitive,
                            ),
                        )
                        if result_data is not None:
                            try:
                                findings = json.loads(result_data).get("findings", [])
                                if isinstance(findings, list):
                                    for finding in findings[:100]:
                                        if isinstance(finding, dict):
                                            await asyncio.to_thread(
                                                self.log,
                                                f"mergeCraft {finding.get('severity', '')}: "
                                                f"{finding.get('path', '')}:{finding.get('start_line', '')} — "
                                                # Redact before truncating: a cut must not
                                                # leave an unredactable secret prefix.
                                                f"{sanitize(str(finding.get('message', '')), self.sensitive)[:3000]}\n"
                                                f"Suggested fix: "
                                                f"{sanitize(str(finding.get('remediation', '')), self.sensitive)[:3000]}\n",
                                            )
                                    if findings:
                                        detail += f"; {len(findings)} findings — see review details"
                            except (ValueError, AttributeError, OSError):
                                await asyncio.to_thread(
                                    self.log,
                                    "mergeCraft JSON report could not be parsed; see diagnostic output.\n",
                                )
                        executed += 1
                        await asyncio.to_thread(
                            self.step,
                            "mergeCraft",
                            state,
                            detail,
                            review_failure_threshold=config.get("review_failure_threshold", "major"),
                            non_blocking_findings=len(findings or []) if state == "success" else 0,
                        )
                        if state != "success":
                            final_state, message = state, detail

            async def guarded(lane, names, action):
                nonlocal final_state, message
                self._lane.set(lane)
                if names:
                    self.phase = names[0]
                try:
                    await action()
                except Cancelled:
                    raise
                except Exception as exc:
                    final_state, message = "error", redact(str(exc), self.sensitive)
                    await asyncio.to_thread(self.log, f"ERROR: {message}\n")
                    steps = json.loads(
                        self.store.rows("SELECT steps FROM runs WHERE id=?", (run["id"],))[0]["steps"]
                    )
                    for step in steps:
                        if step["name"] in names and step["state"] in ("queued", "running"):
                            await asyncio.to_thread(self.step, step["name"], "error", message)
                finally:
                    await self.cleanup(name if lane == "ci" else review_name)

            tasks = [
                asyncio.create_task(guarded("ci", prepared, ci_phase)),
                asyncio.create_task(guarded("review", ["mergeCraft"] if run_review else [], review_phase)),
            ]
            try:
                await asyncio.gather(*tasks)
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
            if blockers and final_state == "success":
                final_state, message = "blocked", "; ".join(blockers)
            if prepared and not ci_jobs and final_state == "success":
                # Every selected workflow ran zero jobs (e.g. all `if:` false). The review's
                # own result stays on its step; the run is not green without CI.
                final_state, message = (
                    "blocked",
                    "No CI job executed in the selected workflows; check workflow conditions and variables",
                )
            if not prepared and not run_review:
                final_state, message = "blocked", "; ".join(blockers) or "No CI workflows selected"
            if final_state == "success" and not executed:
                final_state, message = (
                    "blocked",
                    "No checks executed; check workflow conditions and variables",
                )
            await asyncio.to_thread(self.cancelled)
        except asyncio.CancelledError:
            # Graceful worker stop: the store may automatically re-queue this run.
            # Re-queued by the next poll without using the retry budget (see RECOVERABLE).
            final_state, message = (
                "error",
                "Execution worker stopped during this run; it is re-queued automatically if still eligible",
            )
            end_reason = "worker_interrupted"
        except Cancelled as exc:
            # Operator/superseded cancellation: the store recorded its reason at request time.
            final_state, message = "cancelled", str(exc)
        except Blocked as exc:
            final_state, message = "blocked", str(exc)
        except Exception as exc:
            final_state, message = "error", redact(str(exc), self.sensitive)
        finally:
            await self._finalize(
                run["id"], work, (review_name, name), metrics, final_state, message, end_reason
            )

    async def _finalize(self, rid, work, containers, metrics, state, message, reason):
        """Each step runs even if an earlier one fails; credential removal and
        run finalisation always complete, and a cancellation arriving meanwhile is
        re-raised afterwards instead of being swallowed.

        Order: containers, metrics, the decrypted work directory, the run's final
        state, and only then the network, whose removal may wait for slow
        teardown: a graceful stop's grace period must not expire with
        credentials on disk or the run still marked running. When the run is
        being interrupted the network is left to the worker's startup sweep.
        """
        interrupted: asyncio.CancelledError | None = None

        async def attempt(action, *args):
            nonlocal interrupted
            try:
                await action(*args)
            except asyncio.CancelledError as exc:
                interrupted = interrupted or exc
            except Exception:  # noqa: BLE001 - best effort; must not skip later steps
                pass

        async def complete(function, *args, **kwargs):
            # Shielded: a cancellation cannot abandon this step midway.
            nonlocal interrupted
            task = asyncio.ensure_future(asyncio.to_thread(function, *args, **kwargs))
            while True:
                try:
                    return await asyncio.shield(task)
                except asyncio.CancelledError as exc:
                    interrupted = interrupted or exc

        async def stop_metrics():
            if metrics is not None:
                metrics.cancel()
                await asyncio.gather(metrics, return_exceptions=True)

        await attempt(asyncio.to_thread, self.log, f"\n{state.upper()}: {message}\n")
        for container in containers:
            await attempt(self.cleanup, container)
        await attempt(stop_metrics)
        await complete(shutil.rmtree, work, ignore_errors=True)
        try:
            await complete(self.store.finish, rid, state, message, reason=reason)
            # Once the CI worker container is gone: the network is named after it,
            # the last entry.
            if interrupted is None and reason != "worker_interrupted":
                await attempt(self.remove_network, containers[-1])
        finally:
            if interrupted is not None:
                raise interrupted
