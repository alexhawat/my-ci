"""Meter native cumulative usage, including summaries, on the stream-reader thread."""

import json
import secrets
from pathlib import Path


class JournalIntegrityError(ValueError):
    """Usage evidence violated its provenance, numeric constraints, or size bound."""


class JournalGap(ValueError):
    """The provider or the plugin left usage unreported; what was measured stays valid.

    Only this failure may be treated as advisory. Anything else that goes wrong while
    the journal is read, a line that does not parse or a row with a missing field
    included, stops the review: the journal sits in a directory the agent can write.
    """


# Failures the usage plugin reports. Only these fixed texts and an HTTP status are
# copied into the evidence, so nothing a provider sent can reach it.
_PLUGIN_FAILURES = frozenset(
    {
        "Provider request failed; complete usage unavailable",
        "Usage arrived without a metered request",
        "Usage event subscription failed",
    }
)
_NOT_INITIALIZED = "Usage plugin did not initialize"


def plugin_failure(row):
    """Describe an ``error`` row the plugin wrote."""
    reason = row.get("reason")
    if reason not in _PLUGIN_FAILURES:
        return "Usage journal reported an incomplete provider request"
    status = row.get("status")
    if type(status) is int and 100 <= status <= 599:
        return f"{reason} (HTTP {status})"
    return reason


def failure_detail(exc):
    """Name an accounting failure without copying text this module did not write.

    The journal's own errors carry fixed texts (plus, at most, an HTTP status). Any
    other exception, a ``ValueError`` from the upstream usage callback included, is
    named by its type only.
    """
    own = type(exc) in (JournalGap, JournalIntegrityError)
    if own or (type(exc) is ValueError and str(exc) == _NOT_INITIALIZED):
        return str(exc)
    return type(exc).__name__


class UsageJournal:
    def __init__(self, root):
        directory = Path(root) / "opencode-xdg-config"
        directory.mkdir(parents=True, exist_ok=True)
        self.nonce = secrets.token_hex(16)
        self.path = directory / f"localci-usage-{self.nonce}.jsonl"
        self.path.write_text("")
        self.offset = 0
        self.ready = False
        self.pending = {}
        self.request_seen = set()
        self.previous = {}
        self.native = {}
        self.native_seen = set()
        self.primary = {}
        self.compactions = 0
        self.draining = False

    @staticmethod
    def counters(tokens):
        if tokens is None:
            raise JournalGap("Usage counters missing")
        if not isinstance(tokens, dict):
            raise JournalIntegrityError("Usage counters invalid")
        cache = tokens.get("cache")
        if cache is not None and not isinstance(cache, dict):
            raise JournalIntegrityError("Usage counters invalid")
        values = [tokens.get(k) for k in ("input", "output", "reasoning")]
        values += [(cache or {}).get(k) for k in ("read", "write")]
        if any(v is not None and (type(v) is not int or v < 0) for v in values):
            raise JournalIntegrityError("Usage counters invalid")
        if None in values:
            raise JournalGap("Usage counters missing")
        return values

    def note_native(self, event):
        if event.get("type") != "step_finish":
            return
        part = event.get("part") or {}
        session = part.get("sessionID") or event.get("sessionID")
        key = (session, part.get("id") or part.get("messageID"))
        if not all(key) or key in self.native_seen:
            return
        self.native_seen.add(key)
        values = self.counters(part.get("tokens"))
        before = self.native.get(session, [0] * 5)
        self.native[session] = [a + b for a, b in zip(before, values, strict=True)]

    def drain(self, absorb, *, native_primary=False):
        if self.path.stat().st_size > 2_000_000:
            raise JournalIntegrityError("Usage journal exceeded its bound")
        with self.path.open("rb") as stream:
            stream.seek(self.offset)
            data = stream.read()
        complete = data.rfind(b"\n") + 1
        self.offset += complete
        self.draining = True
        try:
            for line in data[:complete].splitlines():
                row = json.loads(line)
                if row.get("nonce") != self.nonce:
                    raise JournalIntegrityError("Usage journal provenance mismatch")
                kind = row.get("kind")
                if kind == "ready":
                    self.ready = True
                elif kind == "request":
                    key = (row["session"], row["request"])
                    if key in self.request_seen:
                        raise JournalIntegrityError("Duplicate provider request")
                    self.request_seen.add(key)
                    self.pending[key] = row["request_kind"]
                elif kind == "rejected":
                    key = (row["session"], row["request"])
                    if row.get("status") != 429 or self.pending.pop(key) != row["request_kind"]:
                        raise JournalIntegrityError("Invalid provider rejection")
                elif kind == "usage":
                    key = (row["session"], row["request"])
                    request_kind = self.pending.pop(key)
                    if row["request_kind"] != request_kind:
                        raise JournalIntegrityError("Usage request kind mismatch")
                    values = self.counters(row.get("tokens"))
                    before, before_cost = self.previous.get(row["session"], ([0] * 5, 0))
                    cost = row.get("cost", 0)
                    if native_primary and row.get("cost") is None:
                        cost = before_cost
                    if type(cost) not in (int, float) or not 0 <= cost < float("inf"):
                        raise JournalIntegrityError("Invalid cumulative cost")
                    delta = [a - b for a, b in zip(values, before, strict=True)]
                    if any(v < 0 for v in delta) or cost < before_cost:
                        raise JournalIntegrityError("Cumulative usage decreased")
                    self.previous[row["session"]] = (values, cost)
                    if request_kind == "primary":
                        primary = self.primary.get(row["session"], [0] * 5)
                        self.primary[row["session"]] = [a + b for a, b in zip(primary, delta, strict=True)]
                        if native_primary:
                            continue  # The CLI meters this step directly.
                    if request_kind == "compaction":
                        self.compactions += 1
                    absorb(
                        {
                            "type": "step_finish",
                            "sessionID": row["session"],
                            "part": {
                                "messageID": f"localci-request-{row['request']}",
                                "cost": cost - before_cost,
                                "tokens": {
                                    "input": delta[0],
                                    "output": delta[1],
                                    "reasoning": delta[2],
                                    "cache": {"read": delta[3], "write": delta[4]},
                                },
                            },
                        }
                    )
                elif kind == "error":
                    raise JournalGap(plugin_failure(row))
                else:
                    raise JournalIntegrityError("Usage journal row of an unknown kind")
        finally:
            self.draining = False

    def finish(self):
        if self.offset != self.path.stat().st_size:
            raise JournalIntegrityError("Usage journal incomplete at review completion")
        if self.pending:
            raise JournalGap("Provider usage incomplete at review completion")
        if self.native != {key: value for key, value in self.primary.items() if key in self.native}:
            # Raised only once the review has finished, so no later spend goes unmetered.
            raise JournalGap("Native primary usage does not reconcile with the journal")


def configure(ctx, model, config):
    from mergecraft.localci_live_budget import current

    live = current()
    if live is None:
        return
    provider = (model or "").partition("/")[0]
    endpoint = config.get("provider", {}).get(provider, {}).get("options", {}).get("baseURL")
    live.mistral = (
        endpoint.rstrip("/") in {"https://api.mistral.ai/v1", "https://api.mistral.ai/openai/v1"}
        if isinstance(endpoint, str)
        else provider == "mistral"
    )
    live.journal = UsageJournal(ctx.tmpdir)
    if live.mistral:
        live.save()  # Record unknown subscription cost even if the provider returns no usage.
    from mergecraft.agents.opencode import _hand_xdg_data_home_to_agent

    _hand_xdg_data_home_to_agent(live.journal.path.parent)
    config["plugins"] = [
        *config.get("plugins", []),
        {
            "package": "/opt/localci/usage-plugin",
            "options": {
                "journal": str(live.journal.path),
                "nonce": live.journal.nonce,
                "allowRateLimit": live.mistral or model == "opencode/deepseek-v4.1-flash-free",
            },
        },
    ]
    config["compaction"] = {
        "auto": True,
        "background": False,
        "keep": {"tokens": 16000},
        "buffer": "92%" if model == "opencode-go/deepseek-v4.1-flash" else "20%",
    }
    config["permission"]["subagent"] = "deny"


def consume(accumulator, event, absorb, *, final=False, unrouted=False):
    from mergecraft.localci_live_budget import current

    live = current()
    journal = getattr(live, "journal", None)
    if journal is None or journal.draining:
        return False
    if live.journal_error_type:
        return not live.journal_partial  # Only advisory gaps fall back to CLI steps.
    try:
        journal.note_native(event)
        journal.drain(absorb, native_primary=live.mistral)
        needs_ready = final or event.get("type") == "step_finish"
        no_request = unrouted and not journal.request_seen and not journal.native_seen
        if needs_ready and not journal.ready and not no_request:
            raise ValueError(_NOT_INITIALIZED)
        if final:
            journal.finish()
    except Exception as exc:
        live.journal_error = str(exc)
        live.journal_error_type = type(exc).__name__
        # An allowlist: only a reported gap is advisory. A line that does not parse, a
        # row with a missing field or any other failure stops the review.
        live.journal_partial = live.mistral and isinstance(exc, JournalGap)
        detail = failure_detail(exc)
        live.journal_error_detail = detail
        if not live.journal_partial:
            accumulator.halt_reason = (
                accumulator.halt_reason or f"Complete model usage unavailable ({detail}); review stopped"
            )
        live.save()
    return not live.mistral or bool(accumulator.halt_reason)
