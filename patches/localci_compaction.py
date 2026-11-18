"""Meter native cumulative usage, including summaries, on the stream-reader thread."""

import json
import secrets
from pathlib import Path


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
        if not isinstance(tokens, dict) or not isinstance(tokens.get("cache"), dict):
            raise ValueError("Usage counters missing")
        values = [tokens.get(k) for k in ("input", "output", "reasoning")]
        values += [tokens["cache"].get(k) for k in ("read", "write")]
        if any(type(v) is not int or v < 0 for v in values):
            raise ValueError("Usage counters invalid")
        return values

    def note_native(self, event):
        if event.get("type") != "step_finish":
            return
        part = event.get("part") or {}
        session = part.get("sessionID") or event.get("sessionID")
        key = (session, part.get("messageID"))
        if not all(key) or key in self.native_seen:
            return
        self.native_seen.add(key)
        values = self.counters(part.get("tokens"))
        before = self.native.get(session, [0] * 5)
        self.native[session] = [a + b for a, b in zip(before, values, strict=True)]

    def drain(self, absorb):
        if self.path.stat().st_size > 2_000_000:
            raise ValueError("Usage journal exceeded its bound")
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
                    raise ValueError("Usage journal provenance mismatch")
                kind = row.get("kind")
                if kind == "ready":
                    self.ready = True
                elif kind == "request":
                    key = (row["session"], row["request"])
                    if key in self.request_seen:
                        raise ValueError("Duplicate provider request")
                    self.request_seen.add(key)
                    self.pending[key] = row["request_kind"]
                elif kind == "usage":
                    key = (row["session"], row["request"])
                    request_kind = self.pending.pop(key)
                    if row["request_kind"] != request_kind:
                        raise ValueError("Usage request kind mismatch")
                    values = self.counters(row["tokens"])
                    cost = row.get("cost", 0)
                    if type(cost) not in (int, float) or not 0 <= cost < float("inf"):
                        raise ValueError("Invalid cumulative cost")
                    before, before_cost = self.previous.get(row["session"], ([0] * 5, 0))
                    delta = [a - b for a, b in zip(values, before, strict=True)]
                    if any(v < 0 for v in delta) or cost < before_cost:
                        raise ValueError("Cumulative usage decreased")
                    self.previous[row["session"]] = (values, cost)
                    if request_kind == "primary":
                        primary = self.primary.get(row["session"], [0] * 5)
                        self.primary[row["session"]] = [a + b for a, b in zip(primary, delta, strict=True)]
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
                else:
                    raise ValueError("Usage journal reported an incomplete provider request")
        finally:
            self.draining = False

    def finish(self):
        if self.pending or self.offset != self.path.stat().st_size:
            raise ValueError("Provider usage incomplete at review completion")
        if self.native != {key: value for key, value in self.primary.items() if key in self.native}:
            raise ValueError("Native primary usage does not reconcile with the journal")


def configure(ctx, model, config):
    from mergecraft.localci_live_budget import current

    live = current()
    if live is None:
        return
    live.journal = UsageJournal(ctx.tmpdir)
    from mergecraft.agents.opencode import _hand_xdg_data_home_to_agent

    _hand_xdg_data_home_to_agent(live.journal.path.parent)
    config["plugins"] = [
        *config.get("plugins", []),
        {
            "package": "/opt/localci/usage-plugin",
            "options": {"journal": str(live.journal.path), "nonce": live.journal.nonce},
        },
    ]
    config["compaction"] = {
        "auto": True,
        "background": False,
        "keep": {"tokens": 16000},
        "buffer": "92%" if model == "opencode-go/deepseek-v4.1-flash" else "20%",
    }
    config["permission"]["subagent"] = "deny"


def consume(accumulator, event, absorb, *, final=False):
    from mergecraft.localci_live_budget import current

    live = current()
    journal = getattr(live, "journal", None)
    if journal is None or journal.draining:
        return False
    try:
        journal.note_native(event)
        journal.drain(absorb)
        if (final or event.get("type") == "step_finish") and not journal.ready:
            raise ValueError("Usage plugin did not initialize")
        if final:
            journal.finish()
    except Exception as exc:
        live.journal_error = str(exc)
        live.journal_error_type = type(exc).__name__
        accumulator.halt_reason = (
            accumulator.halt_reason or "Complete model usage unavailable; review stopped"
        )
        live.save()
    return True
