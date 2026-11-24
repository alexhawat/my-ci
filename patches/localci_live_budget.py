"""Meter OpenCode steps during execution, with numeric-only durable evidence."""

import json
import math
import os
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import replace
from pathlib import Path

from mergecraft.localci_profile import event
from mergecraft.utils.run_bounds import BudgetExhausted

_current = ContextVar("localci_live_budget", default=None)


def _counter(value):
    """Return a non-negative integral token counter; absent or null is zero."""
    if value is None:
        return 0
    if type(value) is float and value.is_integer():
        value = int(value)
    if type(value) is not int or value < 0:
        return None
    return value


def _valid_cost(value):
    """A cost is absent, null or a finite non-negative number (bool is not)."""
    if value is None:
        return True
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


class LiveBudget:
    def __init__(self, tracker):
        self.tracker = tracker
        self.prior_tokens = tracker.tokens_used
        self.seen = set()
        self.steps = 0
        self.duplicates = 0
        self.totals = dict(input=0, output=0, reasoning=0, cache_read=0, cache_write=0)
        self.error = None
        self.mistral = False
        self.journal = None
        self.journal_error_type = ""
        self.journal_partial = False
        self.unreported_step = False

    def reported_usage(self, usage):
        if self.mistral and usage is not None:
            return replace(usage, cost_usd=None, cost_note="Subscription charge unavailable")
        return usage

    @staticmethod
    def _fields(tokens):
        cache = tokens.get("cache")
        cache = cache if isinstance(cache, dict) else {}  # As upstream: only a mapping counts.
        fields = {k: _counter(tokens.get(k)) for k in ("input", "output", "reasoning")}
        fields.update(cache_read=_counter(cache.get("read")), cache_write=_counter(cache.get("write")))
        return fields

    def _reject_counters(self, what="token counters", kind="token"):
        self.error = BudgetExhausted(kind, f"Invalid provider {what}; review stopped")
        self.tracker.last_exhausted = self.error
        self.save()

    def accept(self, value):
        if value.get("type") != "step_finish":
            return True
        part = value.get("part") or {}
        # Validate before the upstream handler sees the event: it converts counters
        # itself and its failure (NaN, infinity) would be swallowed, leaving the
        # step unmetered. A rejected event sets the error and is not processed.
        tokens = part.get("tokens")
        if isinstance(tokens, dict) and any(v is None for v in self._fields(tokens).values()):
            self._reject_counters()
            return False
        # Upstream adds any int/float cost; NaN, infinity or a negative value
        # would make the accumulated cost stop counting against the cost budget.
        if not _valid_cost(part.get("cost")):
            self._reject_counters("cost", "cost")
            return False
        # One assistant message can contain several step_finish parts, each
        # billed separately, so the part ID identifies a step. Replayed events
        # keep their part ID; message identity is only a fallback without one.
        session = part.get("sessionID") or value.get("sessionID")
        if part.get("id"):
            identity = ("part", session, part["id"])
        elif session and part.get("messageID"):
            identity = ("message", session, part["messageID"])
        else:
            return True
        if identity in self.seen:
            self.duplicates += 1
            self.save()
            return False
        self.seen.add(identity)
        return True

    def observe(self, value, stop):
        """Persist numeric consumption; upstream alone enforces and charges limits."""
        if value.get("type") != "step_finish" or not isinstance(
            (value.get("part") or {}).get("tokens"), dict
        ):
            return
        fields = self._fields(value["part"]["tokens"])
        if any(v is None for v in fields.values()):
            raise ValueError("Invalid provider token counters")
        if not _valid_cost(value["part"].get("cost")):
            raise ValueError("Invalid provider cost")
        if self.mistral and not any(fields.values()):
            # A completion with no provider usage reaches OpenCode as zero counters.
            self.unreported_step = True
        self.steps += 1
        for key, number in fields.items():
            self.totals[key] += number
        if stop:
            self.error = BudgetExhausted("token", stop)
        event("usage_step", step=self.steps, **fields, total=sum(self.totals.values()))
        self.save()

    def save(self):
        profile = os.environ.get("LOCALCI_PROFILE_PATH")
        if not profile:
            return
        path = Path(profile).with_name("mergecraft-usage.json")
        journal_stop = bool(self.journal_error_type) and not self.journal_partial
        data = {
            "schema_version": 1,
            "steps": self.steps,
            "compaction_steps": self.journal.compactions if self.journal else 0,
            "usage_source": "native_session_journal" if self.journal else "cli_step_finish",
            "duplicates_ignored": self.duplicates,
            "tokens": self.totals,
            "total_tokens": self.prior_tokens + sum(self.totals.values()),
            "prior_attempt_tokens": self.prior_tokens,
            "target": self.tracker.bounds.token_budget,
            "ceiling": self.tracker.bounds.token_ceiling,
            "stopped": self.error is not None or journal_stop,
            "reason": str(self.error)
            if self.error
            else "Complete model usage unavailable"
            if journal_stop
            else "",
            "accounting_error_type": self.journal_error_type,
        }
        if self.mistral:
            data.update(
                usage_source="cli_primary_and_journal_compaction",
                cost_availability="unknown_subscription_charge",
                usage_partial=self.journal_partial or self.unreported_step,
            )
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(data))
        temporary.replace(path)


@contextmanager
def bind(tracker):
    budget = LiveBudget(tracker)
    token = _current.set(budget)
    try:
        yield budget
    finally:
        _current.reset(token)


def current():
    return _current.get()
