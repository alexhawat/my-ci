"""Meter OpenCode steps during execution, with numeric-only durable evidence."""

import json
import os
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

from mergecraft.localci_profile import event
from mergecraft.utils.run_bounds import BudgetExhausted

_current = ContextVar("localci_live_budget", default=None)


class LiveBudget:
    def __init__(self, tracker):
        self.tracker = tracker
        self.prior_tokens = tracker.tokens_used
        self.seen = set()
        self.steps = 0
        self.duplicates = 0
        self.totals = dict(input=0, output=0, reasoning=0, cache_read=0, cache_write=0)
        self.error = None

    def accept(self, value):
        if value.get("type") != "step_finish":
            return True
        part = value.get("part") or {}
        # Live and reconciliation events can have different part IDs for the
        # same assistant step. Message identity is stable across both paths.
        identity = (part.get("sessionID") or value.get("sessionID"), part.get("messageID"))
        if all(identity):
            if identity in self.seen:
                self.duplicates += 1
                self.save()
                return False
            self.seen.add(identity)
        return True

    def charge(self, value, usage, previous):
        if value.get("type") != "step_finish" or not isinstance(
            (value.get("part") or {}).get("tokens"), dict
        ):
            return
        tokens = value["part"]["tokens"]
        cache = tokens.get("cache") or {}
        fields = {k: tokens.get(k, 0) for k in ("input", "output", "reasoning")}
        fields.update(cache_read=cache.get("read", 0), cache_write=cache.get("write", 0))
        if any(type(v) is not int or v < 0 for v in fields.values()):
            self.error = BudgetExhausted("token", "Invalid provider token counters; review stopped")
            self.tracker.last_exhausted = self.error
            self.save()
            return
        self.steps += 1
        for key, number in fields.items():
            self.totals[key] += number
        # The adapter's counters are disjoint in OpenCode 2.2.5. Cached
        # input still counts as processed tokens, independently of its price.
        count = usage.input_tokens + usage.output_tokens - previous[0]
        cost = (usage.cost_usd or 0) - previous[1]
        tokens_before, cost_before = self.tracker.tokens_used, self.tracker.cost_used
        try:
            self.tracker.record_tokens(count, phase="opencode_step")
            if cost > 0:
                self.tracker.record_cost(cost)
        except BudgetExhausted as exc:
            # These tokens were already consumed, even when the upstream
            # admission-oriented tracker rejects the over-ceiling increment.
            missing = tokens_before + count - self.tracker.tokens_used
            if missing > 0:
                self.tracker.tokens_used += missing
                self.tracker.phase_totals["opencode_step"] += missing
            self.tracker.cost_used = max(self.tracker.cost_used, cost_before + max(0, cost))
            actual = self.prior_tokens + sum(self.totals.values())
            self.error = BudgetExhausted(
                exc.kind,
                f"Live {exc.kind} budget stopped OpenCode after step {self.steps}: "
                f"{actual} reported tokens; ceiling {self.tracker.bounds.token_ceiling}. "
                "Usage arrives after each response, so the final in-flight response can exceed the limit; "
                "no further model turn or fallback is permitted. " + str(exc),
            )
            self.tracker.last_exhausted = self.error
        event("usage_step", step=self.steps, **fields, total=sum(self.totals.values()))
        self.save()

    def save(self):
        profile = os.environ.get("LOCALCI_PROFILE_PATH")
        if not profile:
            return
        path = Path(profile).with_name("mergecraft-usage.json")
        data = {
            "schema_version": 1,
            "steps": self.steps,
            "duplicates_ignored": self.duplicates,
            "tokens": self.totals,
            "total_tokens": self.prior_tokens + sum(self.totals.values()),
            "prior_attempt_tokens": self.prior_tokens,
            "target": self.tracker.bounds.token_budget,
            "ceiling": self.tracker.bounds.token_ceiling,
            "stopped": self.error is not None,
            "reason": str(self.error) if self.error else "",
        }
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
