"""Ordered secondary-reviewer fallback in the local offline review image."""

import asyncio
import json
import os
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

from mergecraft.agents.resolution.chain import may_advance_chain
from mergecraft.localci_live_budget import bind
from mergecraft.utils.run_bounds import record_agent_usage

_usages = ContextVar("localci_secondary_usages", default=None)


def _load_routes():
    path = Path("/control/local-review-pipeline")
    if not path.is_file():
        return {}
    routes = json.loads(path.read_text())
    # Remove the private slot variables before launching model CLIs.
    for row in routes.values():
        for slot in row:
            slot["key"] = os.environ.pop(slot["source"])
    return routes


_routes = _load_routes()


# Managed rows run serially. MCP requests may arrive on a different task from the model.
_running = None


def harness_batches(batches):
    # The worker dispatches secondary rows with their own credentials and deadline.
    return batches[:1] if _routes else batches


def recording_model(agent_id):
    if not _routes:
        return None
    if _running is None or agent_id != _running[0]:
        raise ValueError("Only the active pipeline reviewer can record its outcome")
    return _running[1]


@contextmanager
def running_reviewer(agent_id, slug):
    global _running
    _running = (agent_id, slug)
    try:
        yield
    finally:
        _running = None


def primary_routes(allowed, *, pin):
    # Native residency filtering still decides which slugs may run. Restore distinct
    # credential slots for the same slug, which native model-only chains deduplicate.
    slots = [s for s in _routes.get("reviewer", []) if s["model"] in allowed]
    return slots[:1] if pin else slots


@contextmanager
def activate_key(slot):
    if slot is None:
        yield
        return
    target = slot["target"]
    previous = os.environ.get(target)
    os.environ[target] = slot["key"]
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(target, None)
        else:
            os.environ[target] = previous


@contextmanager
def secondary_usage(usages):
    token = _usages.set(usages)
    try:
        yield
    finally:
        _usages.reset(token)


async def run_attempt(agent, ctx, binding, slug):
    usages = _usages.get()
    if usages is None:
        return await agent.run(ctx)
    tracker = ctx.budget_tracker
    if tracker.last_exhausted is not None:
        raise tracker.last_exhausted
    tracker.stream_tokens_charged = 0
    tracker.stream_cost_charged = 0.0
    row = _routes.get(binding.agent_id, [])
    # dispatch_secondary trims the prefix after each failed attempt. Native
    # availability selection may also skip ahead within the remaining chain.
    position = len(row) - len(binding.model_chain) + binding.model_chain.index(slug)
    with (
        running_reviewer(binding.agent_id, slug),
        activate_key(row[position] if row else None),
        bind(tracker) as budget,
    ):
        result = await agent.run(ctx)
        record_agent_usage(tracker, result.usage, phase="reviewer_dispatch")
        usages.append(budget.reported_usage(result.usage))
        if tracker.last_exhausted is not None:
            raise tracker.last_exhausted
    return result


class NextModel(Exception):
    """Continue this reviewer's chain after an eligible, unsubmitted attempt."""


def check_backup(result, slug, binding, *, clean):
    if (
        _usages.get() is not None
        and clean
        and slug in binding.model_chain[:-1]
        and not result.metadata.get("budget_exhausted")
        and may_advance_chain(result)
    ):
        raise NextModel(slug)


async def dispatch_secondary(dispatch, *, binding, timeout_s, **kwargs):
    if _usages.get() is None:
        return await dispatch(binding=binding, timeout_s=timeout_s, **kwargs)
    clock = asyncio.get_running_loop().time
    deadline = clock() + timeout_s
    while True:
        remaining = deadline - clock()
        if remaining <= 0:
            raise TimeoutError("Secondary reviewer deadline reached")
        try:
            return await dispatch(binding=binding, timeout_s=remaining, **kwargs)
        except NextModel as exc:
            slug = exc.args[0]
            binding = binding.model_copy(
                update={"model_chain": binding.model_chain[binding.model_chain.index(slug) + 1 :]}
            )
