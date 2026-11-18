"""Run the installed OpenCode stream adapter against deterministic JSONL events."""

import asyncio
import importlib
import io
import json
import os
import subprocess
import sys
import tempfile
from contextlib import ExitStack, nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mergecraft.localci_live_budget import bind
from mergecraft.utils.run_bounds import BudgetExhausted, BudgetTracker, RunBounds

adapter = importlib.import_module("mergecraft.agents.opencode")


def step(identity, **tokens):
    return {"type": "step_finish", "sessionID": "session", "part": {"messageID": identity, "tokens": tokens}}


def part_step(part_id, identity, **tokens):
    value = step(identity, **tokens)
    value["part"]["id"] = part_id
    return value


def priced_step(part_id, cost, **tokens):
    value = part_step(part_id, part_id, **tokens)
    value["part"]["cost"] = cost
    return value


def stream(events):
    process = SimpleNamespace(
        stdout=io.StringIO("\n".join(json.dumps(e) for e in events)), stderr=io.StringIO(""), pid=123
    )
    with ExitStack() as stack:
        for name, value in {
            "watchdog_for_process": SimpleNamespace(stalled=False, touch=Mock(), stop=Mock()),
            "spawn_agent_cli": process,
            "start_stderr_drain": SimpleNamespace(join=Mock(), text=lambda: ""),
            "track_process_group": nullcontext(),
            "wait_or_kill_process_group": 0,
        }.items():
            stack.enter_context(patch.object(adapter, name, return_value=value))
        kill = stack.enter_context(patch("mergecraft.utils.process_group.kill_process_group"))
        try:
            result = adapter._run_opencode_cli_streaming(
                cmd=[],
                ctx=SimpleNamespace(
                    tool_state=SimpleNamespace(driver_reports_reads=False),
                    idle_timeout_s=60,
                    resolved_model=None,
                ),
                env={},
                session={},
            )
        except BudgetExhausted:
            assert kill.call_count >= 1
            raise
        assert not kill.called
        return result


def tracker():
    return BudgetTracker(
        RunBounds(
            token_budget=1000,
            token_budget_tolerance=0.1,
            cost_budget_usd=5,
            tool_call_budget=100,
            run_timeout_s=60,
            context_retrieval_timeout_s=10,
            max_diff_lines=10000,
            external_operation_timeout_s=10,
        )
    )


async def main():
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["LOCALCI_PROFILE_PATH"] = str(Path(tmp) / "mergecraft-profile.jsonl")
        first = step("first", input=400, output=20, reasoning=10, cache={"read": 500, "write": 5})
        budget = tracker()
        with bind(budget) as live:
            result = await asyncio.to_thread(stream, [first, first])
            assert result.usage.input_tokens == 905 and result.usage.output_tokens == 30
            assert budget.tokens_used == 935 and live.steps == 1 and live.duplicates == 1
            # A resumed CLI stream shares the limit and the stable message IDs.
            try:
                await asyncio.to_thread(
                    stream, [first, step("second", input=200), step("never-charge", input=900)]
                )
            except BudgetExhausted as exc:
                assert "1135 reported tokens; ceiling 1100" in str(exc)
            else:
                raise AssertionError("A successful CLI exit must not override budget exhaustion")
            assert live.steps == 2 and live.duplicates == 2
            assert budget.tokens_used == 1135
            assert budget.phase_totals["opencode_step"] == 1135
            saved = json.loads((Path(tmp) / "mergecraft-usage.json").read_text())
            assert saved["stopped"] and saved["total_tokens"] == 1135
            assert saved["tokens"]["cache_read"] == 500
        # The next run has independent counters, even with the same message IDs.
        with bind(tracker()) as live:
            await asyncio.to_thread(stream, [first])
            assert live.steps == 1
        # Several steps of one assistant message are each charged; a replayed part is not.
        budget = tracker()
        with bind(budget) as live:
            await asyncio.to_thread(
                stream,
                [
                    part_step("part-1", "shared", input=100),
                    part_step("part-2", "shared", input=50),
                    part_step("part-1", "shared", input=100),
                ],
            )
            assert live.steps == 2 and live.duplicates == 1 and budget.tokens_used == 150
        # Null counters are zero and integral floats are accepted.
        budget = tracker()
        with bind(budget) as live:
            await asyncio.to_thread(
                stream,
                [part_step("float", "float", input=12.0, output=3, reasoning=None, cache={"read": None})],
            )
            assert live.steps == 1 and live.error is None and live.totals["input"] == 12
            assert budget.tokens_used == 15
        # Negative, fractional and non-numeric counters still stop the review.
        for invalid in (-1, 1.5, "7", True, float("nan"), float("inf"), -float("inf")):
            with bind(tracker()) as live:
                try:
                    await asyncio.to_thread(stream, [part_step("bad", "bad", input=invalid)])
                except BudgetExhausted as exc:
                    assert "Invalid provider token counters" in str(exc)
                else:
                    raise AssertionError(f"Invalid counter accepted: {invalid!r}")
                assert live.steps == 0
        # Meter I/O failure cannot be swallowed by the stream's generic handler.
        with bind(tracker()) as live, patch.object(live, "save", side_effect=OSError("fixture")):
            try:
                await asyncio.to_thread(stream, [first])
            except BudgetExhausted as exc:
                assert "meter failed" in str(exc)
            else:
                raise AssertionError("Meter failure must stop the review")
        # Nor a failure while rejecting invalid counters: the agent must still be stopped.
        with bind(tracker()) as live, patch.object(live, "save", side_effect=OSError("fixture")):
            try:
                await asyncio.to_thread(
                    stream, [part_step("bad", "bad", input=-1), part_step("later", "later", input=900)]
                )
            except BudgetExhausted:
                assert live.steps == 0
            else:
                raise AssertionError("A failed rejection must stop the review")
        # A failed meter write after a budget stop keeps the real stop reason and kind.
        for kind, priced in (
            ("token", part_step("over", "over", input=1200)),
            ("cost", priced_step("pricey", 6, input=10)),
        ):
            budget = tracker()
            with bind(budget) as live, patch.object(live, "save", side_effect=OSError("fixture")):
                try:
                    await asyncio.to_thread(stream, [priced])
                except BudgetExhausted as exc:
                    assert exc.kind == kind and f"Live {kind} budget stopped" in str(exc), str(exc)
                    assert "meter failed" not in str(exc) and budget.last_exhausted is exc
                else:
                    raise AssertionError(f"{kind} budget stop was lost")
        # An accepted step the upstream handler fails on is a meter failure, not an
        # unmetered step; other event types keep the upstream logged-and-continue path.
        real_handler = adapter._session_event_handler

        def failing_handler(*args, **kwargs):
            handle = real_handler(*args, **kwargs)

            def wrapped(acc, value):
                if (value.get("part") or {}).get("id") == "explode":
                    raise ValueError("fixture")
                handle(acc, value)

            return wrapped

        budget = tracker()
        with bind(budget) as live, patch.object(adapter, "_session_event_handler", failing_handler):
            try:
                await asyncio.to_thread(
                    stream,
                    [part_step("explode", "explode", input=10), part_step("later", "later", input=900)],
                )
            except BudgetExhausted as exc:
                assert "meter failed" in str(exc) and budget.last_exhausted is exc
                assert live.steps == 0 and budget.tokens_used == 0
            else:
                raise AssertionError("A step the upstream handler failed on went unmetered")
        budget = tracker()
        with bind(budget) as live, patch.object(adapter, "_session_event_handler", failing_handler):
            text = {"type": "text", "sessionID": "session", "part": {"id": "explode", "text": "x"}}
            await asyncio.to_thread(stream, [text, part_step("after-text", "after-text", input=10)])
            assert live.error is None and live.steps == 1 and budget.tokens_used == 10
        # Step cost is validated like the token counters; absent, null and finite
        # non-negative costs are charged.
        for cost, used in ((None, 0), (0, 0), (0.25, 0.25), (1, 1)):
            budget = tracker()
            with bind(budget) as live:
                await asyncio.to_thread(stream, [priced_step("ok", cost, input=1)])
                assert live.error is None and live.steps == 1 and budget.cost_used == used
        for invalid in (float("nan"), float("inf"), -float("inf"), -0.5, "1", True, [1]):
            budget = tracker()
            with bind(budget) as live:
                try:
                    await asyncio.to_thread(
                        stream, [priced_step("bad", invalid, input=1), part_step("later", "later", input=1)]
                    )
                except BudgetExhausted as exc:
                    assert exc.kind == "cost" and "Invalid provider cost" in str(exc)
                else:
                    raise AssertionError(f"Invalid cost accepted: {invalid!r}")
                assert live.steps == 0 and budget.cost_used == 0
        # Prove the real OS process is terminated and reaped, without a provider.
        child = await asyncio.to_thread(
            subprocess.Popen,
            [
                sys.executable,
                "-u",
                "-c",
                "import time; print("
                + repr(json.dumps(step("real", input=1200)))
                + ", flush=True); time.sleep(30)",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            with bind(tracker()), patch.object(adapter, "spawn_agent_cli", return_value=child):
                try:
                    await asyncio.to_thread(
                        adapter._run_opencode_cli_streaming,
                        cmd=[],
                        ctx=SimpleNamespace(
                            tool_state=SimpleNamespace(driver_reports_reads=False),
                            idle_timeout_s=60,
                            resolved_model=None,
                        ),
                        env={},
                        session={},
                    )
                except BudgetExhausted:
                    assert child.poll() is not None and child.returncode != 0
                else:
                    raise AssertionError("Real process exceeded its budget without stopping")
        finally:
            if child.poll() is None:
                child.kill()
                await asyncio.to_thread(child.wait)
    print(
        "PASS: disjoint accounting, duplicate/replayed events, multi-step messages, counter and cost validation, resumed-turn ceiling, fail-closed stream stop (first stop reason kept, failed upstream step handler) and durable usage"
    )


asyncio.run(main())
