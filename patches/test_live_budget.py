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
        # Meter I/O failure cannot be swallowed by the stream's generic handler.
        with bind(tracker()) as live, patch.object(live, "save", side_effect=OSError("fixture")):
            try:
                await asyncio.to_thread(stream, [first])
            except BudgetExhausted as exc:
                assert "meter failed" in str(exc)
            else:
                raise AssertionError("Meter failure must stop the review")
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
        "PASS: disjoint accounting, duplicate/replayed events, resumed-turn ceiling, fail-closed stream stop and durable usage"
    )


asyncio.run(main())
