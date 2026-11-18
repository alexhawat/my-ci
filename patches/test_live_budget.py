"""Exercise native stream enforcement, durable telemetry and real process cleanup."""

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
from mergecraft.utils.run_bounds import BudgetTracker, RunBounds, record_agent_usage

adapter = importlib.import_module("mergecraft.agents.opencode")
runner = importlib.import_module("mergecraft.agents.cli_runner")


def step(identity, **tokens):
    return {"type": "step_finish", "sessionID": "session", "part": {"messageID": identity, "tokens": tokens}}


def context(budget):
    return SimpleNamespace(
        tool_state=SimpleNamespace(driver_reports_reads=False, repos={}, primary_repo_key=""),
        idle_timeout_s=60,
        resolved_model=None,
        budget_tracker=budget,
    )


def priced_step(identity, cost, **tokens):
    value = step(identity, **tokens)
    value["part"]["cost"] = cost
    return value


def stream(events, budget):
    process = SimpleNamespace(
        stdout=io.StringIO("\n".join(json.dumps(e) for e in events)),
        stderr=io.StringIO(""),
        pid=123,
        poll=lambda: None,
    )
    with ExitStack() as stack:
        for name, value in {
            "watchdog_for_process": SimpleNamespace(stalled=False, touch=Mock(), stop=Mock()),
            "spawn_agent_cli": process,
            "start_stderr_drain": SimpleNamespace(join=Mock(), text=lambda: ""),
            "track_process_group": nullcontext(),
            "wait_or_kill_process_group": 0,
        }.items():
            stack.enter_context(patch.object(runner, name, return_value=value))
        kill = stack.enter_context(patch.object(runner, "kill_process_group"))
        result = adapter._run_opencode_cli_streaming(cmd=[], ctx=context(budget), env={}, session={})
        assert kill.called == bool(result.metadata.get("budget_exhausted"))
        return result


def tracker():
    return BudgetTracker(
        RunBounds(
            token_budget=1100,
            token_budget_tolerance=0,
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
            result = await asyncio.to_thread(stream, [first, first], budget)
            assert result.success and result.usage.input_tokens == 905 and result.usage.output_tokens == 30
            assert budget.tokens_used == 935 and live.steps == 1 and live.duplicates == 1
            record_agent_usage(budget, result.usage)
            assert budget.tokens_used == 935, "Final accounting must not double-charge native steps"
            result = await asyncio.to_thread(
                stream, [first, step("second", input=200), step("never", input=900)], budget
            )
            assert (
                not result.success
                and result.metadata["budget_exhausted"]
                and not result.metadata["retryable"]
            )
            assert live.steps == 2 and live.duplicates == 2
            assert budget.last_exhausted is not None
            saved = json.loads((Path(tmp) / "mergecraft-usage.json").read_text())
            assert saved["stopped"] and saved["total_tokens"] == 1135 and saved["ceiling"] == 1100
            assert saved["tokens"]["cache_read"] == 500
        budget = tracker()
        with bind(budget) as live:
            assert (await asyncio.to_thread(stream, [first], budget)).success and live.steps == 1
        budget = tracker()
        with bind(budget) as live, patch.object(live, "save", side_effect=OSError("fixture")):
            result = await asyncio.to_thread(stream, [first], budget)
            assert not result.success and "evidence failed" in result.error
        # A finite, non-negative step cost is accepted.
        budget = tracker()
        with bind(budget) as live:
            result = await asyncio.to_thread(stream, [priced_step("priced", 0.25, input=1)], budget)
            assert result.success and live.steps == 1 and live.error is None
        # A step with invalid counters or cost halts the review; it is not
        # dropped unmetered while the agent keeps running.
        for invalid in (
            step("bad", input=-1),
            step("bad", input=1.5),
            step("bad", input=float("nan")),
            priced_step("bad", float("nan"), input=1),
            priced_step("bad", float("inf"), input=1),
            priced_step("bad", -0.5, input=1),
            priced_step("bad", "1", input=1),
        ):
            budget = tracker()
            with bind(budget) as live:
                result = await asyncio.to_thread(stream, [invalid, step("later", input=1)], budget)
                assert not result.success and "Invalid provider" in result.error, result.error
                assert live.steps == 0 and live.error is not None and budget.last_exhausted is live.error
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
            budget = tracker()
            with bind(budget), patch.object(runner, "spawn_agent_cli", return_value=child):
                result = await asyncio.to_thread(
                    adapter._run_opencode_cli_streaming, cmd=[], ctx=context(budget), env={}, session={}
                )
                assert not result.success and result.metadata["budget_exhausted"]
                assert child.poll() is not None and child.returncode != 0
        finally:
            if child.poll() is None:
                child.kill()
                await asyncio.to_thread(child.wait)
    print(
        "PASS: native per-step ceiling, no duplicate charging, counter and cost validation that halts the review, durable actual usage and real process termination"
    )


asyncio.run(main())
