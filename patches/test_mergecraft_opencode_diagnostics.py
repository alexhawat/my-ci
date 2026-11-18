"""Exercise the pinned adapter's failure result without a provider or subprocess."""

import importlib
import io
from contextlib import ExitStack, nullcontext
from types import SimpleNamespace
from unittest.mock import Mock, patch


def check():
    adapter = importlib.import_module("mergecraft.agents.opencode")
    runner = importlib.import_module("mergecraft.agents.cli_runner")
    for status, stdout, expected in [
        (137, "", "opencode exited 137: no diagnostic event"),
        (1, '{"type":"error","error":{"message":"fixture failure"}}\n', "fixture failure"),
        (
            1,
            '{"type":"tool_use","part":{"tool":"fixture","state":{"status":"error"}}}\n',
            "last event=tool_use/fixture/error",
        ),
    ]:
        process = SimpleNamespace(stdout=io.StringIO(stdout), stderr=io.StringIO(""))
        drain = SimpleNamespace(join=Mock(), text=lambda: "")
        with ExitStack() as stack:
            stack.enter_context(
                patch.object(
                    runner,
                    "watchdog_for_process",
                    return_value=SimpleNamespace(stalled=False, touch=Mock(), stop=Mock()),
                )
            )
            stack.enter_context(patch.object(runner, "spawn_agent_cli", return_value=process))
            stack.enter_context(patch.object(runner, "start_stderr_drain", return_value=drain))
            stack.enter_context(patch.object(runner, "track_process_group", return_value=nullcontext()))
            stack.enter_context(patch.object(runner, "wait_or_kill_process_group", return_value=status))
            result = adapter._run_opencode_cli_streaming(
                cmd=[],
                ctx=SimpleNamespace(
                    tool_state=SimpleNamespace(driver_reports_reads=False, repos={}, primary_repo_key=""),
                    idle_timeout_s=60,
                    resolved_model=None,
                    budget_tracker=None,
                ),
                env={},
                session={},
            )
        assert not result.success and expected in result.error
    print("PASS: OpenCode exit status and structured error survive failure reporting")


if __name__ == "__main__":
    check()
