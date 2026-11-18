"""Exercise both OpenCode routes with fake CLI events and no provider traffic."""

import asyncio
import json
import os
from contextlib import chdir
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import yaml
from mergecraft.agents import opencode
from mergecraft.agents.registry import load_registry
from mergecraft.agents.resolution.credentials import credential_status_for_slug
from mergecraft.agents.shared import AgentRunContext
from mergecraft.config.settings_snapshot import capture_repo_settings_snapshot
from mergecraft.localci_live_budget import bind
from mergecraft.mcp.tool_state import init_tool_state
from mergecraft.review.pipeline.dispatch import dispatch_reviewer
from mergecraft.review.roster_auth import validate_roster_at_run_start
from mergecraft.utils.run_bounds import BudgetTracker, RunBounds
from mergecraft.utils.secrets import build_agent_env

FREE = "opencode/deepseek-v4.1-flash-free"
GO = "opencode-go/deepseek-v4.1-flash"


async def check(
    root: Path, error: dict[str, str] | None, expected: list[str], *, settled: bool = True
) -> None:
    snapshot = capture_repo_settings_snapshot(root=root)
    settings = snapshot.settings
    validate_roster_at_run_start(snapshot=snapshot)
    registry = load_registry(settings=settings)
    registry.validate()
    verifier = registry.resolve_role("verifier").agent_id
    state = init_tool_state(owner="fixture", name="project", dir=str(root))
    tracker = BudgetTracker(
        RunBounds(
            token_budget=1000,
            cost_budget_usd=5,
            tool_call_budget=100,
            run_timeout_s=60,
            context_retrieval_timeout_s=10,
            max_diff_lines=1000,
            external_operation_timeout_s=10,
        )
    )
    attempts = []

    async def run(model: str):
        attempts.append(model)
        assert credential_status_for_slug(model, settings=settings, cwd=root, wired=True).available
        assert build_agent_env("opencode", model=model)["OPENCODE_API_KEY"] == "fixture"
        ctx = AgentRunContext(
            payload={"model": FREE, "shell": "disabled", "push": "disabled"},
            mcp_server_url="http://127.0.0.1:0/mcp",
            tmpdir=str(root),
            instructions="Review fixture",
            subagent_denied_tools=(),
            tool_state=state,
            resolved_model=model,
            budget_tracker=tracker,
        )
        config = json.loads(opencode.build_security_config(ctx, model))
        assert config["enabled_providers"] == [model.split("/")[0]]
        assert config["agent"][verifier]["model"] == model

        def fake_cli(spec, _ctx):
            journal = live.journal
            if model != FREE or not error or error.get("type") != "provider.no-route":
                rows = [{"kind": "ready"}]
                if model == FREE and error and (error.get("type") == "provider.free-limit" or not settled):
                    request = {"session": "s", "request": "r", "request_kind": "primary"}
                    rows.append({"kind": "request", **request})
                    if settled:
                        rows.append({"kind": "rejected", "status": 429, **request})
                journal.path.write_text(
                    "".join(json.dumps({"nonce": journal.nonce, **row}) + "\n" for row in rows)
                )
            if model == FREE and error:
                spec.handler(spec.accumulator, {"type": "error", "error": error})
                return spec.classify(1, "")
            return replace(spec.classify(0, ""), terminal_submission_received=True)

        with patch.object(opencode, "run_cli_attempt", fake_cli):
            return opencode._run_opencode_cli_streaming(cmd=[], ctx=ctx, env={}, session={})

    with bind(tracker) as live:
        result = await dispatch_reviewer(
            settings, model_head=None, model_pin=settings.model_pin, tool_state=state, run_once=run
        )
    assert attempts == expected
    assert result.winning_slug == expected[-1]
    assert result.agent_result.success is (error is None or GO in expected)
    assert bool(result.agent_result.metadata.get("budget_exhausted")) is (not settled)


if __name__ == "__main__":
    roster = {
        "models": [FREE, GO],
        "allowFallback": True,
        "providers": [
            {"label": name, "harness": "opencode", "envIndex": index, "authKind": "api_key"}
            for index, name in enumerate(("opencode-go", "opencode"), start=1)
        ],
        "agents": {role: {"role": role, "modelChain": [FREE, GO]} for role in ("reviewer", "verifier")},
    }
    with TemporaryDirectory() as directory:
        root = Path(directory)
        config = root / ".mergecraft" / "config.yaml"
        config.parent.mkdir()
        config.write_text(yaml.safe_dump(roster))
        with (
            chdir(root),
            patch.dict(os.environ, {"OPENCODE_GO_API_KEY": "fixture", "LLM_PROVIDER_2_API_KEY": "fixture"}),
        ):
            asyncio.run(check(root, None, [FREE]))
            # Untyped, so failover_eligible is False: upstream's retryable path
            # is what moves a rate limit on to the next model.
            asyncio.run(check(root, {"message": "429 Too Many Requests"}, [FREE, GO]))
            free_limit = {"type": "provider.free-limit", "message": "Free usage limit reached"}
            asyncio.run(check(root, free_limit, [FREE, GO]))
            asyncio.run(check(root, free_limit, [FREE], settled=False))
            asyncio.run(
                check(root, {"type": "provider.no-route", "message": "Model unavailable"}, [FREE, GO])
            )
            asyncio.run(check(root, {"type": "other", "message": "Model unavailable"}, [FREE]))
            # Untyped errors: only a rate limit falls back, through upstream's
            # retryable path (the 429 case above). Anything else ends the review.
            asyncio.run(check(root, {"message": "Model unavailable"}, [FREE]))
    print("PASS: OpenCode ordered fallback, offline roster credentials and verifier routing")
