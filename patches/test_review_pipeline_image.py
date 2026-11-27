"""Exercise a three-reviewer roster in the pinned image without provider traffic."""

import asyncio
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import yaml
from mergecraft import localci_review_pipeline
from mergecraft.agents.registry import load_registry
from mergecraft.agents.resolution.chain import run_with_model_chain
from mergecraft.agents.shared import AgentResult, AgentRunContext, AgentUsage
from mergecraft.config.settings import load_repo_settings
from mergecraft.localci_review_pipeline import secondary_usage
from mergecraft.mcp.context import PayloadEvent, RepoIdentity, ResolvedPayload, ToolContext
from mergecraft.mcp.tool_state import init_tool_state
from mergecraft.review.roster_dispatch import reviewer_dispatch_batches
from mergecraft.review.roster_execution import run_pending_roster_reviewers
from mergecraft.utils.github import GitHubClient
from mergecraft.utils.instructions import ResolvedInstructions
from mergecraft.utils.run_bounds import BudgetTracker, resolve_run_bounds

A, B, C = "anthropic/claude-sonnet", "openai/gpt-5.3-codex", "opencode-go/deepseek-v4.1-flash"


async def exercise(root, retry):
    config = root / ".mergecraft/config.yaml"
    config.parent.mkdir(exist_ok=True)
    config.write_text(
        yaml.safe_dump(
            {
                "models": [A, A, B],
                "agents": {
                    "reviewer": {"role": "reviewer", "modelChain": [A]},
                    "reviewer-2": {"role": "reviewer", "modelChain": [A, B, C], "after": "reviewer"},
                    "reviewer-3": {"role": "reviewer", "modelChain": [C], "after": "reviewer-2"},
                },
            }
        )
    )
    settings = load_repo_settings(root=root)
    registry = load_registry(settings=settings)
    registry.validate()
    assert [len(level) for level in reviewer_dispatch_batches(registry)] == [1, 1, 1]
    state = init_tool_state(owner="local", name="demo", dir=str(root))
    tracker = BudgetTracker(resolve_run_bounds(settings=settings))
    tool = ToolContext(
        agent_id="opencode",
        repo=RepoIdentity(owner="local", name="demo"),
        payload=ResolvedPayload(event=PayloadEvent(trigger="unknown"), shell="disabled"),
        github=GitHubClient(token=""),
        github_installation_token="",
        git_token="",
        api_token="",
        modes=(),
        tool_state=state,
        mcp_server_url="",
        tmpdir=str(root),
        trust_tier="trusted",
        budget_tracker=tracker,
    )
    ctx = AgentRunContext(
        payload={},
        mcp_server_url="",
        tmpdir=str(root),
        instructions="Review",
        subagent_denied_tools=(),
        tool_state=state,
        budget_tracker=tracker,
    )
    attempts = []

    class Agent:
        name = "opencode"

        async def run(self, ctx):
            agent_id = next(
                name
                for name in ("reviewer-2", "reviewer-3")
                if f"Your reviewer agent_id is `{name}`." in ctx.instructions.system
            )
            assert localci_review_pipeline.recording_model(agent_id) == ctx.resolved_model
            attempts.append((ctx.resolved_model, os.environ["REVIEW_TEST_API_KEY"]))
            return AgentResult(
                success=ctx.resolved_model == C,
                metadata={"retryable": retry},
                usage=AgentUsage(agent=self.name, input_tokens=10, output_tokens=5, cost_usd=0.01),
            )

    with (
        patch.dict(os.environ, {"REVIEW_TEST_API_KEY": "fixture-default"}),
        patch.object(
            localci_review_pipeline,
            "_routes",
            {
                name: [
                    {"model": slug, "target": "REVIEW_TEST_API_KEY", "key": f"fixture-{i}"}
                    for i, slug in enumerate(slugs)
                ]
                for name, slugs in {"reviewer": [A, A, B], "reviewer-2": [A, B, C], "reviewer-3": [C]}.items()
            },
        ),
        secondary_usage(usages := []),
        patch(
            "mergecraft.agents.registry.pick_runnable_slug_from_chain",
            side_effect=lambda chain, **kw: chain[0],
        ),
        patch("mergecraft.review.roster_execution.resolve_runtime_agent", return_value=Agent()),
        patch("mergecraft.review.roster_execution.resolve_model", side_effect=lambda slug, **kw: slug),
        patch("mergecraft.review.roster_execution.credential_status_for_slug") as credentials,
        patch(
            "mergecraft.utils.instructions.resolve_instructions",
            return_value=ResolvedInstructions(system="review", user=""),
        ),
        patch("mergecraft.review.roster_execution.subagent_denied_tool_names", return_value=[]),
        patch("mergecraft.review.roster_execution.verifier_denied_tool_names", return_value=[]),
    ):
        assert len(localci_review_pipeline.harness_batches(reviewer_dispatch_batches(registry))) == 1
        try:
            localci_review_pipeline.recording_model("reviewer-2")
        except ValueError:
            pass
        else:
            raise AssertionError("A primary must not record a secondary outcome")
        primary = []

        async def primary_attempt(slug):
            primary.append((slug, os.environ["REVIEW_TEST_API_KEY"]))
            return AgentResult(
                success=slug == B, terminal_submission_received=slug == B, metadata={"retryable": True}
            )

        with patch("mergecraft.agents.resolution.runtime.agent_mode_for_slug", return_value="opencode"):
            _, result = await run_with_model_chain(
                settings=settings, run_once=primary_attempt, max_attempts=3
            )
        assert result.success and primary == [(A, "fixture-0"), (A, "fixture-1"), (B, "fixture-2")], primary
        assert os.environ["REVIEW_TEST_API_KEY"] == "fixture-default"
        credentials.return_value.available = True
        summary = await run_pending_roster_reviewers(
            tool_context=tool,
            base_run_ctx=ctx,
            settings=settings,
            payload={},
            repo_root=root,
            per_reviewer_timeout_s=10,
        )
    assert attempts == (
        [(A, "fixture-0"), (B, "fixture-1"), (C, "fixture-2"), (C, "fixture-0")]
        if retry
        else [(A, "fixture-0"), (C, "fixture-0")]
    ), (attempts, summary)
    assert len(usages) == len(attempts)
    assert tracker.tokens_used == 15 * len(attempts)
    assert abs(tracker.cost_used - 0.01 * len(attempts)) < 1e-9
    assert (summary.hard_error is None) == retry


with TemporaryDirectory() as directory:
    asyncio.run(exercise(Path(directory), True))
    asyncio.run(exercise(Path(directory), False))
print("PASS: ordered reviewer roster, two backups, and required failure")
