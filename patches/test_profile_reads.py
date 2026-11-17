"""Installed-image integration checks: real Git, original guards, bounded batches."""

import asyncio
import importlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace

from mergecraft.localci_git_batch import git_batch_tool
from mergecraft.localci_profile import invoke
from mergecraft.mcp.git import _git_show_preview
from mergecraft.mcp.tool_state import init_tool_state
from mergecraft.utils.run_bounds import BudgetTracker, RunBounds


async def main():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        repo = root / "repo"
        repo.mkdir()

        def git(*args):
            return (
                subprocess.check_output(["git", *args], cwd=repo, stderr=subprocess.DEVNULL).decode().strip()
            )

        git("init", "-b", "main")
        git("config", "user.name", "Fixture")
        git("config", "user.email", "fixture@local")
        content = "\n".join(f"line {i}" for i in range(500)) + "\n"
        (repo / "sample.txt").write_text(content)
        git("add", ".")
        git("commit", "-qm", "fixture")
        head = git("rev-parse", "HEAD")
        state = init_tool_state(owner="fixture", name="repo", dir=str(repo))
        bounds = RunBounds(
            token_budget=1000,
            cost_budget_usd=1,
            tool_call_budget=100,
            run_timeout_s=60,
            context_retrieval_timeout_s=10,
            max_diff_lines=10000,
            external_operation_timeout_s=10,
        )
        ctx = SimpleNamespace(tool_state=state, tmpdir=str(root), budget_tracker=BudgetTracker(bounds))
        tool = git_batch_tool(ctx)
        assert not tool.mutates
        os.environ["LOCALCI_PROFILE_PATH"] = str(root / "profile.jsonl")
        result = await invoke(
            tool,
            {
                "requests": [
                    {"command": "show", "args": ["HEAD:sample.txt"]},
                    {"command": "diff", "args": ["HEAD", "HEAD"]},
                ]
            },
        )
        assert not result.is_error
        data = json.loads(result.content[0]["text"])
        assert len(data["results"]) == 2 and not any(r["isError"] for r in data["results"])
        path = Path(json.loads(data["results"][0]["content"][0]["text"])["outputPath"])
        assert path.read_text() == content and path.is_relative_to(root / "evidence")
        assert "line 119" in _git_show_preview(str(path)) and "truncated" in _git_show_preview(str(path))
        guards = await tool.execute(
            {
                "requests": [
                    {"command": "reset", "args": ["--hard", "HEAD~1"]},
                    {"command": "show", "args": ["HEAD:.git/config"]},
                ]
            }
        )
        data = json.loads(guards.content[0]["text"])
        assert all(v["isError"] for v in data["results"]) and git("rev-parse", "HEAD") == head
        assert (await tool.execute({"requests": [{"command": "status"}] * 9})).is_error
        assert ctx.budget_tracker.tool_calls == 4
        rows = [json.loads(line) for line in (root / "profile.jsonl").read_text().splitlines()]
        assert rows[0]["batch_size"] == 2 and rows[0]["seconds"] >= 0
        assert "sample.txt" not in json.dumps(rows) and "line 119" not in json.dumps(rows)
        opencode = importlib.import_module("mergecraft.agents.opencode")
        allows = opencode._build_review_mode_read_allowlist(repo, root / "evidence")
        assert allows[str(root / "evidence") + "/**"] == "allow"
        assert allows[str(repo) + "/.git/**"] == "deny"
        print(
            "Batch reads, full exports, original mutation/config guards, budgets and metadata-only timing passed"
        )


asyncio.run(main())
