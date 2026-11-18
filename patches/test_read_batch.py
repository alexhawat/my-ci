"""Verify real text batches, original Git guards and exact returned-span evidence."""

import asyncio
import json
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace

from mergecraft.localci_read_batch import read_batch_tool
from mergecraft.mcp.git import git_tool
from mergecraft.mcp.tool_state import init_tool_state, primary_repo_state
from mergecraft.utils.run_bounds import BudgetTracker, RunBounds


async def main():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        repo = root / "repo"
        repo.mkdir()

        def git(*args):
            return subprocess.check_output(["git", *args], cwd=repo, stderr=subprocess.DEVNULL)

        git("init", "-b", "main")
        git("config", "user.name", "Fixture")
        git("config", "user.email", "fixture@local")
        (repo / "sample.txt").write_text("\n".join(f"line {i}" for i in range(500)) + "\n")
        (repo / "long.txt").write_text("shown\n" + "x" * 80000 + "\nnot returned\n")
        # One "\n"-terminated line holding characters that str.splitlines() also breaks on.
        (repo / "breaks.txt").write_bytes("first\fstill\u2028first\x85same\rline\nsecond\r\nthird\n".encode())
        git("add", ".")
        git("commit", "-qm", "fixture")
        state = init_tool_state(owner="fixture", name="repo", dir=str(repo))
        diff = root / "review.diff"
        diff.write_text(
            "diff --git a/sample.txt b/sample.txt\n--- a/sample.txt\n+++ b/sample.txt\n@@ -1 +1 @@\n-line 0\n+changed\n"
        )
        primary_repo_state(state).diff_path = str(diff)
        ctx = SimpleNamespace(
            tool_state=state,
            tmpdir=str(root),
            budget_tracker=BudgetTracker(
                RunBounds(
                    token_budget=5000000,
                    token_budget_tolerance=0,
                    cost_budget_usd=5,
                    tool_call_budget=100,
                    run_timeout_s=60,
                    context_retrieval_timeout_s=10,
                    max_diff_lines=10000,
                    external_operation_timeout_s=10,
                )
            ),
        )
        tool = read_batch_tool(ctx)
        assert not tool.mutates

        async def read(requests):
            result = await tool.execute({"requests": requests})
            assert not result.is_error, result.content
            text = result.content[0]["text"]
            assert len(text.encode("utf-8")) <= 40000 and len(text.splitlines()) <= 1100
            parts = text.split("\nRange: ")
            ranges = []
            for part in parts[1:]:
                header, _, body = part.partition("\n")
                ranges.append({**json.loads(header), "text": body})
            used = ctx.budget_tracker.tokens_used
            return {
                "results": ranges,
                "note": parts[0].split("\n", 1)[1],
                "token_usage": {"used": used, "ceiling": 5000000, "remaining": 5000000 - used},
            }

        data = await read(
            [{"path": "@diff", "start": 2, "limit": 3}, {"path": "sample.txt", "start": 123, "limit": 4}]
        )
        assert data["results"][0]["text"].startswith("2: ---")
        assert data["results"][0]["next_line"] == 5
        assert data["results"][1]["text"] == "123: line 122\n124: line 123\n125: line 124\n126: line 125"
        assert data["token_usage"]["ceiling"] == 5000000
        calls = [v.model_dump() for v in state.tool_calls]
        assert any(c.get("diff_read") == (2, 4) for c in calls), calls
        data = await read([{"path": "long.txt", "limit": 20}])
        assert data["results"][0]["text"] == "1: shown"
        assert data["results"][0]["end"] == 1 and data["results"][0]["next_line"] == 2
        for requests in [
            [{"path": "../outside"}],
            [{"path": "/etc/passwd"}],
            [{"path": "sample.txt", "limit": 2001}],
            [{"path": "sample.txt", "start": True}],
            [{"path": "sample.txt", "command": "reset"}],
            [{"path": "sample.txt"}] * 9,
        ]:
            assert (await tool.execute({"requests": requests})).is_error
        exported = await git_tool(ctx).execute({"command": "show", "args": ["HEAD:sample.txt"]})
        export_path = json.loads(exported.content[0]["text"])["outputPath"]
        data = await read([{"path": export_path, "start": 498, "limit": 3}])
        assert data["results"][0]["text"] == "498: line 497\n499: line 498\n500: line 499"
        # Form feed, U+2028, NEL and a bare carriage return inside a line do not start a new
        # one: later lines keep the numbers Git gives them, and CRLF endings are not shown.
        data = await read([{"path": "breaks.txt", "start": 2, "limit": 5}])
        assert data["results"][0]["text"] == "2: second\n3: third", data["results"][0]
        assert data["results"][0]["end"] == 3 and data["results"][0]["next_line"] is None
        assert data["results"][0]["total_lines"] == 3
        assert data["token_usage"]["remaining"] == 5000000
        outside = root / "private-config.json"
        outside.write_text("private fixture")
        assert (await tool.execute({"requests": [{"path": str(outside)}]})).is_error
        before = len(state.tool_calls)
        failed = await tool.execute({"requests": [{"path": "@diff"}, {"path": "../outside"}]})
        assert failed.is_error and len(state.tool_calls) == before, (
            "Failed batches must not credit unreturned text"
        )
        data = await read([{"path": ".git/config"}])
        assert "error" in data["results"][0]
        (repo / "unicode.txt").write_text(("漢" * 200 + "\n") * 1500)
        git("add", "unicode.txt")
        git("commit", "-qm", "unicode fixture")
        data = await read([{"path": "unicode.txt", "limit": 2000}])
        assert 1 < data["results"][0]["end"] < 40
        assert data["results"][0]["next_line"] == data["results"][0]["end"] + 1
        ctx.budget_tracker.record_tokens(2500000)
        data = await read([{"path": "sample.txt", "limit": 2}])
        assert data["note"].startswith("Budget checkpoint:")
        assert "Never drop an unresolved finding or approve incomplete coverage" in data["note"]
        assert data["results"][0]["text"] == "1: line 0\n2: line 1"
        assert data["token_usage"]["remaining"] == 2500000
        assert git("status", "--porcelain") == b""
    print(
        "PASS: batched full text, precise diff spans, truncation continuation, Git confinement and unchanged checkout"
    )


asyncio.run(main())
