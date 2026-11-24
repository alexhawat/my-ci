"""Verifier citations for files outside the working tree, and the repeated-call stop."""

import asyncio
import json
import os
import shutil
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

from mergecraft.agents import opencode
from mergecraft.agents.verifier import AgentFinding, plan_agent_verifications
from mergecraft.localci_compaction import configure
from mergecraft.localci_live_budget import active, bind
from mergecraft.localci_loop_guard import NOTICE_AT, STOP_AT
from mergecraft.localci_profile import invoke
from mergecraft.mcp.shared import ToolClass, execute, tool
from mergecraft.mcp.tool_state import init_tool_state
from mergecraft.utils.run_bounds import BudgetTracker, RunBounds


def citations():
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)

        def git(*args):
            subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)

        git("init", "-b", "main")
        git("config", "user.name", "Fixture")
        git("config", "user.email", "fixture@local")
        for name in (".agents/fleet/tool.py", "docs/other.md", "src/app.py"):
            (repo / name).parent.mkdir(parents=True, exist_ok=True)
            (repo / name).write_text("fixture\n")
        (repo / ".agents/link.py").symlink_to("fleet/tool.py")
        git("add", ".")
        git("commit", "-qm", "fixture")
        shutil.rmtree(repo / ".agents")  # As Local CI does before the review.
        (repo / "untracked.py").write_text("fixture\n")
        changed = frozenset({".agents/fleet/tool.py", ".agents/link.py", "src/app.py", "gone.py"})

        def plan(path):
            finding = AgentFinding(path=path, body="Claim.", severity="Major", line=1, fingerprint="f" * 64)
            (item,) = plan_agent_verifications(
                [finding], budget=24, repo_root=repo, changed_paths=changed
            ).dispatch
            return item

        present = plan("src/app.py")
        assert present.cited_file and "read_batch" not in present.brief
        removed = plan(".agents/fleet/tool.py")
        assert removed.cited_file is None, "No path outside the working tree may be handed out"
        assert "Local CI removed it from the working tree" in removed.brief
        assert "that alone is a **drop**" not in removed.brief
        outside = plan("docs/other.md")
        assert outside.cited_file is None and "this diff does not change it" in outside.brief
        assert "not present in the checkout" not in outside.brief
        for path in (
            "gone.py",
            "untracked.py",
            ".agents/link.py",
            ".agents",
            "../outside",
            "/etc/passwd",
            "src/../src/app.py",
        ):
            item = plan(path)
            if item.cited_file is None:
                assert "that alone is a **drop**" in item.brief, (path, item.brief)
    print("PASS: the verifier names files of the reviewed commit and still drops anything else")


requests = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, body, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if body is not None:
            self.wfile.write(json.dumps(body).encode())

    def do_GET(self):
        self.reply(None, 405)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or "{}")
        if self.path == "/mcp":
            if "id" not in body:
                return self.reply(None, 202)
            method, result = body.get("method"), {}
            if method == "initialize":
                result = {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fixture", "version": "1"},
                }
            elif method == "tools/list":
                schema = {"type": "object", "properties": {"path": {"type": "string"}}}
                result = {"tools": [{"name": spec.name, "description": "Fixture", "inputSchema": schema}]}
            elif method == "tools/call":
                # The real hook, on a server thread that never saw bind().
                value = asyncio.run(invoke(spec, body["params"].get("arguments") or {}))
                result = {"content": value.content}
            return self.reply({"jsonrpc": "2.0", "id": body["id"], "result": result})
        names = [t.get("function", {}).get("name", "") for t in body.get("tools", [])]
        name = next((n for n in names if spec.name in n), "")
        replies = [m for m in body["messages"] if m.get("role") == "tool"]
        requests.append({"mcp": bool(name), "text": "\n".join(str(m.get("content", "")) for m in replies)})
        if len(requests) > 40:
            return self.send_error(500)
        # MCP discovery is asynchronous; read a file until the tool is listed.
        mcp_calls = sum(r["mcp"] for r in requests)
        if name and case == "progress" and mcp_calls > STOP_AT + 4:
            chunks = [({"role": "assistant", "content": "Fixture review complete."}, None), ({}, "stop")]
        else:
            arguments = {"path": f"file-{mcp_calls}" if case == "progress" else f"file-{mcp_calls % 2}"}
            if not name:
                name, arguments = "read", {"filePath": str(root / "source.txt")}
            call = {
                "index": 0,
                "id": f"call{len(requests)}",
                "type": "function",
                "function": {"name": name, "arguments": json.dumps(arguments)},
            }
            chunks = [({"role": "assistant", "tool_calls": [call]}, None), ({}, "tool_calls")]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        common = {
            "id": f"f{len(requests)}",
            "object": "chat.completion.chunk",
            "created": 1,
            "model": "fixture",
        }
        rows = [{**common, "choices": [{"index": 0, "delta": d, "finish_reason": f}]} for d, f in chunks]
        usage = {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110}
        rows.append({**common, "choices": [], "usage": usage})
        for row in rows:
            self.wfile.write(f"data: {json.dumps(row)}\n\n".encode())
        self.wfile.write(b"data: [DONE]\n\n")


async def answer(params):
    return "fixture result"


spec = tool(
    name="read_batch",
    tool_class=ToolClass.REPOSITORY_READ,
    description="Fixture",
    input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
    execute=execute(answer, "read_batch"),
)
citations()
server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
for case in ("loop", "progress"):
    with tempfile.TemporaryDirectory() as tmp:
        requests.clear()
        root = Path(tmp)
        (root / "source.txt").write_text("fixture source\n")
        url = f"http://127.0.0.1:{server.server_port}"
        config = {
            "provider": {
                "fixture": {
                    "npm": "@ai-sdk/openai-compatible",
                    "name": "Fixture",
                    "options": {"baseURL": f"{url}/v1", "apiKey": "disposable-fixture"},
                    "models": {"fixture": {"name": "Fixture", "limit": {"context": 1000000, "output": 1000}}},
                }
            },
            "enabled_providers": ["fixture"],
            "mcp": {"fixture": {"type": "remote", "url": f"{url}/mcp", "codemode": False}},
            "permission": {
                "*": "deny",
                "read": "allow",
                "external_directory": "allow",
                "fixture_read_batch": "allow",
                "execute": "deny",
            },
        }
        tracker = BudgetTracker(
            RunBounds(
                token_budget=1000000,
                token_budget_tolerance=0,
                cost_budget_usd=5,
                tool_call_budget=100,
                run_timeout_s=240,
                context_retrieval_timeout_s=10,
                max_diff_lines=10000,
                external_operation_timeout_s=10,
            )
        )
        ctx = SimpleNamespace(
            tmpdir=str(root),
            tool_state=init_tool_state(owner="fixture", name="repo", dir=str(root)),
            budget_tracker=tracker,
            idle_timeout_s=90,
            resolved_model="fixture/fixture",
        )
        with bind(tracker) as live:
            assert active() is live
            os.environ["LOCALCI_PROFILE_PATH"] = str(root / "profile.jsonl")
            configure(ctx, "fixture/fixture", config)
            path = root / "opencode.json"
            path.write_text(json.dumps(config))
            opencode._hand_xdg_data_home_to_agent(root)
            result = opencode._run_opencode_cli_streaming(
                cmd=[
                    "opencode",
                    "run",
                    "--standalone",
                    "--format",
                    "json",
                    "--title",
                    "mergecraft",
                    "--model",
                    "fixture/fixture",
                    "Review the fixture.",
                ],
                ctx=ctx,
                env={
                    **os.environ,
                    "OPENCODE_CONFIG": str(path),
                    "OPENCODE_CONFIG_DIR": str(root / "opencode-xdg-config"),
                    "OPENCODE_DISABLE_PROJECT_CONFIG": "1",
                    "OPENCODE_DISABLE_MODELS_FETCH": "true",
                    "XDG_DATA_HOME": str(root / "data"),
                    "XDG_CONFIG_HOME": str(root / "config"),
                    "XDG_CACHE_HOME": str(root / "cache"),
                    "PWD": str(root),
                },
                session={},
            )
        assert active() is None
        usage = json.loads((root / "mergecraft-usage.json").read_text())
        calls = sum(r["mcp"] for r in requests)
        assert calls, "The fixture never reached the MCP tool"
        told = sum("Local CI: this exact call" in r["text"] for r in requests)
        if case == "progress":
            assert result.success and calls == STOP_AT + 5, (result, calls)
            assert not told and not live.loops.reason and not usage["stopped"]
            assert tracker.last_exhausted is None
            print("PASS: a review that keeps making new calls is never told or stopped")
            continue
        # Two alternating calls, as in the review that looped; each may be made STOP_AT times.
        assert 2 * STOP_AT - 1 <= calls <= 2 * STOP_AT + 1, calls
        assert told >= 2 * (STOP_AT - NOTICE_AT) - 2, "OpenCode must deliver the note to the model"
        assert not result.success and result.metadata.get("budget_exhausted"), result
        assert "Repeated tool calls without progress (read_batch" in result.error
        assert tracker.last_exhausted is not None and tracker.last_exhausted.kind == "tool_call"
        assert usage["stopped"] and "Repeated tool calls" in usage["reason"], usage
        assert usage["total_tokens"] >= 110 * (calls - 1), "Steps before the stop stay charged"
        print("PASS: alternating repeated calls are named to the model, then stop the review as inconclusive")
server.shutdown()
