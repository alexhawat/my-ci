import asyncio
import json
import os
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mergecraft.agents import opencode_config as opencode
from mergecraft.localci_read_batch import read_batch_tool
from mergecraft.mcp.tool_state import init_tool_state, primary_repo_state
from mergecraft.utils.run_bounds import BudgetTracker, RunBounds

seen = []
fixture = tempfile.TemporaryDirectory()
fixture_root = Path(fixture.name)
diff = fixture_root / "fixture.diff"
diff.write_text("FIRST_RETURNED_LINE\n" + ("source 漢字 " + "x" * 60 + "\n") * 1500)
state = init_tool_state(owner="fixture", name="repo", dir=str(fixture_root))
primary_repo_state(state).diff_path = str(diff)
tracker = BudgetTracker(
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
)
tracker.record_tokens(2500000)
ctx = SimpleNamespace(tool_state=state, tmpdir=str(fixture_root), budget_tracker=tracker)
result = asyncio.run(read_batch_tool(ctx).execute({"requests": [{"path": "@diff", "limit": 2000}]}))
assert not result.is_error
payload = result.content[0]["text"]
assert payload.startswith("Token budget: used=2500000; ceiling=5000000; remaining=2500000")
assert "Budget checkpoint:" in payload
assert len(payload.encode("utf-8")) < 40000
assert len(payload.splitlines()) < 1100
assert any(call.diff_read for call in state.tool_calls)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_error(405)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or "{}")
        if self.path == "/mcp":
            method = body.get("method")
            result = (
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fixture", "version": "1"},
                }
                if method == "initialize"
                else {
                    "tools": [
                        {
                            "name": "read_batch",
                            "description": "Read fixture source ranges",
                            "inputSchema": {"type": "object", "properties": {}},
                        }
                    ]
                }
                if method == "tools/list"
                else {"content": [{"type": "text", "text": payload}]}
                if method == "tools/call"
                else {}
            )
            self.send_response(200 if "id" in body else 202)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            if "id" in body:
                self.wfile.write(json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": result}).encode())
            return
        names = [t.get("function", {}).get("name") for t in body.get("tools", [])]
        tool = next((name for name in names if "read_batch" in name), "")
        messages = [m for m in body.get("messages", []) if m.get("role") == "tool"]
        text = "\n".join(str(m.get("content", "")) for m in messages)
        seen.append(
            {
                "tools": names,
                "tool_message_chars": len(text),
                "full_payload": payload in text
                or payload in "\n".join(str(m.get("content", "")) for m in messages),
                "has_first": "FIRST_RETURNED_LINE" in text,
                "has_last": payload.splitlines()[-1] in text,
                "has_budget": "remaining=2500000" in text,
                "truncated": "truncat" in text.lower(),
                "lines": len(text.splitlines()),
            }
        )
        if tool and not messages:
            chunks = [
                (
                    {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "fixturecall",
                                "type": "function",
                                "function": {"name": tool, "arguments": "{}"},
                            }
                        ],
                    },
                    None,
                ),
                ({}, "tool_calls"),
            ]
        else:
            chunks = [({"role": "assistant", "content": "Fixture complete."}, None), ({}, "stop")]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for delta, finish in chunks:
            data = {
                "id": "fixture",
                "object": "chat.completion.chunk",
                "created": 1,
                "model": "fixture",
                "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
            }
            self.wfile.write(("data: " + json.dumps(data) + "\n\n").encode())
            self.wfile.flush()
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


s = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=s.serve_forever, daemon=True).start()
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    config = {
        "provider": {
            "fixture": {
                "npm": "@ai-sdk/openai-compatible",
                "name": "Fixture",
                "options": {
                    "baseURL": f"http://127.0.0.1:{s.server_port}/v1",
                    "apiKey": "disposable-fixture",
                },
                "models": {"fixture": {"name": "Fixture", "limit": {"context": 1000000, "output": 1000}}},
            }
        },
        "enabled_providers": ["fixture"],
        "mcp": {
            "fixture": {"type": "remote", "url": f"http://127.0.0.1:{s.server_port}/mcp", "codemode": False}
        },
        "permission": {"*": "deny", "fixture_read_batch": "allow", "execute": "deny"},
        "compaction": {"auto": False},
    }
    with (
        patch.object(opencode, "_checkout_root", return_value=root),
        patch.object(opencode, "evidence_dir", return_value=root / "evidence"),
        patch(
            "mergecraft.agents.harness_render.render_for_run",
            return_value=SimpleNamespace(payload={"agent": {}}),
        ),
        patch.object(opencode, "build_custom_providers_for_models", return_value={}),
    ):
        security = json.loads(
            opencode.build_security_config(
                SimpleNamespace(
                    tmpdir=str(root),
                    mcp_server_url=f"http://127.0.0.1:{s.server_port}/mcp",
                    mcp_auth_token=None,
                ),
                None,
            )
        )
    config["permission"] = security["permission"]
    config["mcp"] = {"fixture": next(iter(security["mcp"].values()))}
    assert config["permission"]["execute"] == "deny" and config["permission"]["read"] == "deny"
    assert config["mcp"]["fixture"]["codemode"] is False
    p = root / "opencode.json"
    p.write_text(json.dumps(config))
    env = {
        **os.environ,
        "OPENCODE_CONFIG": str(p),
        "OPENCODE_DISABLE_MODELS_FETCH": "true",
        "XDG_DATA_HOME": str(root / "data"),
        "XDG_CONFIG_HOME": str(root / "config"),
        "XDG_CACHE_HOME": str(root / "cache"),
        "PWD": str(root),
    }
    r = subprocess.run(
        [
            "opencode",
            "run",
            "--standalone",
            "--format",
            "json",
            "--title",
            "mergecraft",
            "--model",
            "fixture/fixture",
            "Read the fixture using read_batch then finish.",
        ],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert r.returncode == 0, r.stderr[-1000:]
    assert any(
        row["full_payload"] and row["has_first"] and row["has_last"] and row["has_budget"] for row in seen
    ), seen
    assert not any(row["truncated"] for row in seen), seen
    print("PASS: real OpenCode delivers every credited source line and the live budget intact to the model")
s.shutdown()

fixture.cleanup()
