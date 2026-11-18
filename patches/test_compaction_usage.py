import json
import os
import re
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

from mergecraft.agents import opencode
from mergecraft.localci_compaction import configure
from mergecraft.localci_live_budget import bind
from mergecraft.mcp.tool_state import init_tool_state
from mergecraft.utils.run_bounds import BudgetTracker, RunBounds, record_agent_usage

requests = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        last = str(body["messages"][-1].get("content", ""))
        compact = "Do not continue the task or call tools." in last
        requests.append({"kind": "compaction" if compact else "primary"})
        count = len(requests)
        primary = sum(r["kind"] == "primary" for r in requests)
        headings = re.findall(r"^## .+$", last, re.M) if compact else []
        if count > 5:
            self.send_error(500)
            return
        if not compact and primary <= primary_reads:
            chunks = [
                (
                    {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": f"fixturecall{count}",
                                "type": "function",
                                "function": {
                                    "name": "read",
                                    "arguments": json.dumps({"filePath": str(root / "source.txt")}),
                                },
                            }
                        ],
                    },
                    None,
                ),
                ({}, "tool_calls"),
            ]
        else:
            chunks = [
                (
                    {
                        "role": "assistant",
                        "content": "\n\n".join(
                            h + "\n- Fixture source inspected; complete the pending verdict."
                            for h in headings
                        )
                        if headings
                        else "Fixture review complete.",
                    },
                    None,
                ),
                ({}, "stop"),
            ]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for delta, finish in chunks:
            data = {
                "id": f"fixture{count}",
                "object": "chat.completion.chunk",
                "created": count,
                "model": "fixture",
                "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
            }
            self.wfile.write(("data: " + json.dumps(data) + "\n\n").encode())
            self.wfile.flush()
        tokens = 1000 if compact or primary > primary_reads else (first_tokens if primary == 1 else 90000)
        self.wfile.write(
            (
                "data: "
                + json.dumps(
                    {
                        "id": f"fixture{count}",
                        "object": "chat.completion.chunk",
                        "created": count,
                        "model": "fixture",
                        "choices": [],
                        "usage": {
                            "prompt_tokens": tokens,
                            "completion_tokens": 10,
                            "total_tokens": tokens + 10,
                            "prompt_tokens_details": {"cached_tokens": 100},
                            "completion_tokens_details": {"reasoning_tokens": 2},
                        },
                    }
                )
                + "\n\ndata: [DONE]\n\n"
            ).encode()
        )
        self.wfile.flush()


s = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=s.serve_forever, daemon=True).start()
for case, ceiling, first_tokens, primary_reads in [
    ("complete", 10000, 5000, 1),
    ("ceiling", 6000, 5000, 1),
    ("threshold", 200000, 50000, 2),
    ("missing-plugin", 10000, 5000, 1),
]:
    assert first_tokens > 0 and primary_reads > 0
    with tempfile.TemporaryDirectory() as tmp:
        requests.clear()
        root = Path(tmp)
        (root / "source.txt").write_text("fixture source\n")
        config = {
            "provider": {
                "fixture": {
                    "npm": "@ai-sdk/openai-compatible",
                    "name": "Fixture",
                    "options": {
                        "baseURL": f"http://127.0.0.1:{s.server_port}/v1",
                        "apiKey": "disposable-fixture",
                    },
                    "models": {"fixture": {"name": "Fixture", "limit": {"context": 10000, "output": 1000}}},
                }
            },
            "enabled_providers": ["fixture"],
            "permission": {"*": "deny", "read": "allow", "external_directory": "allow"},
            "compaction": {"auto": True, "background": False, "keep": {"tokens": 1000}, "buffer": 6000},
        }
        tracker = BudgetTracker(
            RunBounds(
                token_budget=ceiling,
                token_budget_tolerance=0,
                cost_budget_usd=5,
                tool_call_budget=100,
                run_timeout_s=60,
                context_retrieval_timeout_s=10,
                max_diff_lines=10000,
                external_operation_timeout_s=10,
            )
        )
        ctx = SimpleNamespace(
            tmpdir=str(root),
            tool_state=init_tool_state(owner="fixture", name="repo", dir=str(root)),
            budget_tracker=tracker,
            idle_timeout_s=30,
            resolved_model="fixture/fixture",
        )
        with bind(tracker) as live:
            configure(ctx, "fixture/fixture", config)
            config["compaction"] = {
                "auto": True,
                "background": False,
                "keep": {"tokens": 1000},
                "buffer": 6000,
            }
            if case == "threshold":
                config["provider"]["fixture"]["models"]["fixture"]["limit"] = {
                    "context": 1000000,
                    "output": 384000,
                }
                config["compaction"]["buffer"] = "92%"
            if case == "missing-plugin":
                config["plugins"] = []
            os.environ["LOCALCI_PROFILE_PATH"] = str(root / "profile.jsonl")
            p = root / "opencode.json"
            p.write_text(json.dumps(config))
            env = {
                **os.environ,
                "OPENCODE_CONFIG": str(p),
                "OPENCODE_CONFIG_DIR": str(root / "opencode-xdg-config"),
                "OPENCODE_DISABLE_PROJECT_CONFIG": "1",
                "OPENCODE_DISABLE_MODELS_FETCH": "true",
                "XDG_DATA_HOME": str(root / "data"),
                "XDG_CONFIG_HOME": str(root / "config"),
                "XDG_CACHE_HOME": str(root / "cache"),
                "PWD": str(root),
                "LOCALCI_PROFILE_PATH": str(root / "profile.jsonl"),
            }
            opencode._hand_xdg_data_home_to_agent(root)
            session = {}
            command = [
                "opencode",
                "run",
                "--standalone",
                "--print-logs",
                "--log-level",
                "error",
                "--format",
                "json",
                "--title",
                "mergecraft",
                "--model",
                "fixture/fixture",
                "Read source.txt then deliver a short verdict.",
            ]
            result = opencode._run_opencode_cli_streaming(
                cmd=command,
                ctx=ctx,
                env=env,
                session=session,
            )
            if case in {"ceiling", "missing-plugin"}:
                assert not result.success and result.metadata.get("budget_exhausted"), result
                if case == "ceiling":
                    assert live.error and sum(live.totals.values()) >= 6020
                else:
                    assert "did not initialize" in live.journal_error
                    saved = json.loads((root / "mergecraft-usage.json").read_text())
                    assert saved["stopped"] and saved["accounting_error_type"] == "ValueError"
                print("PASS:", case, "fails closed")
                continue
            assert result.success, (
                result.error,
                getattr(live, "journal_error", None),
                live.journal.path.read_text(),
            )
            expected = 7030 if case == "complete" else 142040
            assert [r["kind"] for r in requests] == (
                ["primary", "compaction", "primary"]
                if case == "complete"
                else ["primary", "primary", "compaction", "primary"]
            ), requests
            assert live.journal.compactions == 1
            assert tracker.tokens_used == expected, (tracker.tokens_used, live.journal.path.read_text())
            assert result.usage.input_tokens + result.usage.output_tokens == expected
            assert live.totals["cache_read"] == len(requests) * 100
            record_agent_usage(tracker, result.usage)
            assert tracker.tokens_used == expected, "Final accounting must not double-charge summaries"
            saved = json.loads((root / "mergecraft-usage.json").read_text())
            assert saved["total_tokens"] == expected and saved["compaction_steps"] == 1
            print(
                "PASS:", case, "native complete usage", expected, "with cached tokens and no double charging"
            )
            if case == "complete":
                resumed = opencode._run_opencode_cli_streaming(
                    cmd=[*command[:-1], "--session", session["id"], "Record the terminal verdict now."],
                    ctx=ctx,
                    env=env,
                    session=session,
                )
                assert resumed.success, (resumed.error, getattr(live, "journal_error", None))
                assert tracker.tokens_used == 8040
                assert live.journal.compactions == 1
                assert len(requests) == 4
                record_agent_usage(tracker, resumed.usage)
                assert tracker.tokens_used == 8040, "Resume usage must not be charged twice"
                print("PASS: post-run CLI resume retains cumulative usage without request-ID collisions")

s.shutdown()
