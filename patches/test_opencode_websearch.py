"""Real pinned CLI regression, entirely offline with a synthetic model endpoint."""

import importlib
import json
import os
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        names = [t.get("function", {}).get("name") for t in body.get("tools", [])]
        requested = any(m.get("role") == "tool" for m in body["messages"])
        if "websearch" in names and not requested:
            chunks = [
                (
                    {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "fixturecall",
                                "type": "function",
                                "function": {
                                    "name": "websearch",
                                    "arguments": json.dumps({"query": "fixture"}),
                                },
                            }
                        ],
                    },
                    None,
                ),
                ({}, "tool_calls"),
            ]
        else:
            chunks = [({"role": "assistant", "content": "Fixture response."}, None), ({}, "stop")]
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
root = Path(tempfile.mkdtemp(prefix="opencode-lifecycle-"))
config = {
    "$schema": "https://opencode.ai/config.json",
    "provider": {
        "fixture": {
            "npm": "@ai-sdk/openai-compatible",
            "name": "Fixture",
            "options": {"baseURL": f"http://127.0.0.1:{s.server_port}/v1", "apiKey": "disposable-fixture"},
            "models": {"fixture": {"name": "Fixture", "limit": {"context": 100000, "output": 1000}}},
        }
    },
    "enabled_providers": ["fixture"],
    "permission": {"*": "deny"},
}
adapter = importlib.import_module("mergecraft.agents.opencode")
with (
    patch.object(adapter, "_checkout_root", return_value=root),
    patch.object(adapter, "_evidence_dir", return_value=root / "evidence"),
):
    config["permission"] = adapter._build_review_mode_permissions(SimpleNamespace(tmpdir=str(root)))
assert config["permission"]["websearch"] == "deny"
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
for permission in ("allow", "deny"):
    config["permission"]["websearch"] = permission
    p.write_text(json.dumps(config))
    r = subprocess.run(
        [
            "opencode",
            "run",
            "--standalone",
            "--print-logs",
            "--log-level",
            "error",
            "--format",
            "json",
            "--model",
            "fixture/fixture",
            "Reply with a short sentence.",
        ],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=90,
    )
    if permission == "allow":
        assert r.returncode == 1 and "Web search cancelled" in r.stdout, (
            r.returncode,
            r.stdout,
            r.stderr[-1000:],
        )
    else:
        assert (
            r.returncode == 0 and "Fixture response." in r.stdout and "Web search cancelled" not in r.stdout
        ), (r.returncode, r.stdout, r.stderr[-1000:])
    print("PASS: websearch", permission, "exit", r.returncode, flush=True)
s.shutdown()
