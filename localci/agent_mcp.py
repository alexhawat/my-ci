"""MCP streamable HTTP server sharing AgentService with the HTTP API."""

from __future__ import annotations

import contextvars
import json

from mcp.server.mcpserver import MCPServer

from localci.agent_service import AgentService
from localci.agent_tokens import AgentTokenStore, VerifiedToken

_agent_token: contextvars.ContextVar[VerifiedToken | None] = contextvars.ContextVar(
    "agent_token", default=None
)


class AgentMcpMiddleware:
    """Validate Bearer tokens before MCP handles the request."""

    def __init__(self, app, token_store: AgentTokenStore, addon_enabled):
        self.app = app
        self.token_store = token_store
        self.addon_enabled = addon_enabled

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if not self.addon_enabled():
            await _json_error(send, 404, "Agent access is disabled")
            return
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        auth = headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            self.token_store.audit("anonymous", "denied", scope.get("path", ""), "missing bearer")
            await _json_error(send, 401, "Bearer token required")
            return
        verified = self.token_store.verify(auth[7:].strip())
        if not verified:
            self.token_store.audit("anonymous", "denied", scope.get("path", ""), "invalid token")
            await _json_error(send, 401, "Invalid or expired token")
            return
        self.token_store.audit(verified.id, "auth", scope.get("path", ""), "mcp")
        token = _agent_token.set(verified)
        try:
            await self.app(scope, receive, send)
        finally:
            _agent_token.reset(token)


async def _json_error(send, status: int, detail: str) -> None:
    body = json.dumps({"detail": detail}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _service(controller) -> AgentService:
    verified = _agent_token.get()
    if not verified:
        raise RuntimeError("Agent token missing")
    return AgentService(controller, verified.scopes)


def build_mcp_app(controller, token_store: AgentTokenStore, addon_enabled):
    server = MCPServer(
        "my-ci",
        instructions="Programmatic access to my-ci runs and repositories. Requires a my-ci agent token.",
    )

    @server.tool(name="list_repos", description="List configured repositories and enablement flags.")
    async def list_repos() -> str:
        return json.dumps(_service(controller).list_repos())

    @server.tool(name="list_runs", description="List runs with optional repo/state filters.")
    async def list_runs(repo: str | None = None, state: str | None = None, limit: int = 50) -> str:
        return json.dumps(_service(controller).list_runs(repo=repo, state=state, limit=limit))

    @server.tool(name="get_run", description="Fetch one run by id.")
    async def get_run(run_id: str) -> str:
        return json.dumps(_service(controller).get_run(run_id))

    @server.tool(name="get_review", description="Review findings and diagnostics for a run.")
    async def get_review(run_id: str) -> str:
        return json.dumps(_service(controller).get_review(run_id))

    @server.tool(name="get_queue", description="Queued/running counts and worker status.")
    async def get_queue() -> str:
        return json.dumps(_service(controller).queue_status())

    @server.tool(name="rerun", description="Queue a new run for the same PR revision (write-runs scope).")
    async def rerun(run_id: str) -> str:
        return json.dumps(await _service(controller).rerun(run_id))

    @server.tool(
        name="set_repo_review",
        description="Toggle repository enabled/review flags (write-config scope).",
    )
    async def set_repo_review(
        repo: str,
        enabled: bool | None = None,
        review: bool | None = None,
    ) -> str:
        return json.dumps(_service(controller).set_repo_review(repo, enabled=enabled, review=review))

    core = server.streamable_http_app(streamable_http_path="/", stateless_http=True)
    return AgentMcpMiddleware(core, token_store, addon_enabled)
