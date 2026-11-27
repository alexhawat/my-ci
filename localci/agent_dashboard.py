"""Dashboard routes for agent access tokens and setup hints."""

from __future__ import annotations

import json
import shutil
import subprocess

from fastapi import HTTPException
from pydantic import BaseModel, Field

from localci.agent_tokens import VALID_SCOPES, token_store_from_controller


class TokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    scopes: list[str] = Field(min_length=1, max_length=10)
    expires_days: int | None = Field(default=None, ge=1, le=3650)


class IntegrationsPatch(BaseModel):
    mergecraft: bool | None = None
    agent_access: bool | None = None


def tailscale_hint() -> dict:
    if not shutil.which("tailscale"):
        return {"available": False, "summary": "Tailscale CLI not found on this host."}
    try:
        proc = subprocess.run(
            ["tailscale", "status", "--json"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"available": False, "summary": "Could not read Tailscale status."}
    if proc.returncode != 0:
        return {"available": False, "summary": (proc.stderr or proc.stdout or "Tailscale offline").strip()[:200]}
    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return {"available": True, "summary": "Tailscale is running."}
    backend = (payload.get("BackendState") or "").casefold()
    return {
        "available": True,
        "backend_state": payload.get("BackendState", ""),
        "summary": "Connected to tailnet." if backend == "running" else f"Tailscale state: {payload.get('BackendState', 'unknown')}",
    }


def register_agent_dashboard(app, controller):
    token_store = token_store_from_controller(controller)

    @app.get("/api/agent-access")
    def agent_access_status():
        base = controller.base_url
        integrations = controller.store.integrations()
        return {
            "enabled": bool(integrations.get("agent_access")),
            "http_base": f"{base}/api/agent/v1",
            "mcp_url": f"{base}/agent/mcp",
            "tailscale": tailscale_hint(),
            "mcp_config_cursor": {
                "mcpServers": {
                    "my-ci": {
                        "url": f"{base}/agent/mcp",
                        "headers": {"Authorization": "Bearer YOUR_MY_CI_TOKEN"},
                    }
                }
            },
            "mcp_config_claude": {
                "mcpServers": {
                    "my-ci": {
                        "type": "http",
                        "url": f"{base}/agent/mcp",
                        "headers": {"Authorization": "Bearer YOUR_MY_CI_TOKEN"},
                    }
                }
            },
        }

    @app.get("/api/agent-tokens")
    def list_tokens():
        if not controller.store.integrations().get("agent_access"):
            raise HTTPException(404, "Enable agent access in Settings first")
        return token_store.list_tokens()

    @app.post("/api/agent-tokens")
    def create_token(body: TokenCreate):
        if not controller.store.integrations().get("agent_access"):
            raise HTTPException(404, "Enable agent access in Settings first")
        bad = set(body.scopes) - VALID_SCOPES
        if bad:
            raise HTTPException(400, f"Unknown scopes: {', '.join(sorted(bad))}")
        try:
            raw, meta = token_store.create(body.name, body.scopes, expires_days=body.expires_days)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        return {"token": raw, "record": meta}

    @app.delete("/api/agent-tokens/{token_id}")
    def revoke_token(token_id: str):
        if not controller.store.integrations().get("agent_access"):
            raise HTTPException(404, "Enable agent access in Settings first")
        if not token_store.revoke(token_id):
            raise HTTPException(404, "Unknown or already revoked token")
        return {"ok": True}