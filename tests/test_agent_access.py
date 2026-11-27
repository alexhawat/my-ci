import asyncio
import json
import sqlite3
import time
from unittest.mock import AsyncMock
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

from localci.agent_service import AgentService
from localci.agent_tokens import (
    AgentTokenStore,
    hash_agent_secret,
    parse_agent_token,
    token_store_from_controller,
)
from localci.app import create_app

WORKFLOW = (
    "on: pull_request\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\n"
)


def agent_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def mcp_headers(controller, token: str | None = None) -> dict:
    host = urlparse(controller.base_url).netloc
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "Host": host,
    }
    if token is not None:
        headers.update(agent_headers(token))
    return headers


_MCP_INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "pytest", "version": "1"},
    },
}


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALCI_TAILSCALE_LOGIN", "owner@example.com")
    app = create_app(tmp_path, background=False)
    controller = app.state.controller
    controller.store.save_integrations({"mergecraft": True, "agent_access": True})
    controller.store.discover(
        [
            {
                "full_name": "o/r",
                "private": True,
                "html_url": "https://github.com/o/r",
                "default_branch": "main",
            }
        ]
    )
    controller.store.execute(
        "UPDATE repos SET enabled=1,config=? WHERE name=?",
        (json.dumps({"enabled": True, "workflows": [".github/workflows/ci.yml"], "review": False}), "o/r"),
    )
    token_store = token_store_from_controller(controller)
    raw, _meta = token_store.create("test", ["read", "write-config", "write-runs"])
    with TestClient(
        app,
        headers={
            "Tailscale-User-Login": "owner@example.com",
            "Origin": controller.base_url,
            **agent_headers(raw),
        },
    ) as http:
        yield http, controller, raw, token_store


def test_token_create_verify_revoke(env):
    http, controller, raw, token_store = env
    token_store.revoke(json.loads(http.get("/api/agent-tokens").text)[0]["id"])
    assert token_store.verify(raw) is None


def test_mcp_http_requires_bearer(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALCI_TAILSCALE_LOGIN", "owner@example.com")
    app = create_app(tmp_path, background=False)
    controller = app.state.controller
    controller.store.save_integrations({"agent_access": True})
    with TestClient(app, base_url=controller.base_url) as http:
        r = http.post("/agent/mcp/", json=_MCP_INIT, headers=mcp_headers(controller))
        assert r.status_code == 401


def test_mcp_http_addon_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALCI_TAILSCALE_LOGIN", "owner@example.com")
    app = create_app(tmp_path, background=False)
    controller = app.state.controller
    controller.store.save_integrations({"agent_access": False})
    token_store = token_store_from_controller(controller)
    raw, _ = token_store.create("x", ["read"])
    with TestClient(app, base_url=controller.base_url) as http:
        r = http.post("/agent/mcp/", json=_MCP_INIT, headers=mcp_headers(controller, raw))
        assert r.status_code == 404


def test_mcp_http_tools_list(env):
    http, controller, raw, token_store = env
    headers = mcp_headers(controller, raw)
    assert http.post("/agent/mcp/", json=_MCP_INIT, headers=headers).status_code == 200
    tools = http.post(
        "/agent/mcp/",
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        headers=headers,
    )
    assert tools.status_code == 200
    names = {t["name"] for t in tools.json()["result"]["tools"]}
    assert "list_repos" in names


def test_addon_disabled_returns_404(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALCI_TAILSCALE_LOGIN", "owner@example.com")
    app = create_app(tmp_path, background=False)
    controller = app.state.controller
    controller.store.save_integrations({"mergecraft": False, "agent_access": False})
    token_store = token_store_from_controller(controller)
    raw, _ = token_store.create("x", ["read"])
    with TestClient(app, headers=agent_headers(raw)) as http:
        assert http.get("/api/agent/v1/repos").status_code == 404


def test_addon_disabled_without_bearer_returns_404(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALCI_TAILSCALE_LOGIN", "owner@example.com")
    app = create_app(tmp_path, background=False)
    controller = app.state.controller
    controller.store.save_integrations({"agent_access": False})
    with TestClient(app) as http:
        assert http.get("/api/agent/v1/repos").status_code == 404
        assert http.get("/api/agent/v1/openapi.json").status_code == 404


def test_scope_enforcement(env):
    http, controller, raw, token_store = env
    read_only, _ = token_store.create("read", ["read"])
    assert http.get("/api/agent/v1/repos", headers=agent_headers(read_only)).status_code == 200
    rid = controller.store.enqueue("o/r", _pr(), {"workflows": []})
    assert http.post(f"/api/agent/v1/runs/{rid}/retry", headers=agent_headers(read_only)).status_code == 403


def test_api_repos_and_queue(env):
    http, controller, raw, token_store = env
    body = http.get("/api/agent/v1/repos").json()
    assert body[0]["name"] == "o/r"
    queue = http.get("/api/agent/v1/queue").json()
    assert "queued" in queue and "running" in queue


def test_agent_openapi_not_exposed(env):
    http, controller, raw, token_store = env
    assert http.get("/api/agent/v1/openapi.json").status_code == 404
    assert http.get("/api/agent/v1/docs").status_code == 404


def test_no_secret_leak_in_agent_payloads(env):
    http, controller, raw, token_store = env
    leaked = "super-secret-provider-value"
    controller.store.execute(
        "INSERT INTO secrets VALUES(?,?,?)",
        (
            "o/r",
            "review:OPENAI_API_KEY",
            controller.cipher.encrypt(leaked.encode()).decode(),
        ),
    )
    rid = controller.store.enqueue("o/r", _pr(), {"workflows": []})
    endpoints = [
        "/api/agent/v1/repos",
        f"/api/agent/v1/runs/{rid}",
        f"/api/agent/v1/runs/{rid}/review",
        f"/api/agent/v1/runs/{rid}/logs/meta",
        "/api/agent/v1/queue",
    ]
    blob = ""
    for path in endpoints:
        blob += http.get(path).text
    assert "ciphertext" not in blob.casefold()
    assert "private_key" not in blob
    assert "BEGIN RSA" not in blob
    assert leaked not in blob


def test_mcp_list_repos_via_service(env):
    http, controller, raw, token_store = env
    svc = AgentService(controller, frozenset({"read"}))
    payload = svc.list_repos()
    assert "ciphertext" not in json.dumps(payload)


def test_invalid_token_401(env):
    http, controller, raw, token_store = env
    assert http.get("/api/agent/v1/repos", headers=agent_headers("mci_invalid")).status_code == 401


def test_public_view_allows_benign_begin_in_title(env):
    http, controller, raw, token_store = env
    title = "Document -----BEGIN marker in PEM export"
    rid = controller.store.enqueue("o/r", _pr(title=title), {"workflows": []})
    body = http.get(f"/api/agent/v1/runs/{rid}").json()
    assert body["title"] == title


def test_public_view_strips_secret_keys():
    payload = AgentService.public_view(
        {"name": "o/r", "ciphertext": "hidden", "nested": {"private_key": "x"}}
    )
    assert payload == {"name": "o/r", "nested": {}}


def test_verify_rejects_legacy_format_without_hash(monkeypatch, tmp_path):
    store = AgentTokenStore(
        __import__("localci.store", fromlist=["Store"]).Store(tmp_path / "db"), b"pepper" * 4
    )
    calls = []
    monkeypatch.setattr(
        "localci.agent_tokens.hash_agent_secret",
        lambda *args, **kwargs: calls.append(1) or "deadbeef",
    )
    assert parse_agent_token("mci_onlylegacysecret") is None
    assert store.verify("mci_onlylegacysecret") is None
    assert calls == []


def test_verify_hashes_once_with_many_tokens(monkeypatch, tmp_path):
    from localci.store import Store

    token_store = AgentTokenStore(Store(tmp_path / "db"), b"pepper" * 4)
    raws = [token_store.create(f"t{i}", ["read"])[0] for i in range(5)]
    calls = []
    monkeypatch.setattr(
        "localci.agent_tokens.hash_agent_secret",
        lambda *args, **kwargs: calls.append(1) or hash_agent_secret(args[0], args[1]),
    )
    assert token_store.verify(raws[2]) is not None
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_verify_async_delegates_to_thread(monkeypatch, tmp_path):
    from localci.store import Store

    token_store = AgentTokenStore(Store(tmp_path / "db"), b"pepper" * 4)
    raw, _ = token_store.create("async", ["read"])

    async def capture(fn, *args):
        return fn(*args)

    monkeypatch.setattr(asyncio, "to_thread", capture)
    verified = await token_store.verify_async(raw)
    assert verified is not None
    assert verified.name == "async"


def test_expired_token_rejected(env):
    http, controller, raw, token_store = env
    meta = token_store.list_tokens()[0]
    token_store.store.execute(
        "UPDATE agent_tokens SET expires_at=? WHERE id=?",
        (time.time() - 60, meta["id"]),
    )
    assert token_store.verify(raw) is None
    assert http.get("/api/agent/v1/repos", headers=agent_headers(raw)).status_code == 401


def test_revoke_via_dashboard_then_api_401(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALCI_TAILSCALE_LOGIN", "owner@example.com")
    app = create_app(tmp_path, background=False)
    controller = app.state.controller
    controller.store.save_integrations({"agent_access": True})
    token_store = token_store_from_controller(controller)
    raw, meta = token_store.create("rev", ["read"])
    dash = {
        "Tailscale-User-Login": "owner@example.com",
        "Origin": controller.base_url,
    }
    with TestClient(app, headers=dash) as http:
        assert http.delete(f"/api/agent-tokens/{meta['id']}").status_code == 200
        assert http.get("/api/agent/v1/repos", headers=agent_headers(raw)).status_code == 401


def test_write_config_scope_patch_allowed_and_denied(env):
    http, controller, raw, token_store = env
    writer, _ = token_store.create("cfg", ["write-config"])
    read_only, _ = token_store.create("ro", ["read"])
    assert (
        http.patch(
            "/api/agent/v1/repos/o/r",
            headers=agent_headers(writer),
            json={"enabled": True},
        ).status_code
        == 200
    )
    assert (
        http.patch(
            "/api/agent/v1/repos/o/r",
            headers=agent_headers(read_only),
            json={"review": False},
        ).status_code
        == 403
    )


def test_write_runs_retry_allowed(env):
    http, controller, raw, token_store = env
    controller.github.request = AsyncMock(return_value=_pr())
    rid = controller.store.enqueue("o/r", _pr(), {"workflows": [".github/workflows/ci.yml"]})
    controller.store.finish(rid, "failure", "fixture")
    assert http.post(f"/api/agent/v1/runs/{rid}/retry", headers=agent_headers(raw)).status_code == 200


def test_write_runs_denied_without_scope(env):
    http, controller, raw, token_store = env
    cfg_only, _ = token_store.create("cfg", ["write-config"])
    rid = controller.store.enqueue("o/r", _pr(), {"workflows": []})
    assert http.post(f"/api/agent/v1/runs/{rid}/retry", headers=agent_headers(cfg_only)).status_code == 403


def test_mcp_tool_call_list_repos(env):
    http, controller, raw, token_store = env
    headers = mcp_headers(controller, raw)
    assert http.post("/agent/mcp/", json=_MCP_INIT, headers=headers).status_code == 200
    call = http.post(
        "/agent/mcp/",
        json={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "list_repos", "arguments": {}},
        },
        headers=headers,
    )
    assert call.status_code == 200
    payload = json.loads(call.json()["result"]["content"][0]["text"])
    assert payload and payload[0]["name"] == "o/r"


def test_integrations_toggle_preserves_mergecraft(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALCI_TAILSCALE_LOGIN", "owner@example.com")
    app = create_app(tmp_path, background=False)
    controller = app.state.controller
    controller.store.save_integrations({"mergecraft": True, "agent_access": True})
    dash = {"Tailscale-User-Login": "owner@example.com", "Origin": controller.base_url}
    with TestClient(app, headers=dash) as http:
        body = http.put("/api/integrations", json={"agent_access": False}).json()
    assert body["integrations"]["mergecraft"] is True
    assert body["integrations"]["agent_access"] is False


def test_v6_migration_revokes_legacy_salted_tokens(tmp_path):
    from localci.store import Store

    path = tmp_path / "localci.db"
    store = Store(path)
    store.close()
    created = time.time()
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA user_version=5")
        db.execute(
            "INSERT INTO agent_tokens VALUES(?,?,?,?,?,?,?,?,NULL)",
            ("legacy", "old", '["read"]', "salted", "deadbeef", created, None, None),
        )
        db.commit()
    Store(path)
    row = Store(path).rows("SELECT revoked_at FROM agent_tokens WHERE id='legacy'")[0]
    assert row["revoked_at"] is not None


def test_audit_retention_caps_rows(monkeypatch, tmp_path):
    from localci.store import Store

    monkeypatch.setenv("LOCALCI_AGENT_AUDIT_MAX_ROWS", "5")
    monkeypatch.setenv("LOCALCI_AGENT_AUDIT_RETENTION_DAYS", "3650")
    store = Store(tmp_path / "db")
    token_store = AgentTokenStore(store, b"pepper" * 4)
    for i in range(12):
        token_store.audit(f"id{i}", "read", "/p", "")
    count = store.rows("SELECT COUNT(*) AS n FROM agent_token_audit")[0]["n"]
    assert count == 5


def test_agent_path_skips_tailscale_login(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALCI_TAILSCALE_LOGIN", "owner@example.com")
    app = create_app(tmp_path, background=False)
    controller = app.state.controller
    controller.store.save_integrations({"agent_access": True})
    token_store = token_store_from_controller(controller)
    raw, _ = token_store.create("a", ["read"])
    with TestClient(app, headers=agent_headers(raw)) as http:
        assert http.get("/api/agent/v1/repos").status_code == 200


def _pr(n=1, title="Test"):
    return {
        "number": n,
        "title": title,
        "state": "open",
        "draft": False,
        "head": {"sha": "a" * 40, "ref": "feature", "repo": {"full_name": "o/r"}},
        "base": {"sha": "b" * 40, "repo": {"full_name": "o/r"}},
        "user": {"login": "o"},
    }
