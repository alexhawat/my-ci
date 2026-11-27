import json

import pytest
from fastapi.testclient import TestClient

from localci.agent_service import AgentService
from localci.agent_tokens import token_store_from_controller
from localci.app import create_app

WORKFLOW = (
    "on: pull_request\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\n"
)


def agent_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


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
        headers={"Tailscale-User-Login": "owner@example.com", "Origin": controller.base_url, **agent_headers(raw)},
    ) as http:
        yield http, controller, raw, token_store


def test_token_create_verify_revoke(env):
    http, controller, raw, token_store = env
    token_store.revoke(json.loads(http.get("/api/agent-tokens").text)[0]["id"])
    assert token_store.verify(raw) is None


def test_addon_disabled_returns_404(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALCI_TAILSCALE_LOGIN", "owner@example.com")
    app = create_app(tmp_path, background=False)
    controller = app.state.controller
    controller.store.save_integrations({"mergecraft": False, "agent_access": False})
    token_store = token_store_from_controller(controller)
    raw, _ = token_store.create("x", ["read"])
    with TestClient(app, headers=agent_headers(raw)) as http:
        assert http.get("/api/agent/v1/repos").status_code == 404


def test_scope_enforcement(env):
    http, controller, raw, token_store = env
    read_only, _ = token_store.create("read", ["read"])
    client = TestClient(http.app, headers=agent_headers(read_only))
    assert client.get("/api/agent/v1/repos").status_code == 200
    rid = controller.store.enqueue("o/r", _pr(), {"workflows": []})
    assert client.post(f"/api/agent/v1/runs/{rid}/retry").status_code == 403


def test_api_repos_and_queue(env):
    http, controller, raw, token_store = env
    body = http.get("/api/agent/v1/repos").json()
    assert body[0]["name"] == "o/r"
    queue = http.get("/api/agent/v1/queue").json()
    assert "queued" in queue and "running" in queue


def test_openapi_available(env):
    http, controller, raw, token_store = env
    assert http.get("/api/agent/v1/openapi.json").status_code == 200


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
    with TestClient(http.app, headers=agent_headers("mci_invalid")) as client:
        assert client.get("/api/agent/v1/repos").status_code == 401


def test_agent_path_skips_tailscale_login(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALCI_TAILSCALE_LOGIN", "owner@example.com")
    app = create_app(tmp_path, background=False)
    controller = app.state.controller
    controller.store.save_integrations({"agent_access": True})
    token_store = token_store_from_controller(controller)
    raw, _ = token_store.create("a", ["read"])
    with TestClient(app, headers=agent_headers(raw)) as http:
        assert http.get("/api/agent/v1/repos").status_code == 200


def _pr(n=1):
    return {
        "number": n,
        "title": "Test",
        "state": "open",
        "draft": False,
        "head": {"sha": "a" * 40, "ref": "feature", "repo": {"full_name": "o/r"}},
        "base": {"sha": "b" * 40, "repo": {"full_name": "o/r"}},
        "user": {"login": "o"},
    }