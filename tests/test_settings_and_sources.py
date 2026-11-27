"""Watch-only repositories, the Settings page (GitHub App, mergeCraft add-on) and
workflows loaded from any YAML source: a repository path, an uploaded file or pasted text."""

import json
import time
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from localci.app import RepoConfig, create_app
from localci.github import GitHub, GitHubError
from localci.policy import valid_workflow_path, workflow_files
from localci.reporting import reports
from localci.runner import Runner
from localci.store import Store

WORKFLOW = "on: pull_request\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps: [{run: echo ok}]\n"


def pr(number=1, head="a" * 40):
    return {
        "number": number,
        "title": f"PR {number}",
        "state": "open",
        "draft": False,
        "head": {"sha": head, "ref": "feature", "repo": {"full_name": "o/r"}},
        "base": {"sha": "b" * 40, "ref": "main", "repo": {"full_name": "o/r"}},
        "user": {"login": "someone"},
        "updated_at": "2026-11-20T10:00:00Z",
    }


def repo(name="o/r"):
    return {
        "full_name": name,
        "private": True,
        "html_url": f"https://github.com/{name}",
        "default_branch": "main",
    }


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALCI_TAILSCALE_LOGIN", "owner@example.com")
    app = create_app(tmp_path, background=False)
    controller = app.state.controller
    controller.store.discover([repo()])
    with TestClient(
        app, headers={"Tailscale-User-Login": "owner@example.com", "Origin": controller.base_url}
    ) as http:
        yield http, controller


# Watch only


def test_watch_only_is_exclusive_with_local_checks_and_stays_disabled(client):
    http, c = client
    both = http.put("/api/repos/o/r", json={"watch_only": True, "enabled": True, "workflows": ["ci/a.yml"]})
    assert both.status_code == 400 and "runs nothing locally" in both.json()["detail"]
    # No workflow or review is needed to watch.
    assert http.put("/api/repos/o/r", json={"watch_only": True}).status_code == 200
    row = c.store.repo("o/r")
    assert row["enabled"] == 0 and json.loads(row["config"])["watch_only"] is True
    assert [r["name"] for r in c.store.watched_repos()] == ["o/r"]
    assert http.get("/api/state").json()["repos"][0]["config"]["watch_only"] is True


def test_switching_a_running_repository_to_watch_only_cancels_its_runs(client):
    http, c = client
    assert http.put("/api/repos/o/r", json={"enabled": True, "workflows": ["ci/a.yml"]}).status_code == 200
    rid = c.store.enqueue("o/r", pr(), {})
    assert http.put("/api/repos/o/r", json={"watch_only": True, "workflows": ["ci/a.yml"]}).status_code == 200
    assert c.store.rows("SELECT state FROM runs WHERE id=?", (rid,))[0]["state"] == "cancelled"
    # The poll's own path refuses to queue anything for it.
    assert c.store.enqueue("o/r", pr(2), {}, require_enabled=True) is None


async def test_poll_lists_watched_prs_without_queueing_or_cancelling(tmp_path):
    from localci.controller import Controller

    controller = Controller(tmp_path)
    controller.store.discover([repo(), repo("o/run"), repo("o/off")])
    controller.store.execute(
        "UPDATE repos SET config=? WHERE name='o/r'", (json.dumps({"watch_only": True}),)
    )
    controller.store.execute(
        "UPDATE repos SET enabled=1,config=? WHERE name='o/run'", (json.dumps({"workflows": ["ci/a.yml"]}),)
    )
    controller.last_discovery = time.time()
    controller.publish = AsyncMock()
    running = pr(3)
    for side in ("head", "base"):
        running[side] = {**running[side], "repo": {"full_name": "o/run"}}
    listed = {"o/r": [pr(1), pr(2)], "o/run": [running]}

    async def pages(path, **_):
        return listed[path.split("/pulls")[0].removeprefix("repos/")]

    controller.github.pages = AsyncMock(side_effect=pages)
    cancel_stale, calls = controller.store.cancel_stale, []

    def tracked(name, prs):
        calls.append(name)
        return cancel_stale(name, prs)

    controller.store.cancel_stale = tracked  # type: ignore[method-assign]
    await controller.poll()
    fetched = sorted(call.args[0].split("/pulls")[0] for call in controller.github.pages.await_args_list)
    assert fetched == ["repos/o/r", "repos/o/run"]  # The disabled repository is not polled.
    assert sorted(r["number"] for r in controller.store.rows("SELECT number FROM prs WHERE repo='o/r'")) == [
        1,
        2,
    ]
    runs = controller.store.rows("SELECT repo,pr FROM runs")
    assert runs == [{"repo": "o/run", "pr": 3}]
    assert calls == ["o/run"]


def test_pr_page_shows_watched_prs_with_github_ci_and_allows_merge(client):
    http, c = client
    c.store.discover([repo("o/off")])
    assert http.put("/api/repos/o/r", json={"watch_only": True}).status_code == 200
    c.store.replace_prs("o/r", [pr(1)])
    c.store.replace_prs("o/off", [pr(9)])
    c.github.pull_request_checks = AsyncMock(
        return_value={
            "merge_methods": ["squash"],
            "prs": {
                1: {
                    "number": 1,
                    "headRefOid": "a" * 40,
                    "mergeable": "MERGEABLE",
                    "mergeStateStatus": "CLEAN",
                    "commits": {
                        "nodes": [
                            {
                                "commit": {
                                    "statusCheckRollup": {
                                        "contexts": {
                                            "totalCount": 1,
                                            "nodes": [
                                                {
                                                    "__typename": "CheckRun",
                                                    "name": "test",
                                                    "status": "IN_PROGRESS",
                                                    "detailsUrl": "https://github.com/o/r/actions/runs/1",
                                                }
                                            ],
                                        }
                                    }
                                }
                            }
                        ]
                    },
                }
            },
        }
    )
    (item,) = http.get("/api/prs").json()["prs"]
    assert item["repo"] == "o/r" and item["watch_only"] is True
    assert item["ci_eligibility"] == "Watch only — not run locally" and item["latest_run"] is None
    assert item["github"]["state"] == "running" and item["github"]["checks"][0]["name"] == "test"
    c.github.pages = AsyncMock(return_value=[{**pr(5), "state": "closed"}])
    closed = http.get("/api/prs", params={"state": "closed"}).json()["prs"]
    assert [p["number"] for p in closed] == [5]
    c.github.merge = AsyncMock(return_value={"merged": True, "sha": "d" * 40})
    assert (
        http.post("/api/repos/o/r/prs/1/merge", json={"sha": "a" * 40, "method": "squash"}).status_code == 200
    )
    refused = http.post("/api/repos/o/off/prs/9/merge", json={"sha": "a" * 40, "method": "squash"})
    assert refused.status_code == 400


def test_retry_of_an_earlier_run_is_refused_while_only_watching(client):
    http, c = client
    rid = c.store.enqueue("o/r", pr(), {})
    c.store.finish(rid, "failure", "failed")
    assert http.put("/api/repos/o/r", json={"watch_only": True}).status_code == 200
    c.github.request = AsyncMock(return_value=pr())
    assert http.post(f"/api/runs/{rid}/retry").status_code == 400
    c.github.request.assert_not_awaited()


# Settings: mergeCraft add-on


def test_mergecraft_is_off_until_added_and_gates_review(client):
    http, c = client
    assert http.get("/api/state").json()["integrations"] == {"mergecraft": False}
    refused = http.put("/api/repos/o/r", json={"enabled": True, "review": True})
    assert refused.status_code == 400 and "Settings" in refused.json()["detail"]
    nothing = http.put("/api/repos/o/r", json={"enabled": True})
    assert nothing.json()["detail"] == "Select at least one CI workflow"
    assert http.put("/api/integrations", json={"mergecraft": True}).status_code == 200
    assert http.get("/api/state").json()["integrations"] == {"mergecraft": True}
    assert http.put("/api/repos/o/r", json={"enabled": True, "review": True}).status_code == 200
    assert (
        http.put("/api/integrations", json={"mergecraft": True}, headers={"Origin": "https://x"}).status_code
        == 403
    )


def test_installations_that_already_review_keep_mergecraft(tmp_path):
    store = Store(tmp_path / "db")
    store.discover([repo()])
    assert store.integrations() == {"mergecraft": False}
    store.execute("UPDATE repos SET config=? WHERE name='o/r'", (json.dumps({"review": True}),))
    assert store.integrations() == {"mergecraft": True}


def test_turning_review_off_in_the_last_repository_keeps_mergecraft(client):
    http, c = client
    c.store.execute("UPDATE repos SET config=? WHERE name='o/r'", (json.dumps({"review": True}),))
    assert http.put("/api/repos/o/r", json={"review": False}).status_code == 200
    assert http.get("/api/state").json()["integrations"] == {"mergecraft": True}


def test_removing_mergecraft_turns_review_off_but_never_empties_a_running_repository(client):
    http, c = client
    c.store.discover([repo("o/s"), repo("o/off")])
    assert http.put("/api/integrations", json={"mergecraft": True}).status_code == 200
    assert http.put("/api/repos/o/r", json={"enabled": True, "review": True}).status_code == 200
    assert (
        http.put(
            "/api/repos/o/s", json={"enabled": True, "review": True, "workflows": ["ci/a.yml"]}
        ).status_code
        == 200
    )
    assert http.put("/api/repos/o/off", json={"review": True}).status_code == 200
    refused = http.put("/api/integrations", json={"mergecraft": False})
    assert refused.status_code == 409 and "o/r run only mergeCraft review" in refused.json()["detail"]
    assert c.store.integrations() == {"mergecraft": True}  # Nothing changed.
    assert json.loads(c.store.repo("o/s")["config"])["review"] is True
    assert http.put("/api/repos/o/r", json={"enabled": False, "review": True}).status_code == 200
    removed = http.put("/api/integrations", json={"mergecraft": False}).json()
    assert removed == {"integrations": {"mergecraft": False}, "review_turned_off": ["o/off", "o/r", "o/s"]}
    assert not any(json.loads(r["config"]).get("review") for r in c.store.rows("SELECT config FROM repos"))
    assert json.loads(c.store.repo("o/s")["config"])["workflows"] == ["ci/a.yml"]


# Settings: GitHub App


def test_github_app_is_named_in_state_and_can_be_disconnected(client):
    http, c = client
    key = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        .decode()
    )
    assert http.get("/api/state").json()["github_app"] is None
    c.github.request = AsyncMock(return_value={"id": 42, "name": "My Checks App", "slug": "my-checks-app"})
    assert (
        http.put("/api/github-app", json={"app_id": "42", "private_key": key}).json()["name"]
        == "My Checks App"
    )
    assert http.get("/api/state").json()["github_app"] == {
        "app_id": "42",
        "name": "My Checks App",
        "slug": "my-checks-app",
    }
    assert set(c.secrets("__github_app__", "app")) == {"app_id", "private_key"}
    assert http.delete("/api/github-app").status_code == 200
    assert c.secrets("__github_app__", "app") == {}
    assert http.get("/api/state").json()["github_app"] is None
    assert http.delete("/api/github-app", headers={"Origin": "https://x"}).status_code == 403


# Workflows from any YAML source


@pytest.mark.parametrize(
    ("path", "valid"),
    [
        (".github/workflows/ci.yml", True),
        ("ci/pipeline.yaml", True),
        ("deep/er/checks.yml", True),
        ("local:pasted.yml", True),
        ("../escape.yml", False),
        ("ci/../../escape.yml", False),
        ("./ci.yml", False),
        ("/etc/ci.yml", False),
        ("ci/notes.txt", False),
        ("local:nested/name.yml", False),
        ("local:", False),
        ("with space.yml", False),
        ("x" * 300 + ".yml", False),
    ],
)
def test_workflow_paths_name_repository_files_or_local_workflows(path, valid):
    assert valid_workflow_path(path) is valid
    if valid:
        assert RepoConfig(workflows=[path]).workflows == [path]
    else:
        with pytest.raises(ValueError):
            RepoConfig(workflows=[path])


def test_selected_workflows_run_under_unique_names_and_github_ones_keep_theirs():
    assert workflow_files(["ci/ci.yml", ".github/workflows/ci.yml", "local:ci.yml", "other/lint.yml"]) == {
        "ci/ci.yml": "ci-2.yml",
        ".github/workflows/ci.yml": "ci.yml",
        "local:ci.yml": "ci-3.yml",
        "other/lint.yml": "lint.yml",
    }


def test_workflow_list_includes_repository_files_and_local_workflows(client):
    http, c = client
    assert http.put("/api/repos/o/r", json={"workflows": ["ci/selected.yml"]}).status_code == 200
    files = {
        ".github/workflows/ci.yml": WORKFLOW,
        "ci/selected.yml": WORKFLOW.replace("test:", "selected:"),
        "ci/added.yml": "name: Added\n" + WORKFLOW,
        "ci/broken.yml": "- not\n- a workflow\n",
    }
    c.github.request = AsyncMock(
        return_value=[{"type": "file", "path": ".github/workflows/ci.yml", "name": "ci.yml"}]
    )

    async def content(_, path, ref):
        assert ref == "main"
        if path not in files:
            raise GitHubError(404, "GET", f"repos/o/r/contents/{path}")
        return files[path]

    c.github.content = AsyncMock(side_effect=content)
    saved = http.put(
        "/api/repos/o/r/workflow",
        json={"path": "local:pasted.yml", "content": WORKFLOW, "source_ref": "pasted", "expected_version": 0},
    )
    assert saved.json() == {"version": 1}
    listed = http.get(
        "/api/repos/o/r/workflows",
        params=[("include", "ci/added.yml"), ("include", "ci/missing.yml"), ("include", "ci/broken.yml")],
    ).json()
    by_path = {w["path"]: w for w in listed}
    assert list(by_path) == [
        ".github/workflows/ci.yml",
        "ci/selected.yml",
        "ci/added.yml",
        "ci/missing.yml",
        "ci/broken.yml",
        "local:pasted.yml",
    ]
    assert by_path[".github/workflows/ci.yml"]["source"] == "workflows"
    assert by_path["ci/selected.yml"]["source"] == "repository" and by_path["ci/selected.yml"]["jobs"] == [
        "selected"
    ]
    assert by_path["ci/added.yml"]["name"] == "Added" and by_path["ci/added.yml"]["pr"]
    assert by_path["ci/missing.yml"]["error"] == "Not found on main"
    assert "jobs mapping" in by_path["ci/broken.yml"]["error"]
    local = by_path["local:pasted.yml"]
    assert local["source"] == "local" and local["local_version"] == 1 and local["pr"]
    assert http.get("/api/repos/o/r/workflows", params={"include": "../x.yml"}).status_code == 400


def test_local_workflows_are_saved_validated_snapshotted_and_deleted(client):
    http, c = client
    payload = {
        "path": "local:checks.yml",
        "content": WORKFLOW,
        "source_ref": "file checks.yml",
        "expected_version": 0,
    }
    assert http.put("/api/repos/o/r/workflow", json=payload).json() == {"version": 1}
    duplicate = http.put("/api/repos/o/r/workflow", json=payload)
    assert duplicate.status_code == 409 and "already exists" in duplicate.json()["detail"]
    push_only = http.put(
        "/api/repos/o/r/workflow",
        json={**payload, "path": "local:push.yml", "content": WORKFLOW.replace("pull_request", "push")},
    )
    assert push_only.status_code == 400 and "on: pull_request" in push_only.json()["detail"]
    assert (
        http.get("/api/repos/o/r/workflow", params={"path": "local:checks.yml"}).json()["content"] == WORKFLOW
    )
    assert (
        http.put("/api/repos/o/r", json={"enabled": True, "workflows": ["local:checks.yml"]}).status_code
        == 200
    )
    rid = c.store.enqueue("o/r", pr(), json.loads(c.store.repo("o/r")["config"]))
    snapshot = json.loads(c.store.rows("SELECT config FROM runs WHERE id=?", (rid,))[0]["config"])
    assert snapshot["workflow_overrides"]["local:checks.yml"]["content"] == WORKFLOW
    # Deleting a local workflow also unselects it; there is no repository file to fall back to.
    assert http.delete("/api/repos/o/r/workflow", params={"path": "local:checks.yml"}).status_code == 200
    assert json.loads(c.store.repo("o/r")["config"])["workflows"] == []
    assert http.get("/api/repos/o/r/workflow", params={"path": "local:checks.yml"}).status_code == 404
    assert http.delete("/api/repos/o/r/workflow", params={"path": "../x.yml"}).status_code == 400
    # The name is free again.
    assert http.put("/api/repos/o/r/workflow", json=payload).json() == {"version": 2}


def test_editor_reports_a_repository_file_that_does_not_exist(client):
    http, c = client
    c.github.request = AsyncMock(return_value={"sha": "c" * 40})
    c.github.content = AsyncMock(side_effect=GitHubError(404, "GET", "repos/o/r/contents/ci/none.yml"))
    missing = http.get("/api/repos/o/r/workflow", params={"path": "ci/none.yml"})
    assert missing.status_code == 404 and missing.json()["detail"] == "ci/none.yml is not on main"


async def test_runner_uses_local_and_repository_workflows_under_unique_names(tmp_path):
    token = tmp_path / "token"
    token.write_text("fixture-github-token")
    store = Store(tmp_path / "data/db")
    runner = Runner(store, GitHub(token), tmp_path / "data", lambda *_: {})
    shown, acts = [], []

    async def command(*args, **kwargs):
        if args[:2] == ("git", "clone"):
            Path(args[-1]).mkdir(parents=True)
        if args[:2] == ("git", "show"):
            path = args[2].split(":", 1)[1]
            shown.append(path)
            return (128, "") if path == "ci/missing.yml" else (0, WORKFLOW)
        if "act" in args:
            acts.append(args[args.index("-W") + 1])
            runner.completed_jobs = 1
        return 0, ""

    runner.command = command
    runner.cleanup = AsyncMock()
    store.save_workflow("owner/repo", "local:ci.yml", WORKFLOW.replace("echo ok", "echo local"), "pasted")
    store.save_workflow("owner/repo", "local:gone.yml", WORKFLOW, "pasted")
    store.execute("UPDATE workflow_versions SET active=0 WHERE path='local:gone.yml'")
    workflows = [".github/workflows/ci.yml", "ci/ci.yml", "local:ci.yml", "ci/missing.yml", "local:gone.yml"]
    rid = store.enqueue(
        "owner/repo",
        {**pr(), "head": {**pr()["head"], "repo": {"full_name": "owner/repo"}}},
        {"review": False, "workflows": workflows},
    )
    await runner.execute(store.claim())
    row = store.rows("SELECT * FROM runs WHERE id=?", (rid,))[0]
    # A local workflow is never looked up in the repository.
    assert shown == [".github/workflows/ci.yml", "ci/ci.yml", "ci/missing.yml"]
    assert acts == ["/control/ci.yml", "/control/ci-2.yml", "/control/ci-3.yml"]
    steps = {s["name"]: s for s in json.loads(row["steps"])}
    assert steps["ci-3.yml"]["state"] == "success"
    assert (
        steps["missing.yml"]["state"] == "blocked"
        and "not found in base commit" in steps["missing.yml"]["message"]
    )
    assert steps["gone.yml"]["state"] == "blocked" and "was deleted" in steps["gone.yml"]["message"]
    assert row["state"] == "blocked"
    log = (runner.root / "logs" / f"{rid}.log").read_text()
    assert "Using local workflow v1: local:ci.yml (uploaded or pasted here)" in log
    # Reports wait for exactly these check names before calling CI complete.
    assert reports(row, runner.root, store, [])["ci"]["state"] == "blocked"


def test_edit_review_pipeline_atomic_credentials_and_snapshots(client):
    http, c = client
    endpoint = "/api/repos/o/r"
    first = {"label": "General", "model": "anthropic/claude-sonnet", "credential": "GENERAL_API_KEY"}
    backup = {"label": "Backup", "model": "openai/gpt-5.3-codex", "credential": "BACKUP_API_KEY"}
    key = "fixture-only-pipeline-key"
    config = {"review_pipeline": [[first, backup], [backup]], "review_key_updates": {"GENERAL_API_KEY": key}}
    assert http.put(endpoint, json=config).status_code == 400
    http.put("/api/integrations", json={"mergecraft": True}).raise_for_status()
    assert http.put(endpoint, json=config).status_code == 400
    assert c.secrets("o/r", "review") == {}  # The missing second key rolls back the first write.
    config["review_key_updates"]["BACKUP_API_KEY"] = "fixture-only-backup"
    http.put(endpoint, json=config).raise_for_status()
    persisted = json.loads(c.store.repo("o/r")["config"])
    assert persisted["review_pipeline"] == config["review_pipeline"]
    assert "review_key_updates" not in persisted
    assert key not in http.get("/api/state").text
    assert key not in str(c.store.rows("SELECT ciphertext FROM secrets"))
    assert c.secrets("o/r", "review")["GENERAL_API_KEY"] == key and not c.secrets("o/r", "ci")
    rid = c.store.enqueue("o/r", pr(), persisted)
    http.put(endpoint, json={"review_pipeline": [[{**backup, "label": "New primary"}]]}).raise_for_status()
    snapshot = json.loads(c.store.rows("SELECT config FROM runs WHERE id=?", (rid,))[0]["config"])
    assert snapshot["review_pipeline"] == persisted["review_pipeline"]
    assert http.delete(endpoint + "/secrets/review/BACKUP_API_KEY").status_code == 409
    malformed = http.put(endpoint, json={"review_key_updates": {"BACKUP_API_KEY": {"invalid": key}}})
    assert malformed.status_code == 422 and key not in malformed.text
    # An older client saving generic settings retains the new pipeline.
    http.put(endpoint, json={"workflows": ["ci/a.yml"]}).raise_for_status()
    assert json.loads(c.store.repo("o/r")["config"])["review_pipeline"][0][0]["label"] == "New primary"
    assert http.put(endpoint, json={"review_pipeline": [[{**first, "label": " "}]]}).status_code == 422
    assert http.put(endpoint, json={"review_pipeline": [[first] * 4]}).status_code == 422


def test_pipeline_targets_and_trusted_policy():
    from copy import deepcopy

    from localci.review_pipeline import configure_pipeline

    agents = {"old": {"role": "reviewer"}, "verifier": {"budget": 500}}
    base = {
        "agents": agents,
        "review": {"ignorePaths": ["docs/**"]},
        "providers": [{"label": "opencode-go", "envIndex": 3}],
    }
    original = deepcopy(base)
    keys = {"GENERAL_API_KEY": "fixture-only-one", "BACKUP_API_KEY": "fixture-only-two", "OTHER": "unused"}
    assert configure_pipeline(base, [], keys) == (keys, {}) and base == original
    a = {"label": "General", "model": "anthropic/claude-sonnet", "credential": "GENERAL_API_KEY"}
    b = {"label": "Backup", "model": "opencode-go/deepseek-v4.1-flash", "credential": "BACKUP_API_KEY"}
    env, routes = configure_pipeline(base, [[a, b], [b]], keys)
    assert env["ANTHROPIC_API_KEY"] == keys["GENERAL_API_KEY"]
    assert env["LLM_PROVIDER_3_API_KEY"] == keys["BACKUP_API_KEY"]
    assert "OTHER" not in env
    assert env[routes["reviewer-2"][0]["source"]] == keys["BACKUP_API_KEY"]
    assert base["models"] == [a["model"], b["model"]] and base["allowFallback"] and not base["modelPin"]
    assert base["agents"]["reviewer-2"] == {
        "role": "reviewer",
        "modelChain": [b["model"]],
        "required": True,
        "after": "reviewer",
    }
    assert base["agents"]["verifier"] == agents["verifier"] and "old" not in base["agents"]
    assert base["review"] == original["review"]
