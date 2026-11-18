import asyncio
import json
import sqlite3
import time
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from localci.app import Controller, create_app
from localci.runner import Runner
from localci.store import Store
from localci.telemetry import memory_bytes

WORKFLOW = (
    "on: pull_request\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\n"
)
PATH = ".github/workflows/ci.yml"


def pr(n=1):
    return {
        "number": n,
        "title": "Test <script>",
        "state": "open",
        "draft": False,
        "head": {"sha": "a" * 40, "ref": "feature", "repo": {"full_name": "o/r"}},
        "base": {"sha": "b" * 40, "repo": {"full_name": "o/r"}},
        "user": {"login": "o"},
    }


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALCI_TAILSCALE_LOGIN", "owner@example.com")
    app = create_app(tmp_path, background=False)
    controller = app.state.controller
    controller.capacity = {"cpus": 32, "memory_gb": 125}
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
    with TestClient(
        app, headers={"Tailscale-User-Login": "owner@example.com", "Origin": controller.base_url}
    ) as http:
        yield http, controller


def test_workflow_versions_are_local_immutable_snapshots(client):
    http, c = client
    c.github.request = AsyncMock(return_value={"sha": "c" * 40})
    c.github.content = AsyncMock(return_value=WORKFLOW)
    imported = http.get("/api/repos/o/r/workflow", params={"path": PATH}).json()
    assert imported["version"] == 0 and imported["source_ref"] == "c" * 40
    payload = {"path": PATH, "content": WORKFLOW, "source_ref": imported["source_ref"], "expected_version": 0}
    assert http.put("/api/repos/o/r/workflow", json=payload).json()["version"] == 1
    rid = c.store.enqueue("o/r", pr(), {"workflows": [PATH]})
    payload.update(content=WORKFLOW.replace("hello", "second"), expected_version=1)
    assert http.put("/api/repos/o/r/workflow", json=payload).json()["version"] == 2
    snapshot = json.loads(c.store.rows("SELECT config FROM runs WHERE id=?", (rid,))[0]["config"])
    assert snapshot["workflow_overrides"][PATH]["version"] == 1
    assert "second" not in snapshot["workflow_overrides"][PATH]["content"]
    assert http.put("/api/repos/o/r/workflow", json=payload).status_code == 409
    assert http.delete("/api/repos/o/r/workflow", params={"path": PATH}).status_code == 200
    assert http.get("/api/repos/o/r/workflow", params={"path": PATH}).json()["version"] == 0
    assert (
        http.get("/api/repos/o/r/workflow", params={"path": PATH, "version": 1}).json()["content"] == WORKFLOW
    )
    assert all(call.args[0] == "GET" for call in c.github.request.call_args_list)


def test_workflow_validation_and_protected_routes(client):
    http, c = client
    for path, content in [
        ("../../evil.yml", WORKFLOW),
        (PATH, "not yaml"),
        (PATH, WORKFLOW.replace("pull_request", "push")),
    ]:
        assert http.put(
            "/api/repos/o/r/workflow", json={"path": path, "content": content, "source_ref": "main"}
        ).status_code in {400, 422}
    assert http.put("/api/execution", json={}, headers={"Origin": "https://evil.test"}).status_code == 403
    assert http.get("/api/analytics", headers={"Tailscale-User-Login": "other"}).status_code == 403


def test_execution_bounds_and_config_preservation(client):
    http, c = client
    valid = {
        "max_parallel_runs": 3,
        "cpus_per_run": 8,
        "memory_gb_per_run": 24,
        "paused": False,
        "max_retries": 2,
    }
    assert http.put("/api/execution", json=valid).status_code == 200
    assert http.get("/api/execution").json()["settings"] == valid
    assert http.put("/api/execution", json={**valid, "max_parallel_runs": 8}).status_code == 400
    assert http.put("/api/execution", json={**valid, "memory_gb_per_run": 64}).status_code == 400
    assert http.put("/api/execution", json={**valid, "max_parallel_runs": 0}).status_code == 422
    assert http.put("/api/repos/o/r", json={"job_parallelism": 4, "timeout": 600}).status_code == 200
    assert json.loads(c.store.repo("o/r")["config"])["job_parallelism"] == 4


def test_logs_export_timestamp_and_usage(client):
    http, c = client
    rid = c.store.enqueue("o/r", pr(), {"workflows": []})
    run = c.store.claim()
    r = Runner(c.store, c.github, c.root, lambda *_: {})
    r.run = run
    r.log_path = c.root / "logs" / f"{rid}.log"
    r.sensitive = ["private-value"]
    r.step("ci.yml", "running")
    r.log("[Build/test] failure private-value\n")
    r.step("ci.yml", "failure", "failed")
    c.store.usage_sample(rid, 100, 250, 2**30, 4)
    c.store.usage_sample(rid, 105, 100, 2 * 2**30, 5)
    c.store.finish(rid, "failure", "Fixture")
    events = http.get(f"/api/runs/{rid}/events").json()
    assert (
        events[0]["job"] == "Build/test" and events[0]["phase"] == "ci.yml" and events[0]["level"] == "error"
    )
    assert events[0]["timestamp"] > 0 and events[0]["message"] == "failure [redacted]"
    text = http.get(f"/api/runs/{rid}/download-log")
    assert "attachment" in text.headers["content-disposition"] and "private-value" not in text.text
    assert "T" in text.text[:11] and "+00:00" in text.text
    details = http.get(f"/api/runs/{rid}").json()
    assert details["branch"] == "feature" and details["actor"] == "o" and details["attempt"] == 1
    assert details["steps"][0]["finished"] >= details["steps"][0]["started"]
    assert details["usage"]["cpu_seconds"] == 15 and details["usage"]["peak_memory_bytes"] == 2 * 2**30
    totals = http.get("/api/analytics").json()["totals"]
    assert totals["runs"] == 1 and totals["cpu_minutes"] == 0.25 and totals["failure"] == 1
    # Compact aggregates survive normal log retention; resource samples do not.
    c.store.execute("UPDATE runs SET finished=?,published=1 WHERE id=?", (time.time() - 15 * 86400, rid))
    c.prune()
    assert not c.store.rows("SELECT * FROM run_events")
    assert not c.store.rows("SELECT * FROM resource_samples")
    assert http.get("/api/analytics").json()["totals"]["cpu_minutes"] == 0.25


def test_v1_migration_backup_and_restore(tmp_path):
    path = tmp_path / "localci.db"
    store = Store(path)
    rid = store.enqueue("o/r", pr(), {})
    with sqlite3.connect(path) as db:
        for table in ("settings", "workflow_versions", "run_events", "resource_samples", "run_usage"):
            db.execute(f"DROP TABLE {table}")
        db.execute("PRAGMA user_version=1")
    migrated = Store(path)
    assert migrated.rows("SELECT id FROM runs")[0]["id"] == rid
    backup = path.with_suffix(".pre-v2.sqlite")
    assert backup.stat().st_mode & 0o777 == 0o600
    with sqlite3.connect(backup) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
        assert db.execute("SELECT id FROM runs").fetchone()[0] == rid
    migrated.save_workflow("o/r", PATH, WORKFLOW, "base")
    migrated.backup(tmp_path / "backup.sqlite")
    assert (
        Store(tmp_path / "backup.sqlite").rows("SELECT content FROM workflow_versions")[0]["content"]
        == WORKFLOW
    )


@pytest.mark.parametrize(
    "value,expected",
    [("1.25GiB", int(1.25 * 2**30)), ("512MiB", 512 * 2**20), ("12.3MB", 12300000), ("0B", 0), ("broken", 0)],
)
def test_docker_memory_units(value, expected):
    assert memory_bytes(value) == expected


async def test_scheduler_parallel_slots_drain_and_resource_reservation(tmp_path):
    c = Controller(tmp_path)
    c.capacity = {"cpus": 32, "memory_gb": 125}
    c.store.save_settings(
        {"max_parallel_runs": 1, "cpus_per_run": 24, "memory_gb_per_run": 24, "paused": False}
    )
    for n in range(1, 5):
        c.store.enqueue("o/r", pr(n), {})
    started = []
    release = asyncio.Event()

    async def execute(run):
        started.append(run)
        await release.wait()
        c.store.finish(run["id"], "success", "done")

    c.execute_run = execute
    task = asyncio.create_task(c.schedule())
    try:
        await asyncio.sleep(0.1)
        assert len(started) == 1
        # New 3x8 plan is valid, but cannot overlap a prior 24-CPU worker.
        c.store.save_settings(
            {"max_parallel_runs": 3, "cpus_per_run": 8, "memory_gb_per_run": 24, "paused": False}
        )
        await asyncio.sleep(1.1)
        assert len(started) == 1
        release.set()
        await asyncio.sleep(1.1)
        assert len(started) == 4
        assert all(json.loads(r["config"])["execution"]["cpus_per_run"] == 8 for r in started[1:])
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def test_scheduler_pause_and_live_parallel_limit(tmp_path):
    c = Controller(tmp_path)
    c.capacity = {"cpus": 32, "memory_gb": 125}
    settings = {"max_parallel_runs": 2, "cpus_per_run": 8, "memory_gb_per_run": 24, "paused": False}
    c.store.save_settings(settings)
    for n in range(4):
        c.store.enqueue("o/r", pr(n), {})
    started = []
    release = asyncio.Event()

    async def execute(run):
        started.append(run)
        await release.wait()
        c.store.finish(run["id"], "success", "done")

    c.execute_run = execute
    task = asyncio.create_task(c.schedule())
    try:
        await asyncio.sleep(0.1)
        assert len(started) == 2
        c.store.save_settings({**settings, "paused": True})
        release.set()
        await asyncio.sleep(1.1)
        assert len(started) == 2
        assert len(c.store.rows("SELECT id FROM runs WHERE state='queued'")) == 2
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


def test_final_usage_is_idempotent(tmp_path):
    store = Store(tmp_path / "db")
    rid = store.enqueue("o/r", pr(), {})
    store.claim()
    store.finish(rid, "success", "done")
    before = store.rows("SELECT * FROM run_usage")[0]
    store.finish(rid, "error", "late failure")
    assert store.rows("SELECT * FROM run_usage")[0] == before
    assert store.rows("SELECT state FROM runs")[0]["state"] == "success"


def test_pr_tab_includes_all_open_enabled_prs_with_current_revision_status(client):
    http, c = client
    assert (
        http.put("/api/repos/o/r", json={"enabled": True, "review": True, "github_auth": "gh"}).status_code
        == 200
    )
    c.store.discover([{"full_name": "o/disabled", "private": True, "default_branch": "main"}])
    items = [pr(i) for i in range(1, 105)]
    items[0]["draft"] = True
    items[1]["head"]["repo"]["full_name"] = "fork/r"
    items[2]["state"] = "closed"
    items[3].update(created_at="2026-11-12T10:00:00Z", updated_at="2026-11-13T11:00:00Z")
    c.store.replace_prs("o/r", items)
    c.store.replace_prs("o/disabled", [pr(1)])
    rid = c.store.enqueue("o/r", pr(4), {})
    c.store.finish(rid, "success", "passed")
    data = http.get("/api/prs").json()
    assert len(data["prs"]) == 103
    assert all(p["repo"] == "o/r" for p in data["prs"])
    by_number = {p["number"]: p for p in data["prs"]}
    assert by_number[1]["draft"] and "not scheduled" in by_number[1]["ci_eligibility"]
    assert by_number[2]["fork"] and "not scheduled" in by_number[2]["ci_eligibility"]
    assert 3 not in by_number
    assert by_number[4]["latest_run"]["current"] is True
    assert by_number[4]["latest_run"]["id"] == rid
    assert by_number[4]["url"] == "https://github.com/o/r/pull/4"
    assert data["prs"][0]["number"] == 4
    items[3]["head"]["sha"] = "c" * 40
    c.store.replace_prs("o/r", items)
    c.store.execute("UPDATE repos SET error='GitHub returned HTTP 403' WHERE name='o/r'")
    changed = http.get("/api/prs").json()
    assert not next(p for p in changed["prs"] if p["number"] == 4)["latest_run"]["current"]
    assert changed["errors"] == [{"name": "o/r", "error": "GitHub returned HTTP 403"}]
    assert http.get("/api/prs", headers={"Tailscale-User-Login": "stranger"}).status_code == 403
    assert http.put("/api/repos/o/r", json={"enabled": False}).status_code == 200
    assert http.get("/api/prs").json()["prs"] == []


def test_pr_refresh_replaces_closed_prs_atomically(client):
    _, c = client
    c.store.replace_prs("o/r", [pr(1), pr(2)])
    with pytest.raises(sqlite3.IntegrityError):
        c.store.replace_prs("o/r", [pr(3), pr(3)])
    assert [r["number"] for r in c.store.rows("SELECT number FROM prs ORDER BY number")] == [1, 2]
    c.store.replace_prs("o/r", [pr(2)])
    assert [r["number"] for r in c.store.rows("SELECT number FROM prs")] == [2]


def test_retry_api_and_history_share_the_configured_limit(client):
    http, c = client
    c.store.execute("UPDATE repos SET enabled=1 WHERE name='o/r'")
    c.github.request = AsyncMock(return_value=pr())
    rid = c.store.enqueue("o/r", pr(), {})
    c.store.finish(rid, "failure", "fixture")
    for _ in range(2):
        response = http.post(f"/api/runs/{rid}/retry")
        assert response.status_code == 200
        c.store.finish(response.json()["id"], "failure", "fixture")
    response = http.post(f"/api/runs/{rid}/retry")
    assert response.status_code == 409 and "3 attempts" in response.json()["detail"]
    runs = http.get("/api/state").json()["runs"]
    assert all(r["retry_limit_reached"] and r["retries_remaining"] == 0 for r in runs)
    settings = http.get("/api/execution").json()["settings"]
    assert settings["max_retries"] == 2
    assert http.put("/api/execution", json=settings | {"max_retries": 6}).status_code == 422
    assert http.put("/api/execution", json=settings | {"max_retries": 0}).status_code == 200
    assert http.post(f"/api/runs/{rid}/retry").status_code == 409
    assert http.put("/api/execution", json=settings | {"max_retries": 3}).status_code == 200
    assert http.post(f"/api/runs/{rid}/retry").json()["id"]


def test_overview_latest_per_repo_pr_is_selected_before_history_limit(client):
    http, c = client
    older = c.store.enqueue("o/r", pr(2), {})
    other_repo = c.store.enqueue("other/repo", pr(1), {})
    newest = None
    for index in range(101):
        revision = pr(1)
        revision["head"]["sha"] = f"{index:040x}"
        newest = c.store.enqueue("o/r", revision, {})
    result = http.get("/api/state").json()
    assert len(result["runs"]) == 100
    assert older not in {r["id"] for r in result["runs"]}
    assert [r["id"] for r in result["latest_runs"]] == [newest, other_repo, older]
    assert len({(r["repo"], r["pr"]) for r in result["latest_runs"]}) == 3


def test_closed_prs_are_display_only_cached_and_limited_to_enabled_repos(client):
    http, c = client
    assert http.put("/api/repos/o/r", json={"enabled": True, "review": True}).status_code == 200
    c.store.discover([{"full_name": "o/disabled", "private": True, "default_branch": "main"}])
    c.store.replace_prs("o/r", [pr(124)])
    closed, merged = pr(12), pr(13)
    closed.update(state="closed", closed_at="2026-11-14T10:00:00Z")
    merged.update(state="closed", merged_at="2026-11-14T11:00:00Z")
    c.github.pages = AsyncMock(return_value=[closed, merged])
    result = http.get("/api/prs?state=closed").json()
    assert [p["number"] for p in result["prs"]] == [13, 12]
    assert all(
        p["state"] == "closed" and p["ci_eligibility"] == "Closed — not scheduled" for p in result["prs"]
    )
    assert result["prs"][0]["merged"] and not result["prs"][1]["merged"]
    assert http.get("/api/prs?state=closed").json()["prs"] == result["prs"]
    c.github.pages.assert_awaited_once_with(
        "repos/o/r/pulls?state=closed&sort=updated&direction=desc", max_pages=2, truncate=True
    )
    assert [p["number"] for p in http.get("/api/prs").json()["prs"]] == [124]
    assert c.store.rows("SELECT * FROM runs") == []
    http.put("/api/repos/o/r", json={"enabled": False})
    assert http.get("/api/prs?state=closed").json()["prs"] == []
    assert http.get("/api/prs?state=invalid").status_code == 422


async def test_simultaneous_closed_pr_requests_share_one_fetch_per_repository(tmp_path, monkeypatch):
    import asyncio

    import httpx

    monkeypatch.setenv("LOCALCI_TAILSCALE_LOGIN", "owner@example.com")
    monkeypatch.setenv("LOCALCI_URL", "https://machine.example:9443")
    app = create_app(tmp_path, background=False)
    c = app.state.controller
    for name in ("o/r", "o/second"):
        c.store.discover([{"full_name": name, "private": True, "default_branch": "main"}])
    c.store.execute("UPDATE repos SET enabled=1")
    release, running, peak, calls = asyncio.Event(), 0, 0, []

    async def pages(path, **_):
        nonlocal running, peak
        calls.append(path)
        running += 1
        peak = max(peak, running)
        await release.wait()
        running -= 1
        return []

    c.github.pages = pages
    transport = httpx.ASGITransport(app=app)
    headers = {"Tailscale-User-Login": "owner@example.com"}
    async with httpx.AsyncClient(transport=transport, base_url="http://test", headers=headers) as http:
        requests = [asyncio.create_task(http.get("/api/prs?state=closed")) for _ in range(5)]
        await asyncio.sleep(0.2)
        release.set()
        assert all(r.status_code == 200 for r in await asyncio.gather(*requests))
    # One request per repository, and the two repositories were fetched at the same time.
    assert sorted(calls) == sorted(
        f"repos/{n}/pulls?state=closed&sort=updated&direction=desc" for n in ("o/r", "o/second")
    )
    assert peak == 2
    c.store.close()


def test_failed_closed_pr_refresh_keeps_the_time_of_the_last_success(client, monkeypatch):
    import localci.dashboard as module

    http, c = client
    assert http.put("/api/repos/o/r", json={"enabled": True, "review": True}).status_code == 200
    closed = pr(12)
    closed.update(state="closed", closed_at="2026-11-14T10:00:00Z")
    c.github.pages = AsyncMock(return_value=[closed])
    first = http.get("/api/prs?state=closed").json()
    now = module.time.time()
    monkeypatch.setattr(module.time, "time", lambda: now + 120)  # The cache is stale.
    c.github.pages = AsyncMock(side_effect=RuntimeError("GitHub returned HTTP 403"))
    second = http.get("/api/prs?state=closed").json()
    assert [p["number"] for p in second["prs"]] == [12] and second["errors"]
    # The time of the last success (within the first request), not of the failed attempt.
    assert abs(second["last_poll"] - first["last_poll"]) < 5 and second["last_poll"] < now + 60


def test_closed_pr_fetch_failure_is_reported_without_changing_open_snapshot(client):
    http, c = client
    assert http.put("/api/repos/o/r", json={"enabled": True, "review": True}).status_code == 200
    c.store.replace_prs("o/r", [pr(124)])
    c.github.pages = AsyncMock(side_effect=RuntimeError("GitHub returned HTTP 403"))
    result = http.get("/api/prs?state=closed").json()
    assert result["prs"] == []
    assert result["errors"] == [{"name": "o/r", "error": "GitHub returned HTTP 403"}]
    assert len(http.get("/api/prs").json()["prs"]) == 1


def test_threshold_is_validated_and_snapshotted_for_new_runs(client):
    http, c = client
    for invalid in ("off", "critical", "MAJOR", None):
        assert http.put("/api/repos/o/r", json={"review_failure_threshold": invalid}).status_code == 422
    for number, threshold in enumerate(("major", "minor", "trivial"), start=1):
        assert (
            http.put(
                "/api/repos/o/r", json={"review": True, "review_failure_threshold": threshold}
            ).status_code
            == 200
        )
        config = json.loads(c.store.repo("o/r")["config"])
        rid = c.store.enqueue("o/r", pr(number), config)
        saved = json.loads(c.store.rows("SELECT config FROM runs WHERE id=?", (rid,))[0]["config"])
        assert saved["review_failure_threshold"] == threshold and saved["review_policy_version"] == 1
    http.put("/api/repos/o/r", json={"review_failure_threshold": "major"})
    assert (
        json.loads(c.store.rows("SELECT config FROM runs WHERE id=?", (rid,))[0]["config"])[
            "review_failure_threshold"
        ]
        == "trivial"
    )
