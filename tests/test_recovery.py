"""Run recovery, cancellation, approval gates, and result aggregation."""

import asyncio
import json
import sqlite3
from unittest.mock import AsyncMock

import pytest

from localci.controller import Controller
from localci.github import GitHub
from localci.policy import BOT_HOLD, bot_pr
from localci.results import aggregate
from localci.store import MAX_RECOVERIES, SCHEMA_VERSION, RetryLimitReached, Store
from tests.test_service import client, pr, repo  # noqa: F401  (client is a fixture)

REPO = "owner/repo"


def run(store, rid):
    return store.rows("SELECT * FROM runs WHERE id=?", (rid,))[0]


def budget(store):
    return store.rows("SELECT attempts,recoveries FROM revision_attempts")[0]


def start_step(store, rid, name="ci.yml"):
    """Mirror a worker that began a check before being interrupted."""
    store.execute(
        "UPDATE runs SET steps=? WHERE id=?",
        (json.dumps([{"name": name, "state": "running", "message": ""}]), rid),
    )


def test_operator_cancel_of_queued_run_is_final_until_operator_retries(tmp_path):
    store = Store(tmp_path / "db")
    rid = store.enqueue(REPO, pr(), {})
    store.request_cancel(rid, "operator", "Cancelled by operator")
    assert run(store, rid)["state"] == "cancelled"
    # Every later poll offers the same open PR again; it must stay stopped.
    for _ in range(3):
        assert store.enqueue(REPO, pr(), {}) is None
    retried = store.enqueue(REPO, pr(), {}, retry=True)
    assert retried and run(store, retried)["state"] == "queued"


def test_operator_cancel_of_running_run_survives_worker_finalization_and_stop(tmp_path):
    store = Store(tmp_path / "db")
    rid = store.enqueue(REPO, pr(), {})
    assert store.claim()["id"] == rid
    store.request_cancel(rid, "operator", "Cancelled by operator")
    assert run(store, rid)["state"] == "running"  # The worker, not the request, ends it.
    # A graceful worker stop racing the cancel must not turn it into a recoverable run.
    store.finish(rid, "error", "Controller stopped during execution", reason="worker_interrupted")
    assert run(store, rid)["end_reason"] == "operator"
    assert store.enqueue(REPO, pr(), {}) is None


@pytest.mark.parametrize("started_step", [False, True])
def test_worker_interruption_recovers_without_billing_even_after_checks_started(tmp_path, started_step):
    store = Store(tmp_path / "db")
    rid = store.enqueue(REPO, pr(), {})
    store.claim()
    if started_step:
        start_step(store, rid)
    store.finish(
        rid, "error", "Execution worker restarted before this run completed", reason="worker_interrupted"
    )
    # The stored message is rewritten by aggregation once a step exists; recovery must not depend on it.
    assert ("ci.yml" in run(store, rid)["message"]) is started_step
    recovered = store.enqueue(REPO, pr(), {})
    assert recovered and recovered != rid
    assert budget(store) == {"attempts": 1, "recoveries": 1}


def test_draft_then_ready_recovers_and_recoveries_are_capped(tmp_path):
    store = Store(tmp_path / "db")
    rid = store.enqueue(REPO, pr(), {})
    draft = {**pr(), "draft": True}
    for expected in range(1, MAX_RECOVERIES + 1):
        store.cancel_stale(REPO, [draft])
        assert run(store, rid)["end_reason"] == "pr_inactive"
        rid = store.enqueue(REPO, pr(), {})
        assert rid, "system-cancelled run must be re-queued"
        assert budget(store) == {"attempts": 1, "recoveries": expected}
    store.cancel_stale(REPO, [draft])
    assert store.enqueue(REPO, pr(), {}) is None  # A crash or flapping loop stops here.
    assert store.enqueue(REPO, pr(), {}, retry=True)  # The operator can still run it.


def test_manual_retry_after_recovery_gets_unique_run_number_and_correct_billing(tmp_path):
    store = Store(tmp_path / "db")
    first = store.enqueue(REPO, pr(), {})
    store.cancel_stale(REPO, [])
    recovered = store.enqueue(REPO, pr(), {})
    store.finish(recovered, "failure", "Checks failed")
    assert store.enqueue(REPO, pr(), {}) is None  # A real failure is never re-run automatically.
    retried = store.enqueue(REPO, pr(), {}, retry=True)  # Previously an IntegrityError (HTTP 500).
    assert [run(store, r)["attempt"] for r in (first, recovered, retried)] == [1, 2, 3]
    assert budget(store) == {"attempts": 2, "recoveries": 1}
    store.finish(retried, "failure", "Checks failed")
    assert store.enqueue(REPO, pr(), {}, retry=True)
    store.finish(store.claim()["id"], "failure", "Checks failed")
    with pytest.raises(RetryLimitReached):
        store.enqueue(REPO, pr(), {}, retry=True)


def test_reopening_the_database_does_not_bill_recoveries(tmp_path):
    store = Store(tmp_path / "db")
    store.enqueue(REPO, pr(), {})
    store.cancel_stale(REPO, [])
    store.enqueue(REPO, pr(), {})
    store.close()
    assert budget(Store(tmp_path / "db")) == {"attempts": 1, "recoveries": 1}


def test_cancel_request_does_not_requeue_a_run_that_completed_first(tmp_path):
    store = Store(tmp_path / "db")
    rid = store.enqueue(REPO, pr(), {})
    store.claim()
    store.request_cancel(rid, "pr_inactive", "PR changed, closed, or became a draft")
    store.finish(rid, "success", "All configured checks passed")
    assert run(store, rid)["end_reason"] == ""
    assert store.enqueue(REPO, pr(), {}) is None


def test_stale_cancel_never_finalizes_a_run_claimed_by_a_worker(tmp_path):
    store = Store(tmp_path / "db")
    rid = store.enqueue(REPO, pr(), {})
    read = store.rows

    def rows_then_worker_claims(sql, args=()):
        result = read(sql, args)
        if "state IN ('queued','running')" in sql:
            assert result[0]["state"] == "queued"
            store.claim()  # The worker claims between the stale check's read and its write.
        return result

    store.rows = rows_then_worker_claims
    store.cancel_stale(REPO, [])
    store.rows = read
    row = run(store, rid)
    assert (row["state"], row["cancel"], row["finished"]) == ("running", 1, None)


def test_disable_cancels_runs_and_reenable_recovers_them(client):  # noqa: F811
    store = client.app.state.controller.store
    assert client.put("/api/repos/owner/repo", json={"enabled": True, "review": True}).status_code == 200
    rid = store.enqueue(REPO, pr(), {})
    assert client.put("/api/repos/owner/repo", json={"enabled": False}).status_code == 200
    row = run(store, rid)
    assert (row["state"], row["end_reason"], row["message"]) == (
        "cancelled",
        "repo_disabled",
        "Repository disabled",
    )
    # While disabled, the poll's path refuses; re-enabling is what recovers the run.
    assert store.enqueue(REPO, pr(), {}, require_enabled=True) is None
    assert client.put("/api/repos/owner/repo", json={"enabled": True, "review": True}).status_code == 200
    recovered = store.enqueue(REPO, pr(), {}, require_enabled=True)
    assert recovered and store.claim()["id"] == recovered


def test_cancel_endpoint_is_final_and_retry_endpoint_still_works(client):  # noqa: F811
    controller = client.app.state.controller
    store = controller.store
    assert client.put("/api/repos/owner/repo", json={"enabled": True, "review": True}).status_code == 200
    rid = store.enqueue(REPO, pr(), {})
    assert client.post(f"/api/runs/{rid}/cancel").status_code == 200
    assert run(store, rid)["end_reason"] == "operator"
    assert store.enqueue(REPO, pr(), {}) is None
    controller.github.request = AsyncMock(return_value=pr())
    response = client.post(f"/api/runs/{rid}/retry")
    assert response.status_code == 200 and response.json()["id"] != rid


def test_bot_pr_is_held_unbilled_until_an_operator_runs_it(tmp_path):
    store = Store(tmp_path / "db")
    held = store.enqueue(REPO, pr(), {}, hold=BOT_HOLD)
    row = run(store, held)
    assert (row["state"], row["message"], row["end_reason"]) == ("blocked", BOT_HOLD, "awaiting_approval")
    assert row["finished"] and store.claim() is None
    assert budget(store) == {"attempts": 0, "recoveries": 0}
    assert store.enqueue(REPO, pr(), {}, hold=BOT_HOLD) is None  # Later polls add nothing.
    approved = store.enqueue(REPO, pr(), {}, retry=True)
    assert store.claim()["id"] == approved
    assert budget(store) == {"attempts": 1, "recoveries": 0}


def test_bot_detection_uses_author_identity_not_branch_name():
    human = pr()
    human["head"]["ref"] = "dependabot/npm/left-pad"
    assert not bot_pr(human)
    assert bot_pr({**pr(), "user": {"login": "dependabot[bot]", "type": "Bot"}})
    assert bot_pr({**pr(), "user": {"login": "renovate[bot]"}})
    assert bot_pr({**pr(), "user": {"login": "custom-updater", "type": "Bot"}})


@pytest.mark.parametrize("run_bot_prs", [False, True])
async def test_poll_holds_bot_prs_unless_the_repository_opts_in(tmp_path, monkeypatch, run_bot_prs):
    monkeypatch.setenv("LOCALCI_TOKEN_FILE", str(tmp_path / "token"))
    controller = Controller(tmp_path / "data")
    store = controller.store
    store.discover([repo()])
    store.execute("UPDATE repos SET enabled=1,config=?", (json.dumps({"run_bot_prs": run_bot_prs}),))
    bot = {**pr(), "number": 7, "user": {"login": "dependabot[bot]", "type": "Bot"}}
    controller.last_discovery = float("inf")
    controller.github.pages = AsyncMock(return_value=[pr(), bot])
    controller.publish = AsyncMock()
    await controller.poll()
    await controller.poll()
    states = {r["pr"]: r["state"] for r in store.rows("SELECT pr,state FROM runs")}
    assert states == {4: "queued", 7: "queued" if run_bot_prs else "blocked"}
    held = store.rows("SELECT * FROM runs WHERE pr=7")[0]
    if not run_bot_prs:
        assert controller.reports(held) == {}  # No phase comments for a run that never started.
    store.close()


async def test_pagination_refuses_partial_results_unless_caller_opts_in(tmp_path):
    github = GitHub(tmp_path / "token")
    github.request = AsyncMock(return_value=[{}] * 100)
    with pytest.raises(RuntimeError, match="partial"):
        await github.pages("repos/owner/repo/pulls?state=open", max_pages=3)
    assert github.request.await_count == 3
    assert len(await github.pages("repos/owner/repo/pulls?state=closed", max_pages=2, truncate=True)) == 200
    github.request = AsyncMock(side_effect=[[{}] * 100, [{}] * 5])
    assert len(await github.pages("repos/owner/repo/pulls?state=open", max_pages=2)) == 105


def test_cancelled_run_keeps_earlier_failures_visible():
    steps = [
        {"name": "ci.yml", "state": "failure", "message": "1 job failed"},
        {"name": "mergeCraft", "state": "cancelled", "message": "Cancelled by operator"},
    ]
    state, message = aggregate(steps, "cancelled", "Cancelled by operator")
    assert state == "cancelled"
    assert "Cancelled by operator" in message and "ci.yml: failure (1 job failed)" in message
    assert aggregate([], "cancelled", "Cancelled by operator") == ("cancelled", "Cancelled by operator")


def test_workflow_where_no_job_ran_is_named_not_counted_as_passed():
    steps = [
        {"name": "Checkout", "state": "success"},
        {"name": "ci.yml", "state": "success"},
        {"name": "release.yml", "state": "skipped"},
    ]
    state, message = aggregate(steps, "success", "All configured checks passed")
    assert state == "success"
    assert "All configured checks passed" not in message and "release.yml" in message
    assert (
        aggregate(steps[:2], "success", "All configured checks passed")[1] == "All configured checks passed"
    )


@pytest.mark.parametrize(
    "capacity", [{"cpus": 1, "memory_gb": 1}, {"cpus": 2, "memory_gb": 4}, {"cpus": 3, "memory_gb": 5}]
)
async def test_scheduler_starts_default_sized_runs_on_small_hosts(tmp_path, monkeypatch, capacity):
    monkeypatch.setenv("LOCALCI_TOKEN_FILE", str(tmp_path / "token"))
    controller = Controller(tmp_path / "data")
    controller.capacity = capacity
    started = asyncio.Event()

    async def execute(run):
        started.set()

    controller.execute_run = execute
    controller.store.enqueue(REPO, pr(), {})
    task = asyncio.create_task(controller.schedule())
    try:
        await asyncio.wait_for(started.wait(), 5)
        assert controller.error == ""
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        controller.store.close()


async def test_scheduler_reports_unfit_run_and_clears_the_message_when_it_fits(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALCI_TOKEN_FILE", str(tmp_path / "token"))
    controller = Controller(tmp_path / "data")
    store = controller.store
    controller.capacity = {"cpus": 4, "memory_gb": 8}
    store.save_settings({**store.settings(controller.capacity), "cpus_per_run": 16})
    controller.execute_run = AsyncMock()
    rid = store.enqueue(REPO, pr(), {})
    task = asyncio.create_task(controller.schedule())

    async def until(predicate):
        async with asyncio.timeout(5):
            while not predicate():  # noqa: ASYNC110  (observes the scheduler loop from outside)
                await asyncio.sleep(0.05)

    try:
        await until(lambda: "does not fit" in controller.error)
        # A completed poll clears only its own error; the capacity problem stays visible.
        controller.poll_error = "GitHub request failed"
        controller.last_discovery = float("inf")
        controller.publish = AsyncMock()
        await controller.poll()
        assert controller.error.startswith("Queued run does not fit")
        assert run(store, rid)["state"] == "queued"
        store.save_settings({**store.settings(controller.capacity), "cpus_per_run": 2})
        await until(lambda: controller.error == "")
        assert run(store, rid)["state"] == "running"
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        store.close()


def test_version_3_database_migrates_without_rebilling_and_keeps_recovery(tmp_path):
    """A database written by the previous release: no end_reason/recoveries columns, and
    recoverable runs identified only by the message that release stored."""
    path = tmp_path / "db"
    store = Store(path)
    store.close()
    revisions = {
        "pr_inactive": ("cancelled", "PR changed, closed, or became a draft"),
        "repo_disabled": ("cancelled", "Repository disabled"),
        "worker_interrupted": ("error", "ci.yml: error (Execution worker restarted; retry this run)"),
        # What stopping the old worker for the upgrade itself leaves behind.
        "worker_interrupted ": (
            "error",
            "ci.yml: error (Controller stopped during execution; retry this run)",
        ),
        "": ("failure", "ci.yml: failure (1 job failed)"),
    }
    with sqlite3.connect(path) as db:
        db.execute("ALTER TABLE runs DROP COLUMN end_reason")
        db.execute("ALTER TABLE revision_attempts DROP COLUMN recoveries")
        for number, (state, message) in enumerate(revisions.values(), start=1):
            snapshot = {**pr(head=f"{number:040x}"), "number": number}
            # Run number 2 after one billed attempt: the old release's unbilled recovery.
            db.execute(
                "INSERT INTO runs(id,repo,pr,head,base,attempt,state,created,finished,snapshot,config,message) "
                "VALUES(?,?,?,?,?,2,?,1,2,?,'{}',?)",
                (
                    f"{number:032x}",
                    REPO,
                    number,
                    snapshot["head"]["sha"],
                    "b" * 40,
                    state,
                    json.dumps(snapshot),
                    message,
                ),
            )
            db.execute(
                "INSERT INTO revision_attempts VALUES(?,?,?,?,1)",
                (REPO, number, snapshot["head"]["sha"], "b" * 40),
            )
        db.execute("PRAGMA user_version=3")
    migrated = Store(path)
    assert migrated.rows("PRAGMA user_version")[0]["user_version"] == SCHEMA_VERSION
    assert path.with_suffix(".pre-v4.sqlite").exists()
    reasons = [r["end_reason"] for r in migrated.rows("SELECT end_reason FROM runs ORDER BY pr")]
    assert reasons == [reason.strip() for reason in revisions]
    # Opening again must neither re-bill the unbilled run numbers nor alter reasons.
    migrated.close()
    migrated = Store(path)
    assert {r["attempts"] for r in migrated.rows("SELECT attempts FROM revision_attempts")} == {1}
    for number, reason in enumerate(revisions, start=1):
        requeued = migrated.enqueue(REPO, {**pr(head=f"{number:040x}"), "number": number}, {})
        assert bool(requeued) is bool(reason), reason or "a genuine failure must not be re-run"


@pytest.mark.parametrize("later", ["repo_disabled", "pr_inactive"])
def test_operator_cancel_is_not_overwritten_by_a_later_system_cancel(tmp_path, later):
    store = Store(tmp_path / "db")
    rid = store.enqueue(REPO, pr(), {})
    store.claim()
    store.request_cancel(rid, "operator", "Cancelled by operator")
    # Before the worker stops the run, the repository is disabled or the PR is drafted.
    store.request_cancel(rid, later, "Repository disabled")
    store.finish(rid, "cancelled", "Cancelled by operator or superseded PR revision")
    assert run(store, rid)["end_reason"] == "operator"
    assert store.enqueue(REPO, pr(), {}) is None


def test_cancel_request_and_finalization_are_one_transaction(tmp_path, monkeypatch):
    store = Store(tmp_path / "db")
    rid = store.enqueue(REPO, pr(), {})
    monkeypatch.setattr(Store, "_finish", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("crash")))
    with pytest.raises(RuntimeError):
        store.request_cancel(rid, "operator", "Cancelled by operator")
    # Nothing half-applied: the run is still claimable rather than stuck queued with cancel=1.
    assert (run(store, rid)["cancel"], run(store, rid)["end_reason"]) == (0, "")
    assert store.claim()["id"] == rid


async def test_poll_in_flight_cannot_requeue_a_run_cancelled_by_disabling_the_repository(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("LOCALCI_TOKEN_FILE", str(tmp_path / "token"))
    controller = Controller(tmp_path / "data")
    store = controller.store
    store.discover([repo()])
    store.execute("UPDATE repos SET enabled=1,config='{}'")
    rid = store.enqueue(REPO, pr(), {})
    controller.last_discovery = float("inf")
    controller.publish = AsyncMock()

    async def pages_while_operator_disables(path):
        # The poll has already listed the repository as enabled and is waiting on GitHub.
        store.execute("UPDATE repos SET enabled=0")
        store.request_cancel(rid, "repo_disabled", "Repository disabled")
        return [pr()]

    controller.github.pages = pages_while_operator_disables
    await controller.poll()
    assert [r["state"] for r in store.rows("SELECT state FROM runs")] == ["cancelled"]
    assert store.claim() is None
    # Re-enabling is what recovers it.
    store.execute("UPDATE repos SET enabled=1")
    controller.github.pages = AsyncMock(return_value=[pr()])
    await controller.poll()
    assert store.claim()["id"] != rid
    store.close()


def bot(head="a" * 40):
    return {**pr(head=head), "user": {"login": "dependabot[bot]", "type": "Bot"}}


def test_retry_approves_only_the_reviewed_revision_of_a_bot_pr(client):  # noqa: F811
    controller = client.app.state.controller
    store = controller.store
    assert client.put("/api/repos/owner/repo", json={"enabled": True, "review": True}).status_code == 200
    held = store.enqueue(REPO, bot(), {}, hold=BOT_HOLD)
    # The bot pushes a new commit after the operator reviewed the held one.
    controller.github.request = AsyncMock(return_value=bot(head="c" * 40))
    response = client.post(f"/api/runs/{held}/retry")
    assert response.status_code == 409 and "changed" in response.json()["detail"]
    assert [r["state"] for r in store.rows("SELECT state FROM runs")] == ["blocked"]
    # Unchanged revision: the approval runs exactly what was reviewed.
    controller.github.request = AsyncMock(return_value=bot())
    approved = client.post(f"/api/runs/{held}/retry").json()["id"]
    assert run(store, approved)["head"] == "a" * 40 and run(store, approved)["state"] == "queued"
    # A human-authored PR keeps the ordinary "retry the latest revision" behaviour.
    store.finish(approved, "failure", "Checks failed")
    controller.github.request = AsyncMock(return_value=pr(head="d" * 40))
    assert client.post(f"/api/runs/{approved}/retry").status_code == 200


def test_enabling_automatic_bot_runs_releases_held_prs_once(tmp_path):
    store = Store(tmp_path / "db")
    held = store.enqueue(REPO, bot(), {}, hold=BOT_HOLD)
    assert store.enqueue(REPO, bot(), {}, hold=BOT_HOLD) is None  # Still gated.
    released = store.enqueue(REPO, bot(), {})  # The poll after run_bot_prs was switched on.
    assert released and released != held and run(store, released)["state"] == "queued"
    assert budget(store) == {"attempts": 1, "recoveries": 0}
    store.finish(store.claim()["id"], "failure", "Checks failed")
    assert store.enqueue(REPO, bot(), {}) is None  # Released once, not re-run after failing.


async def test_finalization_error_stays_while_its_run_is_stuck(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALCI_TOKEN_FILE", str(tmp_path / "token"))
    controller = Controller(tmp_path / "data")
    store = controller.store
    controller.capacity = {"cpus": 8, "memory_gb": 16}
    clean_run_done = asyncio.Event()

    async def execute(claimed):
        if claimed["head"] == "a" * 40:
            raise RuntimeError("database is locked")  # Left 'running' with no worker task.
        store.finish(claimed["id"], "success", "All configured checks passed")
        clean_run_done.set()

    async def until(predicate):
        async with asyncio.timeout(5):
            while not predicate():  # noqa: ASYNC110
                await asyncio.sleep(0.05)

    controller.execute_run = execute
    stuck = store.enqueue(REPO, pr(), {})
    task = asyncio.create_task(controller.schedule())
    try:
        await until(lambda: "finalization failed" in controller.error)
        store.enqueue(REPO, {**pr(head="c" * 40), "number": 5}, {})
        await asyncio.wait_for(clean_run_done.wait(), 5)
        await asyncio.sleep(1.2)  # At least one further scheduler pass.
        # A later clean run must not hide that the first is still stuck.
        assert stuck[:8] in controller.error and run(store, stuck)["state"] == "running"
        # Once the run is no longer active and some time has passed, the message goes.
        store.finish(stuck, "error", "Execution worker restarted before this run completed")
        message, _ = controller.run_errors[stuck]
        controller.run_errors[stuck] = (message, 0.0)
        await until(lambda: controller.error == "")
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        store.close()


def test_retry_cannot_queue_into_a_repository_disabled_during_the_request(client):  # noqa: F811
    controller = client.app.state.controller
    store = controller.store
    assert client.put("/api/repos/owner/repo", json={"enabled": True, "review": True}).status_code == 200
    rid = store.enqueue(REPO, pr(), {})
    store.finish(rid, "failure", "Checks failed")

    async def fetch_while_operator_disables(*_):
        # The retry already saw the repository enabled and is waiting on GitHub.
        store.execute("UPDATE repos SET enabled=0 WHERE name=?", (REPO,))
        return pr()

    controller.github.request = fetch_while_operator_disables
    response = client.post(f"/api/runs/{rid}/retry")
    assert response.status_code == 400 and "Enable the repository" in response.json()["detail"]
    assert store.claim() is None
    assert [r["state"] for r in store.rows("SELECT state FROM runs")] == ["failure"]


async def test_poll_with_stale_configuration_cannot_release_or_run_bot_prs(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALCI_TOKEN_FILE", str(tmp_path / "token"))
    controller = Controller(tmp_path / "data")
    store = controller.store
    store.discover([repo()])
    store.execute("UPDATE repos SET enabled=1,config=?", (json.dumps({"run_bot_prs": True}),))
    held = store.enqueue(REPO, bot(), {}, hold=BOT_HOLD)
    controller.last_discovery = float("inf")
    controller.publish = AsyncMock()

    async def pages_while_operator_switches_bot_runs_off(path):
        # The poll read run_bot_prs=True when it listed the repository.
        store.execute("UPDATE repos SET config=?", (json.dumps({"run_bot_prs": False}),))
        return [bot(), {**bot(head="c" * 40), "number": 9}]

    controller.github.pages = pages_while_operator_switches_bot_runs_off
    await controller.poll()
    states = {r["pr"]: r["state"] for r in store.rows("SELECT pr,state FROM runs ORDER BY created")}
    assert states == {4: "blocked", 9: "blocked"} and store.claim() is None
    assert (
        store.rows("SELECT COUNT(*) AS n FROM runs")[0]["n"] == 2 and run(store, held)["state"] == "blocked"
    )
    store.close()
