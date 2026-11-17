import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from test_service import pr

from localci.app import RepoConfig
from localci.github import GitHub, GitHubError
from localci.policy import Blocked, plan
from localci.runner import Runner
from localci.store import Store


@pytest.mark.parametrize("review", ["error", "blocked", "failure", "success"])
def test_ci_failure_survives_review_result_and_history_repair(tmp_path, review):
    store = Store(tmp_path / "db")
    rid = store.enqueue("owner/repo", pr(), {})
    store.claim()
    steps = [
        {"name": "ci.yml", "state": "failure", "message": "tests failed"},
        {"name": "mergeCraft", "state": review, "message": "review result"},
    ]
    store.execute("UPDATE runs SET steps=? WHERE id=?", (json.dumps(steps), rid))
    store.finish(rid, review, "review result")
    row = store.rows("SELECT * FROM runs WHERE id=?", (rid,))[0]
    assert row["state"] == "failure"
    assert "ci.yml: failure" in row["message"]
    if review != "success":
        assert f"mergeCraft: {review}" in row["message"]
    assert store.rows("SELECT state FROM run_usage")[0]["state"] == "failure"
    store.execute("UPDATE runs SET state=?,message=? WHERE id=?", (review, "old summary", rid))
    if review != "success":
        store.reconcile_results()
        assert store.rows("SELECT state FROM runs")[0]["state"] == "failure"
    repaired = store.rows("SELECT * FROM runs")
    store.reconcile_results()
    assert store.rows("SELECT * FROM runs") == repaired


def test_cancellation_closes_step_and_preserves_failure_evidence(tmp_path):
    store = Store(tmp_path / "db")
    rid = store.enqueue("owner/repo", pr(), {})
    store.claim()
    store.execute(
        "UPDATE runs SET steps=?",
        (
            json.dumps(
                [
                    {"name": "ci.yml", "state": "failure", "message": "failed"},
                    {"name": "mergeCraft", "state": "running", "started": 1},
                ]
            ),
        ),
    )
    store.finish(rid, "cancelled", "Cancelled by user")
    row = store.rows("SELECT * FROM runs")[0]
    assert row["state"] == "cancelled"
    steps = json.loads(row["steps"])
    assert steps[0]["state"] == "failure"
    assert steps[1]["state"] == "cancelled" and steps[1]["finished"] > 1
    store.reconcile_results()
    assert store.rows("SELECT * FROM runs")[0] == row


def test_github_auth_is_explicit_and_policy_requires_it():
    assert RepoConfig().github_auth == "none"
    text = "on: pull_request\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo '${{ github.token }}'\n"
    with pytest.raises(Blocked, match="GitHub authentication"):
        plan(text, set(), {})
    assert plan(text, {"GITHUB_TOKEN"}, {})[0]["jobs"]["test"]


@pytest.mark.parametrize("enabled", [False, True])
async def test_worker_token_opt_in_file_redaction_and_review_isolation(tmp_path, monkeypatch, enabled):
    monkeypatch.setenv("LOCALCI_REVIEW_IMAGE", "review:test")
    token = tmp_path / "token"
    token.write_text("fixture-private-account-token")
    store = Store(tmp_path / "data/db")
    runner = Runner(
        store,
        GitHub(token),
        tmp_path / "data",
        lambda _, scope: {"PROVIDER_KEY": "provider-value"} if scope == "review" else {},
    )
    seen = {"ci": False, "review": False}

    async def command(*args, **kwargs):
        assert token.read_text() not in repr(args)
        if args[:2] == ("git", "clone"):
            Path(args[-1]).mkdir(parents=True)
        if args[:2] == ("git", "show"):
            if args[-1].endswith("ci.yml"):
                return (
                    0,
                    "on: pull_request\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps: [{run: echo ok}]\n",
                )
            return 0, "{}"
        if args[:2] == ("docker", "cp") and Path(args[2]).name == "control":
            assert not list(Path(args[2]).glob("*.secrets"))  # Secrets arrive per workflow, not up front.
        if args[:2] == ("docker", "cp") and Path(args[2]).name == "ci.yml.secrets":
            secret_file = Path(args[2])
            content = secret_file.read_text()
            assert (token.read_text() in content) == enabled
            assert secret_file.stat().st_mode & 0o777 == 0o600
            assert "provider-value" not in content
            seen["ci"] = True
        if "act" in args:
            assert "--init" in args[args.index("--container-options") + 1]
            assert "-s" not in args
            runner.completed_jobs = 1
            runner.log(token.read_text())
        if args[:2] == ("docker", "create"):
            content = Path(args[args.index("--env-file") + 1]).read_text()
            assert "provider-value" in content and token.read_text() not in content
            seen["review"] = True
        if args[:3] == ("docker", "start", "-a"):
            runner.log(
                '{"event":"verdict","protocol_version":"1","outcome":"passed","exit_code":0}\n{"event":"run_finished","protocol_version":"1","exit_code":0}\n'
            )
        if args[:2] == ("docker", "cp") and args[2].endswith(":/tmp/review.json"):
            Path(args[3]).write_text('{"findings":[]}')
        return 0, ""

    runner.command = command
    runner.cleanup = AsyncMock()
    rid = store.enqueue(
        "owner/repo",
        pr(),
        {
            "github_auth": "gh" if enabled else "none",
            "workflows": [".github/workflows/ci.yml"],
            "review": True,
        },
    )
    await runner.execute(store.claim())
    assert store.rows("SELECT state,message FROM runs")[0]["state"] == "success"
    assert all(seen.values())
    assert token.read_text() not in runner.log_path.read_text()
    assert not (tmp_path / "data/work" / rid).exists()


@pytest.mark.parametrize(
    "status,path,fallback",
    [
        (404, "repos/owner/repo/installation", True),
        (401, "repos/owner/repo/installation", False),
        (403, "repos/owner/repo/check-runs", False),
        (404, "repos/owner/repo/check-runs", False),
    ],
)
async def test_missing_app_installation_uses_gh_commit_status_only(tmp_path, status, path, fallback):
    github = GitHub(tmp_path / "token", lambda: {"app_id": "123"})
    github.check_run = AsyncMock(side_effect=GitHubError(status, "GET", path))
    github.request = AsyncMock(return_value={})
    run = {"repo": "owner/repo", "head": "a" * 40}
    if fallback:
        mode = await github.status(run, "failure", "CI failed; review errored", "https://local.test")
        assert "gh login" in mode
        assert github.request.call_args.args == ("POST", "repos/owner/repo/statuses/" + "a" * 40)
        assert github.request.call_args.kwargs["json"]["state"] == "failure"
    else:
        with pytest.raises(GitHubError):
            await github.status(run, "failure", "failed", "https://local.test")
        github.request.assert_not_called()


def test_historical_cancelled_run_does_not_keep_running_checks(tmp_path):
    store = Store(tmp_path / "db")
    rid = store.enqueue("owner/repo", pr(), {})
    store.execute(
        "UPDATE runs SET state='cancelled',finished=123,message='Stopped',steps=? WHERE id=?",
        (json.dumps([{"name": "ci.yml", "state": "running", "started": 100}]), rid),
    )
    store.reconcile_results()
    row = store.rows("SELECT * FROM runs")[0]
    assert row["state"] == "cancelled"
    assert json.loads(row["steps"]) == [
        {"name": "ci.yml", "state": "cancelled", "started": 100, "finished": 123, "message": "Stopped"}
    ]
    store.reconcile_results()
    assert store.rows("SELECT * FROM runs")[0] == row
