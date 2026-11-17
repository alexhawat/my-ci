import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from test_service import pr

from localci.github import GitHub
from localci.reporting import reports
from localci.runner import Runner
from localci.store import Store


@pytest.mark.parametrize("first", ["ci", "review"])
@pytest.mark.parametrize(
    "failed",
    [
        None,
        "ci",
        "review",
        "ci_exception",
        "review_exception",
        "inconclusive",
        "nonblocking",
        "ci_nonblocking",
        "config_error",
    ],
)
async def test_phases_overlap_keep_secrets_and_results_independent(tmp_path, monkeypatch, first, failed):
    monkeypatch.setenv("LOCALCI_REVIEW_IMAGE", "review:test")
    token = tmp_path / "token"
    token.write_text("fixture-github-token")
    store = Store(tmp_path / "data/db")
    runner = Runner(
        store, GitHub(token), tmp_path / "data", lambda _, scope: {"KEY": f"{scope}-private-value"}
    )
    started = {k: asyncio.Event() for k in ("ci", "review")}
    release = {k: asyncio.Event() for k in ("ci", "review")}
    limits = {}

    async def command(*args, **kwargs):
        if args[:2] == ("git", "clone"):
            Path(args[-1]).mkdir(parents=True)
        if args[:2] == ("git", "show"):
            if args[-1].endswith("ci.yml"):
                return (
                    0,
                    "on: pull_request\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps: [{run: echo ok}]\n",
                )
            return 0, "{}"
        if args[:2] in (("docker", "run"), ("docker", "create")):
            kind = "ci" if args[1] == "run" else "review"
            limits[kind] = {
                key: float(next(a for a in args if a.startswith(f"--{key}=")).split("=")[1].rstrip("g"))
                for key in ("cpus", "memory")
            }
            if kind == "review":
                env_path = Path(args[args.index("--env-file") + 1])
                assert "review-private-value" in env_path.read_text()
                assert "ci-private-value" not in env_path.read_text()
                assert env_path.parent.name != "control"
                assert "--privileged" not in args and "-v" not in args
        if args[:2] == ("docker", "cp") and Path(args[2]).name == "control":
            # Check the entire directory transferred to CI, not just secrets.
            text = "".join(p.read_text() for p in Path(args[2]).rglob("*") if p.is_file())
            assert "review-private-value" not in text
        kind = "ci" if "act" in args else "review" if args[:3] == ("docker", "start", "-a") else None
        if kind:
            started[kind].set()
            await started["review" if kind == "ci" else "ci"].wait()
            await asyncio.to_thread(runner.log, f"{kind} phase marker\n")
            await release[kind].wait()
            if failed == kind + "_exception":
                raise RuntimeError(f"{kind} infrastructure failed")
            if kind == "ci":
                runner.completed_jobs = 1
            code = (1 if kind == "ci" else 12) if failed == kind else 0
            if failed == "ci_nonblocking" and kind == "ci":
                code = 1
            if kind == "review":
                if failed == "config_error":
                    runner.log(
                        "config validation failed: 1 validation error for RepoSettings\nreview.ignorePaths\n  Extra inputs are not permitted\n"
                    )
                    return 30, ""
                if failed in ("nonblocking", "ci_nonblocking"):
                    code = 10
                if failed == "inconclusive":
                    code = 11
                for event in ("verdict", "run_finished"):
                    runner.log(
                        json.dumps(
                            {
                                "event": event,
                                "protocol_version": "1",
                                "outcome": "inconclusive"
                                if failed == "inconclusive"
                                else "failed"
                                if code and code != 10
                                else "passed",
                                "exit_code": code,
                            }
                        )
                        + "\n"
                    )
            return code, ""
        if args[:2] == ("docker", "cp") and args[2].endswith(":/tmp/review.json"):
            if failed == "config_error":
                return 1, "missing JSON report"
            findings = (
                [{"severity": "Minor", "message": "warning", "evidence": []}]
                if failed in ("nonblocking", "ci_nonblocking")
                else []
            )
            Path(args[3]).write_text(json.dumps({"findings": findings, "source": "review"}))
        if args[:2] == ("docker", "cp") and args[2].endswith(":/artifacts/."):
            # An untrusted CI artifact must never replace the review result.
            (Path(args[3]) / "mergecraft.json").write_text('{"source":"ci"}')
        return 0, ""

    runner.command = command
    runner.cleanup = AsyncMock()
    rid = store.enqueue("owner/repo", pr(), {"workflows": [".github/workflows/ci.yml"], "review": True})
    task = asyncio.create_task(runner.execute(store.claim()))
    try:
        await asyncio.wait_for(asyncio.gather(*(e.wait() for e in started.values())), 5)
        release[first].set()
        phase_name = "ci.yml" if first == "ci" else "mergeCraft"
        for _ in range(200):
            row = store.rows("SELECT * FROM runs WHERE id=?", (rid,))[0]
            phase = next(s for s in json.loads(row["steps"]) if s["name"] == phase_name)
            if phase["state"] not in ("running", "queued"):
                break
            await asyncio.sleep(0.01)
        else:
            pytest.fail("First phase did not finish independently")
        assert row["state"] == "running"
        evidence = reports(row, runner.root, store, [])
        assert set(evidence) == {first}
        release["review" if first == "ci" else "ci"].set()
        await asyncio.wait_for(task, 5)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    row = store.rows("SELECT * FROM runs WHERE id=?", (rid,))[0]
    assert row["state"] == (
        "failure"
        if failed in ("ci", "review", "ci_nonblocking")
        else "blocked"
        if failed in ("inconclusive", "config_error")
        else "error"
        if failed and failed != "nonblocking"
        else "success"
    )
    if failed in ("nonblocking", "ci_nonblocking"):
        report = reports(row, runner.root, store, [])["review"]
        assert report["state"] == "success" and report["non_blocking_findings"] == 1
        assert "non-blocking findings" in report["checks"][0]["message"]
    if failed == "inconclusive":
        report = reports(row, runner.root, store, [])["review"]
        assert report["state"] == "blocked"
        assert "inconclusive" in report["checks"][0]["message"]
        runtime = json.loads((runner.root / "artifacts" / rid / "mergecraft-runtime.json").read_text())
        assert runtime["exit_code"] == 11
        assert runtime["terminal"]["verdict"]["outcome"] == "inconclusive"
    assert all(s["state"] not in ("queued", "running") for s in json.loads(row["steps"]))
    result_file = runner.root / "artifacts" / rid / "mergecraft.json"
    if failed in ("review_exception", "config_error"):
        assert not result_file.exists()
        diagnostics = reports(row, runner.root, store, [])["review"]["diagnostics"]
        assert any("No readable" in d for d in diagnostics)
        if failed == "config_error":
            assert "review.ignorePaths" in diagnostics[0]
            assert "Review configuration invalid" in row["message"]
    else:
        assert json.loads(result_file.read_text())["source"] == "review"
    events = store.rows("SELECT phase,message FROM run_events WHERE message LIKE ?", ("%phase marker",))
    assert {e["message"]: e["phase"] for e in events} == {
        "ci phase marker": "ci.yml",
        "review phase marker": "mergeCraft",
    }
    assert sum(v["cpus"] for v in limits.values()) <= 8
    assert sum(v["memory"] for v in limits.values()) <= 24
    assert not (runner.root / "work" / rid).exists()


async def test_controller_cancellation_stops_both_phases_and_finalizes_queue(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALCI_REVIEW_IMAGE", "review:test")
    token = tmp_path / "token"
    token.write_text("fixture-token")
    store = Store(tmp_path / "data/db")
    runner = Runner(store, GitHub(token), tmp_path / "data", lambda *_: {"KEY": "fixture-key"})
    started = {kind: asyncio.Event() for kind in ("ci", "review")}
    stopped = set()

    async def command(*args, **kwargs):
        if args[:2] == ("git", "clone"):
            Path(args[-1]).mkdir(parents=True)
        if args[:2] == ("git", "show"):
            if args[-1].endswith(".yml"):
                return (
                    0,
                    "on: pull_request\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps: [{run: echo ok}]\n",
                )
            return 0, "{}"
        kind = "ci" if "act" in args else "review" if args[:3] == ("docker", "start", "-a") else None
        if kind:
            started[kind].set()
            try:
                await asyncio.Event().wait()
            finally:
                stopped.add(kind)
        return 0, ""

    runner.command = command
    runner.cleanup = AsyncMock()
    rid = store.enqueue(
        "owner/repo",
        pr(),
        {"workflows": [".github/workflows/ci.yml", ".github/workflows/second.yml"], "review": True},
    )
    task = asyncio.create_task(runner.execute(store.claim()))
    try:
        await asyncio.wait_for(asyncio.gather(*(event.wait() for event in started.values())), 5)
    finally:
        task.cancel()
        await asyncio.wait_for(task, 5)
    assert stopped == {"ci", "review"}
    row = store.rows("SELECT * FROM runs WHERE id=?", (rid,))[0]
    assert row["state"] == "error"
    assert not any(s["state"] in ("queued", "running") for s in json.loads(row["steps"]))
    assert not (runner.root / "work" / rid).exists()


def test_review_timeout_is_bounded_and_defaults_preserve_existing_runs():
    from pydantic import ValidationError

    from localci.app import RepoConfig

    assert RepoConfig().review_timeout == 3000
    assert RepoConfig(review_timeout=900).review_timeout == 900
    for invalid in (0, 3001):
        with pytest.raises(ValidationError):
            RepoConfig(review_timeout=invalid)
