import json
from unittest.mock import AsyncMock

from test_service import pr

from localci.github import GitHub
from localci.policy import dependabot_pr
from localci.reporting import comment_body, reports
from localci.review_evidence import classify_review, configuration_diagnostic
from localci.runner import Runner
from localci.store import Store


def test_configuration_errors_keep_multiline_context_and_redaction(tmp_path):
    store = Store(tmp_path / "db")
    rid = store.enqueue("owner/repo", pr(), {"review": True})
    lines = [
        "config validation failed: 2 validation errors for RepoSettings",
        "review.ignorePaths",
        "  Extra inputs are not permitted [type=extra_forbidden, input_value=['fixture-private'], input_type=list]",
        "    For further information visit",
        "https://errors.pydantic.dev/2.13/v/extra_forbidden",
        "review.anotherField",
        "  Extra inputs are not permitted",
        "mergeCraft exited 30 without a JSON report; see its diagnostic output above.",
        "unrelated later output",
    ]
    store.append_events([(rid, i, "mergeCraft", "", "info", line) for i, line in enumerate(lines)])
    diagnostic = configuration_diagnostic(store, rid)
    assert "review.ignorePaths" in diagnostic and "review.anotherField" in diagnostic
    assert "unrelated" not in diagnostic
    state, detail = classify_review(30, {}, configuration_error=diagnostic)
    assert state == "blocked" and "Review configuration invalid" in detail
    assert classify_review(0, {}, configuration_error=diagnostic)[0] == "error"
    assert classify_review(30, {"verdict": {}}, configuration_error=diagnostic)[0] == "error"
    assert classify_review(30, {})[0] == "error"
    store.execute(
        "UPDATE runs SET state=?,steps=? WHERE id=?",
        (state, json.dumps([{"name": "mergeCraft", "state": state, "message": detail}]), rid),
    )
    run = store.rows("SELECT * FROM runs WHERE id=?", (rid,))[0]
    report = reports(run, tmp_path, store, ["fixture-private"])["review"]
    body = comment_body(run, "review", report, "https://private.test")
    assert r"review\.ignorePaths" in body and r"review\.anotherField" in body
    assert "Extra inputs are not permitted" in body and "fixture-private" not in body


async def test_dependabot_keeps_ci_without_review_credentials_or_container(tmp_path):
    from pathlib import Path

    token = tmp_path / "token"
    token.write_text("fixture-token")
    store = Store(tmp_path / "data/db")
    scopes = []

    def secrets(repo, scope):
        scopes.append(scope)
        assert scope == "ci"
        return {}

    runner = Runner(store, GitHub(token), tmp_path / "data", secrets)
    calls = []

    async def command(*args, **kwargs):
        calls.append(args)
        assert args[:2] != ("docker", "create")
        if args[:2] == ("git", "clone"):
            Path(args[-1]).mkdir(parents=True)
        if args[:2] == ("git", "show"):
            return (
                0,
                "on: pull_request\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps: [{run: echo ok}]\n",
            )
        if "act" in args:
            runner.completed_jobs = 1
        return 0, ""

    runner.command = command
    runner.cleanup = AsyncMock()
    snapshot = pr()
    snapshot["user"]["login"] = "dependabot[bot]"
    snapshot["head"]["ref"] = "dependency-update"
    assert dependabot_pr(snapshot)
    named_branch = pr()
    named_branch["head"]["ref"] = "dependabot/not-a-bot"
    assert not dependabot_pr(named_branch)
    rid = store.enqueue("owner/repo", snapshot, {"review": True, "workflows": [".github/workflows/ci.yml"]})
    await runner.execute(store.claim())
    run = store.rows("SELECT * FROM runs WHERE id=?", (rid,))[0]
    assert run["state"] == "success"
    assert any("act" in call for call in calls)
    assert scopes == ["ci"]
    review = reports(run, runner.root, store, [])["review"]
    assert review["state"] == "skipped" and not review["diagnostics"]
    body = comment_body(run, "review", review, "https://private.test")
    assert "Dependabot PR" in body and "unavailable" not in body
    assert not dependabot_pr(pr())


def test_new_image_evidence_schema_preserves_bound_findings(tmp_path):
    import hashlib

    from test_review_evidence import evidence_fixture

    from localci.review_evidence import recover_findings

    store, run, directory, packet, runtime = evidence_fixture(tmp_path)
    packet["schema_version"] = "1.19.0"
    packet["coverage"] = {"status": "complete"}
    path = directory / "mergecraft-evidence.json"
    path.write_text(json.dumps(packet))
    runtime["evidence_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    (directory / "mergecraft-runtime.json").write_text(json.dumps(runtime))
    assert recover_findings(run, directory)


def test_budget_exhaustion_is_reported_even_without_final_artifacts(tmp_path):
    store = Store(tmp_path / "db")
    rid = store.enqueue("owner/repo", pr(), {"review": True})
    detail = "run budget exhausted (token): token budget exhausted by single increment (1200 > ceiling 1000; target 900, tolerance 0.1)"
    store.append_events([(rid, 1, "mergeCraft", "", "info", detail)])
    store.execute(
        "UPDATE runs SET state='blocked',steps=? WHERE id=?",
        (json.dumps([{"name": "mergeCraft", "state": "blocked", "message": "Review inconclusive"}]), rid),
    )
    run = store.rows("SELECT * FROM runs WHERE id=?", (rid,))[0]
    report = reports(run, tmp_path, store, [])["review"]
    assert report["diagnostics"][0] == detail
    assert report["state"] == "blocked" and report["findings_source"] == "unavailable"
    body = comment_body(run, "review", report, "https://private.test")
    assert "1200" in body and "1000" in body


def test_live_budget_breakdown_survives_missing_final_review(tmp_path):
    store = Store(tmp_path / "db")
    rid = store.enqueue("owner/repo", pr(), {"review": True})
    store.execute(
        "UPDATE runs SET state='blocked',steps=? WHERE id=?",
        (json.dumps([{"name": "mergeCraft", "state": "blocked", "message": "Review inconclusive"}]), rid),
    )
    directory = tmp_path / "artifacts" / rid
    directory.mkdir(parents=True)
    (directory / "mergecraft-usage.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "steps": 2,
                "duplicates_ignored": 1,
                "tokens": {"input": 600, "output": 20, "reasoning": 10, "cache_read": 500, "cache_write": 5},
                "total_tokens": 1135,
                "target": 1000,
                "ceiling": 1100,
                "stopped": True,
                "reason": "Live token budget stopped OpenCode after step 2: fixture-private",
            }
        )
    )
    run = store.rows("SELECT * FROM runs WHERE id=?", (rid,))[0]
    report = reports(run, tmp_path, store, ["fixture-private"])["review"]
    assert report["state"] == "blocked" and report["findings_source"] == "unavailable"
    body = comment_body(run, "review", report, "https://private.test")
    assert "1135 reported across 2 model steps" in body and "cached read 500" in body
    assert "Live token budget stopped" in body and "fixture-private" not in body
