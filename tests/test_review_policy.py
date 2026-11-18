import json

import pytest
from test_review_evidence import events, evidence_fixture

from localci.reporting import comment_body, reports
from localci.results import aggregate, check_summary
from localci.review_evidence import classify_review
from localci.review_reconcile import reconcile_legacy_reviews


@pytest.mark.parametrize(
    "threshold,failed",
    [
        ("major", {"Major", "Critical"}),
        ("minor", {"Minor", "Major", "Critical"}),
        ("trivial", {"Trivial", "Minor", "Major", "Critical"}),
    ],
)
@pytest.mark.parametrize("severity", ["Trivial", "Minor", "Major", "Critical"])
def test_severity_failure_threshold(threshold, failed, severity):
    state, detail = classify_review(
        10, events("passed", 10), findings=[{"severity": severity}], failure_threshold=threshold
    )
    assert state == ("failure" if severity in failed else "success")
    assert ("non-blocking findings" in detail) == (state == "success")
    assert "CLI exit 10" in detail


@pytest.mark.parametrize(
    "findings,available",
    [(None, True), ([], True), ([{"severity": "Unexpected"}], True), ([{"severity": "Minor"}], False)],
)
def test_exit_ten_cannot_pass_without_valid_primary_findings(findings, available):
    assert (
        classify_review(10, events("passed", 10), findings=findings, primary_available=available)[0]
        == "error"
    )


@pytest.mark.parametrize(
    "outcome,code,state",
    [
        ("failed", 10, "failure"),
        ("passed", 11, "failure"),
        ("failed", 12, "failure"),
        ("inconclusive", 11, "blocked"),
        ("configuration_error", 30, "blocked"),
        ("infra_error", 40, "error"),
        ("timed_out", 50, "error"),
    ],
)
def test_threshold_never_relaxes_execution_or_blocking_failures(outcome, code, state):
    assert (
        classify_review(
            code, events(outcome, code), findings=[{"severity": "Trivial"}], failure_threshold="major"
        )[0]
        == state
    )


def legacy(tmp_path, ci="success"):
    store, run, directory, packet, runtime = evidence_fixture(tmp_path)
    findings = [
        {"severity": "Minor", "message": "a minor finding", "path": "x", "evidence": []},
        {"severity": "Trivial", "message": "a nit", "path": "y", "evidence": []},
    ]
    (directory / "mergecraft.json").write_text(json.dumps({"findings": findings}))
    runtime.update(exit_code=10, terminal=events("passed", 10))
    (directory / "mergecraft-runtime.json").write_text(json.dumps(runtime))
    steps = [
        {"name": "ci.yml", "state": ci, "message": "CI evidence"},
        {
            "name": "mergeCraft",
            "state": "failure",
            "message": "Review has findings (CLI outcome passed; exit 10)",
        },
    ]
    state, message = aggregate(steps, "success", "All configured checks passed")
    config = json.loads(run["config"])
    config.pop("review_failure_threshold")
    config.pop("review_policy_version")
    store.execute(
        "UPDATE runs SET state=?,message=?,steps=?,config=?,published=1 WHERE id=?",
        (state, message, json.dumps(steps), json.dumps(config), run["id"]),
    )
    return store, run["id"], directory


@pytest.mark.parametrize("ci", ["success", "failure", "blocked", "error"])
def test_legacy_repair_is_audited_idempotent_and_preserves_ci(tmp_path, ci):
    store, rid, directory = legacy(tmp_path, ci)
    before = store.rows("SELECT * FROM runs WHERE id=?", (rid,))[0]
    assert reconcile_legacy_reviews(store, tmp_path, apply=False) == [rid]
    assert store.rows("SELECT * FROM runs WHERE id=?", (rid,))[0] == before
    assert reconcile_legacy_reviews(store, tmp_path) == [rid]
    after = store.rows("SELECT * FROM runs WHERE id=?", (rid,))[0]
    assert after["state"] == ci
    assert after["attempt"] == before["attempt"] and after["finished"] == before["finished"]
    assert after["published"] == 0
    assert store.rows("SELECT state FROM run_usage WHERE run_id=?", (rid,))[0]["state"] == ci
    assert reconcile_legacy_reviews(store, tmp_path) == []
    steps = json.loads(after["steps"])
    assert "2 non-blocking findings" in check_summary(steps)
    review = reports(after, tmp_path, store, [])["review"]
    assert review["state"] == "success" and review["failure_threshold"] == "Major or Critical"
    assert "2 non-blocking findings" in review["result_label"]
    assert review["policy_adjustment"]["previous_run_message"] == before["message"]
    body = comment_body(after, "review", review, "https://private.test")
    assert "non\\-blocking findings" in body and "Failure threshold: Major or Critical" in body
    assert "CI was not rerun" in body and "a minor finding" in body


@pytest.mark.parametrize(
    "damage",
    ["digest", "head", "terminal", "primary", "severity", "explicit_policy", "other_failure", "cancelled"],
)
def test_legacy_repair_never_guesses_when_evidence_or_outcome_is_uncertain(tmp_path, damage):
    store, rid, directory = legacy(tmp_path)
    runtime_path = directory / "mergecraft-runtime.json"
    runtime = json.loads(runtime_path.read_text())
    if damage == "digest":
        runtime["evidence_sha256"] = "bad"
    elif damage == "head":
        runtime["head"] = "c" * 40
    elif damage == "terminal":
        runtime["terminal"] = events("failed", 10)
    elif damage == "primary":
        (directory / "mergecraft.json").unlink()
    elif damage == "severity":
        (directory / "mergecraft.json").write_text('{"findings":[{"severity":"Unknown"}]}')
    elif damage == "explicit_policy":
        store.execute(
            "UPDATE runs SET config=? WHERE id=?", (json.dumps({"review_failure_threshold": "trivial"}), rid)
        )
    elif damage == "other_failure":
        store.execute("UPDATE runs SET message=message || '; runner exception' WHERE id=?", (rid,))
    elif damage == "cancelled":
        store.execute("UPDATE runs SET state='cancelled' WHERE id=?", (rid,))
    runtime_path.write_text(json.dumps(runtime))
    before = store.rows("SELECT * FROM runs WHERE id=?", (rid,))[0]
    assert reconcile_legacy_reviews(store, tmp_path) == []
    assert store.rows("SELECT * FROM runs WHERE id=?", (rid,))[0] == before
