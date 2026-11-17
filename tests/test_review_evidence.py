import hashlib
import json

import pytest
from test_reporting import completed

from localci.reporting import comment_body, reports
from localci.review_evidence import classify_review, terminal_event


def events(outcome, code):
    return {
        name: {"event": name, "protocol_version": "1", "outcome": outcome, "exit_code": code}
        for name in ("verdict", "run_finished")
    }


@pytest.mark.parametrize(
    "outcome,code,state",
    [
        ("passed", 0, "success"),
        ("passed", 10, "success"),
        ("passed", 11, "failure"),
        ("failed", 12, "failure"),
        ("failed", 11, "failure"),
        ("inconclusive", 20, "blocked"),
        ("inconclusive", 11, "blocked"),
        ("configuration_error", 30, "blocked"),
        ("configuration_error", 11, "blocked"),
        ("infra_error", 40, "error"),
        ("infra_error", 11, "error"),
        ("timed_out", 50, "error"),
        ("timed_out", 11, "error"),
        ("passed", 99, "error"),
        ("inconclusive", 0, "error"),
        ("unknown", 0, "error"),
    ],
)
def test_pinned_completion_contract(outcome, code, state):
    actual, message = classify_review(
        code, events(outcome, code), findings=[{"severity": "Minor"}] if code == 10 else []
    )
    assert actual == state
    assert str(code) in message


@pytest.mark.parametrize("damage", ["missing", "version", "code", "name", "boolean"])
def test_completion_requires_matching_terminal_pair(damage):
    pair = events("passed", 0)
    if damage == "missing":
        del pair["run_finished"]
    else:
        field, value = {
            "version": ("protocol_version", "2"),
            "code": ("exit_code", 11),
            "name": ("event", "verdict"),
            "boolean": ("exit_code", False),
        }[damage]
        pair["run_finished"][field] = value
    assert classify_review(0, pair)[0] == "error"


def test_success_requires_primary_report_and_event_projection_is_bounded():
    assert classify_review(0, events("passed", 0), primary_available=False)[0] == "error"
    assert terminal_event('{"event":"tool", "secret":"private"}') is None
    event = terminal_event(
        '{"event":"verdict", "protocol_version":"1", "exit_code":11, "outcome":"inconclusive", "secret":"private"}'
    )
    assert event is not None and "secret" not in event


def evidence_fixture(tmp_path):
    store, run = completed(tmp_path, review_state="blocked")
    directory = tmp_path / "artifacts" / run["id"]
    directory.mkdir(parents=True)
    finding = {
        "scope": "change",
        "severity": "Major",
        "path": "src/test.py",
        "start_line": 7,
        "end_line": 8,
        "message": "fixture-secret blocker",
        "evidence": ["fixture-secret evidence"],
        "remediation": "fix",
        "rule_id": "agent:draft",
        "fingerprint": "draft",
        "source": "agent",
    }
    packet = {
        "schema_version": "1.13.0",
        "reviewed_head_sha": None,
        "change_id": "local/review@patch",
        "findings": [
            finding,
            finding,
            dict(finding, rule_id="agent:terminal", fingerprint="final"),
            dict(finding, scope="run", message="coverage advisory"),
        ],
    }
    path = directory / "mergecraft-evidence.json"
    path.write_text(json.dumps(packet))
    runtime = {k: run[k] for k in ("repo", "head", "base")}
    runtime.update(
        run_id=run["id"], evidence_sha256=hashlib.sha256(path.read_bytes()).hexdigest(), exit_code=11
    )
    (directory / "mergecraft-runtime.json").write_text(json.dumps(runtime))
    return store, run, directory, packet, runtime


def test_recovery_preserves_distinct_drafts_redacts_and_keeps_incomplete_status(tmp_path):
    store, run, directory, _, _ = evidence_fixture(tmp_path)
    (directory / "mergecraft.json").write_text("{")
    report = reports(run, tmp_path, store, ["fixture-secret"])["review"]
    assert report["state"] == "blocked"
    assert report["findings_source"] == "evidence" and report["finding_count"] == 2
    assert {f["fingerprint"] for f in report["findings"]} == {"draft", "final"}
    body = comment_body(run, "review", report, "https://private.test")
    assert "fixture-secret" not in body and "coverage advisory" not in body
    assert "draft" in body and "final" in body and "incomplete" in body.lower()
    assert "11" == report["record"]["exit_code"]


@pytest.mark.parametrize(
    "damage", ["schema", "head", "change", "binding", "digest", "malformed", "scope", "symlink", "oversize"]
)
def test_fallback_rejects_unbound_or_invalid_evidence(tmp_path, damage):
    store, run, directory, packet, runtime = evidence_fixture(tmp_path)
    path = directory / "mergecraft-evidence.json"
    if damage in ("schema", "head", "change"):
        packet[{"schema": "schema_version", "head": "reviewed_head_sha", "change": "change_id"}[damage]] = (
            "wrong"
        )
    if damage == "scope":
        packet["findings"][0]["scope"] = "unknown"
    path.write_text(json.dumps(packet))
    runtime["evidence_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    if damage == "binding":
        runtime["head"] = "another-commit"
    if damage == "digest":
        runtime["evidence_sha256"] = "wrong"
    if damage == "malformed":
        path.write_text("{")
    if damage == "oversize":
        path.write_text(" " * 10_000_001)
    if damage == "symlink":
        target = directory / "other.json"
        path.rename(target)
        path.symlink_to(target)
    (directory / "mergecraft-runtime.json").write_text(json.dumps(runtime))
    report = reports(run, tmp_path, store, [])["review"]
    assert report["findings_source"] == "unavailable" and report["findings"] == []
    body = comment_body(run, "review", report, "https://private.test")
    assert "unavailable" in body.lower() and "No findings" not in body


def test_primary_valid_empty_result_takes_precedence(tmp_path):
    store, run, directory, _, _ = evidence_fixture(tmp_path)
    (directory / "mergecraft.json").write_text('{"findings":[]}')
    report = reports(run, tmp_path, store, [])["review"]
    assert report["findings_source"] == "primary" and report["finding_count"] == 0


def test_terminal_capture_survives_retention_caps_and_ignores_ci_lane(tmp_path):
    from localci.github import GitHub
    from localci.runner import Runner
    from localci.store import Store

    runner = Runner(Store(tmp_path / "db"), GitHub(tmp_path / "token"), tmp_path, lambda *_: {})
    runner.log_path = tmp_path / "run.log"
    runner.log_path.write_bytes(b" " * 8_000_001)
    runner.event_count = 50000
    runner.run = {"id": "fixture"}
    for event in events("passed", 0).values():
        runner.log(json.dumps(event))
    assert runner.review_events == {}
    token = runner._lane.set("review")
    try:
        for event in events("inconclusive", 11).values():
            runner.log(json.dumps(event))
        assert classify_review(11, runner.review_events)[0] == "blocked"
        runner.log(json.dumps(events("passed", 0)["verdict"]))
        assert classify_review(0, runner.review_events)[0] == "error"
    finally:
        runner._lane.reset(token)


def test_review_completion_diagnostics_survive_info_level_and_noisy_errors(tmp_path):
    store, run, _, _, _ = evidence_fixture(tmp_path)
    messages = [
        "submit_review_verdict terminal submission rejected: approve_with_confirmed_blocker",
        "submit_review_verdict terminal submission conflict: a different verdict payload was already recorded",
        "no terminal review verdict was submitted for this attempt fixture-secret @team <script>",
    ]
    store.append_events([(run["id"], i, "mergeCraft", "", "info", m) for i, m in enumerate(messages)])
    store.append_events([(run["id"], 100 + i, "mergeCraft", "", "error", "noisy finding") for i in range(30)])
    report = reports(run, tmp_path, store, ["fixture-secret"])["review"]
    assert all(any(m.split(" fixture-secret")[0] in d for d in report["diagnostics"]) for m in messages)
    body = comment_body(run, "review", report, "https://private.test")
    assert "fixture-secret" not in body and "@team" not in body and "<script>" not in body


def test_runtime_protocol_projection_never_retains_arbitrary_strings():
    payload = {
        "event": "verdict",
        "outcome": "fixture-secret",
        "protocol_version": "fixture-secret",
        "exit_code": "fixture-secret",
    }
    event = terminal_event(json.dumps(payload))
    assert "fixture-secret" not in json.dumps(event)
    assert classify_review(0, {"verdict": event, "run_finished": event})[0] == "error"
