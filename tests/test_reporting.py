import json
import re
from unittest.mock import AsyncMock

import pytest
from test_service import pr

from localci.app import Controller
from localci.github import GitHub
from localci.reporting import comment_body, reports
from localci.store import Store


def completed(tmp_path, *, review_state="failure"):
    store = Store(tmp_path / "db")
    rid = store.enqueue("owner/repo", pr(), {"workflows": [".github/workflows/ci.yml"], "review": True})
    store.claim()
    steps = [
        {"name": "ci.yml", "state": "failure", "message": "act exited 1; 2 jobs passed"},
        {"name": "mergeCraft", "state": review_state, "message": "Blocking review findings"},
    ]
    store.execute("UPDATE runs SET steps=? WHERE id=?", (json.dumps(steps), rid))
    store.finish(rid, "failure", "failed")
    return store, store.rows("SELECT * FROM runs")[0]


def test_reports_show_phase_failures_and_redacted_review_details(tmp_path):
    store, run = completed(tmp_path)
    artifact = tmp_path / "artifacts" / run["id"] / "mergecraft.json"
    artifact.parent.mkdir(parents=True)
    artifact.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "severity": "Major",
                        "message": "Secret fixture-private-value leaked",
                        "path": "src/test.py",
                        "start_line": 7,
                        "end_line": 8,
                        "evidence": ["evidence fixture-private-value"],
                        "remediation": "Mask progress",
                    }
                ]
            }
        )
    )
    store.append_events(
        [
            (run["id"], 1, "ci.yml", "Tests", "error", "FAILED test_private fixture-private-value"),
            (run["id"], 2, "mergeCraft", "Review", "error", "review diagnostic"),
            (run["id"], 3, "ci.yml", "Tests", "info", "irrelevant ordinary output"),
        ]
    )
    result = reports(run, tmp_path, store, ["fixture-private-value"])
    assert set(result) == {"ci", "review"}
    assert result["ci"]["diagnostics"] == ["Tests: FAILED test_private [redacted]"]
    assert result["review"]["findings"][0]["remediation"] == "Mask progress"
    assert "fixture-private-value" not in json.dumps(result)
    assert "Review: review diagnostic" in result["review"]["diagnostics"]
    for kind, report in result.items():
        body = comment_body(run, kind, report, "https://private.test/?run=" + run["id"])
        assert "Tailscale access required" in body and run["head"] in body
        assert "fixture-private-value" not in body
    assert "src/test" in comment_body(run, "review", result["review"], "https://private.test")


@pytest.mark.parametrize("payload", ["{", '{"findings": null}', '{"findings":[{"evidence":null}]}'])
def test_malformed_report_is_visible_not_a_publish_crash(tmp_path, payload):
    store, run = completed(tmp_path)
    path = tmp_path / "artifacts" / run["id"] / "mergecraft.json"
    path.parent.mkdir(parents=True)
    path.write_text(payload)
    report = reports(run, tmp_path, store, [])["review"]
    assert report["state"] == "failure"
    assert "could not be parsed" in " ".join(report["diagnostics"])


def test_untrusted_report_text_cannot_inject_links_or_mentions(tmp_path):
    _, run = completed(tmp_path)
    report = {
        "state": "failure",
        "checks": [],
        "findings": [],
        "diagnostics": ["@team ![secret](https://evil.test) <script>bad</script>"],
    }
    body = comment_body(run, "review", report, "https://private.test")
    assert "@team" not in body and "![secret]" not in body and "<script>" not in body


async def test_two_comments_are_updated_idempotently_only_by_owner(tmp_path):
    github = GitHub(tmp_path / "token")
    run = {"repo": "owner/repo", "pr": 73, "id": "run1"}
    comments = [{"id": 1, "user": {"id": 9}, "body": "<!-- localci:ci:v2:run1 -->\nforeign"}]
    writes = []

    async def request(method, path, **kwargs):
        if path == "user":
            return {"id": 42}
        if method == "GET":
            return comments.copy()
        writes.append((method, path))
        if method == "POST":
            comments.append({"id": len(comments) + 1, "user": {"id": 42}, "body": kwargs["json"]["body"]})
        else:
            next(c for c in comments if str(c["id"]) == path.rsplit("/", 1)[1])["body"] = kwargs["json"][
                "body"
            ]

    github.request = request
    for revision in ("first", "first", "second", "second"):
        for kind in ("ci",):
            await github.comment(run, kind, f"<!-- localci:ci:v2:run1 -->\n{revision}")
    assert [method for method, _ in writes] == ["POST", "PATCH"]
    assert len(comments) == 2 and comments[0]["body"].endswith("foreign")
    run["id"] = "run2"
    await github.comment(run, "ci", "<!-- localci:ci:v2:run2 -->\nnew run")
    await github.comment(run, "ci", "<!-- localci:ci:v2:run2 -->\nnew run")
    assert len(comments) == 3 and [method for method, _ in writes] == ["POST", "PATCH", "POST"]


async def test_publish_comments_retry_without_losing_final_phase(tmp_path):
    controller = Controller(tmp_path)
    rid = controller.store.enqueue(
        "owner/repo", pr(), {"workflows": [".github/workflows/ci.yml"], "review": True}
    )
    controller.store.claim()
    steps = [
        {"name": "ci.yml", "state": "success", "message": "4 jobs passed"},
        {"name": "mergeCraft", "state": "running", "message": ""},
    ]
    controller.store.execute("UPDATE runs SET steps=?,published=0 WHERE id=?", (json.dumps(steps), rid))
    controller.github.request = AsyncMock(return_value=pr())
    controller.github.status = AsyncMock(return_value="status")
    controller.github.comment = AsyncMock()
    await controller.publish()
    assert [call.args[1] for call in controller.github.comment.call_args_list] == ["ci"]
    controller.github.comment.reset_mock()
    controller.store.finish(rid, "error", "Review exceeded timeout")
    controller.github.comment.side_effect = RuntimeError("GitHub unavailable")
    await controller.publish()
    assert controller.store.rows("SELECT published FROM runs")[0]["published"] == 0
    controller.github.comment.side_effect = None
    controller.github.comment.reset_mock()
    controller.publish_retries.clear()
    controller.publish_backoff.clear()
    await controller.publish()
    assert [call.args[1] for call in controller.github.comment.call_args_list] == ["ci", "review"]
    assert "timeout" in controller.github.comment.call_args.args[2]
    assert controller.store.rows("SELECT published FROM runs")[0]["published"] == 1


async def test_superseded_revision_never_updates_comments(tmp_path):
    controller = Controller(tmp_path)
    rid = controller.store.enqueue(
        "owner/repo", pr(), {"workflows": [".github/workflows/ci.yml"], "review": True}
    )
    controller.store.finish(rid, "error", "failed setup")
    controller.github.request = AsyncMock(return_value=pr(base="c" * 40))
    controller.github.comment = AsyncMock()
    controller.github.status = AsyncMock()
    await controller.publish()
    controller.github.comment.assert_not_called()
    controller.github.status.assert_not_called()


async def test_native_review_ambiguous_post_is_recovered_without_duplicate(tmp_path):
    github = GitHub(tmp_path / "token")
    run = {"repo": "owner/repo", "pr": 76, "id": "run1", "head": "a" * 40}
    saved = [
        {
            "id": 1,
            "user": {"id": 9},
            "body": "<!-- localci:review:v2:run1 -->foreign",
            "commit_id": run["head"],
            "state": "COMMENTED",
        }
    ]
    writes = []

    async def request(method, path, **kwargs):
        if path == "user":
            return {"id": 42}
        if method == "GET":
            return saved.copy()
        writes.append((method, kwargs["json"]))
        if method == "POST":
            assert kwargs["json"]["event"] == "COMMENT"
            assert kwargs["json"]["commit_id"] == run["head"]
            saved.append(
                {
                    "id": 2,
                    "user": {"id": 42},
                    "commit_id": run["head"],
                    "state": "COMMENTED",
                    "body": kwargs["json"]["body"],
                }
            )
            raise TimeoutError("Response lost after GitHub accepted review")
        saved[1]["body"] = kwargs["json"]["body"]
        return saved[1]

    github.request = request
    with pytest.raises(TimeoutError):
        await github.comment(run, "review", "full review")
    await github.comment(run, "review", "full review")
    await github.comment(run, "review", "expanded evidence")
    await github.comment(run, "review", "expanded evidence")
    assert [w[0] for w in writes] == ["POST", "PUT"]
    assert len(saved) == 2 and saved[0]["body"].endswith("foreign")


def test_native_record_preserves_failure_and_run_health_without_fabricated_metrics(tmp_path):
    store, run = completed(tmp_path)
    directory = tmp_path / "artifacts" / run["id"]
    directory.mkdir(parents=True)
    (directory / "mergecraft.json").write_text('{"findings":[]}')
    (directory / "mergecraft-evidence.json").write_text(
        json.dumps(
            {
                "agent": {"model": "test-model", "provider": "provider"},
                "agent_terminal_verdict": "approve",
                "decision": {"result": "success"},
                "files_changed": ["read.py", "unread.py"],
                "trajectory": {"files_read": ["read.py"], "tool_calls": [{}, {}], "retries": 4},
                "deterministic_checks": [{"name": "scanner", "status": "failed"}],
                "run_health": {
                    "findings": [{"severity": "Major", "path": "unread.py", "message": "Never read"}]
                },
                "unrelated_secret": "fixture-private-value",
            }
        )
    )
    (directory / "mergecraft-review.md").write_text("Agent narrative fixture-private-value @team")
    report = reports(run, tmp_path, store, ["fixture-private-value"])["review"]
    body = comment_body(run, "review", report, "https://private.test")
    assert "Outcome: **failure**" in body
    assert "Tokens: Not recorded" in body
    assert "scanner: **failed**" in body
    assert "Never read" in body and "Run health" in body
    assert report["record"]["tool_retries"] == 4
    assert "Agent narrative [redacted]" in report["narrative"]
    assert "fixture-private-value" not in json.dumps(report)
    assert "@team" not in body
    assert "hunk coverage was not recorded" in body


def test_ci_report_lists_observed_jobs_tests_and_skips(tmp_path):
    store, run = completed(tmp_path)
    store.append_events(
        [
            (run["id"], 1, "ci.yml", "Verify/tests ", "info", "⭐ Run Main pytest"),
            (run["id"], 2, "ci.yml", "Verify/tests ", "info", "| 42 passed, 2 skipped in 18.5s"),
            (run["id"], 3, "ci.yml", "Verify/tests ", "info", "✅  Success - Main pytest [15s]"),
            (
                run["id"],
                4,
                "ci.yml",
                "Verify/tests ",
                "info",
                "| Optional packaging tool unavailable; skipping package check",
            ),
            (run["id"], 5, "ci.yml", "Verify/tests ", "info", "🏁  Job succeeded"),
            (
                run["id"],
                6,
                "ci.yml",
                "Verify/scanner ",
                "error",
                "❌  Failure - Main scan fixture-secret [2s]",
            ),
            (run["id"], 7, "ci.yml", "Verify/scanner ", "error", "🏁  Job failed"),
        ]
    )
    report = reports(run, tmp_path, store, ["fixture-secret"])["ci"]
    body = comment_body(run, "ci", report, "https://private.test")
    assert body.startswith(f"<!-- localci:ci:v2:{run['id']} -->")
    assert "42 passed, 2 skipped" in body
    assert "skipping package check" in body
    assert "pytest: **success**" in body and "15s" in body
    assert "fixture-secret" not in body
    assert report["state"] == "failure"  # Log evidence never overrides the workflow gate.
    assert [j["state"] for j in report["jobs"]] == ["success", "failure"]


def test_profile_uses_union_for_nested_tools_and_labels_non_tool_time(tmp_path):
    from localci.review_profile import summarize

    path = tmp_path / "profile.jsonl"
    rows = [
        {"kind": "agent_start", "time": 100},
        {"kind": "mcp", "tool": "verify_agent_findings", "started": 110, "seconds": 20},
        {"kind": "mcp", "tool": "git", "started": 115, "seconds": 1},
        {"kind": "agent_end", "time": 140},
    ]
    path.write_text("\n".join(json.dumps(v) for v in rows))
    result = summarize(path)
    assert result["complete"] and result["agent_seconds"] == 40
    assert result["mcp_busy_seconds"] == 20 and result["outside_mcp_seconds"] == 20
    assert result["mcp"]["git"]["calls"] == 1
    path.write_text(json.dumps(rows[0]))
    assert summarize(path)["complete"] is False


def test_failed_step_stdout_reaches_comment_without_error_level(tmp_path):
    store, run = completed(tmp_path)
    rows = [
        ("Verify/tests", "⭐ Run Main Passed check"),
        ("Verify/tests", "| unrelated prior step"),
        ("Verify/tests", "✅  Success - Main Passed check [1s]"),
        ("Verify/tests", "⭐ Run Main Validate GitHub Actions workflows"),
        ("Verify/tests", "| /var/run/act/workflow/11: line 2: go: command not found"),
        ("Verify/other", "| unrelated parallel job fixture-private-value"),
        ("Verify/tests", "| fixture-private-value @team <script>"),
        ("Verify/tests", "❌  Failure - Main Validate GitHub Actions workflows [171ms]"),
        ("Verify/tests", "⭐ Run Post Cleanup"),
        ("Verify/tests", "| cleanup output"),
        ("Verify/tests", "✅  Success - Post Cleanup [1s]"),
    ]
    store.append_events(
        [(run["id"], i, "ci.yml", job, "info", message) for i, (job, message) in enumerate(rows)]
    )
    report = reports(run, tmp_path, store, ["fixture-private-value"])["ci"]
    diagnostics = "\n".join(report["diagnostics"])
    assert "go: command not found" in diagnostics
    assert "Validate GitHub Actions workflows" in diagnostics
    assert "[redacted]" in diagnostics
    assert not any(s in diagnostics for s in ("prior step", "parallel job", "cleanup output"))
    body = comment_body(run, "ci", report, "https://private.test")
    assert body.index("go: command not found") < body.index("### Jobs and checks performed")
    assert "fixture-private-value" not in body and "@team" not in body and "<script>" not in body


def test_failed_output_is_bounded_and_post_failures_are_reported(tmp_path):
    store, run = completed(tmp_path)
    messages = (
        ["⭐ Run Post Upload"] + [f"| line {i}" for i in range(100)] + ["❌  Failure - Post Upload [2s]"]
    )
    store.append_events([(run["id"], i, "ci.yml", "Verify/tests", "info", m) for i, m in enumerate(messages)])
    report = reports(run, tmp_path, store, [])["ci"]
    check = report["jobs"][0]["checks"][0]
    assert check["name"] == "Post Upload"
    assert len(check["diagnostics"]) == 20
    assert check["diagnostics"][0] == "line 80"
    assert "line 99" in report["diagnostics"][0]


def test_pytest_timeout_trace_survives_long_warning_tail_and_parallel_output(tmp_path):
    store, run = completed(tmp_path)
    lines = [
        "⭐ Run Main pytest",
        "| ================= FAILURES =================",
        "| _____ test_incomplete_cleanup[database] _____",
        "| > assert clean_incomplete_records() is True",
        "| E assert False is True",
        "| --- Captured stderr call ---",
        "| Incomplete record cleanup reached its time budget; maintenance will retry",
        "| Traceback (most recent call last):",
        "|   async with asyncio.timeout(5):",
        "| TimeoutError fixture-secret @team <script>",
        "| ================= warnings summary =================",
        *["| ResourceWarning: unrelated warning" for _ in range(250)],
        "| ================= tests coverage =================",
        "| Required test coverage reached",
        "| 1 failed, 41 passed",
        "❌  Failure - Main pytest [20s]",
        "⭐ Run Post cleanup",
        "| cleanup does not belong in failure",
        "✅  Success - Post cleanup [1s]",
    ]
    store.append_events(
        [(run["id"], i, "ci.yml", "Verify/tests", "info", line) for i, line in enumerate(lines)]
    )
    report = reports(run, tmp_path, store, ["fixture-secret"])["ci"]
    output = "\n".join(report["diagnostics"])
    assert "asyncio.timeout(5)" in output and "time budget" in output and "TimeoutError" in output
    assert "1 failed, 41 passed" in output and "cleanup does not belong" not in output
    assert output.count("ResourceWarning") <= 20
    body = comment_body(run, "ci", report, "https://private.test")
    assert "fixture-secret" not in body and "@team" not in body and "<script>" not in body
    assert body.index("TimeoutError") < body.index("ResourceWarning")


def test_failure_excerpt_caps_memory_and_resets_for_next_step(tmp_path):
    from localci.ci_report import StepOutput

    output = StepOutput()
    output.append("================= FAILURES =================")
    for _ in range(500):
        output.append("x" * 1000)
    assert output.failure_bytes <= 9000 and len(output.failure) <= 120
    assert "truncated" in "\n".join(output.diagnostics())


def test_engine_error_after_composite_failure_is_reported_and_isolated(tmp_path):
    store, run = completed(tmp_path)
    rows = [
        ("Verify/containers-2", "⭐ Run Main Save Trivy binary to cache"),
        ("Verify/containers-2", "❌  Failure - Main Save Trivy binary to cache [9ms]"),
        ("Verify/containers-1", "unrelated parallel output"),
        (
            "Verify/containers-2",
            "remove /cache/actions-cache-save/.gitignore: no such file or directory fixture-secret @team <script>",
        ),
        ("Verify/containers-2", "❌  Failure - Main Install Trivy [18s]"),
        ("Verify/containers-2", "remove /cache/actions-cache-save/.gitignore: no such file or directory"),
        ("Verify/containers-2", "⭐ Run Post Cleanup"),
        ("Verify/containers-2", "| unrelated cleanup output"),
        ("Verify/containers-2", "✅  Success - Post Cleanup [1s]"),
    ]
    store.append_events(
        [(run["id"], i, "ci.yml", job, "info", message) for i, (job, message) in enumerate(rows)]
    )
    report = reports(run, tmp_path, store, ["fixture-secret"])["ci"]
    diagnostics = "\n".join(report["diagnostics"])
    assert "Save Trivy binary to cache" in diagnostics
    assert "no such file or directory" in diagnostics
    assert "[redacted]" in diagnostics
    assert "unrelated" not in diagnostics
    body = comment_body(run, "ci", report, "https://private.test")
    assert "no such file or directory" in body
    assert all(value not in body for value in ("fixture-secret", "@team", "<script>"))
    assert report["state"] == "failure"


def finished_run(tmp_path, config, steps, state, message):
    store = Store(tmp_path / "db")
    rid = store.enqueue("owner/repo", pr(), config)
    store.claim()
    store.execute("UPDATE runs SET steps=? WHERE id=?", (json.dumps(steps), rid))
    store.finish(rid, state, message)
    return store, store.rows("SELECT * FROM runs WHERE id=?", (rid,))[0]


@pytest.mark.parametrize("workflows", [[], [".github/workflows/ci.yml"]])
def test_review_that_never_started_is_reported_as_not_run(tmp_path, workflows):
    message = "PR does not merge cleanly into its base; resolve conflicts first"
    store, run = finished_run(
        tmp_path,
        {"workflows": workflows, "review": True},
        [{"name": "Checkout", "state": "running", "message": ""}],
        "blocked",
        message,
    )
    report = reports(run, tmp_path, store, [])["review"]
    assert report["state"] == "not run"
    body = comment_body(run, "review", report, "https://private.test")
    assert body.startswith("### mergeCraft: not run")
    assert "does not merge cleanly" in body
    assert "skipped" not in body and "No readable primary" not in body


def test_review_queued_but_never_started_is_reported_as_not_run(tmp_path):
    message = "docker exited 1; could not create the run network"
    store, run = finished_run(
        tmp_path,
        {"workflows": [".github/workflows/ci.yml"], "review": True},
        [
            {"name": "Checkout", "state": "success", "message": "merged"},
            {"name": "ci.yml", "state": "queued", "message": ""},
            {"name": "mergeCraft", "state": "queued", "message": ""},
        ],
        "error",
        message,
    )
    report = reports(run, tmp_path, store, [])["review"]
    assert report["state"] == "not run"
    body = comment_body(run, "review", report, "https://private.test")
    assert body.startswith("### mergeCraft: not run") and "No readable primary" not in body


def test_review_only_repository_gets_no_ci_report(tmp_path):
    store, run = finished_run(
        tmp_path,
        {"workflows": [], "review": True},
        [
            {"name": "Checkout", "state": "success", "message": "merged"},
            {"name": "mergeCraft", "state": "success", "message": "Review passed"},
        ],
        "success",
        "All configured checks passed",
    )
    assert set(reports(run, tmp_path, store, [])) == {"review"}


def test_run_level_error_outside_steps_is_not_reported_as_ci_success(tmp_path):
    store, run = finished_run(
        tmp_path,
        {"workflows": [".github/workflows/ci.yml"], "review": True},
        [
            {"name": "Checkout", "state": "success", "message": "merged"},
            {"name": "ci.yml", "state": "success", "message": "act exited 0; 1 jobs passed"},
            {"name": "mergeCraft", "state": "success", "message": "Review passed"},
        ],
        "error",
        "Run exceeded its wall-clock limit",
    )
    assert run["state"] == "error"
    report = reports(run, tmp_path, store, [])["ci"]
    assert report["state"] == "error"
    body = comment_body(run, "ci", report, "https://private.test")
    assert (
        "## Local CI: error" in body and "wall\\-clock limit" in body and "success" not in body.split("\n")[1]
    )


def test_failed_review_does_not_turn_successful_ci_into_a_failure(tmp_path):
    store, run = completed(tmp_path)
    steps = [
        {"name": "ci.yml", "state": "success", "message": "act exited 0; 1 jobs passed"},
        {"name": "mergeCraft", "state": "failure", "message": "Blocking review findings"},
    ]
    run = {**run, "steps": json.dumps(steps)}
    assert reports(run, tmp_path, store, [])["ci"]["state"] == "success"


@pytest.mark.parametrize(
    "forged",
    [
        "line\n===\n",
        "line\n---",
        "x\n# Local CI: success",
        "x\n> quoted",
        "x\n- **ci.yml: success**",
        "x\n1. numbered",
        "x\n\n    indented code",
        "x\r\n## heading",
    ],
)
def test_untrusted_text_cannot_forge_markdown_structure(tmp_path, forged):
    from localci.reporting import literal

    _, run = completed(tmp_path)
    inline = literal(forged)
    assert "\n" not in inline and "\r" not in inline
    for line in literal(forged, block=True).splitlines():
        assert not line.startswith((" ", "\t", "=", "-", "#", ">", "*", "+")), line
        assert not re.match(r"\d+[.)]", line), line
    report = {
        "state": "failure",
        "checks": [{"name": forged, "state": "failure", "message": forged}],
        "findings": [],
        "diagnostics": [],
        "jobs": [],
    }
    body = comment_body(run, "ci", report, "https://private.test")
    item = next(line for line in body.splitlines() if line.startswith("- **"))
    assert ": failure**" in item  # the forged text stayed inside its own list item
    forged_starts = ("===", "---", "# Local", "## heading", "> quoted", "    indented", "1. numbered")
    assert not any(line.startswith(forged_starts) for line in body.splitlines())
    assert literal("@team") == "@​team" and literal("[a](b)") == r"\[a\]\(b\)"
