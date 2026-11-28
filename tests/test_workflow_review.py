"""A mergeCraft review that a CI workflow ran is published as the run's review message."""

import io
import json
import shutil
import zipfile
from unittest.mock import AsyncMock

import pytest
from test_service import pr

from localci.app import Controller, RepoConfig
from localci.reporting import comment_body, reports
from localci.store import Store
from localci.workflow_review import ARTIFACT, FILENAME, SCHEMA

HEAD = "a" * 40
WORKFLOW = ".github/workflows/review.yml"
# Built at runtime so no credential-shaped literal is committed.
PROVIDER_KEY_SHAPE = "sk-" + "fixtureonly" * 3


def document(**changes):
    base = {
        "schema": SCHEMA,
        "status": "reviewed",
        "reason": None,
        "pull_request": 4,
        "base_sha": "b" * 40,
        "head_sha": HEAD,
        "model": "gpt-fixture",
        "summary": "Checked the queue and the store.",
        "findings": [
            {
                "severity": "Minor",
                "file": "src/queue.py",
                "line": 3,
                "message": "Retry count is off by one.",
                "suggested_fix": None,
            },
            {
                "severity": "Major",
                "file": "deploy/compose.yaml",
                "line": 24,
                "message": "The worker service has no data directory, so it exits on start.",
                "suggested_fix": "Set the data directory for the worker service.",
            },
        ],
        "dropped": ["finding references path outside change set: 'other.py'"],
        "changed_files": ["deploy/compose.yaml", "src/queue.py"],
        "omitted_files": ["uv.lock"],
        "usage": {"requests": 7, "input_tokens": 120000, "output_tokens": 4000},
    }
    return base | changes


def upload(tmp_path, rid, payload, *, act_run="1735", name=FILENAME):
    """Store an artifact the way act's artifact server does: <run>/<name>/<name>.zip."""
    folder = tmp_path / "artifacts" / rid / "ci" / act_run / ARTIFACT
    folder.mkdir(parents=True)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr(name, payload if isinstance(payload, str) else json.dumps(payload))
    (folder / f"{ARTIFACT}.zip").write_bytes(buffer.getvalue())
    return folder / f"{ARTIFACT}.zip"


def finished(tmp_path, *, publish=True, review=False, state="failure", store=None):
    store = store or Store(tmp_path / "db")
    config = {"workflows": [WORKFLOW], "review": review, "publish_workflow_review": publish}
    rid = store.enqueue("owner/repo", pr(head=HEAD), config)
    store.claim()
    steps = [
        {"name": "Checkout", "state": "success", "message": "merged"},
        {"name": "review.yml", "state": state, "message": "act exited 1; 0 jobs passed"},
    ]
    store.execute("UPDATE runs SET steps=? WHERE id=?", (json.dumps(steps), rid))
    store.finish(rid, state, "One or more CI workflows failed")
    return store, store.rows("SELECT * FROM runs WHERE id=?", (rid,))[0]


def test_setting_is_off_by_default():
    assert RepoConfig().publish_workflow_review is False


def test_report_becomes_a_review_with_every_finding_scope_usage_and_dropped(tmp_path):
    store, run = finished(tmp_path)
    upload(tmp_path, run["id"], document())
    result = reports(run, tmp_path, store, [])
    assert set(result) == {"ci", "review"}
    review = result["review"]
    assert review["source"] == "workflow"
    assert review["state"] == "failure"
    assert review["result_label"] == "changes requested: 1 blocking of 2 findings"
    # Blocking first, in the fields the dashboard already renders.
    assert [(f["severity"], f["path"], f["start_line"]) for f in review["findings"]] == [
        ("Major", "deploy/compose.yaml", "24"),
        ("Minor", "src/queue.py", "3"),
    ]
    body = comment_body(run, "review", review, "https://example.com/run")
    assert body.startswith("### mergeCraft review (OpenAI Agents SDK, run by CI)")
    assert "- Outcome: **changes requested: 1 blocking of 2 findings**" in body
    assert "#### Major — deploy/compose\\.yaml:24" in body
    assert "- Suggested fix: Set the data directory for the worker service\\." in body
    assert "#### Minor — src/queue\\.py:3" in body
    assert "- Model: gpt\\-fixture" in body
    assert "- Tokens: 120000 input · 4000 output · 7 model requests" in body
    assert "- Scope: 2 files reviewed · 1 generated files listed without content" in body
    assert "- Dropped findings: 1 removed by mergeCraft's guardrails" in body
    assert "outside change set" in body
    assert "Checked the queue and the store\\." in body
    assert "not in my-ci's review sandbox" in body
    # my-ci's own review evidence and run-level messages are not mixed in.
    assert "One or more CI workflows failed" not in body
    assert "No readable primary" not in body


def test_clean_report_succeeds_and_says_it_is_not_an_approval(tmp_path):
    store, run = finished(tmp_path, state="success")
    upload(tmp_path, run["id"], document(findings=[], dropped=[]))
    review = reports(run, tmp_path, store, [])["review"]
    assert (review["state"], review["result_label"]) == ("success", "success: no findings")
    body = comment_body(run, "review", review, "https://example.com/run")
    assert "No findings in the workflow's report. This alone is not an approval." in body


def test_failed_workflow_review_shows_its_reason(tmp_path):
    store, run = finished(tmp_path)
    upload(tmp_path, run["id"], document(status="error", reason="RateLimitError: slow down", findings=[]))
    review = reports(run, tmp_path, store, [])["review"]
    assert review["state"] == "failure"
    body = comment_body(run, "review", review, "https://example.com/run")
    assert "**review failed**" in body
    assert "RateLimitError: slow down" in body


def test_report_text_is_redacted_and_cannot_forge_markdown_or_mentions(tmp_path):
    store, run = finished(tmp_path)
    forged = (
        f"@maintainers ![x](https://evil.example/p) <details open> fixture-ci-secret {PROVIDER_KEY_SHAPE}"
        "\n# Approved\n    indented"
    )
    upload(
        tmp_path,
        run["id"],
        document(
            summary=forged,
            findings=[
                {"severity": "Major", "file": "a.py", "line": 1, "message": forged, "suggested_fix": forged}
            ],
        ),
    )
    review = reports(run, tmp_path, store, ["fixture-ci-secret"])["review"]
    body = comment_body(run, "review", review, "https://example.com/run")
    assert "fixture-ci-secret" not in json.dumps(review) and "fixture-ci-secret" not in body
    assert PROVIDER_KEY_SHAPE not in body
    assert "@maintainers" not in body
    assert "](https://evil" not in body
    assert "<details open> " not in body
    assert "\n# Approved" not in body
    assert "\n    indented" not in body


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        (document(head_sha="c" * 40), "not bound to the reviewed commit"),
        (document(schema="mergecraft.agents-sdk-review.v9"), "does not declare schema"),
        (document(status="approved"), "no valid status"),
        ("not json", "is not UTF-8 JSON"),
        ([], "is not a JSON object"),
    ],
)
def test_unusable_report_is_published_as_no_report_never_as_clean(tmp_path, payload, reason):
    store, run = finished(tmp_path)
    upload(tmp_path, run["id"], payload)
    review = reports(run, tmp_path, store, [])["review"]
    assert review["state"] == "unavailable"
    assert reason in review["diagnostics"][0]
    body = comment_body(run, "review", review, "https://example.com/run")
    assert body.startswith("### mergeCraft review (OpenAI Agents SDK): no report")
    assert "A missing report is not a clean review" in body


def test_missing_duplicate_misnamed_and_oversized_artifacts_are_not_read(tmp_path, monkeypatch):
    store, run = finished(tmp_path)
    assert "uploaded no" in reports(run, tmp_path, store, [])["review"]["diagnostics"][0]

    archive = upload(tmp_path, run["id"], document(), name="other.json")
    assert "has no" in reports(run, tmp_path, store, [])["review"]["diagnostics"][0]

    archive.unlink()
    upload(tmp_path, run["id"], document(), act_run="1736")
    upload(tmp_path, run["id"], document(), act_run="1737")
    assert "2 " in reports(run, tmp_path, store, [])["review"]["diagnostics"][0]

    shutil.rmtree(tmp_path / "artifacts" / run["id"] / "ci" / "1737")
    monkeypatch.setattr("localci.workflow_review.MAX_REPORT_BYTES", 100)
    assert "larger than 100 bytes" in reports(run, tmp_path, store, [])["review"]["diagnostics"][0]


def test_workflow_skip_keeps_the_workflow_message_and_disclaimer(tmp_path):
    store, run = finished(tmp_path, state="success")
    upload(tmp_path, run["id"], document(status="skipped", reason="no reviewable files changed", findings=[]))
    review = reports(run, tmp_path, store, [])["review"]
    assert review["state"] == "skipped"
    body = comment_body(run, "review", review, "https://example.com/run")
    assert body.startswith("### mergeCraft review (OpenAI Agents SDK, run by CI)")
    assert "- Outcome: **skipped by the workflow**" in body
    assert "no reviewable files changed" in body
    assert "not in my-ci's review sandbox" in body
    assert "The workflow completed no review" in body


def test_corrupt_deflate_and_deeply_nested_json_are_no_report_not_a_crash(tmp_path):
    store, run = finished(tmp_path)
    archive = upload(tmp_path, run["id"], document())
    data = bytearray(archive.read_bytes())
    # Damage the compressed stream after the local header, leaving the directory intact.
    start = 30 + len(FILENAME)
    data[start : start + 40] = b"\xff" * 40
    archive.write_bytes(bytes(data))
    review = reports(run, tmp_path, store, [])["review"]
    assert review["state"] == "unavailable"
    assert "could not be" in review["diagnostics"][0]

    shutil.rmtree(archive.parent.parent)
    upload(tmp_path, run["id"], "[" * 200_000 + "]" * 200_000)
    review = reports(run, tmp_path, store, [])["review"]
    assert review["state"] == "unavailable"
    assert "is not UTF-8 JSON" in review["diagnostics"][0]


def test_any_unexpected_reader_error_is_no_report(tmp_path, monkeypatch):
    store, run = finished(tmp_path)
    upload(tmp_path, run["id"], document())

    def broken(*_):
        raise MemoryError

    monkeypatch.setattr("localci.workflow_review.read", broken)
    review = reports(run, tmp_path, store, [])["review"]
    assert review["state"] == "unavailable"
    assert "could not be read (MemoryError)" in review["diagnostics"][0]


def test_symlinked_artifact_is_ignored(tmp_path):
    store, run = finished(tmp_path)
    elsewhere = upload(tmp_path, "elsewhere", document())
    folder = tmp_path / "artifacts" / run["id"] / "ci" / "1735" / ARTIFACT
    folder.mkdir(parents=True)
    (folder / f"{ARTIFACT}.zip").symlink_to(elsewhere)
    assert "uploaded no" in reports(run, tmp_path, store, [])["review"]["diagnostics"][0]


def test_without_the_setting_the_review_stays_skipped(tmp_path):
    store, run = finished(tmp_path, publish=False)
    upload(tmp_path, run["id"], document())
    review = reports(run, tmp_path, store, [])["review"]
    assert review["state"] == "skipped"
    assert comment_body(run, "review", review, "https://example.com").startswith("### mergeCraft: skipped")


async def test_review_is_posted_first_and_linked_from_the_ci_comment(tmp_path):
    controller = Controller(tmp_path)
    _, run = finished(tmp_path, store=controller.store)
    upload(tmp_path, run["id"], document())
    controller.github.request = AsyncMock(return_value=pr(head=HEAD))
    controller.github.status = AsyncMock(return_value="status")
    review_url = "https://github.com/owner/repo/pull/4#pullrequestreview-1"
    controller.github.comment = AsyncMock(side_effect=[{"html_url": review_url}, None])
    await controller.publish()
    calls = controller.github.comment.call_args_list
    assert [call.args[1] for call in calls] == ["review", "ci"]
    assert calls[0].args[2].startswith("### mergeCraft review (OpenAI Agents SDK, run by CI)")
    assert f"[review for this commit]({review_url})" in calls[1].args[2]
