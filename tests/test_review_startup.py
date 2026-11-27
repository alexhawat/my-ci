import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from test_service import pr

from localci.github import GitHub
from localci.policy import dependabot_pr
from localci.reporting import comment_body, reports
from localci.review_evidence import classify_review, configuration_diagnostic
from localci.runner import Runner, apply_review_token_ceiling
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


@pytest.mark.parametrize(
    "case,ci_code,review_skipped,profile,lightweight_expected",
    [
        ("inputs", 0, True, "", False),
        ("inputs", 0, True, "mounted", True),
        ("inputs", 0, True, "sysbox", True),
        ("inputs", 0, True, "missing", False),
        ("inputs", 1, True, "mounted", True),
        ("mixed", 0, False, "mounted", False),
        ("empty", 0, False, "", False),
        ("rename from outside", 0, False, "", False),
        ("rename to outside", 0, False, "", False),
        ("invalid filename encoding", 0, False, "", False),
        ("git error", 0, False, "", False),
        ("oversized output", 0, False, "", False),
        ("head policy only", 0, False, "mounted", False),
        ("invalid policy", 0, False, "", False),
    ],
)
async def test_trusted_path_policy_controls_the_review_lane(
    tmp_path, monkeypatch, case, ci_code, review_skipped, profile, lightweight_expected
):
    monkeypatch.setenv("LOCALCI_REVIEW_IMAGE", "review:test")
    monkeypatch.setenv("LOCALCI_WORKER_RUNTIME", "sysbox-runc" if profile == "sysbox" else "privileged")
    lightweight_archive = tmp_path / "lightweight-runner-image.tar"
    monkeypatch.setattr("localci.runner.LIGHTWEIGHT_JOB_ARCHIVE", lightweight_archive)
    if profile != "missing":
        lightweight_archive.touch()

    async def git_command(directory, *args, check=True, output=None):
        command = await asyncio.create_subprocess_exec(
            "git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.com",
            *args,
            cwd=directory,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await command.communicate()
        if check:
            assert command.returncode == 0, stderr
        if output:
            output.write_bytes(stdout)
        return command.returncode, stdout.decode(errors="replace")

    async def git(directory, *args):
        _, output = await git_command(directory, *args)
        return output

    origin = tmp_path / "origin"
    origin.mkdir()
    await git(origin, "init", "-q")
    (origin / ".mergecraft").mkdir()
    policy = origin / ".mergecraft/config.yaml"
    original_policy = "review:\n  ignorePaths: [scratch/**]\n"
    valid_rule = '  skipWhenOnly: ["execution_files/**"]\n'
    rule = "" if case == "head policy only" else valid_rule
    if case == "invalid policy":
        rule = "  skipWhenOnly: ['execution_files/**', 42]\n"
    policy.write_text(original_policy + rule)
    (origin / ".github/workflows").mkdir(parents=True)
    (origin / ".github/workflows/ci.yml").write_text(
        "on: pull_request\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps: [{run: echo ok}]\n"
    )
    (origin / "execution_files/batch").mkdir(parents=True)
    (origin / "execution_files/batch/plan.md").write_text("Plan\n")
    (origin / "outside.txt").write_text("Code-adjacent input\n")
    await git(origin, "add", "-A")
    await git(origin, "commit", "-qm", "base")
    base = (await git(origin, "rev-parse", "HEAD")).strip()
    if case == "rename from outside":
        await git(origin, "mv", "outside.txt", "execution_files/previous.txt")
    elif case == "rename to outside":
        await git(origin, "mv", "execution_files/batch/plan.md", "previous-plan.md")
    elif case != "empty":
        (origin / "execution_files/batch/plan\nrevision.md").write_text("Revised plan\n")
        if case == "mixed":
            (origin / "outside.txt").write_text("Mixed change\n")
        if case == "head policy only":
            policy.write_text(original_policy + valid_rule)
    await git(origin, "add", "-A")
    await git(origin, "commit", "-qm", "pull request", "--allow-empty")
    head = (await git(origin, "rev-parse", "HEAD")).strip()

    token = tmp_path / "token"
    token.write_text("fixture-token")
    store = Store(tmp_path / "data/db")
    scopes = []

    def secrets(repo, scope):
        scopes.append(scope)
        return {"KEY": "synthetic-review-key"} if scope == "review" else {}

    runner = Runner(store, GitHub(token), tmp_path / "data", secrets)
    created_reviews = []
    seeded_archives = []
    act_args = []

    async def run_command(*args, **kwargs):
        if args[:2] == ("git", "clone") and args[-2].startswith("https://"):
            args = (*args[:-2], str(origin), args[-1])
        if args[:2] == ("git", "diff") and "--name-only" in args:
            if case == "invalid filename encoding":
                return 0, "execution_files/\ufffd.txt\0"
            if case == "git error":
                return 128, ""
            if case == "oversized output":
                raise RuntimeError("Command output exceeded limit")
        if args[0] == "git":
            return await git_command(
                kwargs.get("cwd"), *args[1:], check=kwargs.get("check", True), output=kwargs.get("output")
            )
        if args[:2] == ("docker", "create"):
            env = Path(args[args.index("--env-file") + 1])
            config = (env.parent / "review-control/review-config.yaml").read_text()
            created_reviews.append(config)
        if args[:2] == ("docker", "cp") and args[-1].endswith(":/runner-image.tar"):
            seeded_archives.append(Path(args[-2]))
        if args[-2:] == ("docker", "load"):
            seeded_archives.append(kwargs["stdin_file"])
        if "act" in args:
            act_args.extend(args)
            runner.completed_jobs = 1
            return ci_code, ""
        return 0, ""

    runner.command = run_command
    runner.cleanup = AsyncMock()
    snapshot = pr()
    snapshot["base"]["sha"] = base
    snapshot["head"]["sha"] = head
    snapshot["labels"] = [{"name": "execution-files"}]
    rid = store.enqueue(
        "owner/repo",
        snapshot,
        {
            "review": True,
            "workflows": [".github/workflows/ci.yml"],
            "variables": {"LOCALCI_LIGHTWEIGHT_JOBS": "true"} if profile else {},
        },
    )
    await runner.execute(store.claim())
    run = store.rows("SELECT * FROM runs WHERE id=?", (rid,))[0]
    review = next(step for step in json.loads(run["steps"]) if step["name"] == "mergeCraft")
    assert seeded_archives == [
        lightweight_archive if lightweight_expected else Path("/opt/localci/runner-image.tar")
    ]
    image = "localci-jobs-lightweight:1" if lightweight_expected else "localci-jobs:1"
    assert f"ubuntu-latest={image}" in act_args
    assert f"ubuntu-24.04={image}" in act_args
    if review_skipped:
        assert review["state"] == "skipped"
        assert "review.skipWhenOnly" in review["message"]
        assert scopes == ["ci"] and not created_reviews
        assert run["state"] == ("failure" if ci_code else "success")
    else:
        assert review["state"] != "skipped"
        assert scopes == ["ci", "review"]
        assert len(created_reviews) == 1
        assert "skipWhenOnly" not in created_reviews[0]
        assert "scratch/**" in created_reviews[0]


@pytest.mark.parametrize("version", ["1.19.0", "1.21.0"])
def test_new_image_evidence_schema_preserves_bound_findings(tmp_path, version):
    import hashlib

    from test_review_evidence import evidence_fixture

    from localci.review_evidence import recover_findings

    store, run, directory, packet, runtime = evidence_fixture(tmp_path)
    packet["schema_version"] = version
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


@pytest.mark.parametrize("ceiling", [None, 5_000_000])
async def test_operator_ceiling_reaches_review_container_without_trusting_head(
    tmp_path, monkeypatch, ceiling
):
    import yaml

    monkeypatch.setenv("LOCALCI_REVIEW_IMAGE", "review:test")
    token = tmp_path / "token"
    token.write_text("fixture-token")
    store = Store(tmp_path / "data/db")
    runner = Runner(store, GitHub(token), tmp_path / "data", lambda _, scope: {"KEY": "synthetic-review-key"})
    observed = {}

    async def command(*args, **kwargs):
        if args[:2] == ("git", "clone"):
            directory = Path(args[-1])
            directory.mkdir(parents=True)
            # A PR cannot supply its own trusted budget or execution policy.
            (directory / ".mergecraft").mkdir()
            (directory / ".mergecraft/config.yaml").write_text(
                "runBounds: {tokenBudget: 99000000}\nshell: enabled\n"
            )
        if args[:2] == ("git", "show"):
            assert args[-1] == "b" * 40 + ":.mergecraft/config.yaml"
            return (
                0,
                "runBounds: {tokenBudget: 2000000, tokenBudgetTolerance: 0.1, toolCallBudget: 123}\nreview: {ignorePaths: [private/**], roundBudgets: {multipliers: [2.0], carryOver: true}}\n",
            )
        if args[:2] == ("docker", "create"):
            env = Path(args[args.index("--env-file") + 1])
            observed["env"] = env.read_text()
            observed["config"] = yaml.safe_load(
                (env.parent / "review-control/review-config.yaml").read_text()
            )
            assert not (env.parent / "review-export/.mergecraft").exists()
        return 0, ""

    runner.command = command
    runner.cleanup = AsyncMock()
    store.enqueue("owner/repo", pr(), {"review": True, "review_token_ceiling": ceiling})
    await runner.execute(store.claim())
    config = observed["config"]
    assert config["shell"] == config["push"] == "disabled"
    assert config["review"]["ignorePaths"] == ["private/**"]
    assert config["runBounds"]["toolCallBudget"] == 123
    if ceiling is None:
        assert config["runBounds"]["tokenBudget"] == 2_000_000
        assert config["runBounds"]["tokenBudgetTolerance"] == 0.1
        assert config["review"]["roundBudgets"]["multipliers"] == [2.0]
        assert "MERGECRAFT_TOKEN_BUDGET=" not in observed["env"]
    else:
        assert config["runBounds"]["tokenBudget"] == ceiling
        assert config["runBounds"]["tokenBudgetTolerance"] == 0
        assert config["review"]["roundBudgets"]["multipliers"] == [1.0]
        # Other trusted settings next to the overridden ones are kept.
        assert config["review"]["roundBudgets"]["carryOver"] is True
        assert f"MERGECRAFT_TOKEN_BUDGET={ceiling}\n" in observed["env"]


@pytest.mark.parametrize(
    "config,ceiling,path",
    [
        (["not", "a", "mapping"], None, "top level"),
        ({"runBounds": [1]}, 1000, "`runBounds`"),
        ({"review": "strict"}, 1000, "`review`"),
        ({"review": {"roundBudgets": [2.0]}}, 1000, "`review.roundBudgets`"),
    ],
)
def test_malformed_base_review_config_is_a_clear_configuration_error(config, ceiling, path):
    with pytest.raises(ValueError, match="Base .mergecraft/config.yaml is invalid") as error:
        apply_review_token_ceiling(config, ceiling)
    assert path in str(error.value)


def test_token_ceiling_leaves_config_alone_when_unset_and_fills_missing_sections():
    config = {"runBounds": [1], "review": "strict"}  # Not this function's concern without a ceiling.
    apply_review_token_ceiling(config, None)
    assert config == {"runBounds": [1], "review": "strict"}
    config = {"runBounds": None}
    apply_review_token_ceiling(config, 1000)
    assert config == {
        "runBounds": {"tokenBudget": 1000, "tokenBudgetTolerance": 0},
        "review": {"roundBudgets": {"multipliers": [1.0]}},
    }


@pytest.mark.parametrize("steps", [0, 2])
def test_unpriced_subscription_overrides_estimate_even_on_partial_review(tmp_path, steps):
    from localci.reporting import add_review_record

    (tmp_path / "mergecraft-metrics.json").write_text(json.dumps({"cost": "$0.123 estimate"}))
    (tmp_path / "mergecraft-usage.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "usage_partial": True,
                "cost_availability": "unknown_subscription_charge",
                "total_tokens": steps * 100,
                "steps": steps,
                "stopped": False,
            }
        )
    )
    report = {"diagnostics": [], "findings_source": "unavailable"}
    add_review_record(report, tmp_path, [])
    assert report["record"]["cost"] == "NA"
    assert ("partial usage" if steps else "Unavailable") in report["record"]["tokens"]
    assert any("Only measured tokens" in text for text in report["diagnostics"])


def test_partial_usage_diagnostic_names_the_recorded_cause(tmp_path):
    from localci.reporting import add_review_record

    cause = "Provider request failed; complete usage unavailable (HTTP 429)"
    (tmp_path / "mergecraft-usage.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "usage_partial": True,
                "cost_availability": "unknown_subscription_charge",
                "total_tokens": 200,
                "steps": 2,
                "stopped": False,
                "accounting_error": cause,
            }
        )
    )
    report = {"diagnostics": [], "findings_source": "unavailable"}
    add_review_record(report, tmp_path, [])
    assert (
        f"Session usage was incomplete ({cause}). Only measured tokens are included." in report["diagnostics"]
    )
