import time
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from localci.github import GitHub
from localci.policy import Blocked, dependabot_pr, plan
from localci.reporting import clean
from localci.runner import Runner
from localci.store import Store
from tests.test_service import pr


def test_redaction_cannot_be_reassembled_by_control_character_stripping():
    assert clean("token=sup\x1b[0mersecret", ["supersecret"]) == "token=[redacted]"
    assert clean("token=sup\x00ersecret", ["supersecret"]) == "token=[redacted]"


def test_runner_applies_the_same_redaction_order(tmp_path):
    store = Store(tmp_path / "db")
    rid = store.enqueue("owner/repo", pr(), {})
    runner = Runner(store, GitHub(tmp_path / "token"), tmp_path, lambda *_: {})
    runner.run = store.rows("SELECT * FROM runs WHERE id=?", (rid,))[0]
    runner.log_path = tmp_path / "run.log"
    runner.sensitive = ["supersecret"]
    runner.log("token=sup\x1b[0mersecret\n")
    assert "supersecret" not in runner.log_path.read_text()
    assert "[redacted]" in runner.log_path.read_text()


async def test_oversized_output_line_discards_secret_suffix(tmp_path):
    store = Store(tmp_path / "db")
    rid = store.enqueue("owner/repo", pr(), {})
    runner = Runner(store, GitHub(tmp_path / "token"), tmp_path, lambda *_: {})
    runner.run = store.rows("SELECT * FROM runs WHERE id=?", (rid,))[0]
    runner.log_path = tmp_path / "run.log"
    runner.deadline = time.monotonic() + 30
    runner.sensitive = ["SECRETVALUE123"]
    code, _ = await runner.command(
        "python3",
        "-c",
        "import sys; sys.stdout.write('x' * 131000 + 'SECRETVALUE123\\nnext line\\n')",
    )
    assert code == 0
    log = runner.log_path.read_text()
    assert "[oversized output line omitted]" in log
    assert "SECRETVALUE123" not in log and "TVALUE123" not in log
    assert log.splitlines()[-1].endswith(" next line")  # the following line survives


def test_workflow_level_secret_references_are_required():
    text = """on: pull_request
env:
  TOKEN: ${{ secrets.WORKFLOW_TOKEN }}
jobs:
  test:
    runs-on: ubuntu-latest
    steps: [{run: echo ok}]
"""
    with pytest.raises(Blocked, match="WORKFLOW_TOKEN"):
        plan(text, set(), {})
    plan(text, {"WORKFLOW_TOKEN"}, {})


def test_dependabot_branch_name_does_not_bypass_review():
    snapshot = pr()
    snapshot["user"]["login"] = "maintainer"
    snapshot["head"]["ref"] = "dependabot/not-a-bot"
    assert not dependabot_pr(snapshot)


def test_capacity_defaults_fit_small_hosts(tmp_path):
    store = Store(tmp_path / "db")
    settings = store.settings({"cpus": 4, "memory_gb": 8})
    assert settings["cpus_per_run"] == 2
    assert settings["memory_gb_per_run"] == 4


async def test_credential_setup_failure_removes_plaintext_work_directory(tmp_path):
    token = tmp_path / "token"
    token.write_text("fixture-token")
    store = Store(tmp_path / "data/db")
    rid = store.enqueue("owner/repo", pr(), {})

    def fail(*_):
        raise RuntimeError("credential store unavailable")

    runner = Runner(store, GitHub(token), tmp_path / "data", fail)
    runner.cleanup = AsyncMock()
    await runner.execute(store.claim())
    assert not any((tmp_path / "data/work").iterdir())
    assert store.rows("SELECT state FROM runs WHERE id=?", (rid,))[0]["state"] == "error"


async def test_each_workflow_receives_only_referenced_secret_values(tmp_path):
    token = tmp_path / "token"
    token.write_text("fixture-token")
    store = Store(tmp_path / "data/db")
    runner = Runner(
        store,
        GitHub(token),
        tmp_path / "data",
        lambda *_: {"USED_TOKEN": "selected-value", "UNUSED_TOKEN": "unselected-value"},
    )
    secret_files = []
    worker = {}  # files present in the worker's /control

    async def command(*args, **kwargs):
        if args[:2] == ("git", "clone"):
            Path(args[-1]).mkdir(parents=True)
        if args[:2] == ("docker", "cp") and args[3].endswith(":/control"):
            worker.update({p.name: p.read_text() for p in Path(args[2]).iterdir()})
        elif args[:2] == ("docker", "cp") and ":/control/" in args[3]:
            worker[args[3].rsplit("/", 1)[1]] = Path(args[2]).read_text()
        if args[:2] == ("docker", "exec") and "rm" in args:
            worker.pop(args[-1].rsplit("/", 1)[1], None)
        if args[:2] == ("git", "show"):
            return (
                0,
                """on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    env:
      TOKEN: ${{ secrets.USED_TOKEN }}
    steps: [{run: echo ok}]
""",
            )
        if "act" in args:
            name = Path(args[args.index("--secret-file") + 1]).name
            secret_files.append(worker[name])
            runner.completed_jobs = 1
        return 0, ""

    runner.command = command
    runner.cleanup = AsyncMock()
    rid = store.enqueue("owner/repo", pr(), {"review": False, "workflows": [".github/workflows/ci.yml"]})
    await runner.execute(store.claim())
    row = store.rows("SELECT state,message FROM runs WHERE id=?", (rid,))[0]
    assert row["state"] == "success", row
    assert len(secret_files) == 1
    assert "selected-value" in secret_files[0]
    assert "unselected-value" not in secret_files[0]
    assert not any(name.endswith(".secrets") for name in worker)  # removed after act


def test_container_inputs_are_pinned_and_nested_secrets_are_ignored():
    root = Path(__file__).parents[1]
    for name in ("Dockerfile", "Dockerfile.worker", "Dockerfile.jobs"):
        for line in (root / name).read_text().splitlines():
            if line.startswith("FROM ") and "${BASE_IMAGE}" not in line:
                assert "@sha256:" in line
    jobs = (root / "Dockerfile.jobs").read_text()
    # Chrome comes from the signed apt repository, never a moving direct download.
    assert "_current_" not in jobs and "/linux/direct/" not in jobs
    assert "deb [arch=amd64 signed-by=$keyring] https://dl.google.com/linux/chrome/deb/ stable main" in jobs
    fingerprint = [line for line in jobs.splitlines() if line.startswith("ARG CHROME_KEY_FINGERPRINT=")]
    assert len(fingerprint) == 1
    value = fingerprint[0].split("=", 1)[1]
    assert len(value) == 40 and all(c in "0123456789ABCDEF" for c in value)
    assert 'grep -qx "${CHROME_KEY_FINGERPRINT}"' in jobs
    ignored = (root / ".dockerignore").read_text()
    assert "**/*.key" in ignored and "**/*.pem" in ignored and "**/__pycache__" in ignored
